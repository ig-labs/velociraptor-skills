"""Release checks must cover binary assets, state and oversized files."""

import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_export_validation", ROOT / "utils/validate-public-export.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


@pytest.mark.parametrize("state", [
    [], {"schema_version": 1, "files": []},
    {"schema_version": 1, "files": {"bad": "not a record"}},
    {"schema_version": 1, "files": {"bad": {"fingerprint": None}}},
])
def test_malformed_state_is_reported(tmp_path, monkeypatch, state):
    path = tmp_path / ".sync-state.json"
    path.write_text(json.dumps(state))
    monkeypatch.setattr(validator, "STATE", path)
    errors = []
    validator.check_state(errors)
    assert errors


@pytest.mark.parametrize("state_kind", ["missing", "valid", "malformed", "sensitive"])
def test_static_gate_handles_untracked_local_state(tmp_path, monkeypatch, state_kind):
    marker = "Info" + "Guard"
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validator, "git_files", lambda: [])
    for setting in ("DENY_FILE", "STATE", "MANIFEST", "GOLDEN_DB"):
        monkeypatch.setattr(validator, setting, tmp_path / setting.lower())
    validator.DENY_FILE.write_text("private-organization\t" + marker + "\n")
    for name in ("check_env", "check_manifest", "check_database"):
        monkeypatch.setattr(validator, name, lambda errors: None)
    if state_kind != "missing":
        state = {"schema_version": 1, "files": {}}
        if state_kind == "sensitive":
            state["note"] = marker
        validator.STATE.write_text("{" if state_kind == "malformed" else json.dumps(state))
    assert validator.validate_static() == int(state_kind in {"malformed", "sensitive"})


def test_symlinked_parent_is_rejected_without_reading_external_content(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "sample.txt").write_text("Info" + "Guard")
    (repo / "linked").symlink_to(external, target_is_directory=True)
    path = repo / "linked/sample.txt"
    monkeypatch.setattr(validator, "REPO_ROOT", repo)
    errors = []
    validator.check_paths([path], errors)
    assert any("symlink" in error for error in errors)
    assert validator.check_deny_patterns([path], errors) == []


@pytest.mark.parametrize("kind", ["binary", "large", "utf16", "state", "filename"])
def test_sensitive_content_is_not_skipped(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    marker = b"Info" + b"Guard"
    name = ".sync-state.json" if kind == "state" else "asset.bin"
    if kind == "filename":
        name = marker.decode() + ".txt"
    path = tmp_path / name
    monkeypatch.setattr(validator, "STATE", tmp_path / ".sync-state.json")
    data = {
        "binary": b"SQLite format 3\0" + marker,
        "large": b"x" * 5_000_001 + marker,
        "utf16": marker.decode().encode("utf-16"),
        "state": b'{"note":"' + marker + b'"}',
        "filename": b"ordinary content",
    }[kind]
    path.write_bytes(data)
    errors = []
    validator.check_deny_patterns([path], errors)
    assert any("private-organization" in error for error in errors)
    if kind != "filename":
        assert all(marker.decode() not in error for error in errors)


@pytest.mark.parametrize("name", [".env.production", "client.key", "identity.p12"])
def test_sensitive_filenames_are_rejected(tmp_path, monkeypatch, name):
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    path = tmp_path / name
    path.write_text("placeholder")
    errors = []
    validator.check_paths([path], errors)
    assert errors == [f"forbidden configuration filename: {name}"]


@pytest.mark.parametrize("denied", [False, True])
def test_static_gate_logs_result_without_matched_content(tmp_path, monkeypatch, denied):
    marker = "Info" + "Guard"
    path = tmp_path / "sample.txt"
    path.write_text(marker if denied else "ordinary content")
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validator, "git_files", lambda: [path])
    for setting in ("DENY_FILE", "STATE", "MANIFEST", "GOLDEN_DB"):
        monkeypatch.setattr(validator, setting, tmp_path / setting.lower())
    validator.DENY_FILE.write_text("private-organization\t" + marker + "\n")
    for name in ("check_env", "check_state", "check_manifest", "check_database"):
        monkeypatch.setattr(validator, name, lambda errors: None)
    assert validator.validate_static() == int(denied)
    log = tmp_path / ".local/public-checks.jsonl"
    record = json.loads(log.read_text())
    assert record["status"] == ("failed" if denied else "passed")
    assert record["errors"] == int(denied)
    assert marker not in log.read_text()
    assert "sample.txt" not in log.read_text()


@pytest.mark.parametrize("manifest", [
    "# no mappings\n", "\ttarget\tfile\n", ".\ttarget\ttree\n",
    "source//file\ttarget\tfile\n",
    "source\ttarget\ttree\nother/file\ttarget/file\tfile\n",
    "source\ttarget\ttree\nsource/file\tother/file\tfile\n",
])
def test_invalid_or_overlapping_manifest_is_reported(tmp_path, monkeypatch, manifest):
    path = tmp_path / "manifest.tsv"
    path.write_text(manifest)
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(validator, "MANIFEST", path)
    errors = []
    validator.check_manifest(errors)
    assert errors


def test_force_added_log_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    path = tmp_path / ".local/public-checks.jsonl"
    errors = []
    validator.check_paths([path], errors)
    assert errors == ["local audit state must not be published: .local/public-checks.jsonl"]


@pytest.fixture
def runtime_repo(tmp_path, monkeypatch):
    """Exercise real shell/Python checks with offline executable fixtures."""
    repo = tmp_path / "checkout with spaces"
    scripts = repo / "utils"
    scripts.mkdir(parents=True)
    package = repo / "src/vraptor"
    (package / "agent").mkdir(parents=True)
    (package / "__init__.py").touch()
    (package / "agent/__init__.py").touch()
    (package / "agent/profiles.py").write_text(
        "def load_agent_profile_config():\n    return {}\n"
    )
    runner = repo / "fixture.py"
    runner.write_text(
        "import json, os, sys\nfrom pathlib import Path\n"
        "name = Path(sys.argv[1]).name\n"
        "home = os.environ.get('CODEX_HOME') if name.startswith('link-') else None\n"
        "with open(os.environ['VALIDATION_TEST_LOG'], 'a') as log:\n"
        "    log.write(json.dumps([name, sys.argv[2:], home]) + '\\n')\n"
        "if home:\n"
        "    assert sys.argv[2:] == ['--dry-run']\n"
        "    Path(home, 'fixture').touch()\n"
        "sys.exit(7 if os.environ.get('VALIDATION_TEST_FAIL') == name else 0)\n"
    )
    for name in ("dfir", "vraptor", "utils/link-codex-skills.sh", "utils/link-codex-agents.sh"):
        target = repo / name
        target.write_text('#!/bin/bash\nexec "$VALIDATION_TEST_PYTHON" "$VALIDATION_TEST_RUNNER" "$0" "$@"\n')
        target.chmod(0o755)
    log = tmp_path / "calls.jsonl"
    operator_home = tmp_path / "operator-codex"
    operator_home.mkdir()
    monkeypatch.setattr(validator, "REPO_ROOT", repo)
    monkeypatch.setattr(validator, "validate_static", lambda: 0)
    environment = {
        "PATH": os.defpath, "HOME": str(tmp_path), "CODEX_HOME": str(operator_home),
        "VALIDATION_TEST_LOG": str(log), "VALIDATION_TEST_PYTHON": sys.executable,
        "VALIDATION_TEST_RUNNER": str(runner),
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    return repo, log, operator_home


def test_runtime_gate_runs_all_smoke_checks_and_cleans_linker_home(runtime_repo):
    repo, log, operator_home = runtime_repo
    assert validator.main() == 0
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(name, args) for name, args, _ in calls] == [
        ("dfir", ["--help"]), ("dfir", ["tools", "prep", "--help"]),
        ("dfir", ["velociraptor", "--help"]), ("vraptor", ["--help"]),
        ("vraptor", ["agent", "config", "--view", "defaults"]),
        ("vraptor", ["tools", "prep", "--help"]),
        ("link-codex-skills.sh", ["--dry-run"]),
        ("link-codex-agents.sh", ["--dry-run"]),
    ]
    temporary_home = Path(calls[-1][2])
    assert temporary_home != operator_home
    assert calls[-2][2] == str(temporary_home)
    assert not temporary_home.exists()
    assert list(operator_home.iterdir()) == []


@pytest.mark.parametrize("failure", ["shell", "python", "cli", "profile", "linker"])
def test_runtime_gate_propagates_failures(runtime_repo, monkeypatch, capfd, failure):
    repo, log, operator_home = runtime_repo
    if failure == "shell":
        (repo / "utils/broken.sh").write_text("if then\n")
    elif failure == "python":
        (repo / "src/vraptor/broken.py").write_text("def broken(\n")
    elif failure == "profile":
        (repo / "src/vraptor/agent/profiles.py").write_text(
            "def load_agent_profile_config():\n    raise ValueError('invalid fixture profile')\n"
        )
    else:
        monkeypatch.setenv("VALIDATION_TEST_FAIL", "dfir" if failure == "cli" else "link-codex-agents.sh")
    assert validator.main() == 1
    output = capfd.readouterr()
    assert "runtime validation failed" in output.err
    assert "agent-link validation passed" not in output.out
    if failure == "python":
        assert "SyntaxError" in output.out
    if failure in {"shell", "python"}:
        assert not log.exists()
    if failure == "profile":
        assert "invalid fixture profile" in output.err
    if failure == "cli":
        assert len(log.read_text().splitlines()) == 1
    if failure == "linker":
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        assert not Path(calls[-1][2]).exists()
    assert list(operator_home.iterdir()) == []


def test_static_failure_stops_before_runtime_checks(monkeypatch):
    monkeypatch.setattr(validator, "validate_static", lambda: 1)
    monkeypatch.setattr(validator, "validate_runtime", lambda: pytest.fail("Runtime checks must not run"))
    assert validator.main() == 1
