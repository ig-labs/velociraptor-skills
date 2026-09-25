"""Release checks must cover binary assets, state and oversized files."""

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_export_validation", ROOT / "utils/validate-public-export.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


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
    for name in ("check_env", "check_state", "check_manifest", "check_database"):
        monkeypatch.setattr(validator, name, lambda errors: None)
    assert validator.main() == int(denied)
    log = tmp_path / ".local/public-checks.jsonl"
    record = json.loads(log.read_text())
    assert record["status"] == ("failed" if denied else "passed")
    assert record["errors"] == int(denied)
    assert marker not in log.read_text()
    assert "sample.txt" not in log.read_text()


def test_force_added_log_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(validator, "REPO_ROOT", tmp_path)
    path = tmp_path / ".local/public-checks.jsonl"
    errors = []
    validator.check_paths([path], errors)
    assert errors == ["local audit state must not be published: .local/public-checks.jsonl"]
