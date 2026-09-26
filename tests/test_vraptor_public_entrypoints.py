from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("launcher", "args", "module", "forwarded"),
    [
        ("vraptor", ["collect", "--client", "C.1"], "vraptor.cli", ["collect", "--client", "C.1"]),
        ("dfir", ["velociraptor", "collect", "analyze", "--skip-ai"],
         "vraptor.cli", ["collect", "analyze", "--skip-ai"]),
        ("dfir", ["agent", "config", "--view", "defaults"],
         "vraptor.cli", ["agent", "config", "--view", "defaults"]),
        ("dfir", ["tools", "prep", "-t", "plaso"], "vraptor.cli", ["tools", "prep", "-t", "plaso"]),
        ("dfir", ["setup", "init", "--id", "example-case"],
         "vraptor.cli", ["setup", "init", "--id", "example-case"]),
    ],
)
@pytest.mark.parametrize("via_path", [False, True])
def test_launchers_preserve_dispatch_from_another_directory(tmp_path, launcher, args, module, forwarded, via_path):
    repo = tmp_path / "repository with spaces"
    for relative in [launcher, "utils/runtime-env.sh"]:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    fake_python = repo / ".venv/bin/python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$AI_SKILLS_REPO_ROOT" "$VELOCIRAPTOR_SKILLS_REPO_ROOT" "$PYTHONPATH" "$PWD" "$@"\n'
    )
    fake_python.chmod(0o755)
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path / "home")}
    if via_path:
        env["PATH"] = str(repo) + os.pathsep + env["PATH"]
    result = subprocess.run([launcher if via_path else str(repo / launcher), *args], cwd=tmp_path, env=env,
                            text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [str(repo), str(repo), str(repo / "src"), str(tmp_path), "-m", module, *forwarded]


@pytest.mark.parametrize("command", [("vraptor",), ("dfir",), ("dfir", "velociraptor")])
def test_checkout_commands_share_python_settings_precedence(tmp_path, command):
    repo, home = tmp_path / "repo", tmp_path / "home"
    for relative in ["vraptor", "dfir", "utils/runtime-env.sh"]:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    (repo / "src").symlink_to(ROOT / "src", target_is_directory=True)
    (repo / ".venv/bin").mkdir(parents=True)
    (repo / ".venv/bin/python3").symlink_to(sys.executable)
    config = home / ".config/vraptor/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('schema_version = 1\n[workstation]\ncase_root="~/saved"\n')
    env = {"HOME": str(home), "PATH": os.defpath, "PYTHONNOUSERSITE": "1"}

    def inspect(expected, source, *flags):
        result = subprocess.run(
            [str(repo / command[0]), *command[1:], "config", *flags],
            cwd=tmp_path, env=env, text=True, capture_output=True, check=True,
        )
        output = json.loads(result.stdout)
        assert "fixture-secret" not in result.stdout
        assert output["values"]["case_root"] == str(home / expected)
        assert output["sources"]["case_root"] == source

    inspect("saved", f"{config}:workstation.case_root")
    shared = home / ".codex/.env"
    shared.parent.mkdir()
    shared.write_text("CASE_ROOT=~/shared\n")
    inspect("shared", f"environment:{shared}:CASE_ROOT")
    (repo / ".env").write_text("CASE_ROOT=~/repository\n")
    inspect("repository", f"environment:{repo / '.env'}:CASE_ROOT")
    credentials = home / "credentials.env"
    credentials.write_text("CASE_ROOT=~/selected\nAPI_SECRET=fixture-secret\n")
    config.write_text(config.read_text() + '[credentials]\nenv_file="~/credentials.env"\n')
    inspect("selected", f"environment:{credentials}:CASE_ROOT")
    env["CASE_ROOT"] = "~/process"
    inspect("process", "environment:process:CASE_ROOT")
    inspect("explicit", "command_line", "--case-root", str(home / "explicit"))


@pytest.mark.parametrize("kind", ["skills", "agents"])
def test_codex_linkers_resolve_relative_source_overrides(tmp_path, kind):
    source = tmp_path / kind
    item = source / ("example/SKILL.md" if kind == "skills" else "example.toml")
    item.parent.mkdir(parents=True)
    item.write_text("fixture")
    destination = tmp_path / "codex"
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "CODEX_HOME": str(destination),
           f"AI_SKILLS_{kind.upper()}_DIR": kind}
    for _ in range(2):
        subprocess.run([str(ROOT / f"utils/link-codex-{kind}.sh")], cwd=tmp_path,
                       env=env, text=True, capture_output=True, check=True)
    link = destination / kind / ("example" if kind == "skills" else "example.toml")
    assert link.is_symlink()
    assert link.resolve() == (item.parent if kind == "skills" else item)
    assert link.exists()


def test_package_finds_public_root_without_launcher(tmp_path):
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path),
           "PYTHONPATH": str(ROOT / "src"), "PYTHONNOUSERSITE": "1"}
    result = subprocess.run(
        [sys.executable, "-c",
         "from vraptor.resources import repository_root; print(repository_root())"],
        cwd=tmp_path, env=env, text=True, capture_output=True, check=True,
    )
    assert Path(result.stdout.strip()) == ROOT


def test_installer_resolves_editable_requirement_from_repository(tmp_path):
    repo = tmp_path / "repository with spaces"
    (repo / "utils").mkdir(parents=True)
    shutil.copy2(ROOT / "utils/install.sh", repo / "utils/install.sh")
    (repo / "requirements.txt").write_text("-e .[ai]\n")
    fake_python = repo / ".venv/bin/python"
    fake_python.parent.mkdir(parents=True)
    log = tmp_path / "calls.jsonl"
    fake_python.write_text(
        "#!" + sys.executable + "\nimport json, os, sys\n"
        "with open(os.environ['TEST_CALL_LOG'], 'a') as f:\n"
        "    f.write(json.dumps([os.getcwd(), sys.argv[1:]]) + '\\n')\n"
    )
    fake_python.chmod(0o755)
    subprocess.run(
        [str(repo / "utils/install.sh")], cwd=tmp_path,
        env={**os.environ, "PYTHON_BIN": sys.executable, "TEST_CALL_LOG": str(log)},
        text=True, capture_output=True, check=True,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls[-1] == [str(repo), ["-m", "pip", "install", "-r", "requirements.txt"]]


@pytest.mark.parametrize("placeholder", ["api_username", "your_api_user", "<api-user>"])
def test_api_fetch_rejects_public_placeholders_before_connection(tmp_path, placeholder):
    script = ROOT / "src/vraptor/resources/scripts/velociraptor/fetch_live_api_client.sh"
    result = subprocess.run(
        ["bash", str(script), "--server-profile", "example"],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path),
             "AI_SKILLS_REPO_ROOT": str(tmp_path), "VELO_REMOTE_API_USER": placeholder},
        text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "example placeholder" in result.stdout + result.stderr


def test_public_runtime_has_no_legacy_business_package():
    assert not (ROOT / "dfir-case-tools").exists()
    for name in ["case_state", "case_backend", "case_session.py", "sod_store.py", "artifact_refs.py"]:
        assert not (ROOT / "src/vraptor" / name).exists()
