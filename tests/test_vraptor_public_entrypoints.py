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
         "vraptor.legacy_cli", ["collect", "analyze", "--skip-ai"]),
        ("dfir", ["agent", "config", "--view", "defaults"],
         "vraptor.cli", ["agent", "config", "--view", "defaults"]),
        ("dfir", ["tools", "prep", "-t", "plaso"], "vraptor.cli", ["tools", "prep", "-t", "plaso"]),
        ("dfir", ["setup", "init", "--id", "example-case"],
         "vraptor.cli", ["setup", "init", "--id", "example-case"]),
    ],
)
def test_launchers_preserve_dispatch_from_another_directory(tmp_path, launcher, args, module, forwarded):
    repo = tmp_path / "repository with spaces"
    for relative in [launcher, "utils/runtime-env.sh", "src/vraptor/resources/scripts/load_repo_env.sh"]:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    fake_python = repo / ".venv/bin/python3"
    fake_python.parent.mkdir(parents=True)
    fake_python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$AI_SKILLS_REPO_ROOT" "$PYTHONPATH" "$@"\n'
    )
    fake_python.chmod(0o755)
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path / "home")}
    result = subprocess.run([str(repo / launcher), *args], cwd=tmp_path, env=env,
                            text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [str(repo), str(repo / "src"), "-m", module, *forwarded]


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
