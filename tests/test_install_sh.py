"""Bootstrap routing without package downloads or operator configuration."""

import errno
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def installer(tmp_path):
    repo = tmp_path / "checkout with spaces"
    (repo / "utils").mkdir(parents=True)
    shutil.copy2(ROOT / "utils/install.sh", repo / "utils/install.sh")
    shutil.copy2(ROOT / "requirements.txt", repo / "requirements.txt")
    fake = tmp_path / "python-fixture"
    fake.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ["INSTALL_TEST_LOG"], "a") as f:
    f.write(json.dumps([args, os.getcwd()]) + "\\n")
if args[:1] == ["-c"] and os.environ.get("INSTALL_TEST_OLD_PYTHON"):
    sys.exit("Python 3.11 or newer is required")
if args[:2] == ["-m", "venv"]:
    if os.environ.get("INSTALL_TEST_NO_VENV"):
        sys.exit(1)
    target = pathlib.Path(args[2]) / "bin"
    target.mkdir(parents=True)
    shutil.copy2(__file__, target / "python")
if args == ["-m", "pip", "--version"] and os.environ.get("INSTALL_TEST_NO_PIP"):
    sys.exit(1)
''')
    fake.chmod(0o755)
    launcher = repo / "vraptor"
    launcher.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
with open(os.environ["INSTALL_TEST_LOG"], "a") as f:
    f.write(json.dumps([["vraptor", *sys.argv[1:]], os.getcwd()]) + "\\n")
''')
    launcher.chmod(0o755)
    log = tmp_path / "calls.jsonl"
    env = {"PATH": os.defpath, "HOME": str(tmp_path), "PYTHON_BIN": str(fake),
           "INSTALL_TEST_LOG": str(log)}
    return repo, env, log


def run_installer(repo, env, *args, terminal=False):
    command = [str(repo / "utils/install.sh"), *args]
    if not terminal:
        return subprocess.run(command, cwd=repo.parent, env=env, capture_output=True, text=True)
    master, slave = pty.openpty()
    process = None
    try:
        process = subprocess.Popen(command, cwd=repo.parent, env=env,
                                   stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        slave = None
        data = bytearray()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                if process.poll() is not None:
                    break
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            data.extend(chunk)
        return subprocess.CompletedProcess(command, process.wait(timeout=1), data.decode(), "")
    finally:
        os.close(master)
        if slave is not None:
            os.close(slave)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


@pytest.mark.parametrize("terminal,flags,configure", [
    (False, [], False), (True, [], True), (True, ["--no-configure"], False),
    (True, ["--configure"], True),
])
def test_install_and_configuration_routing(installer, terminal, flags, configure):
    repo, env, log = installer
    result = run_installer(repo, env, *flags, terminal=terminal)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert [["-m", "pip", "install", "-r", "requirements.txt"], str(repo)] in calls
    assert any(args == ["vraptor", "setup", "configure"] for args, _ in calls) == configure
    # Reuse an existing environment, including uv-created environments without pip.
    log.write_text("")
    result = run_installer(repo, {**env, "INSTALL_TEST_NO_PIP": "1"}, "--no-configure")
    assert result.returncode == 0, result.stdout + result.stderr
    args = [json.loads(line)[0] for line in log.read_text().splitlines()]
    assert not any(command[:2] == ["-m", "venv"] for command in args)
    assert ["-m", "ensurepip", "--upgrade"] in args


@pytest.mark.parametrize("flag,message", [
    ("INSTALL_TEST_OLD_PYTHON", "Python 3.11 or newer"),
    ("INSTALL_TEST_NO_VENV", "venv/ensurepip support"),
])
def test_install_prerequisite_failure_stops_before_dependencies(installer, flag, message):
    repo, env, log = installer
    result = run_installer(repo, {**env, flag: "1"}, "--no-configure")
    assert result.returncode != 0
    assert message in result.stderr
    assert not (repo / ".venv").exists()
    assert not any("install" in json.loads(line)[0] for line in log.read_text().splitlines())


def test_configure_requires_terminal_before_installing(installer):
    repo, env, log = installer
    result = run_installer(repo, env, "--configure")
    assert result.returncode == 2
    assert "interactive terminal" in result.stderr
    assert not log.exists()
