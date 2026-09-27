"""Exercise sudo provisioning through fake SSH and a real local terminal."""
import json
import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "src/vraptor/resources/scripts/velociraptor"


@pytest.fixture
def remote(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    dispatcher = tools / "dispatcher"
    dispatcher.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, shutil, subprocess, sys, termios
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
root = pathlib.Path(os.environ["TEST_ROOT"])
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps([name, args]) + "\n")
if name == "ssh-keyscan":
    print("server ssh-ed25519 fakekey")
elif name == "ssh-keygen":
    pass
elif name == "id":
    print("root" if os.environ.get("TEST_AS_ROOT") else "operator")
    if args == ["-u"]:
        # This branch is handled separately below by the SSH shim.
        raise AssertionError("unexpected local id -u")
elif name == "ssh":
    if args[-1] == "id -u":
        print("1000")
    elif os.environ.get("TEST_TRANSPORT_FAIL") == "1" and "sudo" in args[-1]:
        sys.exit(255)
    else:
        sys.exit(subprocess.call(["/bin/sh", "-c", args[-1]]))
elif name == "sudo":
    noninteractive = args[0] == "-n"
    if noninteractive:
        args = args[1:]
    assert args[:3] == ["--", "sh", "-c"]
    access = os.environ.get("TEST_SUDO", "nopass")
    if access == "denied" or (access in {"password", "cancel"} and noninteractive):
        sys.exit(1)
    if access == "cancel":
        sys.exit(130)
    if access == "password":
        assert all(os.isatty(fd) for fd in (0, 1, 2))
        old = termios.tcgetattr(0)
        new = termios.tcgetattr(0)
        new[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, new)
        print("sudo password: ", end="", file=sys.stderr, flush=True)
        password = sys.stdin.readline().strip()
        termios.tcsetattr(0, termios.TCSANOW, old)
        assert password == "terminal-only-password"
    status = subprocess.call(args[1:], env=dict(os.environ, TEST_AS_ROOT="1"))
    if status == 0:
        (root / "prepared").touch()
    sys.exit(status)
elif name in {"runuser", "su"}:
    assert os.environ.get("TEST_AS_ROOT") == "1"
    if name == "runuser":
        assert args[:3] == ["-u", "service", "--"]
        command = args[3:]
    else:
        assert args[:3] == ["-s", "/bin/sh", "service"]
        command = ["/bin/sh", "-c", args[-1]]
    sys.exit(subprocess.call(command, env=dict(os.environ, TEST_SERVICE="1")))
elif name == "velociraptor":
    if os.environ.get("VELO_REMOTE_RUN_AS") == "service":
        assert os.environ.get("TEST_SERVICE") == "1"
    if os.environ.get("TEST_GENERATION_FAIL") == "1":
        print("credential-bearing-error", file=sys.stderr)
        sys.exit(1)
    if "api_client" in args:
        pathlib.Path(args[-1]).write_text("generated-secret\n")
    else:
        print("generated-secret")
elif name == "scp":
    if not (root / "prepared").exists() or os.environ.get("TEST_COPY_FAIL") == "1":
        sys.exit(1)
    source = pathlib.Path(args[-2].split(":", 1)[1])
    shutil.copyfile(source, args[-1])
elif name == "chown":
    assert args[:2] == ["--", "operator"]
    assert pathlib.Path(args[-1]).is_file()
elif name == "chmod":
    args = [arg for arg in args if arg != "--"]
    os.chmod(args[1], int(args[0], 8))
elif name == "install":
    assert args[:5] == ["-o", "operator", "-m", "600", "--"]
    shutil.copyfile(args[-2], args[-1])
    os.chmod(args[-1], 0o600)
else:
    raise AssertionError(name)
''')
    dispatcher.chmod(0o755)
    for name in ("ssh", "scp", "sudo", "id", "ssh-keygen", "ssh-keyscan", "velociraptor",
                 "runuser", "su", "install", "chmod", "chown"):
        (tools / name).symlink_to(dispatcher)
    server = tmp_path / "server space's"
    server.mkdir()
    source = server / "retrieval.yaml"
    destination = tmp_path / "local.yaml"
    destination.write_text("old-local-secret\n")
    key = tmp_path / "key"
    key.touch()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VELO_", "VRAPTOR_"))}
    env.update(HOME=str(tmp_path), AI_SKILLS_REPO_ROOT=str(tmp_path), PATH=f"{tools}:{os.defpath}",
               TEST_ROOT=str(tmp_path), VELO_REMOTE_SSH_USER="operator", VELO_REMOTE_SSH_KEY=str(key),
               VELO_REMOTE_RUN_AS="root", VELO_REMOTE_API_USER="test-api",
               VELO_REMOTE_API_CONFIG_PATH=str(source), VELO_REMOTE_CLIENT_CONFIG_PATH=str(source),
               VELO_REMOTE_SERVER_CONFIG_PATH=str(server / "server.yaml"),
               VELO_LOCAL_CONFIG_ROOT=str(tmp_path / "cache"))

    def command(kind="api", provision=True):
        return ["bash", str(SCRIPTS / f"fetch_live_{'api_client' if kind == 'api' else 'client_config'}.sh"),
                "--server-profile", "test", "--server-ip", "server", "--force",
                "--output-path", str(destination), *([f"--provision-{kind}"] if provision else [])]

    def calls():
        return [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]

    return tmp_path, source, destination, env, command, calls


@pytest.mark.parametrize("kind", ["api", "client"])
@pytest.mark.parametrize("scenario", ["new", "service", "existing", "existing_service", "installed", "empty", "dangling",
                                      "no_authorization", "failure", "copy_failure"])
def test_sudo_fetch(remote, kind, scenario):
    root, source, destination, env, command, calls = remote
    installed = source.parent / ("test-api_api_client.yaml" if kind == "api" else "dfir_client.config.yaml")
    if scenario in {"existing", "existing_service"}:
        source.write_text("preserved-secret\n")
    if scenario == "installed":
        installed.write_text("preserved-secret\n")
    if scenario == "empty":
        source.touch()
    if scenario == "dangling":
        source.symlink_to(source.parent / "absent.yaml")
    if scenario in {"service", "existing_service"}:
        env["VELO_REMOTE_RUN_AS"] = "service"
    if scenario == "failure":
        env["TEST_GENERATION_FAIL"] = "1"
    if scenario == "copy_failure":
        env["TEST_COPY_FAIL"] = "1"
    result = subprocess.run(command(kind, scenario not in {"no_authorization", "existing"}), env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    failed = scenario in {"empty", "dangling", "no_authorization", "failure", "copy_failure"}
    assert (result.returncode != 0) == failed, result.stderr
    expected = "preserved-secret\n" if scenario in {"existing", "existing_service", "installed"} else "generated-secret\n"
    assert destination.read_text() == ("old-local-secret\n" if failed else expected)
    if not failed:
        assert destination.stat().st_mode & 0o777 == 0o600
        assert source.read_text() == expected
        assert source.stat().st_mode & 0o777 == 0o600
    names = [call[0] for call in calls()]
    assert names.count("sudo") == 1
    assert names.count("velociraptor") == (0 if scenario in {"existing", "existing_service", "installed", "empty", "dangling", "no_authorization"} else 1)
    if scenario == "existing_service":
        assert "runuser" not in names and "su" not in names
    if scenario == "dangling":
        assert source.is_symlink()
        assert not source.exists()
    assert "Continue" not in result.stdout + result.stderr
    assert all(secret not in result.stdout + result.stderr for secret in
               ("generated-secret", "preserved-secret", "old-local-secret", "credential-bearing-error"))
    assert not list(root.glob("*.tmp.*"))


@pytest.mark.parametrize("fault", [None, "generation", "copy"])
def test_regeneration_is_explicit_and_not_retried(remote, fault):
    _, source, destination, env, command, calls = remote
    source.write_text("preserved-secret\n")
    if fault == "generation":
        env["TEST_GENERATION_FAIL"] = "1"
    if fault == "copy":
        env["TEST_COPY_FAIL"] = "1"
    result = subprocess.run([*command(), "--regenerate-remote-api"], env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    assert (result.returncode != 0) == (fault is not None)
    assert source.read_text() == ("preserved-secret\n" if fault == "generation" else "generated-secret\n")
    assert destination.read_text() == ("old-local-secret\n" if fault else "generated-secret\n")
    assert sum(call[0] == "velociraptor" for call in calls()) == 1
    assert sum(call[0] == "sudo" for call in calls()) == 1


@pytest.mark.parametrize("empty", [False, True])
def test_readable_file_never_uses_sudo(remote, empty):
    root, source, destination, env, command, calls = remote
    (root / "prepared").touch()
    source.write_text("" if empty else "readable-secret\n")
    result = subprocess.run(command(), env=env, capture_output=True, text=True, timeout=20, check=False)
    assert (result.returncode != 0) == empty
    assert destination.read_text() == ("old-local-secret\n" if empty else "readable-secret\n")
    assert not any(call[0] in {"sudo", "velociraptor"} for call in calls())


@pytest.mark.parametrize("scenario", ["password", "denied", "transport"])
def test_noninteractive_fallback_and_transport_failure(remote, scenario):
    _, source, destination, env, command, calls = remote
    env["TEST_SUDO"] = scenario
    if scenario == "transport":
        env["TEST_TRANSPORT_FAIL"] = "1"
    result = subprocess.run(command(), env=env, input="", capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == (1 if scenario == "transport" else 3)
    assert ("USER ACTION REQUIRED" in result.stdout) == (scenario != "transport")
    assert destination.read_text() == "old-local-secret\n"
    assert not source.exists()
    assert not any(call[0] == "velociraptor" for call in calls())


@pytest.mark.parametrize("access", ["password", "cancel", "denied"])
def test_sudo_terminal_authentication_and_fallback(remote, access):
    root, source, destination, env, command, calls = remote
    env.update(TEST_SUDO=access, VRAPTOR_CONFIG_MANUAL_PROMPT="0")
    result_file = root / "captured.json"
    pid, master = pty.fork()
    if pid == 0:
        result = subprocess.run(command(), env=env, capture_output=True, text=True, timeout=20, check=False)
        result_file.write_text(json.dumps([result.returncode, result.stdout, result.stderr]))
        os._exit(0)
    terminal = b""
    answered = False
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                terminal += chunk
                if b"sudo password:" in terminal and not answered:
                    os.write(master, b"terminal-only-password\n")
                    answered = True
            if result_file.exists():
                break
        assert result_file.exists(), terminal.decode(errors="replace")
        status, stdout, stderr = json.loads(result_file.read_text())
        assert status == {"password": 0, "cancel": 1, "denied": 3}[access], stderr
        assert answered == (access == "password")
        assert "sudo password:" not in stdout + stderr
        assert "terminal-only-password" not in stdout + stderr + terminal.decode()
        assert "generated-secret" not in stdout + stderr + terminal.decode()
        assert ("Continue" in stdout + stderr + terminal.decode()) == (access == "denied")
        if access == "password":
            assert destination.read_text() == source.read_text() == "generated-secret\n"
        else:
            assert destination.read_text() == "old-local-secret\n"
            assert not source.exists()
        assert sum(call[0] == "sudo" for call in calls()) == 2
        assert sum(call[0] == "velociraptor" for call in calls()) == (1 if access == "password" else 0)
        assert any(call[0] == "ssh" and "-t" in call[1] for call in calls())
    finally:
        os.close(master)
        done, _ = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
