"""Exercise sudo provisioning through fake SSH and a real local terminal."""
import json
import os
import pty
import select
import shutil
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
    if len(args) == 2 and args[0] == "-u":
        sys.exit(int(os.environ.get("TEST_ACCOUNT_CHECK_STATUS", "0")))
    print("root" if os.environ.get("TEST_AS_ROOT") else "operator")
    if args == ["-u"]:
        # This branch is handled separately below by the SSH shim.
        raise AssertionError("unexpected local id -u")
elif name == "ssh":
    if args[-1] == "id -u":
        print(os.environ.get("TEST_SSH_UID", "1000"))
    elif os.environ.get("TEST_TRANSPORT_FAIL") == "1" and "sudo" in args[-1]:
        sys.exit(255)
    else:
        sys.exit(subprocess.call([os.environ["TEST_REMOTE_SHELL"], "-c", args[-1]]))
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
    status = subprocess.call([os.environ["TEST_REMOTE_SHELL"], *args[2:]], env=dict(os.environ, TEST_AS_ROOT="1"))
    if status == 0:
        (root / "prepared").touch()
    sys.exit(status)
elif name in {"runuser", "su"}:
    assert os.environ.get("TEST_AS_ROOT") == "1"
    if name == "runuser":
        assert args[:3] == ["-u", os.environ.get("TEST_GENERATION_USER", "service"), "--"]
        command = args[3:]
    else:
        assert args[:3] == ["-s", "/bin/sh", os.environ.get("TEST_GENERATION_USER", "service")]
        command = ["/bin/sh", "-c", args[-1]]
    if os.environ.get("TEST_ACCOUNT_CHECK_STATUS") == "1":
        sys.exit(1)
    sys.exit(subprocess.call(command, env=dict(os.environ, TEST_SERVICE="1")))
elif name == "velociraptor":
    if os.environ.get("TEST_REQUIRED_USER") and not os.environ.get("TEST_SERVICE"):
        print("Velociraptor should be running as the 'service' user but you are 'root'. Please change user with sudo first.", file=sys.stderr)
        print("credential-bearing-error", file=sys.stderr)
        sys.exit(1)
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
    (server / "server.yaml").write_text("synthetic-server-config\n")
    source = server / "retrieval.yaml"
    destination = tmp_path / "local.yaml"
    destination.write_text("old-local-secret\n")
    key = tmp_path / "key"
    key.touch()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VELO_", "VRAPTOR_"))}
    env.update(HOME=str(tmp_path), AI_SKILLS_REPO_ROOT=str(tmp_path), PATH=f"{tools}:{os.defpath}",
               TEST_ROOT=str(tmp_path), TEST_REMOTE_SHELL=shutil.which("dash") or "/bin/sh",
               VELO_REMOTE_SSH_USER="operator", VELO_REMOTE_SSH_KEY=str(key),
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


@pytest.mark.parametrize("failure,message", [
    ("wrong_user", "Set --run-as to the server's Frontend.run_as_user"),
    ("missing_binary", "binary is unavailable"),
    ("missing_config", "cannot read the remote server configuration"),
    ("native_failure", "credential generation failed"),
])
def test_generation_failure_reports_safe_reason_without_retry(remote, failure, message):
    root, source, destination, env, command, calls = remote
    if failure == "wrong_user":
        env["TEST_REQUIRED_USER"] = "service"
    elif failure == "missing_binary":
        env["VELO_REMOTE_BIN"] = str(root / "missing-velociraptor")
    elif failure == "missing_config":
        env["VELO_REMOTE_SERVER_CONFIG_PATH"] = str(source.parent / "missing.yaml")
    else:
        env["TEST_GENERATION_FAIL"] = "1"
    result = subprocess.run(command(), env=env, capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 1
    assert message in result.stderr
    assert "credential-bearing-error" not in result.stdout + result.stderr
    assert not source.exists()
    assert destination.read_text() == "old-local-secret\n"
    assert sum(call[0] == "sudo" for call in calls()) == 1
    assert sum(call[0] == "velociraptor" for call in calls()) == (failure in {"wrong_user", "native_failure"})


@pytest.mark.parametrize("kind", ["api", "client"])
def test_explicit_service_account_satisfies_native_user_requirement(remote, kind):
    _, source, destination, env, command, calls = remote
    env.update(TEST_REQUIRED_USER="service", VELO_REMOTE_RUN_AS="root")
    result = subprocess.run([*command(kind), "--run-as", "service"], env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    assert source.read_text() == destination.read_text() == "generated-secret\n"
    assert sum(call[0] == "velociraptor" for call in calls()) == 1


@pytest.mark.parametrize("access", ["password", "password_wrong_user", "cancel", "denied"])
def test_sudo_terminal_authentication_and_fallback(remote, access):
    root, source, destination, env, command, calls = remote
    env.update(TEST_SUDO="password" if access == "password_wrong_user" else access,
               VRAPTOR_CONFIG_MANUAL_PROMPT="0")
    if access == "password_wrong_user":
        env["TEST_REQUIRED_USER"] = "service"
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
        assert status == {"password": 0, "password_wrong_user": 1, "cancel": 1, "denied": 3}[access], stderr
        assert answered == (access in {"password", "password_wrong_user"})
        if access == "password_wrong_user":
            assert "Velociraptor rejected the generation account" in stderr
            assert "credential-bearing-error" not in stdout + stderr + terminal.decode()
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
        assert sum(call[0] == "velociraptor" for call in calls()) == (1 if access in {"password", "password_wrong_user"} else 0)
        assert any(call[0] == "ssh" and "-t" in call[1] for call in calls())
    finally:
        os.close(master)
        done, _ = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.kill(pid, 9)
            os.waitpid(pid, 0)


@pytest.mark.parametrize("kind", ["api", "client"])
def test_unset_run_as_generates_as_velociraptor(remote, kind):
    _, source, destination, env, command, calls = remote
    env.pop("VELO_REMOTE_RUN_AS")
    env.update(TEST_REQUIRED_USER="velociraptor", TEST_GENERATION_USER="velociraptor")
    result = subprocess.run(command(kind), env=env, capture_output=True, text=True,
                            timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    assert source.read_text() == destination.read_text() == "generated-secret\n"
    assert any(call[0] == "runuser" and call[1][:2] == ["-u", "velociraptor"] for call in calls())


@pytest.mark.parametrize("kind", ["api", "client"])
@pytest.mark.parametrize("scenario", ["missing", "resolved_default", "explicit_env", "explicit_cli", "lookup_failure", "generation_failure"])
def test_default_account_fallback_is_before_generation_only(remote, kind, scenario):
    root, source, destination, env, command, calls = remote
    env.pop("VELO_REMOTE_RUN_AS")
    env.update(TEST_GENERATION_USER="velociraptor", TEST_ACCOUNT_CHECK_STATUS="1")
    extra = []
    if scenario in {"resolved_default", "explicit_env", "explicit_cli"}:
        env["VELO_REMOTE_RUN_AS"] = "velociraptor"
        env["VRAPTOR_REMOTE_RUN_AS_DEFAULT"] = "0" if scenario == "explicit_env" else "1"
    if scenario == "explicit_cli":
        extra = ["--run-as", "velociraptor"]
    if scenario == "lookup_failure":
        env["TEST_ACCOUNT_CHECK_STATUS"] = "255"
    if scenario == "generation_failure":
        env.update(TEST_ACCOUNT_CHECK_STATUS="0", TEST_GENERATION_FAIL="1")
    manifest = root / "result.json"
    result = subprocess.run([*command(kind), *extra, "--json-out", str(manifest)], env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    succeeds = scenario in {"missing", "resolved_default"}
    assert (result.returncode == 0) == succeeds, result.stderr
    assert destination.read_text() == ("generated-secret\n" if succeeds else "old-local-secret\n")
    assert ("using root" in result.stdout + result.stderr) == succeeds
    names = [call[0] for call in calls()]
    assert names.count("velociraptor") == (1 if succeeds or scenario == "generation_failure" else 0)
    assert names.count("sudo") == (0 if scenario == "lookup_failure" else 1)
    assert names.count("runuser") == (1 if scenario in {"explicit_env", "explicit_cli", "generation_failure"} else 0)
    if succeeds:
        assert json.loads(manifest.read_text())["remote_run_as"] == "root"
    else:
        assert not source.exists()
    assert "credential-bearing-error" not in result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["api", "client"])
def test_root_ssh_selects_root_when_default_service_account_is_missing(remote, kind):
    root, source, destination, env, command, calls = remote
    env.pop("VELO_REMOTE_RUN_AS")
    env.update(TEST_SSH_UID="0", TEST_AS_ROOT="1", TEST_ACCOUNT_CHECK_STATUS="1")
    manifest = root / "result.json"
    result = subprocess.run([*command(kind), "--json-out", str(manifest)], env=env,
                            capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    assert source.read_text() == destination.read_text() == "generated-secret\n"
    assert json.loads(manifest.read_text())["remote_run_as"] == "root"
    names = [call[0] for call in calls()]
    assert names.count("velociraptor") == 1
    assert not any(name in names for name in ("sudo", "runuser", "su"))
