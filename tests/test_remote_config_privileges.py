"""Root generation and manual fallback when non-root sudo is unavailable."""
import json
import os
from pathlib import Path
import pty
import pwd
import subprocess
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "src/vraptor/resources/scripts/velociraptor"


@pytest.mark.parametrize("kind", ["api", "client"])
@pytest.mark.parametrize("login,run_as,existing", [
    ("root", "root", False),
    ("root", "velociraptor", False),
    ("operator", "root", False),
    ("operator", "velociraptor", False),
    ("operator", "root", True),
])
def test_remote_privilege_boundary(tmp_path, kind, login, run_as, existing):
    tools = tmp_path / "bin"
    tools.mkdir()
    dispatcher = tools / "dispatcher"
    dispatcher.write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_LOG"], "a") as out:
    out.write(json.dumps([name, os.environ.get("TEST_IDENTITY"), args]) + "\\n")
if name == "id":
    print(("0" if os.environ["TEST_IDENTITY"] == "root" else "1000") if args == ["-u"] else os.environ["TEST_IDENTITY"])
elif name == "ssh-keyscan":
    print("server ssh-ed25519 fakekey")
elif name == "ssh-keygen":
    sys.exit(0)
elif name == "scp":
    sys.exit(1)  # Force privileged streaming; never grant world-readable YAML.
elif name == "ssh":
    sys.exit(subprocess.call(["/bin/sh", "-c", args[-1]]))
elif name == "sudo":
    assert args[:2] == ["-n", "--"]
    if os.environ["TEST_DENIED"] == "1":
        print("sudo: a password is required", file=sys.stderr)
        sys.exit(1)
    env = dict(os.environ, TEST_IDENTITY="root")
    sys.exit(subprocess.call(args[1:], env=env))
elif name in {"su", "runuser"}:
    assert os.environ["TEST_IDENTITY"] == "root"
    if name == "su":
        assert args[:2] == ["-s", "/bin/sh"]
        command, user = ["/bin/sh", "-c", args[-1]], args[2]
    else:
        assert args[0] == "-u" and args[2] == "--"
        command, user = args[3:], args[1]
    sys.exit(subprocess.call(command, env=dict(os.environ, TEST_IDENTITY=user)))
elif name == "velociraptor":
    assert os.environ["TEST_IDENTITY"] == os.environ["TEST_RUN_AS"]
    if "api_client" in args:
        pathlib.Path(args[-1]).write_text("synthetic-secret\\n")
    else:
        print("synthetic-secret")
else:
    raise AssertionError(name)
''')
    dispatcher.chmod(0o755)
    for name in ("id", "ssh-keyscan", "ssh-keygen", "scp", "ssh", "sudo", "su", "runuser", "velociraptor"):
        (tools / name).symlink_to(dispatcher)
    remote = tmp_path / "remote space's"
    remote.mkdir()
    source = remote / "credential.yaml"
    if existing:
        source.write_text("existing-secret\n")
    key = tmp_path / "key"
    key.touch()
    destination = tmp_path / "cache" / "config.yaml"
    destination.parent.mkdir()
    destination.write_text("old-cache\n")
    log = tmp_path / "commands.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VELO_", "VRAPTOR_"))}
    env.update(HOME=str(tmp_path), AI_SKILLS_REPO_ROOT=str(tmp_path),
               PATH=f"{tools}:{os.defpath}", TEST_LOG=str(log), TEST_IDENTITY=login,
               TEST_RUN_AS=run_as, TEST_DENIED="1",
               VELO_REMOTE_SSH_USER=login, VELO_REMOTE_SSH_KEY=str(key),
               VELO_REMOTE_RUN_AS=run_as, VELO_REMOTE_API_USER="test-investigator",
               VELO_REMOTE_API_CONFIG_PATH=str(source), VELO_REMOTE_CLIENT_CONFIG_PATH=str(source),
               VELO_REMOTE_SERVER_CONFIG_PATH=str(remote / "server.yaml"),
               VELO_LOCAL_CONFIG_ROOT=str(tmp_path / "cache"))
    result = subprocess.run(["bash", str(SCRIPTS / ("fetch_live_api_client.sh" if kind == "api" else "fetch_live_client_config.sh")),
                             "--server-profile", "test", "--server-ip", "server", "--force",
                             "--output-path", str(destination), f"--provision-{kind}",
                             "--json-out", str(tmp_path / "status.json")],
                            env=env, capture_output=True, text=True, timeout=20)
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    if login != "root":
        assert result.returncode == 3
        assert "USER ACTION REQUIRED" in result.stdout
        expected_shell = "sudo su" if run_as == "root" else "sudo -u 'velociraptor' bash"
        assert expected_shell in result.stdout
        assert "Continue" in result.stdout
        manual = json.loads((tmp_path / "status.json").read_text())
        assert manual["status"] == "needs_user_action"
        assert "600" in manual["instructions"]
        assert sum(call[0] == "sudo" for call in calls) == 1
        assert not any(call[0] in {"su", "runuser"} for call in calls)
        assert destination.read_text() == "old-cache\n"
        assert not any(call[0] == "velociraptor" for call in calls)
        assert source.exists() == existing
    else:
        assert result.returncode == 0, result.stderr
        assert destination.read_text() == ("existing-secret\n" if existing else "synthetic-secret\n")
        assert destination.stat().st_mode & 0o777 == 0o600
        assert (any(call[0] == "sudo" for call in calls)) == (login != "root")
        assert sum(call[0] == "velociraptor" for call in calls) == (0 if existing else 1)
        assert source.stat().st_mode & 0o777 == (0o644 if existing else 0o600)
    assert "synthetic-secret" not in result.stdout + result.stderr
    assert "existing-secret" not in result.stdout + result.stderr
    assert not list(destination.parent.glob("*.tmp.*"))


def test_terminal_handoff_pauses_then_copies_after_continue(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    scp = tools / "scp"
    scp.write_text('#!/bin/sh\ncp "$TEST_SOURCE" "$2"\n')
    scp.chmod(0o755)
    source = tmp_path / "operator-created.yaml"
    source.write_text("operator-created-secret\n")
    destination = tmp_path / "download.yaml"
    script = '''source "$TEST_HELPER"
SSH_ARGS=(); SCP_ARGS=(); SSH_TARGET=operator@server; REMOTE_SSH_USER=operator
LOCAL_TEMP_PATH="$TEST_DESTINATION"; PROVISION_API=1
REMOTE_RUN_AS=root; REMOTE_CONFIG_KIND=api; API_USER=test-api; API_ROLES=administrator,api
REMOTE_SERVER_CONFIG_PATH=/etc/velociraptor/server.config.yaml; REMOTE_VELOCIRAPTOR_BIN=velociraptor
remote_dirname() { dirname "$1"; }
GENERATE_REMOTE_COMMAND="echo this-must-not-execute"
manual_remote_config /root/api.yaml
'''
    master, slave = pty.openpty()
    process = subprocess.Popen(["bash", "-c", script], stdin=slave, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env={**os.environ,
                               "PATH": f"{tools}:{os.defpath}", "TEST_SOURCE": str(source),
                               "TEST_DESTINATION": str(destination),
                               "TEST_HELPER": str(SCRIPTS / "remote_config_access.sh")})
    os.close(slave)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.2)
        assert not destination.exists()
        os.write(master, b"y\n")
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr
        assert "USER ACTION REQUIRED" in stdout
        assert "Configuration ready? Continue" in stderr
        assert destination.read_text() == "operator-created-secret\n"
        assert "operator-created-secret" not in stdout + stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


@pytest.mark.parametrize("kind,operation", [("api", "provision"), ("client", "provision"),
                                           ("api", "regenerate"), ("api", "failure")])
@pytest.mark.parametrize("run_as", ["root", "velociraptor"])
@pytest.mark.parametrize("existing", [False, True, "retrieval"])
def test_manual_generation_stages_then_hands_off_without_overwriting_existing(tmp_path, kind, operation, run_as, existing):
    """Execute the displayed generation/copy bodies with mocked sudo, not SSH."""
    tools = tmp_path / "bin"
    tools.mkdir()
    for name, body in {
        "mktemp": 'exec /usr/bin/mktemp -d "$TEST_TEMP_ROOT/config.XXXXXXXX"',
        "sudo": 'exec "$@"',
        "ssh": 'printf "%s\\n" "$@"',
        # The displayed handoff targets Linux; adapt GNU flags on macOS.
        "chown": 'test "$1" = -- && test "$2" = "$REMOTE_SSH_USER" && test -f "$3"',
        "chmod": '[ "$2" != -- ] || set -- "$1" "$3"\nexec /bin/chmod "$@"',
        "velociraptor": '[ "$TEST_GENERATION_FAIL" != 1 ] || exit 1\ncase "$*" in *api_client*) for destination; do :; done; printf "generated\\n" > "$destination";; *) printf "generated\\n";; esac',
    }.items():
        script = tools / name
        script.write_text("#!/bin/sh\n" + body + "\n")
        script.chmod(0o755)
    installed = tmp_path / "server space's"
    installed.mkdir()
    (installed / "server.yaml").write_text("synthetic-server-config\n")
    output = installed / ("test-api_api_client.yaml" if kind == "api" else "dfir_client.config.yaml")
    if existing is True:
        output.write_text("preserved\n")
        output.chmod(0o600)
    retrieved = tmp_path / "retrieval.yaml"
    if existing == "retrieval":
        retrieved.write_text("existing-retrieval\n")
    env = dict(os.environ, PATH=f"{tools}:{os.defpath}", TEST_TEMP_ROOT=str(tmp_path),
               TEST_HELPER=str(SCRIPTS / "remote_config_access.sh"),
               REMOTE_RUN_AS=run_as, REMOTE_CONFIG_KIND=kind, API_USER="test-api",
               API_ROLES="administrator,api", REMOTE_SERVER_CONFIG_PATH=str(installed / "server.yaml"),
               REMOTE_VELOCIRAPTOR_BIN=str(tools / "velociraptor"),
               REMOTE_SSH_USER=pwd.getpwuid(os.getuid()).pw_name,
               TEST_RETRIEVED=str(retrieved), PROVISION_API="1" if kind == "api" else "0",
               PROVISION_CLIENT="1" if kind == "client" else "0",
               REGENERATE_REMOTE_API="1" if operation in {"regenerate", "failure"} else "0",
               TEST_GENERATION_FAIL="1" if operation == "failure" else "0")
    result = subprocess.run(["bash", "-c", '''
source "$TEST_HELPER"
remote_dirname() { dirname "$1"; }
SSH_ARGS=(-o BatchMode=yes -o "UserKnownHostsFile=/tmp/known hosts" -i "/tmp/key's")
SSH_TARGET=operator@server
manual_remote_config "$TEST_RETRIEVED"
'''], env=env, input="", text=True, capture_output=True, timeout=5)
    assert result.returncode == 3
    assert not result.stderr
    lines = result.stdout.splitlines()
    connect = "\n".join(lines[
        lines.index("# 1. Connect to the server.") + 1:
        lines.index("# 2. Open the generation shell (enter your sudo password there).")
    ])
    connected = subprocess.run(["bash", "-c", connect], env=env, check=True,
                               capture_output=True, text=True, timeout=5)
    assert connected.stdout.splitlines() == [
        "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/tmp/known hosts",
        "-i", "/tmp/key's", "operator@server",
    ]
    shell = "sudo su" if run_as == "root" else "sudo -u 'velociraptor' bash"
    assert shell in lines
    body = "\n".join(lines[
        lines.index("# 3. Prepare the configuration. Paste this entire block.") + 1:
        lines.index("# Stop if generation fails; do not run the handoff commands below.")
    ])
    generated = subprocess.run(["bash", "-c", body], env=env, timeout=5)
    if operation == "failure":
        assert generated.returncode != 0
        assert output.exists() == (existing is True)
        if existing is True:
            assert output.read_text() == "preserved\n"
        assert retrieved.exists() == (existing == "retrieval")
        if existing == "retrieval":
            assert retrieved.read_text() == "existing-retrieval\n"
        return
    assert generated.returncode == 0
    reuse_retrieval = existing == "retrieval" and operation == "provision"
    if reuse_retrieval:
        assert not output.exists()
    else:
        assert output.read_text() == ("preserved\n" if existing is True and operation == "provision" else "generated\n")
        assert output.stat().st_mode & 0o777 == 0o600
    assert retrieved.exists() == (existing == "retrieval")
    handoff = "\n".join(lines[lines.index("exit") + 1:lines.index("# 5. Disconnect from the server.")])
    subprocess.run(["bash", "-c", handoff], env=env, check=True, timeout=5)
    assert retrieved.read_text() == ("existing-retrieval\n" if reuse_retrieval else output.read_text())
    assert retrieved.stat().st_mode & 0o777 == 0o600
    assert output.is_file() == (not reuse_retrieval)
    assert not list(tmp_path.glob("config.*"))
