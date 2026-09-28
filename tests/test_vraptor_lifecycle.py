import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vraptor import lifecycle as lc


def write_api(path, *, days=365, **fields):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fields.get("name", "operator"))])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=days)).sign(key, hashes.SHA256()))
    path.write_text(yaml.safe_dump({"name": "operator", "ca_certificate": "test-ca",
        "api_connection_string": "127.0.0.1:8001", "org_id": "root",
        "client_cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "client_private_key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()).decode(), **fields}))
    path.chmod(0o600)


@pytest.fixture
def configs(tmp_path):
    api, client = tmp_path / "api.yaml", tmp_path / "client.yaml"
    write_api(api)
    client.write_text(yaml.safe_dump({"Client": {"ca_certificate": "test-ca", "nonce": "test-nonce"}}))
    evidence = tmp_path / "disk.E01"
    evidence.write_bytes(b"synthetic test evidence")
    return evidence, api, client


@pytest.fixture
def shell_binding(tmp_path, configs):
    evidence, api, client = configs
    client_dir = tmp_path / "mapped-clients/host"
    client_dir.mkdir(parents=True)
    writeback = client_dir / "Velociraptor.writeback.yaml"
    writeback.write_text("client_id: C.retained\nprivate_key: synthetic-original\n")
    # Exercise the actual shell validation and session writer without starting processes.
    script = lc.SCRIPTS / "add_mapped_client.sh"
    definitions, separator, _ = script.read_text().partition('while [ "$#" -gt 0 ]; do')
    assert separator
    harness = tmp_path / "binding.sh"
    harness.write_text(definitions + '''
API_CLIENT_CONFIG="$1"
CLIENT_CONFIG="$2"
EVIDENCE_PATH="$3"
WORKSPACE_DIR="$4"
prepare_remote_client_runtime "$4/mapped-clients/host"
write_session_file "$4/mapped-clients/host/session.env" host "$4/remapping.yaml" "" \
    "$4/mapped-clients/host/client.config.yaml" "$4/client-info.json" pending ""
''')

    def run():
        return subprocess.run(["bash", str(harness), str(api), str(client), str(evidence), str(tmp_path)],
                              capture_output=True, text=True, check=False,
                              env={**os.environ, "VRAPTOR_PYTHON": sys.executable, "VRAPTOR_SETTINGS_RESOLVED": "1"})
    return run, client_dir / "session.env", writeback


def test_shell_credential_renewal_retains_binding_and_writeback(configs, shell_binding):
    _, api, client = configs
    run, session, writeback = shell_binding
    first = run()
    assert first.returncode == 0, first.stderr
    saved = session.read_text()
    original = writeback.read_bytes()
    before = lc.connection_binding(api, client)
    write_api(api)
    client.write_text('# reformatted endpoint config\n' + client.read_text())
    assert lc.connection_binding(api, client, session) == before
    renewed = run()
    assert renewed.returncode == 0, renewed.stderr
    assert 'CONFIG_BINDING_SHA256=' in saved
    assert 'API_CONFIG_SHA256=' not in session.read_text()
    assert writeback.read_bytes() == original


@pytest.mark.parametrize("change", ["endpoint", "org", "name", "ca", "nonce", "expired", "permissions"])
def test_shell_rejects_changed_identity_and_invalid_credentials(configs, shell_binding, change):
    _, api, client = configs
    run, session, writeback = shell_binding
    assert run().returncode == 0
    original, original_session = writeback.read_bytes(), session.read_bytes()
    if change in {"endpoint", "org", "name"}:
        field = {"endpoint": "api_connection_string", "org": "org_id", "name": "name"}[change]
        write_api(api, **{field: "different"})
    elif change in {"ca", "nonce"}:
        data = yaml.safe_load(client.read_text())
        field = "ca_certificate" if change == "ca" else "nonce"
        data["Client"][field] = "different"
        client.write_text(yaml.safe_dump(data))
        if change == "ca":
            write_api(api, ca_certificate="different")
    elif change == "expired":
        write_api(api, days=-1)
    else:
        api.chmod(0o644)
    result = run()
    assert result.returncode != 0
    assert "saved identity was preserved" in result.stderr
    assert session.read_bytes() == original_session
    assert writeback.read_bytes() == original
    assert "PRIVATE KEY" not in result.stderr


@pytest.mark.parametrize("changed", [False, True])
def test_legacy_shell_hashes_upgrade_only_with_original_credentials(configs, shell_binding, changed):
    evidence, api, client = configs
    run, session, writeback = shell_binding
    session.write_text(f'API_CLIENT_CONFIG={api}\nSOURCE_CLIENT_CONFIG={client}\nEVIDENCE_PATH={evidence}\n'
                       f'API_CONFIG_SHA256={lc._hash(api.read_bytes())}\nSOURCE_CONFIG_SHA256={lc._hash(client.read_bytes())}\n')
    original, original_session = writeback.read_bytes(), session.read_bytes()
    if changed:
        write_api(api)
    result = run()
    if changed:
        assert result.returncode != 0
        assert "Legacy mapping credentials cannot be verified" in result.stderr
        assert session.read_bytes() == original_session
    else:
        assert result.returncode == 0, result.stderr
        assert 'CONFIG_BINDING_SHA256=' in session.read_text()
        write_api(api)
        result = run()
        assert result.returncode == 0, result.stderr
    assert writeback.read_bytes() == original


def test_create_reuse_mapping_and_preserve_state_on_mismatch(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    workspace = tmp_path / "mapping"
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        client_dir = Path(lc._read(workspace / "mapping.json")["client_dir"])
        client_dir.mkdir(parents=True, exist_ok=True)
        (client_dir / "Velociraptor.writeback.yaml").write_text("client_id: C.test\n")
        result = Path(args[args.index("--json-out") + 1])
        result.write_text(json.dumps({"client_id": "C.test", "status": "ready"}))
        return ""

    monkeypatch.setattr(lc, "_binary", lambda value: value)
    monkeypatch.setattr(lc, "_run", run)
    first = lc.ensure_mapping(evidence, api, client, workspace)
    original = (workspace / "mapping.json").read_bytes()
    assert lc.ensure_mapping(evidence, api, client, workspace) == first
    assert len(calls) == 2
    evidence.write_bytes(b"changed evidence")
    with pytest.raises(lc.LifecycleError, match="binding differs"):
        lc.ensure_mapping(evidence, api, client, workspace)
    assert (workspace / "mapping.json").read_bytes() == original
    assert len(calls) == 2


@pytest.mark.parametrize("timeout", [120, 300])
def test_mapping_startup_uses_resolved_timeout(tmp_path, configs, monkeypatch, timeout):
    from unittest.mock import Mock
    from vraptor import settings

    evidence, api, client = configs
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    run = Mock(side_effect=RuntimeError("stop before process"))
    monkeypatch.setattr(lc, "_run", run)
    snapshot = settings.resolve(repo_root=tmp_path, process_environment={"HOME": str(tmp_path)},
                                overrides={"startup_timeout_seconds": timeout})
    with settings.activate(snapshot), pytest.raises(RuntimeError, match="stop before process"):
        lc.ensure_mapping(evidence, api, client, tmp_path / "mapping")
    assert run.call_args.kwargs["timeout"] == timeout


@pytest.mark.parametrize("proof", ["matches", "renewed", "missing"])
def test_legacy_mapping_upgrade_requires_session_proof(tmp_path, configs, monkeypatch, proof):
    evidence, api, client = configs
    workspace = tmp_path / "mapping"
    client_dir = workspace / "mapped-clients/disk"
    client_dir.mkdir(parents=True)
    old_binding = lc._binding(evidence, api, client, "disk")
    old_binding.pop("api_identity")
    lc._save(workspace / "mapping.json", {"schema_version": 1, "binding": old_binding})
    if proof != "missing":
        (client_dir / "session.env").write_text(
            f'API_CONFIG_SHA256={lc._hash(api.read_bytes())}\nSOURCE_CONFIG_SHA256={lc._hash(client.read_bytes())}\n')
    before = (workspace / "mapping.json").read_bytes()
    if proof == "renewed":
        write_api(api)
    monkeypatch.setattr(lc, "_binary", lambda value: value)

    def run(*a, **kw):
        lc._save(workspace / "mapping-result.json", {"client_id": "C.kept"})
        return ""

    with patch.object(lc, "_run", side_effect=run) as launch:
        if proof == "matches":
            lc.ensure_mapping(evidence, api, client, workspace, hostname="disk")
            state = lc._read(workspace / "mapping.json")
            assert state["schema_version"] == 2
            assert state["binding"]["api_identity"] == "operator"
        else:
            with pytest.raises(lc.LifecycleError, match="preserved"):
                lc.ensure_mapping(evidence, api, client, workspace, hostname="disk")
            assert (workspace / "mapping.json").read_bytes() == before
            launch.assert_not_called()


def test_mapping_rejects_mismatched_ca_before_launch(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    client.write_text(yaml.safe_dump({"Client": {"ca_certificate": "other-ca"}}))
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    with patch.object(lc, "_run") as run, pytest.raises(lc.LifecycleError, match="CA certificates"):
        lc.ensure_mapping(evidence, api, client, tmp_path / "mapping")
    run.assert_not_called()


def test_mapping_rejects_runtime_inside_mounted_evidence_without_writes(tmp_path, configs):
    _, api, client = configs
    evidence = tmp_path / "mounted-evidence"
    evidence.mkdir()
    workspace = evidence / "runtime"
    with patch.object(lc, "_run") as run, pytest.raises(lc.LifecycleError, match="outside the mounted evidence"):
        lc.ensure_mapping(evidence, api, client, workspace)
    run.assert_not_called()
    assert not list(evidence.iterdir())


def test_mapping_rejects_org_nonce_and_hostname_changes(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    workspace = tmp_path / "mapping"
    workspace.mkdir()
    binding = lc._binding(evidence, api, client, "original")
    lc._save(workspace / "mapping.json", {"binding": binding})
    with pytest.raises(lc.LifecycleError, match="binding differs"):
        lc.ensure_mapping(evidence, api, client, workspace, hostname="different")
    client.write_text(yaml.safe_dump({"Client": {"ca_certificate": "test-ca", "nonce": "other-org"}}))
    with pytest.raises(lc.LifecycleError, match="binding differs"):
        lc.ensure_mapping(evidence, api, client, workspace, hostname="original")


def test_failed_start_leaves_binding_for_safe_resume(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    workspace = tmp_path / "mapping"
    with patch.object(lc, "_run", side_effect=lc.LifecycleError("interrupted")):
        with pytest.raises(lc.LifecycleError, match="Saved identity was preserved"):
            lc.ensure_mapping(evidence, api, client, workspace)
    state = lc._read(workspace / "mapping.json")
    assert state["binding"]["evidence_path"] == str(evidence)
    with lc._locked(workspace):
        pass  # Failed startup released its lock.


def test_unmanaged_mapping_is_not_adopted(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    workspace = tmp_path / "mapping"
    (workspace / "mapped-clients").mkdir(parents=True)
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    with pytest.raises(lc.LifecycleError, match="unmanaged"):
        lc.ensure_mapping(evidence, api, client, workspace)


def test_workspace_lock_rejects_concurrent_operation(tmp_path):
    with lc._locked(tmp_path):
        with pytest.raises(lc.LifecycleError, match="already running"):
            with lc._locked(tmp_path):
                pass


def test_pid_reuse_never_signals_unrelated_process():
    process = {"pid": os.getpid(), "identity": "an earlier process start and command"}
    with patch.object(os, "kill") as kill:
        lc._stop(process)
    kill.assert_not_called()


def test_local_server_rejects_used_port_without_signaling(tmp_path, monkeypatch):
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    with socket.socket() as sock, patch.object(os, "kill") as kill:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        with pytest.raises(lc.LifecycleError, match="already in use"):
            lc.ensure_local_server(tmp_path, api_port=port)
    kill.assert_not_called()


def test_managed_server_never_adopts_existing_config(tmp_path, monkeypatch):
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    config = tmp_path / "server.config.yaml"
    config.write_text("existing server")
    with pytest.raises(lc.LifecycleError, match="unmanaged"):
        lc.ensure_local_server(tmp_path)
    assert config.read_text() == "existing server"


def test_new_local_server_uses_default_gui_credentials_without_override(tmp_path, monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1:3] == ["config", "generate"]:
            return "GUI:\n  authenticator:\n    type: Basic\n"
        if "api_client" in args:
            Path(args[-1]).write_text("name: vraptor\n")
        return ""

    class Process:
        pid = 4321

        @staticmethod
        def poll():
            return None

    monkeypatch.delenv("VELO_LOCAL_API_PASSWORD", raising=False)
    monkeypatch.setattr(lc, "_binary", lambda value: value or "velociraptor")
    monkeypatch.setattr(lc, "_check_ports", lambda ports: None)
    monkeypatch.setattr(lc, "_run", run)
    monkeypatch.setattr(lc, "_process_identity", lambda pid: "test-server")
    monkeypatch.setattr(lc, "_api_healthy", lambda binary, api: True)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())

    lc.ensure_local_server(tmp_path)

    assert ["velociraptor", "--config", str(tmp_path / "server.config.yaml"), "user", "add",
            "--role", "administrator", "admin", "password"] in calls


def test_server_stop_refuses_active_mapping(tmp_path):
    lc._save(tmp_path / "server.json", {"owned": True, "mappings": [str(tmp_path / "mapping")], "process": {}})
    with patch.object(lc, "mapping_status", return_value={"client_process_running": True}), patch.object(lc, "_stop") as stop:
        with pytest.raises(lc.LifecycleError, match="active mapping"):
            lc.stop_local_server(tmp_path)
    stop.assert_not_called()


@pytest.mark.parametrize("escape", ["absolute", "traversal", "symlink"])
def test_stop_mapping_cannot_escape_owned_workspace(tmp_path, escape):
    workspace = tmp_path / "runtime"
    mapped = workspace / "mapped-clients"
    mapped.mkdir(parents=True)
    outside = tmp_path / "unrelated"
    outside.mkdir()
    if escape == "absolute":
        client_dir = outside
    elif escape == "traversal":
        client_dir = mapped / ".." / ".." / "unrelated"
    else:
        client_dir = mapped / "link"
        client_dir.symlink_to(outside, target_is_directory=True)
    lc._save(workspace / "mapping.json", {"client_dir": str(client_dir)})
    with (
        patch.object(lc, "_shell_process") as processes,
        patch.object(lc, "_stop") as stop,
        pytest.raises(lc.LifecycleError, match="outside"),
    ):
        lc.stop_mapping(workspace)
    processes.assert_not_called()
    stop.assert_not_called()


def test_stop_mapping_reports_unverifiable_pid_without_signaling(tmp_path):
    client_dir = tmp_path / "mapped-clients/disk"
    client_dir.mkdir(parents=True)
    (client_dir / "client.pid").write_text(str(os.getpid()))
    lc._save(tmp_path / "mapping.json", {"client_dir": str(client_dir)})
    assert lc.mapping_status(tmp_path)["status"] == "ownership_error"
    with patch.object(os, "kill") as kill, pytest.raises(lc.LifecycleError, match="ownership changed"):
        lc.stop_mapping(tmp_path)
    kill.assert_not_called()


def test_server_stop_rejects_mapping_setup_in_progress(tmp_path):
    mapping = tmp_path / "mapping"
    lc._save(tmp_path / "server.json", {"owned": True, "mappings": [str(mapping)]})
    with lc._locked(mapping), pytest.raises(lc.LifecycleError, match="already running"):
        lc.stop_local_server(tmp_path)


def test_resume_rejects_missing_writeback_before_enrollment(tmp_path, configs, monkeypatch):
    evidence, api, client = configs
    monkeypatch.setattr(lc, "_binary", lambda value: value)
    workspace = tmp_path / "mapping"
    workspace.mkdir()
    lc._save(workspace / "mapping.json", {"binding": lc._binding(evidence, api, client, "disk"),
             "manifest": {"client_id": "C.original"}, "client_dir": str(workspace / "mapped-clients/disk")})
    with patch.object(lc, "_run") as run, pytest.raises(lc.LifecycleError, match="writeback identity"):
        lc.ensure_mapping(evidence, api, client, workspace)
    run.assert_not_called()


def test_stopped_mapping_retains_native_identity(tmp_path):
    client_dir = tmp_path / "mapped-clients/disk"
    client_dir.mkdir(parents=True)
    writeback = client_dir / "Velociraptor.writeback.yaml"
    writeback.write_text("client_id: C.test\nprivate_key: test-only\n")
    (client_dir / "client.id").write_text("C.test\n")
    lc._save(tmp_path / "mapping.json", {"client_dir": str(client_dir)})
    before = writeback.read_bytes()
    assert lc.stop_mapping(tmp_path)["status"] == "stopped"
    assert writeback.read_bytes() == before
    assert lc.mapping_status(tmp_path)["client_id"] == "C.test"


def test_command_errors_do_not_expose_native_config_secrets():
    completed = subprocess.CompletedProcess(["velociraptor"], 1, "secret private key", "secret token")
    with patch.object(subprocess, "run", return_value=completed):
        with pytest.raises(lc.LifecycleError) as error:
            lc._run(["velociraptor", "config", "generate"])
    assert "secret" not in str(error.value)


def test_json_state_private_and_atomic(tmp_path):
    path = tmp_path / "state.json"
    lc._save(path, {"value": 1})
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == {"value": 1}
    assert not path.with_name("state.json.tmp").exists()
