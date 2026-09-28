"""Owned local servers and stable mapped clients for engagement setup.

Native configurations and writebacks remain authoritative. This module only
coordinates their creation, locks, and process ownership on macOS/Linux.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager

import yaml

from .settings import active_value, current
from .readiness_state import api_metadata, credential_security_failures, _canonical_hash
from .common.atomic_io import write_json_atomic as _save, write_text_atomic as _write


SCRIPTS = Path(__file__).parent / "resources/scripts/velociraptor"


class LifecycleError(ValueError):
    pass


@contextmanager
def _locked(workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (workspace / ".setup.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LifecycleError(f"Setup already running in {workspace}") from exc
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _read(path: Path) -> dict:
    return json.loads(path.read_text()) if path.is_file() else {}


def _yaml(path: Path) -> dict:
    try:
        result = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise LifecycleError(f"Cannot read YAML configuration: {path}") from exc
    if not isinstance(result, dict):
        raise LifecycleError(f"Expected YAML object: {path}")
    return result


def _binary(binary: str | None) -> str:
    if not binary:
        from .paths import resolve_velociraptor_binary
        from .resources import repository_root
        binary = resolve_velociraptor_binary(None, repository_root())
    resolved = shutil.which(os.path.expanduser(str(binary)))
    if not resolved:
        raise LifecycleError(f"Velociraptor executable not found: {binary}")
    return str(Path(resolved).resolve())


def _run(argv: list[str], *, timeout: float = 30, cwd: Path | None = None) -> str:
    snapshot = current()
    environment = dict(snapshot.environment) if snapshot else os.environ.copy()
    environment["VRAPTOR_PYTHON"] = sys.executable
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                            env=environment)
    if result.returncode:
        # Configuration commands may print secret material. Never include their
        # captured output in a public exception.
        raise LifecycleError(f"Velociraptor command failed (exit {result.returncode}): {argv[1]}")
    return result.stdout


def _process_identity(pid: int) -> str:
    if pid <= 1:
        return ""
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def _running(process: dict) -> bool:
    return _process_status(process) == "running"


def _process_status(process: dict) -> str:
    actual = _process_identity(int(process.get("pid", 0)))
    if not actual:
        return "stopped"
    return "running" if actual == process.get("identity") else "ownership_error"


def _stop(process: dict):
    if not _running(process):
        return
    pid = int(process["pid"])
    os.kill(pid, signal.SIGTERM)
    until = time.monotonic() + 5
    while _running(process) and time.monotonic() < until:
        time.sleep(0.1)
    if _running(process):
        os.kill(pid, signal.SIGKILL)


def _shell_process(client_dir: Path, kind: str) -> dict:
    try:
        pid = int((client_dir / f"{kind}.pid").read_text().strip())
    except (OSError, ValueError):
        return {}
    identity = client_dir / f"{kind}.pid.identity"
    return {"pid": pid, "identity": identity.read_text().strip() if identity.is_file() else ""}


def _ownership_error(process: dict) -> bool:
    return _process_status(process) == "ownership_error"


def _check_ports(ports: dict):
    if len(set(ports.values())) != len(ports):
        raise LifecycleError("Local server ports must be distinct")
    for name, port in ports.items():
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise LifecycleError(f"Invalid {name} port: {port}")
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as exc:
                raise LifecycleError(f"Local {name} port {port} is already in use; select another port") from exc


def ensure_local_server(workspace: Path, binary: str | None = None, *,
                        api_user: str = "vraptor", frontend_port: int = 8000,
                        api_port: int = 8001, gui_port: int = 8889,
                        timeout: float = 30) -> dict:
    """Create once and start/reuse a loopback-only, setup-owned local server."""
    workspace = Path(workspace).expanduser().resolve()
    binary = _binary(binary)
    ports = {"frontend": frontend_port, "api": api_port, "gui": gui_port}
    with _locked(workspace):
        state_path = workspace / "server.json"
        state = _read(state_path)
        server = workspace / "server.config.yaml"
        api = workspace / "api_client.yaml"
        client = workspace / "client.config.yaml"
        if not state:
            if any(workspace.glob("*.yaml")) or (workspace / "datastore").exists():
                raise LifecycleError("Existing server state is unmanaged; use its API YAML or choose an empty workspace")
            state = {"schema_version": 1, "owned": True, "workspace": str(workspace),
                     "binary": binary, "api_user": api_user, "ports": ports,
                     "server_config": str(server), "api_client": str(api),
                     "client_config": str(client), "mappings": []}
            _save(state_path, state)
        if not state.get("owned") or state.get("ports") != ports or state.get("api_user") != api_user:
            raise LifecycleError("Local server settings differ from saved state; reuse the original settings")
        if state.get("config_sha256") and (not server.is_file() or _hash(server.read_bytes()) != state["config_sha256"]):
            raise LifecycleError("Managed server configuration changed or is missing; restore it before resuming")
        if _running(state.get("process", {})):
            if _api_healthy(binary, api):
                return {**state, "status": "ready"}
            raise LifecycleError("Owned local server is running but its API is unhealthy; inspect server.log")
        _check_ports(ports)
        if not server.is_file():
            patch = {"Frontend": {"hostname": "localhost", "bind_address": "127.0.0.1", "bind_port": frontend_port},
                     "API": {"hostname": "127.0.0.1", "bind_address": "127.0.0.1", "bind_port": api_port},
                     "GUI": {"bind_address": "127.0.0.1", "bind_port": gui_port},
                     "Client": {"server_urls": [f"https://localhost:{frontend_port}/"]},
                     "Datastore": {"location": str(workspace / "datastore"), "filestore_directory": str(workspace / "datastore")},
                     "Logging": {"output_directory": str(workspace / "logs")}}
            generated = _run([binary, "config", "generate", "--merge", json.dumps(patch)], timeout=timeout)
            _write(server, generated)
            snapshot = current()
            password = (snapshot.environment if snapshot else os.environ).get("VELO_LOCAL_API_PASSWORD", "")
            gui_user, gui_password = (api_user, password) if password else ("admin", "password")
            _run([binary, "--config", str(server), "user", "add", "--role", "administrator",
                  gui_user, gui_password], timeout=timeout)
        state["config_sha256"] = _hash(server.read_bytes())
        _save(state_path, state)
        if not client.is_file():
            _write(client, _run([binary, "--config", str(server), "config", "client"], timeout=timeout))
        if not api.is_file():
            temporary = api.with_suffix(".tmp.yaml")
            _run([binary, "--config", str(server), "config", "api_client", "--name", api_user,
                  "--role", "administrator,api", str(temporary)], timeout=timeout)
            temporary.chmod(0o600)
            temporary.replace(api)
        with (workspace / "server.log").open("ab") as log:
            snapshot = current()
            proc = subprocess.Popen([binary, "--config", str(server), "frontend", "--disable-panic-guard"],
                                    cwd=workspace, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True,
                                    env=dict(snapshot.environment) if snapshot else None)
        state["process"] = {"pid": proc.pid, "identity": _process_identity(proc.pid)}
        _save(state_path, state)
        until = time.monotonic() + timeout
        while proc.poll() is None and time.monotonic() < until:
            if _api_healthy(binary, api):
                return {**state, "status": "ready"}
            time.sleep(0.2)
        raise LifecycleError(f"Local server did not become ready; inspect {workspace / 'server.log'} and resume")


def _api_healthy(binary: str, api: Path) -> bool:
    try:
        _run([binary, "-a", str(api), "query", "--format", "json", "SELECT 1 AS ok FROM scope()"], timeout=3)
        return True
    except (LifecycleError, subprocess.TimeoutExpired):
        return False


def local_server_status(workspace: Path) -> dict:
    state = _read(Path(workspace) / "server.json")
    return {**state, "status": _process_status(state.get("process", {}))}


def stop_local_server(workspace: Path) -> dict:
    workspace = Path(workspace).resolve()
    with _locked(workspace):
        state = _read(workspace / "server.json")
        if not state.get("owned"):
            raise LifecycleError("This server is not owned by setup")
        for mapping in state.get("mappings", []):
            with _locked(Path(mapping)):
                status = mapping_status(Path(mapping))
            if status.get("supervisor_process_running") or status.get("client_process_running"):
                raise LifecycleError(f"Local server still has an active mapping: {mapping}")
            if status.get("status") == "ownership_error":
                raise LifecycleError(f"Mapping process ownership needs inspection: {mapping}")
        if _ownership_error(state.get("process", {})):
            raise LifecycleError("Server PID ownership changed; process was preserved")
        _stop(state.get("process", {}))
        state.pop("process", None)
        _save(workspace / "server.json", state)
    return local_server_status(workspace)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def connection_binding(api: Path, client: Path, session: Path | None = None) -> dict:
    """Validate credentials and stable enrollment identity, including old sessions."""
    api_data, client_data = _yaml(api), _yaml(client).get("Client", {})
    if not isinstance(client_data, dict):
        raise LifecycleError("Endpoint configuration requires a Client mapping")
    api_ca = str(api_data.get("ca_certificate") or api_data.get("ca_cert") or "").strip()
    client_ca = str(client_data.get("ca_certificate", "")).strip()
    if not api_ca or api_ca != client_ca:
        raise LifecycleError("API and endpoint client configurations have different or missing CA certificates")
    metadata = api_metadata(api, config=api_data)
    failures = credential_security_failures(metadata)
    if failures:
        raise LifecycleError("API credential validation failed: " + "; ".join(failures))
    binding = {"ca_sha256": _hash(api_ca.encode()), "api_endpoint": metadata["connection"],
               "org_id": metadata["org_id"], "api_identity": metadata["identity"],
               "client_nonce_sha256": _hash(str(client_data.get("nonce", "")).encode())}
    if session and session.is_file():
        saved = dict(line.split("=", 1) for line in session.read_text().splitlines() if "=" in line)
        digest = saved.get("CONFIG_BINDING_SHA256")
        if digest:
            if digest != _canonical_hash(binding):
                raise LifecycleError("Mapping server, organization, API identity or enrollment changed; saved identity was preserved")
        elif (saved.get("API_CONFIG_SHA256") != _hash(api.read_bytes())
              or saved.get("SOURCE_CONFIG_SHA256") != _hash(client.read_bytes())):
            raise LifecycleError("Legacy mapping credentials cannot be verified. Restore the original configurations and resume once before renewing them; saved identity was preserved")
    return binding


def _binding(evidence: Path, api: Path, client: Path, hostname: str, *, session: Path | None = None) -> dict:
    connection = connection_binding(api, client, session)
    stat = evidence.stat()
    # Directory mtimes change during normal mount use. Inode/device distinguish
    # replaced inputs without hashing a potentially multi-terabyte image.
    identity = {"device": stat.st_dev, "inode": stat.st_ino}
    if evidence.is_file():
        identity.update(size=stat.st_size, mtime_ns=stat.st_mtime_ns)
    return {"evidence_path": str(evidence), "evidence_identity": identity, "hostname": hostname,
            "api_client": str(api), "client_config": str(client), **connection}


def validate_output_paths(evidence_path: Path, *outputs: Path) -> None:
    evidence = evidence_path.expanduser().resolve()
    for output in outputs:
        path = output.expanduser().resolve()
        if path == evidence or (evidence.is_dir() and path.is_relative_to(evidence)):
            raise LifecycleError("Setup outputs must be outside the mounted evidence directory or image")


def ensure_mapping(evidence_path: Path, api_client: Path, client_config: Path,
                   workspace: Path, binary: str | None = None, *, hostname: str | None = None,
                   evidence_type: str | None = None) -> dict:
    """Ensure one stable mapped client. Exact enrollment is verified by readiness."""
    evidence, api, client = (Path(value).expanduser().resolve() for value in (evidence_path, api_client, client_config))
    workspace = Path(workspace).expanduser().resolve()
    validate_output_paths(evidence, workspace)
    binary = _binary(binary)
    hostname = hostname or re.sub(r"[^a-z0-9._-]", "-", evidence.stem.lower()).strip(".-") or "mapped-client"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", hostname):
        raise LifecycleError("Mapped hostname must be a simple hostname, without path separators")
    if not evidence.exists() or not os.access(evidence, os.R_OK):
        raise LifecycleError(f"Evidence is missing or unreadable: {evidence}")
    with _locked(workspace):
        state_path = workspace / "mapping.json"
        state = _read(state_path)
        session = workspace / "mapped-clients" / hostname / "session.env"
        binding = _binding(evidence, api, client, hostname, session=session)
        if state and state.get("binding") != binding:
            legacy = {key: value for key, value in binding.items() if key != "api_identity"}
            if state.get("schema_version") != 1 or state.get("binding") != legacy or not session.is_file():
                raise LifecycleError("Mapping evidence, hostname or server binding differs; saved identity was preserved")
        expected_id = state.get("manifest", {}).get("client_id")
        if expected_id:
            writeback = Path(state["client_dir"]) / "Velociraptor.writeback.yaml"
            if not writeback.is_file() or _yaml(writeback).get("client_id") != expected_id:
                raise LifecycleError("Mapped client writeback identity changed or is missing; restore it before resuming")
        if not state and (workspace / "mapped-clients").exists():
            raise LifecycleError("Existing mapping is unmanaged; reuse its original command or choose another workspace")
        from .export_mapping import detect, prepare
        selected_type = detect(evidence, evidence_type or "auto")
        if state.get("evidence_type") and state["evidence_type"] != selected_type:
            raise LifecycleError("Evidence type changed; use a separate mapping workspace")
        state.update(schema_version=2, binding=binding, binary=binary,
                     evidence_type=selected_type,
                     client_dir=str(workspace / "mapped-clients" / hostname))
        _save(state_path, state)
        export = None
        if selected_type in ("velociraptor-export", "velociraptor-kapefiles-zip"):
            export = prepare(evidence, workspace / "mapped-clients" / hostname / "remapping.yaml", binary, hostname)
        # Register references before startup so stopping a shared server cannot
        # overlook an interrupted mapping creation.
        server_state_path = api.parent / "server.json"
        if server_state_path.is_file():
            with _locked(api.parent):
                server = _read(server_state_path)
                if server.get("owned") and server.get("api_client") == str(api):
                    server["mappings"] = sorted(set(server.get("mappings", []) + [str(workspace)]))
                    _save(server_state_path, server)
        manifest = workspace / "mapping-result.json"
        args = ["bash", str(SCRIPTS / "add_remote_mapped_client.sh"), "--api-client", str(api),
                "--client-config", str(client), "--workspace", str(workspace), "--velociraptor-bin", binary,
                "--evidence-type", selected_type,
                "-n", hostname, "--json-out", str(manifest), str(evidence)]
        try:
            _run(args, timeout=active_value("startup_timeout_seconds") or 120, cwd=workspace)
        except (LifecycleError, subprocess.TimeoutExpired) as exc:
            raise LifecycleError(
                f"Mapped startup could not verify its expected identity. Inspect {state['client_dir']}/client.log "
                "and supervisor.log; check configuration/evidence access and that the binary retains --remap impersonation. "
                "Velociraptor 0.77.1 has a known remapping regression; use a corrected build. Saved identity was preserved."
            ) from exc
        result = _read(manifest)
        if not result:
            raise LifecycleError("Mapped-client startup did not produce a manifest")
        result["evidence_type"] = selected_type
        if export:
            result["export_mapping"] = {k: v for k, v in export.items() if k != "verified_files"}
        state["manifest"] = result
        _save(state_path, state)
        return result


def mapping_status(workspace: Path) -> dict:
    workspace = Path(workspace).resolve()
    state = _read(workspace / "mapping.json")
    if not state:
        return {"status": "not_configured"}
    client_dir = Path(state["client_dir"])
    supervisor_status, client_status = (_process_status(_shell_process(client_dir, kind)) for kind in ("supervisor", "client"))
    supervisor, client = supervisor_status == "running", client_status == "running"
    ownership_error = "ownership_error" in (supervisor_status, client_status)
    client_id_path = client_dir / "client.id"
    status = "ownership_error" if ownership_error else "running" if supervisor and client else "stopped"
    status_file = client_dir / "client-status.env"
    reported = "unknown"
    if status_file.is_file():
        reported = next((line.removeprefix("STATE=") for line in status_file.read_text().splitlines()
                         if line.startswith("STATE=")), "unknown")
    return {**state.get("manifest", {}), "status": status,
            "state": reported,
            "client_dir": str(client_dir), "supervisor_process_running": supervisor,
            "client_process_running": client,
            "client_id": client_id_path.read_text().strip() if client_id_path.is_file() else ""}


def stop_mapping(workspace: Path) -> dict:
    workspace = Path(workspace).resolve()
    with _locked(workspace):
        state = _read(workspace / "mapping.json")
        if not state:
            raise LifecycleError("This mapping is not owned by setup")
        client_dir = Path(state["client_dir"]).resolve()
        if not client_dir.is_relative_to(workspace / "mapped-clients"):
            raise LifecycleError("Saved mapping directory is outside its workspace")
        if any(_ownership_error(_shell_process(client_dir, kind)) for kind in ("supervisor", "client")):
            raise LifecycleError("Mapping PID ownership changed; processes were preserved")
        _stop(_shell_process(client_dir, "supervisor"))
        _stop(_shell_process(client_dir, "client"))
    return mapping_status(workspace)


if __name__ == "__main__":
    # Internal bridge for the shell mapping engine; no credential contents leave Python.
    import argparse
    parser = argparse.ArgumentParser(description="Validate mapped-client credential binding")
    parser.add_argument("api", type=Path)
    parser.add_argument("client", type=Path)
    parser.add_argument("session", type=Path)
    args = parser.parse_args()
    try:
        print(_canonical_hash(connection_binding(args.api, args.client, args.session)))
    except (OSError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
