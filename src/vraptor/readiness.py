#!/usr/bin/env python3
from __future__ import annotations

from vraptor.resources import resource_root

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from vraptor.common import atomic_io
from vraptor.common.labels import parse_label_values
from vraptor import case_layout

SCRIPT_DIR = Path(__file__).resolve().parent
from vraptor.resources import repository_root
REPO_ROOT = repository_root()


from vraptor.paths import add_case_root_arg
from vraptor.paths import resolve_case_root
from vraptor.paths import resolve_velociraptor_api_client_path
from vraptor.paths import resolve_velociraptor_binary
from vraptor.paths import resolve_velociraptor_client_config_path
from vraptor import readiness_state as engagement_state
from vraptor import context as engagement_context
from vraptor.logging import operations as operation_log
from vraptor.api import VeloApiClient

FETCH_LIVE_API_CLIENT_SCRIPT = (
    resource_root() / "scripts"
    / "velociraptor"
    / "fetch_live_api_client.sh"
)
ADD_REMOTE_MAPPED_CLIENT_SCRIPT = (
    resource_root() / "scripts"
    / "velociraptor"
    / "add_remote_mapped_client.sh"
)
MAPPED_CLIENT_STATUS_SCRIPT = (
    resource_root() / "scripts"
    / "velociraptor"
    / "mapped_client_status.sh"
)
MAPPED_CLIENT_READY_WAIT_SECONDS = 45
MAPPED_CLIENT_TERMINAL_STATES = {
    "backoff",
    "evidence_unavailable",
    "identity_error",
    "process_dead",
    "server_unreachable",
    "supervisor_dead",
}

def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    from vraptor.settings import current
    snapshot = current()
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env if env is not None else dict(snapshot.environment) if snapshot else None,
        **({"timeout": timeout} if timeout is not None else {}),
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def validate_api_client_security(path: Path) -> dict[str, Any]:
    metadata = engagement_state.api_metadata(path)
    failures = engagement_state.credential_security_failures(metadata)
    if failures:
        raise RuntimeError(
            "Velociraptor API credential validation failed: "
            + "; ".join(failures)
        )
    security = dict(metadata.get("credential_security") or {})
    status_value = str(security.get("certificate_status") or "")
    operation_log.emit(
        "credential_validated",
        level="warning" if status_value == "expiring" else "info",
        component="engagement_setup",
        stage="credential_validation",
        status="warning" if status_value == "expiring" else "complete",
        certificate_status=status_value,
        certificate_days_remaining=security.get("certificate_days_remaining"),
    )
    return metadata


def build_leaf_manifest_path(manifest_out: str | None, prefix: str) -> Path:
    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=".json", delete=False) as tmp_file:
        return Path(tmp_file.name)


@contextmanager
def managed_leaf_manifest_path(
    manifest_out: str | None,
    prefix: str,
) -> Iterator[Path]:
    path = build_leaf_manifest_path(manifest_out, prefix)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def read_leaf_manifest(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Leaf manifest was not created: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Leaf manifest is not valid JSON: {path}") from exc


def ensure_local_runtime(api_client_path: Path) -> None:
    binary = local_binary()
    binary_path = Path(binary)
    if not binary_path.is_file() and shutil.which(binary) is None:
        raise RuntimeError(
            "Velociraptor executable not found. Install ~/velociraptor/velociraptor or configure workstation.binary / VELO_BIN."
        )
    if not api_client_path.is_file():
        raise RuntimeError(
            f"Velociraptor API client config not found: {api_client_path}. "
            "Set VELO_LOCAL_API_CLIENT or pass --api-client."
        )
    validate_api_client_security(api_client_path)


def local_binary() -> str:
    from vraptor.settings import active_value
    return active_value("velociraptor_bin") or resolve_velociraptor_binary(None, REPO_ROOT)


def local_query(api_config_path: Path, query: str) -> list[dict[str, Any]]:
    from vraptor.settings import active_value
    org_args = ["--org", active_value("org_id")] if active_value("org_id") else []
    command = [
        local_binary(),
        *org_args,
        "--api_config",
        str(api_config_path),
        "query",
        "--format",
        "json",
        query,
    ]
    result = run_command(command)
    if result.returncode != 0:
        command = [
            local_binary(),
            *org_args,
            "--api_config",
            str(api_config_path),
            "--runas",
            "api",
            "query",
            "--format",
            "json",
            query,
        ]
        result = run_command(command)
    if result.returncode != 0:
        raise RuntimeError(
            "Velociraptor query failed.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Velociraptor query did not return valid JSON.\n{result.stdout}") from exc
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise RuntimeError("Unexpected Velociraptor query payload shape.")


def remote_query(api_config_path: Path, query: str) -> list[dict[str, Any]]:
    try:
        with VeloApiClient(api_config_path) as client:
            return client.query(query)
    except Exception as exc:
        raise RuntimeError(f"Remote Velociraptor API query failed: {exc}") from exc


def selected_engagement_id(args: argparse.Namespace) -> str:
    return engagement_context.effective_engagement_id(
        getattr(args, "engagement_id", None),
        selected_server_profile(args),
    )[0]


def selected_engagement_id_source(args: argparse.Namespace) -> str:
    return engagement_context.effective_engagement_id(
        getattr(args, "engagement_id", None),
        selected_server_profile(args),
    )[1]


def selected_server_profile(args: argparse.Namespace) -> str:
    selected = str(
        getattr(args, "server_profile", None)
        or getattr(args, "engagement_code", None)
        or ""
    ).strip()
    if selected:
        return selected
    if str(getattr(args, "command", "")) != "live-remote":
        return str(getattr(args, "engagement_id", None) or "").strip()
    return ""


def selected_engagement_state_path(args: argparse.Namespace) -> Path:
    explicit = str(getattr(args, "manifest_out", None) or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    return engagement_state.state_path(
        resolve_case_root(getattr(args, "case_root", None), REPO_ROOT),
        selected_engagement_id(args),
    )


def publish_mapped_system_state(
    args: argparse.Namespace,
    payload: dict[str, Any],
) -> str:
    mode = str(payload.get("mode") or "")
    if mode not in {"local_dead_disk", "remote_dead_disk"}:
        return ""
    readiness = dict(payload.get("readiness") or {})
    targets = [
        dict(item)
        for item in readiness.get("targets") or []
        if isinstance(item, dict)
    ]
    if not targets:
        return ""
    target = targets[0]
    hostname = str(target.get("hostname") or "").strip()
    if not hostname:
        return ""
    engagement_id = selected_engagement_id(args)
    root = resolve_case_root(getattr(args, "case_root", None), REPO_ROOT)
    path = case_layout.system_dir(root, engagement_id, hostname) / "system.json"
    mapped = dict(readiness.get("mapped_client") or {})
    evidence_path = str(
        mapped.get("evidence_path")
        or getattr(args, "evidence_path", None)
        or ""
    )
    atomic_io.write_json_atomic(
        path,
        {
            "layout_version": 3,
            "hostname": hostname,
            "velociraptor_client_ids": [str(target.get("client_id") or "")],
            "source_mode": mode,
            "evidence_path": evidence_path,
            "mapped_client": mapped,
            "updated_at": str(payload.get("verified_at") or ""),
        },
        sort_keys=True,
    )
    return str(path)


def verify_api_reachable(config_path: Path, *, use_local_cli: bool) -> bool:
    query_fn = local_query if use_local_cli else remote_query
    rows = query_fn(config_path, "SELECT 1 AS ok FROM scope()")
    return bool(rows)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted({str(item).strip().lower() for item in value if str(item).strip()})
    return sorted(
        {
            item.strip().lower()
            for item in str(value or "").split(",")
            if item.strip()
        }
    )


def verify_api_authorization(
    config_path: Path,
    *,
    api_user: str,
    role_profile: str,
) -> dict[str, Any]:
    """Read the API principal's actual roles and effective policy from the server."""

    rows = remote_query(
        config_path,
        "SELECT name, roles, effective_policy FROM gui_users() WHERE name = whoami()",
    )
    if not rows:
        raise RuntimeError("Could not verify the live API user's server-side roles.")
    row = dict(rows[0])
    returned_user = str(row.get("name") or row.get("Name") or "").strip()
    if returned_user and returned_user != api_user:
        raise RuntimeError("Live API role verification returned a different identity.")
    roles = _string_list(row.get("roles") or row.get("Roles"))
    policy_value = (
        row.get("effective_policy")
        or row.get("_EffectivePolicy")
        or row.get("EffectivePolicy")
        or {}
    )
    if isinstance(policy_value, str):
        try:
            policy_value = json.loads(policy_value)
        except json.JSONDecodeError:
            policy_value = {}
    effective_permissions = sorted(
        str(key).upper()
        for key, value in dict(policy_value or {}).items()
        if value is True
    )
    required_roles = {
        "investigation": {"investigator", "api"},
        "provisioning-admin": {"administrator", "api"},
    }[role_profile]
    missing = sorted(required_roles - set(roles))
    if missing:
        raise RuntimeError(
            f"Live API role profile {role_profile} is missing required roles: "
            + ", ".join(missing)
        )
    if role_profile == "investigation" and "administrator" in roles:
        raise RuntimeError(
            "Live API credential has administrator but the investigation profile "
            "was selected. Use a least-privilege credential or explicitly select "
            "--api-role-profile provisioning-admin."
        )
    effective = set(effective_permissions)
    if role_profile == "investigation":
        required_permissions = {
            "ANY_QUERY",
            "READ_RESULTS",
            "COLLECT_CLIENT",
            "START_HUNT",
        }
        missing_permissions = sorted(required_permissions - effective)
        if missing_permissions:
            raise RuntimeError(
                "Investigation API credential is missing effective permissions: "
                + ", ".join(missing_permissions)
            )
    elif not {"SUPER_USER", "SERVER_ADMIN"} & effective:
        raise RuntimeError(
            "Provisioning-admin API credential does not report an effective "
            "administrator capability."
        )
    return {
        "status": "verified",
        "api_user": api_user,
        "role_profile": role_profile,
        "roles": roles,
        "effective_permissions": effective_permissions,
        "required_capabilities": [
            "ANY_QUERY",
            "READ_RESULTS",
            "COLLECT_CLIENT",
            "START_HUNT",
        ]
        if role_profile == "investigation"
        else ["SUPER_USER_OR_SERVER_ADMIN"],
        "verification_source": "server_role_query",
    }


def verify_hostname_visible(config_path: Path, hostname: str, *, use_local_cli: bool) -> dict[str, Any]:
    escaped = hostname.replace("\\", "\\\\").replace("'", "\\'")
    query = (
        "SELECT client_id, "
        "os_info.hostname AS Hostname, "
        "os_info.fqdn AS Fqdn, "
        "timestamp(epoch=last_seen_at) AS LastSeen "
        f"FROM clients() WHERE os_info.hostname =~ '^{escaped}$' OR os_info.fqdn =~ '^{escaped}$' "
        "ORDER BY LastSeen DESC LIMIT 1"
    )
    query_fn = local_query if use_local_cli else remote_query
    rows = query_fn(config_path, query)
    if not rows:
        return {
            "target_visible": False,
            "client_id": "",
            "hostname": hostname,
            "last_seen": "",
        }
    row = rows[0]
    return {
        "target_visible": True,
        "client_id": str(row.get("client_id") or ""),
        "hostname": str(row.get("Hostname") or row.get("Fqdn") or hostname),
        "last_seen": str(row.get("LastSeen") or ""),
        "scope_type": "hostname",
        "requested_hostname": hostname,
    }


def verify_client_id_visible(config_path: Path, client_id: str, *, use_local_cli: bool) -> dict[str, Any]:
    escaped = client_id.replace("\\", "\\\\").replace("'", "\\'")
    query = (
        "SELECT client_id, "
        "os_info.hostname AS Hostname, "
        "os_info.fqdn AS Fqdn, "
        "timestamp(epoch=last_seen_at) AS LastSeen "
        f"FROM clients() WHERE client_id =~ '^{escaped}$' "
        "ORDER BY LastSeen DESC LIMIT 1"
    )
    query_fn = local_query if use_local_cli else remote_query
    rows = query_fn(config_path, query)
    if not rows:
        return {
            "target_visible": False,
            "client_id": client_id,
            "hostname": "",
            "last_seen": "",
            "scope_type": "client_id",
            "requested_client_id": client_id,
        }
    row = rows[0]
    return {
        "target_visible": True,
        "client_id": str(row.get("client_id") or client_id),
        "hostname": str(row.get("Hostname") or row.get("Fqdn") or ""),
        "last_seen": str(row.get("LastSeen") or ""),
        "scope_type": "client_id",
        "requested_client_id": client_id,
    }


def verify_any_client_visible(config_path: Path, *, use_local_cli: bool) -> dict[str, Any]:
    query = (
        "SELECT client_id, "
        "os_info.hostname AS Hostname, "
        "timestamp(epoch=last_seen_at) AS LastSeen "
        "FROM clients() ORDER BY LastSeen DESC LIMIT 1"
    )
    query_fn = local_query if use_local_cli else remote_query
    rows = query_fn(config_path, query)
    if not rows:
        return {
            "target_visible": False,
            "client_id": "",
            "hostname": "",
            "last_seen": "",
        }
    row = rows[0]
    return {
        "target_visible": True,
        "client_id": str(row.get("client_id") or ""),
        "hostname": str(row.get("Hostname") or ""),
        "last_seen": str(row.get("LastSeen") or ""),
        "scope_type": "environment_only",
    }


def verify_label_scope_visible(
    config_path: Path,
    include_labels: list[str],
    exclude_labels: list[str],
    *,
    use_local_cli: bool,
) -> dict[str, Any]:
    required = {label.strip() for label in include_labels if label.strip()}
    excluded = {label.strip() for label in exclude_labels if label.strip()}
    query = (
        "SELECT client_id, "
        "os_info.hostname AS Hostname, "
        "os_info.fqdn AS Fqdn, "
        "labels AS Labels, "
        "timestamp(epoch=last_seen_at) AS LastSeen "
        "FROM clients() ORDER BY last_seen_at DESC"
    )
    query_fn = local_query if use_local_cli else remote_query
    rows = query_fn(config_path, query)
    targets: list[dict[str, str]] = []
    matched_labels: set[str] = set()
    for row in rows:
        labels = parse_label_values(row.get("Labels"))
        if required and not required.issubset(labels):
            continue
        if excluded and excluded.intersection(labels):
            continue
        targets.append(
            {
                "client_id": str(row.get("client_id") or ""),
                "hostname": str(row.get("Hostname") or row.get("Fqdn") or ""),
                "last_seen": str(row.get("LastSeen") or ""),
            }
        )
        matched_labels.update(labels)
    if targets:
        return {
            "target_visible": True,
            "matched_client_count": len(targets),
            "scope_type": "label_scope",
            "requested_host_labels": sorted(required),
            "requested_exclude_host_labels": sorted(excluded),
            "matched_host_labels": sorted(matched_labels),
        }
    return {
        "target_visible": False,
        "client_id": "",
        "hostname": "",
        "last_seen": "",
        "scope_type": "label_scope",
        "matched_client_count": 0,
        "requested_host_labels": sorted(required),
        "requested_exclude_host_labels": sorted(excluded),
        "matched_host_labels": [],
    }


def mapped_client_status(workspace: Path, client_name: str) -> dict[str, Any]:
    result = run_command(
        [
            "bash",
            str(MAPPED_CLIENT_STATUS_SCRIPT),
            "--workspace",
            str(workspace),
            "--client",
            client_name,
            "--json",
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Mapped-client status failed.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Mapped-client status did not return valid JSON.\n{result.stdout}"
        ) from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise RuntimeError("Mapped-client status did not return exactly one client record.")
    return payload[0]


def wait_for_mapped_client_ready(
    workspace: Path,
    client_name: str,
    *,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    from vraptor.settings import active_value, _validate_value
    if timeout_seconds is None:
        timeout_seconds = active_value("ready_timeout_seconds") or MAPPED_CLIENT_READY_WAIT_SECONDS
    _validate_value("ready_timeout_seconds", timeout_seconds, "positive")
    deadline = time.monotonic() + timeout_seconds
    last_status: dict[str, Any] = {}
    while True:
        last_status = mapped_client_status(workspace, client_name)
        state = str(last_status.get("state") or "")
        client_running = bool(last_status.get("client_process_running"))
        supervisor_running = bool(last_status.get("supervisor_process_running"))
        if state == "online" and client_running and supervisor_running:
            return last_status
        if state in MAPPED_CLIENT_TERMINAL_STATES:
            raise RuntimeError(
                f"Mapped-client health state is not ready: {state}"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Mapped client did not reach online state within "
                f"{timeout_seconds} seconds: "
                f"state={state or 'unknown'}, "
                f"client_process_running={client_running}, "
                f"supervisor_process_running={supervisor_running}"
            )
        time.sleep(1)


def build_unified_manifest(
    *,
    engagement_id: str,
    engagement_id_source: str,
    server_profile: str,
    mode: str,
    source_skill: str,
    api_client_path: Path,
    verification: dict[str, Any],
    next_step_hint: str,
) -> dict[str, Any]:
    return engagement_state.build_state(
        engagement_id=engagement_id,
        engagement_id_source=engagement_id_source,
        server_profile=server_profile,
        mode=mode,
        source_skill=source_skill,
        api_client_path=api_client_path,
        verification=verification,
        next_step_hint=next_step_hint,
    )


def command_local_deaddisk(args: argparse.Namespace) -> dict[str, Any]:
    api_client_path = resolve_velociraptor_api_client_path(
        args.api_client,
        REPO_ROOT,
        server_profile=selected_server_profile(args),
    )
    ensure_local_runtime(api_client_path)
    if not args.client_id and not args.hostname:
        raise RuntimeError("Local readiness requires --client-id or --hostname for explicit target verification.")
    with managed_leaf_manifest_path(
        args.manifest_out,
        "velo-engage-local-",
    ) as leaf_manifest_path:
        server_reachable = verify_api_reachable(api_client_path, use_local_cli=True)
        if args.client_id:
            target = verify_client_id_visible(api_client_path, args.client_id, use_local_cli=True)
        else:
            target = verify_hostname_visible(api_client_path, args.hostname, use_local_cli=True)
        if not server_reachable:
            raise RuntimeError("Local Velociraptor API did not answer.")
        if not target["target_visible"]:
            raise RuntimeError("Requested local client is not visible through the Velociraptor API.")
        write_json(
            leaf_manifest_path,
            {
                "status": "verified",
                "api_client_config": str(api_client_path),
                "evidence_path": str(args.evidence_path or ""),
                "client_id": str(target.get("client_id") or ""),
                "hostname": str(target.get("hostname") or ""),
            },
        )
        return build_unified_manifest(
            engagement_id=selected_engagement_id(args),
            engagement_id_source=selected_engagement_id_source(args),
            server_profile=selected_server_profile(args),
            mode="local_dead_disk",
            source_skill="velociraptor-engagement-setup",
            api_client_path=api_client_path,
            verification={
                "server_reachable": server_reachable,
                **target,
            },
            next_step_hint="Proceed to velociraptor-collection for one-host deep dive or velociraptor-hunting if scope is still cross-host.",
        )


def command_remote_deaddisk(args: argparse.Namespace) -> dict[str, Any]:
    with managed_leaf_manifest_path(
        args.manifest_out,
        "velo-engage-remote-disk-",
    ) as leaf_manifest_path:
        return _command_remote_deaddisk(args, leaf_manifest_path)


def _command_remote_deaddisk(
    args: argparse.Namespace,
    leaf_manifest_path: Path,
) -> dict[str, Any]:
    evidence_path = Path(args.evidence_path).expanduser().resolve()
    profile = selected_server_profile(args)
    api_client_path = resolve_velociraptor_api_client_path(
        args.api_client,
        REPO_ROOT,
        server_profile=profile,
    )
    client_config_path = resolve_velociraptor_client_config_path(
        args.client_config,
        REPO_ROOT,
        server_profile=profile,
    )
    for label, path in (
        ("Evidence", evidence_path),
        ("API client config", api_client_path),
        ("Client config", client_config_path),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} does not exist: {path}")
    validate_api_client_security(api_client_path)

    command = [
        "bash",
        str(ADD_REMOTE_MAPPED_CLIENT_SCRIPT),
        "--api-client",
        str(api_client_path),
        "--client-config",
        str(client_config_path),
        "--json-out",
        str(leaf_manifest_path),
    ]
    if args.hostname:
        command.extend(["-n", args.hostname])
    if args.workspace:
        command.extend(["--workspace", args.workspace])
    if args.velociraptor_bin:
        command.extend(["--velociraptor-bin", args.velociraptor_bin])
    command.append(str(evidence_path))

    from vraptor.settings import active_value
    result = run_command(command, timeout=active_value("startup_timeout_seconds") or 120)
    if result.returncode != 0:
        raise RuntimeError(
            "Remote mapped-client setup failed.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    leaf_manifest = read_leaf_manifest(leaf_manifest_path)
    if str(leaf_manifest.get("mode") or "") != "remote_dead_disk":
        raise RuntimeError("Mapped-client manifest did not record remote_dead_disk mode.")
    client_name = str(leaf_manifest.get("client_name") or "").strip()
    client_id = str(leaf_manifest.get("client_id") or "").strip()
    recorded_evidence = str(leaf_manifest.get("evidence_path") or "").strip()
    recorded_api_client = str(
        leaf_manifest.get("api_client_config") or ""
    ).strip()
    recorded_source_client = str(
        leaf_manifest.get("source_client_config") or ""
    ).strip()
    workspace = Path(str(leaf_manifest.get("workspace_dir") or "")).expanduser().resolve()
    remap_file = Path(str(leaf_manifest.get("remap_file") or "")).expanduser().resolve()
    if not client_name:
        raise RuntimeError("Mapped-client manifest did not record client_name.")
    if not client_id:
        raise RuntimeError("Mapped-client manifest did not record client_id.")
    for label, recorded, expected in (
        ("evidence path", recorded_evidence, evidence_path),
        ("API client config", recorded_api_client, api_client_path),
        ("source client config", recorded_source_client, client_config_path),
    ):
        if not recorded or Path(recorded).expanduser().resolve() != expected:
            raise RuntimeError(
                f"Mapped-client manifest {label} does not match the requested path."
            )
    if not workspace.is_dir():
        raise RuntimeError(f"Mapped-client workspace does not exist: {workspace}")
    if not remap_file.is_file() or "type: mount" not in remap_file.read_text(
        encoding="utf-8"
    ):
        raise RuntimeError(f"Mapped-client remap is missing or invalid: {remap_file}")

    return verify_mapped_readiness(args, leaf_manifest, api_client_path, mode="remote_dead_disk")


def verify_mapped_readiness(args, mapping, api_client_path, *, mode):
    """Verify enrollment and process health after a validated mapping startup."""
    client_name, client_id = mapping["client_name"], mapping["client_id"]
    workspace = Path(mapping["workspace_dir"]).expanduser().resolve()
    server_reachable = verify_api_reachable(api_client_path, use_local_cli=False)
    if not server_reachable:
        raise RuntimeError("Velociraptor API did not answer after mapped-client setup.")
    target = verify_client_id_visible(
        api_client_path,
        client_id,
        use_local_cli=False,
    )
    if not target["target_visible"]:
        raise RuntimeError(
            f"Mapped client id is not visible through the remote API: {client_id}"
        )
    if str(target.get("hostname") or "") != client_name:
        raise RuntimeError(
            "Mapped-client identity mismatch: "
            f"{client_id} resolved to {target.get('hostname') or 'no hostname'}, "
            f"expected {client_name}."
        )
    if not str(target.get("last_seen") or "").strip():
        raise RuntimeError(f"Mapped client has no LastSeen value: {client_id}")

    status = wait_for_mapped_client_ready(workspace, client_name)

    mapped_client = {
        "evidence_type": mapping.get("evidence_type"),
        "export_mapping": mapping.get("export_mapping"),
        "client_name": client_name,
        "client_id": client_id,
        "workspace_dir": str(workspace),
        "client_dir": str(mapping.get("client_dir") or ""),
        "remap_file": str(Path(mapping["remap_file"]).expanduser().resolve()),
        "evidence_path": str(Path(mapping["evidence_path"]).expanduser().resolve()),
        "state": str(status.get("state") or ""),
        "client_pid": str(status.get("client_pid") or ""),
        "supervisor_pid": str(status.get("supervisor_pid") or ""),
        "supervisor_mode": str(status.get("supervisor_mode") or ""),
        "client_process_running": True,
        "supervisor_process_running": True,
    }
    return build_unified_manifest(
        engagement_id=selected_engagement_id(args),
        engagement_id_source=selected_engagement_id_source(args),
        server_profile=selected_server_profile(args),
        mode=mode,
        source_skill="velociraptor-mapped-client",
        api_client_path=api_client_path,
        verification={
            "server_reachable": server_reachable,
            "mapped_client": mapped_client,
            **target,
        },
        next_step_hint="Proceed to velociraptor-host-analysis for the mapped dead-disk client.",
    )


def command_live_remote(args: argparse.Namespace) -> dict[str, Any]:
    with managed_leaf_manifest_path(
        args.manifest_out,
        "velo-engage-live-",
    ) as leaf_manifest_path:
        return _command_live_remote(args, leaf_manifest_path)


def build_live_api_fetch_command(
    args: argparse.Namespace,
    leaf_manifest_path: Path,
    *,
    regenerate_remote_api: bool = False,
    server_ip: str = "",
) -> list[str]:
    command = [
        "bash",
        str(FETCH_LIVE_API_CLIENT_SCRIPT),
        "--server-profile",
        selected_server_profile(args),
        "--json-out",
        str(leaf_manifest_path),
        "--api-role-profile",
        str(getattr(args, "api_role_profile", None) or "provisioning-admin"),
    ]
    selected_server_ip = str(server_ip or getattr(args, "server_ip", None) or "").strip()
    if selected_server_ip:
        command.extend(["--server-ip", selected_server_ip])
    output_path = str(getattr(args, "output_path", None) or "").strip()
    if output_path:
        command.extend(["--output-path", output_path])
    if bool(getattr(args, "force", False)) or regenerate_remote_api:
        command.append("--force")
    if regenerate_remote_api:
        command.append("--regenerate-remote-api")
    if getattr(args, "provision_api", False):
        command.append("--provision-api")
    return command


def run_live_api_fetch(
    args: argparse.Namespace,
    leaf_manifest_path: Path,
    fetch_env: dict[str, str],
    *,
    regenerate_remote_api: bool = False,
    server_ip: str = "",
) -> dict[str, Any]:
    started = time.monotonic()
    operation_log.emit(
        "api_config_fetch_started",
        component="engagement_setup",
        stage="api_config_fetch",
        status="running",
        regenerate=regenerate_remote_api,
    )
    command = build_live_api_fetch_command(
        args,
        leaf_manifest_path,
        regenerate_remote_api=regenerate_remote_api,
        server_ip=server_ip,
    )
    result = run_command(command, env=fetch_env)
    if result.returncode != 0:
        operation_log.emit(
            "api_config_fetch_failed",
            level="error",
            component="engagement_setup",
            stage="api_config_fetch",
            status="failed",
            regenerate=regenerate_remote_api,
            exit_code=result.returncode,
            duration_ms=(time.monotonic() - started) * 1000,
        )
        raise RuntimeError(
            "velociraptor-live-api-client failed.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    operation_log.emit(
        "api_config_fetch_completed",
        component="engagement_setup",
        stage="api_config_fetch",
        status="complete",
        regenerate=regenerate_remote_api,
        exit_code=result.returncode,
        duration_ms=(time.monotonic() - started) * 1000,
    )
    return read_leaf_manifest(leaf_manifest_path)


def live_api_identity(
    leaf_manifest: dict[str, Any],
) -> tuple[Path, str]:
    api_client_path = Path(str(leaf_manifest["local_dest_path"]))
    api_user = str(leaf_manifest.get("api_user") or "").strip()
    if not api_user:
        raise RuntimeError("Live API client manifest did not record api_user.")
    api_metadata = validate_api_client_security(api_client_path)
    if api_metadata["identity"] != api_user:
        raise RuntimeError(
            "Existing API client identity does not match the requested API user: "
            f"{api_metadata['identity']} != {api_user}. Pass --force to refresh."
        )
    return api_client_path, api_user


def recoverable_live_api_auth_error(error: RuntimeError) -> bool:
    message = str(error).lower()
    return "user not found:" in message or "requires permission any_query" in message


def _command_live_remote(
    args: argparse.Namespace,
    leaf_manifest_path: Path,
) -> dict[str, Any]:
    setup_started = time.monotonic()
    from vraptor import settings
    snapshot = settings.current()
    fetch_env = dict(snapshot.environment) if snapshot else os.environ.copy()
    for argument, environment_key in (
        ("api_user", "VELO_REMOTE_API_USER"),
        ("ssh_user", "VELO_REMOTE_SSH_USER"),
        ("ssh_key", "VELO_REMOTE_SSH_KEY"),
    ):
        value = str(getattr(args, argument, None) or "").strip()
        if value:
            fetch_env[environment_key] = value
    regenerate_remote_api = bool(getattr(args, "regenerate_remote_api", False))
    role_profile = str(
        getattr(args, "api_role_profile", None)
        or fetch_env.get("VELO_REMOTE_API_ROLE_PROFILE")
        or "provisioning-admin"
    ).strip()
    fetch_started = time.monotonic()
    supplied_api = getattr(args, "api_client", None)
    if supplied_api:
        api_path = Path(supplied_api).expanduser().resolve()
        identity = validate_api_client_security(api_path)["identity"]
        if getattr(args, "api_user", None) and args.api_user != identity:
            raise RuntimeError("Supplied API client does not match the selected API identity.")
        leaf_manifest = {"local_dest_path": str(api_path), "api_user": identity,
                         "api_client_source": "supplied"}
        api_client_path, api_user = api_path, identity
    else:
        leaf_manifest = run_live_api_fetch(
            args, leaf_manifest_path, fetch_env,
            regenerate_remote_api=regenerate_remote_api,
        )
        api_client_path, api_user = live_api_identity(leaf_manifest)
    fetch_seconds = time.monotonic() - fetch_started
    api_reachability_started = time.monotonic()
    recovery_attempted = regenerate_remote_api
    try:
        server_reachable = verify_api_reachable(api_client_path, use_local_cli=False)
    except RuntimeError as exc:
        if (supplied_api or regenerate_remote_api or not getattr(args, "provision_api", False)
                or not recoverable_live_api_auth_error(exc)):
            raise
        recovery_server_ip = str(
            getattr(args, "server_ip", None)
            or leaf_manifest.get("server_ip")
            or ""
        ).strip()
        recovery_started = time.monotonic()
        leaf_manifest = run_live_api_fetch(
            args,
            leaf_manifest_path,
            fetch_env,
            regenerate_remote_api=True,
            server_ip=recovery_server_ip,
        )
        fetch_seconds += time.monotonic() - recovery_started
        recovery_attempted = True
        api_client_path, api_user = live_api_identity(leaf_manifest)
        server_reachable = verify_api_reachable(api_client_path, use_local_cli=False)
    api_reachability_seconds = time.monotonic() - api_reachability_started
    if not server_reachable:
        raise RuntimeError("Fetched remote API client but could not query the remote Velociraptor API.")
    provisioning = verify_api_authorization(
        api_client_path,
        api_user=api_user,
        role_profile=role_profile,
    )
    provisioning["provisioning_source"] = str(
        leaf_manifest.get("api_client_source") or "target_api_client"
    )
    target_verification_started = time.monotonic()
    include_labels = list(args.host_label or [])
    exclude_labels = list(args.exclude_host_label or [])
    client_id = getattr(args, "client_id", None)
    if sum((bool(args.hostname), bool(client_id), bool(include_labels or exclude_labels))) > 1:
        raise RuntimeError("Use one of --client-id, --hostname or --host-label/--exclude-host-label.")
    if args.environment_only_ok and (args.hostname or client_id or include_labels or exclude_labels):
        raise RuntimeError(
            "Use --environment-only-ok only when you are not validating a specific hostname or label scope."
        )
    if client_id:
        target = verify_client_id_visible(api_client_path, client_id, use_local_cli=False)
        if not target["target_visible"]:
            raise RuntimeError("Requested live client is not visible through the API.")
    elif args.hostname:
        target = verify_hostname_visible(api_client_path, args.hostname, use_local_cli=False)
        if not target["target_visible"]:
            raise RuntimeError(
                f"Fetched remote API client but the intended live hostname was not visible: {args.hostname}"
            )
    elif include_labels or exclude_labels:
        target = verify_label_scope_visible(
            api_client_path,
            include_labels,
            exclude_labels,
            use_local_cli=False,
        )
        if not target["target_visible"]:
            raise RuntimeError(
                "Fetched remote API client but no clients were visible for the requested live label scope."
            )
    elif args.environment_only_ok:
        target = verify_any_client_visible(api_client_path, use_local_cli=False)
        if not target["target_visible"]:
            raise RuntimeError("Fetched remote API client but no clients were visible through the remote Velociraptor API.")
    else:
        raise RuntimeError(
            "Live remote readiness requires --hostname, --host-label/--exclude-host-label, "
            "or --environment-only-ok so the verification scope is explicit."
        )
    target_verification_seconds = time.monotonic() - target_verification_started
    setup_timing = {
        "fetch_seconds": round(fetch_seconds, 3),
        "api_reachability_seconds": round(api_reachability_seconds, 3),
        "target_verification_seconds": round(target_verification_seconds, 3),
        "total_seconds": round(time.monotonic() - setup_started, 3),
        "remote_recovery_attempted": recovery_attempted,
        "fetch_detail": dict(leaf_manifest.get("timing") or {}),
    }
    return build_unified_manifest(
        engagement_id=selected_engagement_id(args),
        engagement_id_source=selected_engagement_id_source(args),
        server_profile=selected_server_profile(args),
        mode="live_remote",
        source_skill="velociraptor-live-api-client",
        api_client_path=api_client_path,
        verification={
            "server_reachable": server_reachable,
            "api_user_provisioning": provisioning,
            "setup_timing": setup_timing,
            **target,
        },
        next_step_hint="Proceed to velociraptor-hunting for wide search or velociraptor-collection for one-host deep dive.",
    )


def add_engagement_state_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--engagement-id",
        "--id",
        "--investigation-id",
        dest="engagement_id",
        help=(
            "Case namespace used for <case-root>/<engagement-id>. Defaults "
            "to --server-profile when omitted."
        ),
    )
    add_case_root_arg(parser)
    parser.add_argument(
        "--manifest-out",
        help=(
            "Explicit engagement-state path. Normal operation writes "
            "<case-root>/<id>/engagement.json."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Velociraptor readiness. Prepare the folder separately with 'dfir setup init --id ID'."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    local_cmd = subparsers.add_parser(
        "local-deaddisk",
        help="Verify an existing local dead-disk or offline mapped-client Velociraptor engagement.",
    )
    local_cmd.add_argument("--evidence-path", help="Optional provenance path for the already mapped evidence.")
    local_cmd.add_argument("--api-client", help="Existing local Velociraptor API client config.")
    local_cmd.add_argument("--server-profile", help="Logical Velociraptor instance profile; defaults to the engagement id.")
    local_cmd.add_argument("--client-id", help="Require this existing mapped client id to be visible.")
    local_cmd.add_argument("--hostname", help="Require this existing mapped-client hostname to be visible.")
    add_engagement_state_args(local_cmd)

    remote_disk_cmd = subparsers.add_parser(
        "remote-deaddisk",
        help="Create and verify a local dead-disk mapped client enrolled with a remote Velociraptor server.",
    )
    remote_disk_cmd.add_argument(
        "--evidence-path",
        required=True,
        help="Local E01/raw image or mounted Windows directory to expose read-only.",
    )
    remote_disk_cmd.add_argument(
        "--api-client",
        help="Remote Velociraptor API client configuration; defaults from --server-profile.",
    )
    remote_disk_cmd.add_argument(
        "--client-config",
        help="Remote endpoint client configuration; defaults from --server-profile.",
    )
    remote_disk_cmd.add_argument("--server-profile", help="Logical Velociraptor instance profile; defaults to the engagement id.")
    remote_disk_cmd.add_argument("--hostname", help="Mapped-client hostname override.")
    remote_disk_cmd.add_argument(
        "--workspace",
        help="Mapped-client runtime workspace; defaults to VELO_MAPPED_CLIENT_WORKSPACE.",
    )
    remote_disk_cmd.add_argument(
        "--velociraptor-bin",
        help="Velociraptor executable; defaults to VELO_BIN.",
    )
    add_engagement_state_args(remote_disk_cmd)

    live_cmd = subparsers.add_parser(
        "live-remote",
        help="Prepare and verify a live remote Velociraptor engagement.",
    )
    live_cmd.add_argument("--server-ip", dest="server_ip", help="Remote SSH host, required when fetching credentials.")
    live_cmd.add_argument("--api-client", help="Use existing API credentials directly, without SSH provisioning.")
    live_cmd.add_argument("--client-id", help="Require this live client to be visible.")
    live_cmd.add_argument("--provision-api", action="store_true", help="Allow generation of missing remote API credentials and one authentication recovery attempt.")
    live_cmd.add_argument(
        "--server-profile",
        "--engagement-code",
        dest="server_profile",
        required=True,
        help="Velociraptor instance profile used for local config filenames.",
    )
    add_engagement_state_args(live_cmd)
    live_cmd.add_argument(
        "--output-path",
        dest="output_path",
        help="Optional explicit local output path for the copied <server-profile>_api_client.yaml.",
    )
    live_cmd.add_argument(
        "--api-user",
        help="Explicit remote API identity; overrides VELO_REMOTE_API_USER and root .env.",
    )
    live_cmd.add_argument(
        "--ssh-user",
        help="Explicit remote SSH user; overrides VELO_REMOTE_SSH_USER and root .env.",
    )
    live_cmd.add_argument(
        "--ssh-key",
        help="Explicit SSH identity file; overrides VELO_REMOTE_SSH_KEY and root .env.",
    )
    live_cmd.add_argument(
        "--force",
        action="store_true",
        help="Refresh the local API client even if the target file already exists.",
    )
    live_cmd.add_argument(
        "--api-role-profile",
        choices=("investigation", "provisioning-admin"),
        default=os.environ.get("VELO_REMOTE_API_ROLE_PROFILE") or "provisioning-admin",
        help=(
            "API credential role profile. provisioning-admin (default) uses "
            "administrator,api; investigation uses investigator,api."
        ),
    )
    live_cmd.add_argument(
        "--regenerate-remote-api",
        action="store_true",
        help=(
            "Regenerate and replace the configured remote target API YAML from "
            "the server config before fetching it. This implies --force."
        ),
    )
    live_cmd.add_argument("--hostname", help="Require this live hostname or FQDN to be visible before the engagement is marked ready.")
    live_cmd.add_argument(
        "--host-label",
        action="append",
        default=[],
        help="Require the live Velociraptor label scope to be visible. Repeat as needed.",
    )
    live_cmd.add_argument(
        "--exclude-host-label",
        action="append",
        default=[],
        help="Exclude clients carrying these labels when validating the live label scope.",
    )
    live_cmd.add_argument(
        "--environment-only-ok",
        action="store_true",
        help="Allow readiness to stop at API reachability plus any visible client when no hostname or label scope is available yet.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from vraptor.settings import current
    if current():
        current().apply(args)
    operation_log.bind_case(
        resolve_case_root(getattr(args, "case_root", None), REPO_ROOT),
        selected_engagement_id(args),
    )
    operation_log.emit(
        "readiness_started",
        component="engagement_setup",
        stage="preflight",
        status="running",
        mode=str(args.command).replace("-", "_"),
    )
    try:
        if args.command == "local-deaddisk":
            payload = command_local_deaddisk(args)
        elif args.command == "remote-deaddisk":
            payload = command_remote_deaddisk(args)
        elif args.command == "live-remote":
            payload = command_live_remote(args)
        else:
            raise RuntimeError(f"Unsupported command: {args.command}")
    except (RuntimeError, ValueError) as exc:
        operation_log.record_exception(exc, stage="readiness")
        payload = {
            "status": "error",
            "mode": {
                "local-deaddisk": "local_dead_disk",
                "remote-deaddisk": "remote_dead_disk",
                "live-remote": "live_remote",
            }.get(args.command, args.command),
            "message": str(exc),
        }
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 1

    output_path = selected_engagement_state_path(args)
    system_state_file = publish_mapped_system_state(args, payload)
    engagement_state.publish(output_path, payload)
    result = {
        **payload,
        "engagement_state_file": str(output_path),
        "system_state_file": system_state_file,
        **operation_log.correlation_metadata(),
    }
    print(json.dumps(result, indent=2, sort_keys=False))
    operation_log.emit(
        "readiness_completed",
        component="engagement_setup",
        stage="readiness",
        status="complete",
        mode=str(payload.get("mode") or ""),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
