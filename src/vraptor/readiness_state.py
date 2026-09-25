"""Compact, server-authoritative Velociraptor engagement readiness state."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml
from cryptography import x509

from vraptor.common import atomic_io
from vraptor import case_layout
from vraptor.common.hashing import sha256_file


SCHEMA_VERSION = 5
CERTIFICATE_WARNING_DAYS = 30


def state_path(case_root: Path, engagement_id: str) -> Path:
    return case_layout.engagement_dir(case_root, engagement_id) / "engagement.json"


def _canonical_hash(value: Any) -> str:
    rendered = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _certificate_time(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def api_metadata(path: Path, *, config: dict[str, Any] | None = None) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    payload = config
    if payload is None:
        try:
            payload = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuntimeError(f"Could not read API client config metadata from {resolved}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"API client config is not a YAML mapping: {resolved}")
    identity = str(payload.get("name") or "").strip()
    if not identity:
        raise RuntimeError(f"API client config does not declare an identity name: {resolved}")
    credential_sha256 = sha256_file(resolved)
    connection = str(
        payload.get("api_connection_string")
        or payload.get("connection_string")
        or payload.get("server")
        or ""
    ).strip()
    from .settings import active_value, current
    from .api import resolve_org_id
    selected_org = active_value("org_id") if current() else os.environ.get("VELO_LOCAL_ORG_ID")
    org_id = resolve_org_id(selected_org or payload.get("org_id") or payload.get("OrgId") or "root")
    ca_value = str(payload.get("ca_certificate") or payload.get("ca_cert") or "")
    certificate_value = str(payload.get("client_cert") or "")
    private_key_present = bool(str(payload.get("client_private_key") or "").strip())
    file_stat = resolved.stat()
    mode = stat.S_IMODE(file_stat.st_mode)
    certificate_status = "missing"
    not_before = ""
    not_after = ""
    days_remaining: int | None = None
    if certificate_value:
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_value.encode("utf-8")
            )
        except ValueError:
            certificate_status = "invalid"
        else:
            certificate_not_before = _certificate_time(
                certificate.not_valid_before_utc
                if hasattr(certificate, "not_valid_before_utc")
                else certificate.not_valid_before
            )
            certificate_not_after = _certificate_time(
                certificate.not_valid_after_utc
                if hasattr(certificate, "not_valid_after_utc")
                else certificate.not_valid_after
            )
            current = datetime.now(timezone.utc)
            days_remaining = int((certificate_not_after - current).total_seconds() // 86400)
            not_before = certificate_not_before.isoformat().replace("+00:00", "Z")
            not_after = certificate_not_after.isoformat().replace("+00:00", "Z")
            if current < certificate_not_before:
                certificate_status = "not_yet_valid"
            elif current >= certificate_not_after:
                certificate_status = "expired"
            elif days_remaining < CERTIFICATE_WARNING_DAYS:
                certificate_status = "expiring"
            else:
                certificate_status = "valid"
    server_basis = {
        "connection": connection,
        "org_id": org_id,
        "ca_sha256": hashlib.sha256(ca_value.encode("utf-8")).hexdigest()
        if ca_value
        else "",
    }
    # Real API configs provide connection or CA identity. Minimal test/local
    # configs fall back to credential identity so state still fails closed.
    if not connection and not ca_value:
        server_basis["credential_fallback"] = credential_sha256
    return {
        "identity": identity,
        "credential_sha256": credential_sha256,
        "server_fingerprint": _canonical_hash(server_basis),
        "connection": connection,
        "org_id": org_id,
        "credential_security": {
            "certificate_status": certificate_status,
            "certificate_not_before": not_before,
            "certificate_not_after": not_after,
            "certificate_days_remaining": days_remaining,
            "private_key_present": private_key_present,
            "file_mode": f"{mode:04o}",
            "owner_uid": file_stat.st_uid,
            "owner_matches_current_user": file_stat.st_uid == os.getuid(),
            "group_or_other_access": bool(mode & 0o077),
        },
    }


def credential_security_failures(metadata: Mapping[str, Any]) -> list[str]:
    security = dict(metadata.get("credential_security") or {})
    failures: list[str] = []
    certificate_status = str(security.get("certificate_status") or "missing")
    if certificate_status in {"missing", "invalid", "expired", "not_yet_valid"}:
        failures.append(f"API client certificate status is {certificate_status}")
    if not security.get("private_key_present"):
        failures.append("API client private key is missing")
    if security.get("group_or_other_access"):
        failures.append(
            f"API client permissions are {security.get('file_mode')}; remove group/other access"
        )
    if not security.get("owner_matches_current_user"):
        failures.append("API client is not owned by the current user")
    return failures


def engagement_fingerprint(payload: Mapping[str, Any]) -> str:
    api = dict(payload.get("api") or {})
    server = dict(payload.get("server") or {})
    connection = dict(payload.get("connection") or {})
    readiness = dict(payload.get("readiness") or {})
    authorization = dict(readiness.get("api_user_provisioning") or {})
    return _canonical_hash(
        {
            "engagement_id": str(payload.get("engagement_id") or "").lower(),
            "engagement_id_source": str(
                payload.get("engagement_id_source") or ""
            ),
            "server_profile": str(connection.get("server_profile") or ""),
            "mode": str(payload.get("mode") or ""),
            "server_fingerprint": str(server.get("fingerprint") or ""),
            "org_id": str(server.get("org_id") or "root"),
            "api_identity": str(api.get("identity") or ""),
            "credential_security": dict(api.get("credential_security") or {}),
            "api_authorization": {
                "status": str(authorization.get("status") or ""),
                "api_user": str(authorization.get("api_user") or ""),
                "role_profile": str(authorization.get("role_profile") or ""),
                "roles": sorted(
                    str(item) for item in authorization.get("roles") or []
                ),
                "effective_permissions": sorted(
                    str(item)
                    for item in authorization.get("effective_permissions") or []
                ),
            },
        }
    )


def build_state(
    *,
    engagement_id: str,
    engagement_id_source: str,
    server_profile: str,
    mode: str,
    source_skill: str,
    api_client_path: Path,
    verification: Mapping[str, Any],
    next_step_hint: str,
) -> dict[str, Any]:
    if engagement_id_source not in {"explicit", "server_profile_fallback"}:
        raise ValueError("engagement_id_source must be explicit or server_profile_fallback")
    if not str(server_profile or "").strip():
        raise ValueError("server_profile is required for schema-v5 readiness")
    metadata = api_metadata(api_client_path)
    credential_failures = credential_security_failures(metadata)
    if credential_failures:
        raise RuntimeError(
            "Velociraptor API credential validation failed: "
            + "; ".join(credential_failures)
        )
    verified_at = datetime.now(timezone.utc)
    scope_type = str(verification.get("scope_type") or "").strip()
    scope: dict[str, Any] = {
        "type": "site" if mode == "live_remote" else scope_type,
    }
    if mode == "live_remote":
        scope["verification_method"] = scope_type
    for key in (
        "requested_client_id",
        "requested_hostname",
        "requested_host_labels",
        "requested_exclude_host_labels",
        "matched_host_labels",
    ):
        if key in verification:
            scope[key] = verification[key]

    targets = [
        {
            "client_id": str(item.get("client_id") or ""),
            "hostname": str(item.get("hostname") or ""),
            "last_seen": str(item.get("last_seen") or ""),
        }
        for item in verification.get("targets") or []
        if isinstance(item, Mapping)
    ]
    if not targets and (verification.get("client_id") or verification.get("hostname")):
        targets.append(
            {
                "client_id": str(verification.get("client_id") or ""),
                "hostname": str(verification.get("hostname") or ""),
                "last_seen": str(verification.get("last_seen") or ""),
            }
        )
    readiness: dict[str, Any] = {
        "server_reachable": bool(verification.get("server_reachable")),
        "target_visible": bool(verification.get("target_visible")),
        "scope": scope,
        "matched_client_count": int(
            verification.get("matched_client_count")
            or (len(targets) if targets else 0)
        ),
    }
    # Exact host/mapped-client modes retain one bounded target. Live site
    # readiness deliberately does not persist a fleet client inventory.
    if mode != "live_remote" and targets:
        readiness["targets"] = targets[:1]
    if "api_user_provisioning" in verification:
        readiness["api_user_provisioning"] = dict(
            verification.get("api_user_provisioning") or {}
        )
    if "setup_timing" in verification:
        readiness["setup_timing"] = dict(verification.get("setup_timing") or {})
    if "mapped_client" in verification:
        readiness["mapped_client"] = dict(verification.get("mapped_client") or {})

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "layout_version": 3,
        "engagement_id": str(engagement_id).strip(),
        "engagement_id_source": str(engagement_id_source).strip(),
        "connection": {
            "server_profile": str(server_profile).strip(),
        },
        "status": "ready",
        "mode": mode,
        "source_skill": source_skill,
        "source_of_truth": "velociraptor",
        "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
        "server": {
            "fingerprint": metadata["server_fingerprint"],
            "org_id": metadata["org_id"],
        },
        "api": {
            "identity": metadata["identity"],
            "credential_sha256": metadata["credential_sha256"],
            "credential_security": metadata["credential_security"],
        },
        "readiness": readiness,
        "persistence": {
            "raw_evidence": False,
            "leaf_manifest": False,
        },
        "next_step_hint": next_step_hint,
    }
    payload["engagement_fingerprint"] = engagement_fingerprint(payload)
    return payload


def publish(path: Path, payload: Mapping[str, Any]) -> None:
    atomic_io.write_json_atomic(path, dict(payload), sort_keys=True)


def load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Velociraptor readiness is not proven: {path} does not exist") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Velociraptor engagement state is invalid at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Velociraptor engagement state is not a JSON object: {path}")
    return payload


def validate(
    *,
    path: Path,
    engagement_id: str,
    server_profile: str,
    api_client: Path,
    requested_client_id: str = "",
    requested_hostname: str = "",
    expected_org_id: str | None = None,
) -> dict[str, Any]:
    payload = load(path)
    records = payload.get("mappings")
    if records and (requested_client_id or requested_hostname):
        # Validate the selected host's own readiness, including stopped/failed
        # state and credential hash. A sibling's successful resume cannot bless it.
        matches = []
        requested_host = str(requested_hostname or "").lower()
        for record in records.values():
            for target in record.get("readiness", {}).get("targets", []):
                host = str(target.get("hostname") or "").lower()
                if ((not requested_client_id or target.get("client_id") == requested_client_id)
                        and (not requested_host or host == requested_host
                             or host.split(".", 1)[0] == requested_host.split(".", 1)[0])):
                    matches.append(record)
                    break
        if len(matches) != 1:
            raise RuntimeError("Velociraptor readiness failed closed: target must select exactly one saved mapping.")
        selected = matches[0]
        if engagement_fingerprint(selected) != engagement_fingerprint(payload):
            raise RuntimeError("Velociraptor readiness failed closed: mapping and investigation bindings differ.")
        payload = selected
    failures: list[str] = []
    if int(payload.get("schema_version") or 0) != SCHEMA_VERSION:
        failures.append(
            f"schema_version must be {SCHEMA_VERSION}; rerun Velociraptor "
            "engagement setup to create schema-v5 readiness"
        )
    if str(payload.get("status") or "") != "ready":
        failures.append(f"status={str(payload.get('status') or 'missing')}")
    if str(payload.get("engagement_id") or "").lower() != engagement_id.lower():
        failures.append("engagement_id does not match the selected case")
    if str(payload.get("engagement_id_source") or "") not in {
        "explicit",
        "server_profile_fallback",
    }:
        failures.append("engagement_id_source is missing or unsupported")
    recorded_profile = str(
        dict(payload.get("connection") or {}).get("server_profile") or ""
    )
    if recorded_profile != str(server_profile or ""):
        failures.append("server_profile does not match readiness")
    if str(payload.get("source_of_truth") or "") != "velociraptor":
        failures.append("source_of_truth is not velociraptor")
    if str(payload.get("engagement_fingerprint") or "") != engagement_fingerprint(
        payload
    ):
        failures.append("engagement_fingerprint does not match canonical state")
    if str(payload.get("source_skill") or "") not in {
        "velociraptor-engagement-setup",
        "velociraptor-live-api-client",
        "velociraptor-mapped-client",
    }:
        failures.append("source_skill is not an approved Velociraptor setup workflow")
    if bool(dict(payload.get("persistence") or {}).get("raw_evidence")):
        failures.append("engagement state may not persist raw evidence")

    verified_at_text = str(payload.get("verified_at") or "")
    try:
        verified_at = datetime.fromisoformat(verified_at_text.replace("Z", "+00:00"))
    except ValueError:
        failures.append("verified_at is missing or invalid")
        verified_at = datetime.fromtimestamp(0, tz=timezone.utc)
    if verified_at.tzinfo is None:
        failures.append("verified_at must include a timezone")

    current_api = api_metadata(api_client)
    failures.extend(credential_security_failures(current_api))
    recorded_api = dict(payload.get("api") or {})
    recorded_server = dict(payload.get("server") or {})
    if str(recorded_api.get("identity") or "") != current_api["identity"]:
        failures.append("API identity does not match readiness")
    if str(recorded_api.get("credential_sha256") or "") != current_api[
        "credential_sha256"
    ]:
        failures.append("API client content hash does not match readiness")
    if str(recorded_server.get("fingerprint") or "") != current_api[
        "server_fingerprint"
    ]:
        failures.append("Velociraptor server fingerprint does not match readiness")
    selected_org = str(expected_org_id or current_api["org_id"] or "root")
    if str(recorded_server.get("org_id") or "root") != selected_org:
        failures.append("Velociraptor org does not match readiness")

    readiness = dict(payload.get("readiness") or {})
    if not readiness.get("server_reachable") or not readiness.get("target_visible"):
        failures.append("server or target verification is false")
    mode = str(payload.get("mode") or "")
    if mode == "live_remote":
        provisioning = dict(readiness.get("api_user_provisioning") or {})
        roles = {str(role) for role in provisioning.get("roles") or []}
        effective_permissions = {
            str(permission)
            for permission in provisioning.get("effective_permissions") or []
        }
        role_profile = str(provisioning.get("role_profile") or "")
        if (
            str(provisioning.get("status") or "") != "verified"
            or str(provisioning.get("api_user") or "") != current_api["identity"]
            or "api" not in roles
            or role_profile not in {"investigation", "provisioning-admin"}
        ):
            failures.append("live API user provisioning provenance is incomplete")
        if role_profile == "investigation" and "investigator" not in roles:
            failures.append("investigation API role profile requires investigator")
        if role_profile == "investigation" and "administrator" in roles:
            failures.append("investigation API role profile may not include administrator")
        if role_profile == "provisioning-admin" and "administrator" not in roles:
            failures.append("provisioning-admin API role profile requires administrator")
        if role_profile == "provisioning-admin" and not {
            "SUPER_USER",
            "SERVER_ADMIN",
        } & effective_permissions:
            failures.append(
                "provisioning-admin readiness lacks a verified effective administrator capability"
            )
        if role_profile == "investigation" and not {
            "ANY_QUERY",
            "READ_RESULTS",
            "COLLECT_CLIENT",
            "START_HUNT",
        }.issubset(effective_permissions):
            failures.append(
                "investigation readiness lacks required effective capabilities"
            )
    elif mode not in {"local_dead_disk", "remote_dead_disk"}:
        failures.append("mode is missing or unsupported")

    if mode in {"local_dead_disk", "remote_dead_disk"}:
        targets = [
            dict(item)
            for item in readiness.get("targets") or []
            if isinstance(item, Mapping)
        ]
        if requested_client_id and requested_client_id not in {
            str(item.get("client_id") or "") for item in targets
        }:
            failures.append(f"verified clients do not include {requested_client_id}")
        requested_host = str(requested_hostname or "").lower()
        if requested_host:
            verified_hosts = {
                str(item.get("hostname") or "").lower() for item in targets
            }
            if not any(
                value == requested_host
                or value.split(".", 1)[0] == requested_host.split(".", 1)[0]
                for value in verified_hosts
            ):
                failures.append(f"verified hostnames do not include {requested_hostname}")

    if failures:
        raise RuntimeError(
            "Velociraptor readiness failed closed: " + "; ".join(failures)
            + ". Rerun engagement setup to regenerate readiness for the selected server and engagement."
        )
    return payload
