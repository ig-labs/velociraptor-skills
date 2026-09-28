#!/usr/bin/env python3
from __future__ import annotations
from vraptor.resources import resource_root

import argparse
import csv
import fcntl
import hashlib
import json
import os
import re
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from vraptor.common import atomic_io
from vraptor.common.hashing import sha256_file
from vraptor.common.sequences import unique_ordered as dedupe
from vraptor.api import VeloApiClient
from vraptor.api import grpc
from vraptor.api import resolve_org_id
from vraptor.collect.catalog import ARTIFACT_GROUPS
from vraptor.collect.catalog import BASELINE_COLLECTION_TYPES
from vraptor.collect.catalog import COLLECTION_TYPE_CHOICES
from vraptor.collect.catalog import IR_COLLECTION_BUNDLES
from vraptor.collect.catalog import IR_COLLECTION_GROUPS
from vraptor.collect.catalog import IR_TARGET_MODES
from vraptor.collect.catalog import collection_policy_followups
from vraptor.collect.catalog import resolve_collection_policy
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor import context as engagement_context
from vraptor.collect import layout
from vraptor.logging import operations as operation_log
from vraptor.artifacts import persistence as persistence_policy
from vraptor.analyze import identity as run_identity

from vraptor.resources import repository_root
REPO_ROOT = repository_root()

from vraptor.paths import add_case_root_arg
from vraptor.paths import default_case_root

REFERENCE_DIR = resource_root() / "vql"
CASE_ROOT = default_case_root(REPO_ROOT)
OPEN_STATES = {"RUNNING", "IN_PROGRESS", "WAITING", "QUEUED"}
DEFAULT_QUEUE_API_TIMEOUT_SECONDS = 60
DEFAULT_QUEUE_DISCOVERY_TIMEOUT_SECONDS = 60
DEFAULT_FLOW_QUERY_TIMEOUT_SECONDS = 30
DEFAULT_ARTIFACT_PREFLIGHT_TIMEOUT_SECONDS = 30
COLLECTION_COVERAGE_TERMINAL_STATUSES = {"collected", "empty", "not_applicable"}
TIMELINE_ARTIFACT_LABELS = frozenset(
    {
        "Windows.NTFS.MFT",
        "Windows.EventLogs.EvtxHunter",
    }
)
CLIENT_ID_RE = re.compile(r"^C\.[0-9A-Fa-f]+$")
STATE_THREAD_LOCKS_GUARD = threading.Lock()
STATE_THREAD_LOCKS: dict[str, threading.RLock] = {}
STATE_LOCK_CONTEXT = threading.local()


ZERO_ROW_FALLBACK_RULES: dict[str, dict[str, Any]] = {
    "Windows.Persistence.PermanentWMIEvents": {
        "rule_id": "permanent-wmi-events",
        "reason": (
            "Permanent WMI event collection can return zero rows on mapped dead-disk or otherwise weak "
            "collection paths. Review adjacent persistence artifacts before treating this as absence."
        ),
        "recommended_artifacts": [
            "Windows.System.TaskScheduler",
            "Windows.System.Services",
            "Windows.EventLogs.EvtxHunter",
        ],
    },
    "Windows.Sysinternals.Autoruns": {
        "rule_id": "autoruns",
        "reason": (
            "Autoruns can be incomplete or empty in dead-disk collection paths. Review adjacent ASEP, service, "
            "and task artifacts before calling the host clear."
        ),
        "recommended_artifacts": [
            "Windows.System.Services",
            "Windows.System.TaskScheduler",
            "Windows.Sys.StartupItems",
        ],
    },
    "Windows.Registry.TaskCache.HiddenTasks": {
        "rule_id": "hidden-task-cache",
        "reason": (
            "A zero-row hidden-task result does not close task-based persistence by itself. Review scheduler, "
            "registry, and event-log artifacts before treating the lane as absent."
        ),
        "recommended_artifacts": [
            "Windows.System.TaskScheduler",
            "Windows.EventLogs.EvtxHunter",
        ],
    },
}

ALL_COLLECTION_GROUPS = BASELINE_COLLECTION_TYPES
REGISTRY_HUNTER_COLLECTION_LABEL = "Windows.Registry.Hunter[all]"
REGISTRY_HUNTER_TIMEOUT_SECONDS = 1800

REGISTRY_HUNTER_PRESET_CATEGORIES = {
    "all": [
        "ASEP",
        "ASEP Classes",
        "Antivirus",
        "Autoruns",
        "Cloud Storage",
        "Devices",
        "Event Logs",
        "Installed Software",
        "Microsoft Exchange",
        "Microsoft Office",
        "Network Shares",
        "Persistence",
        "Program Execution",
        "Services",
        "System Info",
        "Third Party Applications",
        "Threat Hunting",
        "User Accounts",
        "User Activity",
        "Volume Shadow Copies",
        "Web Browsers",
    ],
    "asep": ["ASEP", "ASEP Classes"],
    "antivirus": ["Antivirus"],
    "autoruns": ["Autoruns"],
    "cloud-storage": ["Cloud Storage"],
    "devices": ["Devices"],
    "event-logs": ["Event Logs"],
    "execution": ["Program Execution"],
    "installed-software": ["Installed Software"],
    "microsoft-exchange": ["Microsoft Exchange"],
    "microsoft-office": ["Microsoft Office"],
    "network-shares": ["Network Shares"],
    "persistence": ["Persistence"],
    "services": ["Services"],
    "system-info": ["System Info"],
    "third-party-applications": ["Third Party Applications"],
    "threat-hunting": ["Threat Hunting"],
    "user-accounts": ["User Accounts"],
    "user-activity": ["User Activity"],
    "volume-shadow-copies": ["Volume Shadow Copies"],
    "web-browsers": ["Web Browsers"],
}
MULTI_SCOPE_ARTIFACT_EXPORTS = {
    "Windows.Forensics.SRUM": (
        "Windows.Forensics.SRUM/Execution Stats",
        "Windows.Forensics.SRUM/Application Resource Usage",
        "Windows.Forensics.SRUM/Network Connections",
        "Windows.Forensics.SRUM/Network Usage",
    ),
}
CURATED_ARTIFACT_EXPORT_QUERIES = {
    "Windows.NTFS.MFT": "export_windows_ntfs_mft.vql",
    "Windows.EventLogs.EvtxHunter": "export_windows_eventlogs_evtxhunter.vql",
    "Windows.EventLogs.RDPAuth": "export_windows_eventlogs_rdpauth.vql",
    "Windows.EventLogs.ExplicitLogon": "export_windows_eventlogs_explicitlogon.vql",
}
CURATED_ARTIFACT_TEXT_EXPORT_QUERIES = {
    "Windows.NTFS.MFT.BodyfileCompat": "export_windows_ntfs_mft_bodyfile_compat.vql",
}
REGISTRY_HUNTER_CURATED_PROFILES = {
    "execution": (
        (
            "Windows.Registry.Hunter.Execution.AppCompatCache.csv",
            "export_registry_hunter_execution_appcompatcache.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.UserAssist.csv",
            "export_registry_hunter_execution_userassist.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.RADAR.csv",
            "export_registry_hunter_execution_radar.vql",
        ),
        (
            "Windows.Registry.Hunter.Execution.BAM.csv",
            "export_registry_hunter_execution_bam.vql",
        ),
    ),
    "system-info": (
        (
            "Windows.Registry.Hunter.SystemInfo.csv",
            "export_registry_hunter_system_info.vql",
        ),
    ),
    "web-browsers": (
        (
            "Windows.Registry.Hunter.WebBrowsers.csv",
            "export_registry_hunter_web_browsers.vql",
        ),
    ),
    "volume-shadow-copies": (
        (
            "Windows.Registry.Hunter.VolumeShadowCopies.csv",
            "export_registry_hunter_volume_shadow_copies.vql",
        ),
    ),
    "user-activity": (
        (
            "Windows.Registry.Hunter.UserActivity.csv",
            "export_registry_hunter_user_activity.vql",
        ),
    ),
    "user-accounts": (
        (
            "Windows.Registry.Hunter.UserAccounts.csv",
            "export_registry_hunter_user_accounts.vql",
        ),
    ),
    "threat-hunting": (
        (
            "Windows.Registry.Hunter.ThreatHunting.csv",
            "export_registry_hunter_threat_hunting.vql",
        ),
    ),
    "third-party-applications": (
        (
            "Windows.Registry.Hunter.ThirdPartyApplications.csv",
            "export_registry_hunter_third_party_applications.vql",
        ),
    ),
    "services": (
        (
            "Windows.Registry.Hunter.Services.csv",
            "export_registry_hunter_services.vql",
        ),
    ),
    "network-shares": (
        (
            "Windows.Registry.Hunter.NetworkShares.csv",
            "export_registry_hunter_network_shares.vql",
        ),
    ),
    "persistence": (
        (
            "Windows.Registry.Hunter.Persistence.csv",
            "export_registry_hunter_persistence.vql",
        ),
    ),
    "program-execution": (
        (
            "Windows.Registry.Hunter.ProgramExecution.csv",
            "export_registry_hunter_program_execution.vql",
        ),
    ),
    "microsoft-office": (
        (
            "Windows.Registry.Hunter.MicrosoftOffice.csv",
            "export_registry_hunter_microsoft_office.vql",
        ),
    ),
    "microsoft-exchange": (
        (
            "Windows.Registry.Hunter.MicrosoftExchange.csv",
            "export_registry_hunter_microsoft_exchange.vql",
        ),
    ),
    "installed-software": (
        (
            "Windows.Registry.Hunter.InstalledSoftware.csv",
            "export_registry_hunter_installed_software.vql",
        ),
    ),
    "event-logs": (
        (
            "Windows.Registry.Hunter.EventLogs.csv",
            "export_registry_hunter_event_logs.vql",
        ),
    ),
    "devices": (
        (
            "Windows.Registry.Hunter.Devices.csv",
            "export_registry_hunter_devices.vql",
        ),
    ),
    "cloud-storage": (
        (
            "Windows.Registry.Hunter.CloudStorage.csv",
            "export_registry_hunter_cloud_storage.vql",
        ),
    ),
    "autoruns": (
        (
            "Windows.Registry.Hunter.Autoruns.csv",
            "export_registry_hunter_autoruns.vql",
        ),
    ),
}
REGISTRY_HUNTER_PROFILE_PRESETS = {
    profile: ("execution" if profile == "program-execution" else profile)
    for profile in REGISTRY_HUNTER_CURATED_PROFILES
}


@dataclass
class ClientRecord:
    client_id: str
    hostname: str
    last_seen: str
    selector_type: str = ""
    requested_client_id: str = ""
    requested_hostname: str = ""


@dataclass
class ArtifactSpec:
    label: str
    artifact: str
    env: dict[str, str]
    timeout_seconds: int | None = None


@dataclass
class TimelineOptions:
    date_after: str | None = None
    date_before: str | None = None
    mft_drive: str | None = None
    mft_path_regex: str | None = None
    mft_file_regex: str | None = None
    mft_size_min: int | None = None
    mft_size_max: int | None = None
    evtx_glob: str | None = None
    evtx_ioc_regex: str | None = None
    evtx_whitelist_regex: str | None = None
    evtx_path_regex: str | None = None
    evtx_channel_regex: str | None = None
    evtx_provider_regex: str | None = None
    evtx_id_regex: str | None = None
    evtx_vss_analysis_age: int | None = None


@dataclass
class FlowRecord:
    session_id: str
    state: str
    total_rows: int
    created: str
    last_active: str
    request_timeout_seconds: int | None
    artifacts_with_results: list[str]
    requested_specs: list[ArtifactSpec]
    compiled_collector_args: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CollectionRequest:
    target_collection_type: str
    requested_groups: list[str]
    requested_artifacts: list[str]
    expected_specs: list[ArtifactSpec]
    analysis_inputs: dict[str, dict[str, str]] = field(default_factory=dict)
    supersedes_request_id: str = ""
    unavailable_artifacts: list[str] = field(default_factory=list)
    collection_bundle: str = ""
    target_mode: str = ""
    candidate_artifacts: list[str] = field(default_factory=list)
    collection_policy: dict[str, Any] = field(default_factory=dict)
    collection_resolution: dict[str, Any] = field(default_factory=dict)
    flow_timeout_seconds: int | None = None


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-").replace("--", "-")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def short_signature(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()[:12]


def normalize_collection_label(label: str) -> str:
    prefix = "Windows.Registry.Hunter["
    if label.startswith(prefix) and label.endswith("]"):
        preset = label[len(prefix) : -1]
        if preset not in REGISTRY_HUNTER_PRESET_CATEGORIES:
            raise RuntimeError(
                f"Unsupported Registry Hunter preset {preset!r}. Supported presets: "
                + ", ".join(sorted(REGISTRY_HUNTER_PRESET_CATEGORIES))
            )
    return label


def normalize_artifacts(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
        return [item.strip() for item in text.split(",") if item.strip()]
    return []


def spec_env_from_parameters(parameters: Any) -> dict[str, str]:
    if not isinstance(parameters, dict):
        return {}
    env = parameters.get("env")
    if not isinstance(env, list):
        return {}

    env_map: dict[str, str] = {}
    for item in env:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not key:
            continue
        env_map[str(key)] = str(item.get("value", ""))
    return env_map


def parse_specs_json(specs_json: str) -> list[ArtifactSpec]:
    if not specs_json:
        return []
    try:
        parsed = json.loads(specs_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []

    specs: list[ArtifactSpec] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        artifact = item.get("artifact")
        if not artifact:
            continue
        specs.append(
            ArtifactSpec(
                label=str(item.get("artifact")),
                artifact=str(artifact),
                env=spec_env_from_parameters(item.get("parameters")),
                timeout_seconds=int(item.get("timeout") or 0) or None,
            )
        )
    return specs


def parse_json_object_list(value: Any) -> list[dict[str, Any]]:
    if not value:
        return []
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(parsed, list):
        return []
    return [dict(item) for item in parsed if isinstance(item, dict)]


def serialize_specs(specs: list[ArtifactSpec]) -> list[dict[str, Any]]:
    return [
        {
            "label": spec.label,
            "artifact": spec.artifact,
            "env": dict(sorted(spec.env.items())),
            "timeout_seconds": spec.timeout_seconds,
        }
        for spec in specs
    ]


def bounded_argument_keys(env: dict[str, str]) -> list[str]:
    bounded: list[str] = []
    for key in env:
        normalized = key.lower()
        if (
            "regex" in normalized
            or normalized.endswith("after")
            or normalized.endswith("before")
            or normalized.startswith("date")
        ):
            bounded.append(key)
    return sorted(bounded)


def effective_argument_validation(expected: ArtifactSpec, flow: FlowRecord | None) -> dict[str, Any]:
    if flow is None:
        return {
            "status": "unavailable",
            "validated": False,
            "artifact": expected.label,
            "artifact_name": expected.artifact,
            "expected_env": dict(sorted(expected.env.items())),
            "effective_env": {},
            "bounded_argument_keys": bounded_argument_keys(expected.env),
            "mismatches": ["matching flow is unavailable"],
            "expected_timeout_seconds": expected.timeout_seconds,
            "effective_timeout_seconds": None,
        }

    matching_specs = [
        spec
        for spec in flow.requested_specs
        if spec.artifact == expected.artifact
    ]
    effective_spec = matching_specs[0] if matching_specs else None
    effective_env = dict(sorted((effective_spec.env if effective_spec else {}).items()))
    mismatches: list[str] = []
    all_env_keys = sorted(set(expected.env) | set(effective_env))
    for key in all_env_keys:
        expected_value = expected.env.get(key)
        effective_value = effective_env.get(key)
        if expected_value != effective_value:
            mismatches.append(
                f"{key}: expected {expected_value!r}, effective {effective_value!r}"
            )
    if not matching_specs:
        mismatches.append(f"artifact {expected.artifact!r} is absent from flow.request.specs")
    if expected.timeout_seconds is not None and flow.request_timeout_seconds != expected.timeout_seconds:
        mismatches.append(
            "timeout: expected "
            f"{expected.timeout_seconds!r}, effective {flow.request_timeout_seconds!r}"
        )
    return {
        "status": "validated" if not mismatches else "mismatch",
        "validated": not mismatches,
        "artifact": expected.label,
        "artifact_name": expected.artifact,
        "expected_env": dict(sorted(expected.env.items())),
        "effective_env": effective_env,
        "bounded_argument_keys": bounded_argument_keys(expected.env),
        "mismatches": mismatches,
        "expected_timeout_seconds": expected.timeout_seconds,
        "effective_timeout_seconds": flow.request_timeout_seconds,
    }


def effective_arguments_payload(artifact_statuses: list[dict[str, Any]]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for item in artifact_statuses:
        validation = dict(item.get("effective_argument_validation") or {})
        record = {
            "artifact": str(item.get("artifact") or ""),
            "artifact_name": str(item.get("artifact_name") or ""),
            "flow_id": str(item.get("flow_id") or ""),
            "source": str(item.get("effective_argument_source") or ""),
            "effective_spec_arguments": list(item.get("server_effective_spec_arguments") or []),
            "compiled_collector_args": list(item.get("server_compiled_collector_args") or []),
            "validation": validation,
        }
        records.append(record)
        if item.get("matching_flow_found") and not validation.get("validated", False):
            failures.append(
                {
                    "artifact": record["artifact"],
                    "flow_id": record["flow_id"],
                    "mismatches": list(validation.get("mismatches") or []),
                }
            )
    return {
        "server_effective_artifact_arguments": records,
        "effective_arguments_valid": not failures,
        "effective_argument_validation_failures": failures,
    }


def raise_for_effective_argument_validation(
    artifact_statuses: list[dict[str, Any]],
    *,
    context: str,
) -> None:
    payload = effective_arguments_payload(artifact_statuses)
    failures = payload["effective_argument_validation_failures"]
    if not failures:
        return
    details = "; ".join(
        f"{item['artifact']}: {', '.join(item['mismatches'])}"
        for item in failures
    )
    raise RuntimeError(
        f"Refusing {context} because server-effective artifact arguments differ "
        f"from the requested bounds: {details}"
    )


def timeline_options_present(options: TimelineOptions | None) -> bool:
    if options is None:
        return False
    return any(
        value is not None
        for value in (
            options.date_after,
            options.date_before,
            options.mft_drive,
            options.mft_path_regex,
            options.mft_file_regex,
            options.mft_size_min,
            options.mft_size_max,
            options.evtx_glob,
            options.evtx_ioc_regex,
            options.evtx_whitelist_regex,
            options.evtx_path_regex,
            options.evtx_channel_regex,
            options.evtx_provider_regex,
            options.evtx_id_regex,
            options.evtx_vss_analysis_age,
        )
    )


def build_timeline_specs(
    options: TimelineOptions | None,
    *,
    collection_type: str = "timeline",
) -> list[ArtifactSpec]:
    options = options or TimelineOptions()
    if not options.date_after and not options.date_before:
        raise RuntimeError(
            f"--collection-type {collection_type} requires --date-after, "
            "--date-before, or both."
        )

    mft_env = {
        "MFTDrive": options.mft_drive or "C:",
        "PathRegex": options.mft_path_regex or ".",
        "FileRegex": options.mft_file_regex or ".",
    }
    if options.date_after:
        mft_env["DateAfter"] = options.date_after
    if options.date_before:
        mft_env["DateBefore"] = options.date_before
    if options.mft_size_min is not None:
        mft_env["SizeMin"] = str(options.mft_size_min)
    if options.mft_size_max is not None:
        mft_env["SizeMax"] = str(options.mft_size_max)

    evtx_env = {
        "EvtxGlob": options.evtx_glob or r"%SystemRoot%\System32\Winevt\Logs\*.evtx",
        "IocRegex": options.evtx_ioc_regex or ".",
        "PathRegex": options.evtx_path_regex or ".",
        "ChannelRegex": options.evtx_channel_regex or ".",
        "ProviderRegex": options.evtx_provider_regex or ".",
        "IdRegex": options.evtx_id_regex or ".",
        "VSSAnalysisAge": str(options.evtx_vss_analysis_age or 0),
    }
    if options.date_after:
        evtx_env["DateAfter"] = options.date_after
    if options.date_before:
        evtx_env["DateBefore"] = options.date_before
    if options.evtx_whitelist_regex:
        evtx_env["WhitelistRegex"] = options.evtx_whitelist_regex

    return [
        ArtifactSpec(label="Windows.NTFS.MFT", artifact="Windows.NTFS.MFT", env=mft_env),
        ArtifactSpec(
            label="Windows.EventLogs.EvtxHunter",
            artifact="Windows.EventLogs.EvtxHunter",
            env=evtx_env,
        ),
    ]


def spec_to_request_dict(spec: ArtifactSpec) -> dict[str, Any]:
    env_items = [
        {"key": key, "value": value}
        for key, value in sorted(spec.env.items())
    ]
    return {
        "artifact": spec.artifact,
        "parameters": {
            "env": env_items,
        },
    }


def normalize_specs_value(value: Any) -> list[ArtifactSpec]:
    if not isinstance(value, list):
        return []
    specs: list[ArtifactSpec] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact = item.get("artifact")
        if not artifact:
            continue
        env = item.get("env")
        if not isinstance(env, dict):
            env = {}
        specs.append(
            ArtifactSpec(
                label=str(item.get("label") or artifact),
                artifact=str(artifact),
                env={str(key): str(val) for key, val in env.items()},
                timeout_seconds=int(item.get("timeout_seconds") or 0) or None,
            )
        )
    return specs


def build_plain_spec(label: str) -> ArtifactSpec:
    return ArtifactSpec(label=label, artifact=label, env={})


def build_registry_hunter_specs() -> dict[str, ArtifactSpec]:
    specs: dict[str, ArtifactSpec] = {}
    for preset, categories in REGISTRY_HUNTER_PRESET_CATEGORIES.items():
        label = f"Windows.Registry.Hunter[{preset}]"
        specs[label] = ArtifactSpec(
            label=label,
            artifact="Windows.Registry.Hunter",
            env={
                "Categories": json.dumps(categories, separators=(",", ":")),
                "RemappingStrategy": "None",
            },
            timeout_seconds=REGISTRY_HUNTER_TIMEOUT_SECONDS,
        )
    return specs


SPECIAL_ARTIFACT_SPECS = build_registry_hunter_specs()


def build_expected_specs(labels: list[str]) -> list[ArtifactSpec]:
    specs: list[ArtifactSpec] = []
    for label in labels:
        specs.append(SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label)))
    return specs


def build_policy_specs(
    resolution: dict[str, Any],
    flow_timeout_seconds: int | None = None,
) -> list[ArtifactSpec]:
    parameter_map = {
        str(item.get("artifact") or ""): {
            str(name): str(value)
            for name, value in dict(
                item.get("default_parameters") or {}
            ).items()
        }
        for item in resolution.get("physical_sources") or []
        if str(item.get("artifact") or "").strip()
    }
    specs: list[ArtifactSpec] = []
    for base_spec in build_expected_specs(list(resolution["selected_artifacts"])):
        specs.append(
            ArtifactSpec(
                label=base_spec.label,
                artifact=base_spec.artifact,
                env=dict(
                    sorted(
                        {
                            **base_spec.env,
                            **parameter_map.get(base_spec.label, {}),
                        }.items()
                    )
                ),
                timeout_seconds=(
                    flow_timeout_seconds
                    if flow_timeout_seconds is not None
                    else base_spec.timeout_seconds
                ),
            )
        )
    return specs


def get_client_by_id(api: VeloApiClient, client_id: str, fallback_hostname: str = "") -> ClientRecord | None:
    rows = api.query(
        """
        SELECT
          client_id,
          os_info.hostname AS Hostname,
          timestamp(epoch=last_seen_at) AS LastSeen
        FROM clients()
        WHERE client_id = ClientId
        """,
        {"ClientId": client_id},
    )
    if not rows:
        return None
    row = rows[0]
    return ClientRecord(
        client_id=row["client_id"],
        hostname=row.get("Hostname") or fallback_hostname,
        last_seen=row.get("LastSeen", ""),
        selector_type="client_id",
        requested_client_id=client_id,
    )


def get_client(api: VeloApiClient, hostname: str) -> ClientRecord:
    rows = api.query_file("get_client.vql", {"hostname_regex": f"^{hostname}$"})
    if rows:
        unique_client_ids = {
            str(row.get("client_id") or "").strip()
            for row in rows
            if str(row.get("client_id") or "").strip()
        }
        if len(unique_client_ids) > 1:
            raise RuntimeError(
                f"Hostname {hostname!r} resolves to multiple Velociraptor clients "
                f"({', '.join(sorted(unique_client_ids))}). Use --client-id."
            )
        row = rows[0]
        return ClientRecord(
            client_id=row["client_id"],
            hostname=row.get("Hostname") or hostname,
            last_seen=row.get("LastSeen", ""),
            selector_type="hostname",
            requested_hostname=hostname,
        )

    raise RuntimeError(f"No Velociraptor client found for hostname {hostname}")


def client_identity_payload(client: ClientRecord) -> dict[str, Any]:
    selector_type = (
        client.selector_type
        or ("client_id" if client.requested_client_id else "")
        or ("hostname" if client.requested_hostname else "")
    )
    return {
        "hostname": client.hostname,
        "client_id": client.client_id,
        "last_seen": client.last_seen,
        "target_selector_type": selector_type,
        "requested_client_id": client.requested_client_id,
        "requested_hostname": client.requested_hostname,
        "resolved_client_id": client.client_id,
        "resolved_hostname": client.hostname,
    }


def apply_saved_client_selection(
    client: ClientRecord,
    state: dict[str, Any],
    fallback_hostname: str,
) -> ClientRecord:
    saved_selector_type = str(state.get("target_selector_type") or "").strip()
    saved_client_id = str(state.get("requested_client_id") or "").strip()
    saved_hostname = str(state.get("requested_hostname") or "").strip()
    if saved_selector_type or saved_client_id or saved_hostname:
        client.selector_type = saved_selector_type
        client.requested_client_id = saved_client_id
        client.requested_hostname = saved_hostname
    if not client.selector_type:
        client.selector_type = "hostname"
        client.requested_hostname = fallback_hostname
    return client


def flow_from_row(row: dict[str, Any]) -> FlowRecord:
    requested_specs = parse_specs_json(row.get("RequestSpecsJson", ""))
    if not requested_specs:
        requested_specs = build_expected_specs(normalize_artifacts(row.get("RequestedArtifacts")))
    return FlowRecord(
        session_id=row["session_id"],
        state=(row.get("state") or "").upper(),
        total_rows=int(row.get("total_collected_rows") or 0),
        created=row.get("Created", ""),
        last_active=row.get("LastActive", ""),
        request_timeout_seconds=int(row.get("RequestTimeoutSeconds") or 0) or None,
        artifacts_with_results=normalize_artifacts(row.get("artifacts_with_results")),
        requested_specs=requested_specs,
        compiled_collector_args=parse_json_object_list(row.get("CompiledCollectorArgsJson")),
    )


def get_all_flows(
    api: VeloApiClient,
    client_id: str,
    timeout_seconds: int = DEFAULT_FLOW_QUERY_TIMEOUT_SECONDS,
) -> list[FlowRecord]:
    rows = api.query_file(
        "list_flows.vql",
        {"client_id": client_id},
        timeout=timeout_seconds,
    )
    return [flow_from_row(row) for row in rows]


def get_flow(
    api: VeloApiClient,
    client_id: str,
    flow_id: str,
    timeout_seconds: int = DEFAULT_FLOW_QUERY_TIMEOUT_SECONDS,
) -> FlowRecord:
    rows = api.query_file(
        "get_flow.vql",
        {"client_id": client_id, "flow_id": flow_id},
        timeout=timeout_seconds,
    )
    if not rows:
        raise RuntimeError(f"Flow {flow_id} not found for client {client_id}")
    return flow_from_row(rows[0])


def query_available_artifacts(
    api: VeloApiClient,
    artifact_names: list[str],
) -> list[str]:
    requested = sorted({str(name).strip() for name in artifact_names if str(name).strip()})
    if not requested:
        return []
    rows = api.query_file(
        "list_artifact_availability.vql",
        {"Artifacts": json.dumps(requested)},
        timeout=DEFAULT_ARTIFACT_PREFLIGHT_TIMEOUT_SECONDS,
        max_row=max(100, len(requested) + 1),
    )
    return sorted(
        {
            str(row.get("name") or "").strip()
            for row in rows
            if str(row.get("name") or "").strip()
        }
    )


def resolve_policy_request_for_api(
    api: VeloApiClient,
    request: CollectionRequest,
) -> CollectionRequest:
    if not request.collection_policy:
        return request
    if str(request.collection_resolution.get("status") or "") != "availability_unchecked":
        return request

    available = query_available_artifacts(api, request.candidate_artifacts)
    resolution = resolve_collection_policy(
        bundle=request.collection_bundle or None,
        groups=() if request.collection_bundle else request.requested_groups,
        target_mode=request.target_mode,
        available_artifacts=available,
    )
    request.collection_resolution = resolution
    request.collection_policy = dict(resolution["policy"])
    request.requested_groups = list(resolution["requested_groups"])
    request.candidate_artifacts = list(resolution["candidate_artifacts"])
    request.requested_artifacts = list(resolution["selected_artifacts"])
    request.expected_specs = build_policy_specs(
        resolution,
        request.flow_timeout_seconds,
    )
    return request


def preflight_artifact_availability(
    api: VeloApiClient,
    request: CollectionRequest,
) -> dict[str, Any]:
    requested = sorted({spec.artifact for spec in request.expected_specs})
    available = query_available_artifacts(api, requested)
    missing = sorted(set(requested) - set(available))
    missing_core_sources = list(
        request.collection_resolution.get("missing_core") or []
    )
    blocking_core_sources = (
        missing_core_sources
        if str(request.collection_resolution.get("status") or "") == "blocked"
        else []
    )
    unavailable_recommended = list(
        request.collection_resolution.get("unavailable_recommended") or []
    )
    unavailable_optional = list(
        request.collection_resolution.get("unavailable_optional") or []
    )
    if missing or blocking_core_sources:
        status = "failed"
    elif (
        missing_core_sources
        or unavailable_recommended
        or unavailable_optional
    ):
        status = "degraded"
    else:
        status = "ready"
    api_config_value = getattr(api, "api_config", None)
    api_client_path = ""
    api_client_sha256 = ""
    if isinstance(api_config_value, (str, Path)):
        config_path = Path(api_config_value).expanduser().resolve()
        api_client_path = str(config_path)
        if config_path.is_file():
            api_client_sha256 = sha256_file(config_path)
    return {
        "status": status,
        "requested_artifacts": requested,
        "available_artifacts": available,
        "missing_artifacts": missing,
        "missing_core_sources": missing_core_sources,
        "blocking_core_sources": blocking_core_sources,
        "unavailable_recommended": unavailable_recommended,
        "unavailable_optional": unavailable_optional,
        "not_applicable": list(
            request.collection_resolution.get("not_applicable") or []
        ),
        "collection_policy": dict(request.collection_policy),
        "api_client_path": api_client_path,
        "api_client_sha256": api_client_sha256,
        "org_id": str(getattr(api, "org_id", "") or ""),
        "checked_at": now_utc(),
    }


def raise_for_missing_server_artifacts(preflight: dict[str, Any]) -> None:
    missing = list(preflight.get("missing_artifacts") or [])
    blocking_core_sources = list(preflight.get("blocking_core_sources") or [])
    if not missing and not blocking_core_sources:
        return
    details: list[str] = []
    if missing:
        details.append("Missing requested artifact definition(s): " + ", ".join(missing))
    if blocking_core_sources:
        details.append("unresolved core source(s): " + ", ".join(blocking_core_sources))
    raise RuntimeError(
        "Velociraptor server artifact preflight failed. "
        + "; ".join(details)
        + ". Install or synchronize the artifacts, or choose a server-supported "
        "collection scope before queueing."
    )


def get_output_dir(investigation_id: str, hostname: str) -> Path:
    return layout.collection_dir(CASE_ROOT, investigation_id, hostname)


def get_exports_dir(investigation_id: str, hostname: str) -> Path:
    return layout.exports_dir(CASE_ROOT, investigation_id, hostname)


def get_coverage_path(investigation_id: str, hostname: str) -> Path:
    return layout.coverage_path(CASE_ROOT, investigation_id, hostname)


def get_request_coverage_path(investigation_id: str, hostname: str, request_id: str) -> Path:
    return layout.request_coverage_path(CASE_ROOT, investigation_id, hostname, request_id)


def get_current_state_path(investigation_id: str, hostname: str) -> Path:
    return layout.current_state_path(CASE_ROOT, investigation_id, hostname)


@contextmanager
def collection_state_lock(investigation_id: str, hostname: str):
    lock_path = (
        get_output_dir(investigation_id, hostname) / ".state.lock"
    ).resolve()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_key = str(lock_path)
    with STATE_THREAD_LOCKS_GUARD:
        thread_lock = STATE_THREAD_LOCKS.setdefault(lock_key, threading.RLock())
    with thread_lock:
        held_locks = getattr(STATE_LOCK_CONTEXT, "held_locks", None)
        if held_locks is None:
            held_locks = {}
            STATE_LOCK_CONTEXT.held_locks = held_locks
        held = held_locks.get(lock_key)
        if held is not None:
            held["depth"] += 1
            try:
                yield
            finally:
                held["depth"] -= 1
            return

        handle = lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            held_locks[lock_key] = {"depth": 1, "handle": handle}
            try:
                yield
            finally:
                del held_locks[lock_key]
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def request_id_for_request(request: CollectionRequest) -> str:
    identity: Any = serialize_specs(request.expected_specs)
    if (
        request.analysis_inputs
        or request.supersedes_request_id
        or request.unavailable_artifacts
        or request.collection_policy
        or request.collection_resolution
    ):
        resolution_identity = dict(request.collection_resolution)
        resolution_identity.pop("available_artifacts", None)
        identity = {
            "specs": identity,
            "analysis_inputs": request.analysis_inputs,
            "supersedes_request_id": request.supersedes_request_id,
            "unavailable_artifacts": sorted(request.unavailable_artifacts),
            "collection_policy": request.collection_policy,
            "collection_resolution": resolution_identity,
        }
    return f"{slugify(request.target_collection_type)}-{short_signature(identity)}"


def request_provenance_payload(request: CollectionRequest) -> dict[str, Any]:
    return {
        "supersedes_request_id": request.supersedes_request_id,
        "unavailable_artifacts": list(request.unavailable_artifacts),
        "collection_bundle": request.collection_bundle,
        "target_mode": request.target_mode,
        "candidate_artifacts": list(request.candidate_artifacts),
        "collection_policy": dict(request.collection_policy),
        "collection_resolution": dict(request.collection_resolution),
    }


def get_request_dir(investigation_id: str, hostname: str, request_id: str) -> Path:
    return layout.request_dir(CASE_ROOT, investigation_id, hostname, request_id)


def get_request_state_path(investigation_id: str, hostname: str, request_id: str) -> Path:
    return get_request_dir(investigation_id, hostname, request_id) / "state.json"


def get_state_path(investigation_id: str, hostname: str, request_id: str | None = None) -> Path:
    if request_id:
        return get_request_state_path(investigation_id, hostname, request_id)
    return get_current_state_path(investigation_id, hostname)


def engagement_relative_path(investigation_id: str, path: Path) -> str:
    engagement_root = layout.engagement_dir(CASE_ROOT, investigation_id)
    try:
        return path.relative_to(engagement_root).as_posix()
    except ValueError:
        return str(path)


def write_system_identity(
    investigation_id: str,
    hostname: str,
    payload: dict[str, Any],
) -> None:
    identity_path = layout.system_identity_path(CASE_ROOT, investigation_id, hostname)
    existing: dict[str, Any] = {}
    if identity_path.is_file():
        try:
            existing = json.loads(identity_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"System identity file is not valid JSON: {identity_path}"
            ) from exc
    existing_hostname = str(existing.get("hostname") or "").strip()
    if existing_hostname and existing_hostname.lower() != hostname.lower():
        raise RuntimeError(
            f"System identity collision at {identity_path}: "
            f"expected {hostname}, found {existing_hostname}."
        )
    client_ids = {
        str(value).strip()
        for value in existing.get("velociraptor_client_ids") or []
        if str(value).strip()
    }
    client_id = str(payload.get("client_id") or "").strip()
    if client_id:
        client_ids.add(client_id)
    write_json(
        identity_path,
        {
            "layout_version": layout.LAYOUT_VERSION,
            "hostname": hostname,
            "velociraptor_client_ids": sorted(client_ids),
            "updated_at": str(payload.get("updated_at") or now_utc()),
        },
    )


def write_json(path: Path, payload: Any) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    atomic_io.write_text_atomic(path, rendered)


def collection_groups_for_artifact(
    label: str,
    collection_resolution: dict[str, Any] | None = None,
) -> list[str]:
    policy_groups = [
        str(group)
        for item in (collection_resolution or {}).get("physical_sources") or []
        if str(item.get("artifact") or "") == label
        for group in item.get("groups") or []
    ]
    legacy_groups = [
        group_name
        for group_name, artifact_labels in ARTIFACT_GROUPS.items()
        if label in artifact_labels
    ]
    return dedupe(policy_groups + legacy_groups)


def coverage_status_for_artifact(
    artifact_status: dict[str, Any],
    artifact_exports: list[dict[str, Any]],
) -> tuple[str, str]:
    if not artifact_status.get("matching_flow_found"):
        return ("missing", "not_ready")
    if not artifact_status.get("matching_flow_matches_expected_arguments", False):
        return ("failed", "not_ready")
    if not artifact_status.get("is_finished"):
        return ("in_progress", "not_ready")

    total_rows = int(artifact_status.get("total_rows") or 0)
    exported_row_count = sum(int(item.get("row_count") or 0) for item in artifact_exports)
    available_components = list(artifact_status.get("available_result_components") or [])
    if str(artifact_status.get("flow_state") or "").strip().upper() == "ERROR":
        if total_rows > 0 or exported_row_count > 0 or available_components:
            return ("partial", "exported" if artifact_exports else "not_exported")
        return ("failed", "not_applicable")
    if total_rows <= 0:
        return ("empty", "not_applicable")
    if artifact_exports:
        return ("collected", "exported")
    return ("collected", "not_exported")


def output_classification_for_artifact(
    artifact_status: dict[str, Any],
    artifact_exports: list[dict[str, Any]],
) -> str:
    if not artifact_status.get("matching_flow_found"):
        return "failed-no-output"
    if not artifact_status.get("matching_flow_matches_expected_arguments", False):
        return "failed-no-output"
    if not artifact_status.get("is_finished"):
        return "in-progress"

    total_rows = int(artifact_status.get("total_rows") or 0)
    exported_row_count = sum(int(item.get("row_count") or 0) for item in artifact_exports)
    available_components = list(artifact_status.get("available_result_components") or [])
    has_output = total_rows > 0 or exported_row_count > 0 or bool(available_components)
    if str(artifact_status.get("flow_state") or "").strip().upper() == "ERROR":
        return "partial-from-error" if has_output else "failed-no-output"
    if total_rows <= 0 and exported_row_count <= 0:
        return "zero-row"
    return "complete"


def output_caveat_for_classification(classification: str) -> str:
    if classification == "partial-from-error":
        return (
            "Velociraptor flow ended ERROR but produced rows or result components; "
            "treat output as partial positive context, not a clean negative."
        )
    if classification == "failed-no-output":
        return "Velociraptor flow ended without reusable output; recollect or use alternate evidence."
    if classification == "zero-row":
        return "Collection returned zero rows; absence should be interpreted with artifact-specific caveats."
    if classification == "in-progress":
        return "Collection is not terminal yet; output is not ready for review."
    return ""


def fallback_artifact_status(label: str) -> dict[str, Any]:
    return {
        "artifact": label,
        "artifact_name": label,
        "matching_flow_found": False,
        "matching_flow_matches_expected_arguments": False,
        "flow_id": "",
        "flow_state": "MISSING",
        "is_finished": False,
        "total_rows": 0,
        "available_result_components": [],
        "expected_env": {},
        "expected_timeout_seconds": None,
    }


def zero_row_fallback_for_artifact(label: str) -> dict[str, Any] | None:
    rule = ZERO_ROW_FALLBACK_RULES.get(label)
    if not rule:
        return None
    return {
        "required": True,
        "rule_id": str(rule["rule_id"]),
        "reason": str(rule["reason"]),
        "recommended_artifacts": [str(item) for item in rule.get("recommended_artifacts", [])],
    }


def item_is_timeline_artifact(item: dict[str, Any]) -> bool:
    artifact = str(item.get("artifact") or "").strip()
    if artifact in TIMELINE_ARTIFACT_LABELS:
        return True
    return "timeline" in {str(group).strip().lower() for group in item.get("collection_groups", []) or []}


def build_timeline_coverage_summary(
    coverage_items: list[dict[str, Any]],
    requested_groups: list[str],
    requested_artifacts: list[str],
) -> dict[str, Any]:
    timeline_items = [item for item in coverage_items if item_is_timeline_artifact(item)]
    present_artifacts = [str(item.get("artifact") or "").strip() for item in timeline_items if str(item.get("artifact") or "").strip()]
    requested = "timeline" in {group.lower() for group in requested_groups} or any(
        artifact in TIMELINE_ARTIFACT_LABELS for artifact in requested_artifacts
    )
    missing_artifacts = sorted(artifact for artifact in TIMELINE_ARTIFACT_LABELS if artifact not in present_artifacts)
    complete = (
        not missing_artifacts
        and all(str(item.get("status") or "").strip() in COLLECTION_COVERAGE_TERMINAL_STATUSES for item in timeline_items)
    )
    review_ready = (
        not missing_artifacts
        and all(str(item.get("status") or "").strip() in {"collected", "empty", "not_applicable", "partial"} for item in timeline_items)
    )
    return {
        "requested": requested,
        "present": bool(timeline_items),
        "complete": complete,
        "review_ready": review_ready,
        "present_artifacts": present_artifacts,
        "missing_artifacts": missing_artifacts,
    }


def build_coverage_manifest(payload: dict[str, Any]) -> dict[str, Any] | None:
    investigation_id = str(payload.get("investigation_id") or "").strip()
    hostname = str(payload.get("hostname") or "").strip()
    if not investigation_id or not hostname:
        return None

    requested_groups = normalize_artifacts(payload.get("requested_groups"))
    requested_artifacts = normalize_artifacts(payload.get("requested_artifacts"))
    collection_resolution = dict(payload.get("collection_resolution") or {})
    artifact_statuses = list(payload.get("artifact_flows") or [])
    exported_files = list(payload.get("exported_files") or [])
    exports_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for item in exported_files:
        artifact_label = str(item.get("artifact") or "").strip()
        if not artifact_label:
            continue
        exports_by_artifact.setdefault(artifact_label, []).append(item)

    artifact_status_map = {
        str(item.get("artifact") or "").strip(): item
        for item in artifact_statuses
        if str(item.get("artifact") or "").strip()
    }
    request_id = str(payload.get("request_id") or "").strip()
    preserved_exports_by_artifact = preserved_exports_from_existing_request_coverage(
        investigation_id,
        hostname,
        request_id,
        artifact_status_map,
        exports_by_artifact,
    )
    ordered_artifact_labels = dedupe(
        requested_artifacts + [label for label in artifact_status_map if label not in requested_artifacts]
    )
    coverage_items: list[dict[str, Any]] = []
    for artifact_label in ordered_artifact_labels:
        artifact_status = artifact_status_map.get(artifact_label, fallback_artifact_status(artifact_label))
        artifact_label = str(artifact_status.get("artifact") or "").strip()
        artifact_exports = exports_by_artifact.get(artifact_label, [])
        export_state_preserved = False
        if not artifact_exports and artifact_label in preserved_exports_by_artifact:
            artifact_exports = preserved_exports_by_artifact[artifact_label]
            export_state_preserved = True
        status, export_state = coverage_status_for_artifact(artifact_status, artifact_exports)
        output_classification = output_classification_for_artifact(artifact_status, artifact_exports)
        coverage_items.append(
            {
                "artifact": artifact_label,
                "artifact_name": str(artifact_status.get("artifact_name") or "").strip(),
                "collection_groups": collection_groups_for_artifact(
                    artifact_label,
                    collection_resolution,
                ),
                "status": status,
                "export_state": export_state,
                "matching_flow_found": bool(artifact_status.get("matching_flow_found")),
                "matching_flow_matches_expected_arguments": bool(
                    artifact_status.get("matching_flow_matches_expected_arguments")
                ),
                "flow_id": str(artifact_status.get("flow_id") or "").strip(),
                "flow_state": str(artifact_status.get("flow_state") or "").strip(),
                "is_finished": bool(artifact_status.get("is_finished")),
                "total_rows": int(artifact_status.get("total_rows") or 0),
                "available_result_components": list(artifact_status.get("available_result_components") or []),
                "expected_env": dict(artifact_status.get("expected_env") or {}),
                "expected_timeout_seconds": artifact_status.get("expected_timeout_seconds"),
                "server_effective_spec_arguments": list(
                    artifact_status.get("server_effective_spec_arguments") or []
                ),
                "server_compiled_collector_args": list(
                    artifact_status.get("server_compiled_collector_args") or []
                ),
                "effective_argument_source": str(
                    artifact_status.get("effective_argument_source") or ""
                ),
                "effective_argument_validation": dict(
                    artifact_status.get("effective_argument_validation") or {}
                ),
                "output_classification": output_classification,
                "output_caveat": output_caveat_for_classification(output_classification),
                "exported_row_count": sum(int(item.get("row_count") or 0) for item in artifact_exports),
                "exported_files": [str(item.get("output_file") or "") for item in artifact_exports if str(item.get("output_file") or "").strip()],
                "export_state_preserved": export_state_preserved,
                "zero_row_fallback": zero_row_fallback_for_artifact(artifact_label) if status == "empty" else None,
            }
        )

    item_map = {
        str(item.get("artifact") or "").strip(): item
        for item in coverage_items
        if str(item.get("artifact") or "").strip()
    }
    zero_row_fallback_required_count = 0
    zero_row_fallback_collection_ready_count = 0
    for item in coverage_items:
        fallback_rule = item.get("zero_row_fallback")
        if not isinstance(fallback_rule, dict) or not fallback_rule.get("required"):
            continue
        zero_row_fallback_required_count += 1
        recommended_artifacts = [str(value) for value in fallback_rule.get("recommended_artifacts", [])]
        supporting_artifacts_present = [
            artifact
            for artifact in recommended_artifacts
            if artifact in item_map
        ]
        supporting_artifacts_missing = [
            artifact
            for artifact in recommended_artifacts
            if artifact not in item_map
        ]
        collection_ready = any(
            str(item_map[artifact].get("status") or "").strip() in COLLECTION_COVERAGE_TERMINAL_STATUSES
            for artifact in supporting_artifacts_present
        )
        if collection_ready:
            zero_row_fallback_collection_ready_count += 1
        fallback_rule["supporting_artifacts_present"] = supporting_artifacts_present
        fallback_rule["supporting_artifacts_missing"] = supporting_artifacts_missing
        fallback_rule["collection_ready"] = collection_ready

    status_counts: dict[str, int] = {}
    export_state_counts: dict[str, int] = {}
    output_classification_counts: dict[str, int] = {}
    for item in coverage_items:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
        export_state_counts[item["export_state"]] = export_state_counts.get(item["export_state"], 0) + 1
        output_classification_counts[item["output_classification"]] = (
            output_classification_counts.get(item["output_classification"], 0) + 1
        )

    physical_collection_complete = all(
        item["status"] in COLLECTION_COVERAGE_TERMINAL_STATUSES
        for item in coverage_items
    )
    physical_review_ready = all(
        item["status"] in {"collected", "empty", "not_applicable", "partial"}
        for item in coverage_items
    )
    policy_coverage_status = str(
        collection_resolution.get("status") or "not_applicable"
    )
    complete = physical_collection_complete and policy_coverage_status in {
        "ready",
        "not_applicable",
    }
    review_ready = physical_review_ready and policy_coverage_status != "blocked"
    timeline_summary = build_timeline_coverage_summary(coverage_items, requested_groups, requested_artifacts)
    manifest = {
        "generated_at": now_utc(),
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": str(payload.get("client_id") or "").strip(),
        "target_selector_type": str(payload.get("target_selector_type") or "").strip(),
        "requested_client_id": str(payload.get("requested_client_id") or "").strip(),
        "requested_hostname": str(payload.get("requested_hostname") or "").strip(),
        "resolved_client_id": str(payload.get("resolved_client_id") or payload.get("client_id") or "").strip(),
        "resolved_hostname": str(payload.get("resolved_hostname") or hostname).strip(),
        "request_id": request_id,
        "target_collection_type": str(payload.get("target_collection_type") or "").strip(),
        "requested_groups": requested_groups,
        "requested_artifacts": requested_artifacts,
        "expected_spec_arguments": list(payload.get("expected_spec_arguments") or []),
        "analysis_inputs": {
            str(artifact): dict(values)
            for artifact, values in dict(
                payload.get("analysis_inputs") or {}
            ).items()
            if isinstance(values, dict)
        },
        "collection_bundle": str(payload.get("collection_bundle") or ""),
        "target_mode": str(payload.get("target_mode") or ""),
        "candidate_artifacts": normalize_artifacts(
            payload.get("candidate_artifacts")
        ),
        "collection_policy": dict(payload.get("collection_policy") or {}),
        "collection_resolution": collection_resolution,
        "policy_coverage_status": policy_coverage_status,
        "run_identity": dict(payload.get("run_identity") or {}),
        "run_identity_sha256": str(
            payload.get("run_identity_sha256") or ""
        ),
        "reuse_decisions": list(payload.get("reuse_decisions") or []),
        "server_effective_artifact_arguments": list(
            payload.get("server_effective_artifact_arguments") or []
        ),
        "effective_arguments_valid": bool(payload.get("effective_arguments_valid", False)),
        "effective_argument_validation_failures": list(
            payload.get("effective_argument_validation_failures") or []
        ),
        "host_coverage_complete": complete,
        "physical_collection_complete": physical_collection_complete,
        "review_ready": review_ready,
        "status_counts": status_counts,
        "export_state_counts": export_state_counts,
        "output_classification_counts": output_classification_counts,
        "zero_row_fallback_required_count": zero_row_fallback_required_count,
        "zero_row_fallback_collection_ready_count": zero_row_fallback_collection_ready_count,
        "timeline": timeline_summary,
        "items": coverage_items,
    }
    return manifest


def preserved_exports_from_existing_request_coverage(
    investigation_id: str,
    hostname: str,
    request_id: str,
    artifact_status_map: dict[str, dict[str, Any]],
    current_exports_by_artifact: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    if not request_id:
        return {}
    request_coverage_path = get_request_coverage_path(
        investigation_id,
        hostname,
        request_id,
    )
    if not request_coverage_path.exists():
        return {}
    try:
        existing_manifest = json.loads(request_coverage_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if str(existing_manifest.get("request_id") or "").strip() != request_id:
        return {}

    preserved: dict[str, list[dict[str, Any]]] = {}
    for item in existing_manifest.get("items") or []:
        if not isinstance(item, dict):
            continue
        artifact_label = str(item.get("artifact") or "").strip()
        if not artifact_label or artifact_label in current_exports_by_artifact:
            continue
        artifact_status = artifact_status_map.get(artifact_label)
        if not artifact_status:
            continue
        existing_flow_id = str(item.get("flow_id") or "").strip()
        current_flow_id = str(artifact_status.get("flow_id") or "").strip()
        if not existing_flow_id or existing_flow_id != current_flow_id:
            continue
        output_files = [
            str(value).strip()
            for value in item.get("exported_files") or []
            if str(value).strip()
        ]
        existing_files = [path for path in output_files if Path(path).exists()]
        if not existing_files:
            continue
        row_count = int(item.get("exported_row_count") or 0)
        preserved[artifact_label] = [
            {
                "artifact": artifact_label,
                "flow_id": current_flow_id,
                "mode": "preserved-coverage-export",
                "row_count": row_count if index == 0 else 0,
                "output_file": path,
                "preserved_from_coverage": str(request_coverage_path),
            }
            for index, path in enumerate(existing_files)
        ]
    return preserved


def write_coverage_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    manifest = build_coverage_manifest(payload)
    if manifest is None:
        return payload
    manifest["layout_version"] = layout.LAYOUT_VERSION

    investigation_id = str(manifest["investigation_id"])
    hostname = str(manifest["hostname"])
    coverage_path = get_coverage_path(investigation_id, hostname)
    write_json(coverage_path, manifest)
    payload["coverage_manifest_file"] = str(coverage_path)

    request_id = str(manifest.get("request_id") or "").strip()
    if request_id:
        request_coverage_path = get_request_coverage_path(investigation_id, hostname, request_id)
        write_json(request_coverage_path, manifest)
        payload["request_coverage_manifest_file"] = str(request_coverage_path)

    return payload


def read_state(path: Path) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        decoder = json.JSONDecoder()
        payload, end = decoder.raw_decode(raw_text)
        if raw_text[end:].strip():
            return payload
        raise exc
    if (
        isinstance(payload, dict)
        and payload.get("latest_request_id")
        and payload.get("state_file")
        and not payload.get("artifact_flows")
    ):
        target = Path(str(payload["state_file"]))
        if not target.is_absolute():
            target = path.parent / target
        if not target.is_file():
            raise RuntimeError(
                f"Latest collection state pointer {path} targets missing file {target}."
            )
        return read_state(target)
    return payload


def parse_env_assignments(env_values: list[str]) -> dict[str, str]:
    env_map: dict[str, str] = {}
    for raw_item in env_values:
        key, sep, value = raw_item.partition("=")
        key = key.strip()
        if not sep or not key:
            raise RuntimeError(f"Invalid --env value {raw_item!r}. Use KEY=VALUE.")
        env_map[key] = value
    return env_map


def build_custom_specs(extra_artifacts: list[str], artifact_env: dict[str, str]) -> dict[str, ArtifactSpec]:
    if not artifact_env:
        return {}
    if len(extra_artifacts) != 1:
        raise RuntimeError("--env requires exactly one explicit --artifact target.")

    label = normalize_collection_label(extra_artifacts[0])
    base_spec = SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label))
    return {
        label: ArtifactSpec(
            label=label,
            artifact=base_spec.artifact,
            env=dict(sorted({**base_spec.env, **artifact_env}.items())),
            timeout_seconds=base_spec.timeout_seconds,
        )
    }


def resolve_requested_groups(collection_type: str | None, extra_artifacts: list[str]) -> list[str]:
    resolved: list[str] = []
    if collection_type == "all":
        resolved.extend(ALL_COLLECTION_GROUPS)
    elif collection_type in ARTIFACT_GROUPS:
        resolved.append(collection_type)
    if not resolved and not extra_artifacts:
        resolved = list(ALL_COLLECTION_GROUPS)
    return resolved


def build_artifacts(groups: list[str], extra_artifacts: list[str]) -> list[str]:
    artifacts: list[str] = []
    for group in groups:
        artifacts.extend(ARTIFACT_GROUPS[group])
    artifacts.extend(extra_artifacts)
    return dedupe(artifacts)


def normalize_collection_artifacts(artifacts: list[str]) -> list[str]:
    return dedupe([normalize_collection_label(artifact) for artifact in artifacts])


def build_request(
    collection_type: str | None,
    extra_artifacts: list[str],
    env_values: list[str],
    timeline_options: TimelineOptions | None = None,
    flow_timeout_seconds: int | None = None,
    analysis_input_values: list[str] | None = None,
    collection_bundle: str | None = None,
    collection_groups: list[str] | None = None,
    target_mode: str | None = None,
) -> CollectionRequest:
    policy_groups = dedupe(
        [str(value).strip() for value in collection_groups or [] if str(value).strip()]
    )
    if target_mode and not (collection_bundle or policy_groups):
        raise RuntimeError("--target-mode requires --bundle or --collection-group.")
    if collection_bundle or policy_groups:
        incompatible = bool(
            collection_type
            or extra_artifacts
            or env_values
            or analysis_input_values
            or timeline_options_present(timeline_options)
        )
        if incompatible:
            raise RuntimeError(
                "--bundle/--collection-group cannot be combined with legacy "
                "--collection-type, explicit --artifact, --env, --analysis-input, "
                "or timeline arguments."
            )
        resolution = resolve_collection_policy(
            bundle=collection_bundle,
            groups=policy_groups,
            target_mode=target_mode,
            available_artifacts=None,
        )
        requested_artifacts = list(resolution["selected_artifacts"])
        expected_specs = build_policy_specs(resolution, flow_timeout_seconds)
        if collection_bundle:
            target_collection_type = str(collection_bundle)
        elif len(policy_groups) == 1:
            target_collection_type = policy_groups[0]
        else:
            target_collection_type = "ir-groups"
        return CollectionRequest(
            target_collection_type=target_collection_type,
            requested_groups=list(resolution["requested_groups"]),
            requested_artifacts=requested_artifacts,
            expected_specs=expected_specs,
            collection_bundle=str(collection_bundle or ""),
            target_mode=str(resolution["target_mode"]),
            candidate_artifacts=list(resolution["candidate_artifacts"]),
            collection_policy=dict(resolution["policy"]),
            collection_resolution=resolution,
            flow_timeout_seconds=flow_timeout_seconds,
        )

    if timeline_options_present(timeline_options) and collection_type not in {
        "timeline",
        "exfiltration",
    }:
        raise RuntimeError(
            "Timeline-specific flags require --collection-type timeline or exfiltration."
        )
    analysis_values = parse_env_assignments(list(analysis_input_values or []))
    if analysis_values and len(extra_artifacts) != 1:
        raise RuntimeError(
            "--analysis-input requires exactly one explicit --artifact target."
        )

    if collection_type == "registry" and extra_artifacts:
        raise RuntimeError(
            "--collection-type registry is standalone and cannot be combined "
            "with --artifact."
        )
    if collection_type == "registry" and env_values:
        raise RuntimeError(
            "--collection-type registry does not accept --env. Use an explicit "
            "Registry Hunter artifact target for custom parameters."
        )
    if REGISTRY_HUNTER_COLLECTION_LABEL in extra_artifacts and (
        collection_type is not None or len(extra_artifacts) > 1
    ):
        raise RuntimeError(
            "Windows.Registry.Hunter[all] is standalone and cannot be combined "
            "with another collection type or artifact."
        )

    if collection_type == "timeline":
        if extra_artifacts:
            raise RuntimeError("--collection-type timeline cannot be combined with --artifact.")
        if env_values:
            raise RuntimeError("--collection-type timeline does not use --env. Use the dedicated timeline flags.")
        expected_specs = build_timeline_specs(timeline_options)
        if flow_timeout_seconds is not None:
            expected_specs = [
                ArtifactSpec(
                    label=spec.label,
                    artifact=spec.artifact,
                    env=dict(spec.env),
                    timeout_seconds=flow_timeout_seconds,
                )
                for spec in expected_specs
            ]
        requested_groups = ["timeline"]
        requested_artifacts = [spec.label for spec in expected_specs]
        return CollectionRequest(
            target_collection_type="timeline",
            requested_groups=requested_groups,
            requested_artifacts=requested_artifacts,
            expected_specs=expected_specs,
            analysis_inputs={},
        )

    if collection_type == "exfiltration":
        options = timeline_options or TimelineOptions()
        if not options.date_after or not options.date_before:
            raise RuntimeError(
                "--collection-type exfiltration requires both --date-after and "
                "--date-before."
            )
        if not any(
            (
                options.mft_path_regex,
                options.mft_file_regex,
                options.evtx_ioc_regex,
            )
        ):
            raise RuntimeError(
                "--collection-type exfiltration requires at least one concrete "
                "--mft-path-regex, --mft-file-regex, or --evtx-ioc-regex scope."
            )
        if extra_artifacts:
            raise RuntimeError(
                "--collection-type exfiltration cannot be combined with --artifact."
            )
        if env_values:
            raise RuntimeError(
                "--collection-type exfiltration does not use --env. Use the "
                "dedicated bounded timeline flags."
            )
        bounded_specs = {
            spec.label: spec
            for spec in build_timeline_specs(
                options,
                collection_type="exfiltration",
            )
        }
        requested_artifacts = list(ARTIFACT_GROUPS["exfiltration"])
        expected_specs = [
            bounded_specs.get(
                label,
                SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label)),
            )
            for label in requested_artifacts
        ]
        if flow_timeout_seconds is not None:
            expected_specs = [
                ArtifactSpec(
                    label=spec.label,
                    artifact=spec.artifact,
                    env=dict(spec.env),
                    timeout_seconds=flow_timeout_seconds,
                )
                for spec in expected_specs
            ]
        return CollectionRequest(
            target_collection_type="exfiltration",
            requested_groups=["exfiltration"],
            requested_artifacts=requested_artifacts,
            expected_specs=expected_specs,
            analysis_inputs={},
        )

    requested_groups = resolve_requested_groups(collection_type, extra_artifacts)
    requested_artifacts = normalize_collection_artifacts(build_artifacts(requested_groups, extra_artifacts))
    if not requested_artifacts:
        raise RuntimeError("No artifacts resolved for the requested collection target.")
    custom_specs = build_custom_specs(extra_artifacts, parse_env_assignments(env_values))
    expected_specs = [
        custom_specs.get(label, SPECIAL_ARTIFACT_SPECS.get(label, build_plain_spec(label)))
        for label in requested_artifacts
    ]
    if flow_timeout_seconds is not None:
        expected_specs = [
            ArtifactSpec(
                label=spec.label,
                artifact=spec.artifact,
                env=dict(spec.env),
                timeout_seconds=flow_timeout_seconds,
            )
            for spec in expected_specs
        ]
    if collection_type:
        target_collection_type = collection_type
    elif requested_groups == list(ALL_COLLECTION_GROUPS) and not extra_artifacts:
        target_collection_type = "all"
    elif len(requested_artifacts) == 1:
        target_collection_type = requested_artifacts[0]
    elif extra_artifacts:
        target_collection_type = "artifacts"
    else:
        target_collection_type = "+".join(requested_groups)
    return CollectionRequest(
        target_collection_type=target_collection_type,
        requested_groups=requested_groups,
        requested_artifacts=requested_artifacts,
        expected_specs=expected_specs,
        analysis_inputs=(
            {
                normalize_collection_label(extra_artifacts[0]): dict(
                    sorted(analysis_values.items())
                )
            }
            if analysis_values
            else {}
        ),
    )


def timeline_options_from_args(args: argparse.Namespace) -> TimelineOptions:
    return TimelineOptions(
        date_after=getattr(args, "date_after", None),
        date_before=getattr(args, "date_before", None),
        mft_drive=getattr(args, "mft_drive", None),
        mft_path_regex=getattr(args, "mft_path_regex", None),
        mft_file_regex=getattr(args, "mft_file_regex", None),
        mft_size_min=getattr(args, "mft_size_min", None),
        mft_size_max=getattr(args, "mft_size_max", None),
        evtx_glob=getattr(args, "evtx_glob", None),
        evtx_ioc_regex=getattr(args, "evtx_ioc_regex", None),
        evtx_whitelist_regex=getattr(args, "evtx_whitelist_regex", None),
        evtx_path_regex=getattr(args, "evtx_path_regex", None),
        evtx_channel_regex=getattr(args, "evtx_channel_regex", None),
        evtx_provider_regex=getattr(args, "evtx_provider_regex", None),
        evtx_id_regex=getattr(args, "evtx_id_regex", None),
        evtx_vss_analysis_age=getattr(args, "evtx_vss_analysis_age", None),
    )


def build_request_from_args(args: argparse.Namespace) -> CollectionRequest:
    request = build_request(
        getattr(args, "collection_type", None),
        getattr(args, "artifact", None) or [],
        getattr(args, "env", None) or [],
        timeline_options_from_args(args),
        getattr(args, "flow_timeout_seconds", None),
        getattr(args, "analysis_input", None),
        getattr(args, "bundle", None),
        getattr(args, "collection_group", None),
        getattr(args, "target_mode", None),
    )
    supersedes_request_id = str(
        getattr(args, "supersedes_request_id", None) or ""
    ).strip()
    unavailable_artifacts = dedupe(
        normalize_artifacts(getattr(args, "unavailable_artifact", None))
    )
    if unavailable_artifacts and not supersedes_request_id:
        raise RuntimeError(
            "--unavailable-artifact requires --supersedes-request-id."
        )
    if supersedes_request_id:
        if getattr(args, "collection_type", None) or not list(
            getattr(args, "artifact", None) or []
        ):
            raise RuntimeError(
                "--supersedes-request-id requires an explicit artifact-only request."
            )
        overlap = sorted(
            set(request.requested_artifacts) & set(unavailable_artifacts)
        )
        if overlap:
            raise RuntimeError(
                "Unavailable artifacts cannot also be requested: "
                + ", ".join(overlap)
            )
    request.supersedes_request_id = supersedes_request_id
    request.unavailable_artifacts = sorted(unavailable_artifacts)
    return request


def flow_matches_spec(flow: FlowRecord, expected: ArtifactSpec) -> bool:
    expected_identity = collection_run_identity("", [expected])["identity"]
    return any(
        run_identity.identities_match(
            expected_identity,
            collection_run_identity("", [spec])["identity"],
        )
        for spec in flow.requested_specs
        if spec.artifact == expected.artifact
    )


def collection_run_identity(
    client_id: str,
    specs: list[ArtifactSpec],
) -> dict[str, Any]:
    return run_identity.build_run_identity(
        source_mode="velociraptor-collection",
        target={"client_id": str(client_id)},
        specs=specs,
    )


def flow_reuse_classification(flow: FlowRecord) -> str:
    return run_identity.classify_state(
        flow.state,
        terminal_success_states={"FINISHED", "COMPLETED"},
        in_flight_states=OPEN_STATES,
    )


def flow_created_sort_value(flow: FlowRecord) -> float:
    text = str(flow.created or "").strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def select_matching_flow_for_spec(
    api: VeloApiClient,
    client_id: str,
    expected: ArtifactSpec,
    *,
    flows: list[FlowRecord] | None = None,
) -> dict[str, Any]:
    expected_identity = collection_run_identity(client_id, [expected])
    candidates: list[dict[str, Any]] = []
    near_match_mismatches: list[dict[str, Any]] = []
    for flow in flows if flows is not None else get_all_flows(api, client_id):
        matching_specs = [
            spec
            for spec in flow.requested_specs
            if spec.artifact == expected.artifact
        ]
        if not matching_specs:
            continue
        selected_spec: ArtifactSpec | None = None
        selected_identity: dict[str, Any] | None = None
        mismatches: list[dict[str, Any]] = []
        for spec in matching_specs:
            actual_identity = collection_run_identity(client_id, [spec])
            candidate_mismatches = run_identity.identity_mismatches(
                expected_identity["identity"],
                actual_identity["identity"],
            )
            if not candidate_mismatches:
                selected_spec = spec
                selected_identity = actual_identity
                break
            mismatches = candidate_mismatches
        if selected_spec is None or selected_identity is None:
            if len(near_match_mismatches) < 10:
                near_match_mismatches.append(
                    {
                        "flow_id": flow.session_id,
                        "state": flow.state,
                        "created": flow.created,
                        "mismatches": mismatches,
                        "actual_run_identity_sha256": collection_run_identity(
                            client_id,
                            [matching_specs[0]],
                        )["sha256"],
                    }
                )
            continue
        classification = flow_reuse_classification(flow)
        candidates.append(
            {
                "_flow": flow,
                "flow_id": flow.session_id,
                "state": flow.state,
                "classification": classification,
                "reuse_allowed": run_identity.reuse_allowed(classification),
                "created": flow.created,
                "last_active": flow.last_active,
                "total_rows": flow.total_rows,
                "run_identity_sha256": selected_identity["sha256"],
            }
        )

    candidates.sort(
        key=lambda item: (
            run_identity.classification_rank(str(item["classification"])),
            flow_created_sort_value(item["_flow"]),
        ),
        reverse=True,
    )
    selected = next(
        (item for item in candidates if bool(item["reuse_allowed"])),
        None,
    )
    blocked = next(
        (
            item
            for item in candidates
            if item["classification"] == run_identity.FAILED_OR_CANCELLED
        ),
        None,
    )
    public_candidates = [
        {key: value for key, value in item.items() if key != "_flow"}
        for item in candidates[:10]
    ]
    return {
        "run_identity": expected_identity["identity"],
        "run_identity_sha256": expected_identity["sha256"],
        "exact_match_count": len(candidates),
        "exact_match_candidates": public_candidates,
        "near_match_mismatches": near_match_mismatches,
        "selected_flow": selected["_flow"] if selected else None,
        "blocked_flow": blocked["_flow"] if blocked else None,
        "selected_candidate": (
            {key: value for key, value in selected.items() if key != "_flow"}
            if selected
            else None
        ),
        "blocked_candidate": (
            {key: value for key, value in blocked.items() if key != "_flow"}
            if blocked
            else None
        ),
    }


def flow_is_finished(flow: FlowRecord) -> bool:
    return flow.state not in OPEN_STATES


def result_components_for_artifact(artifact: str, flow: FlowRecord) -> list[str]:
    return [
        component
        for component in flow.artifacts_with_results
        if component == artifact or component.startswith(f"{artifact}/")
    ]


def query_artifact_source(
    api: VeloApiClient,
    client_id: str,
    flow_id: str,
    artifact: str,
    *,
    projection: list[str] | None = None,
    time_predicate: str = "",
    time_environment: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Read one component in bounded packets with an optional server predicate."""
    from vraptor.analyze import flow as flow_analysis
    from vraptor.analyze import flow_runtime as flow_analysis_runtime

    if not hasattr(api, "query") and hasattr(api, "query_file"):
        if str(time_predicate or "").strip():
            raise RuntimeError(
                "Server-side analysis time filtering requires the direct VQL "
                "query API; refusing to return an unfiltered exact source."
            )
        env = {
            "ClientId": client_id,
            "FlowId": flow_id,
            "ArtifactName": artifact,
        }
        last_error: grpc.RpcError | None = None
        for max_row in (5_000, 2_500, 1_000, 500, 100, 10, 1):
            try:
                return api.query_file(
                    "export_source.vql",
                    env,
                    timeout=0,
                    max_wait=30,
                    max_row=max_row,
                )
            except grpc.RpcError as exc:
                if exc.code() != grpc.StatusCode.RESOURCE_EXHAUSTED:
                    raise
                last_error = exc
        if last_error is not None:
            raise last_error
        return []

    source = flow_analysis.FlowSource(
        org_id=str(getattr(api, "org_id", "root") or "root"),
        client_id=client_id,
        flow_id=flow_id,
        artifact=artifact,
    )
    rows: list[dict[str, Any]] = []
    for segment in flow_analysis_runtime.iter_flow_segments(
        api,
        [source],
        source_page_rows=flow_analysis.DEFAULT_ACQUISITION_WINDOW_ROWS,
        variable_large_artifacts=(
            (artifact,)
            if "evtx" in artifact.casefold() or "powershell" in artifact.casefold()
            else ()
        ),
        projections={artifact: projection} if projection else None,
        time_predicates=(
            {artifact: str(time_predicate)}
            if str(time_predicate or "").strip()
            else None
        ),
        time_environment=(
            dict(time_environment or {})
            if str(time_predicate or "").strip()
            else None
        ),
    ):
        rows.extend(segment.rows)
    return rows


def query_registry_hunter_categories(api: VeloApiClient, client_id: str, flow_id: str) -> list[str]:
    rows = api.query_file(
        "export_registry_hunter_categories.vql",
        {
            "ClientId": client_id,
            "FlowId": flow_id,
        },
        timeout=0,
        max_wait=30,
        max_row=1000,
    )
    return [str(row.get("Category")) for row in rows if str(row.get("Category") or "").strip()]


def query_registry_hunter_category_rows(
    api: VeloApiClient,
    client_id: str,
    flow_id: str,
    category: str,
) -> list[dict[str, Any]]:
    return api.query_file(
        "export_registry_hunter_category.vql",
        {
            "ClientId": client_id,
            "FlowId": flow_id,
            "RequestedCategory": category,
        },
        timeout=0,
        max_wait=30,
        max_row=1000,
    )


def query_curated_artifact_rows(
    api: VeloApiClient,
    artifact_name: str,
    client_id: str,
    flow_id: str,
) -> list[dict[str, Any]]:
    query_filename = CURATED_ARTIFACT_EXPORT_QUERIES.get(artifact_name) or CURATED_ARTIFACT_TEXT_EXPORT_QUERIES[artifact_name]
    last_error: grpc.RpcError | None = None
    for max_row in (1000, 250, 100, 50, 10, 1):
        try:
            return api.query_file(
                query_filename,
                {
                    "ClientId": client_id,
                    "FlowId": flow_id,
                },
                timeout=0,
                max_wait=30,
                max_row=max_row,
            )
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.RESOURCE_EXHAUSTED:
                raise
            last_error = exc
    if last_error is not None:
        raise last_error
    return []


def format_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    return str(value)


def csv_headers(rows: list[dict[str, Any]]) -> list[str]:
    headers: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key in seen:
                continue
            seen.add(key)
            headers.append(key)
    return headers


def write_csv(path: Path, rows: list[dict[str, Any]]) -> int:
    headers = csv_headers(rows)
    if not headers:
        path.unlink(missing_ok=True)
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({header: format_csv_value(row.get(header)) for header in headers})
    return len(rows)


def exported_output_file(path: Path, row_count: int) -> str:
    return str(path) if row_count > 0 else ""


def write_lines(path: Path, lines: list[str]) -> int:
    if not lines:
        path.unlink(missing_ok=True)
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for index, line in enumerate(lines):
            if index:
                handle.write("\n")
            handle.write(line)
    return len(lines)


def request_output_suffix(request: CollectionRequest) -> str:
    if not any(spec.env or spec.timeout_seconds is not None for spec in request.expected_specs):
        return ""
    parts: list[str] = []
    if request.target_collection_type == "timeline":
        parts.append("timeline")
        sample_spec = request.expected_specs[0]
        for key in ("DateAfter", "DateBefore"):
            value = sample_spec.env.get(key)
            if value:
                parts.append(slugify(value))
    parts.append(short_signature(serialize_specs(request.expected_specs)))
    return "-".join(parts)


def append_suffix(filename: str, suffix: str) -> str:
    if not suffix:
        return filename
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        return f"{filename}_{suffix}"
    return f"{stem}_{suffix}.{ext}"


def export_filename_for_artifact(label: str, suffix: str = "") -> str:
    return append_suffix(f"{label}_full.csv", suffix)


def export_filename_for_artifact_text(label: str, extension: str, suffix: str = "") -> str:
    return append_suffix(f"{label}.{extension}", suffix)


def export_filename_for_component(component: str, suffix: str = "") -> str:
    return append_suffix(f"{component.replace('/', '.')}.csv", suffix)


def export_filename_for_registry_category(category: str, suffix: str = "") -> str:
    return append_suffix(f"Windows.Registry.Hunter.{slugify(category)}.csv", suffix)


def export_generic_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> dict[str, Any]:
    components = list(artifact_status.get("available_result_components") or [])
    if not components and int(artifact_status.get("total_rows") or 0) == 0:
        output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
        row_count = write_csv(output_path, [])
        return {
            "artifact": artifact_status["artifact"],
            "flow_id": artifact_status["flow_id"],
            "mode": "full",
            "source_components": [],
            "row_count": row_count,
            "output_file": exported_output_file(output_path, row_count),
        }
    if not components:
        components = [str(artifact_status["artifact_name"])]

    rows: list[dict[str, Any]] = []
    for component in components:
        component_rows = query_artifact_source(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            component,
        )
        if len(components) > 1:
            component_rows = [
                {
                    "ExportComponent": component,
                    **row,
                }
                for row in component_rows
            ]
        rows.extend(component_rows)

    output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
    row_count = write_csv(output_path, rows)
    return {
        "artifact": artifact_status["artifact"],
        "flow_id": artifact_status["flow_id"],
        "mode": "full",
        "source_components": components,
        "row_count": row_count,
        "output_file": exported_output_file(output_path, row_count),
    }


def export_curated_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> dict[str, Any]:
    artifact_name = str(artifact_status["artifact_name"])
    rows = query_curated_artifact_rows(
        api,
        artifact_name,
        client_id,
        str(artifact_status["flow_id"]),
    )
    output_path = exports_dir / export_filename_for_artifact(str(artifact_status["artifact"]), filename_suffix)
    row_count = write_csv(output_path, rows)
    return {
        "artifact": artifact_status["artifact"],
        "flow_id": artifact_status["flow_id"],
        "mode": "curated",
        "query_file": str(REFERENCE_DIR / CURATED_ARTIFACT_EXPORT_QUERIES[artifact_name]),
        "source_components": [artifact_name],
        "row_count": row_count,
        "output_file": exported_output_file(output_path, row_count),
    }


def export_curated_text_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> dict[str, Any]:
    artifact_name = str(artifact_status["artifact_name"])
    rows = query_curated_artifact_rows(
        api,
        artifact_name,
        client_id,
        str(artifact_status["flow_id"]),
    )
    lines = [str(row.get("BodyLine") or "") for row in rows if str(row.get("BodyLine") or "").strip()]
    output_path = exports_dir / export_filename_for_artifact_text(str(artifact_status["artifact"]), "body", filename_suffix)
    row_count = write_lines(output_path, lines)
    return {
        "artifact": artifact_status["artifact"],
        "flow_id": artifact_status["flow_id"],
        "mode": "curated-text",
        "query_file": str(REFERENCE_DIR / CURATED_ARTIFACT_TEXT_EXPORT_QUERIES[artifact_name]),
        "source_components": [artifact_name],
        "row_count": row_count,
        "output_file": exported_output_file(output_path, row_count),
    }


def export_multi_scope_artifact(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> list[dict[str, Any]]:
    exports: list[dict[str, Any]] = []
    for component in MULTI_SCOPE_ARTIFACT_EXPORTS[str(artifact_status["artifact_name"])]:
        rows = query_artifact_source(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            component,
        )
        output_path = exports_dir / export_filename_for_component(component, filename_suffix)
        row_count = write_csv(output_path, rows)
        exports.append(
            {
                "artifact": artifact_status["artifact"],
                "flow_id": artifact_status["flow_id"],
                "mode": "component",
                "source_components": [component],
                "row_count": row_count,
                "output_file": exported_output_file(output_path, row_count),
            }
        )
    return exports


def export_registry_hunter(
    api: VeloApiClient,
    client_id: str,
    exports_dir: Path,
    artifact_status: dict[str, Any],
    filename_suffix: str,
) -> list[dict[str, Any]]:
    results_component = "Windows.Registry.Hunter/Results"
    exports: list[dict[str, Any]] = []
    for category in sorted(query_registry_hunter_categories(api, client_id, str(artifact_status["flow_id"]))):
        rows = query_registry_hunter_category_rows(
            api,
            client_id,
            str(artifact_status["flow_id"]),
            category,
        )
        output_path = exports_dir / export_filename_for_registry_category(category, filename_suffix)
        row_count = write_csv(output_path, rows)
        exports.append(
            {
                "artifact": artifact_status["artifact"],
                "flow_id": artifact_status["flow_id"],
                "mode": "registry-category",
                "category": category,
                "source_components": [results_component],
                "row_count": row_count,
                "output_file": exported_output_file(output_path, row_count),
            }
        )
    return exports


def annotate_exported_files_with_provenance(
    exported_files: list[dict[str, Any]],
    artifact_statuses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    statuses_by_artifact = {
        str(item.get("artifact") or "").strip(): item
        for item in artifact_statuses
        if str(item.get("artifact") or "").strip()
    }
    exports_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for item in exported_files:
        artifact_label = str(item.get("artifact") or "").strip()
        if artifact_label:
            exports_by_artifact.setdefault(artifact_label, []).append(item)

    annotated: list[dict[str, Any]] = []
    for item in exported_files:
        artifact_label = str(item.get("artifact") or "").strip()
        artifact_status = statuses_by_artifact.get(artifact_label, fallback_artifact_status(artifact_label))
        classification = output_classification_for_artifact(
            artifact_status,
            exports_by_artifact.get(artifact_label, []),
        )
        annotated.append(
            {
                **item,
                "flow_state": str(artifact_status.get("flow_state") or "").strip(),
                "output_classification": classification,
                "output_caveat": output_caveat_for_classification(classification),
            }
        )
    return annotated


def artifact_output_classifications(
    artifact_statuses: list[dict[str, Any]],
    exported_files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    exports_by_artifact: dict[str, list[dict[str, Any]]] = {}
    for item in exported_files:
        artifact_label = str(item.get("artifact") or "").strip()
        if artifact_label:
            exports_by_artifact.setdefault(artifact_label, []).append(item)

    classifications: list[dict[str, Any]] = []
    for artifact_status in artifact_statuses:
        artifact_label = str(artifact_status.get("artifact") or "").strip()
        artifact_exports = exports_by_artifact.get(artifact_label, [])
        classification = output_classification_for_artifact(
            artifact_status,
            artifact_exports,
        )
        classifications.append(
            {
                "artifact": artifact_label,
                "flow_id": str(artifact_status.get("flow_id") or "").strip(),
                "flow_state": str(artifact_status.get("flow_state") or "").strip(),
                "total_rows": int(artifact_status.get("total_rows") or 0),
                "exported_row_count": sum(int(item.get("row_count") or 0) for item in artifact_exports),
                "exported_files": [
                    str(item.get("output_file") or "")
                    for item in artifact_exports
                    if str(item.get("output_file") or "").strip()
                ],
                "output_classification": classification,
                "output_caveat": output_caveat_for_classification(classification),
            }
        )
    return classifications


def output_classification_counts(classifications: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in classifications:
        classification = str(item.get("output_classification") or "").strip()
        if classification:
            counts[classification] = counts.get(classification, 0) + 1
    return counts


def resolve_export_request(args: argparse.Namespace, investigation_id: str, hostname: str) -> CollectionRequest:
    has_explicit_target = bool(
        getattr(args, "collection_type", None)
        or getattr(args, "bundle", None)
        or getattr(args, "collection_group", None)
        or getattr(args, "target_mode", None)
        or getattr(args, "artifact", None)
        or getattr(args, "env", None)
        or timeline_options_present(timeline_options_from_args(args))
    )
    if getattr(args, "request_id", None) and has_explicit_target:
        raise RuntimeError("--request-id cannot be combined with explicit export target arguments.")
    if has_explicit_target:
        return build_request_from_args(args)

    state_path = get_state_path(investigation_id, hostname, getattr(args, "request_id", None))
    if not state_path.exists():
        raise RuntimeError(
            "No export target was supplied and no saved state file exists. "
            "Pass --bundle, --collection-group, --collection-type, --artifact, "
            "or queue a collection first."
        )
    state = read_state(state_path)
    return request_from_state(state, normalize_artifacts(state.get("requested_artifacts")))


def export_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    client: ClientRecord | None = None,
    artifact_statuses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    resolve_policy_request_for_api(api, request)
    if artifact_statuses is None:
        client, artifact_statuses = get_matching_artifact_statuses(
            api,
            hostname,
            request,
            client=client,
        )
    else:
        client = client or get_client(api, hostname)
    ensure_exportable_artifacts(artifact_statuses)
    raise_for_effective_argument_validation(
        artifact_statuses,
        context="collection export",
    )
    persistence_authorization = persistence_policy.authorize_persistence(
        "immutable_evidence_export",
        source_ids=[
            "flow:"
            + ":".join(
                (
                    client.client_id,
                    str(item.get("flow_id") or ""),
                    str(item.get("artifact_name") or item.get("artifact") or ""),
                )
            )
            for item in artifact_statuses
        ],
        raw_rows=True,
        explicit_export=True,
    )

    exports_dir = get_exports_dir(investigation_id, hostname)
    exports_dir.mkdir(parents=True, exist_ok=True)
    filename_suffix = request_output_suffix(request)

    exported_files: list[dict[str, Any]] = []
    for artifact_status in artifact_statuses:
        if str(artifact_status["artifact_name"]) == "Windows.Registry.Hunter":
            exported_files.extend(
                export_registry_hunter(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        elif str(artifact_status["artifact_name"]) in CURATED_ARTIFACT_TEXT_EXPORT_QUERIES:
            exported_files.append(
                export_curated_text_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        elif str(artifact_status["artifact_name"]) in CURATED_ARTIFACT_EXPORT_QUERIES:
            exported_files.append(
                export_curated_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        elif str(artifact_status["artifact_name"]) in MULTI_SCOPE_ARTIFACT_EXPORTS:
            exported_files.extend(
                export_multi_scope_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
        else:
            exported_files.append(
                export_generic_artifact(api, client.client_id, exports_dir, artifact_status, filename_suffix)
            )
    exported_files = annotate_exported_files_with_provenance(exported_files, artifact_statuses)
    output_classifications = artifact_output_classifications(artifact_statuses, exported_files)

    request_identity = collection_run_identity(
        client.client_id,
        request.expected_specs,
    )
    manifest = {
        "exported_at": now_utc(),
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "run_identity": request_identity["identity"],
        "run_identity_sha256": request_identity["sha256"],
        "reuse_decisions": [
            {
                "artifact": item.get("artifact", ""),
                "flow_id": item.get("flow_id", ""),
                "classification": item.get("reuse_classification", ""),
                "decision": item.get("reuse_decision", ""),
                "reason": item.get("reuse_reason", ""),
                "force_run_requested": bool(
                    item.get("force_run_requested", False)
                ),
            }
            for item in artifact_statuses
        ],
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
        "artifact_output_classifications": output_classifications,
        "output_classification_counts": output_classification_counts(output_classifications),
        "persistence_authorization": persistence_authorization,
        "exported_files": exported_files,
    }
    manifest_name = f"velociraptor-collection-export-{slugify(request.target_collection_type)}.json"
    manifest_path = exports_dir / append_suffix(manifest_name, filename_suffix)
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def get_matching_artifact_statuses(
    api: VeloApiClient,
    hostname: str,
    request: CollectionRequest,
    client: ClientRecord | None = None,
) -> tuple[ClientRecord, list[dict[str, Any]]]:
    client = client or get_client(api, hostname)
    all_flows = get_all_flows(api, client.client_id)
    artifact_statuses: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        selection = select_matching_flow_for_spec(
            api,
            client.client_id,
            expected,
            flows=all_flows,
        )
        flow = selection["selected_flow"] or selection["blocked_flow"]
        artifact_statuses.append(
            apply_reuse_audit(
                artifact_status_from_flow(expected, flow),
                selection,
                decision=(
                    "export_exact_flow"
                    if selection["selected_flow"] is not None
                    else "export_not_ready"
                ),
                reason=(
                    "selected the highest-ranked exact flow for explicit export"
                    if selection["selected_flow"] is not None
                    else "no reusable exact flow is available for export"
                ),
            )
        )
    return client, artifact_statuses


def ensure_exportable_artifacts(artifact_statuses: list[dict[str, Any]]) -> None:
    incomplete = [
        item["artifact"]
        for item in artifact_statuses
        if not item["matching_flow_found"] or not item["is_finished"]
    ]
    if incomplete:
        raise RuntimeError(
            "Cannot export incomplete collection target. Missing or unfinished artifacts: "
            + ", ".join(incomplete)
        )


def export_registry_hunter_curated_profile(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    profile: str,
    *,
    client: ClientRecord | None = None,
) -> dict[str, Any]:
    if profile not in REGISTRY_HUNTER_CURATED_PROFILES:
        raise RuntimeError(
            f"Unsupported Registry Hunter profile {profile!r}. "
            f"Supported profiles: {', '.join(sorted(REGISTRY_HUNTER_CURATED_PROFILES))}"
        )

    preset = REGISTRY_HUNTER_PROFILE_PRESETS[profile]
    collection_label = f"Windows.Registry.Hunter[{preset}]"
    request = build_request(None, [collection_label], [])
    client, artifact_statuses = get_matching_artifact_statuses(api, hostname, request, client=client)
    ensure_exportable_artifacts(artifact_statuses)
    raise_for_effective_argument_validation(
        artifact_statuses,
        context="curated Registry Hunter export",
    )
    registry_status = artifact_statuses[0]
    persistence_authorization = persistence_policy.authorize_persistence(
        "interoperability_export",
        source_ids=[
            "flow:"
            + ":".join(
                (
                    client.client_id,
                    str(registry_status.get("flow_id") or ""),
                    str(
                        registry_status.get("artifact_name")
                        or registry_status.get("artifact")
                        or ""
                    ),
                )
            )
        ],
        raw_rows=True,
        explicit_export=True,
    )

    exports_dir = get_exports_dir(investigation_id, hostname)
    exports_dir.mkdir(parents=True, exist_ok=True)

    exported_files: list[dict[str, Any]] = []
    for output_name, query_filename in REGISTRY_HUNTER_CURATED_PROFILES[profile]:
        rows = api.query_file(
            query_filename,
            {
                "ClientId": client.client_id,
                "FlowId": str(registry_status["flow_id"]),
            },
            timeout=0,
            max_wait=30,
            max_row=500,
        )
        output_path = exports_dir / output_name
        row_count = write_csv(output_path, rows)
        exported_files.append(
            {
                "artifact": registry_status["artifact"],
                "flow_id": registry_status["flow_id"],
                "mode": "registry-curated",
                "profile": profile,
                "query_file": str(REFERENCE_DIR / query_filename),
                "row_count": row_count,
                "output_file": exported_output_file(output_path, row_count),
            }
        )

    exported_files = annotate_exported_files_with_provenance(exported_files, artifact_statuses)
    output_classifications = artifact_output_classifications(artifact_statuses, exported_files)
    manifest = {
        "exported_at": now_utc(),
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "target_collection_type": collection_label,
        "profile": profile,
        "requested_groups": ["registry"],
        "requested_artifacts": [collection_label],
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
        "artifact_output_classifications": output_classifications,
        "output_classification_counts": output_classification_counts(output_classifications),
        "persistence_authorization": persistence_authorization,
        "exported_files": exported_files,
    }
    manifest_path = exports_dir / f"velociraptor-collection-export-registry-hunter-{slugify(profile)}.json"
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def artifact_status_from_flow(expected: ArtifactSpec, flow: FlowRecord | None, queue_response_file: str = "") -> dict[str, Any]:
    validation = effective_argument_validation(expected, flow)
    if flow is None:
        return {
            "artifact": expected.label,
            "artifact_name": expected.artifact,
            "expected_env": dict(sorted(expected.env.items())),
            "expected_timeout_seconds": expected.timeout_seconds,
            "matching_flow_found": False,
            "matching_flow_matches_expected_arguments": False,
            "flow_id": "",
            "flow_state": "MISSING",
            "created": "",
            "last_active": "",
            "matched_flow_request_timeout_seconds": None,
            "total_rows": 0,
            "matched_flow_requested_specs": [],
            "server_effective_spec_arguments": [],
            "server_compiled_collector_args": [],
            "effective_argument_source": "",
            "effective_argument_validation": validation,
            "available_result_components": [],
            "is_finished": False,
            "is_expected_complete": False,
            "queue_response_file": queue_response_file,
        }

    return {
        "artifact": expected.label,
        "artifact_name": expected.artifact,
        "expected_env": dict(sorted(expected.env.items())),
        "expected_timeout_seconds": expected.timeout_seconds,
        "matching_flow_found": True,
        "matching_flow_matches_expected_arguments": flow_matches_spec(flow, expected),
        "flow_id": flow.session_id,
        "flow_state": flow.state,
        "created": flow.created,
        "last_active": flow.last_active,
        "matched_flow_request_timeout_seconds": flow.request_timeout_seconds,
        "total_rows": flow.total_rows,
        "matched_flow_requested_specs": serialize_specs(flow.requested_specs),
        "server_effective_spec_arguments": serialize_specs(flow.requested_specs),
        "server_compiled_collector_args": list(flow.compiled_collector_args),
        "effective_argument_source": (
            "flow.request.compiled_collector_args+flow.request.specs"
            if flow.compiled_collector_args
            else "flow.request.specs"
        ),
        "effective_argument_validation": validation,
        "available_result_components": result_components_for_artifact(expected.artifact, flow),
        "is_finished": flow_is_finished(flow),
        "is_expected_complete": flow_is_finished(flow),
        "queue_response_file": queue_response_file,
    }


def apply_reuse_audit(
    artifact_status: dict[str, Any],
    selection: dict[str, Any],
    *,
    decision: str,
    reason: str,
    force_run: bool = False,
) -> dict[str, Any]:
    artifact_status["run_identity"] = dict(selection["run_identity"])
    artifact_status["run_identity_sha256"] = str(selection["run_identity_sha256"])
    artifact_status["exact_match_count"] = int(selection["exact_match_count"])
    artifact_status["exact_match_candidates"] = list(
        selection["exact_match_candidates"]
    )
    artifact_status["near_match_mismatches"] = list(
        selection.get("near_match_mismatches") or []
    )
    selected = selection.get("selected_candidate") or {}
    blocked = selection.get("blocked_candidate") or {}
    artifact_status["reuse_classification"] = str(
        selected.get("classification")
        or blocked.get("classification")
        or "no_exact_match"
    )
    artifact_status["reuse_decision"] = decision
    artifact_status["reuse_reason"] = reason
    artifact_status["force_run_requested"] = bool(force_run)
    return artifact_status


def summarize_artifact_statuses(artifact_statuses: list[dict[str, Any]]) -> dict[str, Any]:
    artifacts_missing = [item["artifact"] for item in artifact_statuses if not item["matching_flow_found"]]
    artifacts_in_progress = [
        item["artifact"] for item in artifact_statuses if item["matching_flow_found"] and not item["is_finished"]
    ]
    artifacts_finished = [item["artifact"] for item in artifact_statuses if item["is_finished"]]
    artifacts_with_results = [
        item["artifact"] for item in artifact_statuses if item["available_result_components"]
    ]
    artifacts_expected_no_results = [
        item["artifact"] for item in artifact_statuses if item["is_finished"] and not item["available_result_components"]
    ]

    return {
        "all_artifacts_have_matching_flow": not artifacts_missing,
        "all_artifacts_expected_complete": all(item["is_expected_complete"] for item in artifact_statuses),
        "artifacts_missing": artifacts_missing,
        "artifacts_in_progress": artifacts_in_progress,
        "artifacts_finished": artifacts_finished,
        "artifacts_with_results": artifacts_with_results,
        "artifacts_expected_no_results": artifacts_expected_no_results,
    }


def build_state_payload(
    client: ClientRecord,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    artifact_statuses: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact_flows: dict[str, Any] = {}
    for item in artifact_statuses:
        artifact_flows[item["artifact"]] = {
            "flow_id": item["flow_id"],
            "queue_response_file": item["queue_response_file"],
            "matched_flow_requested_specs": item["matched_flow_requested_specs"],
            "artifact_name": item["artifact_name"],
            "expected_env": item["expected_env"],
            "expected_timeout_seconds": item["expected_timeout_seconds"],
            "matched_flow_request_timeout_seconds": item["matched_flow_request_timeout_seconds"],
            "run_identity": item.get("run_identity", {}),
            "run_identity_sha256": item.get("run_identity_sha256", ""),
            "exact_match_count": item.get("exact_match_count", 0),
            "exact_match_candidates": item.get("exact_match_candidates", []),
            "near_match_mismatches": item.get("near_match_mismatches", []),
            "reuse_classification": item.get("reuse_classification", ""),
            "reuse_decision": item.get("reuse_decision", ""),
            "reuse_reason": item.get("reuse_reason", ""),
            "force_run_requested": bool(item.get("force_run_requested", False)),
            "analysis_inputs": dict(
                request.analysis_inputs.get(str(item["artifact"]), {})
            ),
        }

    request_identity = collection_run_identity(
        client.client_id,
        request.expected_specs,
    )
    return {
        "queued_at": now_utc(),
        "updated_at": now_utc(),
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "run_identity": request_identity["identity"],
        "run_identity_sha256": request_identity["sha256"],
        "reuse_decisions": [
            {
                "artifact": item["artifact"],
                "flow_id": item["flow_id"],
                "classification": item.get("reuse_classification", ""),
                "decision": item.get("reuse_decision", ""),
                "reason": item.get("reuse_reason", ""),
                "force_run_requested": bool(
                    item.get("force_run_requested", False)
                ),
            }
            for item in artifact_statuses
        ],
        "artifact_flows": artifact_flows,
        **effective_arguments_payload(artifact_statuses),
    }


def write_state(
    investigation_id: str,
    hostname: str,
    payload: dict[str, Any],
    *,
    update_current_pointer: bool = True,
) -> None:
    request_id = str(payload.get("request_id", "")).strip()
    if not request_id:
        request = request_from_state(payload, normalize_artifacts(payload.get("requested_artifacts")))
        request_id = request_id_for_request(request)
    request_state_path = get_request_state_path(investigation_id, hostname, request_id)
    payload["request_id"] = request_id
    payload["layout_version"] = layout.LAYOUT_VERSION
    payload["state_file"] = str(request_state_path)
    payload["current_state_file"] = str(get_current_state_path(investigation_id, hostname))
    persisted_payload = dict(payload)
    persisted_payload["state_file"] = engagement_relative_path(
        investigation_id,
        request_state_path,
    )
    persisted_payload["current_state_file"] = engagement_relative_path(
        investigation_id,
        get_current_state_path(investigation_id, hostname),
    )
    write_system_identity(investigation_id, hostname, payload)
    write_json(request_state_path, persisted_payload)
    if update_current_pointer:
        current_path = get_current_state_path(investigation_id, hostname)
        write_json(
            current_path,
            {
                "layout_version": layout.LAYOUT_VERSION,
                "latest_request_id": request_id,
                "state_file": os.path.relpath(
                    request_state_path,
                    current_path.parent,
                ),
                "updated_at": str(payload.get("updated_at") or now_utc()),
            },
        )


def queue_single_artifact(
    api: VeloApiClient,
    client: ClientRecord,
    investigation_id: str,
    hostname: str,
    expected: ArtifactSpec,
    timeout_seconds: int,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("queue_single_artifact")
    output_dir = get_output_dir(investigation_id, hostname)
    output_dir.mkdir(parents=True, exist_ok=True)

    event = {
        "phase": "queue",
        "artifact": expected.label,
        "status": "submitting",
    }
    if progress_callback is not None:
        progress_callback(event)
    before_ids = {flow.session_id for flow in get_all_flows(api, client.client_id)}
    query_timeout = min(
        max(1, int(timeout_seconds)),
        DEFAULT_QUEUE_API_TIMEOUT_SECONDS,
    )
    try:
        rows = api.query_file(
            "queue_collect_client.vql",
            {
                "ClientId": client.client_id,
                "Artifacts": json.dumps([expected.artifact]),
                "Spec": json.dumps(
                    spec_to_request_dict(expected),
                    separators=(",", ":"),
                ),
                "FlowTimeoutSeconds": str(expected.timeout_seconds or 0),
            },
            timeout=query_timeout,
        )
    except grpc.RpcError as exc:
        if exc.code() != grpc.StatusCode.DEADLINE_EXCEEDED:
            raise
        rows = []
        if progress_callback is not None:
            progress_callback(
                {
                    **event,
                    "status": "submission_timed_out",
                    "error": str(exc),
                }
            )
    flow_id = ""
    if rows:
        flow_id = str(rows[0].get("flow_id", ""))

    discovery_timeout = min(
        max(1, int(timeout_seconds)),
        DEFAULT_QUEUE_DISCOVERY_TIMEOUT_SECONDS,
    )
    deadline = time.time() + discovery_timeout
    flow: FlowRecord | None = None
    while time.time() < deadline:
        if flow_id:
            try:
                flow = get_flow(api, client.client_id, flow_id)
            except RuntimeError:
                flow = None
        else:
            for candidate in get_all_flows(api, client.client_id):
                if candidate.session_id in before_ids:
                    continue
                if flow_matches_spec(candidate, expected):
                    flow = candidate
                    break
        if flow is not None:
            break
        time.sleep(2)

    if flow is None:
        raise RuntimeError(f"Timed out waiting for queued flow id for {expected.label} on {hostname}")

    if progress_callback is not None:
        progress_callback(
            {
                **event,
                "status": "queued",
                "flow_id": flow.session_id,
                "flow_state": flow.state,
            }
        )
    return artifact_status_from_flow(expected, flow, "")


def legacy_artifact_flow_map(state: dict[str, Any], request: CollectionRequest) -> dict[str, Any]:
    artifact_flows = state.get("artifact_flows")
    if isinstance(artifact_flows, dict):
        return artifact_flows

    flow_id = state.get("flow_id")
    if not flow_id:
        return {}

    collect_stdout_file = str(state.get("collect_stdout_file", ""))
    return {
        artifact: {
            "flow_id": flow_id,
            "queue_response_file": collect_stdout_file,
            "matched_flow_requested_specs": state.get("matched_flow_requested_specs", []),
        }
        for artifact in request.requested_artifacts
    }


def request_from_state(state: dict[str, Any], fallback_artifacts: list[str]) -> CollectionRequest:
    requested_groups = normalize_artifacts(state.get("requested_groups"))
    requested_artifacts = normalize_artifacts(state.get("requested_artifacts")) or fallback_artifacts
    expected_specs = normalize_specs_value(state.get("expected_spec_arguments")) or build_expected_specs(requested_artifacts)
    target_collection_type = str(state.get("target_collection_type", "")) or "+".join(requested_groups)
    return CollectionRequest(
        target_collection_type=target_collection_type,
        requested_groups=requested_groups,
        requested_artifacts=requested_artifacts,
        expected_specs=expected_specs,
        analysis_inputs={
            str(artifact): {
                str(key): str(value)
                for key, value in dict(inputs or {}).items()
            }
            for artifact, inputs in dict(state.get("analysis_inputs") or {}).items()
            if isinstance(inputs, dict)
        },
        supersedes_request_id=str(state.get("supersedes_request_id") or ""),
        unavailable_artifacts=normalize_artifacts(
            state.get("unavailable_artifacts")
        ),
        collection_bundle=str(state.get("collection_bundle") or ""),
        target_mode=str(state.get("target_mode") or ""),
        candidate_artifacts=normalize_artifacts(
            state.get("candidate_artifacts")
        ),
        collection_policy=dict(state.get("collection_policy") or {}),
        collection_resolution=dict(state.get("collection_resolution") or {}),
    )


def validate_request_supersession(
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    *,
    api: VeloApiClient | None = None,
    client: ClientRecord | None = None,
) -> None:
    previous_request_id = str(
        getattr(request, "supersedes_request_id", "") or ""
    ).strip()
    if not previous_request_id:
        return
    previous_path = get_request_state_path(
        investigation_id,
        hostname,
        previous_request_id,
    )
    if not previous_path.is_file():
        raise RuntimeError(
            f"Superseded request state does not exist: {previous_path}"
        )
    previous = read_state(previous_path)
    if str(previous.get("hostname") or hostname) != hostname:
        raise RuntimeError("Superseded request belongs to a different hostname.")
    if client is not None and str(previous.get("client_id") or "") != client.client_id:
        raise RuntimeError("Superseded request belongs to a different client ID.")
    preflight = dict(previous.get("artifact_preflight") or {})
    if str(preflight.get("status") or "") != "failed":
        raise RuntimeError(
            "Superseded request must contain a failed artifact preflight."
        )
    checked_at = str(preflight.get("checked_at") or "").strip()
    try:
        checked_time = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(
            "Superseded request artifact preflight has no valid checked_at."
        ) from exc
    if checked_time.tzinfo is None:
        raise RuntimeError(
            "Superseded request artifact preflight checked_at needs a timezone."
        )
    if api is not None:
        saved_org_id = resolve_org_id(str(preflight.get("org_id") or ""))
        current_org_id = resolve_org_id(str(getattr(api, "org_id", "") or ""))
        if not str(preflight.get("org_id") or "").strip() or saved_org_id != current_org_id:
            raise RuntimeError(
                "Superseded request artifact preflight belongs to a different org."
            )
        api_config_value = getattr(api, "api_config", None)
        if not isinstance(api_config_value, (str, Path)):
            raise RuntimeError(
                "Current API client path is unavailable for supersession validation."
            )
        current_api_path = Path(api_config_value).expanduser().resolve()
        saved_api_path = str(preflight.get("api_client_path") or "").strip()
        saved_api_hash = str(preflight.get("api_client_sha256") or "").strip()
        if not saved_api_path or Path(saved_api_path).expanduser().resolve() != current_api_path:
            raise RuntimeError(
                "Superseded request artifact preflight belongs to a different API client path."
            )
        if not current_api_path.is_file() or not saved_api_hash:
            raise RuntimeError(
                "API client content hash is unavailable for supersession validation."
            )
        current_api_hash = sha256_file(current_api_path)
        if saved_api_hash != current_api_hash:
            raise RuntimeError(
                "Superseded request artifact preflight belongs to a different API client configuration."
            )
    previous_requested = {
        str(value)
        for value in preflight.get("requested_artifacts") or []
        if str(value).strip()
    }
    previous_available = {
        str(value)
        for value in preflight.get("available_artifacts") or []
        if str(value).strip()
    }
    previous_missing = {
        str(value)
        for value in preflight.get("missing_artifacts") or []
        if str(value).strip()
    }
    requested = {spec.artifact for spec in request.expected_specs}
    unavailable = set(request.unavailable_artifacts)
    if unavailable != previous_missing:
        raise RuntimeError(
            "--unavailable-artifact values must exactly match the superseded "
            "request's failed preflight."
        )
    if requested != previous_available:
        raise RuntimeError(
            "Replacement request must contain the complete supported intersection "
            "from the superseded preflight."
        )
    if requested | unavailable != previous_requested:
        raise RuntimeError(
            "Replacement request does not account for every artifact in the "
            "superseded preflight."
        )
    prior_flows = legacy_artifact_flow_map(
        previous,
        request_from_state(
            previous,
            normalize_artifacts(previous.get("requested_artifacts")),
        ),
    )
    if any(
        str(item.get("flow_id") or "").strip()
        for item in prior_flows.values()
    ):
        raise RuntimeError(
            "Supersession is only valid for a failed preflight request with no "
            "recorded flow IDs; resume requests that already own flows."
        )


def get_saved_client(api: VeloApiClient, state: dict[str, Any], hostname: str) -> ClientRecord:
    saved_client_id = str(state.get("client_id") or "").strip()
    if saved_client_id:
        saved_client = get_client_by_id(api, saved_client_id, fallback_hostname=hostname)
        if saved_client is not None:
            return apply_saved_client_selection(saved_client, state, hostname)
        raise RuntimeError(
            f"Saved client {saved_client_id} for host {hostname} is no longer present. "
            "The mapped client may have been remapped; rerun ensure to queue fresh flows."
        )
    return apply_saved_client_selection(get_client(api, hostname), state, hostname)


def check_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    *,
    client: ClientRecord | None = None,
) -> dict[str, Any]:
    resolve_policy_request_for_api(api, request)
    client = client or get_client(api, hostname)
    all_flows = get_all_flows(api, client.client_id)
    artifact_statuses: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        selection = select_matching_flow_for_spec(
            api,
            client.client_id,
            expected,
            flows=all_flows,
        )
        selected_flow = selection["selected_flow"]
        blocked_flow = selection["blocked_flow"]
        if selected_flow is not None:
            classification = str(
                (selection.get("selected_candidate") or {}).get("classification")
                or ""
            )
            decision = "reuse_exact_match"
            reason = (
                "terminal successful exact match is reusable"
                if classification == run_identity.TERMINAL_SUCCESS
                else "in-flight exact match is reusable"
            )
            status_flow = selected_flow
        elif blocked_flow is not None:
            decision = "force_run_required"
            reason = (
                "only failed or cancelled exact matches exist; "
                "pass --force-run to queue a fresh flow"
            )
            status_flow = blocked_flow
        else:
            decision = "queue_new_flow"
            reason = "no exact prior flow matches the requested run identity"
            status_flow = None
        artifact_statuses.append(
            apply_reuse_audit(
                artifact_status_from_flow(expected, status_flow),
                selection,
                decision=decision,
                reason=reason,
            )
        )

    request_identity = collection_run_identity(
        client.client_id,
        request.expected_specs,
    )
    return {
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "state_file": str(get_request_state_path(investigation_id, hostname, request_id_for_request(request))),
        "current_state_file": str(get_current_state_path(investigation_id, hostname)),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "run_identity": request_identity["identity"],
        "run_identity_sha256": request_identity["sha256"],
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
    }


def plan_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    *,
    client: ClientRecord | None = None,
) -> dict[str, Any]:
    """Resolve server capabilities without finding, queueing, or persisting flows."""
    resolve_policy_request_for_api(api, request)
    client = client or get_client(api, hostname)
    preflight = preflight_artifact_availability(api, request)
    request_identity = collection_run_identity(client.client_id, request.expected_specs)
    return {
        "action": "planned_only",
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "artifact_preflight": preflight,
        "followups": collection_policy_followups(),
        "run_identity": request_identity["identity"],
        "run_identity_sha256": request_identity["sha256"],
        "flows_queried": False,
        "flows_queued": False,
        "state_persisted": False,
    }


def queue_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    timeout_seconds: int,
    *,
    client: ClientRecord | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("queue_collection")
    resolve_policy_request_for_api(api, request)
    client = client or get_client(api, hostname)
    total_artifacts = len(request.expected_specs)
    if progress_callback is not None:
        progress_callback(
            {
                "phase": "preflight",
                "status": "running",
                "completed": 0,
                "total": total_artifacts,
            }
        )
    preflight = preflight_artifact_availability(api, request)
    raise_for_missing_server_artifacts(preflight)
    if progress_callback is not None:
        progress_callback(
            {
                "phase": "checking-flows",
                "status": "running",
                "completed": 0,
                "total": total_artifacts,
            }
        )
    all_flows = get_all_flows(api, client.client_id)
    artifact_statuses: list[dict[str, Any]] = []
    for index, expected in enumerate(request.expected_specs, start=1):
        selection = select_matching_flow_for_spec(
            api,
            client.client_id,
            expected,
            flows=all_flows,
        )
        status = queue_single_artifact(
            api,
            client,
            investigation_id,
            hostname,
            expected,
            timeout_seconds,
            progress_callback=(
                lambda event, completed=index - 1: progress_callback(
                    {
                        **event,
                        "completed": completed,
                        "total": total_artifacts,
                    }
                )
                if progress_callback is not None
                else None
            ),
        )
        artifact_statuses.append(
            apply_reuse_audit(
                status,
                selection,
                decision="explicit_new_flow",
                reason=(
                    "the queue command explicitly requests a new flow and "
                    f"bypassed {selection['exact_match_count']} exact prior match(es)"
                ),
                force_run=True,
            )
        )
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": "queueing",
                    "status": "running",
                    "artifact": expected.label,
                    "flow_id": status.get("flow_id", ""),
                    "completed": index,
                    "total": total_artifacts,
                }
            )
    if progress_callback is not None:
        progress_callback(
            {
                "phase": "persisting",
                "status": "running",
                "completed": total_artifacts,
                "total": total_artifacts,
            }
        )
    state = build_state_payload(client, investigation_id, hostname, request, artifact_statuses)
    state["artifact_preflight"] = dict(preflight)
    write_state(investigation_id, hostname, state)
    raise_for_effective_argument_validation(
        artifact_statuses,
        context="queued collection handoff",
    )
    return {
        "action": "queued_new_flows",
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "state_file": state["state_file"],
        "current_state_file": state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "artifact_preflight": preflight,
        "run_identity": state["run_identity"],
        "run_identity_sha256": state["run_identity_sha256"],
        "reuse_decisions": state["reuse_decisions"],
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
    }


def _status_payload_unlocked(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request_id: str | None = None,
    *,
    client: ClientRecord | None = None,
) -> dict[str, Any]:
    state_path = get_state_path(investigation_id, hostname, request_id)
    if not state_path.exists():
        raise RuntimeError(f"No saved state file found at {state_path}")

    state = read_state(state_path)
    request = request_from_state(state, normalize_artifacts(state.get("requested_artifacts")))
    saved_client = get_saved_client(api, state, hostname)
    if client is not None and client.client_id != saved_client.client_id:
        raise RuntimeError(
            f"Saved state for {hostname} belongs to {saved_client.client_id}, "
            f"not requested client {client.client_id}."
        )
    client = apply_saved_client_selection(client or saved_client, state, hostname)
    artifact_flow_map = legacy_artifact_flow_map(state, request)
    live_flows = get_all_flows(api, client.client_id)
    live_flows_by_id = {
        str(flow.session_id): flow
        for flow in live_flows
        if str(flow.session_id).strip()
    }

    artifact_statuses: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        stored = artifact_flow_map.get(expected.label, {})
        if not stored and expected.label != expected.artifact:
            stored = artifact_flow_map.get(expected.artifact, {})
        flow_id = str(stored.get("flow_id", ""))
        if not flow_id:
            selection = select_matching_flow_for_spec(
                api,
                client.client_id,
                expected,
                flows=[],
            )
            artifact_statuses.append(
                apply_reuse_audit(
                    artifact_status_from_flow(
                        expected,
                        None,
                        str(stored.get("queue_response_file", "")),
                    ),
                    selection,
                    decision=str(
                        stored.get("reuse_decision") or "saved_flow_missing"
                    ),
                    reason=str(
                        stored.get("reuse_reason")
                        or "saved collection state does not contain a flow id"
                    ),
                    force_run=bool(stored.get("force_run_requested", False)),
                )
            )
            continue
        flow = live_flows_by_id.get(flow_id)
        if flow is None:
            raise RuntimeError(
                f"Flow {flow_id} not found for client {client.client_id}"
            )
        selection = select_matching_flow_for_spec(
            api,
            client.client_id,
            expected,
            flows=[flow],
        )
        artifact_statuses.append(
            apply_reuse_audit(
                artifact_status_from_flow(
                    expected,
                    flow,
                    str(stored.get("queue_response_file", "")),
                ),
                selection,
                decision=str(
                    stored.get("reuse_decision") or "follow_saved_exact_flow"
                ),
                reason=str(
                    stored.get("reuse_reason")
                    or "refreshed the exact flow recorded in saved collection state"
                ),
                force_run=bool(stored.get("force_run_requested", False)),
            )
        )

    refreshed_state = build_state_payload(
        client,
        investigation_id,
        hostname,
        request,
        artifact_statuses,
    )
    queue_progress = state.get("queue_progress")
    if isinstance(queue_progress, dict):
        refreshed_state["queue_progress"] = dict(queue_progress)
    artifact_preflight = state.get("artifact_preflight")
    if isinstance(artifact_preflight, dict):
        refreshed_state["artifact_preflight"] = dict(artifact_preflight)
    write_state(
        investigation_id,
        hostname,
        refreshed_state,
        update_current_pointer=request_id is None,
    )

    return {
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": refreshed_state["request_id"],
        "state_file": refreshed_state["state_file"],
        "current_state_file": refreshed_state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": refreshed_state.get("analysis_inputs", {}),
        "supersedes_request_id": refreshed_state.get(
            "supersedes_request_id", ""
        ),
        "unavailable_artifacts": refreshed_state.get(
            "unavailable_artifacts", []
        ),
        "run_identity": refreshed_state["run_identity"],
        "run_identity_sha256": refreshed_state["run_identity_sha256"],
        "reuse_decisions": refreshed_state["reuse_decisions"],
        "queue_progress": refreshed_state.get("queue_progress"),
        "artifact_preflight": refreshed_state.get("artifact_preflight"),
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
    }


def status_payload(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request_id: str | None = None,
    *,
    client: ClientRecord | None = None,
) -> dict[str, Any]:
    with collection_state_lock(investigation_id, hostname):
        return _status_payload_unlocked(
            api,
            investigation_id,
            hostname,
            request_id=request_id,
            client=client,
        )


def poll_progress_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    progress: list[dict[str, Any]] = []
    for item in list(payload.get("artifact_flows") or []):
        artifact = str(item.get("artifact") or "").strip()
        flow_state = str(item.get("flow_state") or "").strip() or "UNKNOWN"
        total_rows = int(item.get("total_rows") or 0)
        available_components = list(item.get("available_result_components") or [])
        matching_flow_found = bool(item.get("matching_flow_found"))
        is_finished = bool(item.get("is_finished"))
        if not matching_flow_found:
            state = "missing"
        elif not is_finished:
            state = "running"
        elif flow_state.upper() == "ERROR" and (total_rows > 0 or available_components):
            state = "partial-from-error"
        elif flow_state.upper() == "ERROR":
            state = "failed-no-output"
        elif total_rows <= 0:
            state = "zero-row"
        else:
            state = "complete"
        progress.append(
            {
                "artifact": artifact,
                "flow_id": str(item.get("flow_id") or "").strip(),
                "flow_state": flow_state,
                "state": state,
                "is_finished": is_finished,
                "total_rows": total_rows,
            }
        )
    return progress


def attach_poll_progress(payload: dict[str, Any]) -> dict[str, Any]:
    progress = poll_progress_items(payload)
    payload["poll_progress"] = progress
    payload["poll_in_progress_artifacts"] = [
        item["artifact"]
        for item in progress
        if item["state"] == "running"
    ]
    payload["poll_finished_artifact_count"] = sum(1 for item in progress if item["is_finished"])
    payload["poll_total_artifact_count"] = len(progress)
    return payload


def format_poll_progress(payload: dict[str, Any]) -> str:
    progress = list(payload.get("poll_progress") or poll_progress_items(payload))
    finished = sum(1 for item in progress if item.get("is_finished"))
    total = len(progress)
    request_id = str(payload.get("request_id") or "").strip() or "latest"
    host = str(payload.get("hostname") or "").strip() or "unknown-host"
    parts = [
        f"{item['artifact']}={item['flow_state']} rows={item['total_rows']}"
        for item in progress
    ]
    return f"[poll] {host} {request_id}: done {finished}/{total}; " + "; ".join(parts)


def emit_poll_progress(payload: dict[str, Any]) -> None:
    print(format_poll_progress(payload), file=sys.stderr)


def pending_poll_flow_ids(payload: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("flow_id") or "").strip()
            for item in payload.get("artifact_flows") or []
            if str(item.get("flow_id") or "").strip()
            and not bool(item.get("is_finished"))
        }
    )


def wait_for_flow_completion_event(
    api: VeloApiClient,
    flow_ids: list[str],
    timeout_seconds: int,
) -> dict[str, Any] | None:
    """Wait for one owned flow-completion event before status reconciliation."""
    normalized = sorted({str(value).strip() for value in flow_ids if str(value).strip()})
    if not normalized or timeout_seconds <= 0:
        return None
    flow_id_regex = "^(?:" + "|".join(re.escape(value) for value in normalized) + ")$"
    try:
        rows = api.query_file(
            "watch_flow_completions.vql",
            {"flow_id_regex": flow_id_regex},
            timeout=timeout_seconds,
            max_wait=1,
            max_row=1,
        )
    except grpc.RpcError as exc:
        if exc.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            return None
        raise
    if not rows:
        return None
    row = dict(rows[0])
    flow_id = str(row.get("FlowId") or row.get("flow_id") or "").strip()
    if flow_id not in normalized:
        return None
    return row


def poll_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    interval_seconds: int,
    timeout_seconds: int,
    request_id: str | None = None,
    *,
    client: ClientRecord | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    emit_progress: bool = True,
) -> dict[str, Any]:
    if interval_seconds <= 0:
        raise RuntimeError("--interval-seconds must be greater than zero.")
    if timeout_seconds < 0:
        raise RuntimeError("--timeout-seconds must be zero or greater.")

    deadline = time.time() + timeout_seconds
    latest = attach_poll_progress(
        status_payload(
            api,
            investigation_id,
            hostname,
            request_id=request_id,
            client=client,
        )
    )
    if progress_callback is not None:
        progress_callback(latest)
    if emit_progress:
        emit_poll_progress(latest)
    watcher_event_count = 0
    watcher_error = ""
    while not latest["all_artifacts_expected_complete"]:
        if time.time() >= deadline:
            latest["poll_timed_out"] = True
            latest["poll_interval_seconds"] = interval_seconds
            latest["poll_timeout_seconds"] = timeout_seconds
            latest["poll_watcher_event_count"] = watcher_event_count
            latest["poll_watcher_error"] = watcher_error
            return latest
        remaining_seconds = max(0, int(deadline - time.time()))
        wait_seconds = min(interval_seconds, remaining_seconds)
        if wait_seconds <= 0:
            continue
        try:
            event = wait_for_flow_completion_event(
                api,
                pending_poll_flow_ids(latest),
                wait_seconds,
            )
            if event is not None:
                watcher_event_count += 1
        except Exception as exc:
            watcher_error = str(exc)
            time.sleep(wait_seconds)
        latest = attach_poll_progress(
            status_payload(
                api,
                investigation_id,
                hostname,
                request_id=request_id,
                client=client,
            )
        )
        if progress_callback is not None:
            progress_callback(latest)
        if emit_progress:
            emit_poll_progress(latest)

    latest["poll_timed_out"] = False
    latest["poll_interval_seconds"] = interval_seconds
    latest["poll_timeout_seconds"] = timeout_seconds
    latest["poll_watcher_event_count"] = watcher_event_count
    latest["poll_watcher_error"] = watcher_error
    return latest


def maybe_poll_after_collection(
    api: VeloApiClient,
    payload: dict[str, Any],
    investigation_id: str,
    hostname: str,
    poll_after: bool,
    poll_interval_seconds: int,
    poll_timeout_seconds: int,
    *,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if not poll_after:
        payload["polled_after_action"] = False
        return payload

    latest = poll_collection(
        api,
        investigation_id,
        hostname,
        poll_interval_seconds,
        poll_timeout_seconds,
        request_id=payload.get("request_id"),
        progress_callback=progress_callback,
        emit_progress=progress_callback is None,
    )
    latest["action"] = payload.get("action", "")
    latest["polled_after_action"] = True
    return latest


def maybe_export_after_collection(
    api: VeloApiClient,
    payload: dict[str, Any],
    investigation_id: str,
    hostname: str,
    request: CollectionRequest | None,
    export_after: bool,
) -> dict[str, Any]:
    if not export_after:
        payload["exported_after_action"] = False
        payload["export_skipped_reason"] = "disabled"
        return payload

    if not payload.get("all_artifacts_expected_complete"):
        payload["exported_after_action"] = False
        payload["export_skipped_reason"] = "collection_incomplete"
        return payload

    if request is None:
        raise RuntimeError("Export requested but no collection request was supplied.")

    client = get_client_by_id(api, str(payload.get("client_id") or ""), fallback_hostname=hostname)
    saved_artifact_statuses = list(payload.get("artifact_flows") or [])
    manifest = export_collection(
        api,
        investigation_id,
        hostname,
        request,
        client=client,
        artifact_statuses=saved_artifact_statuses or None,
    )
    payload["exported_after_action"] = True
    payload["export_manifest_file"] = manifest["manifest_file"]
    payload["exported_files"] = manifest["exported_files"]
    return payload


def _ensure_collection_unlocked(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    timeout_seconds: int,
    force_run: bool,
    *,
    client: ClientRecord | None = None,
    update_current_pointer: bool = True,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    client = client or get_client(api, hostname)
    existing_artifact_flow_map: dict[str, Any] = {}
    state_path = get_state_path(investigation_id, hostname)
    if state_path.exists():
        existing_state = read_state(state_path)
        existing_request = request_from_state(existing_state, request.requested_artifacts)
        existing_artifact_flow_map = legacy_artifact_flow_map(existing_state, existing_request)
    artifact_statuses: list[dict[str, Any]] = []
    artifact_preflight: dict[str, Any] = {
        "status": "pending",
        "requested_artifacts": sorted(
            {spec.artifact for spec in request.expected_specs}
        ),
        "available_artifacts": [],
        "missing_artifacts": [],
        "checked_at": "",
    }
    queued_any = False
    reused_any = False
    request_id = request_id_for_request(request)

    def persist_progress(
        *,
        status: str,
        artifact: str = "",
        error: str = "",
    ) -> None:
        state = build_state_payload(
            client,
            investigation_id,
            hostname,
            request,
            artifact_statuses,
        )
        state["queue_progress"] = {
            "status": status,
            "artifact": artifact,
            "completed_artifacts": len(artifact_statuses),
            "planned_artifacts": len(request.expected_specs),
            "error": error,
            "updated_at": now_utc(),
        }
        state["artifact_preflight"] = dict(artifact_preflight)
        with collection_state_lock(investigation_id, hostname):
            write_state(
                investigation_id,
                hostname,
                state,
                update_current_pointer=update_current_pointer,
            )

    def emit_progress(event: dict[str, Any]) -> None:
        if progress_callback is None:
            return
        progress_callback(
            {
                **event,
                "completed": len(artifact_statuses),
                "total": len(request.expected_specs),
            }
        )

    persist_progress(status="starting")
    emit_progress({"phase": "preflight", "status": "running"})
    try:
        artifact_preflight = preflight_artifact_availability(api, request)
        raise_for_missing_server_artifacts(artifact_preflight)
        persist_progress(status="preflight_complete")
        emit_progress({"phase": "checking-existing", "status": "running"})
        all_flows = get_all_flows(api, client.client_id)
        selections = {
            expected.label: select_matching_flow_for_spec(
                api,
                client.client_id,
                expected,
                flows=all_flows,
            )
            for expected in request.expected_specs
        }
    except Exception as exc:
        persist_progress(status="failed", error=str(exc))
        raise

    blocked = []
    if not force_run:
        for expected in request.expected_specs:
            selection = selections[expected.label]
            if selection["selected_flow"] is not None:
                continue
            blocked_candidate = selection.get("blocked_candidate")
            if blocked_candidate:
                blocked.append(
                    {
                        "artifact": expected.label,
                        **blocked_candidate,
                    }
                )
    if blocked:
        details = "; ".join(
            f"{item['artifact']} flow {item['flow_id']} is {item['state']}"
            for item in blocked
        )
        persist_progress(
            status="failed",
            artifact=str(blocked[0]["artifact"]),
            error=(
                "Exact prior collection flow(s) failed or were cancelled. "
                f"{details}. Pass --force-run to queue a fresh flow."
            ),
        )
        raise RuntimeError(
            "Exact prior collection flow(s) failed or were cancelled. "
            f"{details}. Pass --force-run to queue a fresh flow."
        )

    for expected in request.expected_specs:
        selection = selections[expected.label]
        matching_flow = None if force_run else selection["selected_flow"]
        if matching_flow is None:
            persist_progress(status="running", artifact=expected.label)
            emit_progress(
                {
                    "phase": "queueing",
                    "artifact": expected.label,
                    "status": "queueing",
                }
            )
            try:
                status = queue_single_artifact(
                    api,
                    client,
                    investigation_id,
                    hostname,
                    expected,
                    timeout_seconds,
                    progress_callback=emit_progress,
                )
            except Exception as exc:
                persist_progress(
                    status="failed",
                    artifact=expected.label,
                    error=str(exc),
                )
                raise
            artifact_statuses.append(
                apply_reuse_audit(
                    status,
                    selection,
                    decision=(
                        "forced_new_flow"
                        if force_run
                        else "queued_missing_exact_flow"
                    ),
                    reason=(
                        "force-run requested; exact prior matches were deliberately bypassed"
                        if force_run
                        else "no exact prior flow matches the requested run identity"
                    ),
                    force_run=force_run,
                )
            )
            queued_any = True
        else:
            stored = existing_artifact_flow_map.get(expected.label, {})
            if not stored and expected.label != expected.artifact:
                stored = existing_artifact_flow_map.get(expected.artifact, {})
            classification = str(
                (selection.get("selected_candidate") or {}).get("classification")
                or ""
            )
            artifact_statuses.append(
                apply_reuse_audit(
                    artifact_status_from_flow(
                        expected,
                        matching_flow,
                        str(stored.get("queue_response_file", "")),
                    ),
                    selection,
                    decision="reused_exact_flow",
                    reason=(
                        "reused terminal successful exact match"
                        if classification == run_identity.TERMINAL_SUCCESS
                        else "reused in-flight exact match"
                    ),
                )
            )
            reused_any = True
            emit_progress(
                {
                    "phase": "checking-existing",
                    "artifact": expected.label,
                    "status": "reused",
                    "flow_id": matching_flow.session_id,
                }
            )
        persist_progress(status="running", artifact=expected.label)

    state = build_state_payload(client, investigation_id, hostname, request, artifact_statuses)
    state["queue_progress"] = {
        "status": "complete",
        "artifact": "",
        "completed_artifacts": len(artifact_statuses),
        "planned_artifacts": len(request.expected_specs),
        "error": "",
        "updated_at": now_utc(),
    }
    state["artifact_preflight"] = dict(artifact_preflight)
    if update_current_pointer:
        write_state(investigation_id, hostname, state)
    else:
        write_state(
            investigation_id,
            hostname,
            state,
            update_current_pointer=False,
        )
    raise_for_effective_argument_validation(
        artifact_statuses,
        context="collection handoff",
    )

    if force_run:
        action = "forced_new_flows"
    elif queued_any and reused_any:
        action = "reused_and_queued_flows"
    elif queued_any:
        action = "queued_new_flows"
    else:
        action = "reused_existing_flows"

    return {
        "action": action,
        "investigation_id": investigation_id,
        **client_identity_payload(client),
        "request_id": request_id_for_request(request),
        "state_file": state["state_file"],
        "current_state_file": state["current_state_file"],
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": serialize_specs(request.expected_specs),
        "analysis_inputs": request.analysis_inputs,
        **request_provenance_payload(request),
        "artifact_preflight": artifact_preflight,
        "run_identity": state["run_identity"],
        "run_identity_sha256": state["run_identity_sha256"],
        "reuse_decisions": state["reuse_decisions"],
        "force_run_requested": bool(force_run),
        "artifact_flows": artifact_statuses,
        **effective_arguments_payload(artifact_statuses),
        **summarize_artifact_statuses(artifact_statuses),
    }


def ensure_collection(
    api: VeloApiClient,
    investigation_id: str,
    hostname: str,
    request: CollectionRequest,
    timeout_seconds: int,
    force_run: bool,
    *,
    client: ClientRecord | None = None,
    update_current_pointer: bool = True,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("ensure_collection")
    resolve_policy_request_for_api(api, request)
    with collection_state_lock(investigation_id, hostname):
        return _ensure_collection_unlocked(
            api,
            investigation_id,
            hostname,
            request,
            timeout_seconds,
            force_run,
            client=client,
            update_current_pointer=update_current_pointer,
            progress_callback=progress_callback,
        )


def add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bundle",
        choices=IR_COLLECTION_BUNDLES,
        help=(
            "Capability-aware IR bundle. ir-standard-live includes volatile state; "
            "ir-standard-disk records volatile-only sources as not applicable."
        ),
    )
    parser.add_argument(
        "--collection-group",
        action="append",
        choices=IR_COLLECTION_GROUPS,
        default=[],
        help=(
            "Capability-aware IR evidence lane. Repeat to combine lanes. Custom "
            "groups require --target-mode and cannot be combined with --bundle."
        ),
    )
    parser.add_argument(
        "--target-mode",
        choices=IR_TARGET_MODES,
        help=(
            "Endpoint evidence mode for custom --collection-group requests. "
            "Bundles infer this value and reject conflicting overrides."
        ),
    )
    parser.add_argument(
        "--collection-type",
        choices=COLLECTION_TYPE_CHOICES,
        help=(
            "Named target collection type. Use all for the full baseline set, "
            "triage for the DetectRaptor lead-finding subset, execution for "
            "the focused execution subset, network for volatile live network "
            "state, persistence for live Autoruns, persistence-expanded for "
            "complementary service, task, startup, WMI, and Autoruns coverage, "
            "lateral-movement for the remote "
            "access and auth-focused subset, exfiltration for staging and "
            "transfer evidence, timeline for bounded MFT+EVTX pivots, or "
            "registry for a standalone all-category Registry Hunter collection."
        ),
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help=(
            "Exact artifact for an explicit artifact-only request. Repeat as needed; "
            "do not combine with --collection-type."
        ),
    )
    parser.add_argument(
        "--supersedes-request-id",
        help=(
            "Failed preflight request replaced by this explicit supported-artifact "
            "request. The prior request must use the same investigation, client, API "
            "config hash, and org; be <=24h old; and own no flows. Runtime persists "
            "this provenance and prevents a complete baseline status."
        ),
    )
    parser.add_argument(
        "--unavailable-artifact",
        action="append",
        default=[],
        help=(
            "Artifact omitted because the superseded request proved it unavailable. "
            "Repeat for the exact failed preflight missing set. Together with repeated "
            "--artifact values, this must be a complete disjoint partition of the "
            "superseded requested artifacts."
        ),
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="Artifact variable in KEY=VALUE form. Repeat to pass multiple values. Requires exactly one --artifact.",
    )
    parser.add_argument(
        "--analysis-input",
        action="append",
        default=[],
        help=(
            "Analysis-only KEY=VALUE metadata for one explicit --artifact. "
            "It is persisted and affects the saved request id, but does not "
            "change the Velociraptor flow run identity."
        ),
    )
    parser.add_argument(
        "--flow-timeout-seconds",
        type=int,
        help=(
            "Optional server-side timeout for each artifact flow request. "
            "Use this when the artifact itself needs longer to complete, not "
            "just a longer local poll wait."
        ),
    )


def add_request_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--request-id",
        help=(
            "Saved request id under systems/<host>/collection/requests/<request-id>/. "
            "Use this to inspect or export a specific prior collection state instead of the latest one."
        ),
    )


def add_timeline_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--date-after",
        help="Timeline lower bound in UTC, for example 2026-05-01T00:00:00Z. Used with --collection-type timeline or exfiltration.",
    )
    parser.add_argument(
        "--date-before",
        help="Timeline upper bound in UTC, for example 2026-05-01T06:00:00Z. Used with --collection-type timeline or exfiltration.",
    )
    parser.add_argument(
        "--mft-drive",
        help="Drive or pathspec to query with Windows.NTFS.MFT. Defaults to C: for timeline pivots.",
    )
    parser.add_argument(
        "--mft-path-regex",
        help="Optional OSPath regex for Windows.NTFS.MFT timeline pivots. Defaults to .",
    )
    parser.add_argument(
        "--mft-file-regex",
        help="Optional filename regex for Windows.NTFS.MFT timeline pivots. Defaults to .",
    )
    parser.add_argument(
        "--mft-size-min",
        type=int,
        help="Optional minimum file size in bytes for Windows.NTFS.MFT timeline pivots.",
    )
    parser.add_argument(
        "--mft-size-max",
        type=int,
        help="Optional maximum file size in bytes for Windows.NTFS.MFT timeline pivots.",
    )
    parser.add_argument(
        "--evtx-glob",
        help=r"Optional EVTX glob for Windows.EventLogs.EvtxHunter. Defaults to %%SystemRoot%%\System32\Winevt\Logs\*.evtx.",
    )
    parser.add_argument(
        "--evtx-ioc-regex",
        help="Optional message/EventData regex for Windows.EventLogs.EvtxHunter. Defaults to . for bounded broad review.",
    )
    parser.add_argument(
        "--evtx-whitelist-regex",
        help="Optional whitelist regex to suppress known-benign EVTX hits.",
    )
    parser.add_argument(
        "--evtx-path-regex",
        help="Optional EVTX path regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-channel-regex",
        help="Optional EVTX channel regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-provider-regex",
        help="Optional EVTX provider regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-id-regex",
        help="Optional EVTX event id regex. Defaults to .",
    )
    parser.add_argument(
        "--evtx-vss-analysis-age",
        type=int,
        help="Optional VSSAnalysisAge value for EvtxHunter. Defaults to 0.",
    )


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server-profile",
        help=(
            "Velociraptor server/config profile. When --engagement-id is omitted, "
            "this also becomes the engagement folder name."
        ),
    )
    parser.add_argument(
        "--api-client",
        help=(
            "Explicit Velociraptor API config override. Otherwise the "
            "schema-v5 engagement server profile selects the cached config."
        ),
    )
    parser.add_argument(
        "--org-id",
        default=None,
        help="Velociraptor org id to use. Defaults to root, with orgs/<id> as a compatibility fallback.",
    )


def add_engagement_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--engagement-id",
        "--investigation-id",
        "--id",
        dest="investigation_id",
        help=(
            "Local engagement folder name. Defaults to --server-profile when "
            "omitted; it does not select or imply a Velociraptor label."
        ),
    )


def add_poll_args(
    parser: argparse.ArgumentParser,
    *,
    include_disable_flag: bool = False,
    default_interval_seconds: int = 15,
    default_timeout_seconds: int = 3600,
) -> None:
    if include_disable_flag:
        parser.add_argument(
            "--no-poll",
            action="store_true",
            help="Return after queue/reuse without waiting for the saved collection state to complete.",
        )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=default_interval_seconds,
        help="How long to wait between status refreshes when polling the saved collection state.",
    )
    parser.add_argument(
        "--poll-timeout-seconds",
        type=int,
        default=default_timeout_seconds,
        help="Maximum total wait time when polling for collection completion.",
    )


# Keep --allow-export accepted until saved invocations and documentation stop
# passing it. Its replacements are the explicit export command or --export on
# queue, ensure, and poll; it does not authorize an automatic export itself.
def add_export_args(
    parser: argparse.ArgumentParser,
    *,
    include_disable_flag: bool = False,
) -> None:
    if include_disable_flag:
        export_group = parser.add_mutually_exclusive_group()
        export_group.add_argument(
            "--export",
            action="store_true",
            help=(
                "Explicitly export finished collection results to CSV after "
                "the action completes. Server-backed analysis is the default."
            ),
        )
        export_group.add_argument(
            "--no-export",
            action="store_true",
            help=(
                "Compatibility flag confirming that no automatic CSV export "
                "should occur."
            ),
        )
        parser.add_argument(
            "--allow-export",
            action="store_true",
            help=argparse.SUPPRESS,
        )


def export_after_requested(args: argparse.Namespace) -> bool:
    if hasattr(args, "export"):
        return bool(getattr(args, "export"))
    return not bool(getattr(args, "no_export", False))


def add_standalone_export_authorization_arg(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "--allow-export",
        action="store_true",
        help=argparse.SUPPRESS,
    )


def add_client_target_args(parser: argparse.ArgumentParser, *, action: str) -> None:
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument(
        "--client-id",
        help=f"Exact Velociraptor client id to {action}. Preferred when known.",
    )
    selector.add_argument(
        "--host",
        help=(
            f"Hostname to {action}. Fails when the hostname resolves to multiple "
            "Velociraptor clients; use --client-id in that case."
        ),
    )


def resolve_cli_collection_target(
    api: VeloApiClient,
    args: argparse.Namespace,
) -> tuple[str, ClientRecord | None]:
    client_id = str(getattr(args, "client_id", "") or "").strip()
    hostname = str(getattr(args, "host", "") or "").strip()
    if client_id:
        if not CLIENT_ID_RE.fullmatch(client_id):
            raise RuntimeError(
                f"Invalid Velociraptor client id {client_id!r}. Expected C.<hex>."
            )
        client = get_client_by_id(api, client_id)
        if client is None:
            raise RuntimeError(f"No Velociraptor client found for client id {client_id}")
        if not client.hostname:
            raise RuntimeError(
                f"Velociraptor client {client_id} has no hostname; a stable hostname "
                "is required for the case evidence path."
            )
        return client.hostname, client
    if hostname:
        return hostname, None
    raise RuntimeError("Pass exactly one of --client-id or --host.")


def collection_progress_callback(
    reporter: analysis_cli_output.ProgressReporter,
    command: str,
) -> Callable[[dict[str, Any]], None]:
    """Translate collection callbacks into the shared evidence-free contract."""

    def update(event: dict[str, Any]) -> None:
        if "poll_total_artifact_count" in event:
            completed = int(event.get("poll_finished_artifact_count") or 0)
            total = int(event.get("poll_total_artifact_count") or 0)
            rows = sum(
                int(item.get("total_rows") or 0)
                for item in event.get("poll_progress") or []
                if isinstance(item, dict)
            )
            reporter.emit(
                phase="monitoring",
                status="running",
                command=command,
                hostname=event.get("hostname", ""),
                client_id=event.get("client_id", ""),
                request_id=event.get("request_id", ""),
                completed=completed,
                total=total,
                rows=rows,
            )
            return

        raw_status = str(event.get("status") or "running")
        phase = str(event.get("phase") or "running")
        if phase == "queue":
            phase = "submitting" if raw_status == "submitting" else "queueing"
        elif raw_status == "reused":
            phase = "checking-existing"
        reporter.emit(
            phase=phase,
            status="failed" if raw_status == "failed" else "running",
            force=raw_status in {"queued", "reused", "submission_timed_out"},
            command=command,
            hostname=event.get("hostname", ""),
            client_id=event.get("client_id", ""),
            request_id=event.get("request_id", ""),
            artifact=event.get("artifact", ""),
            flow_id=event.get("flow_id", ""),
            completed=event.get("completed"),
            total=event.get("total"),
            rows=event.get("rows"),
        )

    return update


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Queue, inspect, or export per-artifact Velociraptor host collections.",
        epilog=(
            "For exact ensure/reuse, monitoring, and artifact-scoped analysis, use: "
            "dfir collect analyze --id ID --client-id CLIENT "
            "--collection-type TYPE --question QUESTION"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_cmd = subparsers.add_parser(
        "plan",
        help=(
            "Resolve artifact availability and target applicability without "
            "finding, queueing, or persisting flows"
        ),
    )
    add_engagement_id_arg(plan_cmd)
    add_case_root_arg(plan_cmd)
    add_client_target_args(plan_cmd, action="plan")
    add_connection_args(plan_cmd)
    add_target_args(plan_cmd)
    add_timeline_args(plan_cmd)
    analysis_cli_output.add_progress_args(plan_cmd)

    queue_cmd = subparsers.add_parser("queue", help="Queue one new Velociraptor flow per requested artifact")
    add_engagement_id_arg(queue_cmd)
    add_case_root_arg(queue_cmd)
    add_client_target_args(queue_cmd, action="collect")
    add_connection_args(queue_cmd)
    add_target_args(queue_cmd)
    add_timeline_args(queue_cmd)
    queue_cmd.add_argument("--timeout-seconds", type=int, default=60, help="How long to wait for each new flow id")
    add_poll_args(queue_cmd, include_disable_flag=True)
    add_export_args(queue_cmd, include_disable_flag=True)
    analysis_cli_output.add_progress_args(queue_cmd)

    check_cmd = subparsers.add_parser(
        "check",
        help="Check whether matching per-artifact collection flows already exist for the requested target",
    )
    add_engagement_id_arg(check_cmd)
    add_case_root_arg(check_cmd)
    add_client_target_args(check_cmd, action="inspect")
    add_connection_args(check_cmd)
    add_target_args(check_cmd)
    add_timeline_args(check_cmd)
    analysis_cli_output.add_progress_args(check_cmd)

    ensure_cmd = subparsers.add_parser(
        "ensure",
        help="Reuse matching per-artifact flows, or queue new ones when they are missing",
    )
    add_engagement_id_arg(ensure_cmd)
    add_case_root_arg(ensure_cmd)
    add_client_target_args(ensure_cmd, action="collect or inspect")
    add_connection_args(ensure_cmd)
    add_target_args(ensure_cmd)
    add_timeline_args(ensure_cmd)
    ensure_cmd.add_argument("--timeout-seconds", type=int, default=60, help="How long to wait for each new flow id")
    ensure_cmd.add_argument(
        "--force-run",
        action="store_true",
        help="Queue a fresh flow per artifact even when matching prior collections already exist.",
    )
    add_poll_args(ensure_cmd, include_disable_flag=True)
    add_export_args(ensure_cmd, include_disable_flag=True)
    analysis_cli_output.add_progress_args(ensure_cmd)

    export_cmd = subparsers.add_parser(
        "export",
        help="Export finished collection results to CSV files under systems/<host>/exports/",
    )
    add_engagement_id_arg(export_cmd)
    add_case_root_arg(export_cmd)
    add_client_target_args(export_cmd, action="export")
    add_connection_args(export_cmd)
    add_request_id_arg(export_cmd)
    add_target_args(export_cmd)
    add_timeline_args(export_cmd)
    add_standalone_export_authorization_arg(export_cmd)
    analysis_cli_output.add_progress_args(export_cmd)

    export_registry_cmd = subparsers.add_parser(
        "export-registry-hunter",
        help="Export curated Registry Hunter CSV views from a finished Windows.Registry.Hunter[all] flow",
    )
    add_engagement_id_arg(export_registry_cmd)
    add_case_root_arg(export_registry_cmd)
    add_client_target_args(export_registry_cmd, action="export")
    add_connection_args(export_registry_cmd)
    export_registry_cmd.add_argument(
        "--profile",
        choices=sorted(REGISTRY_HUNTER_CURATED_PROFILES),
        default="execution",
        help="Curated Registry Hunter export profile to run.",
    )
    add_standalone_export_authorization_arg(export_registry_cmd)
    analysis_cli_output.add_progress_args(export_registry_cmd)

    status_cmd = subparsers.add_parser("status", help="Refresh the saved per-artifact collection status")
    add_engagement_id_arg(status_cmd)
    add_case_root_arg(status_cmd)
    add_client_target_args(status_cmd, action="inspect")
    add_connection_args(status_cmd)
    add_request_id_arg(status_cmd)
    analysis_cli_output.add_progress_args(status_cmd)

    poll_cmd = subparsers.add_parser(
        "poll",
        help="Poll the saved per-artifact collection state until all requested artifacts are complete",
    )
    add_engagement_id_arg(poll_cmd)
    add_case_root_arg(poll_cmd)
    add_client_target_args(poll_cmd, action="inspect")
    add_connection_args(poll_cmd)
    add_request_id_arg(poll_cmd)
    poll_cmd.add_argument(
        "--interval-seconds",
        type=int,
        default=15,
        help="How long to wait between status refreshes.",
    )
    poll_cmd.add_argument(
        "--timeout-seconds",
        type=int,
        default=3600,
        help="Maximum total wait time before returning the latest incomplete status.",
    )
    add_export_args(poll_cmd, include_disable_flag=True)
    analysis_cli_output.add_progress_args(poll_cmd)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global CASE_ROOT
    reporter: analysis_cli_output.ProgressReporter | None = None
    started_at = time.monotonic()
    command = "collection"
    try:
        args = parse_args(argv)
        command = str(args.command)
        reporter = analysis_cli_output.ProgressReporter(
            scope="collection",
            scope_id=str(
                getattr(args, "investigation_id", "")
                or getattr(args, "server_profile", "")
                or ""
            ),
            enabled=not bool(getattr(args, "no_progress", False)),
            heartbeat_seconds=float(
                getattr(
                    args,
                    "progress_interval_seconds",
                    analysis_cli_output.DEFAULT_HEARTBEAT_SECONDS,
                )
            ),
        )
        reporter.start(phase="preflight", command=command)
        org_id = resolve_org_id(args.org_id)
        context = engagement_context.resolve(
            repo_root=REPO_ROOT,
            engagement_id=getattr(args, "investigation_id", None),
            server_profile=getattr(args, "server_profile", None),
            api_client=getattr(args, "api_client", None),
            case_root=getattr(args, "case_root", None),
            expected_org_id=org_id,
            requested_client_id=getattr(args, "client_id", None),
            requested_hostname=getattr(args, "host", None),
        )
        args.investigation_id = context.engagement_id
        args.server_profile = context.server_profile
        CASE_ROOT = context.case_root
        api_client = context.api_client
        operation_log.bind_case(context.case_root, context.engagement_id)
        operation_log.emit(
            "readiness_validated",
            component="collection",
            stage="preflight",
            status="complete",
            scope="collection",
            scope_id=context.engagement_id,
            org_id=org_id,
        )
        reporter.emit(phase="resolving-target", command=command)

        with VeloApiClient(api_client, org_id=org_id) as api:
            hostname, selected_client = resolve_cli_collection_target(api, args)
            identity = {
                "hostname": hostname,
                "client_id": (
                    selected_client.client_id if selected_client is not None else ""
                ),
            }

            def operation_progress(
                request_id: str = "",
            ) -> Callable[[dict[str, Any]], None]:
                update = collection_progress_callback(reporter, command)

                def emit(event: dict[str, Any]) -> None:
                    update(
                        {
                            **identity,
                            "request_id": request_id,
                            **event,
                        }
                    )

                return emit

            if args.command == "plan":
                reporter.emit(phase="resolving-capabilities", command=command, **identity)
                request = build_request_from_args(args)
                payload = plan_collection(
                    api,
                    args.investigation_id,
                    hostname,
                    request,
                    client=selected_client,
                )
            elif args.command == "status":
                reporter.emit(phase="refreshing", command=command, **identity)
                if selected_client is None:
                    payload = status_payload(
                        api,
                        args.investigation_id,
                        hostname,
                        request_id=args.request_id,
                    )
                else:
                    payload = status_payload(
                        api,
                        args.investigation_id,
                        hostname,
                        request_id=args.request_id,
                        client=selected_client,
                    )
            elif args.command == "poll":
                reporter.emit(
                    phase="monitoring",
                    command=command,
                    request_id=args.request_id or "",
                    **identity,
                )
                poll_kwargs = {
                    "request_id": args.request_id,
                    "progress_callback": operation_progress(args.request_id or ""),
                    "emit_progress": False,
                }
                if selected_client is not None:
                    poll_kwargs["client"] = selected_client
                payload = poll_collection(
                    api,
                    args.investigation_id,
                    hostname,
                    args.interval_seconds,
                    args.timeout_seconds,
                    **poll_kwargs,
                )
                if not export_after_requested(args):
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        None,
                        False,
                    )
                else:
                    reporter.emit(
                        phase=(
                            "exporting"
                            if payload.get("all_artifacts_expected_complete")
                            else "export-skipped"
                        ),
                        command=command,
                        **identity,
                    )
                    request = resolve_export_request(args, args.investigation_id, hostname)
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        request,
                        True,
                    )
            elif args.command == "export":
                reporter.emit(phase="validating-state", command=command, **identity)
                request = resolve_export_request(args, args.investigation_id, hostname)
                reporter.emit(phase="exporting", command=command, **identity)
                if args.request_id:
                    saved_status = status_payload(
                        api,
                        args.investigation_id,
                        hostname,
                        request_id=args.request_id,
                        client=selected_client,
                    )
                    export_client = selected_client or get_client_by_id(
                        api,
                        str(saved_status.get("client_id") or ""),
                        fallback_hostname=hostname,
                    )
                    payload = export_collection(
                        api,
                        args.investigation_id,
                        hostname,
                        request,
                        client=export_client,
                        artifact_statuses=list(saved_status.get("artifact_flows") or []),
                    )
                else:
                    payload = export_collection(
                        api,
                        args.investigation_id,
                        hostname,
                        request,
                        client=selected_client,
                    )
            elif args.command == "export-registry-hunter":
                reporter.emit(phase="validating-state", command=command, **identity)
                reporter.emit(phase="exporting", command=command, **identity)
                payload = export_registry_hunter_curated_profile(
                    api,
                    args.investigation_id,
                    hostname,
                    args.profile,
                    client=selected_client,
                )
            else:
                request = build_request_from_args(args)
                resolve_policy_request_for_api(api, request)
                request_id = request_id_for_request(request)
                if args.command == "queue":
                    payload = queue_collection(
                        api,
                        args.investigation_id,
                        hostname,
                        request,
                        args.timeout_seconds,
                        client=selected_client,
                        progress_callback=operation_progress(request_id),
                    )
                    payload = maybe_poll_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        not args.no_poll,
                        args.poll_interval_seconds,
                        args.poll_timeout_seconds,
                        progress_callback=operation_progress(request_id),
                    )
                    if export_after_requested(args):
                        reporter.emit(
                            phase=(
                                "exporting"
                                if payload.get("all_artifacts_expected_complete")
                                else "export-skipped"
                            ),
                            command=command,
                            **identity,
                        )
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        request,
                        export_after_requested(args),
                    )
                elif args.command == "check":
                    reporter.emit(phase="checking-flows", command=command, **identity)
                    payload = check_collection(
                        api,
                        args.investigation_id,
                        hostname,
                        request,
                        client=selected_client,
                    )
                else:
                    payload = ensure_collection(
                        api,
                        args.investigation_id,
                        hostname,
                        request,
                        args.timeout_seconds,
                        args.force_run,
                        client=selected_client,
                        progress_callback=operation_progress(request_id),
                    )
                    payload = maybe_poll_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        not args.no_poll,
                        args.poll_interval_seconds,
                        args.poll_timeout_seconds,
                        progress_callback=operation_progress(request_id),
                    )
                    if export_after_requested(args):
                        reporter.emit(
                            phase=(
                                "exporting"
                                if payload.get("all_artifacts_expected_complete")
                                else "export-skipped"
                            ),
                            command=command,
                            **identity,
                        )
                    payload = maybe_export_after_collection(
                        api,
                        payload,
                        args.investigation_id,
                        hostname,
                        request,
                        export_after_requested(args),
                    )

        reporter.emit(
            phase="completing" if args.command == "plan" else "persisting",
            command=command,
        )
        if args.command != "plan":
            payload = write_coverage_manifest(payload)
        artifact_flows = [
            item for item in payload.get("artifact_flows") or [] if isinstance(item, dict)
        ]
        completed = sum(bool(item.get("is_finished")) for item in artifact_flows)
        total = len(artifact_flows)
        final_status = "timed_out" if payload.get("poll_timed_out") else "complete"
        reporter.close(
            status=final_status,
            command=command,
            completed=completed,
            total=total,
            rows=sum(int(item.get("total_rows") or 0) for item in artifact_flows),
            elapsed_seconds=round(time.monotonic() - started_at, 3),
        )
        if command in {"check", "ensure", "queue", "status", "poll"}:
            payload["analysis_note"] = (
                "This collection command does not run analysis or final review. "
                "Collection completion alone is not analysis completion; inspect the saved analysis checkpoint."
            )
        payload.update(operation_log.correlation_metadata())
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except (RuntimeError, ValueError) as exc:
        operation_log.record_exception(exc, stage=f"collection_{command}")
        if reporter is not None:
            reporter.close(
                status="failed",
                phase="failed",
                command=command,
                elapsed_seconds=round(time.monotonic() - started_at, 3),
            )
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
