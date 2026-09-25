#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from vraptor.resources import repository_root
REPO_ROOT = repository_root()
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor import context as engagement_context
from vraptor.logging import operations as operation_log
from vraptor.artifacts import persistence as persistence_policy
from vraptor.analyze import identity as run_identity

from vraptor.common import atomic_io
from vraptor.common.hashing import sha256_file
from vraptor.common.labels import parse_label_values
from vraptor.common.sequences import unique_ordered
from vraptor.paths import add_case_root_arg
from vraptor.paths import default_case_root
from vraptor.paths import resolve_case_root
from vraptor import case_layout
CASE_ROOT = default_case_root(REPO_ROOT)
from vraptor.collect import requests as collection


TARGET_CHOICES = ("windows", "linux", "macos")
UNSCOPED_TARGET_NAMESPACE = "all"

HUNT_PROFILES: dict[str, dict[str, Any]] = {
    "autoruns": {
        "description": "Autoruns collection for complete-stack dedup AI review with regex-only GoldenDB.",
        "collection_type": None,
        "artifacts": ["IG.Windows.Sysinternals.Autoruns"],
        "env": [],
    },
    "detectraptor": {
        "description": "DetectRaptor Windows lead-finding hunt across Windows clients.",
        "collection_type": "triage",
        "artifacts": [],
        "env": [],
    },
    "lateral-movement": {
        "description": "High-signal service-creation hunt across Windows clients.",
        "collection_type": None,
        "artifacts": ["Windows.EventLogs.ServiceCreationComspec"],
        "env": [],
    },
}

OPEN_HUNT_STATES = {"RUNNING"}
PAUSED_HUNT_STATES = {"PAUSED"}
FLOW_OPEN_STATES = set(
    getattr(
        collection,
        "OPEN_STATES",
        {"RUNNING", "IN_PROGRESS", "WAITING", "QUEUED"},
    )
)
FLOW_FAILURE_TOKENS = (
    "FAIL",
    "ERROR",
    "CANCEL",
    "TIMEOUT",
    "UNRESPONSIVE",
)
HOST_KEYS = ("Fqdn", "Hostname", "HostName", "ComputerName", "SystemName")
CLIENT_KEYS = ("ClientId", "client_id")
TIME_BOUND_ARTIFACTS = {
    "DetectRaptor.Generic.Detection.YaraWebshell",
    "DetectRaptor.Windows.Detection.Evtx",
    "DetectRaptor.Windows.Detection.MFT",
    "Windows.EventLogs.EvtxHunter",
    "Windows.NTFS.MFT",
}
HIGH_VOLUME_ARTIFACT_FILTERS: dict[str, set[str]] = {
    "Windows.EventLogs.EvtxHunter": {
        "EvtxGlob",
        "ChannelRegex",
        "IocRegex",
        "EventIdRegex",
        "PathRegex",
    },
    "Windows.NTFS.MFT": {
        "Disk",
        "FilenameRegex",
        "PathRegex",
        "FileName",
    },
}
GENERIC_HUNT_NAMESPACE = "velociraptor-hunting"
HUNT_CANDIDATE_EXACT_CASE = "exact_case"
HUNT_CANDIDATE_GENERIC_TEMPLATE = "generic_template"
HUNT_CANDIDATE_DIFFERENT_IR_TEMPLATE = "different_ir_template"
HUNT_CANDIDATE_UNRELATED = "unrelated"
TEMPLATE_CANDIDATE_CLASSES = {
    HUNT_CANDIDATE_GENERIC_TEMPLATE,
    HUNT_CANDIDATE_DIFFERENT_IR_TEMPLATE,
}
GENERIC_HUNT_TARGET = ""
CURRENT_HUNT_GROUP = ""
CURRENT_HUNT_QUESTION = ""
CURRENT_SERVER_PROFILE = ""
HUNT_RESULTS_BATCH_SIZE = 10000
HUNT_RESULTS_RETRY_MAX_ROWS = (10000, 5000, 1000, 250, 100, 50, 10, 1)
HUNT_REVIEW_DEFAULT_LIMIT = 1000
HUNT_REVIEW_LIMIT_PRESETS = {
    "explore": 1000,
    "broad": 10000,
    "deep": 100000,
    "max": 1000000,
}
HUNT_REVIEW_INVENTORY_MODES = ("quick", "exact", "both")
READINESS_IMMEDIATE_RATIO = 0.80
READINESS_DELAYED_RATIO = 0.70
READINESS_DELAYED_HOURS = 24
READINESS_EARLY_RETRY_HOURS = 12
READINESS_RETRY_GRACE_HOURS = 2
STALLED_LOW_RATIO = 0.20
STALLED_FAILURE_RATIO = 0.50
HUNT_REVIEW_FIELD_PROFILES: dict[str, list[str]] = {
    "minimal": [
        "ClientId",
        "Fqdn",
        "Hostname",
        "Timestamp",
    ],
    "stacking": [
        "ClientId",
        "Fqdn",
        "Hostname",
        "Timestamp",
        "Detection",
        "Rule",
        "Type",
        "Category",
        "Path",
        "Name",
        "Hash",
    ],
    "pivot": [
        "ClientId",
        "Fqdn",
        "Hostname",
        "Timestamp",
        "User",
        "Username",
        "CommandLine",
        "ProcessName",
        "ParentName",
        "Path",
        "Name",
        "Hash",
        "Message",
    ],
}


@dataclass(frozen=True)
class HuntTargetScope:
    requested_os: str
    include_labels: tuple[str, ...]
    exclude_labels: tuple[str, ...]

    @property
    def mode(self) -> str:
        if self.include_labels:
            return "label"
        if self.requested_os:
            return "os"
        return "unscoped"

    @property
    def server_os(self) -> str:
        if self.include_labels:
            return ""
        return self.requested_os

    @property
    def namespace(self) -> str:
        return self.requested_os or UNSCOPED_TARGET_NAMESPACE


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, payload: Any) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    atomic_io.write_text_atomic(path, rendered)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=False, ensure_ascii=True, default=str))
            handle.write("\n")
    return len(rows)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def current_target_os() -> str:
    return normalize_target_os(GENERIC_HUNT_TARGET)


def target_namespace(target_os: Any) -> str:
    return normalize_target_os(target_os) or UNSCOPED_TARGET_NAMESPACE


def target_hunt_root(investigation_id: str, target_os: str | None) -> Path:
    # Hunt IDs are globally unique on a Velociraptor server. Keep the target OS
    # in hunt metadata rather than duplicating it in the filesystem hierarchy.
    return case_layout.hunts_dir(CASE_ROOT, investigation_id)


def hunt_root(investigation_id: str, target_os: str | None = None) -> Path:
    return target_hunt_root(investigation_id, current_target_os() if target_os is None else target_os)


def hunt_dir(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return case_layout.hunt_dir(CASE_ROOT, investigation_id, hunt_id)


def hunt_state_path(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return hunt_dir(investigation_id, hunt_id, target_os=target_os) / "state.json"


def current_profile_path(investigation_id: str, profile: str, target_os: str | None = None) -> Path:
    namespace = target_namespace(
        current_target_os() if target_os is None else target_os
    )
    return hunt_root(investigation_id, target_os=target_os) / (
        f"current-{namespace}-{profile}.json"
    )


def get_exports_dir(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return hunt_dir(investigation_id, hunt_id, target_os=target_os) / "exports"


def get_downloads_dir(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return hunt_dir(investigation_id, hunt_id, target_os=target_os) / "downloads"


def baseline_targets_path(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return hunt_dir(investigation_id, hunt_id, target_os=target_os) / "baseline-targets.json"


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)



def parse_json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return [item.strip() for item in text.split(",") if item.strip()]
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item).strip()]
    return []


def build_request_for_profile(profile: str, *, validate_target: bool = True) -> Any:
    if validate_target and current_target_os() not in {"", "windows"}:
        raise RuntimeError(
            f"Profile {profile!r} is Windows-only and cannot use "
            f"--target {current_target_os()}. "
            "Use velociraptor-artifact-selection to choose an explicit artifact "
            "for Linux, macOS, or unscoped generic hunts."
        )
    config = HUNT_PROFILES[profile]
    return collection.build_request(
        config["collection_type"],
        list(config["artifacts"]),
        list(config["env"]),
    )


def artifact_selector_values(args: argparse.Namespace) -> list[str]:
    return unique_ordered(list(getattr(args, "artifact", []) or []))


def profile_artifact_labels(profile: str) -> list[str]:
    request = build_request_for_profile(profile, validate_target=False)
    return [str(spec.label) for spec in request.expected_specs]


def select_profile_artifact(profile: str, artifact_selector: str) -> str:
    request = build_request_for_profile(profile, validate_target=False)
    selector = artifact_selector.strip()
    if not selector:
        raise RuntimeError("Artifact selector cannot be empty.")

    for spec in request.expected_specs:
        if selector in {spec.label, spec.artifact}:
            return spec.label

    available = ", ".join(spec.label for spec in request.expected_specs)
    raise RuntimeError(
        f"Artifact {selector!r} is not part of profile {profile!r}. "
        f"Available profile artifacts: {available}"
    )


def profile_allows_multi_artifact_hunt(profile: str | None) -> bool:
    return False


def enforce_single_artifact_hunt(request: Any, profile: str | None = None) -> Any:
    if profile_allows_multi_artifact_hunt(profile):
        return request
    if len(request.expected_specs) == 1:
        return request

    resolved = ", ".join(spec.label for spec in request.expected_specs)
    if profile:
        raise RuntimeError(
            "velociraptor-hunting currently limits native hunts to one artifact each. "
            f"Profile {profile!r} resolves to multiple artifacts: {resolved}. "
            "Choose one explicit profile artifact with --artifact."
        )
    raise RuntimeError(
        "velociraptor-hunting currently limits native hunts to one artifact each. "
        f"Resolved artifacts: {resolved}. Pass exactly one --artifact target."
    )


def spec_supports_time_bounds(spec: Any) -> bool:
    if "DateAfter" in spec.env or "DateBefore" in spec.env:
        return True
    return spec.label in TIME_BOUND_ARTIFACTS or spec.artifact in TIME_BOUND_ARTIFACTS


def apply_time_bounds_to_request(request: Any, args: argparse.Namespace) -> Any:
    date_after = getattr(args, "date_after", None)
    date_before = getattr(args, "date_before", None)
    if not date_after and not date_before:
        return request

    updated_specs: list[Any] = []
    applied = False
    for spec in request.expected_specs:
        env = dict(spec.env)
        if spec_supports_time_bounds(spec):
            if date_after:
                env["DateAfter"] = date_after
            if date_before:
                env["DateBefore"] = date_before
            applied = True
        updated_specs.append(
            collection.ArtifactSpec(
                label=spec.label,
                artifact=spec.artifact,
                env=env,
                timeout_seconds=spec.timeout_seconds,
            )
        )

    if not applied:
        raise RuntimeError(
            "--date-after/--date-before require at least one artifact that supports "
            "DateAfter/DateBefore, such as Windows.EventLogs.EvtxHunter, "
            "Windows.NTFS.MFT, or DetectRaptor.Windows.Detection.Evtx."
        )

    return collection.CollectionRequest(
        target_collection_type=request.target_collection_type,
        requested_groups=list(request.requested_groups),
        requested_artifacts=list(request.requested_artifacts),
        expected_specs=updated_specs,
    )


def build_request_from_args(args: argparse.Namespace) -> Any:
    profile = str(getattr(args, "profile", "") or "") or None
    artifact_selector = artifact_selector_values(args)
    env_values = list(getattr(args, "env", []) or [])

    if profile:
        profile_request = build_request_for_profile(profile)
        if artifact_selector:
            if profile_allows_multi_artifact_hunt(profile) and env_values:
                raise RuntimeError(
                    "Shared --env values are not supported when the full profile resolves "
                    "to a multi-artifact native hunt. Select one explicit --artifact or "
                    "run the profile without --env overrides."
                )
            if len(artifact_selector) != 1:
                raise RuntimeError(
                    "velociraptor-hunting currently limits native hunts to one artifact each. "
                    "Pass exactly one --artifact selector with --profile."
                )
            selected_artifact = select_profile_artifact(profile, artifact_selector[0])
            request = collection.build_request(None, [selected_artifact], env_values)
        else:
            if env_values:
                if len(profile_request.expected_specs) != 1:
                    raise RuntimeError(
                        "Shared --env values require exactly one resolved artifact. "
                        "Pass one explicit --artifact selector with --profile, or use a "
                        "single-artifact profile."
                    )
                request = collection.build_request(
                    None,
                    [profile_request.expected_specs[0].label],
                    env_values,
                )
            else:
                request = profile_request
    else:
        if not artifact_selector:
            raise RuntimeError("Pass --profile or exactly one --artifact target.")
        if len(artifact_selector) != 1:
            raise RuntimeError(
                "velociraptor-hunting currently limits native hunts to one artifact each. "
                "Pass exactly one --artifact target."
            )
        request = collection.build_request(None, artifact_selector, env_values)

    request = apply_time_bounds_to_request(request, args)
    request = enforce_single_artifact_hunt(request, profile)
    enforce_high_volume_filters(request, profile)
    return request


def enforce_high_volume_filters(request: Any, profile: str | None) -> None:
    if profile == "detectraptor":
        return
    for spec in request.expected_specs:
        required = HIGH_VOLUME_ARTIFACT_FILTERS.get(str(spec.artifact))
        if not required:
            continue
        supplied = {
            str(key)
            for key, value in dict(spec.env).items()
            if str(value).strip()
        }
        if supplied.intersection(required):
            continue
        filters = ", ".join(sorted(required))
        raise RuntimeError(
            f"Refusing broad high-volume hunt for {spec.artifact}. "
            f"Provide at least one artifact-specific filter with --env: {filters}."
        )


def resolve_hunt_target_scope(
    target_os: Any,
    include_labels: list[str],
    exclude_labels: list[str],
) -> HuntTargetScope:
    return HuntTargetScope(
        requested_os=normalize_target_os(target_os),
        include_labels=tuple(normalized_label_scope(include_labels)),
        exclude_labels=tuple(normalized_label_scope(exclude_labels)),
    )


def request_signature(request: Any, target_os: str | None, include_labels: list[str], exclude_labels: list[str]) -> str:
    scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    return collection.short_signature(
        {
            "target_scope_mode": scope.mode,
            "server_target_os": scope.server_os,
            "include_labels": list(scope.include_labels),
            "exclude_labels": list(scope.exclude_labels),
            "expected_specs": collection.serialize_specs(request.expected_specs),
        }
    )


def hunt_run_identity(
    request: Any,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
) -> dict[str, Any]:
    scope = resolve_hunt_target_scope(
        target_os,
        include_labels,
        exclude_labels,
    )
    return run_identity.build_run_identity(
        source_mode="velociraptor-hunt",
        target={
            "target_scope_mode": scope.mode,
            "server_target_os": scope.server_os,
            "include_labels": list(scope.include_labels),
            "exclude_labels": list(scope.exclude_labels),
        },
        specs=request.expected_specs,
    )


def hunt_reuse_classification(state: Any) -> str:
    return run_identity.classify_state(
        state,
        terminal_success_states={"FINISHED", "COMPLETED"},
        in_flight_states=OPEN_HUNT_STATES | PAUSED_HUNT_STATES,
    )


def safe_description_value(value: str, *, limit: int) -> str:
    normalized = re.sub(r"\s+", "_", str(value or "").strip())
    normalized = re.sub(r"[^A-Za-z0-9._:/@+-]+", "-", normalized)
    return normalized[:limit].strip("-_")


def hunt_group_marker(group: str) -> str:
    token = safe_description_value(group, limit=96)
    return f"dfir-group={token}" if token else ""


def build_hunt_description(
    investigation_id: str,
    profile: str,
    signature: str,
    target_os: str | None = None,
) -> str:
    parts = [
        GENERIC_HUNT_NAMESPACE,
        target_namespace(current_target_os() if target_os is None else target_os),
        investigation_id,
        profile,
        signature,
    ]
    marker = hunt_group_marker(CURRENT_HUNT_GROUP)
    if marker:
        parts.append(marker)
    question = safe_description_value(CURRENT_HUNT_QUESTION, limit=160)
    if question:
        parts.append(f"question={question}")
    return " ".join(parts)


def build_hunt_tags(
    investigation_id: str,
    profile: str,
    signature: str,
    target_os: str | None = None,
) -> list[str]:
    tags = [
        GENERIC_HUNT_NAMESPACE,
        target_namespace(current_target_os() if target_os is None else target_os),
        f"dfir-engagement:{safe_description_value(investigation_id, limit=96)}",
    ]
    if CURRENT_SERVER_PROFILE:
        tags.append(
            f"dfir-server-profile:{safe_description_value(CURRENT_SERVER_PROFILE, limit=96)}"
        )
    if CURRENT_HUNT_GROUP:
        tags.append(f"dfir-group:{safe_description_value(CURRENT_HUNT_GROUP, limit=96)}")
    if profile == "autoruns":
        tags.append("dfir-analysis:autoruns")
    return tags


def is_autoruns_hunt(row: dict[str, Any]) -> bool:
    """Recognize the current profile and historical test metadata read-only."""
    if {"dfir-analysis:autoruns", "dfir-analysis:autoruns_test"}.intersection(hunt_tags(row)):
        return True
    parts = str(row.get("hunt_description") or "").split()
    return len(parts) >= 5 and parts[0] == GENERIC_HUNT_NAMESPACE and parts[3] in {"autoruns", "autoruns_test"}


def combined_hunt_tags(
    investigation_id: str,
    profile: str,
    signature: str,
    extra_tags: list[str],
    target_os: str | None = None,
) -> list[str]:
    return unique_ordered(build_hunt_tags(investigation_id, profile, signature, target_os) + extra_tags)


def single_hunt_target_name(profile: str | None, request: Any, artifact_selector: list[str]) -> str:
    if len(request.expected_specs) != 1:
        raise RuntimeError("Single-hunt target naming requires exactly one resolved artifact.")

    spec_label = str(request.expected_specs[0].label)
    if profile:
        profile_request = build_request_for_profile(profile)
        if len(profile_request.expected_specs) == 1:
            return profile
        return f"{profile}--{spec_label}"
    return spec_label


def target_name_from_args(args: argparse.Namespace, request: Any) -> str:
    profile = str(getattr(args, "profile", "") or "") or None
    if profile and profile_allows_multi_artifact_hunt(profile) and not artifact_selector_values(args):
        return profile
    if profile or len(request.expected_specs) == 1:
        return single_hunt_target_name(profile, request, artifact_selector_values(args))
    if request.target_collection_type:
        return str(request.target_collection_type)
    return "custom"


def normalize_hunt_state(value: Any) -> str:
    return str(value or "").upper()


def normalize_target_os(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text


def client_matches_target_os(row: dict[str, Any], target_os: str | None) -> bool:
    normalized = normalize_target_os(target_os)
    if not normalized:
        return True
    os_type = str(row.get("OSType") or row.get("os_type") or "").strip().lower()
    if not os_type:
        return True
    if normalized == "windows":
        return "windows" in os_type
    if normalized == "linux":
        return "linux" in os_type
    if normalized == "macos":
        return "darwin" in os_type or "mac" in os_type or "osx" in os_type
    return True


def normalized_label_scope(values: list[str]) -> list[str]:
    return sorted(unique_ordered([str(value).strip() for value in values if str(value).strip()]))


def parse_datetime_value(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    try:
        numeric = float(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    if numeric > 1e18:
        numeric /= 1e9
    elif numeric > 1e15:
        numeric /= 1e6
    elif numeric > 1e12:
        numeric /= 1e3
    return datetime.fromtimestamp(numeric, tz=timezone.utc)


def coerce_int(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def hunt_requested_artifacts(row: dict[str, Any]) -> list[str]:
    start_request = row.get("start_request")
    if isinstance(start_request, dict):
        artifacts = start_request.get("artifacts")
        if artifacts:
            return collection.normalize_artifacts(artifacts)
    artifacts = row.get("artifacts")
    return collection.normalize_artifacts(artifacts)


def hunt_scope_labels(row: dict[str, Any], key: str) -> list[str]:
    start_request = row.get("start_request")
    if isinstance(start_request, dict) and key in start_request:
        return normalized_label_scope(parse_json_list(start_request.get(key)))
    condition = row.get("condition")
    if isinstance(condition, dict):
        condition_key = "labels" if key == "include_labels" else "excluded_labels"
        condition_value = condition.get(condition_key)
        if isinstance(condition_value, dict):
            condition_value = condition_value.get("label")
        parsed_condition_labels = normalized_label_scope(parse_json_list(condition_value))
        if parsed_condition_labels:
            return parsed_condition_labels
    return normalized_label_scope(parse_json_list(row.get(key)))


def hunt_target_os(row: dict[str, Any]) -> str:
    start_request = row.get("start_request")
    if isinstance(start_request, dict) and "os" in start_request:
        target_os = normalize_target_os(start_request.get("os"))
        if target_os and target_os != "all":
            return target_os
    condition = row.get("condition")
    if isinstance(condition, dict):
        condition_os = condition.get("os")
        if isinstance(condition_os, dict):
            condition_os = condition_os.get("os")
        target_os = normalize_target_os(condition_os)
        if target_os and target_os != "all":
            return target_os
    target_os = normalize_target_os(row.get("os"))
    return "" if target_os == "all" else target_os


def hunt_target_scope(row: dict[str, Any]) -> HuntTargetScope:
    return resolve_hunt_target_scope(
        hunt_target_os(row),
        hunt_scope_labels(row, "include_labels"),
        hunt_scope_labels(row, "exclude_labels"),
    )


def hunt_scope_mode_from_row(row: dict[str, Any]) -> str:
    server_os = hunt_target_os(row)
    include_labels = hunt_scope_labels(row, "include_labels")
    if include_labels and server_os:
        return "invalid_mixed"
    if include_labels:
        return "label"
    if server_os:
        return "os"
    return "unscoped"


def hunt_scope_validation_errors(row: dict[str, Any], expected_scope: HuntTargetScope) -> list[str]:
    actual_server_os = hunt_target_os(row)
    actual_include_labels = tuple(hunt_scope_labels(row, "include_labels"))
    actual_exclude_labels = tuple(hunt_scope_labels(row, "exclude_labels"))
    actual_mode = hunt_scope_mode_from_row(row)
    errors: list[str] = []
    if actual_mode != expected_scope.mode:
        errors.append(
            f"scope mode is {actual_mode!r}, expected {expected_scope.mode!r}"
        )
    if actual_server_os != expected_scope.server_os:
        errors.append(
            f"server OS is {actual_server_os or '<none>'!r}, "
            f"expected {expected_scope.server_os or '<none>'!r}"
        )
    if {casefold_text(value) for value in actual_include_labels} != {
        casefold_text(value) for value in expected_scope.include_labels
    }:
        errors.append(
            f"include labels are {list(actual_include_labels)!r}, "
            f"expected {list(expected_scope.include_labels)!r}"
        )
    if {casefold_text(value) for value in actual_exclude_labels} != {
        casefold_text(value) for value in expected_scope.exclude_labels
    }:
        errors.append(
            f"exclude labels are {list(actual_exclude_labels)!r}, "
            f"expected {list(expected_scope.exclude_labels)!r}"
        )
    return errors


def raise_for_hunt_scope_validation_errors(
    row: dict[str, Any],
    expected_scope: HuntTargetScope,
) -> None:
    errors = hunt_scope_validation_errors(row, expected_scope)
    if errors:
        raise RuntimeError(
            "Refusing to activate hunt because the server target scope differs "
            "from the requested scope: " + "; ".join(errors)
        )


def hunt_requested_specs(row: dict[str, Any]) -> list[Any]:
    start_request = row.get("start_request")
    if isinstance(start_request, dict):
        specs = start_request.get("specs")
        if specs:
            return collection.parse_specs_json(json.dumps(specs))
    requested_artifacts = hunt_requested_artifacts(row)
    if requested_artifacts:
        return collection.build_expected_specs(requested_artifacts)
    return []


def hunt_artifact_names(row: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for spec in hunt_requested_specs(row):
        names.append(spec.label)
        names.append(spec.artifact)
    if not names:
        names.extend(hunt_requested_artifacts(row))
    return unique_ordered([name for name in names if str(name).strip()])


def query_hunts(api: Any) -> list[dict[str, Any]]:
    rows = api.query("SELECT * FROM hunts()")
    rows.sort(key=lambda row: coerce_int(row.get("create_time")), reverse=True)
    return rows


def artifact_filters_match(
    row: dict[str, Any],
    artifact_filters: list[str],
    artifact_regex: str | None,
) -> tuple[bool, list[str]]:
    import re

    names = hunt_artifact_names(row)
    names_by_casefold = {casefold_text(name): name for name in names}
    matched: list[str] = []
    for artifact_filter in artifact_filters:
        actual_name = names_by_casefold.get(casefold_text(artifact_filter))
        if actual_name:
            matched.append(actual_name)
    if artifact_regex:
        pattern = re.compile(artifact_regex)
        matched.extend([name for name in names if pattern.search(name)])
    matched = unique_ordered(matched)
    if artifact_filters and not all(
        casefold_text(item) in names_by_casefold for item in artifact_filters
    ):
        return False, []
    if artifact_regex and not matched:
        return False, []
    return bool(matched or artifact_filters), matched


def query_single_hunt(api: Any, hunt_id: str) -> dict[str, Any] | None:
    rows = api.query("SELECT * FROM hunts(hunt_id=HuntId)", {"HuntId": hunt_id})
    if rows:
        row = dict(rows[0])
        # Modern servers return the complete request and result sources at the
        # top level. Older shapes may need the independently merged fallback.
        if isinstance(row.get("start_request"), dict) and (
            isinstance(row.get("Request"), dict)
            or (
                isinstance(row.get("artifacts"), list)
                and isinstance(row.get("artifact_sources"), list)
                and bool(collection.normalize_artifacts(row["artifact_sources"]))
            )
        ):
            return row
    info_rows = api.query(
        "SELECT hunt_info(hunt_id=HuntId) AS Hunt FROM scope()",
        {"HuntId": hunt_id},
    )
    info_hunt = dict(info_rows[0]["Hunt"]) if info_rows and isinstance(info_rows[0].get("Hunt"), dict) else None
    if rows:
        row = dict(rows[0])
        if info_hunt:
            if not isinstance(row.get("Request"), dict) and isinstance(info_hunt.get("Request"), dict):
                row["Request"] = info_hunt.get("Request")
            if not isinstance(row.get("start_request"), dict) and isinstance(info_hunt.get("start_request"), dict):
                row["start_request"] = info_hunt.get("start_request")
        return row
    if info_hunt:
        return info_hunt
    return None


def find_hunt_by_description(api: Any, description: str) -> dict[str, Any] | None:
    for row in query_hunts(api):
        if str(row.get("hunt_description") or "") == description:
            return row
    return None


def request_needs_validation(request: Any) -> bool:
    return any(spec.env for spec in request.expected_specs)


def artifact_token_variants(name: str) -> list[str]:
    token = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    variants = [name]
    if token:
        variants.append(token)
    return unique_ordered([value for value in variants if value])


def compiled_arg_env_map(compiled_arg: dict[str, Any]) -> dict[str, str]:
    env_values: dict[str, str] = {}
    for item in compiled_arg.get("env") or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        if not key:
            continue
        env_values[key] = str(item.get("value") or "")
    return env_values


def parse_json_string_list(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return [item.strip() for item in text.split(",") if item.strip()]
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    return []


def compiled_arg_text(compiled_arg: dict[str, Any]) -> str:
    parts: list[str] = []
    for artifact in compiled_arg.get("artifacts") or []:
        if isinstance(artifact, dict):
            parts.append(str(artifact.get("name") or ""))
    for query in compiled_arg.get("Query") or []:
        if not isinstance(query, dict):
            continue
        parts.append(str(query.get("Name") or ""))
        parts.append(str(query.get("VQL") or ""))
    return "\n".join(part for part in parts if part)


def registry_hunter_env_matches(env_map: dict[str, str], expected: Any) -> bool:
    expected_categories = parse_json_string_list(expected.env.get("Categories", ""))
    actual_categories = parse_json_string_list(env_map.get("Categories", ""))
    if expected_categories and not set(expected_categories).issubset(set(actual_categories)):
        return False
    for key, value in expected.env.items():
        if key in {"Categories", "RemappingStrategy"}:
            continue
        if env_map.get(key) != value:
            return False
    return True


def compiled_arg_matches_spec(compiled_arg: dict[str, Any], expected: Any) -> bool:
    env_map = compiled_arg_env_map(compiled_arg)
    if expected.artifact == "Windows.Registry.Hunter":
        if not registry_hunter_env_matches(env_map, expected):
            return False
    else:
        for key, value in expected.env.items():
            if env_map.get(key) != value:
                return False

    searchable = compiled_arg_text(compiled_arg)
    tokens = artifact_token_variants(expected.artifact) + artifact_token_variants(expected.label)
    return any(token in searchable for token in tokens)


def hunt_validation_errors(row: dict[str, Any], request: Any) -> list[str]:
    start_request = row.get("start_request")
    if not isinstance(start_request, dict):
        nested_request = row.get("Request")
        if isinstance(nested_request, dict):
            start_request = nested_request.get("start_request")
    if not isinstance(start_request, dict):
        return ["hunt has no start_request to validate against"]

    compiled_args = start_request.get("compiled_collector_args")
    if not isinstance(compiled_args, list) or not compiled_args:
        return ["hunt has no compiled_collector_args to validate against"]

    errors: list[str] = []
    for expected in request.expected_specs:
        if not expected.env:
            continue
        if any(
            compiled_arg_matches_spec(compiled_arg, expected)
            for compiled_arg in compiled_args
            if isinstance(compiled_arg, dict)
        ):
            continue
        expected_env = ", ".join(f"{key}={value}" for key, value in sorted(expected.env.items()))
        errors.append(
            f"{expected.label} did not honor expected env ({expected_env}) in compiled_collector_args"
        )
    return errors


def raise_for_hunt_validation_errors(row: dict[str, Any], request: Any) -> None:
    if not request_needs_validation(request):
        return
    errors = hunt_validation_errors(row, request)
    if not errors:
        return
    raise RuntimeError(
        "Refusing to use parameterized hunt because the server did not honor "
        "the requested artifact parameters: " + "; ".join(errors)
    )


def start_hunt(api: Any, hunt_id: str) -> None:
    api.query(
        "SELECT hunt_update(hunt_id=HuntId, start=TRUE) AS Result FROM scope()",
        {"HuntId": hunt_id},
        max_wait=30,
        max_row=10,
    )


def stop_hunt(api: Any, hunt_id: str) -> None:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("stop_hunt")
    api.query(
        "SELECT hunt_update(hunt_id=HuntId, stop=TRUE) AS Result FROM scope()",
        {"HuntId": hunt_id},
        max_wait=30,
        max_row=10,
    )


def query_hunt_flows(api: Any, hunt_id: str) -> list[dict[str, Any]]:
    # Full Flow records repeat compiled collector requests for every client.
    # Retain the nested shape used by status and snapshot routing, but project
    # only their required metadata before serialization on the server.
    return api.query(
        """SELECT ClientId, FlowId,
    dict(client_id=Flow.client_id, session_id=Flow.session_id,
         state=Flow.state, total_collected_rows=Flow.total_collected_rows,
         artifacts_with_results=Flow.artifacts_with_results) AS Flow
FROM hunt_flows(hunt_id=HuntId, basic_info=FALSE)""",
        {"HuntId": hunt_id},
        max_wait=30,
        max_row=100,
    )


def query_hunt_results(api: Any, hunt_id: str, artifact_name: str) -> list[dict[str, Any]]:
    # In the shared VeloApiClient wrapper, max_row controls the gRPC batch size
    # per streamed response, not a total row cap for the overall query.
    return api.query(
        "SELECT * FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
        {
            "HuntId": hunt_id,
            "ArtifactName": artifact_name,
        },
        max_wait=30,
        max_row=HUNT_RESULTS_BATCH_SIZE,
    )


def is_resource_exhausted_error(exc: Exception) -> bool:
    code_method = getattr(exc, "code", None)
    if not callable(code_method):
        return False
    try:
        code = code_method()
        expected = collection.grpc.StatusCode.RESOURCE_EXHAUSTED
        if code == expected:
            return True
        # Test loaders and some gRPC wrappers may expose an equivalent
        # StatusCode enum from another module instance. Compare the stable
        # symbolic name as a compatibility fallback instead of relying only
        # on enum identity.
        return (
            getattr(code, "name", "") == "RESOURCE_EXHAUSTED"
            or str(code).rsplit(".", 1)[-1] == "RESOURCE_EXHAUSTED"
        )
    except Exception:
        return False


def query_hunt_results_resilient(
    api: Any,
    hunt_id: str,
    artifact_name: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    last_error: Exception | None = None
    for max_row in HUNT_RESULTS_RETRY_MAX_ROWS:
        try:
            rows = api.query(
                "SELECT * FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
                {
                    "HuntId": hunt_id,
                    "ArtifactName": artifact_name,
                },
                max_wait=30,
                max_row=max_row,
            )
            attempts.append({"max_row": max_row, "status": "ok", "row_count": len(rows)})
            return rows, {
                "status": "ok",
                "max_row": max_row,
                "attempts": attempts,
            }
        except Exception as exc:
            if not is_resource_exhausted_error(exc):
                raise
            last_error = exc
            attempts.append(
                {
                    "max_row": max_row,
                    "status": "resource_exhausted",
                    "error": str(exc),
                }
            )

    return [], {
        "status": "resource_exhausted",
        "max_row": HUNT_RESULTS_RETRY_MAX_ROWS[-1],
        "attempts": attempts,
        "error": str(last_error or "RESOURCE_EXHAUSTED"),
        "fallback_recommendation": (
            "Narrow results with review-results --where/--field or preserve raw bulk "
            "evidence with create_hunt_download() / Velociraptor download workflow."
        ),
    }


def write_hunt_result_query_error(path: Path, *, artifact: str, artifact_name: str, query_meta: dict[str, Any]) -> None:
    write_json(
        path,
        {
            "artifact": artifact,
            "artifact_name": artifact_name,
            "generated_at": now_utc(),
            "query_status": query_meta.get("status", ""),
            "query_attempts": query_meta.get("attempts", []),
            "error": query_meta.get("error", ""),
            "fallback_recommendation": query_meta.get("fallback_recommendation", ""),
        },
    )


def get_review_dir(investigation_id: str, hunt_id: str, target_os: str | None = None) -> Path:
    return hunt_dir(investigation_id, hunt_id, target_os=target_os) / "review"


def safe_review_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-")
    return token or "value"


def review_request_signature(
    *,
    operation: str,
    field_profile: str,
    fields: list[str],
    group_by: list[str],
    inventory_group_by: list[str] | None = None,
    where: str | None,
    source: str | None,
    limit: int,
    output_format: str,
    inventory_mode: str = "",
    artifact_profile_hashes: list[str] | None = None,
    effective_stack_ids: dict[str, str] | None = None,
) -> str:
    payload = {
        "operation": operation,
        "field_profile": field_profile,
        "fields": fields,
        "group_by": group_by,
        "inventory_group_by": inventory_group_by or [],
        "where": where or "",
        "source": source or "",
        "limit": limit,
        "output_format": output_format,
        "inventory_mode": inventory_mode,
        "artifact_profile_hashes": artifact_profile_hashes or [],
        "effective_stack_ids": effective_stack_ids or {},
    }
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()[:12]


def review_artifact_source_vql(source: str | None = None) -> str:
    if source:
        return "hunt_results(hunt_id=HuntId, artifact=ArtifactName, source=Source)"
    return "hunt_results(hunt_id=HuntId, artifact=ArtifactName)"


def review_env(hunt_id: str, artifact_name: str, source: str | None = None) -> dict[str, str]:
    env = {
        "HuntId": hunt_id,
        "ArtifactName": artifact_name,
    }
    if source:
        env["Source"] = source
    return env


def stack_requirement_mismatches(
    stack: dict[str, Any],
    collection_env: dict[str, Any],
) -> dict[str, str]:
    truthy = {"1", "true", "t", "yes", "y", "on"}
    falsy = {"0", "false", "f", "no", "n", "off", ""}
    mismatches: dict[str, str] = {}
    for key, required in stack.get("collection_parameters", {}).items():
        actual = str(collection_env.get(key, "")).strip()
        expected = str(required).strip()
        actual_folded = actual.casefold()
        expected_folded = expected.casefold()
        matches = actual_folded == expected_folded
        if expected_folded in truthy:
            matches = actual_folded in truthy
        elif expected_folded in falsy:
            matches = actual_folded in falsy
        if not matches:
            mismatches[str(key)] = expected
    return mismatches


def review_where_clause(where: str | None) -> str:
    where_text = str(where or "").strip()
    if not where_text:
        return ""
    return f"\nWHERE {where_text}"


def review_fields_for_profile(profile: str, fields: list[str] | None = None) -> list[str]:
    requested = [str(item).strip() for item in (fields or []) if str(item).strip()]
    if requested:
        return unique_ordered(requested)
    if profile == "full":
        return ["*"]
    if profile not in HUNT_REVIEW_FIELD_PROFILES:
        raise RuntimeError(f"Unknown field profile: {profile}")
    return list(HUNT_REVIEW_FIELD_PROFILES[profile])


def review_select_clause(profile: str, fields: list[str] | None = None) -> str:
    selected = review_fields_for_profile(profile, fields)
    if selected == ["*"]:
        return "*"
    return ", ".join(selected)


def build_review_sample_vql(
    *,
    source: str | None,
    field_profile: str,
    fields: list[str],
    where: str | None,
    limit: int,
) -> str:
    return (
        f"SELECT {review_select_clause(field_profile, fields)}\n"
        f"FROM {review_artifact_source_vql(source)}"
        f"{review_where_clause(where)}\n"
        f"LIMIT {limit}"
    )


def build_review_stack_vql(
    *,
    source: str | None,
    group_by: list[str],
    where: str | None,
    limit: int,
) -> str:
    groups = [str(item).strip() for item in group_by if str(item).strip()]
    if not groups:
        raise RuntimeError("review-results stack requires at least one --group-by value.")
    select_parts = [f"{expr} AS Group{idx}" for idx, expr in enumerate(groups, start=1)]
    group_aliases = [f"Group{idx}" for idx in range(1, len(groups) + 1)]
    return (
        f"SELECT {', '.join(select_parts)}, count() AS Count\n"
        f"FROM {review_artifact_source_vql(source)}"
        f"{review_where_clause(where)}\n"
        f"GROUP BY {', '.join(group_aliases)}\n"
        f"ORDER BY Count DESC\n"
        f"LIMIT {limit}"
    )


def build_review_count_vql(*, source: str | None, where: str | None = None) -> str:
    return (
        "SELECT count() AS RowCount\n"
        f"FROM {review_artifact_source_vql(source)}"
        f"{review_where_clause(where)}"
    )


def default_inventory_group_by() -> list[str]:
    return ["ClientId", "Fqdn", "Hostname"]


def build_review_inventory_stack_vql(
    *,
    source: str | None,
    group_by: list[str],
    where: str | None,
    limit: int,
) -> str:
    groups = [str(item).strip() for item in group_by if str(item).strip()]
    if not groups:
        groups = default_inventory_group_by()
    select_parts = [f"{expr} AS Group{idx}" for idx, expr in enumerate(groups, start=1)]
    group_aliases = [f"Group{idx}" for idx in range(1, len(groups) + 1)]
    return (
        f"SELECT {', '.join(select_parts)}, count() AS Count\n"
        f"FROM {review_artifact_source_vql(source)}"
        f"{review_where_clause(where)}\n"
        f"GROUP BY {', '.join(group_aliases)}\n"
        "ORDER BY Count DESC\n"
        f"LIMIT {limit}"
    )


def write_review_rows(path: Path, rows: list[dict[str, Any]], output_format: str) -> int:
    if output_format == "jsonl":
        return write_jsonl(path, rows)
    return collection.write_csv(path, rows)


def review_output_record(
    *,
    artifact: str,
    artifact_name: str,
    operation: str,
    output_path: Path,
    row_count: int,
    complete: bool,
    sampled: bool,
    vql: str,
    status: str = "ok",
    error: str = "",
) -> dict[str, Any]:
    record = {
        "artifact": artifact,
        "artifact_name": artifact_name,
        "operation": operation,
        "status": status,
        "row_count": row_count,
        "complete": complete,
        "sampled": sampled,
        "output_file": str(output_path),
        "sha256": sha256_file(output_path) if output_path.exists() else "",
        "vql": vql,
        "error": error,
    }
    if error:
        record["fallback_recommendation"] = (
            "Narrow the server-side VQL with --where, split by artifact/source/host/type/time, "
            "lower --limit, select fewer fields, or use create_hunt_download() plus VFSGetBuffer "
            "for raw ZIP preservation."
        )
    return record


def review_skipped_record(
    *,
    artifact: str,
    artifact_name: str,
    operation: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "artifact": artifact,
        "artifact_name": artifact_name,
        "operation": operation,
        "status": "skipped",
        "reason": reason,
        "row_count": 0,
        "complete": False,
        "sampled": False,
        "output_file": "",
        "sha256": "",
        "vql": "",
        "error": "",
    }


def effective_review_limit(args: argparse.Namespace) -> int:
    if getattr(args, "limit", None) is not None:
        limit = int(args.limit)
    else:
        limit = HUNT_REVIEW_LIMIT_PRESETS[str(args.review_depth)]
    if limit <= 0:
        raise RuntimeError("--limit must be a positive integer.")
    return limit


def review_query_file(
    api: Any,
    *,
    vql: str,
    env: dict[str, str],
    output_path: Path,
    output_format: str,
    max_row: int,
    timeout: int,
    operation: str,
    artifact: str,
    artifact_name: str,
    sampled: bool,
    complete: bool,
) -> dict[str, Any]:
    try:
        rows = api.query(vql, env, max_wait=30, max_row=max_row, timeout=timeout)
        row_count = write_review_rows(output_path, rows, output_format)
        return review_output_record(
            artifact=artifact,
            artifact_name=artifact_name,
            operation=operation,
            output_path=output_path,
            row_count=row_count,
            complete=complete,
            sampled=sampled,
            vql=vql,
        )
    except Exception as exc:
        error_path = output_path.with_suffix(output_path.suffix + ".error.json")
        write_json(
            error_path,
            {
                "artifact": artifact,
                "artifact_name": artifact_name,
                "operation": operation,
                "error": str(exc),
                "vql": vql,
                "env": env,
                "generated_at": now_utc(),
            },
        )
        return review_output_record(
            artifact=artifact,
            artifact_name=artifact_name,
            operation=operation,
            output_path=error_path,
            row_count=0,
            complete=False,
            sampled=sampled,
            vql=vql,
            status="error",
            error=str(exc),
        )


def review_hunt_results(
    api: Any,
    investigation_id: str,
    hunt_id: str,
    request: Any,
    *,
    target_os: str | None,
    operation: str,
    field_profile: str,
    fields: list[str],
    group_by: list[str],
    inventory_group_by: list[str],
    where: str | None,
    source: str | None,
    limit: int,
    output_format: str,
    inventory_mode: str,
    max_row: int,
    timeout: int,
    artifact_references: list[str] | None = None,
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot | None = None,
    stack_id: str | None = None,
) -> dict[str, Any]:
    if limit <= 0:
        raise RuntimeError("--limit must be a positive integer.")
    if operation == "inventory" and inventory_mode not in HUNT_REVIEW_INVENTORY_MODES:
        raise RuntimeError(f"--inventory-mode must be one of: {', '.join(HUNT_REVIEW_INVENTORY_MODES)}")
    if operation == "stack" and group_by and stack_id:
        raise RuntimeError("Use either --stack-id or explicit --group-by values, not both.")
    review_dir = get_review_dir(investigation_id, hunt_id, target_os=target_os)
    review_dir.mkdir(parents=True, exist_ok=True)
    output_dir = review_dir / operation
    output_dir.mkdir(parents=True, exist_ok=True)
    effective_stack_fields: dict[str, list[str]] = {}
    effective_stack_ids: dict[str, str] = {}
    artifact_profile_hashes: list[str] = []
    resolved_policy = artifact_policy.resolve_operation_policy(
        artifact_references=artifact_references,
        policy_snapshot=policy_snapshot,
    )
    if operation == "stack" and not group_by:
        resolved_profiles = resolved_policy.profiles
        for expected in request.expected_specs:
            profile = (
                artifact_profiles.resolve_profile(expected.artifact, resolved_profiles)
                or artifact_profiles.resolve_profile(expected.label, resolved_profiles)
            )
            if profile is None:
                raise RuntimeError(
                    f"No artifact stack profile is available for {expected.artifact}; pass explicit --group-by values."
                )
            selected = artifact_profiles.select_stack_view(
                profile,
                stack_id,
                require_server=True,
            )
            if selected is None:
                available = [
                    name
                    for name, _ in artifact_profiles.ordered_stack_views(
                        profile,
                        require_server=True,
                    )
                ]
                if stack_id:
                    raise RuntimeError(
                        f"Artifact profile for {expected.artifact} does not define a server-safe stack "
                        f"named {stack_id!r}; available server-safe stacks: {', '.join(available) or 'none'}."
                    )
                raise RuntimeError(
                    f"Artifact profile for {expected.artifact} does not define a safe server stack; "
                    "pass explicit --group-by values after applying the recommended filters."
                )
            selected_stack_id, selected_stack = selected
            requirement_mismatches = stack_requirement_mismatches(selected_stack, expected.env)
            if requirement_mismatches:
                requirements = ", ".join(
                    f"{key}={value}" for key, value in sorted(requirement_mismatches.items())
                )
                raise RuntimeError(
                    f"Stack {selected_stack_id!r} for {expected.artifact} requires collection parameters "
                    f"{requirements}; the saved hunt did not collect the required fields."
                )
            effective_stack_fields[expected.label] = list(selected_stack.get("server_dimensions", []))
            effective_stack_ids[expected.label] = selected_stack_id
            artifact_profile_hashes.append(str(profile.get("_profile_hash") or ""))
    request_signature = review_request_signature(
        operation=operation,
        field_profile=field_profile,
        fields=fields,
        group_by=group_by or (["<artifact-profile>"] if effective_stack_fields else []),
        inventory_group_by=inventory_group_by,
        where=where,
        source=source,
        limit=limit,
        output_format=output_format,
        inventory_mode=inventory_mode if operation == "inventory" else "",
        artifact_profile_hashes=artifact_profile_hashes,
        effective_stack_ids=effective_stack_ids,
    )

    reviewed_files: list[dict[str, Any]] = []
    skipped_review_steps: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        env = review_env(hunt_id, expected.artifact, source)
        suffix = "jsonl" if output_format == "jsonl" else "csv"
        artifact_token = safe_review_token(expected.label)
        if operation == "inventory":
            if inventory_mode in {"exact", "both"}:
                count_vql = build_review_count_vql(source=source, where=where)
                count_path = output_dir / f"{artifact_token}-count-{request_signature}.{suffix}"
                reviewed_files.append(
                    review_query_file(
                        api,
                        vql=count_vql,
                        env=env,
                        output_path=count_path,
                        output_format=output_format,
                        max_row=max_row,
                        timeout=timeout,
                        operation="inventory-count",
                        artifact=expected.label,
                        artifact_name=expected.artifact,
                        sampled=False,
                        complete=True,
                    )
                )
            else:
                skipped_review_steps.append(
                    review_skipped_record(
                        artifact=expected.label,
                        artifact_name=expected.artifact,
                        operation="inventory-count",
                        reason="Default quick inventory skips exact global count; rerun with --inventory-mode exact or both if needed.",
                    )
            )
            if inventory_mode in {"quick", "both"}:
                inventory_vql = build_review_inventory_stack_vql(
                    source=source,
                    group_by=inventory_group_by,
                    where=where,
                    limit=limit,
                )
                inventory_suffix = "by-host" if not inventory_group_by else "inventory-stack"
                host_path = output_dir / f"{artifact_token}-{inventory_suffix}-{request_signature}.{suffix}"
                reviewed_files.append(
                    review_query_file(
                        api,
                        vql=inventory_vql,
                        env=env,
                        output_path=host_path,
                        output_format=output_format,
                        max_row=max_row,
                        timeout=timeout,
                        operation="inventory-by-host",
                        artifact=expected.label,
                        artifact_name=expected.artifact,
                        sampled=True,
                        complete=False,
                    )
                )
            else:
                skipped_review_steps.append(
                    review_skipped_record(
                        artifact=expected.label,
                        artifact_name=expected.artifact,
                        operation="inventory-by-host",
                        reason="Exact inventory mode runs only the global count; rerun with --inventory-mode quick or both for by-host stacking.",
                    )
                )
        elif operation == "stack":
            artifact_group_by = group_by or effective_stack_fields.get(expected.label, [])
            stack_vql = build_review_stack_vql(source=source, group_by=artifact_group_by, where=where, limit=limit)
            output_path = output_dir / f"{artifact_token}-stack-{request_signature}.{suffix}"
            reviewed_files.append(
                review_query_file(
                    api,
                    vql=stack_vql,
                    env=env,
                    output_path=output_path,
                    output_format=output_format,
                    max_row=max_row,
                    timeout=timeout,
                    operation="stack",
                    artifact=expected.label,
                    artifact_name=expected.artifact,
                    sampled=True,
                    complete=False,
                )
            )
        elif operation == "sample":
            sample_vql = build_review_sample_vql(
                source=source,
                field_profile=field_profile,
                fields=fields,
                where=where,
                limit=limit,
            )
            output_path = output_dir / f"{artifact_token}-sample-{request_signature}.{suffix}"
            reviewed_files.append(
                review_query_file(
                    api,
                    vql=sample_vql,
                    env=env,
                    output_path=output_path,
                    output_format=output_format,
                    max_row=max_row,
                    timeout=timeout,
                    operation="sample",
                    artifact=expected.label,
                    artifact_name=expected.artifact,
                    sampled=True,
                    complete=False,
                )
            )
        else:
            raise RuntimeError(f"Unsupported review operation: {operation}")

    manifest = {
        "reviewed_at": now_utc(),
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "operation": operation,
        "review_request_signature": request_signature,
        "field_profile": field_profile,
        "fields": review_fields_for_profile(field_profile, fields) if operation == "sample" else [],
        "group_by": group_by if operation == "stack" else [],
        "effective_group_by": effective_stack_fields if operation == "stack" and effective_stack_fields else {},
        "requested_stack_id": stack_id or "",
        "effective_stack_ids": effective_stack_ids if operation == "stack" else {},
        "artifact_profile_hashes": artifact_profile_hashes,
        "artifact_policy": resolved_policy.metadata(),
        "inventory_group_by": inventory_group_by if operation == "inventory" else [],
        "where": where or "",
        "source": source or "",
        "limit": limit,
        "output_format": output_format,
        "inventory_mode": inventory_mode if operation == "inventory" else "",
        "exact_count_skipped": operation == "inventory" and inventory_mode == "quick",
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": collection.serialize_specs(request.expected_specs),
        "reviewed_files": reviewed_files,
        "skipped_review_steps": skipped_review_steps,
    }
    manifest_path = review_dir / f"velociraptor-hunting-review-{operation}-{request_signature}.json"
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def hunt_summary_from_row(row: dict[str, Any], request: Any | None = None) -> dict[str, Any]:
    specs = hunt_requested_specs(row)
    if not specs and request is not None:
        specs = request.expected_specs
    scope = hunt_target_scope(row)
    server_target_os = hunt_target_os(row)
    return {
        "hunt_id": str(row.get("hunt_id") or ""),
        "hunt_description": str(row.get("hunt_description") or ""),
        "state": normalize_hunt_state(row.get("state")),
        "is_open": normalize_hunt_state(row.get("state")) in OPEN_HUNT_STATES,
        "is_paused": normalize_hunt_state(row.get("state")) in PAUSED_HUNT_STATES,
        "creator": str(row.get("creator") or ""),
        "created_raw": str(row.get("create_time") or ""),
        "started_raw": str(row.get("start_time") or ""),
        "expires_raw": str(row.get("expires") or ""),
        "requested_artifacts": hunt_requested_artifacts(row),
        "expected_spec_arguments": collection.serialize_specs(specs),
        "start_request": row.get("start_request"),
        "Request": row.get("Request"),
        "condition": row.get("condition"),
        "target_os": server_target_os,
        "server_target_os": server_target_os,
        "target_scope_mode": hunt_scope_mode_from_row(row),
        "host_include_labels": list(scope.include_labels),
        "host_exclude_labels": list(scope.exclude_labels),
    }


def baseline_client_ids(snapshot: dict[str, Any] | None) -> set[str]:
    if not snapshot:
        return set()
    client_ids: set[str] = set()
    for item in snapshot.get("targets") or []:
        if not isinstance(item, dict):
            continue
        client_id = str(item.get("client_id") or "").strip()
        if client_id:
            client_ids.add(client_id)
    return client_ids


def summary_from_hunt_flows(
    flows: list[dict[str, Any]],
    *,
    baseline_client_ids: set[str] | None = None,
) -> dict[str, Any]:
    client_state_map: dict[str, set[str]] = {}
    missing_client_id_rows = 0
    states: dict[str, int] = {}
    reported_result_row_count = 0
    for flow in flows:
        nested_flow = flow.get("Flow")
        nested_flow = nested_flow if isinstance(nested_flow, dict) else {}
        try:
            reported_result_row_count += max(
                0,
                int(
                    nested_flow.get("total_collected_rows")
                    or nested_flow.get("TotalCollectedRows")
                    or flow.get("total_collected_rows")
                    or flow.get("TotalCollectedRows")
                    or 0
                ),
            )
        except (TypeError, ValueError):
            pass
        state = normalize_hunt_state(
            flow.get("State")
            or flow.get("state")
            or nested_flow.get("State")
            or nested_flow.get("state")
        )
        states[state] = states.get(state, 0) + 1
        client_id = str(
            flow.get("ClientId")
            or flow.get("client_id")
            or nested_flow.get("ClientId")
            or nested_flow.get("client_id")
            or ""
        ).strip()
        if not client_id:
            missing_client_id_rows += 1
            continue
        client_state_map.setdefault(client_id, set()).add(state)
    responded_client_ids = set(client_state_map)
    open_client_ids = {
        client_id
        for client_id, client_states in client_state_map.items()
        if any(client_state in FLOW_OPEN_STATES for client_state in client_states)
    }
    failed_client_ids = {
        client_id
        for client_id, client_states in client_state_map.items()
        if any(any(token in client_state for token in FLOW_FAILURE_TOKENS) for client_state in client_states)
    }
    terminal_client_ids = responded_client_ids - open_client_ids
    success_terminal_client_ids = terminal_client_ids - failed_client_ids
    payload = {
        "flow_count": len(flows),
        "client_count": len(responded_client_ids),
        "responded_client_count": len(responded_client_ids),
        "open_client_count": len(open_client_ids),
        "terminal_client_count": len(terminal_client_ids),
        "completed_client_count": len(success_terminal_client_ids),
        "failed_client_count": len(failed_client_ids),
        "success_terminal_client_count": len(success_terminal_client_ids),
        "flow_rows_missing_client_id": missing_client_id_rows,
        "flow_states": states,
        "reported_result_row_count": reported_result_row_count,
    }
    if baseline_client_ids is not None:
        baseline_responded_client_ids = responded_client_ids & baseline_client_ids
        baseline_open_client_ids = open_client_ids & baseline_client_ids
        baseline_terminal_client_ids = terminal_client_ids & baseline_client_ids
        baseline_failed_client_ids = failed_client_ids & baseline_client_ids
        baseline_success_terminal_client_ids = success_terminal_client_ids & baseline_client_ids
        payload.update(
            {
                "baseline_responded_client_count": len(baseline_responded_client_ids),
                "baseline_open_client_count": len(baseline_open_client_ids),
                "baseline_terminal_client_count": len(baseline_terminal_client_ids),
                "baseline_completed_client_count": len(baseline_success_terminal_client_ids),
                "baseline_failed_client_count": len(baseline_failed_client_ids),
                "baseline_pending_client_count": max(len(baseline_client_ids) - len(baseline_terminal_client_ids), 0),
            }
        )
    return payload


def query_scope_clients(
    api: Any,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
) -> list[dict[str, Any]]:
    scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    required = set(scope.include_labels)
    excluded = set(scope.exclude_labels)
    rows = api.query(
        """
        SELECT
          client_id,
          os_info.hostname AS Hostname,
          os_info.fqdn AS Fqdn,
          labels AS Labels,
          timestamp(epoch=last_seen_at) AS LastSeen,
          os_info.system AS OSType,
          os_info.release AS OS
        FROM clients()
        ORDER BY last_seen_at DESC
        """,
        max_wait=30,
        max_row=1000,
    )

    seen_client_ids: set[str] = set()
    matched: list[dict[str, Any]] = []
    for row in rows:
        client_id = str(row.get("client_id") or row.get("ClientId") or "").strip()
        if not client_id or client_id in seen_client_ids:
            continue
        if not client_matches_target_os(row, scope.server_os):
            continue
        labels = parse_label_values(row.get("Labels"))
        if required and not required.issubset(labels):
            continue
        if excluded and excluded.intersection(labels):
            continue
        seen_client_ids.add(client_id)
        matched.append(
            {
                "client_id": client_id,
                "hostname": str(row.get("Hostname") or row.get("Fqdn") or ""),
                "fqdn": str(row.get("Fqdn") or ""),
                "last_seen": str(row.get("LastSeen") or ""),
                "labels": sorted(labels),
                "os_type": str(row.get("OSType") or ""),
                "os_release": str(row.get("OS") or ""),
            }
        )
    return matched


def baseline_metadata_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "baseline_scope_available": True,
        "baseline_scope_captured_at": str(snapshot.get("captured_at") or ""),
        "baseline_scope_reason": str(snapshot.get("capture_reason") or ""),
        "baseline_target_count": int(snapshot.get("target_count") or 0),
        "baseline_targets_file": str(snapshot.get("baseline_targets_file") or ""),
        "baseline_target_scope_mode": str(snapshot.get("target_scope_mode") or ""),
        "baseline_server_target_os": str(snapshot.get("server_target_os") or ""),
        "baseline_host_include_labels": list(snapshot.get("host_include_labels") or []),
        "baseline_host_exclude_labels": list(snapshot.get("host_exclude_labels") or []),
        "baseline_target_client_id_sample": list(snapshot.get("client_id_sample") or []),
        "baseline_target_hostname_sample": list(snapshot.get("hostname_sample") or []),
    }


def load_baseline_snapshot(saved_state: dict[str, Any] | None, investigation_id: str, hunt_id: str, target_os: str) -> dict[str, Any] | None:
    candidate_paths: list[Path] = []
    if saved_state:
        target_path = str(saved_state.get("baseline_targets_file") or "").strip()
        if target_path:
            candidate_paths.append(Path(target_path).expanduser())
    candidate_paths.append(baseline_targets_path(investigation_id, hunt_id, target_os=target_os))
    seen_paths: set[str] = set()
    for path in candidate_paths:
        path_key = str(path)
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)
        if path.exists() and not path.is_dir():
            snapshot = read_json(path)
            if isinstance(snapshot, dict):
                snapshot.setdefault("baseline_targets_file", str(path))
                return snapshot
    return None


def capture_baseline_snapshot(
    api: Any,
    investigation_id: str,
    hunt_id: str,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
    *,
    capture_reason: str,
) -> dict[str, Any]:
    scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    targets = query_scope_clients(api, target_os, include_labels, exclude_labels)
    hostname_sample: list[str] = []
    seen_hostnames: set[str] = set()
    for item in targets:
        hostname = str(item.get("hostname") or "").strip()
        if not hostname or hostname in seen_hostnames:
            continue
        hostname_sample.append(hostname)
        seen_hostnames.add(hostname)
        if len(hostname_sample) >= 20:
            break
    snapshot = {
        "captured_at": now_utc(),
        "capture_reason": capture_reason,
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "target_os": scope.requested_os,
        "server_target_os": scope.server_os,
        "target_scope_mode": scope.mode,
        "host_include_labels": list(scope.include_labels),
        "host_exclude_labels": list(scope.exclude_labels),
        "target_count": len(targets),
        "client_id_sample": [item["client_id"] for item in targets[:20]],
        "hostname_sample": hostname_sample,
        "targets": targets,
    }
    output_path = baseline_targets_path(investigation_id, hunt_id, target_os=target_os)
    write_json(output_path, snapshot)
    snapshot["baseline_targets_file"] = str(output_path)
    return snapshot


def prepare_baseline_snapshot(
    api: Any,
    investigation_id: str,
    hunt_id: str,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
    *,
    action: str,
) -> dict[str, Any]:
    existing_state: dict[str, Any] | None = None
    existing_state_path = find_saved_state_by_hunt_id(investigation_id, hunt_id)
    if existing_state_path is not None:
        existing_state = read_json(existing_state_path)
        existing_state.setdefault("target_os", target_os_from_state_path(existing_state_path) or normalize_target_os(target_os))

    existing_snapshot = load_baseline_snapshot(existing_state, investigation_id, hunt_id, normalize_target_os(target_os))
    should_capture = action in {"created_new_hunt", "activated_paused_hunt"} or existing_snapshot is None
    if should_capture:
        if action == "created_new_hunt":
            capture_reason = "captured_new_hunt"
        elif action == "activated_paused_hunt":
            capture_reason = "captured_activated_paused_hunt"
        else:
            capture_reason = "captured_missing_baseline_on_reuse"
        snapshot = capture_baseline_snapshot(
            api,
            investigation_id,
            hunt_id,
            target_os,
            include_labels,
            exclude_labels,
            capture_reason=capture_reason,
        )
        return snapshot
    assert existing_snapshot is not None
    existing_snapshot.setdefault("capture_reason", "reused_saved_baseline")
    return existing_snapshot


def started_datetime_from_hunt_summary(hunt_summary: dict[str, Any], baseline_snapshot: dict[str, Any] | None = None) -> datetime | None:
    started_raw = parse_datetime_value(hunt_summary.get("started_raw"))
    state = normalize_hunt_state(hunt_summary.get("state"))
    if state in PAUSED_HUNT_STATES:
        return None
    baseline_capture_reason = str((baseline_snapshot or {}).get("capture_reason") or "")
    if baseline_capture_reason in {"captured_activated_paused_hunt", "captured_missing_baseline_on_reuse"}:
        baseline_started = parse_datetime_value((baseline_snapshot or {}).get("captured_at"))
        if baseline_started is not None:
            return baseline_started
    if started_raw is not None:
        return started_raw
    created_raw = parse_datetime_value(hunt_summary.get("created_raw"))
    if created_raw is not None:
        return created_raw
    if baseline_capture_reason == "captured_new_hunt":
        return parse_datetime_value((baseline_snapshot or {}).get("captured_at"))
    return None


def evaluate_hunt_readiness(hunt_summary: dict[str, Any], baseline_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if baseline_snapshot is None:
        return {
            "baseline_scope_available": False,
            "baseline_scope_reason": "baseline_unavailable",
            "baseline_scope_captured_at": "",
            "baseline_target_count": 0,
            "baseline_targets_file": "",
            "review_readiness": "baseline_unavailable",
            "strict_complete": False,
            "completion_ratio": 0.0,
            "response_ratio": 0.0,
            "failed_ratio": 0.0,
            "retry_after": "",
            "completion_reason": "No saved baseline target snapshot is available for this hunt.",
        }

    baseline_metadata = baseline_metadata_from_snapshot(baseline_snapshot)
    baseline_count = int(baseline_metadata["baseline_target_count"])
    responded_raw = hunt_summary.get("baseline_responded_client_count")
    if responded_raw is None:
        responded_raw = hunt_summary.get("responded_client_count")
    if responded_raw is None:
        responded_raw = hunt_summary.get("client_count")
    responded_count = int(responded_raw or 0)
    completed_raw = hunt_summary.get("baseline_completed_client_count")
    if completed_raw is None:
        completed_raw = hunt_summary.get("completed_client_count")
    if completed_raw is None:
        completed_raw = hunt_summary.get("success_terminal_client_count")
    if completed_raw is None:
        completed_raw = hunt_summary.get("terminal_client_count")
    completed_count = int(completed_raw or 0)
    terminal_raw = hunt_summary.get("baseline_terminal_client_count")
    if terminal_raw is None:
        terminal_raw = hunt_summary.get("terminal_client_count")
    terminal_count = int(terminal_raw or 0)
    failed_raw = hunt_summary.get("baseline_failed_client_count")
    if failed_raw is None:
        failed_raw = hunt_summary.get("failed_client_count")
    failed_count = int(failed_raw or 0)
    responded_count = min(max(responded_count, 0), baseline_count) if baseline_count > 0 else max(responded_count, 0)
    completed_count = min(max(completed_count, 0), baseline_count) if baseline_count > 0 else max(completed_count, 0)
    terminal_count = min(max(terminal_count, 0), baseline_count) if baseline_count > 0 else max(terminal_count, 0)
    failed_count = min(max(failed_count, 0), baseline_count) if baseline_count > 0 else max(failed_count, 0)
    started_at = started_datetime_from_hunt_summary(hunt_summary, baseline_snapshot)
    now = datetime.now(timezone.utc)
    age_hours = (now - started_at).total_seconds() / 3600 if started_at is not None else None
    completion_ratio = (completed_count / baseline_count) if baseline_count > 0 else 0.0
    response_ratio = (responded_count / baseline_count) if baseline_count > 0 else 0.0
    failed_ratio = (failed_count / baseline_count) if baseline_count > 0 else 0.0

    if baseline_count == 0:
        return {
            **baseline_metadata,
            "review_readiness": "stalled_or_needs_operator_attention",
            "strict_complete": False,
            "completion_ratio": 0.0,
            "response_ratio": 0.0,
            "failed_ratio": 0.0,
            "retry_after": "",
            "completion_reason": "Baseline target scope captured zero eligible clients for this hunt.",
            "baseline_age_hours": age_hours,
        }

    strict_complete = terminal_count >= baseline_count
    retry_after = ""
    review_readiness = "not_ready_retry_later"
    completion_reason = (
        f"Hunt has completed on {completed_count} of {baseline_count} baseline targets "
        f"({completion_ratio:.0%})."
    )

    if strict_complete:
        review_readiness = "ready_for_review"
        if failed_count > 0:
            completion_reason = (
                f"All {baseline_count} baseline targets reached terminal state "
                f"({completed_count} succeeded, {failed_count} failed)."
            )
        else:
            completion_reason = (
                f"Hunt completed on all {baseline_count} baseline targets."
            )
    elif completion_ratio >= READINESS_IMMEDIATE_RATIO:
        review_readiness = "ready_for_review"
        completion_reason = (
            f"Hunt completed on {completed_count} of {baseline_count} baseline targets "
            f"({completion_ratio:.0%}), which meets the immediate readiness threshold."
        )
    elif age_hours is not None and completion_ratio >= READINESS_DELAYED_RATIO and age_hours >= READINESS_DELAYED_HOURS:
        review_readiness = "ready_for_review"
        completion_reason = (
            f"Hunt completed on {completed_count} of {baseline_count} baseline targets "
            f"({completion_ratio:.0%}) after {age_hours:.1f} hours, which meets the delayed readiness threshold."
        )
    elif age_hours is not None and age_hours >= READINESS_DELAYED_HOURS and (
        completion_ratio < STALLED_LOW_RATIO or failed_ratio >= STALLED_FAILURE_RATIO
    ):
        review_readiness = "stalled_or_needs_operator_attention"
        completion_reason = (
            f"Hunt is still at {completion_ratio:.0%} completion after {age_hours:.1f} hours; "
            "review is not ready and operator attention is likely needed."
        )
    else:
        if started_at is not None:
            if age_hours is not None and age_hours < READINESS_EARLY_RETRY_HOURS:
                retry_target = started_at + timedelta(hours=READINESS_EARLY_RETRY_HOURS)
            else:
                retry_target = started_at + timedelta(hours=READINESS_DELAYED_HOURS)
                retry_target = max(retry_target, now + timedelta(hours=READINESS_RETRY_GRACE_HOURS))
            retry_after = retry_target.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        completion_reason = (
            f"Hunt is not ready for review yet: {completed_count} of {baseline_count} baseline targets "
            f"have completed ({completion_ratio:.0%})."
        )

    return {
        **baseline_metadata,
        "review_readiness": review_readiness,
        "strict_complete": strict_complete,
        "completion_ratio": completion_ratio,
        "response_ratio": response_ratio,
        "failed_ratio": failed_ratio,
        "retry_after": retry_after,
        "completion_reason": completion_reason,
        "baseline_age_hours": age_hours,
    }


def casefold_text(value: Any) -> str:
    return str(value or "").strip().casefold()


def text_contains_identifier(text: Any, identifier: str) -> bool:
    value = str(identifier or "").strip()
    if not value:
        return False
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])",
            str(text or ""),
            flags=re.IGNORECASE,
        )
    )


def hunt_tags(row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("tags", "hunt_tags", "labels"):
        values.extend(parse_json_list(row.get(key)))
    return unique_ordered([str(value).strip() for value in values if str(value).strip()])


def hunt_case_identifiers(row: dict[str, Any]) -> list[str]:
    description = str(row.get("hunt_description") or "")
    searchable = [description, *hunt_scope_labels(row, "include_labels"), *hunt_tags(row)]
    identifiers: list[str] = []
    for value in searchable:
        identifiers.extend(
            match.group(1)
            for match in re.finditer(
                r"(?i)(?<![A-Za-z0-9])dfir-engagement:([A-Za-z0-9._@+/-]+)",
                value,
            )
        )
        identifiers.extend(
            match.group(0)
            for match in re.finditer(
                r"(?i)(?<![A-Za-z0-9])IR[0-9]+(?![A-Za-z0-9])",
                value,
            )
        )
    return unique_ordered([casefold_text(value) for value in identifiers])


def resolve_case_scope(row: dict[str, Any], investigation_id: str, profile: str, signature: str) -> tuple[bool, bool]:
    description = str(row.get("hunt_description") or "")
    searchable = [description, *hunt_scope_labels(row, "include_labels"), *hunt_tags(row)]
    matches_case = any(
        text_contains_identifier(value, investigation_id)
        for value in searchable
    )
    matches_profile = any(
        casefold_text(value) in casefold_text(description)
        for value in (profile, signature)
        if str(value or "").strip()
    )
    return matches_case, matches_profile


def artifact_specs_match(actual: Any, expected: Any) -> bool:
    return (
        bool(artifact_spec_names(actual).intersection(artifact_spec_names(expected)))
        and dict(actual.env) == dict(expected.env)
        and getattr(actual, "timeout_seconds", None) == getattr(expected, "timeout_seconds", None)
    )


def artifact_spec_names(spec: Any) -> set[str]:
    return {
        casefold_text(value)
        for value in (getattr(spec, "artifact", ""), getattr(spec, "label", ""))
        if str(value or "").strip()
    }


def artifact_subset_match(actual_specs: list[Any], expected_specs: list[Any]) -> bool:
    if not expected_specs:
        return False
    return all(
        any(artifact_spec_names(actual).intersection(artifact_spec_names(expected)) for actual in actual_specs)
        for expected in expected_specs
    )


def requested_spec_compatibility(
    actual_specs: list[Any],
    expected_specs: list[Any],
) -> tuple[bool, list[dict[str, Any]]]:
    mismatches: list[dict[str, Any]] = []
    for expected in expected_specs:
        named_matches = [
            actual
            for actual in actual_specs
            if artifact_spec_names(actual).intersection(artifact_spec_names(expected))
        ]
        if not named_matches:
            mismatches.append(
                {
                    "artifact": str(expected.artifact),
                    "reason": "requested artifact is absent",
                }
            )
            continue
        if any(artifact_specs_match(actual, expected) for actual in named_matches):
            continue
        mismatches.append(
            {
                "artifact": str(expected.artifact),
                "reason": "artifact parameters or timeout differ",
            }
        )
    return not mismatches, mismatches


def case_insensitive_scope_match(actual: HuntTargetScope, expected: HuntTargetScope) -> bool:
    return (
        actual.mode == expected.mode
        and actual.server_os == expected.server_os
        and {casefold_text(value) for value in actual.include_labels}
        == {casefold_text(value) for value in expected.include_labels}
        and {casefold_text(value) for value in actual.exclude_labels}
        == {casefold_text(value) for value in expected.exclude_labels}
    )


def classify_hunt_candidate(
    row: dict[str, Any],
    investigation_id: str,
    *,
    parameters_compatible: bool,
) -> tuple[str, str, list[str]]:
    current = casefold_text(investigation_id)
    identifiers = hunt_case_identifiers(row)
    matches_current, _ = resolve_case_scope(row, investigation_id, "", "")
    other_identifiers = [value for value in identifiers if value != current]
    if not parameters_compatible:
        return (
            HUNT_CANDIDATE_UNRELATED,
            "requested artifacts are present but parameters or timeout are incompatible",
            identifiers,
        )
    if matches_current and other_identifiers:
        return (
            HUNT_CANDIDATE_UNRELATED,
            "hunt contains conflicting current and different engagement identifiers",
            identifiers,
        )
    if matches_current:
        return (
            HUNT_CANDIDATE_EXACT_CASE,
            "current engagement appears in a target label, hunt tag, or description",
            identifiers,
        )
    if other_identifiers:
        return (
            HUNT_CANDIDATE_DIFFERENT_IR_TEMPLATE,
            "compatible artifact request is associated with a different engagement",
            identifiers,
        )
    return (
        HUNT_CANDIDATE_GENERIC_TEMPLATE,
        "compatible artifact request has no engagement association",
        identifiers,
    )


def candidate_rank(item: dict[str, Any]) -> tuple[int, int, int, int, int]:
    classification = str(item.get("candidate_classification") or "")
    compatible = bool(item.get("selection_compatible"))
    class_rank = {
        HUNT_CANDIDATE_EXACT_CASE: 4,
        HUNT_CANDIDATE_GENERIC_TEMPLATE: 3,
        HUNT_CANDIDATE_DIFFERENT_IR_TEMPLATE: 2,
        HUNT_CANDIDATE_UNRELATED: 0,
    }.get(classification, 0)
    if not compatible:
        class_rank = 0
    return (
        class_rank,
        run_identity.classification_rank(str(item.get("reuse_classification") or ""))
        if classification == HUNT_CANDIDATE_EXACT_CASE
        else 0,
        int(bool(item.get("matches_requested_group"))),
        int(bool(item.get("matches_profile_hint"))),
        coerce_int(item.get("created_raw")),
    )


def find_matching_hunts(
    api: Any,
    investigation_id: str,
    target_name: str,
    request: Any,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
    group: str = "",
    mismatch_sink: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    expected_signature = request_signature(request, target_os, include_labels, exclude_labels)
    expected_identity = hunt_run_identity(
        request,
        target_os,
        include_labels,
        exclude_labels,
    )
    requested_group_marker = hunt_group_marker(group) if group else ""
    expected_scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    matches: list[dict[str, Any]] = []

    for row in query_hunts(api):
        actual_specs = hunt_requested_specs(row)
        if not artifact_subset_match(actual_specs, request.expected_specs):
            continue
        actual_scope = hunt_target_scope(row)
        actual_identity = run_identity.build_run_identity(
            source_mode="velociraptor-hunt",
            target={
                "target_scope_mode": actual_scope.mode,
                "server_target_os": actual_scope.server_os,
                "include_labels": list(actual_scope.include_labels),
                "exclude_labels": list(actual_scope.exclude_labels),
            },
            specs=actual_specs,
        )
        mismatches = run_identity.identity_mismatches(
            expected_identity["identity"],
            actual_identity["identity"],
        )
        if mismatches and mismatch_sink is not None and len(mismatch_sink) < 10:
            mismatch_sink.append(
                {
                    "hunt_id": str(row.get("hunt_id") or ""),
                    "state": normalize_hunt_state(row.get("state")),
                    "created_raw": str(row.get("create_time") or ""),
                    "mismatches": mismatches,
                    "actual_run_identity_sha256": actual_identity["sha256"],
                }
            )
        parameters_compatible, parameter_mismatches = requested_spec_compatibility(
            actual_specs,
            request.expected_specs,
        )
        matches_case, matches_profile = resolve_case_scope(row, investigation_id, target_name, expected_signature)
        item = hunt_summary_from_row(row, request=request)
        classification = hunt_reuse_classification(item["state"])
        candidate_classification, classification_reason, engagement_identifiers = classify_hunt_candidate(
            row,
            investigation_id,
            parameters_compatible=parameters_compatible,
        )
        scope_compatible = case_insensitive_scope_match(actual_scope, expected_scope)
        selection_compatible = bool(
            parameters_compatible
            and (
                candidate_classification in TEMPLATE_CANDIDATE_CLASSES
                or scope_compatible
            )
        )
        item["matches_case_scope"] = matches_case
        item["matches_profile_hint"] = matches_profile
        item["matches_requested_group"] = bool(
            requested_group_marker
            and requested_group_marker in str(row.get("hunt_description") or "")
        )
        item["request_signature"] = expected_signature
        item["run_identity"] = expected_identity["identity"]
        item["run_identity_sha256"] = expected_identity["sha256"]
        item["actual_run_identity_sha256"] = actual_identity["sha256"]
        item["reuse_classification"] = classification
        item["reuse_allowed"] = bool(
            run_identity.reuse_allowed(classification)
            and candidate_classification == HUNT_CANDIDATE_EXACT_CASE
            and parameters_compatible
            and scope_compatible
        )
        item["result_evidence_allowed"] = bool(
            candidate_classification == HUNT_CANDIDATE_EXACT_CASE
            and parameters_compatible
            and scope_compatible
        )
        item["template_only"] = candidate_classification in TEMPLATE_CANDIDATE_CLASSES
        item["candidate_classification"] = candidate_classification
        item["candidate_classification_reason"] = classification_reason
        item["engagement_identifiers"] = engagement_identifiers
        item["artifact_subset_match"] = True
        item["parameters_compatible"] = parameters_compatible
        item["scope_compatible"] = scope_compatible
        item["selection_compatible"] = selection_compatible
        item["parameter_mismatches"] = parameter_mismatches
        item["matched_requested_specs"] = collection.serialize_specs(request.expected_specs)
        item["hunt_spec_count"] = len(actual_specs)
        item["source_artifact_set"] = unique_ordered(
            [str(spec.artifact) for spec in actual_specs]
        )
        item["source_parameters"] = collection.serialize_specs(actual_specs)
        matches.append(item)

    matches.sort(key=candidate_rank, reverse=True)
    for index, item in enumerate(matches, start=1):
        item["selection_rank"] = index
    return matches


def hunt_selection_decision(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    classification_counts = {
        HUNT_CANDIDATE_EXACT_CASE: 0,
        HUNT_CANDIDATE_GENERIC_TEMPLATE: 0,
        HUNT_CANDIDATE_DIFFERENT_IR_TEMPLATE: 0,
        HUNT_CANDIDATE_UNRELATED: 0,
    }
    for candidate in candidates:
        classification = str(candidate.get("candidate_classification") or HUNT_CANDIDATE_UNRELATED)
        classification_counts[classification] = classification_counts.get(classification, 0) + 1

    exact_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("candidate_classification") == HUNT_CANDIDATE_EXACT_CASE
        and bool(candidate.get("selection_compatible"))
    ]
    reusable_exact = [candidate for candidate in exact_candidates if bool(candidate.get("reuse_allowed"))]
    template_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("candidate_classification") in TEMPLATE_CANDIDATE_CLASSES
        and bool(candidate.get("selection_compatible"))
    ]
    recommended_template = template_candidates[0] if template_candidates else None

    if reusable_exact:
        selected = reusable_exact[0]
        decision = "reuse_exact_case_hunt"
        reason = (
            "highest-ranked exact current-case hunt has compatible requested artifacts, "
            "parameters, and target scope"
        )
        human_summary = (
            f"Reuse current-case hunt {selected['hunt_id']} ({selected['state'] or 'UNKNOWN'}); "
            f"the requested artifacts are contained in its {selected['hunt_spec_count']}-artifact set."
        )
    elif exact_candidates:
        selected = exact_candidates[0]
        decision = "force_run_required"
        reason = "compatible exact current-case hunts exist, but none are reusable under lifecycle rules"
        human_summary = (
            f"Current-case hunt {selected['hunt_id']} is {selected['state'] or 'UNKNOWN'} and is not reusable; "
            "explicit --force-run authorization is required for a fresh hunt."
        )
    elif recommended_template:
        selected = recommended_template
        decision = "template_authorization_required"
        reason = (
            "a compatible template exists, but templates are reference-only and cannot be used as current-case evidence"
        )
        human_summary = (
            f"Review template hunt {selected['hunt_id']} ({selected['candidate_classification']}); "
            "its results are not current-case evidence. Pass --authorize-template-create to create a new current-case hunt."
        )
    else:
        selected = None
        decision = "create_new_hunt"
        reason = "no reusable exact current-case hunt or compatible template was discovered"
        human_summary = "No reusable current-case hunt or compatible template was found; create a new hunt."

    return {
        "discovery_count": len(candidates),
        "candidate_classification_counts": classification_counts,
        "selection_decision": decision,
        "selection_reason": reason,
        "human_summary": human_summary,
        "selected_candidate": selected,
        "recommended_template": recommended_template,
        "exact_compatible_candidates": exact_candidates,
        "reusable_exact_candidates": reusable_exact,
        "template_candidates": template_candidates,
    }


def build_create_hunt_vql(scope: HuntTargetScope) -> str:
    let_lines = [
        "LET RequestedArtifacts <= parse_json_array(data=ArtifactsJson)",
        "LET RequestedSpecs <= parse_json_array(data=SpecsJson)",
    ]
    hunt_arguments = [
        "description=Description",
        "artifacts=RequestedArtifacts",
        "spec=RequestedSpecs",
        "pause='Y'",
    ]
    if scope.server_os:
        hunt_arguments.append("os=TargetOS")
    if scope.include_labels:
        let_lines.append("LET IncludedLabels <= parse_json_array(data=IncludeLabelsJson)")
        hunt_arguments.append("include_labels=IncludedLabels")
    if scope.exclude_labels:
        let_lines.append("LET ExcludedLabels <= parse_json_array(data=ExcludeLabelsJson)")
        hunt_arguments.append("exclude_labels=ExcludedLabels")
    hunt_arguments.append("tags=parse_json_array(data=TagsJson)")
    rendered_arguments = ",\n          ".join(hunt_arguments)
    return (
        "\n        "
        + "\n        ".join(let_lines)
        + "\n        SELECT hunt(\n          "
        + rendered_arguments
        + "\n        ) AS HuntResult FROM scope()\n        "
    )


def create_hunt(
    api: Any,
    investigation_id: str,
    target_name: str,
    request: Any,
    target_os: str | None,
    include_labels: list[str],
    exclude_labels: list[str],
    hunt_tags: list[str],
    start_paused: bool,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("create_hunt")
    scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    signature = request_signature(request, target_os, include_labels, exclude_labels)
    description = build_hunt_description(investigation_id, target_name, signature, scope.requested_os)
    artifacts = unique_ordered([spec.artifact for spec in request.expected_specs])
    specs_json = stable_json([collection.spec_to_request_dict(spec) for spec in request.expected_specs])
    tags_json = stable_json(
        combined_hunt_tags(
            investigation_id,
            target_name,
            signature,
            hunt_tags,
            scope.requested_os,
        )
    )
    # On current Velociraptor builds, native hunt creation is more reliable
    # when the hunt is created paused first and started in a second step.
    effective_start_paused = True

    query_env = {
        "ArtifactsJson": stable_json(artifacts),
        "SpecsJson": specs_json,
        "Description": description,
        "TagsJson": tags_json,
    }
    if scope.server_os:
        query_env["TargetOS"] = scope.server_os
    if scope.include_labels:
        query_env["IncludeLabelsJson"] = stable_json(list(scope.include_labels))
    if scope.exclude_labels:
        query_env["ExcludeLabelsJson"] = stable_json(list(scope.exclude_labels))

    rows = api.query(
        build_create_hunt_vql(scope),
        query_env,
        max_wait=30,
        max_row=10,
    )

    hunt_result = rows[0].get("HuntResult") if rows else None
    hunt_id = ""
    if isinstance(hunt_result, dict):
        hunt_id = str(
            hunt_result.get("HuntId")
            or hunt_result.get("hunt_id")
            or ((hunt_result.get("Request") or {}).get("hunt_id") if isinstance(hunt_result.get("Request"), dict) else "")
            or ""
        )
    if not hunt_id:
        # Some Velociraptor builds create the hunt successfully but return an
        # empty scope row instead of surfacing HuntId directly from hunt().
        created_row = find_hunt_by_description(api, description)
        if created_row is not None:
            hunt_id = str(created_row.get("hunt_id") or "")
    if not hunt_id:
        raise RuntimeError("Velociraptor hunt() did not return a hunt id.")
    return {
        "hunt_id": hunt_id,
        "hunt_description": description,
        "request_signature": signature,
        "target_os": scope.requested_os,
        "server_target_os": scope.server_os,
        "target_scope_mode": scope.mode,
        "host_include_labels": list(scope.include_labels),
        "host_exclude_labels": list(scope.exclude_labels),
        "created_paused_for_validation": effective_start_paused and not start_paused,
    }


def persist_state(
    investigation_id: str,
    profile: str,
    request: Any,
    hunt_summary: dict[str, Any],
    payload: dict[str, Any],
    *,
    existing_state: dict[str, Any] | None = None,
    update_current_pointer: bool = True,
) -> dict[str, Any]:
    hunt_id = str(hunt_summary["hunt_id"])
    target_os = normalize_target_os(
        payload.get("target_os")
        or hunt_summary.get("target_os")
        or (existing_state or {}).get("target_os")
        or current_target_os()
    )
    timestamp = now_utc()
    state = {
        **(existing_state or {}),
        "saved_at": str((existing_state or {}).get("saved_at") or timestamp),
        "updated_at": timestamp,
        "investigation_id": investigation_id,
        "profile": profile,
        "description": HUNT_PROFILES.get(profile, {}).get("description", f"Hunt target {profile}"),
        "hunt_id": hunt_id,
        "hunt_description": hunt_summary.get("hunt_description", ""),
        "target_os": target_os,
        "target_namespace": target_namespace(target_os),
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": collection.serialize_specs(request.expected_specs),
        **payload,
    }
    state_path = hunt_state_path(investigation_id, hunt_id, target_os=target_os)
    state["state_file"] = str(state_path)
    current_path = current_profile_path(investigation_id, profile, target_os=target_os)
    state["current_state_file"] = str(current_path)
    write_json(state_path, state)
    if update_current_pointer:
        write_json(
            current_path,
            {
                "hunt_id": hunt_id,
                "state_file": str(state_path),
                "updated_at": state["updated_at"],
            },
        )
    return state


SLIM_ENSURE_OUTPUT_OMIT_KEYS = {"Request", "start_request"}


def remove_heavy_hunt_output_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: remove_heavy_hunt_output_fields(item)
            for key, item in value.items()
            if key not in SLIM_ENSURE_OUTPUT_OMIT_KEYS
        }
    if isinstance(value, list):
        return [remove_heavy_hunt_output_fields(item) for item in value]
    return value


def slim_ensure_output(state: dict[str, Any]) -> dict[str, Any]:
    slim = remove_heavy_hunt_output_fields(state)
    if isinstance(slim, dict):
        slim["output_mode"] = "slim"
        slim["full_state_file"] = str(state.get("state_file") or "")
        slim["suppressed_output_fields"] = sorted(SLIM_ENSURE_OUTPUT_OMIT_KEYS)
    return slim


def find_saved_state_by_hunt_id(investigation_id: str, hunt_id: str) -> Path | None:
    state_path = hunt_state_path(investigation_id, hunt_id)
    return state_path if state_path.exists() else None


def target_os_from_state_path(state_path: Path) -> str | None:
    try:
        target_os = normalize_target_os(read_json(state_path).get("target_os"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return target_os if target_os in TARGET_CHOICES else None


def find_current_profile_path(
    investigation_id: str,
    profile: str,
    target_os: str | None,
) -> Path | None:
    candidate = current_profile_path(investigation_id, profile, target_os=target_os)
    return candidate if candidate.exists() else None


def require_saved_profile_artifact(profile: str | None, selected_artifact: list[str]) -> None:
    if not profile or selected_artifact:
        return
    artifact_labels = profile_artifact_labels(profile)
    if len(artifact_labels) <= 1:
        return
    raise RuntimeError(
        f"Profile {profile!r} resolves to multiple artifacts. Pass exactly one "
        "--artifact value with --profile."
    )


def load_saved_state(
    investigation_id: str,
    hunt_id: str | None,
    profile: str | None,
    artifact: str | None = None,
    target_os: str | None = None,
) -> dict[str, Any]:
    if hunt_id:
        state_path = find_saved_state_by_hunt_id(investigation_id, hunt_id)
        if state_path is None:
            raise RuntimeError(
                f"Hunt state not found for {hunt_id}. The saved hunt may not exist under "
                "any target namespace for this investigation."
            )
        state = read_json(state_path)
        state.setdefault("target_os", target_os_from_state_path(state_path) or "")
        return state
    if not profile:
        if artifact:
            resolved_target_os = normalize_target_os(target_os if target_os is not None else current_target_os())
            current_path = find_current_profile_path(
                investigation_id,
                artifact,
                resolved_target_os,
            )
            if current_path is None:
                raise RuntimeError(
                    f"No saved hunt pointer found for artifact {artifact!r} "
                    f"under any target namespace for investigation {investigation_id}."
                )
            pointer = read_json(current_path)
            state_path = Path(str(pointer.get("state_file") or "")).expanduser()
            if not state_path.exists():
                raise RuntimeError(f"Saved hunt state file not found: {state_path}")
            state = read_json(state_path)
            state.setdefault("target_os", target_os_from_state_path(state_path) or resolved_target_os)
            return state
        raise RuntimeError("Pass --hunt-id, --profile, or exactly one --artifact to load a saved hunt state.")
    resolved_target_os = normalize_target_os(target_os if target_os is not None else current_target_os())
    candidate_keys: list[str] = []
    if artifact:
        selected_label = select_profile_artifact(profile, artifact)
        candidate_keys.append(f"{profile}--{selected_label}")
        if len(profile_artifact_labels(profile)) == 1:
            candidate_keys.append(profile)
    else:
        candidate_keys.append(profile)
        artifact_labels = profile_artifact_labels(profile)
        if len(artifact_labels) == 1:
            candidate_keys.append(f"{profile}--{artifact_labels[0]}")

    current_path: Path | None = None
    for profile_key in unique_ordered(candidate_keys):
        candidate_path = find_current_profile_path(investigation_id, profile_key, resolved_target_os)
        if candidate_path is not None:
            current_path = candidate_path
            break
    if current_path is None:
        raise RuntimeError(
            f"No saved hunt pointer found for profile {profile!r} under any target "
            f"namespace for investigation {investigation_id}."
        )
    pointer = read_json(current_path)
    state_path = Path(str(pointer.get("state_file") or "")).expanduser()
    if not state_path.exists():
        raise RuntimeError(f"Saved hunt state file not found: {state_path}")
    state = read_json(state_path)
    state.setdefault("target_os", target_os_from_state_path(state_path) or "")
    return state


def resolve_request_from_state(saved_state: dict[str, Any]) -> Any:
    return collection.request_from_state(saved_state, collection.normalize_artifacts(saved_state.get("requested_artifacts")))


def resolve_request_from_hunt_row(hunt_row: dict[str, Any]) -> Any:
    requested_artifacts = hunt_requested_artifacts(hunt_row)
    return collection.request_from_state(
        {
            "target_collection_type": "",
            "requested_groups": [],
            "requested_artifacts": requested_artifacts,
            "expected_spec_arguments": collection.serialize_specs(hunt_requested_specs(hunt_row)),
        },
        requested_artifacts,
    )


def hunt_result_artifact_sources(hunt_row: dict[str, Any] | None) -> list[str]:
    if not hunt_row:
        return []
    candidates: list[Any] = [hunt_row.get("artifact_sources")]
    request = hunt_row.get("Request")
    if isinstance(request, dict):
        candidates.append(request.get("artifact_sources"))
    start_request = hunt_row.get("start_request")
    if isinstance(start_request, dict):
        candidates.append(start_request.get("artifact_sources"))
    for candidate in candidates:
        sources = collection.normalize_artifacts(candidate)
        if sources:
            return unique_ordered(sources)
    return []


def result_sources_for_artifact(artifact_name: str, artifact_sources: list[str]) -> list[str]:
    prefix = f"{artifact_name}/"
    matches = [
        source
        for source in artifact_sources
        if source == artifact_name or source.startswith(prefix)
    ]
    return unique_ordered(matches) or [artifact_name]


def source_output_label(artifact_label: str, artifact_name: str, artifact_source: str) -> str:
    if artifact_source == artifact_name:
        return artifact_label
    prefix = f"{artifact_name}/"
    suffix = artifact_source[len(prefix) :] if artifact_source.startswith(prefix) else artifact_source
    normalized_suffix = ".".join(
        token
        for token in (safe_review_token(part) for part in suffix.split("/"))
        if token
    )
    return f"{artifact_label}.{normalized_suffix}" if normalized_suffix else artifact_label


def export_hunt(
    api: Any,
    investigation_id: str,
    hunt_id: str,
    request: Any,
    *,
    target_os: str | None = None,
    artifact_sources: list[str] | None = None,
) -> dict[str, Any]:
    persistence_authorization = persistence_policy.authorize_persistence(
        "immutable_evidence_export",
        source_ids=[
            f"hunt:{hunt_id}:{spec.artifact}"
            for spec in request.expected_specs
        ],
        raw_rows=True,
        explicit_export=True,
    )
    exports_dir = get_exports_dir(investigation_id, hunt_id, target_os=target_os)
    exports_dir.mkdir(parents=True, exist_ok=True)

    exported_files: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        resolved_sources = result_sources_for_artifact(expected.artifact, artifact_sources or [])
        for artifact_source in resolved_sources:
            output_label = source_output_label(expected.label, expected.artifact, artifact_source)
            rows, query_meta = query_hunt_results_resilient(api, hunt_id, artifact_source)
            if query_meta["status"] == "resource_exhausted":
                output_path = exports_dir / f"{safe_review_token(output_label)}-resource-exhausted.error.json"
                write_hunt_result_query_error(
                    output_path,
                    artifact=expected.label,
                    artifact_name=artifact_source,
                    query_meta=query_meta,
                )
                row_count = 0
            else:
                output_path = exports_dir / collection.export_filename_for_artifact(output_label)
                row_count = collection.write_csv(output_path, rows)
            exported_files.append(
                {
                    "artifact": expected.label,
                    "artifact_name": expected.artifact,
                    "artifact_source": artifact_source,
                    "source_output_label": output_label,
                    "mode": "hunt-results",
                    "status": query_meta["status"],
                    "query_max_row": query_meta["max_row"],
                    "query_attempts": query_meta["attempts"],
                    "error": query_meta.get("error", ""),
                    "fallback_recommendation": query_meta.get("fallback_recommendation", ""),
                    "row_count": row_count,
                    "output_file": str(output_path),
                }
            )

    manifest = {
        "exported_at": now_utc(),
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": collection.serialize_specs(request.expected_specs),
        "available_artifact_sources": list(artifact_sources or []),
        "persistence_authorization": persistence_authorization,
        "exported_files": exported_files,
    }
    manifest_path = exports_dir / "velociraptor-hunting-export.json"
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def download_hunt_results(
    api: Any,
    investigation_id: str,
    hunt_id: str,
    request: Any,
    *,
    target_os: str | None = None,
    artifact_sources: list[str] | None = None,
) -> dict[str, Any]:
    persistence_authorization = persistence_policy.authorize_persistence(
        "interoperability_export",
        source_ids=[
            f"hunt:{hunt_id}:{spec.artifact}"
            for spec in request.expected_specs
        ],
        raw_rows=True,
        explicit_export=True,
    )
    downloads_dir = get_downloads_dir(investigation_id, hunt_id, target_os=target_os)
    downloads_dir.mkdir(parents=True, exist_ok=True)

    downloaded_files: list[dict[str, Any]] = []
    for expected in request.expected_specs:
        resolved_sources = result_sources_for_artifact(expected.artifact, artifact_sources or [])
        for artifact_source in resolved_sources:
            output_label = source_output_label(expected.label, expected.artifact, artifact_source)
            rows, query_meta = query_hunt_results_resilient(api, hunt_id, artifact_source)
            if query_meta["status"] == "resource_exhausted":
                output_path = downloads_dir / f"{safe_review_token(output_label)}-resource-exhausted.error.json"
                write_hunt_result_query_error(
                    output_path,
                    artifact=expected.label,
                    artifact_name=artifact_source,
                    query_meta=query_meta,
                )
                row_count = 0
            else:
                output_path = downloads_dir / collection.export_filename_for_artifact_text(output_label, "jsonl")
                row_count = write_jsonl(output_path, rows)
            downloaded_files.append(
                {
                    "artifact": expected.label,
                    "artifact_name": expected.artifact,
                    "artifact_source": artifact_source,
                    "source_output_label": output_label,
                    "mode": "hunt-results-jsonl",
                    "status": query_meta["status"],
                    "query_max_row": query_meta["max_row"],
                    "query_attempts": query_meta["attempts"],
                    "error": query_meta.get("error", ""),
                    "fallback_recommendation": query_meta.get("fallback_recommendation", ""),
                    "row_count": row_count,
                    "output_file": str(output_path),
                }
            )

    manifest = {
        "downloaded_at": now_utc(),
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "target_collection_type": request.target_collection_type,
        "requested_groups": request.requested_groups,
        "requested_artifacts": request.requested_artifacts,
        "expected_spec_arguments": collection.serialize_specs(request.expected_specs),
        "available_artifact_sources": list(artifact_sources or []),
        "persistence_authorization": persistence_authorization,
        "downloaded_files": downloaded_files,
    }
    manifest_path = downloads_dir / "velociraptor-hunting-download.json"
    write_json(manifest_path, manifest)
    manifest["manifest_file"] = str(manifest_path)
    return manifest


def resolve_saved_or_explicit_hunt(
    args: argparse.Namespace,
    api: Any,
    *,
    command_name: str,
) -> dict[str, Any]:
    selected_artifact = artifact_selector_values(args)
    if len(selected_artifact) > 1:
        raise RuntimeError(f"Pass at most one --artifact value when loading saved hunt state for {command_name}.")
    if getattr(args, "hunt_id", None) and selected_artifact:
        raise RuntimeError(f"{command_name} does not accept --artifact together with --hunt-id.")
    if not getattr(args, "hunt_id", None) and not getattr(args, "profile", None) and not selected_artifact:
        raise RuntimeError(f"Pass --hunt-id, --profile, or exactly one --artifact to {command_name}.")

    saved_state: dict[str, Any] | None = None
    baseline_snapshot: dict[str, Any] | None = None
    if getattr(args, "hunt_id", None):
        state_path = find_saved_state_by_hunt_id(args.investigation_id, args.hunt_id)
        if state_path is not None:
            saved_state = read_json(state_path)
            saved_state.setdefault("target_os", target_os_from_state_path(state_path) or "")
        hunt_id = str(args.hunt_id)
        hunt_row = query_single_hunt(api, hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        requested_target_os = normalize_target_os(args.os)
        saved_target_os = normalize_target_os((saved_state or {}).get("target_os"))
        hunt_row_target_os = hunt_target_os(hunt_row)
        comparable_target_os = saved_target_os or hunt_row_target_os
        if requested_target_os and comparable_target_os and requested_target_os != comparable_target_os:
            raise RuntimeError(
                f"{command_name} target mismatch: hunt {hunt_id} uses local/server target "
                f"{comparable_target_os}, but this wrapper requested {requested_target_os}."
            )
        request = resolve_request_from_state(saved_state) if saved_state else resolve_request_from_hunt_row(hunt_row)
        profile = str(saved_state.get("profile") or hunt_id) if saved_state else str(hunt_id)
        baseline_snapshot = load_baseline_snapshot(
            saved_state,
            args.investigation_id,
            hunt_id,
            saved_target_os or hunt_row_target_os,
        )
        return {
            "selected_artifact": selected_artifact,
            "saved_state": saved_state,
            "baseline_snapshot": baseline_snapshot,
            "hunt_id": hunt_id,
            "request": request,
            "profile": profile,
            "hunt_row": hunt_row,
        }

    require_saved_profile_artifact(getattr(args, "profile", None), selected_artifact)
    saved_state = load_saved_state(
        args.investigation_id,
        None,
        getattr(args, "profile", None),
        selected_artifact[0] if selected_artifact else None,
        target_os=args.os,
    )
    request = resolve_request_from_state(saved_state)
    hunt_id = str(saved_state["hunt_id"])
    profile = str(saved_state["profile"])
    baseline_snapshot = load_baseline_snapshot(
        saved_state,
        args.investigation_id,
        hunt_id,
        str(saved_state.get("target_os") or current_target_os()),
    )
    return {
        "selected_artifact": selected_artifact,
        "saved_state": saved_state,
        "baseline_snapshot": baseline_snapshot,
        "hunt_id": hunt_id,
        "request": request,
        "profile": profile,
        "hunt_row": None,
    }


def explicit_extraction_required_payload() -> dict[str, Any]:
    return {
        "exported_after_action": False,
        "export_skipped_reason": "explicit_commands_required",
        "export_manifest_file": "",
        "exported_files": [],
        "downloaded_after_action": False,
        "download_manifest_file": "",
        "downloaded_files": [],
    }


def export_action_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "exported_after_action": True,
        "export_manifest_file": manifest["manifest_file"],
        "exported_files": manifest["exported_files"],
        "latest_export_manifest_file": manifest["manifest_file"],
        "latest_exported_files": manifest["exported_files"],
        "downloaded_after_action": False,
        "download_manifest_file": "",
        "downloaded_files": [],
    }


def download_action_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "exported_after_action": False,
        "export_manifest_file": "",
        "exported_files": [],
        "downloaded_after_action": True,
        "download_manifest_file": manifest["manifest_file"],
        "downloaded_files": manifest["downloaded_files"],
        "latest_download_manifest_file": manifest["manifest_file"],
        "latest_downloaded_files": manifest["downloaded_files"],
    }


def review_action_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "reviewed_after_action": True,
        "review_manifest_file": manifest["manifest_file"],
        "reviewed_files": manifest["reviewed_files"],
        "latest_review_manifest_file": manifest["manifest_file"],
        "latest_reviewed_files": manifest["reviewed_files"],
    }


def refresh_hunt_status(
    api: Any,
    hunt_id: str,
    *,
    baseline_snapshot: dict[str, Any] | None = None,
    hunt_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if hunt_row is not None:
        if str(hunt_row.get("hunt_id") or hunt_row.get("HuntId") or "") != hunt_id:
            raise ValueError("Supplied hunt metadata belongs to a different hunt.")
        hunt_row = dict(hunt_row)
    else:
        hunt_row = query_single_hunt(api, hunt_id)
    if hunt_row is None:
        raise RuntimeError(f"Hunt {hunt_id} was not found.")
    summary = hunt_summary_from_row(hunt_row)
    flows = query_hunt_flows(api, hunt_id)
    summary.update(
        summary_from_hunt_flows(
            flows,
            baseline_client_ids=baseline_client_ids(baseline_snapshot) if baseline_snapshot is not None else None,
        )
    )
    summary["flows_sample"] = flows[:20]
    summary["is_open"] = summary["state"] in OPEN_HUNT_STATES
    summary["is_paused"] = summary["state"] in PAUSED_HUNT_STATES
    return summary


def baseline_and_readiness_payload(
    hunt_summary: dict[str, Any],
    baseline_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    return evaluate_hunt_readiness(hunt_summary, baseline_snapshot)


def walk_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(walk_strings(item))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            values.append(str(key))
            values.extend(walk_strings(item))
        return values
    return [str(value)]


def normalize_windows_text(value: str) -> str:
    return value.replace("/", "\\").lower()


def extract_host(row: dict[str, Any]) -> str:
    for key in HOST_KEYS:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def extract_client_id(row: dict[str, Any]) -> str:
    for key in CLIENT_KEYS:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def row_matches(
    row: dict[str, Any],
    literal_patterns: list[str],
    exact_paths: list[str],
    case_sensitive: bool,
) -> tuple[list[str], list[str]]:
    values = walk_strings(row)
    matched_literals: list[str] = []
    matched_paths: list[str] = []

    if literal_patterns:
        haystacks = values if case_sensitive else [value.lower() for value in values]
        for pattern in literal_patterns:
            candidate = pattern if case_sensitive else pattern.lower()
            if any(candidate in haystack for haystack in haystacks):
                matched_literals.append(pattern)

    if exact_paths:
        normalized_values = [normalize_windows_text(value) for value in values]
        for exact_path in exact_paths:
            normalized_exact_path = normalize_windows_text(exact_path)
            if any(normalized_exact_path == value for value in normalized_values):
                matched_paths.append(exact_path)

    return matched_literals, matched_paths


def search_hunt(api: Any, hunt_id: str, request: Any, args: argparse.Namespace) -> dict[str, Any]:
    artifact_filter = set(args.artifact or [])
    matches: list[dict[str, Any]] = []

    for expected in request.expected_specs:
        if artifact_filter and expected.label not in artifact_filter and expected.artifact not in artifact_filter:
            continue
        rows = query_hunt_results(api, hunt_id, expected.artifact)
        for row in rows:
            matched_literals, matched_paths = row_matches(row, args.pattern, args.exact_path, args.case_sensitive)
            if not matched_literals and not matched_paths:
                continue
            matches.append(
                {
                    "artifact": expected.label,
                    "artifact_name": expected.artifact,
                    "host": extract_host(row),
                    "client_id": extract_client_id(row),
                    "matched_literals": matched_literals,
                    "matched_exact_paths": matched_paths,
                    "row": row,
                }
            )
            if args.limit and len(matches) >= args.limit:
                break
        if args.limit and len(matches) >= args.limit:
            break

    hosts_with_hits = sorted({item["host"] for item in matches if item["host"]})
    return {
        "hunt_id": hunt_id,
        "searched_artifacts": [
            expected.label
            for expected in request.expected_specs
            if not artifact_filter or expected.label in artifact_filter or expected.artifact in artifact_filter
        ],
        "pattern": args.pattern,
        "exact_path": args.exact_path,
        "case_sensitive": args.case_sensitive,
        "match_count": len(matches),
        "hosts_with_hits": hosts_with_hits,
        "matches": matches,
    }


def command_profiles() -> dict[str, Any]:
    profiles: list[dict[str, Any]] = []
    for name, config in sorted(HUNT_PROFILES.items()):
        request = build_request_for_profile(name, validate_target=False)
        profiles.append(
            {
                "profile": name,
                "description": config["description"],
                "target_collection_type": request.target_collection_type,
                "requested_groups": request.requested_groups,
                "requested_artifacts": request.requested_artifacts,
                "expected_spec_arguments": collection.serialize_specs(request.expected_specs),
                "requires_explicit_artifact_selection": (
                    len(request.expected_specs) != 1 and not profile_allows_multi_artifact_hunt(name)
                ),
            }
        )
    return {"profiles": profiles}


def command_lookup(args: argparse.Namespace) -> dict[str, Any]:
    if not args.artifact and not args.artifact_regex:
        raise RuntimeError("Pass at least one --artifact or --artifact-regex value.")

    target_os = normalize_target_os(getattr(args, "target", "") or getattr(args, "os", ""))
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        rows = query_hunts(api)

    matches: list[dict[str, Any]] = []
    for row in rows:
        if target_os and hunt_target_os(row) != target_os:
            continue
        is_match, matched_artifacts = artifact_filters_match(row, args.artifact or [], args.artifact_regex)
        if not is_match:
            continue
        summary = hunt_summary_from_row(row)
        summary["matched_artifacts"] = matched_artifacts
        summary["all_artifact_names"] = hunt_artifact_names(row)
        matches.append(summary)
        if args.limit and len(matches) >= args.limit:
            break

    return {
        "action": "looked_up_hunts_by_artifact",
        "target_os": target_os,
        "target_namespace": target_namespace(target_os),
        "artifact_filters": args.artifact or [],
        "artifact_regex": args.artifact_regex,
        "match_count": len(matches),
        "hunts": matches,
    }


def command_check(args: argparse.Namespace) -> dict[str, Any]:
    request = build_request_from_args(args)
    target_name = target_name_from_args(args, request)
    target_os = normalize_target_os(args.os)
    include_labels = unique_ordered((args.include_label or []) + (args.label or []) + (args.host_label or []))
    exclude_labels = unique_ordered((args.exclude_label or []) + (args.exclude_host_label or []))
    requested_scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    identity = hunt_run_identity(
        request,
        target_os,
        include_labels,
        exclude_labels,
    )
    near_match_mismatches: list[dict[str, Any]] = []

    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        matches = find_matching_hunts(
            api,
            args.investigation_id,
            target_name,
            request,
            target_os,
            include_labels,
            exclude_labels,
            str(getattr(args, "group", "") or ""),
            mismatch_sink=near_match_mismatches,
        )
        selection = hunt_selection_decision(matches)
        best_match = selection["selected_candidate"]
        best_status = refresh_hunt_status(api, str(best_match["hunt_id"])) if best_match else None

    best_classification = str((best_match or {}).get("reuse_classification") or "no_exact_match")
    reuse_decision = str(selection["selection_decision"])
    reuse_reason = str(selection["selection_reason"])
    best_output = ({**best_match, **best_status} if best_match and best_status else best_match)

    payload = {
        "action": "checked_existing_hunts",
        "discovery_scope": "all_server_hunts_containing_requested_artifacts",
        "discovery_count": selection["discovery_count"],
        "candidate_classification_counts": selection["candidate_classification_counts"],
        "matching_hunt_count": len(matches),
        "matching_hunts": matches[:10],
        "best_match": best_output,
        "best_match_can_activate": bool(
            best_output
            and best_output.get("is_paused")
            and best_output.get("reuse_allowed")
        ),
        "recommended_template": selection["recommended_template"],
        "selection_decision": selection["selection_decision"],
        "selection_reason": selection["selection_reason"],
        "human_summary": selection["human_summary"],
        "run_identity": identity["identity"],
        "run_identity_sha256": identity["sha256"],
        "reuse_classification": best_classification,
        "reuse_decision": reuse_decision,
        "reuse_reason": reuse_reason,
        "near_match_mismatches": near_match_mismatches,
        "request_signature": request_signature(request, target_os, include_labels, exclude_labels),
        "target_os": target_os,
        "target_namespace": target_namespace(target_os),
        "server_target_os": requested_scope.server_os,
        "target_scope_mode": requested_scope.mode,
        "host_include_labels": include_labels,
        "host_exclude_labels": exclude_labels,
        "target_name": target_name,
        "group": str(getattr(args, "group", "") or ""),
    }
    if best_output is None:
        payload["best_match"] = None
        payload["best_match_can_activate"] = False
        payload["hunt_id"] = ""
        payload["hunt_description"] = ""
        return remove_heavy_hunt_output_fields(payload)

    payload["hunt_id"] = best_output["hunt_id"]
    payload["hunt_description"] = best_output["hunt_description"]
    return remove_heavy_hunt_output_fields(payload)


def command_ensure(args: argparse.Namespace) -> dict[str, Any]:
    request = build_request_from_args(args)
    target_name = target_name_from_args(args, request)
    target_os = normalize_target_os(args.os)
    include_labels = unique_ordered((args.include_label or []) + (args.label or []) + (args.host_label or []))
    exclude_labels = unique_ordered((args.exclude_label or []) + (args.exclude_host_label or []))
    hunt_tags = unique_ordered((args.hunt_tag or []) + (args.hunt_label or []))
    activate_paused = bool(getattr(args, "activate_paused", False))
    authorize_template_create = bool(getattr(args, "authorize_template_create", False))
    requested_scope = resolve_hunt_target_scope(target_os, include_labels, exclude_labels)
    identity = hunt_run_identity(
        request,
        target_os,
        include_labels,
        exclude_labels,
    )
    near_match_mismatches: list[dict[str, Any]] = []

    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        matches = find_matching_hunts(
            api,
            args.investigation_id,
            target_name,
            request,
            target_os,
            include_labels,
            exclude_labels,
            str(getattr(args, "group", "") or ""),
            mismatch_sink=near_match_mismatches,
        )
        selection = hunt_selection_decision(matches)
        exact_matches = list(selection["exact_compatible_candidates"])
        reusable_matches = list(selection["reusable_exact_candidates"])
        if (
            selection["selection_decision"] == "template_authorization_required"
            and not authorize_template_create
        ):
            payload = {
                "action": "template_authorization_required",
                "mutation_performed": False,
                "discovery_scope": "all_server_hunts_containing_requested_artifacts",
                "discovery_count": selection["discovery_count"],
                "candidate_classification_counts": selection["candidate_classification_counts"],
                "matching_hunt_count": len(matches),
                "matching_hunts": matches[:10],
                "recommended_template": selection["recommended_template"],
                "selection_decision": selection["selection_decision"],
                "selection_reason": selection["selection_reason"],
                "human_summary": selection["human_summary"],
                "reuse_decision": selection["selection_decision"],
                "reuse_reason": selection["selection_reason"],
                "run_identity": identity["identity"],
                "run_identity_sha256": identity["sha256"],
                "near_match_mismatches": near_match_mismatches,
                "template_create_authorized": False,
                "force_run_requested": bool(args.force_run),
                "target_os": target_os,
                "target_namespace": requested_scope.namespace,
                "server_target_os": requested_scope.server_os,
                "target_scope_mode": requested_scope.mode,
                "host_include_labels": include_labels,
                "host_exclude_labels": exclude_labels,
                "target_name": target_name,
                "group": str(getattr(args, "group", "") or ""),
            }
            payload = remove_heavy_hunt_output_fields(payload)
            payload["output_mode"] = "slim"
            payload["suppressed_output_fields"] = sorted(SLIM_ENSURE_OUTPUT_OMIT_KEYS)
            return payload
        reused_existing = bool(reusable_matches and not args.force_run)
        if reused_existing:
            selected_match = reusable_matches[0]
            hunt_id = str(selected_match["hunt_id"])
            action = "reused_existing_hunt"
            created_paused_for_validation = False
        else:
            if exact_matches and not args.force_run:
                details = "; ".join(
                    f"{item['hunt_id']} is {item['state'] or 'UNKNOWN'}"
                    for item in exact_matches[:5]
                )
                raise RuntimeError(
                    "Exact prior hunt(s) exist but none are reusable because "
                    f"they failed, were cancelled/stopped, or have unknown state: {details}. "
                    "Pass --force-run to create a fresh hunt."
                )
            created = create_hunt(
                api,
                args.investigation_id,
                target_name,
                request,
                target_os,
                include_labels,
                exclude_labels,
                hunt_tags,
                args.start_paused,
            )
            hunt_id = created["hunt_id"]
            action = (
                "forced_new_hunt"
                if args.force_run
                else "created_new_hunt"
            )
            created_paused_for_validation = bool(created.get("created_paused_for_validation"))

        hunt_status = refresh_hunt_status(api, hunt_id)
        raise_for_hunt_validation_errors(hunt_status, request)
        raise_for_hunt_scope_validation_errors(hunt_status, requested_scope)
        activated_paused_hunt = False
        baseline_action = action
        if reused_existing and activate_paused and hunt_status["state"] in PAUSED_HUNT_STATES:
            baseline_action = "activated_paused_hunt"
        baseline_snapshot = prepare_baseline_snapshot(
            api,
            args.investigation_id,
            hunt_id,
            target_os,
            include_labels,
            exclude_labels,
            action=baseline_action,
        )
        if reused_existing and activate_paused and hunt_status["state"] in PAUSED_HUNT_STATES:
            start_hunt(api, hunt_id)
            hunt_status = refresh_hunt_status(api, hunt_id)
            action = "activated_paused_hunt"
            activated_paused_hunt = True
        if action in {"created_new_hunt", "forced_new_hunt"} and created_paused_for_validation and not args.start_paused:
            start_hunt(api, hunt_id)
            hunt_status = refresh_hunt_status(api, hunt_id)
        hunt_status = refresh_hunt_status(api, hunt_id, baseline_snapshot=baseline_snapshot)
        readiness_payload = baseline_and_readiness_payload(hunt_status, baseline_snapshot)

    payload = {
        "action": action,
        "hunt_id": hunt_status["hunt_id"],
        "hunt_description": hunt_status["hunt_description"],
        "discovery_scope": "all_server_hunts_containing_requested_artifacts",
        "discovery_count": selection["discovery_count"],
        "candidate_classification_counts": selection["candidate_classification_counts"],
        "matching_hunt_count": len(matches),
        "matching_hunts": matches[:10],
        "recommended_template": selection["recommended_template"],
        "selection_decision": (
            "authorized_template_create"
            if authorize_template_create
            and selection["selection_decision"] == "template_authorization_required"
            else selection["selection_decision"]
        ),
        "selection_reason": selection["selection_reason"],
        "human_summary": (
            f"Created current-case hunt {hunt_status['hunt_id']} after explicit template authorization; "
            "the source template was not mutated and its results were not reused."
            if authorize_template_create
            and selection["selection_decision"] == "template_authorization_required"
            else selection["human_summary"]
        ),
        "run_identity": identity["identity"],
        "run_identity_sha256": identity["sha256"],
        "reuse_classification": (
            str(
                (reusable_matches[0] if reused_existing else matches[0]).get(
                    "reuse_classification"
                )
                or ""
            )
            if exact_matches
            else "no_exact_match"
        ),
        "reuse_decision": (
            "forced_new_hunt"
            if args.force_run
            else (
                "reused_exact_hunt"
                if reused_existing
                else "created_missing_exact_hunt"
            )
        ),
        "reuse_reason": (
            "force-run requested; exact prior matches were deliberately bypassed"
            if args.force_run
            else (
                "reused the highest-ranked terminal-success or in-flight exact match"
                if reused_existing
                else (
                    "explicit template authorization allowed a new current-case hunt; "
                    "the template remained reference-only"
                    if authorize_template_create and selection["recommended_template"]
                    else "no reusable exact current-case hunt matched the request"
                )
            )
        ),
        "near_match_mismatches": near_match_mismatches,
        "force_run_requested": bool(args.force_run),
        "template_create_authorized": authorize_template_create,
        **hunt_status,
        "target_os": target_os,
        "target_namespace": requested_scope.namespace,
        "server_target_os": requested_scope.server_os,
        "target_scope_mode": requested_scope.mode,
        "host_include_labels": include_labels,
        "host_exclude_labels": exclude_labels,
        "hunt_tags": hunt_tags,
        "activate_paused": activate_paused,
        "activated_paused_hunt": activated_paused_hunt,
        "request_signature": request_signature(request, target_os, include_labels, exclude_labels),
        "target_name": target_name,
        "group": str(getattr(args, "group", "") or ""),
        "question": str(getattr(args, "question", "") or ""),
        **readiness_payload,
        **explicit_extraction_required_payload(),
    }
    state = persist_state(args.investigation_id, target_name, request, hunt_status, payload)
    if getattr(args, "verbose_output", False):
        return state
    return slim_ensure_output(state)


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        resolved = resolve_saved_or_explicit_hunt(args, api, command_name="status")
        saved_state = resolved["saved_state"]
        baseline_snapshot = resolved["baseline_snapshot"]
        hunt_id = str(resolved["hunt_id"])
        request = resolved["request"]
        profile = str(resolved["profile"])
        hunt_status = refresh_hunt_status(api, hunt_id, baseline_snapshot=baseline_snapshot)
        raise_for_hunt_validation_errors(hunt_status, request)
        readiness_payload = baseline_and_readiness_payload(hunt_status, baseline_snapshot)

    payload = {
        "action": "refreshed_hunt_status",
        "hunt_id": hunt_status["hunt_id"],
        "hunt_description": hunt_status["hunt_description"],
        **hunt_status,
        **readiness_payload,
        **explicit_extraction_required_payload(),
    }
    if args.hunt_id:
        payload["target_name"] = profile
        if saved_state:
            payload["saved_state_updated"] = True
            return persist_state(
                args.investigation_id,
                str(saved_state.get("profile") or profile),
                request,
                hunt_status,
                payload,
                existing_state=saved_state,
                update_current_pointer=False,
            )
        payload["saved_state_updated"] = False
        return payload
    return persist_state(
        args.investigation_id,
        profile,
        request,
        hunt_status,
        payload,
        existing_state=saved_state,
    )


def slim_stop_output(state: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "action",
        "hunt_id",
        "hunt_description",
        "state",
        "is_open",
        "is_paused",
        "stop_requested",
        "stop_verified",
        "target_os",
        "server_target_os",
        "target_scope_mode",
        "host_include_labels",
        "host_exclude_labels",
        "scheduled_client_count",
        "responded_client_count",
        "terminal_client_count",
        "completed_client_count",
        "failed_client_count",
        "state_file",
        "saved_state_updated",
    )
    return {
        key: state[key]
        for key in keys
        if key in state
    }


def command_stop(args: argparse.Namespace) -> dict[str, Any]:
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        saved_state_path = find_saved_state_by_hunt_id(args.investigation_id, args.hunt_id)
        saved_state = read_json(saved_state_path) if saved_state_path is not None else None
        if saved_state is not None:
            saved_state.setdefault("target_os", target_os_from_state_path(saved_state_path) or "")

        hunt_row = query_single_hunt(api, args.hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {args.hunt_id} was not found.")
        request = resolve_request_from_state(saved_state) if saved_state else resolve_request_from_hunt_row(hunt_row)
        local_target_os = normalize_target_os((saved_state or {}).get("target_os") or hunt_target_os(hunt_row))
        baseline_snapshot = load_baseline_snapshot(
            saved_state,
            args.investigation_id,
            args.hunt_id,
            local_target_os,
        )
        initial_state = normalize_hunt_state(hunt_row.get("state"))
        stop_requested = initial_state != "STOPPED"
        if stop_requested:
            stop_hunt(api, args.hunt_id)
        hunt_status = refresh_hunt_status(api, args.hunt_id, baseline_snapshot=baseline_snapshot)
        if hunt_status["state"] != "STOPPED":
            raise RuntimeError(
                f"Stop verification failed for hunt {args.hunt_id}: "
                f"server state is {hunt_status['state'] or '<unknown>'}."
            )
        readiness_payload = baseline_and_readiness_payload(hunt_status, baseline_snapshot)

    payload = {
        "action": "stopped_hunt" if stop_requested else "hunt_already_stopped",
        **hunt_status,
        "target_os": local_target_os,
        "server_target_os": hunt_target_os(hunt_row),
        "stop_requested": stop_requested,
        "stop_verified": True,
        **readiness_payload,
    }
    if saved_state:
        payload["saved_state_updated"] = True
        state = persist_state(
            args.investigation_id,
            str(saved_state.get("profile") or args.hunt_id),
            request,
            hunt_status,
            payload,
            existing_state=saved_state,
            update_current_pointer=False,
        )
        return slim_stop_output(state)
    payload["saved_state_updated"] = False
    return slim_stop_output(payload)


def command_export_results(args: argparse.Namespace) -> dict[str, Any]:
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        resolved = resolve_saved_or_explicit_hunt(args, api, command_name="export-results")
        saved_state = resolved["saved_state"]
        hunt_id = str(resolved["hunt_id"])
        request = resolved["request"]
        profile = str(resolved["profile"])
        hunt_row = resolved["hunt_row"] or query_single_hunt(api, hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        raise_for_hunt_validation_errors(hunt_row, request)
        manifest = export_hunt(
            api,
            args.investigation_id,
            hunt_id,
            request,
            target_os=str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
            artifact_sources=hunt_result_artifact_sources(hunt_row),
        )

    payload = {
        "action": "exported_hunt_results",
        "hunt_id": hunt_id,
        "hunt_description": str(hunt_row.get("hunt_description") or ""),
        **export_action_payload(manifest),
    }
    if args.hunt_id:
        payload["target_name"] = profile
        if saved_state:
            payload["saved_state_updated"] = True
            return persist_state(
                args.investigation_id,
                str(saved_state.get("profile") or profile),
                request,
                {
                    "hunt_id": hunt_id,
                    "hunt_description": str(hunt_row.get("hunt_description") or ""),
                    "target_os": str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
                },
                payload,
                existing_state=saved_state,
                update_current_pointer=False,
            )
        payload["saved_state_updated"] = False
        return payload
    return persist_state(
        args.investigation_id,
        profile,
        request,
        {
            "hunt_id": hunt_id,
            "hunt_description": str(hunt_row.get("hunt_description") or ""),
            "target_os": str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
        },
        payload,
        existing_state=saved_state,
    )


def command_download_results(args: argparse.Namespace) -> dict[str, Any]:
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        resolved = resolve_saved_or_explicit_hunt(args, api, command_name="download-results")
        saved_state = resolved["saved_state"]
        hunt_id = str(resolved["hunt_id"])
        request = resolved["request"]
        profile = str(resolved["profile"])
        hunt_row = resolved["hunt_row"] or query_single_hunt(api, hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        raise_for_hunt_validation_errors(hunt_row, request)
        manifest = download_hunt_results(
            api,
            args.investigation_id,
            hunt_id,
            request,
            target_os=str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
            artifact_sources=hunt_result_artifact_sources(hunt_row),
        )

    payload = {
        "action": "downloaded_hunt_results",
        "hunt_id": hunt_id,
        "hunt_description": str(hunt_row.get("hunt_description") or ""),
        **download_action_payload(manifest),
    }
    if args.hunt_id:
        payload["target_name"] = profile
        if saved_state:
            payload["saved_state_updated"] = True
            return persist_state(
                args.investigation_id,
                str(saved_state.get("profile") or profile),
                request,
                {
                    "hunt_id": hunt_id,
                    "hunt_description": str(hunt_row.get("hunt_description") or ""),
                    "target_os": str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
                },
                payload,
                existing_state=saved_state,
                update_current_pointer=False,
            )
        payload["saved_state_updated"] = False
        return payload
    return persist_state(
        args.investigation_id,
        profile,
        request,
        {
            "hunt_id": hunt_id,
            "hunt_description": str(hunt_row.get("hunt_description") or ""),
            "target_os": str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os()),
        },
        payload,
        existing_state=saved_state,
    )


def command_review_results(args: argparse.Namespace) -> dict[str, Any]:
    resolved_policy = artifact_policy.load_artifact_policy(
        list(getattr(args, "artifact_reference", []) or [])
    )
    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        resolved = resolve_saved_or_explicit_hunt(args, api, command_name="review-results")
        saved_state = resolved["saved_state"]
        hunt_id = str(resolved["hunt_id"])
        request = resolved["request"]
        profile = str(resolved["profile"])
        hunt_row = resolved["hunt_row"] or query_single_hunt(api, hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        raise_for_hunt_validation_errors(hunt_row, request)
        target_os = str((saved_state or {}).get("target_os") or hunt_target_os(hunt_row) or current_target_os())
        manifest = review_hunt_results(
            api,
            args.investigation_id,
            hunt_id,
            request,
            target_os=target_os,
            operation=args.review_operation,
            field_profile=args.field_profile,
            fields=list(args.field or []),
            group_by=list(args.group_by or []),
            inventory_group_by=list(args.inventory_group_by or []),
            where=args.where,
            source=args.source,
            limit=effective_review_limit(args),
            output_format=args.format,
            inventory_mode=args.inventory_mode,
            max_row=args.max_row,
            timeout=args.timeout,
            policy_snapshot=resolved_policy,
            stack_id=getattr(args, "stack_id", None),
        )

    payload = {
        "action": "reviewed_hunt_results",
        "hunt_id": hunt_id,
        "hunt_description": str(hunt_row.get("hunt_description") or ""),
        **review_action_payload(manifest),
    }
    if args.hunt_id:
        payload["target_name"] = profile
        if saved_state:
            payload["saved_state_updated"] = True
            return persist_state(
                args.investigation_id,
                str(saved_state.get("profile") or profile),
                request,
                {
                    "hunt_id": hunt_id,
                    "hunt_description": str(hunt_row.get("hunt_description") or ""),
                    "target_os": target_os,
                },
                payload,
                existing_state=saved_state,
                update_current_pointer=False,
            )
        payload["saved_state_updated"] = False
        return payload
    return persist_state(
        args.investigation_id,
        profile,
        request,
        {
            "hunt_id": hunt_id,
            "hunt_description": str(hunt_row.get("hunt_description") or ""),
            "target_os": target_os,
        },
        payload,
        existing_state=saved_state,
    )


def command_search(args: argparse.Namespace) -> dict[str, Any]:
    if not args.pattern and not args.exact_path:
        raise RuntimeError("At least one --pattern or --exact-path value is required.")

    saved_state: dict[str, Any] | None = None
    if args.hunt_id:
        selected_artifact = artifact_selector_values(args)
        with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
            hunt_row = query_single_hunt(api, args.hunt_id)
            if hunt_row is None:
                raise RuntimeError(f"Hunt {args.hunt_id} was not found.")
            state_path = find_saved_state_by_hunt_id(args.investigation_id, args.hunt_id)
            if state_path is not None:
                saved_state = read_json(state_path)
                saved_state.setdefault("target_os", target_os_from_state_path(state_path) or "")
            requested_target_os = normalize_target_os(args.os)
            saved_target_os = normalize_target_os((saved_state or {}).get("target_os"))
            hunt_row_target_os = hunt_target_os(hunt_row)
            comparable_target_os = saved_target_os or hunt_row_target_os
            if requested_target_os and comparable_target_os and requested_target_os != comparable_target_os:
                raise RuntimeError(
                    f"search target mismatch: hunt {args.hunt_id} uses local/server target "
                    f"{comparable_target_os}, but this wrapper requested {requested_target_os}."
                )
            request = resolve_request_from_hunt_row(hunt_row)
        hunt_id = str(args.hunt_id)
        profile = str(saved_state.get("profile") or hunt_id) if saved_state else str(hunt_id)
    elif args.profile:
        selected_artifact = artifact_selector_values(args)
        if len(selected_artifact) > 1:
            raise RuntimeError("Pass at most one --artifact value with --profile when loading saved hunt state.")
        require_saved_profile_artifact(args.profile, selected_artifact)
        saved_state = load_saved_state(
            args.investigation_id,
            None,
            args.profile,
            selected_artifact[0] if selected_artifact else None,
            target_os=args.os,
        )
        request = resolve_request_from_state(saved_state)
        hunt_id = str(saved_state["hunt_id"])
        profile = str(saved_state["profile"])
    else:
        request = build_request_from_args(args)
        profile = target_name_from_args(args, request)
        target_os = normalize_target_os(args.os)
        include_labels = unique_ordered((args.include_label or []) + (args.label or []) + (args.host_label or []))
        exclude_labels = unique_ordered((args.exclude_label or []) + (args.exclude_host_label or []))
        with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
            matches = find_matching_hunts(
                api,
                args.investigation_id,
                profile,
                request,
                target_os,
                include_labels,
                exclude_labels,
            )
        reusable_matches = [item for item in matches if bool(item.get("reuse_allowed"))]
        if not reusable_matches:
            template_matches = [item for item in matches if bool(item.get("template_only"))]
            if template_matches:
                raise RuntimeError(
                    "No reusable current-engagement hunt was found. Compatible template "
                    f"{template_matches[0]['hunt_id']} is reference-only; its results cannot "
                    "be searched as current-engagement evidence."
                )
            raise RuntimeError("No reusable current-engagement hunt was found for the requested profile.")
        hunt_id = str(reusable_matches[0]["hunt_id"])

    with collection.VeloApiClient(args.api_client_path, org_id=args.org_id) as api:
        hunt_row = query_single_hunt(api, hunt_id)
        if hunt_row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        raise_for_hunt_validation_errors(hunt_row, request)
        payload = search_hunt(api, hunt_id, request, args)

    state_payload = {
        "action": "searched_hunt_results",
        "hunt_id": hunt_id,
        "hunt_description": str(hunt_row.get("hunt_description") or ""),
        **explicit_extraction_required_payload(),
        **payload,
    }
    if args.hunt_id:
        state_payload["saved_state_updated"] = False
        state_payload["target_name"] = profile
        return state_payload
    return persist_state(
        args.investigation_id,
        profile,
        request,
        {
            "hunt_id": hunt_id,
            "hunt_description": str(hunt_row.get("hunt_description") or ""),
        },
        state_payload,
        existing_state=saved_state,
    )
def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--api-client",
        help=(
            "Explicit Velociraptor API config override. Otherwise the "
            "schema-v5 engagement server profile selects the cached config."
        ),
    )
    parser.add_argument(
        "--org-id",
        help="Velociraptor org id to use. Defaults to root, with orgs/<id> as a compatibility fallback.",
    )
    parser.add_argument(
        "--server-profile",
        help="Velociraptor instance profile. Required when --engagement-id is omitted.",
    )


def add_hunt_scope_args(
    parser: argparse.ArgumentParser,
    *,
    require_profile: bool = True,
    include_env: bool = True,
    include_hunt_tags: bool = True,
) -> None:
    parser.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(parser)
    parser.add_argument(
        "--profile",
        required=require_profile,
        choices=sorted(HUNT_PROFILES),
        help="Named hunt profile to use.",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help=(
            "Exact artifact to hunt. When used with --profile, selects one artifact "
            "from that profile."
        ),
    )
    parser.add_argument(
        "--group",
        help="Optional server-discoverable group identifier written into the hunt description.",
    )
    parser.add_argument(
        "--question",
        help="Optional bounded analyst question written into the hunt description.",
    )
    if include_env:
        parser.add_argument(
            "--env",
            action="append",
            default=[],
            help="Artifact variable in KEY=VALUE form. Requires exactly one resolved artifact when used.",
        )
    parser.add_argument(
        "--date-after",
        help=(
            "Optional UTC lower bound to merge into requested artifacts that support "
            "DateAfter, for example 2026-05-16T23:00:00Z."
        ),
    )
    parser.add_argument(
        "--date-before",
        help=(
            "Optional UTC upper bound to merge into requested artifacts that support "
            "DateBefore, for example 2026-05-17T09:00:00Z."
        ),
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Alias for --host-label. Target only clients carrying these labels.",
    )
    parser.add_argument(
        "--host-label",
        action="append",
        default=[],
        help="Target only clients carrying these Velociraptor host labels. Repeat as needed.",
    )
    parser.add_argument(
        "--include-label",
        action="append",
        default=[],
        help="Alias for --host-label.",
    )
    parser.add_argument(
        "--exclude-label",
        action="append",
        default=[],
        help="Alias for --exclude-host-label.",
    )
    parser.add_argument(
        "--exclude-host-label",
        action="append",
        default=[],
        help="Exclude clients with these Velociraptor host labels. Repeat as needed.",
    )
    if include_hunt_tags:
        parser.add_argument(
            "--hunt-tag",
            action="append",
            default=[],
            help="Extra metadata tag to attach to the hunt itself for later lookup and grouping.",
        )
        parser.add_argument(
            "--hunt-label",
            action="append",
            default=[],
            help="Alias for --hunt-tag when you want hunt-level grouping metadata.",
        )


def add_target_arg(parser: argparse.ArgumentParser, *, required: bool = False, expose: bool = True) -> None:
    if not expose:
        return
    parser.add_argument(
        "--target",
        choices=TARGET_CHOICES,
        required=required,
        default=None,
        help=(
            "Optional OS scope. Include labels take priority and suppress the server OS "
            "condition. When neither OS nor include labels are supplied, the hunt is unscoped."
        ),
    )


def finalize_args(args: argparse.Namespace) -> argparse.Namespace:
    global CASE_ROOT, GENERIC_HUNT_TARGET, CURRENT_HUNT_GROUP, CURRENT_HUNT_QUESTION, CURRENT_SERVER_PROFILE
    if args.command == "profiles":
        return args
    args.org_id = collection.resolve_org_id(args.org_id)
    context = engagement_context.resolve(
        repo_root=REPO_ROOT,
        engagement_id=getattr(args, "investigation_id", None),
        server_profile=getattr(args, "server_profile", None),
        api_client=getattr(args, "api_client", None),
        case_root=getattr(args, "case_root", None),
        expected_org_id=args.org_id,
    )
    args.investigation_id = context.engagement_id
    args.server_profile = context.server_profile
    args.api_client_path = context.api_client
    CASE_ROOT = context.case_root
    GENERIC_HUNT_TARGET = normalize_target_os(getattr(args, "target", "") or getattr(args, "os", ""))
    CURRENT_HUNT_GROUP = str(getattr(args, "group", "") or "").strip()
    CURRENT_HUNT_QUESTION = str(getattr(args, "question", "") or "").strip()
    CURRENT_SERVER_PROFILE = context.server_profile
    args.target = normalize_target_os(getattr(args, "target", "") or GENERIC_HUNT_TARGET)
    args.os = normalize_target_os(getattr(args, "os", "") or GENERIC_HUNT_TARGET)
    return args


def parse_args(
    argv: list[str] | None = None,
    *,
    forced_target: str | None = None,
    expose_target: bool = True,
    description: str | None = None,
    finalize: bool = True,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=description
        or "Create, reuse, inspect, export, and search native Velociraptor hunts across Windows, Linux, or macOS."
    )
    add_connection_args(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("profiles", help="List the built-in hunt profiles")

    lookup_cmd = subparsers.add_parser("lookup", help="List hunts that contain one or more requested artifacts")
    lookup_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(lookup_cmd)
    add_target_arg(lookup_cmd, expose=expose_target)
    lookup_cmd.add_argument("--artifact", action="append", default=[], help="Exact artifact label or artifact name to look for. Repeat as needed.")
    lookup_cmd.add_argument("--artifact-regex", help="Regex used to match artifact names inside existing hunts.")
    lookup_cmd.add_argument("--limit", type=int, default=50, help="Maximum number of matching hunts to return.")

    check_cmd = subparsers.add_parser("check", help="Find relevant existing hunts for a profile or explicit artifact request")
    add_hunt_scope_args(check_cmd, require_profile=False, include_hunt_tags=False)
    add_target_arg(check_cmd, expose=expose_target)

    ensure_cmd = subparsers.add_parser("ensure", help="Reuse a relevant existing hunt or create a new native hunt")
    add_hunt_scope_args(ensure_cmd, require_profile=False)
    add_target_arg(ensure_cmd, expose=expose_target)
    ensure_cmd.add_argument(
        "--force-run",
        action="store_true",
        help="Create a fresh hunt even when a matching prior hunt already exists.",
    )
    ensure_cmd.add_argument(
        "--start-paused",
        action="store_true",
        help="Create the hunt paused instead of starting it immediately.",
    )
    ensure_cmd.add_argument(
        "--activate-paused",
        action="store_true",
        help="When the best matching hunt is paused, start it instead of only reusing it as-is.",
    )
    ensure_cmd.add_argument(
        "--authorize-template-create",
        action="store_true",
        help=(
            "After reviewing a compatible generic or different-engagement template, "
            "authorize creation of a separate current-engagement hunt. The source hunt "
            "is never mutated and its results are never reused."
        ),
    )
    ensure_cmd.add_argument(
        "--no-export",
        action="store_true",
        help="Deprecated no-op. Result extraction now uses explicit export-results or download-results commands.",
    )
    ensure_cmd.add_argument(
        "--verbose-output",
        action="store_true",
        help=(
            "Print the full saved state, including Velociraptor Request/start_request "
            "details. By default ensure prints a slim operator summary and writes the "
            "complete state to state_file."
        ),
    )

    status_cmd = subparsers.add_parser("status", help="Refresh status for a saved or explicit hunt")
    status_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(status_cmd)
    add_target_arg(status_cmd, expose=expose_target)
    status_selector = status_cmd.add_mutually_exclusive_group()
    status_selector.add_argument(
        "--hunt-id",
        help="Specific hunt id to refresh. Saved state lookup scans all target namespaces for this investigation.",
    )
    status_selector.add_argument(
        "--profile",
        choices=sorted(HUNT_PROFILES),
        help="Refresh the latest saved hunt for this profile. Profiles that resolve to multiple artifacts also require --artifact.",
    )
    status_cmd.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Select one saved profile artifact with --profile, or load the current saved single-artifact hunt by artifact label.",
    )
    status_cmd.add_argument(
        "--no-export",
        action="store_true",
        help="Deprecated no-op. Result extraction now uses explicit export-results or download-results commands.",
    )

    stop_cmd = subparsers.add_parser("stop", help="Stop a specific hunt and verify the server reports STOPPED")
    stop_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(stop_cmd)
    stop_cmd.add_argument("--hunt-id", required=True, help="Specific hunt id to stop and verify.")

    export_cmd = subparsers.add_parser("export-results", help="Export hunt results into review-friendly CSV artifacts")
    export_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(export_cmd)
    add_target_arg(export_cmd, expose=expose_target)
    export_selector = export_cmd.add_mutually_exclusive_group()
    export_selector.add_argument(
        "--hunt-id",
        help="Specific hunt id to export. Saved state lookup scans all target namespaces for this investigation when available.",
    )
    export_selector.add_argument(
        "--profile",
        choices=sorted(HUNT_PROFILES),
        help="Export the current saved hunt for this profile. Profiles that resolve to multiple artifacts also require --artifact.",
    )
    export_cmd.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Select one saved profile artifact with --profile, or load the current saved single-artifact hunt by artifact label.",
    )

    download_cmd = subparsers.add_parser("download-results", help="Download raw hunt results as JSONL under the hunt downloads tree")
    download_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(download_cmd)
    add_target_arg(download_cmd, expose=expose_target)
    download_selector = download_cmd.add_mutually_exclusive_group()
    download_selector.add_argument(
        "--hunt-id",
        help="Specific hunt id to download. Saved state lookup scans all target namespaces for this investigation when available.",
    )
    download_selector.add_argument(
        "--profile",
        choices=sorted(HUNT_PROFILES),
        help="Download the current saved hunt for this profile. Profiles that resolve to multiple artifacts also require --artifact.",
    )
    download_cmd.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Select one saved profile artifact with --profile, or load the current saved single-artifact hunt by artifact label.",
    )

    review_cmd = subparsers.add_parser("review-results", help="Run server-side large-hunt review queries without full raw export")
    review_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(review_cmd)
    add_target_arg(review_cmd, expose=expose_target)
    review_selector = review_cmd.add_mutually_exclusive_group()
    review_selector.add_argument(
        "--hunt-id",
        help="Specific hunt id to review. Saved state lookup scans all target namespaces for this investigation when available.",
    )
    review_selector.add_argument(
        "--profile",
        choices=sorted(HUNT_PROFILES),
        help="Review the current saved hunt for this profile. Profiles that resolve to multiple artifacts also require --artifact.",
    )
    review_cmd.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Select one saved profile artifact with --profile, or load the current saved single-artifact hunt by artifact label.",
    )
    review_cmd.add_argument(
        "--review-operation",
        choices=("inventory", "stack", "sample"),
        default="inventory",
        help="Server-side review operation to run. Defaults to inventory.",
    )
    review_cmd.add_argument(
        "--field-profile",
        choices=("minimal", "stacking", "pivot", "full"),
        default="stacking",
        help="Field projection profile for sample mode. Defaults to stacking.",
    )
    review_cmd.add_argument(
        "--inventory-mode",
        choices=HUNT_REVIEW_INVENTORY_MODES,
        default="quick",
        help=(
            "Inventory behavior: quick runs only capped by-host stacking, exact "
            "runs only the global count(), and both runs both. Defaults to quick."
        ),
    )
    review_cmd.add_argument(
        "--field",
        action="append",
        default=[],
        help="Explicit field to project in sample mode. Repeat as needed; overrides --field-profile.",
    )
    review_cmd.add_argument(
        "--group-by",
        action="append",
        default=[],
        help="VQL expression/field for stack mode. Repeat for multi-column stacking.",
    )
    review_cmd.add_argument(
        "--stack-id",
        help=(
            "Named artifact-profile stack to use in stack mode. Defaults to the profile's "
            "default server-safe stack. Cannot be combined with --group-by."
        ),
    )
    review_cmd.add_argument(
        "--artifact-reference",
        action="append",
        default=[],
        help=(
            "Site or case artifact-reference JSON file or directory. Repeat to apply ordered overlays. "
            "When stack has no --group-by, use the profile's safe server dimensions."
        ),
    )
    review_cmd.add_argument(
        "--inventory-group-by",
        action="append",
        default=[],
        help=(
            "VQL expression/field for quick/both inventory stacking. Repeat for "
            "multi-column grouping. Defaults to ClientId, Fqdn, Hostname."
        ),
    )
    review_cmd.add_argument("--where", help="Server-side VQL WHERE expression to narrow review rows.")
    review_cmd.add_argument("--source", help="Optional hunt_results source name.")
    review_cmd.add_argument(
        "--review-depth",
        choices=tuple(HUNT_REVIEW_LIMIT_PRESETS),
        default="explore",
        help=(
            "Preset row/group cap when --limit is not supplied: "
            "explore=1000, broad=10000, deep=100000, max=1000000."
        ),
    )
    review_cmd.add_argument(
        "--limit",
        type=int,
        help=(
            "Explicit row/group cap. Overrides --review-depth. Use high values "
            "such as 10000, 100000, or 1000000 for broader review when the "
            "server can satisfy the query."
        ),
    )
    review_cmd.add_argument(
        "--format",
        choices=("csv", "jsonl"),
        default="csv",
        help="Output format for compact review files. Defaults to csv.",
    )
    review_cmd.add_argument(
        "--max-row",
        type=int,
        default=HUNT_RESULTS_BATCH_SIZE,
        help=(
            "Velociraptor gRPC response batch row target. This is not the total "
            "row cap; use --review-depth or --limit for the VQL LIMIT. Defaults "
            "to 1000."
        ),
    )
    review_cmd.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Optional server-side query timeout in seconds.",
    )

    search_cmd = subparsers.add_parser("search", help="Search current hunt results for IOC hits")
    search_cmd.add_argument("--engagement-id", "--investigation-id", "--id", dest="investigation_id", help="Case namespace. Defaults to --server-profile.")
    add_case_root_arg(search_cmd)
    add_target_arg(search_cmd, expose=expose_target)
    search_selector = search_cmd.add_mutually_exclusive_group()
    search_selector.add_argument(
        "--hunt-id",
        help="Specific hunt id to search. Saved state lookup scans all target namespaces for this investigation when available.",
    )
    search_selector.add_argument(
        "--profile",
        choices=sorted(HUNT_PROFILES),
        help="Use the latest saved hunt for this profile. Profiles that resolve to multiple artifacts also require --artifact.",
    )
    search_cmd.add_argument("--artifact", action="append", default=[], help="Limit the search to one or more artifact labels or names, or use one explicit artifact to resolve a similar hunt.")
    search_cmd.add_argument("--env", action="append", default=[], help="Artifact variable in KEY=VALUE form when resolving a similar hunt.")
    search_cmd.add_argument("--date-after", help="Optional UTC lower bound when resolving a time-bounded compatible hunt.")
    search_cmd.add_argument("--date-before", help="Optional UTC upper bound when resolving a time-bounded compatible hunt.")
    search_cmd.add_argument("--label", action="append", default=[], help="Alias for --host-label when resolving a similar hunt.")
    search_cmd.add_argument("--host-label", action="append", default=[], help="Host-label filter when resolving a similar hunt.")
    search_cmd.add_argument("--include-label", action="append", default=[], help="Alias for --host-label when resolving a similar hunt.")
    search_cmd.add_argument("--exclude-label", action="append", default=[], help="Alias for --exclude-host-label when resolving a similar hunt.")
    search_cmd.add_argument("--exclude-host-label", action="append", default=[], help="Exclude-host-label filter when resolving a similar hunt.")
    search_cmd.add_argument("--pattern", action="append", default=[], help="Literal substring to search for. Repeat for multiple values.")
    search_cmd.add_argument("--exact-path", action="append", default=[], help="Exact path string to search for after slash and case normalization. Repeat for multiple values.")
    search_cmd.add_argument("--case-sensitive", action="store_true", help="Use case-sensitive literal matching for --pattern values.")
    search_cmd.add_argument("--limit", type=int, default=500, help="Maximum number of matching rows to return.")

    args = parser.parse_args(argv)
    if forced_target:
        args.target = forced_target
        args.os = forced_target
    else:
        args.target = normalize_target_os(getattr(args, "target", ""))
        args.os = normalize_target_os(getattr(args, "os", "") or args.target)
    return finalize_args(args) if finalize else args


def main(
    argv: list[str] | None = None,
    *,
    forced_target: str | None = None,
    expose_target: bool = True,
    description: str | None = None,
) -> int:
    try:
        args = parse_args(
            argv,
            forced_target=forced_target,
            expose_target=expose_target,
            description=description,
        )
        investigation_id = str(getattr(args, "investigation_id", "") or "")
        if investigation_id:
            operation_log.bind_case(
                resolve_case_root(getattr(args, "case_root", None), REPO_ROOT),
                investigation_id,
            )
        if args.command == "profiles":
            payload = command_profiles()
        elif args.command == "lookup":
            payload = command_lookup(args)
        elif args.command == "check":
            payload = command_check(args)
        elif args.command == "ensure":
            payload = command_ensure(args)
        elif args.command == "status":
            payload = command_status(args)
        elif args.command == "stop":
            payload = command_stop(args)
        elif args.command == "export-results":
            payload = command_export_results(args)
        elif args.command == "download-results":
            payload = command_download_results(args)
        elif args.command == "review-results":
            payload = command_review_results(args)
        else:
            payload = command_search(args)
        payload.update(operation_log.correlation_metadata())
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except (RuntimeError, ValueError, OSError, collection.grpc.RpcError) as exc:
        operation_log.record_exception(exc, stage="native_hunt")
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
