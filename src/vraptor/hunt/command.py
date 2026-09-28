#!/usr/bin/env python3
from __future__ import annotations

from vraptor.analyze import prompt_debug

import argparse
import concurrent.futures
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
from vraptor.agent import diagnostics as agent_diagnostics
from vraptor.analyze import limits as analysis_limits
from vraptor.common import atomic_io
from vraptor import case_layout
from vraptor.agent.profiles import PROFILE_NAMES
from vraptor.agent.profiles import RESPONSE_DEPTH_NAMES
from vraptor.agent.profiles import load_agent_profile_config
from vraptor.agent.profiles import normalize_profile_name
from vraptor.agent.profiles import normalize_response_depth
from vraptor.common.cli_arguments import non_negative_int, positive_int as positive
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import resolve_agent_execution
from vraptor import paths as dfir_paths
from vraptor.hunt import analysis
from vraptor.hunt import operations as generic
from vraptor.collect import requests as collection
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.analyze import model_options
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.hunt import live as live_hunt_analysis
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.analyze import flow_runtime as flow_analysis_runtime
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.analyze import summary as analysis_summary
from vraptor import context as engagement_context
from vraptor.logging import operations as operation_log
from vraptor.artifacts import persistence as persistence_policy
from vraptor.common import token_budget
from vraptor.api import VeloApiClient
from vraptor.api import grpc
from vraptor.api import resolve_org_id as normalize_org_id

DEFAULT_QUERY_BATCH_ROWS = 50_000
DEFAULT_QUERY_WORKERS = 8
GRPC_TARGET_RESPONSE_BYTES = 48 * 1024 * 1024
GRPC_BATCH_SAFETY_FACTOR = 0.90
SNAPSHOT_VERSION = 3
SNAPSHOT_STATE_VERSION = 1
GROUP_PATTERN = re.compile(r"(?:^|\s)dfir-group=([^\s]+)")
GROUP_MANIFEST_VERSION = 1
RETRY_POLICY_VERSION = 1
DEFAULT_RETRY_BATCH_SIZE = 100
SELECTED_ARTIFACTS_KEY = "_dfir_selected_artifacts"
SELECTED_GROUP_KEY = "_dfir_selected_group"
DEFAULT_HUNT_ANALYSIS_QUESTION = (
    "What activity is malicious, security-relevant, or useful cross-host context?"
)
REVIEW_SCOPE_MANAGED_COLLECTION = "managed_collection"
REVIEW_SCOPE_AD_HOC = "ad_hoc_review"
REVIEW_SCOPES = {
    REVIEW_SCOPE_MANAGED_COLLECTION,
    REVIEW_SCOPE_AD_HOC,
}
LIVE_ANALYSIS_MODES = ("stream", "stack", "detectraptor-stack")
DEFAULT_LIVE_ANALYSIS_MODE = "stream"
DETECTRAPTOR_ARTIFACT_PREFIX = "detectraptor."
TASK_MODE_CHOICES = tuple(name.replace("_", "-") for name in PROFILE_NAMES)
RESPONSE_DEPTH_CHOICES = ("rapid", "standard", "deep")
AUTORUNS_ALLOWED_OPTIONS = frozenset({
    "--api-client", "--server-profile", "--org-id", "--engagement-id", "--id",
    "--investigation-id", "--case-root", "--hunt-id", "--artifact", "--profile",
    "--autoruns-golden-db", "--no-autoruns-golden-sync",
    "--query-timeout-seconds", "--format", "--no-progress",
    "--progress-interval-seconds", "--max-review-tokens", "--skip-ai",
    "--stack-max-total-rows",
}) | model_options.OPTIONS


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_task_output(args: argparse.Namespace) -> tuple[str, str]:
    requested_mode = normalize_profile_name(getattr(args, "task_mode", ""))
    stored_mode, stored_depth = stored_task_output(args)
    task_mode = requested_mode or stored_mode or "targeted_hunt"
    if task_mode not in PROFILE_NAMES:
        raise RuntimeError(f"Unknown task mode: {task_mode}")
    requested_depth = normalize_response_depth(
        getattr(args, "response_depth", "")
    )
    depth = (
        requested_depth
        or (stored_depth if not requested_mode else "")
        or load_agent_profile_config().profiles[task_mode].default_depth
    )
    if depth not in RESPONSE_DEPTH_NAMES:
        raise RuntimeError(f"Unknown response depth: {depth}")
    return task_mode, depth


def stored_task_output(args: argparse.Namespace) -> tuple[str, str]:
    """Recover persisted intent for a hunt rerun without changing precedence."""

    investigation_id = str(getattr(args, "investigation_id", "") or "").strip()
    if not investigation_id:
        return "", ""
    case_root = resolve_case_root(args)
    hunt_id = str(getattr(args, "hunt_id", "") or "").strip()
    group = str(getattr(args, "group", "") or "").strip()
    hunt_case_root = hunts_root(case_root, investigation_id)

    if hunt_id:
        state_path = hunt_case_root / hunt_id / "analysis" / "hunt-analysis-state.json"
        if state_path.is_file():
            state = generic.read_json(state_path)
            specialized = dict(state.get("specialized_analysis") or {})
            mode = normalize_profile_name(
                state.get("task_mode") or specialized.get("task_mode")
            )
            depth = normalize_response_depth(
                state.get("response_depth") or specialized.get("response_depth")
            )
            if mode or depth:
                return mode, depth

    manifests: list[dict[str, Any]] = []
    if group:
        manifest, _ = load_group_manifest(
            case_root,
            group,
            investigation_id=investigation_id,
        )
        if manifest:
            manifests.append(manifest)
    elif hunt_id:
        group_root = hunt_case_root / "groups"
        for path in sorted(group_root.glob("*.json"))[:500]:
            payload = generic.read_json(path)
            if any(
                str(item.get("hunt_id") or "") == hunt_id
                for item in payload.get("hunts") or []
                if isinstance(item, dict)
            ):
                manifests.append(payload)

    stored = {
        (
            normalize_profile_name(item.get("task_mode")),
            normalize_response_depth(item.get("response_depth")),
        )
        for item in manifests
        if item.get("task_mode") or item.get("response_depth")
    }
    if len(stored) > 1:
        raise RuntimeError(
            f"Hunt {hunt_id} has conflicting persisted task output policies. "
            "Pass --task-mode and --response-depth explicitly."
        )
    return next(iter(stored), ("", ""))


def timestamp_token() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-")
    return token or "value"


def extract_group(description: str) -> str:
    match = GROUP_PATTERN.search(str(description or ""))
    return match.group(1) if match else ""


def generate_group(profile: str | None) -> str:
    prefix = {
        "detectraptor": "DR",
        "lateral-movement": "TTP",
    }.get(str(profile or ""), "HUNT")
    return f"{prefix}-{timestamp_token()}"


def resolve_api_client(args: argparse.Namespace, investigation_id: str | None = None) -> Path:
    return dfir_paths.resolve_velociraptor_api_client_path(
        getattr(args, "api_client", None),
        REPO_ROOT,
        server_profile=getattr(args, "server_profile", None),
    )


def resolve_org_id(args: argparse.Namespace) -> str:
    return normalize_org_id(
        getattr(args, "org_id", None)
    )


def resolve_case_root(args: argparse.Namespace) -> Path:
    return dfir_paths.resolve_case_root(getattr(args, "case_root", None), REPO_ROOT)


def hunts_root(case_root: Path, investigation_id: str) -> Path:
    return case_root / investigation_id / "hunts"


def resolved_hunts_root(args: argparse.Namespace) -> Path:
    investigation_id = str(getattr(args, "investigation_id", "") or "").strip()
    if not investigation_id:
        raise RuntimeError("--id is required to resolve the case hunt directory.")
    return hunts_root(resolve_case_root(args), investigation_id)


def validate_live_engagement(args: argparse.Namespace) -> Path | None:
    """Fail closed for live server operations; explicit snapshot review is offline."""
    if getattr(args, "command", "") == "analyze" and getattr(args, "snapshot", None):
        return None
    if getattr(args, "command", "") == "retry-missing":
        # This command changes only local retry policy and performs no server query.
        investigation_id, _ = engagement_context.effective_engagement_id(
            getattr(args, "investigation_id", None),
            getattr(args, "server_profile", None),
        )
        args.investigation_id = investigation_id
        return None
    context = engagement_context.resolve(
        repo_root=REPO_ROOT,
        engagement_id=getattr(args, "investigation_id", None),
        server_profile=getattr(args, "server_profile", None),
        api_client=getattr(args, "api_client", None),
        case_root=getattr(args, "case_root", None),
        expected_org_id=resolve_org_id(args),
    )
    args.investigation_id = context.engagement_id
    args.server_profile = context.server_profile
    args.api_client = str(context.api_client)
    return context.state_path


def group_manifest_path(case_root: Path, investigation_id: str, group: str) -> Path:
    return (
        case_root
        / investigation_id
        / "hunts"
        / "groups"
        / f"{safe_token(group)}.json"
    )


def group_manifest_candidates(
    case_root: Path,
    group: str,
    *,
    investigation_id: str | None = None,
) -> list[Path]:
    token = f"{safe_token(group)}.json"
    if investigation_id:
        candidate = group_manifest_path(case_root, investigation_id, group)
        return [candidate] if candidate.is_file() else []
    return sorted(case_root.glob(f"*/hunts/groups/{token}"))


def load_group_manifest(
    case_root: Path,
    group: str,
    *,
    investigation_id: str | None = None,
) -> tuple[dict[str, Any] | None, Path | None]:
    matches: list[tuple[dict[str, Any], Path]] = []
    for path in group_manifest_candidates(
        case_root,
        group,
        investigation_id=investigation_id,
    ):
        payload = generic.read_json(path)
        if str(payload.get("group") or "") == group:
            matches.append((payload, path))
    if len(matches) > 1:
        paths = ", ".join(str(path) for _, path in matches)
        raise RuntimeError(
            f"Multiple local hunt-group manifests match {group}: {paths}. "
            "Pass a narrower --case-root or use --hunt-id."
        )
    return matches[0] if matches else (None, None)


def write_group_manifest(
    *,
    case_root: Path,
    investigation_id: str,
    group: str,
    profile: str,
    question: str,
    hunts: list[dict[str, Any]],
    task_mode: str = "targeted_hunt",
    response_depth: str = "standard",
) -> Path:
    path = group_manifest_path(case_root, investigation_id, group)
    existing = generic.read_json(path) if path.is_file() else {}
    existing_group = str(existing.get("group") or "")
    if existing_group and existing_group != group:
        raise RuntimeError(
            f"Refusing hunt-group manifest collision at {path}: "
            f"found {existing_group}, expected {group}."
        )
    timestamp = now_utc()
    payload = {
        "manifest_version": GROUP_MANIFEST_VERSION,
        "group": group,
        "investigation_id": investigation_id,
        "profile": profile,
        "question": question,
        "task_mode": normalize_profile_name(task_mode),
        "response_depth": normalize_response_depth(response_depth) or "standard",
        "created_at": str(existing.get("created_at") or timestamp),
        "updated_at": timestamp,
        "hunts": [
            {
                "artifact": str(item.get("artifact") or ""),
                "hunt_id": str(item.get("hunt_id") or ""),
                "request_signature": str(item.get("request_signature") or ""),
                "run_identity_sha256": str(
                    item.get("run_identity_sha256") or ""
                ),
                "reuse_classification": str(
                    item.get("reuse_classification") or ""
                ),
                "reuse_decision": str(
                    item.get("reuse_decision") or ""
                ),
                "reuse_reason": str(item.get("reuse_reason") or ""),
                "selection_decision": str(item.get("selection_decision") or ""),
                "selection_reason": str(item.get("selection_reason") or ""),
                "candidate_classification_counts": dict(
                    item.get("candidate_classification_counts") or {}
                ),
                "recommended_template_hunt_id": str(
                    (item.get("recommended_template") or {}).get("hunt_id") or ""
                ),
                "force_run_requested": bool(
                    item.get("force_run_requested", False)
                ),
                "action": str(item.get("action") or ""),
                "state_file": str(item.get("state_file") or ""),
            }
            for item in hunts
        ],
        "server_authoritative": True,
        "local_manifest_role": "operator_group_selection_cache",
    }
    generic.write_json(path, payload)
    return path


def retry_policy_path(hunt_root: Path) -> Path:
    return hunt_root / "coverage" / "retry-policy.json"


def retry_state_path(hunt_root: Path) -> Path:
    return hunt_root / "coverage" / "retry-state.json"


def configure_retry_policy(
    hunt_root: Path,
    *,
    retry_after_hours: int | None,
    max_attempts: int,
    batch_size: int,
) -> dict[str, Any] | None:
    if retry_after_hours is None:
        return None
    policy = {
        "policy_version": RETRY_POLICY_VERSION,
        "enabled": True,
        "retry_after_hours": retry_after_hours,
        "max_attempts": max_attempts,
        "batch_size": batch_size,
        "mode": "baseline_clients_without_flows",
        "updated_at": now_utc(),
    }
    path = retry_policy_path(hunt_root)
    generic.write_json(path, policy)
    return {**policy, "policy_file": str(path)}


def flow_client_ids(flows: list[dict[str, Any]]) -> set[str]:
    client_ids: set[str] = set()
    for flow in flows:
        nested = flow.get("Flow")
        nested = nested if isinstance(nested, dict) else {}
        client_id = str(
            flow.get("ClientId")
            or flow.get("client_id")
            or nested.get("ClientId")
            or nested.get("client_id")
            or ""
        ).strip()
        if client_id:
            client_ids.add(client_id)
    return client_ids


def parse_utc(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def retry_missing_clients(
    api: Any,
    *,
    hunt_id: str,
    hunt_root: Path,
    baseline: dict[str, Any] | None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("retry_missing_clients")
    policy_file = retry_policy_path(hunt_root)
    if not policy_file.is_file():
        return {"status": "disabled", "hunt_id": hunt_id, "queued_count": 0}
    policy = generic.read_json(policy_file)
    if not policy.get("enabled"):
        return {"status": "disabled", "hunt_id": hunt_id, "queued_count": 0}
    if baseline is None:
        return {
            "status": "baseline_unavailable",
            "hunt_id": hunt_id,
            "queued_count": 0,
            "reason": "Missing-client retry requires the target baseline captured by hunt run.",
        }

    baseline_ids = generic.baseline_client_ids(baseline)
    captured_at = parse_utc(baseline.get("captured_at"))
    now = (current_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    retry_after = timedelta(hours=int(policy["retry_after_hours"]))
    if captured_at is None or now < captured_at + retry_after:
        return {
            "status": "not_due",
            "hunt_id": hunt_id,
            "baseline_target_count": len(baseline_ids),
            "queued_count": 0,
        }

    responded_ids = flow_client_ids(generic.query_hunt_flows(api, hunt_id))
    missing_ids = sorted(baseline_ids - responded_ids)
    state_file = retry_state_path(hunt_root)
    state = generic.read_json(state_file) if state_file.is_file() else {}
    attempts = dict(state.get("attempts") or {})
    max_attempts = int(policy["max_attempts"])
    eligible: list[str] = []
    for client_id in missing_ids:
        record = attempts.get(client_id)
        record = record if isinstance(record, dict) else {}
        attempt_count = int(record.get("count") or 0)
        last_attempted_at = parse_utc(
            record.get("last_attempted_at")
            or record.get("last_queued_at")
        )
        if attempt_count >= max_attempts:
            continue
        if (
            last_attempted_at is not None
            and now < last_attempted_at + retry_after
        ):
            continue
        eligible.append(client_id)
    requested = eligible[: int(policy["batch_size"])]
    queued: list[str] = []
    failed: list[str] = []
    if requested:
        result_rows = api.query(
            """
            SELECT ClientId,
                   hunt_add(client_id=ClientId, hunt_id=HuntId) AS Result
            FROM foreach(row=parse_json_array(data=TargetsJson))
            """,
            {
                "HuntId": hunt_id,
                "TargetsJson": json.dumps(
                    [{"ClientId": client_id} for client_id in requested],
                    separators=(",", ":"),
                ),
            },
            max_wait=60,
            max_row=max(1, len(requested)),
        )
        successful_ids = {
            str(row.get("ClientId") or "").strip()
            for row in result_rows
            if bool(row.get("Result"))
        }
        queued = [
            client_id for client_id in requested if client_id in successful_ids
        ]
        failed = [
            client_id for client_id in requested if client_id not in successful_ids
        ]
        queued_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        for client_id in requested:
            record = attempts.get(client_id)
            record = dict(record) if isinstance(record, dict) else {}
            record["count"] = int(record.get("count") or 0) + 1
            record["last_attempted_at"] = queued_at
            if client_id in successful_ids:
                record["last_queued_at"] = queued_at
            attempts[client_id] = record
        generic.write_json(
            state_file,
            {
                "state_version": RETRY_POLICY_VERSION,
                "hunt_id": hunt_id,
                "updated_at": queued_at,
                "attempts": attempts,
            },
        )
    return {
        "status": (
            "queued"
            if queued
            else "queue_failed"
            if requested
            else "nothing_due"
        ),
        "hunt_id": hunt_id,
        "baseline_target_count": len(baseline_ids),
        "responded_client_count": len(responded_ids & baseline_ids),
        "missing_client_count": len(missing_ids),
        "eligible_client_count": len(eligible),
        "requested_count": len(requested),
        "queued_count": len(queued),
        "failed_count": len(failed),
        "remaining_eligible_count": max(len(eligible) - len(queued), 0),
        "policy_file": str(policy_file),
        "state_file": str(state_file) if state_file.is_file() else "",
    }


def manifest_request_signatures(payload: dict[str, Any]) -> dict[str, str]:
    return {
        str(item.get("artifact") or ""): str(item.get("request_signature") or "")
        for item in payload.get("hunts") or []
        if isinstance(item, dict)
        and str(item.get("artifact") or "")
        and str(item.get("request_signature") or "")
    }


def public_artifacts(args: argparse.Namespace) -> list[str]:
    if args.profile == "detectraptor":
        if args.env:
            raise RuntimeError(
                "DetectRaptor group execution does not accept shared --env values. "
                "Use a targeted one-artifact hunt for custom parameters."
            )
        family = generic.profile_artifact_labels("detectraptor")
        requested = generic.unique_ordered(list(args.artifact or []))
        if not requested:
            return family
        invalid = [artifact for artifact in requested if artifact not in family]
        if invalid:
            raise RuntimeError(
                "DetectRaptor artifact selection must stay within the family: "
                + ", ".join(invalid)
            )
        return requested
    if args.profile in {"lateral-movement", "autoruns"}:
        if args.artifact:
            raise RuntimeError(f"The {args.profile} profile owns its curated artifact; do not add --artifact.")
        return [generic.profile_artifact_labels(args.profile)[0]]
    artifacts = generic.unique_ordered(list(args.artifact or []))
    if len(artifacts) != 1:
        raise RuntimeError("Targeted hunt execution requires exactly one --artifact.")
    return artifacts


def generic_ensure_argv(
    args: argparse.Namespace,
    *,
    artifact: str,
    group: str,
    investigation_id: str,
    api_client: Path,
    org_id: str,
) -> list[str]:
    argv = [
        "--api-client",
        str(api_client),
        "--org-id",
        org_id,
        "ensure",
        "--investigation-id",
        investigation_id,
        "--case-root",
        str(resolve_case_root(args)),
        "--question",
        args.question,
    ]
    if group:
        argv.extend(["--group", group])
    if args.profile:
        argv.extend(["--profile", args.profile])
        if args.profile == "detectraptor":
            argv.extend(["--artifact", artifact])
    else:
        argv.extend(["--artifact", artifact])
    for value in args.env or []:
        argv.extend(["--env", value])
    for value in args.include_label or []:
        argv.extend(["--include-label", value])
    for value in args.exclude_label or []:
        argv.extend(["--exclude-label", value])
    supports_time_bounds = (
        args.profile != "detectraptor"
        or artifact
        in {
            "DetectRaptor.Generic.Detection.YaraWebshell",
            "DetectRaptor.Windows.Detection.Evtx",
            "DetectRaptor.Windows.Detection.MFT",
        }
    )
    if args.date_after and supports_time_bounds:
        argv.extend(["--date-after", args.date_after])
    if args.date_before and supports_time_bounds:
        argv.extend(["--date-before", args.date_before])
    if args.force_run:
        argv.append("--force-run")
    if args.start_paused:
        argv.append("--start-paused")
    if args.activate_paused:
        argv.append("--activate-paused")
    if getattr(args, "authorize_template_create", False):
        argv.append("--authorize-template-create")
    return argv


def find_reusable_group(
    args: argparse.Namespace,
    *,
    artifacts: list[str],
    investigation_id: str,
    api_client: Path,
    org_id: str,
) -> str:
    contexts: list[dict[str, Any]] = []
    group_coverage: Counter[str] = Counter()
    for artifact in artifacts:
        generic_args = generic.parse_args(
            generic_ensure_argv(
                args,
                artifact=artifact,
                group="",
                investigation_id=investigation_id,
                api_client=api_client,
                org_id=org_id,
            ),
            forced_target="windows",
            expose_target=False,
            finalize=False,
        )
        request = generic.build_request_from_args(generic_args)
        include_labels = generic.unique_ordered(
            (generic_args.include_label or [])
            + (generic_args.label or [])
            + (generic_args.host_label or [])
        )
        exclude_labels = generic.unique_ordered(
            (generic_args.exclude_label or [])
            + (generic_args.exclude_host_label or [])
        )
        contexts.append(
            {
                "artifact": artifact,
                "request": request,
                "target_name": generic.target_name_from_args(generic_args, request),
                "include_labels": include_labels,
                "exclude_labels": exclude_labels,
                "request_signature": generic.request_signature(
                    request,
                    "windows",
                    include_labels,
                    exclude_labels,
                ),
            }
        )

    expected_signatures = {
        str(item["artifact"]): str(item["request_signature"])
        for item in contexts
    }
    groups_root = (
        resolve_case_root(args)
        / investigation_id
        / "hunts"
        / "groups"
    )
    local_matches: list[tuple[str, str]] = []
    if groups_root.is_dir():
        for path in groups_root.glob("*.json"):
            payload = generic.read_json(path)
            if manifest_request_signatures(payload) != expected_signatures:
                continue
            local_matches.append(
                (
                    str(payload.get("updated_at") or ""),
                    str(payload.get("group") or ""),
                )
            )
    if local_matches:
        local_matches.sort(reverse=True)
        return local_matches[0][1]

    with VeloApiClient(api_client, org_id=org_id) as api:
        for context in contexts:
            matches = generic.find_matching_hunts(
                api,
                investigation_id,
                str(context["target_name"]),
                context["request"],
                "windows",
                list(context["include_labels"]),
                list(context["exclude_labels"]),
            )
            artifact_groups = {
                extract_group(str(match.get("hunt_description") or ""))
                for match in matches
                if bool(match.get("reuse_allowed"))
            }
            for group in artifact_groups:
                if group:
                    group_coverage[group] += 1
    complete_groups = [
        group
        for group, coverage in group_coverage.items()
        if coverage == len(contexts)
    ]
    if not complete_groups:
        return ""
    return sorted(
        complete_groups,
        key=lambda group: (-group_coverage[group], group),
    )[0]


def command_run(args: argparse.Namespace) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("command_run")
    autoruns_profile = args.profile == "autoruns"
    if autoruns_profile and getattr(args, "retry_missing_after_hours", None) is not None:
        raise RuntimeError("autoruns does not enable automatic missing-client retries.")
    task_mode, response_depth = resolve_task_output(args)
    artifacts = public_artifacts(args)
    requested_group = str(args.group or "").strip()
    provisional_group = requested_group or generate_group(args.profile)
    investigation_id = str(args.investigation_id or "").strip() or provisional_group
    if requested_group:
        existing_group, _ = load_group_manifest(
            resolve_case_root(args), requested_group, investigation_id=investigation_id,
        )
        if existing_group and (
            autoruns_profile or str(existing_group.get("profile") or "")
            in {"autoruns", "autoruns_test"}
        ):
            existing_artifacts = {str(item.get("artifact") or "")
                for item in existing_group.get("hunts", [])}
            if existing_artifacts != set(artifacts):
                raise RuntimeError(
                    "The requested group has different or unknown artifacts. "
                    "Choose a separate --group to preserve the existing group manifest."
                )
    api_client = resolve_api_client(args, investigation_id)
    if not api_client.exists():
        raise RuntimeError(f"API client config not found at {api_client}")
    org_id = resolve_org_id(args)
    reusable_group = ""
    if not requested_group and not args.force_run:
        reusable_group = find_reusable_group(
            args,
            artifacts=artifacts,
            investigation_id=investigation_id,
            api_client=api_client,
            org_id=org_id,
        )
    group = requested_group or reusable_group or provisional_group
    if not args.investigation_id and reusable_group:
        investigation_id = reusable_group

    generic_args_by_artifact: list[tuple[str, argparse.Namespace]] = []
    for artifact in artifacts:
        generic_args = generic.parse_args(
            generic_ensure_argv(
                args,
                artifact=artifact,
                group=group,
                investigation_id=investigation_id,
                api_client=api_client,
                org_id=org_id,
            ),
            forced_target="windows",
            expose_target=False,
        )
        generic_args_by_artifact.append((artifact, generic_args))

    preflight: list[dict[str, Any]] = []
    for artifact, generic_args in generic_args_by_artifact:
        check = generic.command_check(generic_args)
        preflight.append(
            {
                "artifact": artifact,
                "discovery_count": int(check.get("discovery_count") or 0),
                "candidate_classification_counts": dict(
                    check.get("candidate_classification_counts") or {}
                ),
                "selection_decision": str(check.get("selection_decision") or ""),
                "selection_reason": str(check.get("selection_reason") or ""),
                "human_summary": str(check.get("human_summary") or ""),
                "hunt_id": str(check.get("hunt_id") or ""),
                "recommended_template": generic.remove_heavy_hunt_output_fields(
                    check.get("recommended_template")
                ),
            }
        )
    template_blocks = [
        item
        for item in preflight
        if item.get("selection_decision") == "template_authorization_required"
    ]
    if template_blocks and not getattr(args, "authorize_template_create", False):
        return {
            "action": "hunt_group_template_authorization_required",
            "mutation_performed": False,
            "group": group,
            "question": args.question,
            "profile": args.profile or "targeted-artifact",
            "task_mode": task_mode,
            "response_depth": response_depth,
            "investigation_id": investigation_id,
            "blocked_artifact_count": len(template_blocks),
            "template_recommendations": template_blocks,
            "human_summary": (
                f"{len(template_blocks)} requested artifact(s) have compatible reference-only templates. "
                "Review them, then pass --authorize-template-create to create separate current-engagement hunts."
            ),
        }
    force_blocks = [
        item
        for item in preflight
        if item.get("selection_decision") == "force_run_required"
    ]
    if force_blocks and not args.force_run:
        details = "; ".join(
            f"{item['artifact']}: {item.get('hunt_id') or '<unknown>'}"
            for item in force_blocks
        )
        raise RuntimeError(
            "Compatible exact current-engagement hunts are not reusable: "
            f"{details}. Pass --force-run to create fresh hunts."
        )

    hunts: list[dict[str, Any]] = []
    for artifact, generic_args in generic_args_by_artifact:
        result = generic.command_ensure(generic_args)
        retry_policy = None if autoruns_profile else configure_retry_policy(
            hunts_root(resolve_case_root(args), investigation_id)
            / str(result["hunt_id"]),
            retry_after_hours=getattr(args, "retry_missing_after_hours", None),
            max_attempts=getattr(args, "retry_max_attempts", 1),
            batch_size=getattr(
                args,
                "retry_batch_size",
                DEFAULT_RETRY_BATCH_SIZE,
            ),
        )
        hunts.append(
            {
                "artifact": artifact,
                "hunt_id": result["hunt_id"],
                "action": result["action"],
                "state": result.get("state", ""),
                "review_readiness": result.get("review_readiness", ""),
                "request_signature": result.get("request_signature", ""),
                "run_identity_sha256": result.get(
                    "run_identity_sha256",
                    "",
                ),
                "reuse_classification": result.get(
                    "reuse_classification",
                    "",
                ),
                "reuse_decision": result.get("reuse_decision", ""),
                "reuse_reason": result.get("reuse_reason", ""),
                "selection_decision": result.get("selection_decision", ""),
                "selection_reason": result.get("selection_reason", ""),
                "human_summary": result.get("human_summary", ""),
                "candidate_classification_counts": result.get(
                    "candidate_classification_counts",
                    {},
                ),
                "recommended_template": result.get("recommended_template"),
                "force_run_requested": bool(
                    result.get("force_run_requested", False)
                ),
                "hunt_description": result.get("hunt_description", ""),
                "state_file": result.get("state_file", ""),
                "retry_policy": retry_policy,
            }
        )

    manifest_path = write_group_manifest(
        case_root=resolve_case_root(args),
        investigation_id=investigation_id,
        group=group,
        profile=args.profile or "targeted-artifact",
        question=args.question,
        hunts=hunts,
        task_mode=task_mode,
        response_depth=response_depth,
    )
    payload = {
        "action": "hunt_group_ensured",
        "group": group,
        "group_manifest": str(manifest_path),
        "question": args.question,
        "profile": args.profile or "targeted-artifact",
        "task_mode": task_mode,
        "response_depth": response_depth,
        "investigation_id": investigation_id,
        "hunt_count": len(hunts),
        "hunts": hunts,
        "preflight": preflight,
        "server_authoritative": True,
        "local_state_role": "rebuildable_cache",
    }
    if autoruns_profile:
        payload["analysis_use_case"] = "autoruns"
        payload["automatic_missing_client_retries"] = False
        payload["analysis_follow_up"] = {
            "argv": [
                "dfir", "velociraptor", "hunt", "analyze", "--profile", "autoruns",
                "--engagement-id", investigation_id, "--api-client", str(api_client),
                "--org-id", org_id, "--case-root", str(resolve_case_root(args)),
                "--hunt-id", str(hunts[0]["hunt_id"]), "--artifact", artifacts[0],
            ],
            "required_options": [],
            "mode": "dedup-first-regex",
            "review_status": "not_performed",
            "stack_rows_saved": False,
        }
    return payload


def command_retry_missing(args: argparse.Namespace) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("command_retry_missing")
    case_root = resolve_case_root(args)
    output_root = resolved_hunts_root(args)
    if args.hunt_id:
        hunt_ids = [args.hunt_id]
    else:
        manifest, manifest_path = load_group_manifest(
            case_root,
            args.group,
            investigation_id=args.investigation_id,
        )
        if manifest is None:
            raise RuntimeError(
                f"Local hunt-group manifest not found for {args.group}."
            )
        hunt_ids = generic.unique_ordered(
            [
                str(item.get("hunt_id") or "")
                for item in manifest.get("hunts") or []
                if isinstance(item, dict)
            ]
        )
        if not hunt_ids:
            raise RuntimeError(
                f"Hunt-group manifest {manifest_path} contains no hunt ids."
            )

    missing_baselines = [
        hunt_id
        for hunt_id in hunt_ids
        if load_cached_baseline(
            case_root,
            hunt_id,
            investigation_id=args.investigation_id,
        )
        is None
    ]
    if missing_baselines:
        raise RuntimeError(
            "Missing-client retry requires a saved target baseline for every "
            "hunt. Missing: " + ", ".join(missing_baselines)
        )

    policies = [
        {
            "hunt_id": hunt_id,
            **(
                configure_retry_policy(
                    output_root / hunt_id,
                    retry_after_hours=args.after_hours,
                    max_attempts=args.max_attempts,
                    batch_size=args.batch_size,
                )
                or {}
            ),
        }
        for hunt_id in hunt_ids
    ]
    return {
        "action": "missing_client_retry_configured",
        "investigation_id": args.investigation_id,
        "group": args.group or "",
        "hunt_count": len(hunt_ids),
        "policies": policies,
        "server_mutated": False,
        "next_action": "Run hunt analyze; due missing baseline clients will be re-queued.",
    }


def discover_hunt_rows(
    api: Any,
    *,
    hunt_id: str | None,
    group: str | None,
    case_root: Path | None = None,
) -> list[dict[str, Any]]:
    if hunt_id:
        row = generic.query_single_hunt(api, hunt_id)
        if row is None:
            raise RuntimeError(f"Hunt {hunt_id} was not found.")
        return [row]
    if case_root is not None and group:
        manifest, _ = load_group_manifest(case_root, group)
        if manifest is not None:
            selected_by_hunt: dict[str, list[str]] = {}
            hunt_order: list[str] = []
            for item in manifest.get("hunts") or []:
                if not isinstance(item, dict):
                    continue
                selected_hunt_id = str(item.get("hunt_id") or "")
                selected_artifact = str(item.get("artifact") or "")
                if not selected_hunt_id or not selected_artifact:
                    continue
                if selected_hunt_id not in selected_by_hunt:
                    selected_by_hunt[selected_hunt_id] = []
                    hunt_order.append(selected_hunt_id)
                selected_by_hunt[selected_hunt_id].append(selected_artifact)
            rows: list[dict[str, Any]] = []
            for selected_hunt_id in hunt_order:
                row = generic.query_single_hunt(api, selected_hunt_id)
                if row is None:
                    raise RuntimeError(
                        f"Hunt group {group} references missing hunt {selected_hunt_id}."
                    )
                row[SELECTED_ARTIFACTS_KEY] = generic.unique_ordered(
                    selected_by_hunt[selected_hunt_id]
                )
                row[SELECTED_GROUP_KEY] = group
                rows.append(row)
            if not rows:
                raise RuntimeError(f"Hunt group manifest {group} contains no hunts.")
            return rows
    marker = generic.hunt_group_marker(str(group or ""))
    rows = [
        row
        for row in generic.query_hunts(api)
        if marker and marker in str(row.get("hunt_description") or "")
    ]
    if not rows:
        raise RuntimeError(f"No Velociraptor hunts were found for group {group}.")
    return rows


def request_for_selected_row(row: dict[str, Any]) -> Any:
    request = generic.resolve_request_from_hunt_row(row)
    selected = generic.unique_ordered(
        [str(value) for value in row.get(SELECTED_ARTIFACTS_KEY) or []]
    )
    specs = list(request.expected_specs)
    if selected:
        specs = [
            spec
            for spec in specs
            if str(spec.label) in selected or str(spec.artifact) in selected
        ]
        matched = {
            value
            for value in selected
            if any(
                value in {str(spec.label), str(spec.artifact)}
                for spec in specs
            )
        }
        missing = [value for value in selected if value not in matched]
        if missing:
            hunt_id = str(row.get("hunt_id") or row.get("HuntId") or "")
            raise RuntimeError(
                f"Hunt {hunt_id} no longer contains selected group artifacts: "
                + ", ".join(missing)
            )

    artifact_sources = generic.hunt_result_artifact_sources(row)
    expanded_specs: list[collection.ArtifactSpec] = []
    for spec in specs:
        for artifact_source in generic.result_sources_for_artifact(
            str(spec.artifact),
            artifact_sources,
        ):
            expanded_specs.append(
                collection.ArtifactSpec(
                    label=(
                        str(spec.label)
                        if artifact_source == str(spec.artifact)
                        else artifact_source
                    ),
                    artifact=artifact_source,
                    env=dict(spec.env),
                    timeout_seconds=spec.timeout_seconds,
                )
            )
    return collection.CollectionRequest(
        target_collection_type=request.target_collection_type,
        requested_groups=request.requested_groups,
        requested_artifacts=[str(spec.label) for spec in expanded_specs],
        expected_specs=expanded_specs,
    )


def hunt_analysis_question(
    *,
    args: argparse.Namespace,
    row: dict[str, Any],
    case_root: Path,
    hunt_root: Path,
) -> str:
    group = str(getattr(args, "group", "") or row.get(SELECTED_GROUP_KEY) or "")
    if group:
        manifest, _path = load_group_manifest(
            case_root,
            group,
            investigation_id=str(args.investigation_id),
        )
        question = str((manifest or {}).get("question") or "").strip()
        if question:
            return question
    state_path = hunt_root / "state.json"
    if state_path.is_file():
        question = str(generic.read_json(state_path).get("question") or "").strip()
        if question:
            return question
    question = str(row.get("question") or "").strip()
    if question:
        return question
    marker = re.search(
        r"(?:^|\s)question=([^\s]+)",
        str(row.get("hunt_description") or ""),
    )
    if marker:
        return marker.group(1).replace("_", " ")
    return DEFAULT_HUNT_ANALYSIS_QUESTION


def resolve_live_analysis_mode(
    args: argparse.Namespace,
    *,
    selected_artifacts: set[str],
) -> dict[str, str]:
    """Select streaming by default and stacking only for an explicit need."""
    requested = str(
        getattr(args, "analysis_mode", DEFAULT_LIVE_ANALYSIS_MODE)
        or DEFAULT_LIVE_ANALYSIS_MODE
    ).strip().casefold()
    if requested not in LIVE_ANALYSIS_MODES:
        raise RuntimeError(
            f"Unknown live analysis mode {requested!r}; expected one of "
            f"{', '.join(LIVE_ANALYSIS_MODES)}."
        )
    use_case = str(getattr(args, "use_case", "") or "").strip()
    detectraptor_selected = {
        artifact
        for artifact in selected_artifacts
        if str(artifact).casefold().startswith(DETECTRAPTOR_ARTIFACT_PREFIX)
    }
    autoruns_selected = selected_artifacts.intersection(
        live_hunt_analysis.AUTORUNS_ARTIFACTS
    )
    detection_regex = str(
        getattr(args, "detection_regex", "") or ""
    ).strip()
    stack_controls = [
        name
        for name, enabled in (
            ("--decisions", bool(getattr(args, "decisions", None))),
            ("--indicator", bool(list(getattr(args, "indicator", []) or []))),
            (
                "--filter-reference",
                bool(list(getattr(args, "filter_reference", []) or [])),
            ),
        )
        if enabled
    ]
    if detectraptor_selected:
        if autoruns_selected or use_case:
            raise RuntimeError(
                "DetectRaptor artifacts use full-row streaming and must be "
                "analyzed separately from Autoruns stack workflows."
            )
        if stack_controls:
            raise RuntimeError(
                f"{', '.join(stack_controls)} are unavailable for "
                "DetectRaptor stream-only analysis."
            )
        if requested == "stack":
            raise RuntimeError(
                "DetectRaptor artifacts use --analysis-mode stream; omit "
                "--analysis-mode stack."
            )
        if requested == "detectraptor-stack":
            if detectraptor_selected != {
                flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
            } or selected_artifacts != detectraptor_selected:
                raise RuntimeError(
                    "--analysis-mode detectraptor-stack requires only "
                    "DetectRaptor.Windows.Detection.Evtx."
                )
            return {
                "mode": "stream",
                "reason": "detectraptor_stack_compatibility_alias",
            }
        if detection_regex and (
            detectraptor_selected != {
                flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
            }
            or selected_artifacts != detectraptor_selected
        ):
            raise RuntimeError(
                "--detection-regex requires only "
                "DetectRaptor.Windows.Detection.Evtx."
            )
        reason = (
            "detectraptor_evtx_automatic"
            if selected_artifacts
            == {flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT}
            else "detectraptor_stream"
        )
        return {"mode": "stream", "reason": reason}
    if requested == "detectraptor-stack":
        raise RuntimeError(
            "--analysis-mode detectraptor-stack is available only for "
            "DetectRaptor.Windows.Detection.Evtx."
        )
    if detection_regex:
        raise RuntimeError(
            "--detection-regex is available only for "
            "DetectRaptor.Windows.Detection.Evtx."
        )
    if use_case:
        return {"mode": "stack", "reason": "declared_use_case"}
    if autoruns_selected:
        return {"mode": "stack", "reason": "autoruns_artifact"}
    if stack_controls and requested != "stack":
        raise RuntimeError(
            f"{', '.join(stack_controls)} require --analysis-mode stack."
        )
    if requested == "stack":
        return {"mode": "stack", "reason": "explicit_stack"}
    return {"mode": "stream", "reason": "default_stream"}


def find_cached_state(case_root: Path, hunt_id: str) -> tuple[dict[str, Any] | None, Path | None]:
    pattern = f"*/hunts/{hunt_id}/state.json"
    matches = sorted(case_root.glob(pattern))
    if not matches:
        return None, None
    path = matches[0]
    return generic.read_json(path), path


def load_cached_baseline(
    case_root: Path,
    hunt_id: str,
    *,
    investigation_id: str | None = None,
) -> dict[str, Any] | None:
    if investigation_id:
        state_path = (
            case_root
            / investigation_id
            / "hunts"
            / hunt_id
            / "state.json"
        )
        state = generic.read_json(state_path) if state_path.is_file() else None
    else:
        state, state_path = find_cached_state(case_root, hunt_id)
    candidates: list[Path] = []
    if state:
        value = str(state.get("baseline_targets_file") or "").strip()
        if value:
            candidates.append(Path(value).expanduser())
    if state_path:
        candidates.append(state_path.with_name("baseline-targets.json"))
    for path in candidates:
        if path.is_file():
            payload = generic.read_json(path)
            if isinstance(payload, dict):
                payload.setdefault("baseline_targets_file", str(path))
                return payload
    return None


def resolve_review_scope(
    case_root: Path,
    hunt_id: str,
    *,
    investigation_id: str | None,
    baseline: dict[str, Any] | None,
) -> str:
    """Classify local collection ownership without overriding Velociraptor."""
    state: dict[str, Any] | None = None
    if investigation_id:
        state_path = case_root / investigation_id / "hunts" / hunt_id / "state.json"
        if state_path.is_file():
            state = generic.read_json(state_path)
    else:
        state, _state_path = find_cached_state(case_root, hunt_id)
    explicit = str((state or {}).get("review_scope") or "").strip()
    if explicit in REVIEW_SCOPES:
        return explicit
    if baseline is not None or state is not None:
        return REVIEW_SCOPE_MANAGED_COLLECTION
    return REVIEW_SCOPE_AD_HOC


def review_readiness_payload(
    summary: dict[str, Any],
    baseline: dict[str, Any] | None,
    *,
    review_scope: str,
) -> dict[str, Any]:
    if review_scope != REVIEW_SCOPE_AD_HOC:
        return {
            **generic.baseline_and_readiness_payload(summary, baseline),
            "review_scope": REVIEW_SCOPE_MANAGED_COLLECTION,
            "target_execution_coverage": "",
        }
    return {
        "review_scope": REVIEW_SCOPE_AD_HOC,
        "baseline_scope_available": False,
        "baseline_scope_required": False,
        "baseline_scope_reason": "not_required_for_ad_hoc_review",
        "baseline_scope_captured_at": "",
        "baseline_target_count": 0,
        "baseline_targets_file": "",
        "review_readiness": "ready_for_review",
        "coverage_readiness": "result_set_only",
        "target_execution_coverage": "not_assessed",
        "strict_complete": False,
        "completion_ratio": 0.0,
        "response_ratio": 0.0,
        "failed_ratio": 0.0,
        "retry_after": "",
        "completion_reason": (
            "Ad-hoc review is scoped to the result set reported by the selected "
            "Velociraptor hunt; original target execution is not assessed."
        ),
    }


def status_for_row(
    api: Any,
    row: dict[str, Any],
    case_root: Path,
    *,
    investigation_id: str | None = None,
) -> dict[str, Any]:
    hunt_id = str(row.get("hunt_id") or row.get("HuntId") or "")
    if not hunt_id:
        raise RuntimeError("Velociraptor hunt row did not contain HuntId.")
    baseline = load_cached_baseline(
        case_root,
        hunt_id,
        investigation_id=investigation_id,
    )
    review_scope = resolve_review_scope(
        case_root,
        hunt_id,
        investigation_id=investigation_id,
        baseline=baseline,
    )
    summary = generic.refresh_hunt_status(api, hunt_id, baseline_snapshot=baseline)
    readiness = review_readiness_payload(
        summary,
        baseline,
        review_scope=review_scope,
    )
    request = request_for_selected_row(row)
    reported_total = max(0, int(summary.get("reported_result_row_count") or 0))
    single_artifact = len(request.expected_specs) == 1
    result_counts: list[dict[str, Any]] = []
    for spec in request.expected_specs:
        result_counts.append(
            {
                "artifact": spec.label,
                "artifact_name": spec.artifact,
                "row_count": reported_total if single_artifact else None,
                "count_source": (
                    "hunt_flow_metadata" if single_artifact else "aggregate_only"
                ),
                "count_error": "",
            }
        )
    total_rows = reported_total
    coverage_readiness = readiness.get("review_readiness", "")
    if total_rows > 0 and coverage_readiness not in {"ready_for_review"}:
        readiness["review_readiness"] = "partial_results_available"
        readiness["coverage_readiness"] = coverage_readiness
        readiness["completion_reason"] = (
            f"Velociraptor flow metadata reports {total_rows} collected rows, "
            "but baseline coverage is not complete."
        )
    return {
        **summary,
        **readiness,
        "group": str(
            row.get(SELECTED_GROUP_KEY)
            or extract_group(str(summary.get("hunt_description") or ""))
        ),
        "result_row_count": total_rows,
        "artifact_result_counts": result_counts,
        "result_count_errors": [
            {
                "artifact_name": item["artifact_name"],
                "error": item["count_error"],
            }
            for item in result_counts
            if item["count_error"]
        ],
        "results_available_for_review": total_rows > 0,
        "server_authoritative": True,
        "local_state_role": "rebuildable_cache",
    }


def analysis_status_for_row(
    api: Any,
    row: dict[str, Any],
    case_root: Path,
    *,
    investigation_id: str | None = None,
    reuse_metadata: bool = False,
) -> dict[str, Any]:
    hunt_id = str(row.get("hunt_id") or row.get("HuntId") or "")
    if not hunt_id:
        raise RuntimeError("Velociraptor hunt row did not contain HuntId.")
    baseline = load_cached_baseline(
        case_root,
        hunt_id,
        investigation_id=investigation_id,
    )
    review_scope = resolve_review_scope(
        case_root,
        hunt_id,
        investigation_id=investigation_id,
        baseline=baseline,
    )
    summary = generic.refresh_hunt_status(
        api,
        hunt_id,
        baseline_snapshot=baseline,
        **({"hunt_row": row} if reuse_metadata else {}),
    )
    readiness = review_readiness_payload(
        summary,
        baseline,
        review_scope=review_scope,
    )
    for key in (SELECTED_ARTIFACTS_KEY, SELECTED_GROUP_KEY):
        if key in row:
            summary[key] = row[key]
    return {
        **summary,
        **readiness,
    }


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    api_client = resolve_api_client(args, args.investigation_id)
    if not api_client.exists():
        raise RuntimeError(f"API client config not found at {api_client}")
    case_root = resolve_case_root(args)
    with VeloApiClient(api_client, org_id=resolve_org_id(args)) as api:
        rows = discover_hunt_rows(
            api,
            hunt_id=args.hunt_id,
            group=args.group,
            case_root=case_root,
        )
        hunts = [
            status_for_row(
                api,
                row,
                case_root,
                investigation_id=args.investigation_id,
            )
            for row in rows
        ]
    return {
        "action": "live_hunt_status",
        "selector": {
            "hunt_id": args.hunt_id or "",
            "group": args.group or "",
            "investigation_id": args.investigation_id or "",
        },
        "hunt_count": len(hunts),
        "hunts": hunts,
        "exported_results": False,
    }


class SnapshotRowTokenLimitError(RuntimeError):
    """Raised when one source row cannot fit in a snapshot CSV chunk."""


def load_snapshot_projections(
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot,
) -> dict[str, list[str]]:
    """Return trusted extraction projections from the shared artifact profiles."""
    profiles = policy_snapshot.profiles
    return {
        artifact_name: list(profile.get("review", {}).get("vql_select") or [])
        for artifact_name, profile in profiles.items()
        if profile.get("review", {}).get("vql_select")
    }


def snapshot_result_vql(vql_select: list[str] | None = None) -> str:
    if not vql_select:
        return "SELECT * FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)"
    return (
        "SELECT\n  "
        + ",\n  ".join(vql_select)
        + "\nFROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)"
    )


def canonical_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        )
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def canonical_csv_chunk(
    rows: list[dict[str, Any]],
) -> tuple[bytes, list[str]]:
    fields = sorted({str(key) for row in rows for key in row})
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                field: (
                    canonical_csv_value(row[field])
                    if field in row
                    else ""
                )
                for field in fields
            }
        )
    return output.getvalue().encode("utf-8"), fields


class TokenBoundedCsvWriter:
    def __init__(
        self,
        output_dir: Path,
        *,
        max_tokens: int,
        token_encoding: str,
    ):
        self.output_dir = output_dir
        self.max_tokens = max_tokens
        self.token_encoding = token_encoding
        self.partition = ""
        self.rows: list[dict[str, Any]] = []
        self.partition_indexes: Counter[str] = Counter()
        self.files: list[dict[str, Any]] = []

    def _flush(self) -> None:
        if not self.rows:
            return
        encoded, fields = canonical_csv_chunk(self.rows)
        estimated_tokens = token_budget.estimate_tokens(
            encoded.decode("utf-8"),
            self.token_encoding,
        )
        if estimated_tokens > self.max_tokens:
            raise RuntimeError(
                "Internal snapshot chunking error: persisted CSV exceeds the "
                f"configured token limit ({estimated_tokens}>{self.max_tokens})."
            )
        chunk_hash = sha256_bytes(encoded)
        partition_dir = self.output_dir / self.partition
        partition_dir.mkdir(parents=True, exist_ok=True)
        path = partition_dir / f"{chunk_hash}.csv"
        if path.exists():
            if path.read_bytes() != encoded:
                raise RuntimeError(f"Snapshot chunk hash collision at {path}.")
        else:
            path.write_bytes(encoded)
        self.partition_indexes[self.partition] += 1
        self.files.append(
            {
                "file": str(path),
                "format": "canonical-csv-v1",
                "partition": self.partition,
                "partition_index": self.partition_indexes[self.partition],
                "fields": fields,
                "row_count": len(self.rows),
                "size_bytes": len(encoded),
                "sha256": chunk_hash,
                "chunk_hash": chunk_hash,
                "estimated_tokens": estimated_tokens,
                "token_encoding": self.token_encoding,
                "token_estimator": token_budget.token_estimator_name(
                    self.token_encoding
                ),
            }
        )
        self.rows = []

    def write(self, row: dict[str, Any]) -> None:
        partition = analysis.row_partition(row)
        if self.rows and partition != self.partition:
            self._flush()
        self.partition = partition
        candidate = [*self.rows, row]
        encoded, _ = canonical_csv_chunk(candidate)
        estimated_tokens = token_budget.estimate_tokens(
            encoded.decode("utf-8"),
            self.token_encoding,
        )
        if estimated_tokens > self.max_tokens:
            if not self.rows:
                raise SnapshotRowTokenLimitError(
                    "One snapshot row exceeds the configured token limit "
                    f"(partition={partition}, tokens={estimated_tokens}, "
                    f"limit={self.max_tokens})."
                )
            self._flush()
            self.partition = partition
            encoded, _ = canonical_csv_chunk([row])
            estimated_tokens = token_budget.estimate_tokens(
                encoded.decode("utf-8"),
                self.token_encoding,
            )
            if estimated_tokens > self.max_tokens:
                raise SnapshotRowTokenLimitError(
                    "One snapshot row exceeds the configured token limit "
                    f"(partition={partition}, tokens={estimated_tokens}, "
                    f"limit={self.max_tokens})."
                )
            self.rows = [row]
            return
        self.rows = candidate

    def close(self) -> list[dict[str, Any]]:
        self._flush()
        return self.files


def result_batches(
    api: Any,
    hunt_id: str,
    artifact_name: str,
    *,
    batch_rows: int,
    vql_select: list[str] | None = None,
) -> Iterator[list[dict[str, Any]]]:
    vql = snapshot_result_vql(vql_select)
    env = {"HuntId": hunt_id, "ArtifactName": artifact_name}
    if hasattr(api, "query_batches"):
        yield from api.query_batches(
            vql,
            env,
            max_wait=30,
            max_row=batch_rows,
        )
        return
    yield api.query(vql, env, max_wait=30, max_row=batch_rows)


def snapshot_flow_result_vql(vql_select: list[str] | None = None) -> str:
    source = (
        "flow_results(client_id=ClientId, flow_id=FlowId, "
        "artifact=ArtifactName)"
    )
    if not vql_select:
        return f"SELECT * FROM {source}"
    return "SELECT\n  " + ",\n  ".join(vql_select) + f"\nFROM {source}"


def flow_result_batches(
    api: Any,
    *,
    client_id: str,
    flow_id: str,
    artifact_name: str,
    batch_rows: int,
    vql_select: list[str] | None = None,
) -> Iterator[list[dict[str, Any]]]:
    vql = snapshot_flow_result_vql(vql_select)
    env = {
        "ClientId": client_id,
        "FlowId": flow_id,
        "ArtifactName": artifact_name,
    }
    if hasattr(api, "query_batches"):
        yield from api.query_batches(
            vql,
            env,
            max_wait=30,
            max_row=batch_rows,
        )
        return
    yield api.query(vql, env, max_wait=30, max_row=batch_rows)


def artifact_matches_flow_results(
    artifact_name: str,
    artifacts_with_results: Any,
) -> bool:
    if not isinstance(artifacts_with_results, list) or not artifacts_with_results:
        return True
    names = {str(item or "") for item in artifacts_with_results}
    return any(
        name == artifact_name or name.startswith(f"{artifact_name}/")
        for name in names
    )


def query_client_identity_map(
    api: Any,
    client_ids: set[str],
) -> dict[str, dict[str, str]]:
    if not client_ids:
        return {}
    rows = api.query(
        """
        SELECT
          client_id,
          os_info.fqdn AS Fqdn,
          os_info.hostname AS Hostname
        FROM clients()
        """,
        max_wait=30,
        max_row=1000,
    )
    identities: dict[str, dict[str, str]] = {}
    for row in rows:
        client_id = str(
            row.get("client_id") or row.get("ClientId") or ""
        ).strip()
        if not client_id or client_id not in client_ids:
            continue
        identities[client_id] = {
            "fqdn": str(row.get("Fqdn") or "").strip(),
            "hostname": str(row.get("Hostname") or "").strip(),
        }
    return identities


def flow_snapshot_targets(
    flow_rows: list[dict[str, Any]],
    artifact_name: str,
    client_identities: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    identities = client_identities or {}
    targets: list[dict[str, Any]] = []
    for row in flow_rows:
        flow = row.get("Flow")
        flow = flow if isinstance(flow, dict) else {}
        row_count = int(flow.get("total_collected_rows") or 0)
        if row_count <= 0 or not artifact_matches_flow_results(
            artifact_name,
            flow.get("artifacts_with_results"),
        ):
            continue
        client_id = str(
            row.get("ClientId")
            or row.get("client_id")
            or flow.get("client_id")
            or ""
        ).strip()
        flow_id = str(
            row.get("FlowId")
            or row.get("flow_id")
            or flow.get("session_id")
            or ""
        ).strip()
        if not client_id or not flow_id:
            continue
        targets.append(
            {
                "client_id": client_id,
                "flow_id": flow_id,
                "state": str(flow.get("state") or ""),
                "expected_rows_upper_bound": row_count,
                "fqdn": str(
                    (identities.get(client_id) or {}).get("fqdn") or ""
                ),
                "hostname": str(
                    (identities.get(client_id) or {}).get("hostname") or ""
                ),
            }
        )
    return sorted(
        targets,
        key=lambda item: (item["client_id"], item["flow_id"]),
    )


GRPC_MESSAGE_SIZE_RE = re.compile(
    r"Received message larger than max\s*"
    r"\(\s*(?P<actual>\d+)\s+vs\.?\s+(?P<limit>\d+)\s*\)",
    re.I,
)


def grpc_message_sizes(exc: Exception) -> tuple[int, int] | None:
    match = GRPC_MESSAGE_SIZE_RE.search(str(exc))
    if not match:
        return None
    actual = int(match.group("actual"))
    limit = int(match.group("limit"))
    if actual <= 0 or limit <= 0:
        return None
    return actual, limit


def next_query_batch_rows(
    current_rows: int,
    *,
    expected_rows: int,
    error: Exception,
) -> tuple[int, dict[str, Any]]:
    current = max(1, int(current_rows))
    fallback = max(1, (current + 1) // 2)
    sizes = grpc_message_sizes(error)
    if sizes is None:
        return fallback, {"strategy": "halved"}
    actual_bytes, limit_bytes = sizes
    target_bytes = min(
        GRPC_TARGET_RESPONSE_BYTES,
        math.floor(limit_bytes * 0.75),
    )
    effective_rows = min(current, expected_rows) if expected_rows > 0 else current
    calculated = math.floor(
        effective_rows
        * target_bytes
        / actual_bytes
        * GRPC_BATCH_SAFETY_FACTOR
    )
    next_rows = max(1, min(current - 1, calculated))
    if next_rows >= current or next_rows <= 0:
        next_rows = fallback
        strategy = "halved"
    else:
        strategy = "response_size"
    return next_rows, {
        "strategy": strategy,
        "actual_response_bytes": actual_bytes,
        "response_limit_bytes": limit_bytes,
        "target_response_bytes": target_bytes,
    }


def extract_flow_snapshot(
    api: Any,
    *,
    target_index: int,
    target: dict[str, Any],
    artifact_name: str,
    output_root: Path,
    max_tokens: int,
    token_encoding: str,
    query_batch_rows: int,
    vql_select: list[str] | None,
) -> dict[str, Any]:
    output_dir = output_root / f"{target_index:08d}"
    attempts: list[dict[str, Any]] = []
    batch_rows = max(1, int(query_batch_rows))
    tried_batch_rows: set[int] = set()
    last_error = ""
    while batch_rows not in tried_batch_rows:
        tried_batch_rows.add(batch_rows)
        if output_dir.exists():
            shutil.rmtree(output_dir)
        writer = TokenBoundedCsvWriter(
            output_dir,
            max_tokens=max_tokens,
            token_encoding=token_encoding,
        )
        extracted_rows = 0
        try:
            for batch in flow_result_batches(
                api,
                client_id=str(target["client_id"]),
                flow_id=str(target["flow_id"]),
                artifact_name=artifact_name,
                batch_rows=batch_rows,
                vql_select=vql_select,
            ):
                for row in batch:
                    enriched = dict(row)
                    if not str(enriched.get("Fqdn") or "").strip():
                        if target.get("fqdn"):
                            enriched["Fqdn"] = str(target["fqdn"])
                        elif (
                            not str(enriched.get("Hostname") or "").strip()
                            and target.get("hostname")
                        ):
                            enriched["Hostname"] = str(target["hostname"])
                    if not any(
                        str(enriched.get(key) or "").strip()
                        for key in (
                            "ClientId",
                            "client_id",
                            "Fqdn",
                            "Hostname",
                            "HostName",
                            "ComputerName",
                        )
                    ):
                        enriched["ClientId"] = str(target["client_id"])
                    writer.write(enriched)
                    extracted_rows += 1
            files = writer.close()
            attempts.append(
                {
                    "query_batch_rows": batch_rows,
                    "status": "ok",
                    "row_count": extracted_rows,
                }
            )
            return {
                "target_index": target_index,
                **target,
                "row_count": extracted_rows,
                "query_batch_rows": batch_rows,
                "attempts": attempts,
                "files": files,
                "error": "",
            }
        except SnapshotRowTokenLimitError:
            writer.close()
            raise
        except Exception as exc:
            writer.close()
            last_error = str(exc)
            resource_exhausted = generic.is_resource_exhausted_error(exc)
            attempt = {
                "query_batch_rows": batch_rows,
                "status": "resource_exhausted"
                if resource_exhausted
                else "error",
                "error": last_error,
            }
            if not resource_exhausted or batch_rows == 1:
                attempts.append(attempt)
                break
            next_rows, sizing = next_query_batch_rows(
                batch_rows,
                expected_rows=int(
                    target.get("expected_rows_upper_bound") or 0
                ),
                error=exc,
            )
            attempt.update(sizing)
            attempt["next_query_batch_rows"] = next_rows
            attempts.append(attempt)
            batch_rows = next_rows
    return {
        "target_index": target_index,
        **target,
        "row_count": 0,
        "query_batch_rows": batch_rows,
        "attempts": attempts,
        "files": [],
        "error": last_error or "Flow result extraction failed.",
    }


def bounded_concurrent_flow_extraction(
    api: Any,
    *,
    targets: list[dict[str, Any]],
    workers: int,
    worker_kwargs: dict[str, Any],
) -> list[dict[str, Any]]:
    results: dict[int, dict[str, Any]] = {}
    next_index = 0
    pending: dict[concurrent.futures.Future[dict[str, Any]], int] = {}
    maximum_workers = max(1, min(int(workers), len(targets)))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=maximum_workers
    ) as executor:
        while next_index < maximum_workers:
            future = executor.submit(
                extract_flow_snapshot,
                api,
                target_index=next_index,
                target=targets[next_index],
                **worker_kwargs,
            )
            pending[future] = next_index
            next_index += 1
        while pending:
            done, _ = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                index = pending.pop(future)
                results[index] = future.result()
                if next_index < len(targets):
                    replacement = executor.submit(
                        extract_flow_snapshot,
                        api,
                        target_index=next_index,
                        target=targets[next_index],
                        **worker_kwargs,
                    )
                    pending[replacement] = next_index
                    next_index += 1
    return [results[index] for index in range(len(targets))]


def merge_flow_snapshot_files(
    flow_results: list[dict[str, Any]],
    artifact_dir: Path,
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for result in flow_results:
        for item in result.get("files", []):
            source = Path(str(item["file"]))
            destination = (
                artifact_dir
                / str(item["partition"])
                / source.name
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if destination.read_bytes() != source.read_bytes():
                    raise RuntimeError(
                        f"Snapshot chunk hash collision at {destination}."
                    )
                source.unlink()
            else:
                os.replace(source, destination)
            merged = dict(item)
            merged["file"] = str(destination)
            files.append(merged)
    return files


def extract_artifact_snapshot_concurrent(
    api: Any,
    *,
    flow_rows: list[dict[str, Any]],
    client_identities: dict[str, dict[str, str]],
    workers: int,
    hunt_id: str,
    artifact: str,
    artifact_name: str,
    expected_rows: int,
    chunks_root: Path,
    max_tokens: int,
    token_encoding: str,
    query_batch_rows: int,
    vql_select: list[str] | None = None,
) -> dict[str, Any]:
    targets = flow_snapshot_targets(
        flow_rows,
        artifact_name,
        client_identities,
    )
    if not targets:
        if expected_rows == 0:
            return {
                "artifact": artifact,
                "artifact_name": artifact_name,
                "expected_row_count": 0,
                "extracted_row_count": 0,
                "complete": True,
                "query_batch_rows": query_batch_rows,
                "query_workers": workers,
                "transport_mode": "concurrent-flow",
                "flow_count": 0,
                "projection_applied": bool(vql_select),
                "vql_select": list(vql_select or ["*"]),
                "attempts": [
                    {
                        "query_batch_rows": query_batch_rows,
                        "status": "ok",
                        "row_count": 0,
                    }
                ],
                "files": [],
                "error": "",
            }
        return extract_artifact_snapshot(
            api,
            hunt_id=hunt_id,
            artifact=artifact,
            artifact_name=artifact_name,
            expected_rows=expected_rows,
            chunks_root=chunks_root,
            max_tokens=max_tokens,
            token_encoding=token_encoding,
            query_batch_rows=query_batch_rows,
            vql_select=vql_select,
        )
    artifact_dir = chunks_root / safe_token(artifact)
    flow_temp_root = chunks_root / f".{safe_token(artifact)}-flows"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    if flow_temp_root.exists():
        shutil.rmtree(flow_temp_root)
    flow_temp_root.mkdir(parents=True, exist_ok=True)
    try:
        results = bounded_concurrent_flow_extraction(
            api,
            targets=targets,
            workers=workers,
            worker_kwargs={
                "artifact_name": artifact_name,
                "output_root": flow_temp_root,
                "max_tokens": max_tokens,
                "token_encoding": token_encoding,
                "query_batch_rows": query_batch_rows,
                "vql_select": vql_select,
            },
        )
        errors = [
            str(item.get("error") or "")
            for item in results
            if item.get("error")
        ]
        if errors:
            raise RuntimeError(
                "Concurrent flow extraction failed: " + "; ".join(errors)
            )
        files = merge_flow_snapshot_files(results, artifact_dir)
        extracted_rows = sum(
            int(item.get("row_count") or 0) for item in results
        )
        if expected_rows >= 0 and extracted_rows != expected_rows:
            raise RuntimeError(
                "Concurrent flow extraction row count mismatch "
                f"({extracted_rows}!={expected_rows})."
            )
        successful_batch_rows = min(
            (
                int(item.get("query_batch_rows") or query_batch_rows)
                for item in results
            ),
            default=query_batch_rows,
        )
        resource_exhausted_count = sum(
            1
            for result in results
            for attempt in result.get("attempts", [])
            if attempt.get("status") == "resource_exhausted"
        )
        effective_expected_rows = (
            extracted_rows if expected_rows < 0 else expected_rows
        )
        return {
            "artifact": artifact,
            "artifact_name": artifact_name,
            "expected_row_count": effective_expected_rows,
            "extracted_row_count": extracted_rows,
            "complete": effective_expected_rows == extracted_rows,
            "query_batch_rows": successful_batch_rows,
            "query_workers": min(workers, len(targets)),
            "transport_mode": "concurrent-flow",
            "flow_count": len(targets),
            "projection_applied": bool(vql_select),
            "vql_select": list(vql_select or ["*"]),
            "attempts": [
                {
                    "query_batch_rows": successful_batch_rows,
                    "status": "ok",
                    "row_count": extracted_rows,
                    "flow_count": len(targets),
                    "resource_exhausted_count": resource_exhausted_count,
                }
            ],
            "files": files,
            "error": "",
        }
    except SnapshotRowTokenLimitError:
        raise
    except Exception as exc:
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
        fallback = extract_artifact_snapshot(
            api,
            hunt_id=hunt_id,
            artifact=artifact,
            artifact_name=artifact_name,
            expected_rows=expected_rows,
            chunks_root=chunks_root,
            max_tokens=max_tokens,
            token_encoding=token_encoding,
            query_batch_rows=query_batch_rows,
            vql_select=vql_select,
        )
        fallback["transport_mode"] = "aggregate-fallback"
        fallback["query_workers"] = 1
        fallback["flow_count"] = len(targets)
        fallback["concurrent_error"] = str(exc)
        return fallback
    finally:
        shutil.rmtree(flow_temp_root, ignore_errors=True)


def extract_artifact_snapshot(
    api: Any,
    *,
    hunt_id: str,
    artifact: str,
    artifact_name: str,
    expected_rows: int,
    chunks_root: Path,
    max_tokens: int,
    token_encoding: str,
    query_batch_rows: int,
    vql_select: list[str] | None = None,
) -> dict[str, Any]:
    artifact_dir = chunks_root / safe_token(artifact)
    attempts: list[dict[str, Any]] = []
    last_error = ""
    batch_rows = max(1, int(query_batch_rows))
    tried_batch_rows: set[int] = set()
    while batch_rows not in tried_batch_rows:
        tried_batch_rows.add(batch_rows)
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
        writer = TokenBoundedCsvWriter(
            artifact_dir,
            max_tokens=max_tokens,
            token_encoding=token_encoding,
        )
        extracted_rows = 0
        try:
            for batch in result_batches(
                api,
                hunt_id,
                artifact_name,
                batch_rows=batch_rows,
                vql_select=vql_select,
            ):
                for row in batch:
                    writer.write(row)
                    extracted_rows += 1
            files = writer.close()
            effective_expected_rows = (
                extracted_rows if expected_rows < 0 else expected_rows
            )
            attempts.append(
                {"query_batch_rows": batch_rows, "status": "ok", "row_count": extracted_rows}
            )
            return {
                "artifact": artifact,
                "artifact_name": artifact_name,
                "expected_row_count": effective_expected_rows,
                "extracted_row_count": extracted_rows,
                "complete": effective_expected_rows == extracted_rows,
                "query_batch_rows": batch_rows,
                "query_workers": 1,
                "transport_mode": "aggregate",
                "flow_count": 0,
                "projection_applied": bool(vql_select),
                "vql_select": list(vql_select or ["*"]),
                "attempts": attempts,
                "files": files,
                "error": "",
            }
        except SnapshotRowTokenLimitError:
            writer.close()
            raise
        except Exception as exc:
            writer.close()
            last_error = str(exc)
            resource_exhausted = generic.is_resource_exhausted_error(exc)
            attempt = {
                "query_batch_rows": batch_rows,
                "status": "resource_exhausted"
                if resource_exhausted
                else "error",
                "error": last_error,
            }
            if not resource_exhausted or batch_rows == 1:
                attempts.append(attempt)
                break
            next_rows, sizing = next_query_batch_rows(
                batch_rows,
                expected_rows=expected_rows,
                error=exc,
            )
            attempt.update(sizing)
            attempt["next_query_batch_rows"] = next_rows
            attempts.append(attempt)
            batch_rows = next_rows
    files = writer.files if "writer" in locals() else []
    return {
        "artifact": artifact,
        "artifact_name": artifact_name,
        "expected_row_count": expected_rows,
        "extracted_row_count": sum(int(item.get("row_count") or 0) for item in files),
        "complete": False,
        "query_batch_rows": batch_rows,
        "query_workers": 1,
        "transport_mode": "aggregate",
        "flow_count": 0,
        "projection_applied": bool(vql_select),
        "vql_select": list(vql_select or ["*"]),
        "attempts": attempts,
        "files": files,
        "error": last_error or "Result extraction failed.",
    }


def compact_capture_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": status.get("state", ""),
        "flows": {
            "total": int(status.get("flow_count") or 0),
            "clients": int(
                status.get("client_count")
                or status.get("total_client_count")
                or 0
            ),
            "open": int(status.get("open_client_count") or 0),
            "completed": int(status.get("completed_client_count") or 0),
            "failed": int(status.get("failed_client_count") or 0),
            "states": dict(status.get("flow_states") or {}),
        },
        "artifact_rows": {
            str(item.get("artifact_name") or ""): int(item.get("row_count") or 0)
            for item in status.get("artifact_result_counts", [])
            if str(item.get("artifact_name") or "")
            and item.get("row_count") is not None
        },
        "reported_rows": int(status.get("result_row_count") or 0),
    }


def compact_chunk_record(
    item: dict[str, Any],
    *,
    chunk_root: Path,
) -> dict[str, Any]:
    path = Path(str(item["file"]))
    return {
        "path": str(path.relative_to(chunk_root)),
        "partition": str(item["partition"]),
        "hash": str(item["sha256"]),
        "rows": int(item["row_count"]),
        "bytes": int(item["size_bytes"]),
        "tokens": int(item["estimated_tokens"]),
    }


def compact_artifact_manifest(record: dict[str, Any]) -> dict[str, Any]:
    chunk_root = Path("chunks") / safe_token(str(record["artifact"]))
    status = (
        "complete"
        if record.get("complete")
        else "error"
        if record.get("error")
        else "partial"
    )
    return {
        "label": str(record["artifact"]),
        "name": str(record["artifact_name"]),
        "status": status,
        "expected_rows": int(record["expected_row_count"]),
        "extracted_rows": int(record["extracted_row_count"]),
        "projection": list(record["vql_select"]),
        "transport": {
            "mode": str(record.get("transport_mode") or "aggregate"),
            "workers": int(record.get("query_workers") or 1),
            "flows": int(record.get("flow_count") or 0),
            "batch_rows": int(record["query_batch_rows"]),
            "attempts": [
                {
                    "rows": int(item["query_batch_rows"]),
                    "status": str(item["status"]),
                    **(
                        {"next_rows": int(item["next_query_batch_rows"])}
                        if item.get("next_query_batch_rows") is not None
                        else {}
                    ),
                    **(
                        {
                            "actual_bytes": int(
                                item["actual_response_bytes"]
                            )
                        }
                        if item.get("actual_response_bytes") is not None
                        else {}
                    ),
                    **(
                        {
                            "limit_bytes": int(
                                item["response_limit_bytes"]
                            )
                        }
                        if item.get("response_limit_bytes") is not None
                        else {}
                    ),
                    **(
                        {"flows": int(item["flow_count"])}
                        if item.get("flow_count") is not None
                        else {}
                    ),
                    **(
                        {
                            "resource_exhausted": int(
                                item["resource_exhausted_count"]
                            )
                        }
                        if item.get("resource_exhausted_count") is not None
                        else {}
                    ),
                }
                for item in record.get("attempts", [])
            ],
        },
        "chunk_root": str(chunk_root),
        "chunks": [
            compact_chunk_record(item, chunk_root=chunk_root)
            for item in record.get("files", [])
        ],
    }


def snapshot_evidence_fingerprint(
    hunt_id: str,
    result_records: list[dict[str, Any]],
) -> str:
    artifacts = [
        {
            "artifact": str(
                record.get("artifact_name") or record.get("artifact") or ""
            ),
            "projection": [
                str(expression) for expression in record.get("vql_select", [])
            ],
            "chunk_hashes": sorted(
                str(item["sha256"]) for item in record.get("files", [])
            ),
        }
        for record in result_records
    ]
    artifacts.sort(
        key=lambda item: (
            item["artifact"],
            tuple(item["projection"]),
            tuple(item["chunk_hashes"]),
        )
    )
    content_basis = {
        "hunt_id": hunt_id,
        "artifacts": artifacts,
    }
    return sha256_bytes(stable_json(content_basis).encode("utf-8"))[:16]


def snapshot_operational_state(
    *,
    hunt_id: str,
    group: str,
    snapshot_path: Path,
    fingerprint: str,
    status: str,
    capture: dict[str, Any],
    result_records: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "state_version": SNAPSHOT_STATE_VERSION,
        "updated_at": now_utc(),
        "hunt_id": hunt_id,
        "group": group,
        "latest_snapshot": str(snapshot_path),
        "latest_fingerprint": fingerprint,
        "latest_status": status,
        "capture": capture,
        "artifacts": [
            {
                "label": str(record["artifact"]),
                "name": str(record["artifact_name"]),
                "expected_rows": int(record["expected_row_count"]),
                "extracted_rows": int(record["extracted_row_count"]),
                "complete": bool(record["complete"]),
                "transport": {
                    "mode": str(
                        record.get("transport_mode") or "aggregate"
                    ),
                    "workers": int(record.get("query_workers") or 1),
                    "flows": int(record.get("flow_count") or 0),
                    "requested_batch_rows": int(
                        (record.get("attempts") or [{}])[0].get(
                            "query_batch_rows",
                            record["query_batch_rows"],
                        )
                    ),
                    "successful_batch_rows": int(record["query_batch_rows"]),
                    "attempts": list(record.get("attempts", [])),
                },
                "error": str(record.get("error") or ""),
            }
            for record in result_records
        ],
    }


def snapshot_hunt(
    api: Any,
    row: dict[str, Any],
    *,
    output_root: Path,
    case_root: Path,
    max_tokens: int,
    token_encoding: str,
    query_batch_rows: int,
    query_workers: int = 1,
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot,
) -> dict[str, Any]:
    hunt_id = str(row.get("hunt_id") or row.get("HuntId") or "")
    hunt_root = output_root / hunt_id
    snapshots_root = hunt_root / "snapshots"
    snapshots_root.mkdir(parents=True, exist_ok=True)
    staging = atomic_io.create_work_directory(
        snapshots_root,
        prefix="snapshot",
    )
    try:
        pre_status = status_for_row(api, row, case_root)
        request = request_for_selected_row(row)
        if pre_status.get("result_count_errors"):
            details = "; ".join(
                f"{item['artifact_name']}: {item['error']}"
                for item in pre_status["result_count_errors"]
            )
            raise RuntimeError(
                "Cannot create a complete snapshot because result sizing failed: "
                + details
            )
        expected_counts = {
            item["artifact_name"]: (
                int(item["row_count"])
                if item.get("row_count") is not None
                else -1
            )
            for item in pre_status["artifact_result_counts"]
        }
        resolved_policy = policy_snapshot
        projections = load_snapshot_projections(resolved_policy)
        projection_reference_sha256 = sha256_bytes(
            stable_json(projections).encode("utf-8")
        )
        flow_rows = (
            generic.query_hunt_flows(api, hunt_id)
            if query_workers > 1
            else []
        )
        flow_client_ids = {
            str(
                item.get("ClientId")
                or item.get("client_id")
                or (
                    item.get("Flow", {}).get("client_id")
                    if isinstance(item.get("Flow"), dict)
                    else ""
                )
                or ""
            ).strip()
            for item in flow_rows
        }
        flow_client_ids.discard("")
        client_identities = (
            query_client_identity_map(api, flow_client_ids)
            if query_workers > 1
            else {}
        )
        result_records: list[dict[str, Any]] = []
        for spec in request.expected_specs:
            extractor = (
                extract_artifact_snapshot_concurrent
                if query_workers > 1
                else extract_artifact_snapshot
            )
            extractor_kwargs = {
                "api": api,
                "hunt_id": hunt_id,
                "artifact": spec.label,
                "artifact_name": spec.artifact,
                "expected_rows": expected_counts.get(spec.artifact, 0),
                "chunks_root": staging / "chunks",
                "max_tokens": max_tokens,
                "token_encoding": token_encoding,
                "query_batch_rows": query_batch_rows,
                "vql_select": projections.get(spec.artifact),
            }
            if query_workers > 1:
                extractor_kwargs.update(
                    {
                        "flow_rows": flow_rows,
                        "client_identities": client_identities,
                        "workers": query_workers,
                    }
                )
            result_records.append(
                extractor(
                    **extractor_kwargs,
                )
            )
        for record in result_records:
            for item in record["files"]:
                item["file"] = str(Path(item["file"]).relative_to(staging))
        post_status = status_for_row(api, row, case_root)
        fingerprint = snapshot_evidence_fingerprint(hunt_id, result_records)
        capture = {
            "before": compact_capture_status(pre_status),
            "after": compact_capture_status(post_status),
        }
        capture_changed = capture["before"] != capture["after"]
        all_results_complete = all(record["complete"] for record in result_records)
        snapshot_status = (
            "complete"
            if not capture_changed and all_results_complete
            else "changed_during_capture"
            if capture_changed
            else "partial"
        )
        group = str(
            row.get(SELECTED_GROUP_KEY)
            or extract_group(str(row.get("hunt_description") or ""))
        )
        snapshot = {
            "snapshot_version": SNAPSHOT_VERSION,
            "created_at": now_utc(),
            "hunt": {
                "id": hunt_id,
                "group": group,
                "description": str(row.get("hunt_description") or ""),
            },
            "fingerprint": fingerprint,
            "status": snapshot_status,
            "chunking": {
                "format": "canonical-csv-v1",
                "max_tokens": max_tokens,
                "encoding": token_encoding,
                "estimator": token_budget.token_estimator_name(token_encoding),
            },
            "projection_reference": {
                "sha256": projection_reference_sha256,
            },
            "artifact_policy": resolved_policy.metadata(),
            "capture": capture,
            "artifacts": [
                compact_artifact_manifest(record) for record in result_records
            ],
        }
        generic.write_json(staging / "snapshot.json", snapshot)
        final_dir = snapshots_root / f"{timestamp_token()}-{fingerprint}"
        if final_dir.exists():
            final_dir = snapshots_root / f"{timestamp_token()}-{fingerprint}-{uuid.uuid4().hex[:8]}"
        os.replace(staging, final_dir)
        snapshot_path = final_dir / "snapshot.json"
        latest = {
            "hunt_id": hunt_id,
            "group": group,
            "snapshot": str(snapshot_path),
            "snapshot_dir": str(final_dir),
            "fingerprint": fingerprint,
            "status": snapshot_status,
            "consistent": snapshot_status == "complete",
            "updated_at": now_utc(),
        }
        snapshot_state_path = hunt_root / "snapshot-state.json"
        latest["snapshot_state"] = str(snapshot_state_path)
        generic.write_json(
            snapshot_state_path,
            snapshot_operational_state(
                hunt_id=hunt_id,
                group=group,
                snapshot_path=snapshot_path,
                fingerprint=fingerprint,
                status=snapshot_status,
                capture=capture,
                result_records=result_records,
            ),
        )
        generic.write_json(hunt_root / "latest.json", latest)
        return latest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def command_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    resolved_limits = analysis_limits.resolve_analysis_limits()
    resolved_policy = artifact_policy.load_artifact_policy()
    api_client = resolve_api_client(args, args.investigation_id)
    if not api_client.exists():
        raise RuntimeError(f"API client config not found at {api_client}")
    output_root = resolved_hunts_root(args)
    output_root.mkdir(parents=True, exist_ok=True)
    case_root = resolve_case_root(args)
    max_tokens = resolved_limits.maximum_evidence_tokens_per_item
    token_encoding = resolved_limits.token_encoding
    with VeloApiClient(api_client, org_id=resolve_org_id(args)) as api:
        rows = discover_hunt_rows(
            api,
            hunt_id=args.hunt_id,
            group=args.group,
            case_root=case_root,
        )
        snapshots = [
            snapshot_hunt(
                api,
                row,
                output_root=output_root,
                case_root=case_root,
                max_tokens=max_tokens,
                token_encoding=token_encoding,
                query_batch_rows=args.query_batch_rows,
                query_workers=getattr(args, "query_workers", 1),
                policy_snapshot=resolved_policy,
            )
            for row in rows
        ]
    payload = {
        "action": "hunt_snapshot_created",
        "investigation_id": args.investigation_id or "",
        "group": args.group or (snapshots[0].get("group") if snapshots else ""),
        "hunt_count": len(snapshots),
        "snapshots": snapshots,
        "artifact_policy": resolved_policy.metadata(),
        "output": str(output_root),
    }
    if args.group:
        group_root = output_root / "groups" / safe_token(args.group)
        manifest_path = group_root / "snapshots" / f"{timestamp_token()}.json"
        generic.write_json(manifest_path, payload)
        generic.write_json(
            group_root / "latest.json",
            {
                "group": args.group,
                "manifest": str(manifest_path),
                "updated_at": now_utc(),
            },
        )
        payload["group_manifest"] = str(manifest_path)
    return payload


def explicit_snapshot_path(args: argparse.Namespace) -> Path:
    path = Path(args.snapshot).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"Snapshot manifest not found: {path}")
    return path


def command_analyze_snapshot(
    args: argparse.Namespace,
    *,
    resolved_limits: analysis_limits.AnalysisLimits,
    resolved_policy: artifact_policy.ArtifactPolicySnapshot,
    task_mode: str = "targeted_hunt",
    response_depth: str = "standard",
) -> dict[str, Any]:
    progress_reporter = getattr(args, "_progress_reporter", None)
    snapshot_path = explicit_snapshot_path(args)
    if progress_reporter is not None:
        progress_reporter.emit(
            phase="snapshot_analysis",
            status="running",
            force=True,
        )
    debug_path = (
        snapshot_path.parent
        / f"analysis-v{analysis.STACK_ANALYSIS_VERSION}"
        / flow_analysis_coordinator.VALIDATION_DEBUG_FILENAME
    )
    session = (
        agent_diagnostics.DebugSession(
            debug_path,
            scope_type="snapshot",
            scope_id=snapshot_path.stem,
            lane="snapshot_planning",
        )
        if bool(getattr(args, "debug", False))
        else None
    )
    if session is not None:
        session.__enter__()
        session.record_stage("snapshot_planning", status="running")
    try:
        results = [
            analysis.analyze_snapshot(
                snapshot_path,
                policy_snapshot=resolved_policy,
                limits=resolved_limits,
                analysis_route=args.analysis_route,
                review_terms=list(args.review_term or []),
                selection_policy=args.selection_policy,
                review_mode=args.review_mode,
                max_total_analysis_tokens=args.max_total_analysis_tokens,
                snapshot_output=args.snapshot_output,
            )
        ]
    except Exception as exc:
        if session is not None:
            session.__exit__(type(exc), exc, exc.__traceback__)
        raise
    if session is not None:
        session.record_stage(
            "snapshot_planning",
            status="complete",
            analysis_count=len(results),
        )
        session.finalize("complete")
        session.__exit__(None, None, None)
    if getattr(args, "investigation_id", None):
        output_root = resolved_hunts_root(args)
    elif (
        len(snapshot_path.parents) > 3
        and snapshot_path.parents[1].name == "snapshots"
    ):
        output_root = snapshot_path.parents[3]
    else:
        output_root = snapshot_path.parent
    return {
        "action": "hunt_snapshot_analyzed",
        "group": "",
        "hunt_count": len(results),
        "task_mode": task_mode,
        "response_depth": response_depth,
        "analyses": results,
        "chat_summary": render_hunt_chat_summary(results),
        "output": str(output_root),
        **(
            {"validation_debug_file": str(debug_path)}
            if session is not None
            else {}
        ),
    }


def analysis_chat_summary_for_response(item: dict[str, Any]) -> str:
    explicit = str(item.get("chat_summary") or "").strip()
    if explicit:
        return explicit
    specialized = [
        str(item.get(key) or "").strip()
        for key in ("autoruns_chat_summary", "analysis_chat_summary")
        if str(item.get(key) or "").strip()
    ]
    if specialized:
        return "\n\n".join(specialized)
    result = item.get("analysis_result")
    if isinstance(result, dict):
        hunt_id = str(item.get("hunt_id") or "unknown")
        return analysis_summary.render_chat_summary(
            result,
            title=f"Hunt {hunt_id} analysis summary",
            status=str(item.get("status") or "unknown"),
            coverage={
                "result_review": item.get("result_review_coverage"),
                "target_execution": item.get("target_execution_coverage"),
                "overall": item.get("status"),
            },
        ).strip()
    hunt_id = str(item.get("hunt_id") or "snapshot")
    status = str(item.get("status") or "complete")
    return (
        f"## Hunt {hunt_id} analysis summary\n\n"
        f"- Status: `{status}`\n"
        "- Detailed structured results are present in the command response."
    )


def render_hunt_chat_summary(analyses: list[dict[str, Any]]) -> str:
    """Return one bounded summary for the main caller, including grouped hunts."""
    sections = [
        analysis_chat_summary_for_response(dict(item)).strip()
        for item in analyses
    ]
    rendered = "\n\n".join(section for section in sections if section).strip()
    if not rendered:
        return "## Hunt analysis summary\n\nNo analyses were returned.\n"
    rendered += "\n"
    if len(rendered) <= analysis_summary.MAX_CHAT_SUMMARY_CHARS:
        return rendered
    suffix = (
        "\n\nCombined chat summary reached its 32,000-character guard; consult "
        "the per-hunt summaries and canonical reports for remaining detail.\n"
    )
    clipped = rendered[
        : analysis_summary.MAX_CHAT_SUMMARY_CHARS - len(suffix)
    ].rsplit("\n", 1)[0].rstrip()
    return clipped + suffix


def preflight_hunt_outputs(output_root: Path, hunt_id: str) -> None:
    paths = live_hunt_analysis.analysis_paths(output_root / hunt_id)
    persistence_policy.preflight_analysis_tree(
        paths["root"], [f"hunt:{hunt_id}"],
        extra_files=[paths["analysis_memory"]],
    )


def validate_autoruns_args(args):
    rejected = sorted(set(getattr(args, "_supplied_options", ())) - AUTORUNS_ALLOWED_OPTIONS)
    if rejected:
        raise RuntimeError("autoruns does not accept: " + ", ".join(rejected))
    if not args.hunt_id or len(args.artifact) != 1 or args.artifact[0] not in live_hunt_analysis.AUTORUNS_ARTIFACTS:
        raise RuntimeError("autoruns requires one --hunt-id and one Autoruns --artifact.")


def command_autoruns(args):
    from vraptor.autoruns import dedup_ai as dedup
    from vraptor.autoruns import golden
    from vraptor.autoruns import review as autoruns_regex_review
    validate_autoruns_args(args)
    started_at = time.monotonic()
    reporter = getattr(args, "_progress_reporter", None)
    progress = reporter.update if reporter is not None else None
    investigation_id = str(args.investigation_id or getattr(args, "server_profile", "") or "").strip()
    if not investigation_id:
        raise RuntimeError("autoruns requires --id or --server-profile to resolve the hunt analysis folder.")
    hunt_root = case_layout.hunt_dir(resolve_case_root(args), investigation_id, args.hunt_id)
    database = dfir_paths.resolve_autoruns_golden_db(args.autoruns_golden_db, REPO_ROOT)
    dedup.autoruns_regex_db.load(database)
    skip_ai = bool(getattr(args, "skip_ai", False))
    if model_options.supplied(args):
        execution, limits = model_options.resolve(
            args, resolver=resolve_agent_execution, allow_missing_credentials=skip_ai,
        )
        if skip_ai:
            execution = None
    else:
        execution = None if skip_ai else resolve_agent_execution()
        limits = analysis_limits.resolve_analysis_limits(execution=execution)
        if execution is not None:
            limits = limits.for_execution(execution)
    maximum = analysis_cli_arguments.resolve_live_review_tokens(
        args.max_review_tokens, limits)
    if progress is not None:
        progress(dict(phase="hunt_preflight", mode="autoruns"))
    api_client = resolve_api_client(args, investigation_id)
    with dedup.publication.hunt_lock(hunt_root):
        dedup.publication.load_state(hunt_root)
        work = atomic_io.create_work_directory(hunt_root.parent, prefix="autoruns-runtime")
        try:
            with VeloApiClient(api_client, org_id=resolve_org_id(args),
                    query_timeout_seconds=args.query_timeout_seconds) as api:
                hunt = generic.query_single_hunt(api, args.hunt_id)
                if hunt is None or args.artifact[0] not in generic.hunt_artifact_names(hunt):
                    raise RuntimeError("Requested hunt/artifact was not found.")
                if not (getattr(args, "no_autoruns_golden_sync", False)
                        or getattr(args, "existing_only", False)):
                    if progress is not None:
                        progress(dict(phase="golden_sync", status="running", mode="autoruns"))
                    sync_started = time.monotonic()
                    sync = golden.publish_database(
                        api, database, tool_name=golden.DEFAULT_TOOL_NAME,
                        tool_version=golden.DEFAULT_TOOL_VERSION,
                    )
                    if progress is not None:
                        progress(dict(phase="golden_sync", status="complete", mode="autoruns",
                            inventory_sync=sync["status"],
                            database_sha256=sync["database_sha256"],
                            elapsed_seconds=round(time.monotonic() - sync_started, 3)))
                if progress is not None:
                    progress(dict(phase="source_query", mode="autoruns"))
                exported = autoruns_regex_review.run(api, hunt_id=args.hunt_id,
                    artifact=args.artifact[0], database=database, output_dir=work / "source",
                    query_timeout_seconds=args.query_timeout_seconds, vql_file=dedup.template(),
                    workflow="autoruns", max_total_rows=args.stack_max_total_rows)
            return dedup.review_saved(exported["stats_json"], database=database, hunt_id=args.hunt_id,
                artifact=args.artifact[0], hunt_root=hunt_root, execution=execution,
                maximum_evidence_tokens=maximum, progress=progress,
                skip_ai=skip_ai, max_total_rows=args.stack_max_total_rows,
                started_at=started_at)
        finally:
            shutil.rmtree(work)


def command_analyze(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "profile", None) == "autoruns":
        return command_autoruns(args)
    skip_ai = bool(getattr(args, "skip_ai", False))
    if skip_ai and bool(getattr(args, "update", False)):
        raise RuntimeError("--skip-ai prepares the full current scope; omit --update")
    progress_reporter = getattr(args, "_progress_reporter", None)
    override_execution = None
    if model_options.supplied(args):
        override_execution, resolved_limits = model_options.resolve(
            args, resolver=resolve_agent_execution,
            allow_missing_credentials=skip_ai or bool(args.snapshot),
        )
    else:
        resolved_limits = analysis_limits.resolve_analysis_limits()
    resolved_policy = artifact_policy.load_artifact_policy(
        list(args.artifact_reference or [])
    )
    args.max_review_tokens = analysis_cli_arguments.resolve_live_review_tokens(
        getattr(args, "max_review_tokens", None),
        resolved_limits,
    )
    requested_time_scope = analysis_time_scope.from_args(args)
    task_mode, response_depth = resolve_task_output(args)
    if args.snapshot:
        if requested_time_scope.bounded:
            raise RuntimeError(
                "Time-bounded analysis requires a live hunt; immutable snapshots "
                "must be filtered when they are created."
            )
        if bool(getattr(args, "update", False)):
            raise RuntimeError("--update is available only for live hunt analysis.")
        return command_analyze_snapshot(
            args,
            resolved_limits=resolved_limits,
            resolved_policy=resolved_policy,
            task_mode=task_mode,
            response_depth=response_depth,
        )
    if args.group and args.decisions:
        raise RuntimeError(
            "--decisions requires --hunt-id so review decisions cannot be "
            "applied to the wrong hunt in a group."
        )
    api_client = resolve_api_client(args, args.investigation_id)
    if not api_client.exists():
        raise RuntimeError(f"API client config not found at {api_client}")
    output_root = resolved_hunts_root(args)
    output_root.mkdir(parents=True, exist_ok=True)
    case_root = resolve_case_root(args)
    if args.hunt_id:
        preflight_hunt_outputs(output_root, args.hunt_id)
    with VeloApiClient(
        api_client, org_id=resolve_org_id(args),
        query_timeout_seconds=getattr(args, "query_timeout_seconds", 0),
    ) as api:
        rows = discover_hunt_rows(
            api,
            hunt_id=args.hunt_id,
            group=args.group,
            case_root=case_root,
        )
        if progress_reporter is not None:
            progress_reporter.emit(
                phase="inventory",
                status="complete",
                force=True,
                submitted=len(rows),
            )
        if not args.hunt_id:
            # Check every selected hunt before processing any of them.
            for row in rows:
                preflight_hunt_outputs(
                    output_root, str(row.get("hunt_id") or row.get("HuntId") or ""),
                )
        if not args.use_case:
            for row in rows:
                selected = set(args.artifact or generic.hunt_artifact_names(row))
                if (selected.intersection(live_hunt_analysis.AUTORUNS_ARTIFACTS)
                        or (not args.artifact and generic.is_autoruns_hunt(row))):
                    raise RuntimeError(
                        "General Autoruns hunt analysis requires --profile autoruns, "
                        "one --hunt-id, one Autoruns --artifact, and "
                        "the case and hunt analysis folder. "
                        "For mixed hunts, select other artifacts separately."
                    )
        analyses = []
        retries = []
        analyst_spec: ResolvedAgentExecution | None = override_execution if not skip_ai else None
        for row in rows:
            hunt_id = str(row.get("hunt_id") or row.get("HuntId") or "")
            if progress_reporter is not None:
                progress_reporter.emit(
                    phase="hunt_preflight",
                    status="running",
                    force=True,
                    hunt_id=hunt_id,
                )
            selected_row = dict(row)
            if list(getattr(args, "artifact", []) or []):
                selected_row[SELECTED_ARTIFACTS_KEY] = generic.unique_ordered(
                    [str(value) for value in args.artifact]
                )
            request = request_for_selected_row(selected_row)
            selected_artifacts = {
                str(spec.artifact)
                for spec in getattr(request, "expected_specs", [])
            }
            analysis_time_scope.resolve_all(
                sorted(selected_artifacts),
                resolved_policy.profiles,
                requested_time_scope,
                profile_resolver=artifact_profiles.resolve_profile,
            )
            analysis_mode = resolve_live_analysis_mode(
                args,
                selected_artifacts=selected_artifacts,
            )
            specialized_live_analysis = analysis_mode["mode"] == "stack"
            if args.stack_max_total_rows is not None and not specialized_live_analysis:
                raise RuntimeError("--stack-max-total-rows requires --analysis-mode stack or --profile autoruns.")
            if bool(getattr(args, "update", False)) and specialized_live_analysis:
                raise RuntimeError(
                    "--update supports --analysis-mode stream only."
                )
            if requested_time_scope.bounded and specialized_live_analysis:
                raise RuntimeError(
                    "Bounded time scope currently requires --analysis-mode stream; "
                    "stack-mode server aggregations cannot preserve exact source-row "
                    "provenance after filtering."
                )
            retries.append(
                {"status": "disabled", "requested_count": 0} if getattr(args, "existing_only", False) else retry_missing_clients(
                    api,
                    hunt_id=hunt_id,
                    hunt_root=output_root / hunt_id,
                    baseline=load_cached_baseline(
                        case_root,
                        hunt_id,
                        investigation_id=args.investigation_id,
                    ),
                )
            )
            selected_row = analysis_status_for_row(
                api,
                selected_row,
                case_root,
                investigation_id=args.investigation_id,
                # Only explicit single-hunt discovery is immediately fresh.
                # Group members can wait hours while earlier hunts are reviewed.
                # Even a failed retry attempt requires a new metadata read.
                reuse_metadata=(
                    bool(args.hunt_id)
                    and retries[-1].get("status") in {
                        "disabled", "baseline_unavailable", "not_due", "nothing_due"
                    }
                    and int(retries[-1].get("requested_count") or 0) == 0
                ),
            )
            if not skip_ai and analyst_spec is None:
                analyst_spec = resolve_agent_execution()
                resolved_limits = resolved_limits.for_execution(analyst_spec)
                args.max_review_tokens = min(args.max_review_tokens, resolved_limits.maximum_evidence_tokens_per_item)
            if not specialized_live_analysis:
                normalized_hunt_state = generic.normalize_hunt_state(
                    selected_row.get("state")
                )
                analysis_question = hunt_analysis_question(
                    args=args,
                    row=selected_row,
                    case_root=case_root,
                    hunt_root=output_root / hunt_id,
                )
                coordinator_hunt_root = output_root / hunt_id
                if skip_ai:
                    from vraptor.analyze import preparation as analysis_preparation
                    prepared = analysis_preparation.prepare_hunt(
                        api, org_id=str(getattr(api, "org_id", "root") or "root"),
                        hunt_id=hunt_id, hunt_root=coordinator_hunt_root,
                        selected_artifacts=selected_artifacts, policy=resolved_policy,
                        limits=resolved_limits, time_scope=requested_time_scope,
                        detection_regex=str(args.detection_regex).strip(),
                        reported_result_rows=int(selected_row.get("reported_result_row_count") or 0),
                        progress_callback=progress_reporter.update if progress_reporter else None,
                    )
                    prepared["analysis_mode"] = analysis_mode["mode"]
                    prepared["analysis_mode_reason"] = analysis_mode["reason"]
                    analyses.append(prepared)
                    continue
                analyses.append(
                    flow_analysis_coordinator.analyze_hunt_flows(
                        api,
                        synthesis_mode=getattr(args, "synthesis", "none"),
                        org_id=str(getattr(api, "org_id", "root") or "root"),
                        hunt_id=hunt_id,
                        hunt_state=normalized_hunt_state,
                        reported_result_rows=int(
                            selected_row.get("reported_result_row_count") or 0
                        ),
                        target_execution_coverage=(
                            live_hunt_analysis.target_execution_coverage(
                                selected_row,
                                hunt_state=normalized_hunt_state,
                            )
                        ),
                        targeted_client_count=int(
                            selected_row.get("baseline_target_count") or 0
                        ),
                        review_scope=str(
                            selected_row.get("review_scope")
                            or REVIEW_SCOPE_MANAGED_COLLECTION
                        ),
                        question=analysis_question,
                        task_mode=task_mode,
                        response_depth=response_depth,
                        hunt_root=coordinator_hunt_root,
                        update=bool(getattr(args, "update", False)),
                        selected_artifacts=selected_artifacts,
                        retire_specialized_artifacts=(
                            selected_artifacts
                            if analysis_mode["reason"].startswith("detectraptor_")
                            else ()
                        ),
                        policy_snapshot=resolved_policy,
                        limits=resolved_limits,
                        debug_validation=bool(
                            getattr(args, "debug", False)
                        ),
                        spec=analyst_spec,
                        time_scope=requested_time_scope,
                        detection_regex=(
                            str(args.detection_regex).strip()
                        ),
                        progress_callback=(
                            progress_reporter.update
                            if progress_reporter is not None
                            else None
                        ),
                    )
                )
                analyses[-1]["analysis_mode"] = analysis_mode["mode"]
                analyses[-1]["analysis_mode_reason"] = analysis_mode["reason"]
                continue
            analyses.append(
                live_hunt_analysis.analyze_live_hunt(
                    api,
                    investigation_id=args.investigation_id,
                    hunt_row=selected_row,
                    request=request,
                    hunt_root=output_root / hunt_id,
                    question=hunt_analysis_question(
                        args=args,
                        row=selected_row,
                        case_root=case_root,
                        hunt_root=output_root / hunt_id,
                    ),
                    task_mode=task_mode,
                    response_depth=response_depth,
                    policy_snapshot=resolved_policy,
                    filter_references=list(args.filter_reference or []),
                    decisions_path=(
                        Path(args.decisions).expanduser().resolve()
                        if args.decisions
                        else None
                    ),
                    indicators=list(args.indicator or []),
                    use_case=str(args.use_case or ""),
                    # Only focused Autoruns scopes reach this shared legacy engine.
                    autoruns_golden_disabled=True,
                    autoruns_golden_sync=False,
                    autoruns_rmm_reference=(
                        Path(args.autoruns_rmm_reference)
                        .expanduser()
                        .resolve()
                        if args.autoruns_rmm_reference
                        else None
                    ),
                    direct_row_limit=args.direct_row_limit,
                    sample_rows=args.sample_rows,
                    stack_discovery_rows=args.stack_discovery_rows,
                    stack_field_preferences=list(
                        args.stack_field_preference or []
                    ),
                    stack_field_guidance=str(
                        args.stack_field_guidance or ""
                    ),
                    max_branches=args.max_branches,
                    max_review_rows=args.max_review_rows,
                    max_stack_groups=args.max_stack_groups,
                    stack_max_total_rows=args.stack_max_total_rows,
                    max_review_tokens=args.max_review_tokens,
                    maximum_review_tokens=(
                        resolved_limits.maximum_evidence_tokens_per_item
                    ),
                    token_encoding=resolved_limits.token_encoding,
                    autoruns_ai_review_enabled=bool(analyst_spec and analyst_spec.enabled),
                    skip_ai=skip_ai,
                    finding_consolidation_spec=analyst_spec,
                    synthesis_mode=getattr(args, "synthesis", "none"),
                    debug_validation=bool(getattr(args, "debug", False)),
                    include_review_rows=bool(args.include_review_rows),
                    progress_callback=(
                        progress_reporter.update
                        if progress_reporter is not None
                        else None
                    ),
                )
            )
            analyses[-1]["analysis_mode"] = analysis_mode["mode"]
            analyses[-1]["analysis_mode_reason"] = analysis_mode["reason"]
    if progress_reporter is not None:
        progress_reporter.emit(
            phase="publishing",
            status="running",
            force=True,
            completed=len(analyses),
        )
    payload = {
        "action": "live_hunt_group_analysis",
        **({"ai_review_status": "skipped", "review_complete": False} if skip_ai else {}),
        "investigation_id": args.investigation_id,
        "group": args.group or "",
        "hunt_count": len(analyses),
        "analyses": analyses,
        "artifact_policy": resolved_policy.metadata(),
        "chat_summary": render_hunt_chat_summary(analyses),
        "missing_client_retries": retries,
        "raw_evidence_persisted": any(
            bool(item.get("raw_evidence_persisted"))
            for item in analyses
        ),
        "snapshot_created": False,
        "output": str(output_root),
    }
    return payload


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-client", help="Velociraptor API client YAML.")
    parser.add_argument("--server-profile", help="Velociraptor instance profile. Required when --engagement-id is omitted.")
    parser.add_argument("--org-id", help="Velociraptor org id. Defaults to root.")


def add_subcommand_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-client", default=argparse.SUPPRESS, help="Velociraptor API client YAML.")
    parser.add_argument("--server-profile", default=argparse.SUPPRESS, help="Velociraptor instance profile.")
    parser.add_argument("--org-id", default=argparse.SUPPRESS, help="Velociraptor org id. Defaults to root.")


def add_case_root_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--case-root",
        help=(
            "Caller-owned case root. Hunt data is stored under "
            "<case-root>/<id>/hunts. Defaults to the configured case root."
        ),
    )


def add_live_investigation_arg(
    parser: argparse.ArgumentParser,
    *,
    required: bool = False,
) -> None:
    parser.add_argument(
        "--engagement-id",
        "--id",
        "--investigation-id",
        dest="investigation_id",
        required=required,
        help=(
            "Case namespace for hunt storage. Defaults to --server-profile."
        ),
    )


def add_live_selector(parser: argparse.ArgumentParser) -> None:
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--hunt-id")
    selector.add_argument("--group")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        description="Run, inspect, snapshot, and analyze server-authoritative Velociraptor hunts."
    )
    add_connection_args(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Reuse or create a bounded hunt group.")
    add_subcommand_connection_args(run)
    run.add_argument("--profile", choices=("detectraptor", "lateral-movement", "autoruns"))
    run.add_argument("--artifact", action="append", default=[])
    run.add_argument("--question", required=True)
    run.add_argument(
        "--task-mode",
        choices=TASK_MODE_CHOICES,
        default="",
        help="Investigation intent. Defaults to persisted group intent, then targeted-hunt.",
    )
    run.add_argument(
        "--response-depth",
        choices=RESPONSE_DEPTH_CHOICES,
        default="",
        help="Output depth. Defaults to the selected task mode.",
    )
    run.add_argument("--group")
    run.add_argument(
        "--engagement-id",
        "--id",
        "--investigation-id",
        dest="investigation_id",
        help="Case namespace. Defaults to --server-profile.",
    )
    add_case_root_arg(run)
    run.add_argument("--env", action="append", default=[])
    run.add_argument("--date-after")
    run.add_argument("--date-before")
    run.add_argument("--include-label", action="append", default=[])
    run.add_argument("--exclude-label", action="append", default=[])
    run.add_argument("--force-run", action="store_true")
    run.add_argument("--start-paused", action="store_true")
    run.add_argument("--activate-paused", action="store_true")
    run.add_argument(
        "--authorize-template-create",
        action="store_true",
        help=(
            "After reviewing compatible template candidates, authorize separate "
            "current-engagement hunt creation without mutating or reusing template results."
        ),
    )
    run.add_argument(
        "--retry-missing-after-hours",
        type=positive,
        help=(
            "Opt in to re-queue baseline clients that still have no hunt flow "
            "after this delay."
        ),
    )
    run.add_argument(
        "--retry-max-attempts",
        type=positive,
        default=1,
        help="Maximum automatic re-queue attempts per missing baseline client.",
    )
    run.add_argument(
        "--retry-batch-size",
        type=positive,
        default=DEFAULT_RETRY_BATCH_SIZE,
        help="Maximum missing baseline clients re-queued by one analysis pass.",
    )

    status = commands.add_parser("status", help="Query live status without exporting results.")
    add_subcommand_connection_args(status)
    add_live_investigation_arg(status)
    add_live_selector(status)
    add_case_root_arg(status)

    retry_missing = commands.add_parser(
        "retry-missing",
        help=(
            "Configure bounded automatic re-queue for target-baseline clients "
            "that have no hunt flow."
        ),
    )
    add_live_investigation_arg(retry_missing)
    retry_missing.add_argument("--server-profile", help="Velociraptor instance profile used as the engagement fallback.")
    add_live_selector(retry_missing)
    add_case_root_arg(retry_missing)
    retry_missing.add_argument("--after-hours", type=positive, required=True)
    retry_missing.add_argument("--max-attempts", type=positive, default=1)
    retry_missing.add_argument(
        "--batch-size",
        type=positive,
        default=DEFAULT_RETRY_BATCH_SIZE,
    )

    snapshot = commands.add_parser("snapshot", help="Create immutable token-bounded CSV snapshots.")
    add_subcommand_connection_args(snapshot)
    add_live_investigation_arg(snapshot)
    add_live_selector(snapshot)
    add_case_root_arg(snapshot)
    snapshot.add_argument("--query-batch-rows", type=positive, default=DEFAULT_QUERY_BATCH_ROWS)
    snapshot.add_argument(
        "--query-workers",
        type=positive,
        default=DEFAULT_QUERY_WORKERS,
        help=(
            "Bounded concurrent flow-result queries. Use 1 for aggregate "
            "hunt_results() extraction."
        ),
    )

    analyze = commands.add_parser(
        "analyze",
        help=(
            "Analyze live hunt results in memory. Pass --snapshot only for "
            "explicit offline snapshot analysis."
        ),
    )
    add_subcommand_connection_args(analyze)
    selector = analyze.add_mutually_exclusive_group(required=True)
    selector.add_argument("--hunt-id")
    selector.add_argument("--group")
    selector.add_argument("--snapshot")
    add_live_investigation_arg(analyze)
    add_case_root_arg(analyze)
    analysis_cli_output.add_analysis_output_args(analyze)
    analysis_cli_arguments.add_artifact_reference_argument(analyze)
    analysis_time_scope.add_arguments(analyze)
    analysis_cli_arguments.add_query_timeout_argument(analyze)
    analyze.add_argument(
        "--stack-max-total-rows", type=non_negative_int,
        help=(
            "Exclude identities above this source-record count before GoldenDB matching "
            "and CSV export for Autoruns, or before AI review for generic stacks; default 20 for "
            "--profile autoruns, unlimited for generic stacks; 0 disables the cutoff."
        ),
    )
    analyze.add_argument(
        "--profile", choices=("autoruns",),
        help="Review complete Autoruns stacks using regex-only GoldenDB and deduplication.",
    )
    analyze.add_argument(
        "--task-mode",
        choices=TASK_MODE_CHOICES,
        default="",
        help="Investigation intent. Defaults to persisted hunt/group intent, then targeted-hunt.",
    )
    analyze.add_argument(
        "--response-depth",
        choices=RESPONSE_DEPTH_CHOICES,
        default="",
        help="Output depth. Defaults to the selected task mode.",
    )
    analyze.add_argument(
        "--artifact",
        action="append",
        default=[],
        help=(
            "Analyze only the named artifact within the selected live hunt. "
            "Repeat for multiple artifacts."
        ),
    )
    analyze.add_argument(
        "--update",
        action="store_true",
        help=(
            "Merge results from flows completed since the last successful full "
            "analysis. Uses server-side source() batches of up to 250 flows and "
            "requires an existing schema-7 checkpoint."
        ),
    )
    analyze.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Persist bounded, value-free provider, timing, retry, validation, "
            "and synthesis diagnostics for this live or snapshot analysis."
        ),
    )
    analysis_cli_arguments.add_skip_ai_argument(analyze)
    analysis_cli_arguments.add_prompt_debug_argument(analyze)
    model_options.add_arguments(analyze)
    analysis_cli_arguments.add_snapshot_review_arguments(analyze)
    analyze.add_argument(
        "--analysis-mode",
        choices=LIVE_ANALYSIS_MODES,
        default=DEFAULT_LIVE_ANALYSIS_MODE,
        help=(
            "Live analysis strategy. Stream is the default. Use stack only for "
            "explicit prevalence or structured reduction; declared Autoruns "
            "workflows select stack automatically. DetectRaptor EVTX selects "
            "direct or exact-stack review automatically. The detectraptor-stack "
            "value is a deprecated alias for stream."
        ),
    )
    analyze.add_argument(
        "--detection-regex",
        default="",
        help=(
            "Optional Velociraptor regex applied to Detection.Name for a "
            "scoped DetectRaptor EVTX automatic analysis."
        ),
    )
    analyze.add_argument(
        "--filter-reference",
        action="append",
        default=[],
        help=(
            "Reusable local analysis-filter JSON file. Repeat to apply ordered "
            "references; explicit values replace VELO_HUNT_FILTER_PATHS."
        ),
    )
    analyze.add_argument(
        "--decisions",
        help=(
            "Structured reviewer decisions for review_ids returned by the "
            "previous live-analysis pass. Accepts decisions JSON or an "
            "editable focused Autoruns review CSV generated by the analyzer."
        ),
    )
    analyze.add_argument(
        "--indicator",
        action="append",
        default=[],
        help=(
            "Known-bad regex for the profile's primary filter field, or "
            "FIELD=REGEX. Repeat as needed."
        ),
    )
    analyze.add_argument(
        "--use-case",
        choices=sorted(live_hunt_analysis.AUTORUNS_USE_CASES),
        help=(
            "Run a focused Autoruns analysis scope. Candidates are stacked "
            "first; suspicious groups use the normal exhaustive drilldown to "
            "return original rows and hosts."
        ),
    )
    analyze.add_argument(
        "--no-autoruns-golden-sync",
        action="store_true",
        help=(
            "Skip server GoldenDB synchronization before live Autoruns analysis."
        ),
    )
    analyze.add_argument(
        "--autoruns-golden-db",
        help=(
            "Local schema-10 GoldenDB (schema 9 also readable) for --profile autoruns; "
            "defaults to the configured shared database. Read-only during analysis."
        ),
    )
    analyze.add_argument(
        "--autoruns-rmm-reference",
        help=(
            "Optional windows-rmm-greyware.json override used to keep RMM, "
            "remote-access, and greyware identities visible and "
            "non-promotable."
        ),
    )
    analyze.add_argument(
        "--direct-row-limit",
        type=positive,
        default=live_hunt_analysis.DEFAULT_DIRECT_ROW_LIMIT,
    )
    analyze.add_argument(
        "--sample-rows",
        type=positive,
        default=live_hunt_analysis.DEFAULT_SAMPLE_ROWS,
    )
    analyze.add_argument(
        "--stack-discovery-rows",
        type=int,
        choices=range(
            live_hunt_analysis.MIN_STACK_DISCOVERY_ROWS,
            live_hunt_analysis.MAX_STACK_DISCOVERY_ROWS + 1,
        ),
        default=live_hunt_analysis.DEFAULT_STACK_DISCOVERY_ROWS,
        metavar="10-20",
        help=(
            "Transient deterministic rows used to derive an ephemeral stack "
            "when no curated signature exists. Defaults to 20."
        ),
    )
    analyze.add_argument(
        "--stack-field-preference",
        action="append",
        default=[],
        metavar="FIELD",
        help=(
            "Advisory field name supplied to dynamic AI stack selection. "
            "Repeat for multiple candidate fields. Names are validated "
            "against the transient sample and are never treated as VQL."
        ),
    )
    analyze.add_argument(
        "--stack-field-guidance",
        default="",
        metavar="TEXT",
        help=(
            "Bounded operator guidance supplied with transient field "
            "statistics to dynamic AI stack selection. If no safe stack can "
            "be selected, analysis stops with an operator question."
        ),
    )
    analyze.add_argument(
        "--max-branches",
        type=positive,
        default=live_hunt_analysis.DEFAULT_MAX_BRANCHES,
    )
    analyze.add_argument(
        "--max-review-rows",
        type=positive,
        default=live_hunt_analysis.DEFAULT_MAX_REVIEW_ROWS,
        help=(
            "Maximum raw/direct/sample/drilldown rows in one live-review "
            "response. Defaults to 1000."
        ),
    )
    analyze.add_argument(
        "--max-stack-groups",
        type=positive,
        default=live_hunt_analysis.DEFAULT_MAX_STACK_GROUPS,
        help=(
            "Maximum normalized aggregate groups in a manual fallback review. "
            "Automated generic stacks stream all source groups and retain at "
            "most 100 flagged groups per pass."
        ),
    )
    analyze.add_argument(
        "--max-review-tokens",
        type=positive,
        help=(
            "Optional live-review evidence ceiling. It may only narrow the "
            "effective AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS limit; snapshot "
            "chunk limits do not apply."
        ),
    )
    analyze.add_argument(
        "--include-review-rows",
        action="store_true",
        help=(
            "Include full transient review rows in command JSON. By default the "
            "response is bounded and links a metadata-only review manifest; raw "
            "rows remain authoritative in Velociraptor."
        ),
    )
    args = parser.parse_args(raw_argv)
    args._supplied_options = {
        value.split("=", 1)[0] for value in raw_argv if value.startswith("--")
    }
    if args.command == "analyze":
        if args.debug_chunk_prompts and args.snapshot:
            parser.error("--debug-chunk-prompts requires live host or hunt analysis")
        if args.stack_max_total_rows is None and args.profile == "autoruns":
            args.stack_max_total_rows = 20
        elif args.stack_max_total_rows == 0:
            args.stack_max_total_rows = None
    if args.command == "analyze" and args.profile == "autoruns":
        try:
            validate_autoruns_args(args)
        except RuntimeError as exc:
            parser.error(str(exc))
        if args.use_case:
            parser.error("autoruns does not accept a separate --use-case.")
    if args.command == "run" and args.profile == "autoruns":
        retry_options = sorted(
            args._supplied_options.intersection({
                "--retry-missing-after-hours", "--retry-max-attempts", "--retry-batch-size",
            })
        )
        if retry_options:
            parser.error(
                "autoruns does not accept automatic retry options: "
                + ", ".join(retry_options)
            )
    if (
        args.command == "analyze"
        and bool(getattr(args, "include_review_rows", False))
        and str(getattr(args, "output_format", "text")) != "json"
    ):
        parser.error("--include-review-rows requires --format json.")
    if args.command == "analyze" and args.snapshot:
        live_only = {
            "--query-timeout-seconds",
            "--profile",
            "--filter-reference",
            "--artifact",
            "--decisions",
            "--indicator",
            "--use-case",
            "--no-autoruns-golden-sync",
            "--autoruns-golden-db",
            "--autoruns-rmm-reference",
            "--direct-row-limit",
            "--sample-rows",
            "--stack-discovery-rows",
            "--stack-max-total-rows",
            "--stack-field-preference",
            "--stack-field-guidance",
            "--max-branches",
            "--max-review-rows",
            "--max-stack-groups",
            "--max-review-tokens",
            "--include-review-rows",
            "--analysis-mode",
        }
        supplied = analysis_cli_arguments.supplied_options(raw_argv, live_only)
        if supplied:
            parser.error(
                "Live-analysis options cannot be used with --snapshot: "
                + ", ".join(supplied)
            )
        analysis_cli_arguments.normalize_snapshot_review_arguments(args)
    elif args.command == "analyze":
        if not args.investigation_id and not getattr(args, "server_profile", None):
            parser.error("--engagement-id or --server-profile is required with --hunt-id or --group.")
        supplied = analysis_cli_arguments.supplied_options(
            raw_argv,
            analysis_cli_arguments.SNAPSHOT_REVIEW_OPTIONS,
        )
        if supplied:
            parser.error(
                "Snapshot-analysis options require --snapshot: "
                + ", ".join(supplied)
            )
    return args


def main(argv: list[str] | None = None, *, existing_only: bool = False) -> int:
    progress_reporter: analysis_cli_output.ProgressReporter | None = None
    try:
        args = parse_args(argv)
        args.existing_only = existing_only
        if args.command == "analyze":
            progress_reporter = analysis_cli_output.ProgressReporter(
                scope="hunt",
                scope_id=str(
                    args.hunt_id
                    or args.group
                    or (Path(args.snapshot).name if args.snapshot else "")
                ),
                enabled=not bool(args.no_progress),
                heartbeat_seconds=float(args.progress_interval_seconds),
            )
            progress_reporter.start(phase="preflight")
            args._progress_reporter = progress_reporter
        readiness_state = validate_live_engagement(args)
        investigation_id = str(getattr(args, "investigation_id", "") or "")
        if investigation_id:
            operation_log.bind_case(resolve_case_root(args), investigation_id)
        operation_log.emit(
            "readiness_validated",
            component="hunt_workflow",
            stage="preflight",
            status="complete",
            scope="hunt",
            scope_id=investigation_id,
        )
        if args.command == "run":
            payload = command_run(args)
        elif args.command == "status":
            payload = command_status(args)
        elif args.command == "retry-missing":
            payload = command_retry_missing(args)
        elif args.command == "snapshot":
            payload = command_snapshot(args)
        else:
            with prompt_debug.session(
                resolve_case_root(args) / investigation_id,
                args.debug_chunk_prompts,
            ) as prompt_dump:
                payload = command_analyze(args)
            if args.debug_chunk_prompts:
                payload["debug_chunk_prompts"] = prompt_dump.summary()
        if readiness_state is not None:
            payload["engagement_state_file"] = str(readiness_state)
        payload.update(operation_log.correlation_metadata())
        if args.command == "analyze":
            if progress_reporter is not None:
                analyses = list(payload.get("analyses") or [])
                final_status = str(
                    payload.get("status")
                    or (
                        dict(analyses[0]).get("status")
                        if len(analyses) == 1
                        else "complete"
                    )
                    or "complete"
                )
                progress_reporter.close(status=final_status)
            analysis_cli_output.emit_final_result(
                payload,
                output_format=str(args.output_format),
            )
        else:
            print(json.dumps(payload, indent=2, sort_keys=False))
        if existing_only:
            if payload.get("review_complete") is False or bool(getattr(args, "skip_ai", False)):
                return 2
            statuses = [payload.get("status", "")] + [item.get("status", "") for item in payload.get("analyses", [])]
            if any(status in {"failed", "partial", "complete_with_failures", "provisional", "incomplete"} for status in statuses):
                return 2
        return 0
    except (RuntimeError, ValueError, OSError, grpc.RpcError) as exc:
        operation_log.record_exception(exc, stage="hunt_workflow")
        if progress_reporter is not None:
            progress_reporter.close(status="failed", phase="failed")
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
