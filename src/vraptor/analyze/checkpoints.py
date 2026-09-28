"""Compact, Velociraptor-authoritative host analysis checkpoints."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from vraptor.common import atomic_io
from vraptor.common.hashing import sha256_file
from vraptor.collect import requests as collection


SCHEMA_VERSION = 4
REQUEST_CHECKPOINT_SCHEMA_VERSION = 4
SUCCESSFUL_RESULT_STATUSES = {"complete", "complete_with_failures"}
TERMINAL_ANALYSIS_STATUSES = {"complete", "failed"}
REUSABLE_ANALYSIS_STATUSES = {*TERMINAL_ANALYSIS_STATUSES, "complete_with_failures"}


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def artifact_name(item: Mapping[str, Any]) -> str:
    return str(item.get("artifact") or item.get("artifact_name") or "").strip()


def artifact_source_fingerprint(
    item: Mapping[str, Any],
    *,
    analysis_identity: str,
) -> str:
    """Fingerprint authoritative flow metadata plus the local analysis policy."""
    return canonical_hash(
        {
            "artifact": artifact_name(item),
            "artifact_name": str(item.get("artifact_name") or ""),
            "flow_id": str(item.get("flow_id") or ""),
            "flow_state": str(item.get("flow_state") or ""),
            "created": str(item.get("created") or ""),
            "last_active": str(item.get("last_active") or ""),
            "total_rows": int(item.get("total_rows") or 0),
            "is_finished": bool(item.get("is_finished")),
            "available_result_components": sorted(
                str(value) for value in item.get("available_result_components") or []
            ),
            "run_identity_sha256": str(item.get("run_identity_sha256") or ""),
            "effective_argument_validation": item.get(
                "effective_argument_validation"
            ),
            "analysis_identity": analysis_identity,
        }
    )


def new_state(
    *,
    hostname: str,
    client_id: str,
    request_id: str,
    analysis_identity: str,
) -> dict[str, Any]:
    now = collection.now_utc()
    return {
        "schema_version": SCHEMA_VERSION,
        "hostname": hostname,
        "client_id": client_id,
        "request_id": request_id,
        "analysis_identity": analysis_identity,
        "status": "pending",
        "created_at": now,
        "updated_at": now,
        "source_observation": {},
        "time_filter": {"coverage": "not_requested"},
        "artifacts": {},
        "synthesis": {"status": "pending", "input_fingerprint": ""},
        "evidence_persisted": False,
    }


def load_or_initialize(
    path: Path,
    *,
    hostname: str,
    client_id: str,
    request_id: str,
    analysis_identity: str,
    request_checkpoint: Path | None = None,
) -> dict[str, Any]:
    """Load current state or its hash-validated request checkpoint; otherwise rebuild."""
    state = new_state(
        hostname=hostname,
        client_id=client_id,
        request_id=request_id,
        analysis_identity=analysis_identity,
    )
    def from_request() -> dict[str, Any]:
        if request_checkpoint is None or not request_checkpoint.is_file():
            return state
        try:
            saved_request = json.loads(request_checkpoint.read_text())
            expected = saved_request.get("checkpoint_fingerprint")
            actual = canonical_hash({key: value for key, value in saved_request.items()
                                     if key not in {"checkpoint_fingerprint", "completed_at"}})
            if (expected == actual and saved_request.get("analysis_identity") == analysis_identity
                    and saved_request.get("client_id") == client_id
                    and saved_request.get("hostname") == hostname
                    and saved_request.get("request_id") == request_id):
                state["artifacts"] = {
                    entry["artifact"]: entry for entry in saved_request.get("artifact_summaries", [])
                    if isinstance(entry, dict) and entry.get("artifact")
                }
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        return state

    if not path.is_file():
        return from_request()
    try:
        saved_text = path.read_text(encoding="utf-8")
    except OSError:
        return from_request()
    try:
        saved = json.loads(saved_text)
    except json.JSONDecodeError:
        return from_request()
    if not isinstance(saved, dict):
        return from_request()
    identity = (
        saved.get("schema_version") == SCHEMA_VERSION
        and str(saved.get("hostname") or "") == hostname
        and str(saved.get("client_id") or "") == client_id
        and str(saved.get("request_id") or "") == request_id
        and str(saved.get("analysis_identity") or "") == analysis_identity
    )
    if not identity:
        return from_request()
    saved.setdefault("artifacts", {})
    saved.setdefault("source_observation", {})
    saved.setdefault("time_filter", {"coverage": "not_requested"})
    saved.setdefault("synthesis", {"status": "pending", "input_fingerprint": ""})
    saved["evidence_persisted"] = False
    return saved


def _source_status(item: Mapping[str, Any]) -> str:
    if not str(item.get("flow_id") or "").strip():
        return "missing"
    if not bool(item.get("is_finished")):
        return "open"
    flow_state = str(item.get("flow_state") or "UNKNOWN").upper()
    has_output = int(item.get("total_rows") or 0) > 0 or bool(
        item.get("available_result_components")
    )
    if flow_state == "ERROR" and not has_output:
        return "failed"
    return "successful_terminal"


def _report_is_valid(entry: Mapping[str, Any], report_root: Path | None) -> bool:
    report_path = Path(str(entry.get("report_file") or ""))
    expected_hash = str(entry.get("report_sha256") or "")
    if not report_path.is_file() or not expected_hash:
        return False
    resolved = report_path.resolve()
    if report_root is not None and resolved.parent != report_root.resolve():
        return False
    return sha256_file(resolved) == expected_hash


def reconcile(
    state: dict[str, Any],
    *,
    payload: Mapping[str, Any],
    analysis_identity: str,
    reset_artifacts: Iterable[str] = (),
    reset_all: bool = False,
    retry_failed: bool = False,
    report_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Refresh derived status from one authoritative Velociraptor observation."""
    reset_names = {str(value).strip() for value in reset_artifacts if str(value).strip()}
    observed_names = {
        artifact_name(item)
        for item in payload.get("artifact_flows") or []
        if artifact_name(item)
    }
    unknown = reset_names - observed_names
    if unknown:
        raise ValueError(
            "reset artifact was not present in the selected request: "
            + ", ".join(sorted(unknown))
        )

    state["source_observation"] = {
        "observed_at": collection.now_utc(),
        "server_cutoff": str(
            payload.get("server_cutoff")
            or payload.get("terminal_observed_through")
            or ""
        ),
        "request_state_file": str(payload.get("state_file") or ""),
        "all_artifacts_expected_complete": bool(
            payload.get("all_artifacts_expected_complete")
        ),
    }
    saved_artifacts = dict(state.get("artifacts") or {})
    reconciled: dict[str, dict[str, Any]] = {}
    runnable: list[dict[str, Any]] = []
    for raw_item in payload.get("artifact_flows") or []:
        item = dict(raw_item)
        name = artifact_name(item)
        if not name:
            continue
        fingerprint = artifact_source_fingerprint(
            item,
            analysis_identity=analysis_identity,
        )
        prior = dict(saved_artifacts.get(name) or {})
        reset = reset_all or name in reset_names
        retry = retry_failed and (
            prior.get("analysis_status") == "failed"
            or any(item.get("status") == "failed" for item in prior.get("diagnostics") or [])
            or prior.get("result_status") == "complete_with_failures"
            and prior.get("result_role") != "final_publication"
        )
        prior_status = str(prior.get("analysis_status") or "")
        reusable = (
            not reset and not retry
            and str(prior.get("source_fingerprint") or "") == fingerprint
            and prior_status in REUSABLE_ANALYSIS_STATUSES
            and isinstance(prior.get("result"), dict)
            and _report_is_valid(prior, report_root)
            and (
                prior_status == "failed"
                or isinstance(prior.get("plan_summary"), dict)
            )
        )
        source_status = _source_status(item)
        entry = {
            "artifact": name,
            "artifact_name": str(item.get("artifact_name") or ""),
            "flow_id": str(item.get("flow_id") or ""),
            "velociraptor_state": str(item.get("flow_state") or "UNKNOWN"),
            "created": str(item.get("created") or ""),
            "last_active": str(item.get("last_active") or ""),
            "reuse_decision": str(item.get("reuse_decision") or ""),
            "source_status": source_status,
            "source_fingerprint": fingerprint,
            "total_rows": int(item.get("total_rows") or 0),
            "updated_at": collection.now_utc(),
        }
        if reusable:
            entry.update(
                {
                    key: copy.deepcopy(prior[key])
                    for key in (
                        "analysis_status",
                        "result_status",
                        "completed_at",
                        "result",
                        "result_role",
                        "accepted_result",
                        "accepted_result_role",
                        "plan_summary",
                        "report_file",
                        "report_sha256",
                        "attempts",
                        "retry_count",
                        "last_error",
                        "error_class",
                        "diagnostics",
                    )
                    if key in prior
                }
            )
            if prior_status == "complete_with_failures":
                entry["analysis_status"] = "complete"
                entry["result_status"] = "complete_with_failures"
        elif source_status == "successful_terminal":
            entry["analysis_status"] = "pending"
            entry["attempts"] = int(prior.get("attempts") or 0)
            runnable.append(item)
        elif source_status == "failed":
            entry["analysis_status"] = "source_failed"
        else:
            entry["analysis_status"] = "waiting"
        reconciled[name] = entry

    state["artifacts"] = reconciled
    current_synthesis = dict(state.get("synthesis") or {})
    accepted_fingerprint = canonical_hash(
        {
            name: entry.get("source_fingerprint")
            for name, entry in sorted(reconciled.items())
            if entry.get("analysis_status") in TERMINAL_ANALYSIS_STATUSES
        }
    )
    if (
        reset_all
        or reset_names
        or runnable
        or str(current_synthesis.get("input_fingerprint") or "")
        != accepted_fingerprint
    ):
        state["synthesis"] = {
            "status": "pending",
            "input_fingerprint": accepted_fingerprint,
        }
    state["updated_at"] = collection.now_utc()
    return runnable


def mark_artifact_started(state: dict[str, Any], artifact: str) -> None:
    entry = state["artifacts"][artifact]
    entry["analysis_status"] = "running"
    entry["attempts"] = int(entry.get("attempts") or 0) + 1
    entry["started_at"] = collection.now_utc()
    entry.pop("last_error", None)
    state["updated_at"] = collection.now_utc()


def mark_artifact_complete(
    state: dict[str, Any],
    artifact: str,
    *,
    status: str,
    result: Mapping[str, Any],
    plan_summary: Mapping[str, Any],
    report_file: Path,
) -> None:
    if status not in SUCCESSFUL_RESULT_STATUSES:
        raise ValueError(f"artifact completion status is not cacheable: {status}")
    report = report_file.resolve()
    if not report.is_file():
        raise ValueError(f"artifact report does not exist: {report}")
    entry = state["artifacts"][artifact]
    entry.update(
        {
            "analysis_status": "complete",
            "result_status": status,
            "completed_at": collection.now_utc(),
            "result": copy.deepcopy(dict(result)),
            "plan_summary": copy.deepcopy(dict(plan_summary)),
            "time_filter": copy.deepcopy(
                dict(plan_summary.get("time_filter") or {})
            ),
            "report_file": str(report),
            "report_sha256": sha256_file(report),
        }
    )
    entry.pop("last_error", None)
    state["synthesis"] = {"status": "pending", "input_fingerprint": ""}
    state["updated_at"] = collection.now_utc()


def mark_artifact_failed(
    state: dict[str, Any],
    artifact: str,
    *,
    error_class: str,
    result: Mapping[str, Any],
    report_file: Path,
) -> None:
    """Record one terminal failure with its bounded summary in the same write."""
    report = report_file.resolve()
    if not report.is_file():
        raise ValueError(f"artifact failure report does not exist: {report}")
    entry = state["artifacts"][artifact]
    entry.update(
        {
            "analysis_status": "failed",
            "result_status": "failed",
            "completed_at": collection.now_utc(),
            "result": copy.deepcopy(dict(result)),
            "time_filter": copy.deepcopy(dict(result.get("time_filter") or {})),
            "report_file": str(report),
            "report_sha256": sha256_file(report),
            "last_error": (
                "artifact analysis failed; use --retry-failed with the same request and question"
            ),
            "error_class": str(error_class or "AnalysisError"),
        }
    )
    state["synthesis"] = {"status": "pending", "input_fingerprint": ""}
    state["updated_at"] = collection.now_utc()


def persist(path: Path, state: Mapping[str, Any]) -> None:
    payload = copy.deepcopy(dict(state))
    if str(payload.get("status") or "") in {"pending", "running"}:
        payload.pop("status", None)
    if str(dict(payload.get("synthesis") or {}).get("status") or "") in {
        "pending",
        "running",
    }:
        payload.pop("synthesis", None)
    for raw_entry in dict(payload.get("artifacts") or {}).values():
        if not isinstance(raw_entry, dict):
            continue
        if str(raw_entry.get("analysis_status") or "") in {"pending", "running"}:
            raw_entry.pop("analysis_status", None)
            raw_entry.pop("started_at", None)
    payload["schema_version"] = SCHEMA_VERSION
    payload["updated_at"] = collection.now_utc()
    payload["evidence_persisted"] = False
    atomic_io.write_json_atomic(path, payload, sort_keys=True)


def plan_summary(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only fields required to validate and synthesize accepted artifacts."""
    retained = (
        "schema_version",
        "reference_protocol",
        "analysis_profile",
        "task_mode",
        "response_depth",
        "scope_type",
        "analysis_objectives",
        "collection_type",
        "source_aliases",
        "analysis_limits",
        "analysis_limits_identity",
        "total_rows",
        "chunk_count",
        "chunks",
        "expected_chunk_headers",
        "artifact_task_count",
        "artifact_tasks",
        "artifacts",
        "collection_failures",
        "time_scope",
        "resolved_time_scopes",
        "time_filter",
        "source_fingerprint",
        "plan_fingerprint",
    )
    return {key: copy.deepcopy(plan[key]) for key in retained if key in plan}


def completed_artifacts(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        copy.deepcopy(dict(entry))
        for _name, entry in sorted(dict(state.get("artifacts") or {}).items())
        if str(entry.get("analysis_status") or "") == "complete"
    ]


def terminal_artifacts(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return terminal complete or failed artifact components."""
    return [
        copy.deepcopy(dict(entry))
        for _name, entry in sorted(dict(state.get("artifacts") or {}).items())
        if str(entry.get("analysis_status") or "") in TERMINAL_ANALYSIS_STATUSES
    ]


def write_request_checkpoint(
    path: Path,
    *,
    state: Mapping[str, Any],
    question: str,
    host_result: Mapping[str, Any],
    status: str,
    task_mode: str = "",
    response_depth: str = "",
) -> dict[str, Any]:
    artifacts = terminal_artifacts(state)
    payload = {
        "schema_version": REQUEST_CHECKPOINT_SCHEMA_VERSION,
        "hostname": str(state.get("hostname") or ""),
        "client_id": str(state.get("client_id") or ""),
        "request_id": str(state.get("request_id") or ""),
        "question": question.strip(),
        "analysis_identity": str(state.get("analysis_identity") or ""),
        "task_mode": str(task_mode).strip(),
        "response_depth": str(response_depth).strip(),
        "status": status,
        "completed_at": collection.now_utc(),
        "source_observation": copy.deepcopy(
            dict(state.get("source_observation") or {})
        ),
        "time_filter": copy.deepcopy(dict(state.get("time_filter") or {})),
        "artifact_summaries": [
            {
                key: copy.deepcopy(entry[key])
                for key in (
                    "artifact",
                    "artifact_name",
                    "flow_id",
                    "velociraptor_state",
                    "created", "last_active", "reuse_decision",
                    "source_fingerprint",
                    "total_rows",
                    "analysis_status",
                    "result_status",
                    "report_file",
                    "report_sha256",
                    "error_class",
                    "time_filter",
                    "source_status",
                    "result", "accepted_result", "result_role", "accepted_result_role",
                    "plan_summary", "attempts", "retry_count", "last_error", "diagnostics",
                )
                if key in entry
            }
            for entry in artifacts
        ],
        "result": copy.deepcopy(dict(host_result)),
        "synthesis_cache": copy.deepcopy(dict(state.get("synthesis_cache") or {})),
        "evidence_persisted": False,
    }
    payload["checkpoint_fingerprint"] = canonical_hash(
        {key: value for key, value in payload.items() if key != "completed_at"}
    )
    atomic_io.write_json_atomic(path, payload, sort_keys=True)
    return payload
