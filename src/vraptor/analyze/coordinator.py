"""Shared resumable coordinator for host and hunt flow-result analysis."""

from __future__ import annotations

from vraptor.analyze import prompt_debug

import asyncio
import concurrent.futures
import copy
import csv
import hashlib
import io
import inspect
import json
import re
import threading
import time
from collections import deque
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from vraptor.agent import diagnostics as agent_diagnostics
from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import recovery
from vraptor.common import atomic_io
from vraptor.common import token_budget
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import analyst_execution_identity
from vraptor.agent.config import analyst_execution_metadata
from vraptor.agent.profiles import PROFILE_NAMES
from vraptor.agent.profiles import RESPONSE_DEPTH_NAMES
from vraptor.agent.profiles import load_agent_profile_config
from vraptor.agent.profiles import normalize_profile_name
from vraptor.agent.profiles import normalize_response_depth
from vraptor.agent.factory import create_agent_runner
from vraptor.common.hashing import sha256_file
from vraptor.agent.runtime import AnalysisPoolStatus
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentRunner
from vraptor.agent.runtime import AgentRuntimeLimits
from vraptor.analyze.scheduler import DynamicAnalysisQueue
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.analyze import summary as analysis_summary
from vraptor.analyze import synthesis as synthesis_policy
from vraptor.analyze import line_protocol as analyst_line_protocol
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.autoruns import reporting as autoruns_reporting
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import runtime as collection_analysis_runtime
from vraptor.analyze import references as evidence_references
from vraptor.analyze import flow as flow_analysis
from vraptor.analyze import flow_runtime as flow_analysis_runtime
from vraptor.logging import operations as operation_log


STATE_FILENAME = "hunt-analysis-state.json"
REPORT_FILENAME = "analysis-hunt.md"
VALIDATION_DEBUG_FILENAME = "hunt-analysis-validation-debug.json"
OUTPUT_CONTRACT = "validated-hunt-analysis-summary-v3"
REVIEW_SCOPE_MANAGED_COLLECTION = "managed_collection"
REVIEW_SCOPE_AD_HOC = "ad_hoc_review"
REVIEW_SCOPES = {
    REVIEW_SCOPE_MANAGED_COLLECTION,
    REVIEW_SCOPE_AD_HOC,
}
MAX_SPECIALIZED_ARTIFACTS = 100
MAX_SPECIALIZED_FINDINGS = 10
MAX_SPECIALIZED_EXAMPLES = 10
MAX_SPECIALIZED_TEXT_CHARS = 320
MAX_SPECIALIZED_FINDING_INPUT_GROUPS = 200
MAX_RUN_RECORDS = 20
MAX_FAILED_CHUNK_ERROR_CHARS = 2048
MAX_FAILED_CHUNK_ATTEMPTS_PER_RUN = 20
MAX_FAILED_CHUNK_ATTEMPT_ERROR_CHARS = 512
MAX_FAILED_CHUNK_DIAGNOSTIC_CODES = 10
VALIDATION_DEBUG_SCHEMA_VERSION = agent_diagnostics.SCHEMA_VERSION
MAX_VALIDATION_DEBUG_ATTEMPTS = 512
MAX_VALIDATION_DEBUG_DETAILS_PER_ATTEMPT = 10
MAX_VALIDATION_DEBUG_BYTES = 1024 * 1024
MAX_VALIDATION_DEBUG_TEXT_CHARS = 256
MAX_SYNTHESIS_FAILURES = 5
PROGRESS_WRITE_INTERVAL_SECONDS = 15.0
STREAMING_CHUNK_SCHEMA_VERSION = 1
DETECTRAPTOR_RECOVERY_SCHEMA_VERSION = 4
DETECTRAPTOR_PROMPT_POLICY_VERSION = 1
DETECTRAPTOR_UPLIFT_SCHEMA_VERSION = 1
MAX_DETECTRAPTOR_TRANSPORT_ERRORS = 5
MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS = 20
DETECTRAPTOR_CONTEXT_FILENAME = "detectraptor-interesting-context.json"
DETECTRAPTOR_UPLIFT_FILENAME = "detectraptor_whitelist_candidates.csv"
MAX_DETECTRAPTOR_REPORT_NOTES = 100
MAX_DETECTRAPTOR_REPORT_EVENTS = 3
MAX_DETECTRAPTOR_REPORT_SOURCE_REFS = 3
DETECTRAPTOR_UPLIFT_FIELDS = (
    "Detection",
    "Scope",
    "SourceRef",
    "OccurrenceCount",
    "PayloadField",
    "Summary",
    "Payload",
)

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(flow_analysis.canonical_json(value).encode("utf-8"))


def _safe_output_component(value: Any, *, fallback: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return normalized.strip(".-") or fallback


def _read_optional_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _detectraptor_analysis_guidance(detection: str) -> tuple[str, ...]:
    """Return high-threshold reporting policy for one detection family."""
    name = str(detection or "").strip()
    normalized = re.sub(r"[^a-z0-9]+", " ", name.casefold()).strip()
    compact = normalized.replace(" ", "")
    guidance = [
        "Treat the DetectRaptor detection as a lead, not a finding. Report only concrete malicious behavior or specific evidence that makes malicious use reasonably plausible; unfamiliarity alone is insufficient.",
        "Review and account for every assigned row or exact-payload group. Expected activity omitted from findings must still remain covered by the reviewed-row accounting.",
        "Return UPLIFT only for clearly expected, stable system, vendor, or enterprise behavior suitable for later whitelist review. Use global for reusable Windows/vendor behavior and site for internal or organization-specific behavior. Do not propose broad detection-name or domain-only suppression.",
    ]
    if any(
        marker in compact
        for marker in ("t1197", "bitstransfer", "bitsadmin", "bitsjob")
    ) or "bits" in normalized.split():
        guidance.append(
            "BITS triage: omit clearly internal transfers and evidence-backed trusted software update, deployment, health-check, or vendor telemetry activity when no suspicious execution, persistence, staging, collection, or destination ambiguity remains. A failed transfer alone is not reportable and a familiar-looking domain alone does not establish trust. Report unknown or unapproved destinations, unexplained uploads, executable/script transfer and execution, notify-command execution, persistence, anomalous users or paths, deceptive domains, or conflicting suspicious evidence."
        )
    if any(
        marker in compact
        for marker in ("powershell", "scriptblock", "commandlet", "t1059001")
    ):
        guidance.append(
            "PowerShell triage: omit standard Windows inbox/module/servicing scripts, expected security-product scripts, deployment or endpoint-management automation, monitoring/backup tooling, evidence-backed vendor scripts, and ordinary administration. Do not report activity merely because it is long, encoded, runs as SYSTEM, invokes PowerShell, or contains one dual-use cmdlet. Report unexplained retrieval and execution, material obfuscation, credential access, defense evasion, security-control changes, log clearing, persistence, suspicious external communication, unusual writable-path execution, or unexpected commands appended to otherwise expected code."
        )
    return tuple(guidance)


def _detectraptor_uplift_rows(
    results: Iterable[Mapping[str, Any]],
    *,
    partition_id: str,
    detection: str,
) -> list[dict[str, Any]]:
    """Hydrate model-selected uplift references from coordinator-owned rows."""
    rows: list[dict[str, Any]] = []
    for result in results:
        for raw in result.get("uplift_candidates") or []:
            if not isinstance(raw, Mapping):
                continue
            fields = dict(raw.get("fields") or {})
            payload_field = str(fields.get("PayloadField") or "").strip()
            if "Payload" in fields:
                payload = str(fields.get("Payload") or "")
                payload_field = payload_field or "EventData"
            elif "Evidence" in fields:
                payload = str(fields.get("Evidence") or "")
                payload_field = payload_field or "Evidence"
            else:
                raise RuntimeError(
                    "DetectRaptor uplift candidate does not contain a complete payload."
                )
            if not payload:
                raise RuntimeError("DetectRaptor uplift candidate payload is empty.")
            rows.append(
                {
                    "partition_id": partition_id,
                    "Detection": str(fields.get("Detection") or detection),
                    "Scope": str(raw.get("scope") or ""),
                    "SourceRef": str(raw.get("ref") or ""),
                    "OccurrenceCount": max(
                        1, int(fields.get("OccurrenceCount") or 1)
                    ),
                    "PayloadField": payload_field,
                    "Summary": str(raw.get("summary") or "").strip(),
                    "Payload": payload,
                    "payload_sha256": hashlib.sha256(
                        payload.encode("utf-8")
                    ).hexdigest(),
                }
            )
    return rows


def _merge_detectraptor_uplift_rows(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Deduplicate exact candidate payloads and omit contradictory scopes."""
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for raw in rows:
        row = dict(raw)
        key = (
            str(row.get("Detection") or ""),
            str(row.get("PayloadField") or ""),
            str(row.get("payload_sha256") or ""),
        )
        grouped.setdefault(key, []).append(row)
    merged: list[dict[str, Any]] = []
    conflict_count = 0
    for key in sorted(grouped):
        members = grouped[key]
        scopes = {str(item.get("Scope") or "") for item in members}
        payloads = {str(item.get("Payload") or "") for item in members}
        if len(scopes) != 1:
            conflict_count += 1
            continue
        if len(payloads) != 1:
            raise RuntimeError("DetectRaptor uplift payload hash collision detected.")
        representative = min(
            members,
            key=lambda item: (
                str(item.get("SourceRef") or ""),
                str(item.get("Summary") or ""),
            ),
        )
        merged.append(
            {
                **representative,
                "OccurrenceCount": sum(
                    max(1, int(item.get("OccurrenceCount") or 1))
                    for item in members
                ),
            }
        )
    return merged, conflict_count


def _write_detectraptor_uplift_csv(
    path: Path,
    *,
    hunt_id: str,
    analysis_id: str,
    status: str,
    rows: Iterable[Mapping[str, Any]],
) -> str:
    """Atomically publish the only persisted full-payload DetectRaptor output."""
    ordered, _ = _merge_detectraptor_uplift_rows(rows)
    with atomic_io.atomic_text_writer(path, newline="") as handle:
        handle.write(f"# SchemaVersion: {DETECTRAPTOR_UPLIFT_SCHEMA_VERSION}\n")
        handle.write(f"# HuntId: {hunt_id}\n")
        handle.write(f"# AnalysisId: {analysis_id}\n")
        handle.write(f"# Status: {status}\n")
        writer = csv.DictWriter(
            handle,
            fieldnames=list(DETECTRAPTOR_UPLIFT_FIELDS),
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in ordered:
            writer.writerow({field: row.get(field, "") for field in DETECTRAPTOR_UPLIFT_FIELDS})
    return sha256_file(path)


def _read_detectraptor_uplift_csv(
    path: Path,
    *,
    analysis_id: str,
    partition_by_detection: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Read only a compatible candidate file, preserving embedded payload lines."""
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    lines = text.splitlines(keepends=True)
    header_index = next(
        (index for index, line in enumerate(lines) if not line.startswith("#")),
        -1,
    )
    if header_index < 0:
        return []
    metadata: dict[str, str] = {}
    for line in lines[:header_index]:
        key, separator, value = line.removeprefix("#").partition(":")
        if separator:
            metadata[key.strip()] = value.strip()
    if (
        metadata.get("SchemaVersion") != str(DETECTRAPTOR_UPLIFT_SCHEMA_VERSION)
        or metadata.get("AnalysisId") != analysis_id
    ):
        return []
    reader = csv.DictReader(io.StringIO("".join(lines[header_index:])))
    if tuple(reader.fieldnames or ()) != DETECTRAPTOR_UPLIFT_FIELDS:
        return []
    rows: list[dict[str, Any]] = []
    for raw in reader:
        detection = str(raw.get("Detection") or "")
        payload = str(raw.get("Payload") or "")
        partition_id = str(partition_by_detection.get(detection) or "")
        if not partition_id or not payload:
            continue
        rows.append(
            {
                **dict(raw),
                "partition_id": partition_id,
                "OccurrenceCount": max(
                    1, int(raw.get("OccurrenceCount") or 1)
                ),
                "payload_sha256": hashlib.sha256(
                    payload.encode("utf-8")
                ).hexdigest(),
            }
        )
    return rows


def _summarize_detectraptor_uplift_csv(path: Path) -> dict[str, int]:
    """Count candidate scopes without retaining the trailing payload column."""
    summary = {"candidate_count": 0, "global_count": 0, "site_count": 0}
    if not path.is_file():
        return summary
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            while True:
                position = handle.tell()
                line = handle.readline()
                if not line:
                    return summary
                if not line.startswith("#"):
                    handle.seek(position)
                    break
            for row in csv.DictReader(handle):
                summary["candidate_count"] += 1
                scope = str(row.get("Scope") or "").strip()
                if scope == "global":
                    summary["global_count"] += 1
                elif scope == "site":
                    summary["site_count"] += 1
    except (OSError, csv.Error, UnicodeError):
        return {"candidate_count": 0, "global_count": 0, "site_count": 0}
    return summary


def _compact_specialized_text(value: Any) -> str:
    text = " ".join(str(value or "").split()).replace("|", "\\|")
    if len(text) <= MAX_SPECIALIZED_TEXT_CHARS:
        return text
    return text[: MAX_SPECIALIZED_TEXT_CHARS - 1].rstrip() + "…"


def _detectraptor_event_identity(event: Mapping[str, Any]) -> str:
    return str(
        event.get("fqdn")
        or event.get("computer")
        or event.get("client_id")
        or ""
    ).strip()


def _detectraptor_representative_events(
    events: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Select bounded endpoint-diverse context while retaining timeline spread."""
    ordered = sorted(
        (item for item in events if isinstance(item, Mapping)),
        key=lambda item: (
            str(item.get("event_time") or ""),
            _detectraptor_event_identity(item),
            str(item.get("source_ref") or ""),
        ),
    )
    selected: list[dict[str, Any]] = []
    selected_refs: set[str] = set()
    selected_identities: set[str] = set()

    def add(item: Mapping[str, Any]) -> None:
        ref = str(item.get("source_ref") or "")
        identity = _detectraptor_event_identity(item)
        key = ref or json.dumps(dict(item), sort_keys=True, default=str)
        if key in selected_refs:
            return
        selected.append(dict(item))
        selected_refs.add(key)
        if identity:
            selected_identities.add(identity)

    for event in ordered:
        identity = _detectraptor_event_identity(event)
        if identity and identity not in selected_identities:
            add(event)
        if len(selected) >= MAX_DETECTRAPTOR_REPORT_EVENTS:
            return selected
    if ordered:
        for index in (0, len(ordered) // 2, len(ordered) - 1):
            add(ordered[index])
            if len(selected) >= MAX_DETECTRAPTOR_REPORT_EVENTS:
                break
    return selected


def _detectraptor_direct_report_groups(
    recovery: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Expose completed direct-partition findings in a failed progress report."""
    groups: list[dict[str, Any]] = []
    for record in recovery.get("partitions") or []:
        if not isinstance(record, Mapping) or (
            str(record.get("mode") or "") == "exact_stack"
        ):
            continue
        result = record.get("result")
        if not isinstance(result, Mapping):
            continue
        detection = str(record.get("detection") or "<unnamed>")
        for finding in result.get("findings") or []:
            if not isinstance(finding, Mapping):
                continue
            evidence = [
                dict(item)
                for item in finding.get("evidence") or []
                if isinstance(item, Mapping)
            ]
            occurrence_count = sum(
                max(
                    1,
                    int(dict(item.get("fields") or {}).get("OccurrenceCount") or 1),
                )
                for item in evidence
            )
            groups.append(
                {
                    "detection": detection,
                    "confidence": str(finding.get("confidence") or "unknown"),
                    "summary": str(finding.get("summary") or "Reportable finding"),
                    "count": occurrence_count or 1,
                    "events": [],
                    "source_refs": [
                        str(item.get("ref") or "")
                        for item in evidence
                        if item.get("ref")
                    ],
                    "direct_partition": True,
                }
            )
    return groups


def _consolidate_detectraptor_report_groups(
    groups: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Consolidate equivalent assessments while preserving exact evidence scope."""
    consolidated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in groups:
        if not isinstance(raw, Mapping):
            continue
        detection = str(raw.get("detection") or "<unnamed>").strip()
        confidence = str(raw.get("confidence") or "unknown").strip().casefold()
        summary = " ".join(
            str(raw.get("summary") or "Reportable finding").split()
        )
        key = (detection, confidence, summary)
        item = consolidated.setdefault(
            key,
            {
                "detection": detection,
                "confidence": confidence,
                "summary": summary,
                "count": 0,
                "hydrated_count": 0,
                "representative_candidates": [],
                "endpoints": set(),
                "payload_hashes": set(),
                "source_refs": set(),
                "observed": set(),
                "direct_partition": False,
            },
        )
        item["count"] += max(1, int(raw.get("count") or 1))
        events = [
            event
            for event in raw.get("events") or []
            if isinstance(event, Mapping)
        ]
        item["hydrated_count"] += len(events)
        item["representative_candidates"].extend(
            _detectraptor_representative_events(events)
        )
        payload_hash = str(raw.get("payload_sha256") or "").strip()
        if payload_hash:
            item["payload_hashes"].add(payload_hash)
        for source_ref in [raw.get("source_ref"), *(raw.get("source_refs") or [])]:
            if str(source_ref or "").strip():
                item["source_refs"].add(str(source_ref).strip())
        for field in ("first_seen", "last_seen"):
            if str(raw.get(field) or "").strip():
                item["observed"].add(str(raw[field]).strip())
        for event in events:
            identity = _detectraptor_event_identity(event)
            if identity:
                item["endpoints"].add(identity)
            if str(event.get("event_time") or "").strip():
                item["observed"].add(str(event["event_time"]).strip())
        item["direct_partition"] = bool(
            item["direct_partition"] or raw.get("direct_partition")
        )
    return sorted(
        consolidated.values(),
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                str(item["confidence"]), 4
            ),
            -int(item["count"]),
            str(item["detection"]),
            str(item["summary"]),
        ),
    )


def _render_detectraptor_report_notes(
    groups: Iterable[Mapping[str, Any]],
    *,
    context_ledger: str,
) -> list[str]:
    """Render bounded analyst notes without duplicating full event evidence."""
    consolidated = _consolidate_detectraptor_report_groups(groups)
    if not consolidated:
        return ["- No malicious or potentially malicious findings selected yet."]
    lines: list[str] = []
    for item in consolidated[:MAX_DETECTRAPTOR_REPORT_NOTES]:
        confidence = _compact_specialized_text(item["confidence"]).upper()
        summary = _compact_specialized_text(item["summary"])
        lines.extend(
            [
                f"### {confidence} — {_compact_specialized_text(item['detection'])}",
                "",
                summary,
                "",
            ]
        )
        representative_events = _detectraptor_representative_events(
            item["representative_candidates"]
        )
        endpoints = sorted(item["endpoints"])
        occurrence_text = f"- Occurrences: {int(item['count'])}"
        if endpoints:
            occurrence_text += f" across {len(endpoints)} endpoint(s)"
        lines.append(occurrence_text)
        observed = sorted(str(value) for value in item["observed"] if str(value))
        if observed:
            interval = observed[0]
            if observed[-1] != observed[0]:
                interval += f" to {observed[-1]}"
            lines.append(f"- Observed: `{_compact_specialized_text(interval)}`")
        if item["payload_hashes"]:
            lines.append(
                f"- Exact payload variants: {len(item['payload_hashes'])}"
            )
        if item["hydrated_count"]:
            lines.append(
                "- Event context hydrated: "
                f"{int(item['hydrated_count'])}/{int(item['count'])}"
            )
            lines.extend(["", "Representative events:", ""])
            for event in representative_events:
                identity = _detectraptor_event_identity(event) or "unknown endpoint"
                client_id = str(event.get("client_id") or "").strip()
                if client_id and client_id != identity:
                    identity += f" ({client_id})"
                event_type = str(event.get("channel") or "unknown channel")
                if str(event.get("event_id") or "").strip():
                    event_type += f", event {event['event_id']}"
                lines.append(
                    "- "
                    f"`{_compact_specialized_text(event.get('event_time') or 'unknown time')}` "
                    "— "
                    f"`{_compact_specialized_text(identity)}` — "
                    "user "
                    f"`{_compact_specialized_text(event.get('username') or 'unknown')}` "
                    "— "
                    f"{_compact_specialized_text(event_type)} — "
                    "source "
                    f"`{_compact_specialized_text(event.get('source_ref') or '-')}`"
                )
        source_refs = sorted(item["source_refs"])
        if source_refs:
            visible = source_refs[:MAX_DETECTRAPTOR_REPORT_SOURCE_REFS]
            suffix = (
                f", plus {len(source_refs) - len(visible)} more"
                if len(source_refs) > len(visible)
                else ""
            )
            lines.append(
                "- Selected group sources: "
                + ", ".join(f"`{_compact_specialized_text(ref)}`" for ref in visible)
                + suffix
            )
        if context_ledger and item["hydrated_count"]:
            lines.append(
                f"- Full hydrated events: `{_compact_specialized_text(context_ledger)}`"
            )
        lines.append("")
    if len(consolidated) > MAX_DETECTRAPTOR_REPORT_NOTES:
        lines.append(
            f"- {len(consolidated) - MAX_DETECTRAPTOR_REPORT_NOTES} additional "
            "assessment group(s) are retained in the context ledger."
        )
    return lines


def _relative_report_link(value: Any, *, hunt_root: Path) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    path = Path(text)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(hunt_root).as_posix()
    except ValueError:
        return path.name


def _specialized_finding_inputs(
    findings: Iterable[Any],
) -> list[dict[str, Any]]:
    """Create stable exact groups before optional semantic consolidation."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in findings:
        if not isinstance(raw, Mapping):
            continue
        artifact = _compact_specialized_text(raw.get("artifact") or "unknown")
        summary = _compact_specialized_text(
            raw.get("summary") or raw.get("title") or "Finding recorded"
        )
        key = (artifact, summary)
        record = grouped.setdefault(
            key,
            {
                "artifact": artifact,
                "summary": summary,
                "count": 0,
                "review_ids": set(),
            },
        )
        record["count"] += 1
        review_id = str(raw.get("review_id") or "").strip()
        if review_id:
            record["review_ids"].add(review_id)
    ordered = sorted(
        grouped.values(),
        key=lambda item: (-int(item["count"]), item["artifact"], item["summary"]),
    )
    return [
        {
            "source_id": f"S{index}",
            "artifact": item["artifact"],
            "summary": item["summary"],
            "count": int(item["count"]),
            "review_ids": sorted(item["review_ids"]),
        }
        for index, item in enumerate(ordered, start=1)
    ]


def _deterministic_specialized_finding_summary(
    inputs: list[dict[str, Any]],
    *,
    source_hash: str,
    error: str = "",
) -> dict[str, Any]:
    visible = inputs[:MAX_SPECIALIZED_FINDING_INPUT_GROUPS]
    limitations = [
        "Semantic finding consolidation was unavailable; exact normalized summaries "
        "remain separate."
    ]
    if len(inputs) > len(visible):
        limitations.append(
            f"{len(inputs) - len(visible)} exact finding group(s) exceeded the "
            "bounded consolidation input."
        )
    if error:
        limitations.append(_compact_specialized_text(error))
    return {
        "schema_version": 1,
        "source_sha256": source_hash,
        "mode": "deterministic_exact_fallback",
        "status": "complete_with_limitations",
        "source_group_count": len(inputs),
        "covered_source_group_count": len(visible),
        "groups": [
            {
                "summary": item["summary"],
                "artifacts": [item["artifact"]],
                "source_ids": [item["source_id"]],
                "record_count": int(item["count"]),
                "review_ids": list(item["review_ids"]),
            }
            for item in visible
        ],
        "limitations": limitations,
    }


def _parse_specialized_finding_output(
    output: str,
    *,
    source_ids: set[str],
) -> list[dict[str, Any]]:
    records = analyst_line_protocol.tab_records(
        output,
        output_name="specialized finding manager output",
        allowed_records={"GROUP", "SOURCE"},
        trailing_text_fields={"GROUP": 2},
    )
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    seen_sources: set[str] = set()
    for _line_number, fields in records:
        record = fields[0]
        if record == "GROUP":
            if len(fields) != 3:
                raise ValueError("specialized GROUP requires id and summary")
            group_id = fields[1].strip()
            summary = _compact_specialized_text(fields[2])
            if not group_id or not summary or group_id in groups:
                raise ValueError("specialized finding manager GROUP is invalid")
            groups[group_id] = {"summary": summary, "source_ids": []}
            order.append(group_id)
            continue
        if len(fields) != 3:
            raise ValueError("specialized SOURCE requires group id and source id")
        group_id, source_id = fields[1:]
        if group_id not in groups:
            raise ValueError("specialized SOURCE references an unknown GROUP")
        if source_id not in source_ids or source_id in seen_sources:
            raise ValueError("specialized finding manager returned invalid source coverage")
        groups[group_id]["source_ids"].append(source_id)
        seen_sources.add(source_id)
    if not groups or any(not groups[group_id]["source_ids"] for group_id in order):
        raise ValueError("specialized finding manager requires non-empty groups")
    if seen_sources != source_ids:
        raise ValueError("specialized finding manager did not cover every source_id")
    return [groups[group_id] for group_id in order]


async def consolidate_specialized_findings_async(
    state: dict[str, Any],
    *,
    question: str,
    spec: ResolvedAgentExecution | None = None,
    workdir: Path | None = None,
    runtime_dir: Path | None = None,
    execute: Any = None,
) -> dict[str, Any]:
    """Semantically consolidate compact findings without exposing raw rows."""
    inputs = _specialized_finding_inputs(state.get("findings") or [])
    source_hash = _sha256_json(inputs)
    selected_route = spec.route if spec is not None else None
    manager_model = str(
        selected_route.model
        if selected_route is not None
        else "injected"
        if execute
        else ""
    )
    manager_reasoning = str(
        selected_route.reasoning_effort if selected_route is not None else ""
    )
    manager_identity = _sha256_json(
        {
            "contract": "specialized-finding-consolidation-v2",
            "execution_route": (
                selected_route.identity_dict() if selected_route is not None else {}
            ),
        }
    )
    cached = state.get("specialized_finding_summary")
    if (
        isinstance(cached, dict)
        and cached.get("source_sha256") == source_hash
        and dict(cached.get("manager") or {}).get("identity") == manager_identity
        and (
            cached.get("mode") == "semantic_manager"
            or (spec is None and execute is None)
        )
    ):
        telemetry = dict(cached.get("manager") or {})
        telemetry["cache_hit"] = True
        telemetry["cache_hit_count"] = int(telemetry.get("cache_hit_count") or 0) + 1
        telemetry["last_cache_hit_at"] = flow_analysis.now_utc()
        cached["manager"] = telemetry
        return cached
    if not inputs:
        result = {
            "schema_version": 1,
            "source_sha256": source_hash,
            "mode": "no_findings",
            "status": "complete",
            "source_group_count": 0,
            "covered_source_group_count": 0,
            "groups": [],
            "limitations": [],
            "manager": {
                "identity": manager_identity,
                "attempted": False,
                "model": manager_model,
                "reasoning_effort": manager_reasoning,
                "cache_hit": False,
                "cache_hit_count": 0,
                "input_group_count": 0,
                "output_group_count": 0,
                "fallback_reason": "",
            },
        }
        state["specialized_finding_summary"] = result
        return result

    visible = inputs[:MAX_SPECIALIZED_FINDING_INPUT_GROUPS]
    if spec is None and execute is None:
        result = _deterministic_specialized_finding_summary(
            inputs,
            source_hash=source_hash,
        )
        result["manager"] = {
            "identity": manager_identity,
            "attempted": False,
            "model": manager_model,
            "reasoning_effort": manager_reasoning,
            "cache_hit": False,
            "cache_hit_count": 0,
            "input_group_count": len(visible),
            "output_group_count": len(result["groups"]),
            "elapsed_seconds": 0.0,
            "fallback_reason": "manager_not_configured",
        }
        state["specialized_finding_summary"] = result
        return result

    prompt = (
        "You are the final read-only DFIR finding-summary manager. Consolidate "
        "semantically equivalent compact finding summaries. No raw evidence is "
        "present. Preserve materially distinct behaviors. Every source_id must "
        "appear exactly once across groups; never invent a source_id. Return only "
        "tab-delimited records in this grammar:\n"
        "GROUP<TAB>G1<TAB>concise security-relevant summary\n"
        "SOURCE<TAB>G1<TAB>S1\n"
        "Repeat SOURCE for every input source exactly once, then END. Do not return "
        "JSON, Markdown, metadata, or evidence values.\n\n"
        f"Question: {question.strip()}\n"
        "Compact finding groups:\n"
        + "\n".join(
            "\t".join(
                (
                    "INPUT",
                    str(item["source_id"]),
                    _compact_specialized_text(item["artifact"]),
                    str(int(item["count"])),
                    _compact_specialized_text(item["summary"]),
                )
            )
            for item in visible
        )
    )
    task = AgentRequest(
        task_id="specialized-finding-consolidation",
        prompt=prompt,
        output_name="specialized-finding-consolidation.txt",
        metadata={
            "stage": "specialized-finding-consolidation",
            "analysis_routing": analysis_limits.stage_routing(
                "specialized-finding-consolidation"
            ),
        },
    )
    started_at = flow_analysis.now_utc()
    started = time.monotonic()
    fallback_reason = ""
    runner: AgentRunner | None = None
    try:
        if execute is None:
            if spec is None or workdir is None or runtime_dir is None:
                raise RuntimeError("specialized finding manager runtime is incomplete")
            if spec is None:
                raise RuntimeError("resolved analyst execution is required")
            runner = create_agent_runner(
                spec,
                persist_runtime_files=False,
            )
            run_result = await runner.run(
                task,
                workdir=workdir,
                output_dir=runtime_dir,
            )
        else:
            run_result = execute(task)
            if inspect.isawaitable(run_result):
                run_result = await run_result
        if str(run_result.status) != "succeeded":
            raise RuntimeError(run_result.error or "specialized finding manager failed")
        by_id = {item["source_id"]: item for item in visible}
        raw_groups = _parse_specialized_finding_output(
            run_result.output,
            source_ids=set(by_id),
        )
        seen: set[str] = set()
        groups: list[dict[str, Any]] = []
        for raw_group in raw_groups:
            summary = _compact_specialized_text(raw_group.get("summary"))
            source_ids = raw_group.get("source_ids")
            if not summary or not isinstance(source_ids, list) or not source_ids:
                raise ValueError(
                    "specialized finding manager groups require summary and source_ids"
                )
            normalized_ids = [str(value) for value in source_ids]
            if len(normalized_ids) != len(set(normalized_ids)):
                raise ValueError("specialized finding manager repeated a source_id")
            if any(value not in by_id or value in seen for value in normalized_ids):
                raise ValueError(
                    "specialized finding manager returned invalid source coverage"
                )
            seen.update(normalized_ids)
            sources = [by_id[value] for value in normalized_ids]
            groups.append(
                {
                    "summary": summary,
                    "artifacts": sorted({item["artifact"] for item in sources}),
                    "source_ids": normalized_ids,
                    "record_count": sum(int(item["count"]) for item in sources),
                    "review_ids": sorted(
                        {
                            review_id
                            for item in sources
                            for review_id in item["review_ids"]
                        }
                    ),
                }
            )
        if seen != set(by_id):
            raise ValueError(
                "specialized finding manager did not cover every source_id"
            )
        limitations: list[str] = []
        if len(inputs) > len(visible):
            limitations.append(
                f"{len(inputs) - len(visible)} exact finding group(s) exceeded the "
                "bounded semantic consolidation input."
            )
        result = {
            "schema_version": 1,
            "source_sha256": source_hash,
            "mode": "semantic_manager",
            "status": "complete" if not limitations else "complete_with_limitations",
            "source_group_count": len(inputs),
            "covered_source_group_count": len(visible),
            "groups": sorted(
                groups,
                key=lambda item: (-int(item["record_count"]), item["summary"]),
            ),
            "limitations": limitations,
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        fallback_reason = _compact_specialized_text(exc)
        result = _deterministic_specialized_finding_summary(
            inputs,
            source_hash=source_hash,
            error=f"Manager error: {exc}",
        )
    finally:
        if runner is not None:
            close_result = runner.close()
            if inspect.isawaitable(close_result):
                await close_result
        if runtime_dir is not None:
            try:
                runtime_dir.rmdir()
            except OSError:
                pass
    result["manager"] = {
        "identity": manager_identity,
        "attempted": True,
        "model": manager_model,
        "reasoning_effort": manager_reasoning,
        "cache_hit": False,
        "cache_hit_count": 0,
        "started_at": started_at,
        "completed_at": flow_analysis.now_utc(),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "input_group_count": len(visible),
        "output_group_count": len(result.get("groups") or []),
        "fallback_reason": fallback_reason,
    }
    state["specialized_finding_summary"] = result
    return result


def consolidate_specialized_findings(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return asyncio.run(consolidate_specialized_findings_async(*args, **kwargs))


def load_state(
    path: Path,
    *,
    scope_type: str,
    scope_id: str,
    analysis_id: str,
) -> dict[str, Any]:
    specialized: dict[str, Any] = {}
    if not path.is_file():
        return flow_analysis.initial_state(
            scope_type=scope_type,
            scope_id=scope_id,
            analysis_id=analysis_id,
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Flow-analysis state is not an object: {path}")
    if (
        int(payload.get("schema_version") or 0) == flow_analysis.SCHEMA_VERSION
        and isinstance(payload.get("specialized_analysis"), dict)
    ):
        specialized = copy.deepcopy(payload["specialized_analysis"])
    if (
        str(payload.get("scope_type") or "") != scope_type
        or str(payload.get("scope_id") or "") != scope_id
        or str(payload.get("analysis_id") or "") != analysis_id
    ):
        rebuilt = flow_analysis.initial_state(
            scope_type=scope_type,
            scope_id=scope_id,
            analysis_id=analysis_id,
        )
        if specialized:
            rebuilt["specialized_analysis"] = specialized
        return rebuilt
    schema_version = int(payload.get("schema_version") or 0)
    if schema_version != flow_analysis.SCHEMA_VERSION:
        rebuilt = flow_analysis.initial_state(
            scope_type=scope_type,
            scope_id=scope_id,
            analysis_id=analysis_id,
        )
        return rebuilt
    compact_persisted_evidence(payload)
    return payload


def archive_incompatible_state(path: Path, *, analysis_id: str) -> Path | None:
    """Preserve prior-schema or prior-identity state before replacement."""
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Flow-analysis state is not an object: {path}")
    previous_analysis_id = str(payload.get("analysis_id") or "")
    schema_version = int(payload.get("schema_version") or 0)
    if (
        schema_version == flow_analysis.SCHEMA_VERSION
        and previous_analysis_id == analysis_id
    ):
        return None
    active = payload.get("active_analysis")
    active_run_id = (
        str(active.get("run_id") or "") if isinstance(active, Mapping) else ""
    )
    prior_runs = [
        str(item.get("run_id") or "")
        for item in payload.get("runs") or []
        if isinstance(item, Mapping) and str(item.get("run_id") or "")
    ]
    previous_run_id = active_run_id or (prior_runs[-1] if prior_runs else "")
    if not previous_run_id:
        previous_run_id = "legacy-" + _sha256_bytes(text.encode("utf-8"))[:12]
    destination = (
        path.parent
        / "runs"
        / _safe_output_component(
            previous_analysis_id,
            fallback=f"schema-{schema_version or 'unknown'}",
        )
        / _safe_output_component(previous_run_id, fallback="unknown-run")
        / path.name
    )
    if not destination.exists():
        atomic_io.write_text_atomic(destination, text)
    return destination


def write_state(path: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = flow_analysis.now_utc()
    persisted = copy.deepcopy(state)
    if isinstance(persisted.get("detectraptor_stack"), Mapping):
        checkpoint = persisted.get("checkpoint")
        if isinstance(checkpoint, dict) and isinstance(
            checkpoint.get("result"), Mapping
        ):
            checkpoint["result"] = _compact_detectraptor_recovery_result(
                checkpoint["result"]
            )
            checkpoint["result_sha256"] = _sha256_json(checkpoint["result"])
        for container in (checkpoint, persisted.get("partial_candidates")):
            if isinstance(container, dict) and isinstance(container.get("accepted_result"), Mapping):
                container["accepted_result"] = _compact_detectraptor_recovery_result(container["accepted_result"])
                limitation = "DetectRaptor event identities and payloads remain in the separate context ledger; checkpoint fields are reduced."
                limitations = container["accepted_result"].setdefault("limitations", [])
                if limitation not in limitations:
                    limitations.append(limitation)
                container["accepted_fingerprint"] = synthesis_policy.fingerprint(container["accepted_result"])
    compact_persisted_evidence(persisted)
    atomic_io.write_json_atomic(path, persisted, sort_keys=True)


def _compact_synthesis_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Retain complete findings/provenance without raw or full evidence rows."""
    source = copy.deepcopy(dict(value))
    retained = {
        key: source[key]
        for key in (
            "format",
            "task",
            "task_id",
            "artifact",
            "question",
            "status",
            "coverage",
            "answer",
            "limitations",
            "bounded_follow_up",
            "domain_assessments",
            "analysis_status", "review_status", "synthesis_mode", "result_role", "groups",
        )
        if key in source
    }
    findings: list[dict[str, Any]] = []
    for raw_finding in source.get("findings") or []:
        if not isinstance(raw_finding, Mapping):
            continue
        finding = {
            key: copy.deepcopy(raw_finding[key])
            for key in ("id", "artifact", "confidence", "domains", "summary")
            if key in raw_finding
        }
        evidence_rows: list[dict[str, Any]] = []
        for raw_evidence in raw_finding.get("evidence") or []:
            if not isinstance(raw_evidence, Mapping):
                continue
            evidence = {
                key: copy.deepcopy(raw_evidence[key])
                for key in ("artifact", "ref", "source", "chunk_index", "chunk_count")
                if key in raw_evidence
            }
            fields = analysis_summary.preview_fields(
                dict(raw_evidence.get("fields") or {})
            )
            if fields:
                evidence["fields"] = fields
            evidence_rows.append(evidence)
        finding["evidence"] = evidence_rows
        findings.append(finding)
    retained["findings"] = findings

    relevant_context: list[Any] = []
    for raw_context in source.get("relevant_context") or []:
        if not isinstance(raw_context, Mapping):
            relevant_context.append(str(raw_context))
            continue
        context = {
            key: copy.deepcopy(raw_context[key])
            for key in ("artifact", "kind", "ref", "summary", "source", "finding_id", "context_type", "chunk_index", "chunk_count")
            if key in raw_context
        }
        fields = analysis_summary.preview_fields(
            dict(raw_context.get("fields") or {})
        )
        if fields:
            context["fields"] = fields
        relevant_context.append(context)
    retained["relevant_context"] = relevant_context
    retained["limitations"] = list(retained.get("limitations") or [])
    retained["bounded_follow_up"] = list(retained.get("bounded_follow_up") or [])
    return retained


_DETECTRAPTOR_RECOVERY_FIELD_ALLOWLIST = {
    "Detection",
    "OccurrenceCount",
    "FirstSeen",
    "LastSeen",
    "PayloadField",
}


def _compact_detectraptor_recovery_result(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Retain resumable classifications without identities or source payloads."""
    result = _compact_synthesis_result(value)
    for finding in result.get("findings") or []:
        for evidence in finding.get("evidence") or []:
            evidence.pop("source", None)
            fields = evidence.get("fields")
            if isinstance(fields, dict):
                evidence["fields"] = {
                    key: field_value
                    for key, field_value in fields.items()
                    if str(key) in _DETECTRAPTOR_RECOVERY_FIELD_ALLOWLIST
                }
    for context in result.get("relevant_context") or []:
        if not isinstance(context, dict):
            continue
        context.pop("source", None)
        fields = context.get("fields")
        if isinstance(fields, dict):
            context["fields"] = {
                key: field_value
                for key, field_value in fields.items()
                if str(key) in _DETECTRAPTOR_RECOVERY_FIELD_ALLOWLIST
            }
    return result


def _compact_detectraptor_recovery(value: Mapping[str, Any]) -> dict[str, Any]:
    """Bound resumable EVTX control state without retaining source payloads."""
    recovery = {
        key: copy.deepcopy(value[key])
        for key in (
            "schema_version",
            "contract_sha256",
            "created_at",
            "updated_at",
        )
        if key in value
    }
    raw_contract = value.get("contract")
    if isinstance(raw_contract, Mapping):
        contract = {
            key: copy.deepcopy(raw_contract[key])
            for key in (
                "analysis_id",
                "server_scope",
                "org_id",
                "hunt_id",
                "artifact",
                "detection_regex",
                "profile_sha256",
                "discovery_query_sha256",
                "query_contract_sha256",
            )
            if key in raw_contract
        }
        time_scope = raw_contract.get("time_scope")
        if isinstance(time_scope, Mapping):
            contract["time_scope"] = {
                key: copy.deepcopy(time_scope[key])
                for key in ("mode", "after", "before", "fields")
                if key in time_scope
            }
        recovery["contract"] = contract
    compact_partitions: list[dict[str, Any]] = []
    for raw in value.get("partitions") or []:
        if not isinstance(raw, Mapping):
            continue
        partition = {
            key: copy.deepcopy(raw[key])
            for key in (
                "partition_id",
                "detection",
                "status",
                "stage",
                "attempt",
                "discovered_row_count",
                "acquired_row_count",
                "model_row_count",
                "group_count",
                "uplift_candidate_count",
                "mode",
                "provisional",
                "started_at",
                "completed_at",
                "heartbeat_at",
                "interrupted_at",
                "failure_type",
                "failure_reason",
            )
            if key in raw
        }
        census = raw.get("census")
        if isinstance(census, Mapping):
            partition["census"] = {
                key: copy.deepcopy(census[key])
                for key in (
                    "row_count",
                    "group_count",
                    "singleton_group_count",
                    "largest_group_rows",
                    "query_sha256",
                )
                if key in census
            }
        raw_query_hashes = raw.get("query_hashes")
        if isinstance(raw_query_hashes, Mapping):
            query_hashes = {}
            for key in ("census", "initial_analysis", "context_hydration"):
                raw_hash = raw_query_hashes.get(key)
                if isinstance(raw_hash, Sequence) and not isinstance(raw_hash, str):
                    query_hashes[key] = [str(value) for value in raw_hash if str(value)]
                elif raw_hash:
                    query_hashes[key] = str(raw_hash)
            partition["query_hashes"] = query_hashes
        selected_source_refs = sorted(
            {
                str(source_ref)
                for source_ref in raw.get("selected_source_refs") or []
                if str(source_ref)
            }
        )[:10_000]
        partition["selected_source_refs"] = selected_source_refs
        errors = [
            {
                key: copy.deepcopy(error[key])
                for key in (
                    "stage",
                    "attempt",
                    "status",
                    "error_class",
                    "elapsed_seconds",
                    "rows_received",
                    "retry_delay_seconds",
                )
                if key in error
            }
            for error in raw.get("transport_errors") or []
            if isinstance(error, Mapping)
        ]
        partition["transport_errors"] = errors[-MAX_DETECTRAPTOR_TRANSPORT_ERRORS:]
        query_diagnostics = [
            {
                key: copy.deepcopy(diagnostic[key])
                for key in (
                    "stage",
                    "attempt",
                    "status",
                    "error_class",
                    "elapsed_seconds",
                    "rows_received",
                    "retry_delay_seconds",
                )
                if key in diagnostic
            }
            for diagnostic in raw.get("query_diagnostics") or []
            if isinstance(diagnostic, Mapping)
        ]
        partition["query_diagnostics"] = query_diagnostics[
            -MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:
        ]
        result_keys = (
            ("result",)
            if str(raw.get("status") or "") == "completed"
            else ("initial_result",)
        )
        for result_key in result_keys:
            result = raw.get(result_key)
            if isinstance(result, Mapping):
                partition[result_key] = _compact_detectraptor_recovery_result(result)
                partition[f"{result_key}_sha256"] = _sha256_json(
                    partition[result_key]
                )
        compact_partitions.append(partition)
    recovery["partitions"] = compact_partitions
    return recovery


def _deduplicate_runs(values: Iterable[Any]) -> list[dict[str, Any]]:
    ordered_ids: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(values):
        if not isinstance(raw, Mapping):
            continue
        record = dict(raw)
        run_id = str(record.get("run_id") or f"run-{index}")
        existing = by_id.get(run_id)
        if existing is None:
            record["run_id"] = run_id
            record.setdefault("observation_count", 1)
            record.setdefault("first_started_at", str(record.get("started_at") or ""))
            record.setdefault(
                "last_completed_at", str(record.get("completed_at") or "")
            )
            by_id[run_id] = record
            ordered_ids.append(run_id)
            continue
        first_started = str(
            existing.get("first_started_at") or existing.get("started_at") or ""
        )
        observation_count = int(existing.get("observation_count") or 1) + int(
            record.get("observation_count") or 1
        )
        existing.update(record)
        existing["first_started_at"] = first_started
        existing["last_completed_at"] = str(record.get("completed_at") or "")
        existing["observation_count"] = observation_count
    return [by_id[run_id] for run_id in ordered_ids[-MAX_RUN_RECORDS:]]


def _terminalize_unhandled_active_analysis(
    state_path: Path,
    error: Exception,
    *,
    preexisting_running_run_id: str = "",
    preexisting_running_started_at: str = "",
) -> bool:
    """Fail a still-running analysis after its normal cleanup callbacks finish."""
    if not state_path.is_file():
        return False
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(state, dict):
        return False
    active = state.get("active_analysis")
    if not isinstance(active, dict) or str(active.get("status") or "") != "running":
        return False
    if (
        preexisting_running_run_id
        and str(active.get("run_id") or "") == preexisting_running_run_id
        and (
            not preexisting_running_started_at
            or str(active.get("started_at") or "")
            == preexisting_running_started_at
        )
    ):
        return False
    phase = str(active.get("phase") or "unknown")
    failure_stage = {
        "inventory_complete": "source_setup",
        "acquiring_results": "acquisition",
        "chunk_analysis": "row_accounting_or_chunk_analysis",
        "reconciling_accounting": "row_accounting",
        "cumulative_synthesis": "cumulative_synthesis",
        "publishing": "publishing",
    }.get(phase, "unhandled_runtime")
    completed_at = flow_analysis.now_utc()
    failure_reason = f"Unhandled {type(error).__name__}"
    active.update(
        {
            "status": "failed",
            "phase": "failed",
            "completed_at": completed_at,
            "heartbeat_at": completed_at,
            "failure_stage": failure_stage,
            "failure_reason": failure_reason,
        }
    )
    run_record = {
        key: copy.deepcopy(active[key])
        for key in (
            "run_id",
            "method",
            "started_at",
            "server_cutoff",
            "time_scope",
            "inventory_flow_count",
            "candidate_flow_count",
            "acquired_row_count",
            "emitted_chunk_count",
            "planned_chunk_count",
            "submitted_chunk_count",
            "completed_chunk_count",
            "abandoned_chunk_count",
            "accepted_chunk_count",
            "failed_chunk_count",
        )
        if key in active
    }
    run_record.update(
        {
            "status": "failed",
            "completed_at": completed_at,
            "failure_stage": failure_stage,
            "failure_reason": failure_reason,
        }
    )
    state["runs"] = _deduplicate_runs(
        [*list(state.get("runs") or []), run_record]
    )
    write_state(state_path, state)
    return True


def _verify_completed_hunt_publication(
    state_path: Path,
    result: Mapping[str, Any],
    *,
    debug_validation: bool,
) -> None:
    """Verify terminal state after the shared scheduler has fully closed."""
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Post-cleanup hunt publication verification could not read state."
        ) from exc
    if not isinstance(state, Mapping):
        raise RuntimeError(
            "Post-cleanup hunt publication verification found invalid state."
        )

    failures: list[str] = []
    if int(state.get("schema_version") or 0) != flow_analysis.SCHEMA_VERSION:
        failures.append("schema")
    if isinstance(state.get("active_analysis"), Mapping):
        failures.append("active_analysis")

    checkpoint = state.get("checkpoint")
    if not isinstance(checkpoint, Mapping):
        checkpoint = {}
    if int(checkpoint.get("generation") or 0) <= 0:
        failures.append("checkpoint_generation")
    if not isinstance(checkpoint.get("result"), Mapping):
        failures.append("checkpoint_result")
    if str(checkpoint.get("method") or "") != str(
        result.get("analysis_method") or ""
    ):
        failures.append("checkpoint_method")

    run_id = str(result.get("run_id") or "")
    matching_run = next(
        (
            dict(item)
            for item in reversed(list(state.get("runs") or []))
            if isinstance(item, Mapping) and str(item.get("run_id") or "") == run_id
        ),
        {},
    )
    if not run_id or not matching_run:
        failures.append("run_record")
    else:
        expected_counts = {
            "acquired_row_count": "accounted_row_count",
            "model_input_row_count": "reviewed_row_count",
            "emitted_chunk_count": "emitted_chunk_count",
            "accepted_chunk_count": "accepted_chunk_count",
            "failed_chunk_count": "failed_chunk_count",
        }
        for state_key, result_key in expected_counts.items():
            if int(matching_run.get(state_key) or 0) != int(
                result.get(result_key) or 0
            ):
                failures.append(state_key)
        if str(matching_run.get("status") or "") != str(
            result.get("synthesis_status") or ""
        ):
            failures.append("run_status")

    coverage = dict(state.get("coverage") or {})
    expected_coverage = {
        "overall": result.get("status"),
        "result_review": result.get("result_review_coverage"),
        "target_execution": result.get("target_execution_coverage"),
    }
    for key, value in expected_coverage.items():
        if str(coverage.get(key) or "") != str(value or ""):
            failures.append(f"coverage_{key}")

    if debug_validation:
        debug_reference = dict(state.get("last_validation_debug") or {})
        debug_path = Path(str(result.get("validation_debug_file") or ""))
        if (
            not debug_path.is_file()
            or str(debug_reference.get("path") or "") != str(debug_path)
            or str(debug_reference.get("run_id") or "") != run_id
            or not bool(debug_reference.get("current_run"))
            or str(debug_reference.get("status") or "")
            != str(result.get("synthesis_status") or "")
        ):
            failures.append("validation_debug_reference")
        elif str(debug_reference.get("sha256") or "") != sha256_file(
            debug_path
        ):
            failures.append("validation_debug_hash")

    if failures:
        raise RuntimeError(
            "Post-cleanup hunt publication verification failed: "
            + ", ".join(sorted(set(failures)))
            + "."
        )


def _bounded_synthesis_failures(
    synthesis: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Retain bounded synthesis diagnostics without model output or evidence."""
    failures: list[dict[str, str]] = []
    for raw in synthesis.get("tasks") or []:
        if not isinstance(raw, Mapping):
            continue
        status = str(raw.get("status") or "")
        if status == "accepted":
            continue
        error = str(raw.get("error") or "").strip()
        if not error:
            continue
        failures.append(
            {
                "task_id": str(raw.get("task_id") or ""),
                "stage": str(raw.get("stage") or ""),
                "error": error[:MAX_FAILED_CHUNK_ERROR_CHARS],
            }
        )
        if len(failures) >= MAX_SYNTHESIS_FAILURES:
            break
    if failures:
        return failures

    host_result = synthesis.get("host_result")
    if not isinstance(host_result, Mapping):
        return []
    for value in host_result.get("limitations") or []:
        error = str(value or "").strip()
        if not error:
            continue
        failures.append(
            {
                "task_id": "hunt-analysis-synthesis",
                "stage": "hunt-synthesis",
                "error": error[:MAX_FAILED_CHUNK_ERROR_CHARS],
            }
        )
        if len(failures) >= MAX_SYNTHESIS_FAILURES:
            break
    return failures


_SAFE_DEBUG_IDENTIFIER = re.compile(r"^_?[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_SAFE_DEBUG_REFERENCE = re.compile(r"^S[0-9]{4,}-R[1-9][0-9]*$")
_SAFE_DEBUG_RECORDS = {
    "FINDING",
    "CONTEXT",
    "EVIDENCE",
}


def _debug_hash(value: Any) -> str:
    return _sha256_bytes(str(value or "").encode("utf-8"))


def _bounded_debug_text(value: Any) -> str:
    return " ".join(str(value or "").split())[:MAX_VALIDATION_DEBUG_TEXT_CHARS]


def _safe_validation_debug_diagnostic(raw: Any) -> dict[str, Any]:
    """Retain schema diagnostics without persisting evidence-like values."""
    if not isinstance(raw, Mapping):
        return {"code": "unstructured_diagnostic", "sha256": _debug_hash(raw)}
    code = _bounded_debug_text(raw.get("code") or "unknown")
    result: dict[str, Any] = {"code": code}
    record = str(raw.get("record") or "")
    if record in _SAFE_DEBUG_RECORDS:
        result["record"] = record
    finding_id = str(raw.get("finding_id") or "")
    if _SAFE_DEBUG_IDENTIFIER.fullmatch(finding_id):
        result["finding_id"] = finding_id
    try:
        line = int(raw.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    if line > 0:
        result["line"] = line

    field = str(raw.get("field") or "")
    if field:
        field_is_safe = bool(_SAFE_DEBUG_IDENTIFIER.fullmatch(field)) and (
            code in {"internal_field", "unpopulated_field"}
            or field.startswith("_")
        )
        if field_is_safe:
            result["field"] = field
        else:
            result["field_sha256"] = _debug_hash(field)
            result["field_length"] = len(field)

    ref = str(raw.get("ref") or "")
    if ref:
        if _SAFE_DEBUG_REFERENCE.fullmatch(ref):
            result["ref"] = ref
        else:
            result["ref_sha256"] = _debug_hash(ref)
            result["ref_length"] = len(ref)

    unknown_fields = raw.get("fields")
    if isinstance(unknown_fields, list):
        result["field_hashes"] = sorted(
            {_debug_hash(value) for value in unknown_fields if str(value)}
        )[:MAX_VALIDATION_DEBUG_DETAILS_PER_ATTEMPT]
    value = str(raw.get("value") or "")
    if value:
        result["value_sha256"] = _debug_hash(value)
        result["value_length"] = len(value)
    if code == "unsupported_tactic":
        result["allowed"] = list(collection_analysis.ATTACK_TACTICS)
    elif code in {"unsupported_evidence_tactic", "unsupported_record"}:
        safe_allowed = {
            *collection_analysis.ATTACK_TACTICS,
            "FINDING",
            "EVIDENCE",
        }
        result["allowed"] = [
            str(item)
            for item in raw.get("allowed") or []
            if str(item) in safe_allowed
        ]
    return result


def validation_debug_attempt(
    event: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    failure_type = str(event.get("failure_type") or "unknown_failure")
    error = str(event.get("error") or "chunk analysis failed")
    stage = str(event.get("stage") or "chunk")
    if failure_type.endswith("validation_failed"):
        safe_error = (
            "synthesis result failed deterministic validation"
            if stage == "hunt-synthesis"
            else "worker result failed deterministic validation"
        )
    elif failure_type == "executor_error":
        safe_error = "executor raised an exception"
    else:
        safe_error = _bounded_debug_text(error)
    record: dict[str, Any] = {
        "chunk_id": str(event.get("chunk_id") or ""),
        "ordinal": int(manifest.get("ordinal") or 0),
        "artifact": str(manifest.get("artifact") or "unknown"),
        "row_count": int(manifest.get("row_count") or 0),
        "input_tokens": int(manifest.get("input_tokens") or 0),
        "attempt": max(1, int(event.get("attempt") or 1)),
        "status": str(event.get("status") or "failed"),
        "failure_type": failure_type,
        "error": safe_error,
    }
    if failure_type == "executor_error":
        record["error_sha256"] = _debug_hash(error)
        record["error_length"] = len(error)
    if _SAFE_DEBUG_IDENTIFIER.fullmatch(stage):
        record["stage"] = stage
    for key in ("response_sha256",):
        value = str(event.get(key) or "")
        if re.fullmatch(r"[0-9a-f]{64}", value):
            record[key] = value
    error_class = str(event.get("error_class") or "")
    if _SAFE_DEBUG_IDENTIFIER.fullmatch(error_class):
        record["error_class"] = error_class
    for source_key, destination_key in (
        ("diagnostics", "diagnostics"),
    ):
        details = [
            _safe_validation_debug_diagnostic(item)
            for item in event.get(source_key) or []
        ][:MAX_VALIDATION_DEBUG_DETAILS_PER_ATTEMPT]
        if details:
            record[destination_key] = details
    return record


def write_validation_debug(
    path: Path,
    base: Mapping[str, Any],
    attempts: Iterable[Mapping[str, Any]],
    *,
    status: str,
    completed_at: str = "",
) -> dict[str, Any]:
    """Atomically replace one bounded, value-free validation debug manifest."""
    session = agent_diagnostics.session_for_path(path)
    if session is not None:
        return session.update_validation(
            base,
            attempts,
            status=status,
            completed_at=completed_at,
        )
    temporary = agent_diagnostics.DebugSession(
        path,
        scope_type=str(base.get("scope_type") or "analysis"),
        scope_id=str(base.get("scope_id") or "unknown"),
        lane=str(base.get("lane") or "validation"),
        request_id=str(base.get("request_id") or ""),
        run_id=str(base.get("run_id") or ""),
    )
    with temporary:
        return temporary.update_validation(
            base,
            attempts,
            status=status,
            completed_at=completed_at,
        )


def _compact_chunk_attempt_failure(
    *,
    attempt: int,
    status: str,
    failure_type: str,
    error: Any,
    diagnostics: Iterable[Any] = (),
) -> dict[str, Any]:
    """Return a bounded, value-free record for one unsuccessful attempt."""
    diagnostic_codes = sorted(
        {
            str(item.get("code") or "")
            for item in diagnostics
            if isinstance(item, Mapping) and str(item.get("code") or "")
        }
    )[:MAX_FAILED_CHUNK_DIAGNOSTIC_CODES]
    error_text = str(error or "chunk analysis failed").strip()
    if failure_type == "validation_failed":
        error_text = "worker result failed deterministic validation"
    result = {
        "attempt": max(1, int(attempt or 1)),
        "status": status if status in {"repaired", "retrying"} else "failed",
        "failure_type": str(failure_type or "unknown_failure"),
        "error": error_text[:MAX_FAILED_CHUNK_ATTEMPT_ERROR_CHARS],
        "diagnostic_codes": diagnostic_codes,
    }
    return result


def _bounded_chunk_attempt_failures(
    outcomes: Iterable[Mapping[str, Any]],
    manifests: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Compact unsuccessful attempt history for the persisted run record."""
    records: list[dict[str, Any]] = []
    for outcome in outcomes:
        chunk_id = str(outcome.get("chunk_id") or "")
        manifest = dict(manifests.get(chunk_id) or {})
        raw_failures = [
            dict(item)
            for item in outcome.get("attempt_failures") or []
            if isinstance(item, Mapping)
        ]
        if not raw_failures and str(outcome.get("status") or "") == "failed":
            raw_failures = [
                {
                    "attempt": int(outcome.get("attempts") or 1),
                    "status": "failed",
                    "failure_type": "unknown_failure",
                    "error": str(outcome.get("error") or "chunk analysis failed"),
                    "diagnostic_codes": [],
                }
            ]
        for raw in raw_failures:
            compact = _compact_chunk_attempt_failure(
                attempt=int(raw.get("attempt") or 1),
                status=str(raw.get("status") or "failed"),
                failure_type=str(raw.get("failure_type") or "unknown_failure"),
                error=raw.get("error") or "chunk analysis failed",
                diagnostics=[
                    {"code": value}
                    for value in raw.get("diagnostic_codes") or []
                    if str(value)
                ],
            )
            records.append(
                {
                    "chunk_id": chunk_id,
                    "ordinal": int(manifest.get("ordinal") or 0),
                    "artifact": str(manifest.get("artifact") or "unknown"),
                    "row_count": int(manifest.get("row_count") or 0),
                    "input_tokens": int(manifest.get("input_tokens") or 0),
                    **compact,
                }
            )
    records.sort(
        key=lambda item: (
            int(item["ordinal"]),
            str(item["chunk_id"]),
            int(item["attempt"]),
        )
    )
    total = len(records)
    return records[:MAX_FAILED_CHUNK_ATTEMPTS_PER_RUN], total


def compact_persisted_evidence(state: dict[str, Any]) -> None:
    """Persist only the schema-6 checkpoint, cursor, aliases, coverage and runs."""
    checkpoint = state.get("checkpoint")
    if not isinstance(checkpoint, dict):
        checkpoint = {}
        state["checkpoint"] = checkpoint
    result = checkpoint.get("result")
    if isinstance(result, Mapping):
        checkpoint["result"] = _compact_synthesis_result(result)
        checkpoint["result_sha256"] = _sha256_json(checkpoint["result"])
        if checkpoint["result"].get("review_status") == "not_requested" and checkpoint.get("accepted_result") == checkpoint["result"]:
            checkpoint.pop("accepted_result")
    state["source_aliases"] = dict(
        sorted(dict(state.get("source_aliases") or {}).items())
    )
    state["runs"] = _deduplicate_runs(state.get("runs") or [])
    recovery = state.get("detectraptor_recovery")
    if isinstance(recovery, Mapping):
        state["detectraptor_recovery"] = _compact_detectraptor_recovery(recovery)
    for key in (
        "sources",
        "segments",
        "chunks",
        "pending_synthesis_results",
        "synthesis_checkpoint",
        "hunt_result",
        "findings",
        "analysis_summary",
        "state_validation",
    ):
        state.pop(key, None)


def retire_specialized_analysis(
    state: dict[str, Any],
    artifacts: Iterable[str],
) -> list[str]:
    """Remove a superseded specialized analysis only when it is fully in scope."""
    requested = {
        str(artifact).strip()
        for artifact in artifacts
        if str(artifact).strip()
    }
    specialized = state.get("specialized_analysis")
    if not requested or not isinstance(specialized, Mapping):
        return []
    specialized_artifacts = {
        str(artifact).strip()
        for artifact in dict(specialized.get("artifacts") or {})
        if str(artifact).strip()
    }
    if not specialized_artifacts or not specialized_artifacts.issubset(requested):
        return []
    state.pop("specialized_analysis", None)
    return sorted(specialized_artifacts)


def _profile_for_artifact(
    artifact: str,
    profiles: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any] | None:
    profile_map = profiles if isinstance(profiles, dict) else dict(profiles)
    return artifact_profiles.resolve_profile(artifact, profile_map)


def _profile_for_source(
    source: flow_analysis.FlowSource,
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    return _profile_for_artifact(source.artifact, profiles)


def _live_projections(
    artifacts: Iterable[str],
    profiles: Mapping[str, Mapping[str, Any]],
    time_scopes: Mapping[str, analysis_time_scope.ResolvedTimeScope],
) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for artifact in artifacts:
        profile = _profile_for_artifact(artifact, profiles)
        review = dict((profile or {}).get("review") or {})
        expressions = [
            str(value).strip()
            for value in review.get("live_vql_select") or []
            if str(value).strip()
        ]
        resolved = time_scopes.get(artifact)
        if resolved is not None:
            for role in resolved.roles:
                for expression in resolved.expressions[role]:
                    root = str(expression).split(".", 1)[0]
                    if root and root not in expressions:
                        expressions.append(root)
        if expressions:
            output[artifact] = expressions
    return output


def profile_identity(
    sources: Sequence[flow_analysis.FlowSource],
    profiles: dict[str, dict[str, Any]],
    *,
    artifact_names: Iterable[str] = (),
) -> str:
    names = {
        str(value)
        for value in artifact_names
        if str(value).strip()
    } or {source.artifact for source in sources}
    return _sha256_json(
        sorted(
            {
                flow_analysis.canonical_json(
                    {
                        "artifact": artifact,
                        "profile_hash": str(
                            (
                                _profile_for_artifact(artifact, profiles)
                                or {}
                            ).get("_profile_hash")
                            or "fallback-all-fields"
                        ),
                    }
                )
                for artifact in names
            }
        )
    )


def analysis_id_for(
    *,
    scope_type: str,
    question: str,
    profile_hash: str,
    policy_limits: Mapping[str, Any],
    spec: ResolvedAgentExecution,
    task_mode: str = "targeted_hunt",
    response_depth: str = "standard",
    time_scope: analysis_time_scope.TimeScope | None = None,
    runtime_scope: Mapping[str, Any] | None = None,
) -> str:
    return flow_analysis.analysis_identity(
        scope_type=scope_type,
        question=question,
        profile_hash=profile_hash,
        runtime_policy={
            "limits": dict(policy_limits),
            "agent": analyst_execution_identity(spec),
            "logical_segment_rows": flow_analysis.DEFAULT_SEGMENT_ROWS,
            "time_scope": (time_scope or analysis_time_scope.TimeScope("all")).canonical(),
            "runtime_scope": dict(runtime_scope or {}),
            "task_mode": task_mode,
            "response_depth": response_depth,
        },
        output_contract=OUTPUT_CONTRACT,
    )


def _project_segment(
    segment: flow_analysis_runtime.AcquiredSegment,
    profiles: dict[str, dict[str, Any]],
    source_reference: Mapping[str, Any],
    client_identities: Mapping[str, Mapping[str, str]] | None = None,
    flow_ids_by_client: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], str]:
    profile = _profile_for_source(segment.source, profiles)
    preferred = artifact_profiles.analysis_fields(profile)
    field_sources = collection_analysis.profile_field_sources(profile)
    projected, fields = collection_analysis.project_rows(
        segment.rows,
        source_alias=str(source_reference["alias"]),
        artifact=segment.source.artifact,
        component=segment.source.source or segment.source.artifact,
        flow_id=segment.source.flow_id,
        preferred_fields=preferred,
        field_sources=field_sources,
        row_offset=segment.row_start,
    )
    for index, row in enumerate(projected):
        client_id = str(
            row.get("_SourceClientId")
            or row.get("_ClientId")
            or row.get("ClientId")
            or row.get("client_id")
            or segment.source.client_id
        )
        if not client_id:
            row_names = {
                str(row.get(key) or "").strip().casefold()
                for key in ("_Hostname", "Hostname", "_Fqdn", "Fqdn")
                if str(row.get(key) or "").strip()
            }
            matches = [
                candidate_id
                for candidate_id, raw_identity in dict(
                    client_identities or {}
                ).items()
                if row_names.intersection(
                    {
                        str(raw_identity.get("hostname") or "").strip().casefold(),
                        str(raw_identity.get("fqdn") or "").strip().casefold(),
                    }
                    - {""}
                )
            ]
            if len(matches) == 1:
                client_id = str(matches[0])
        row["_ClientId"] = client_id
        projected_flow_id = str(
            row.get("_SourceFlowId")
            or row.get("FlowId")
            or row.get("flow_id")
            or row.get("_FlowId")
            or ""
        )
        if (
            segment.source.source == "hunt_results"
            and projected_flow_id == segment.source.flow_id
        ):
            projected_flow_id = ""
        row["_FlowId"] = str(
            projected_flow_id
            or dict(flow_ids_by_client or {}).get(client_id)
            or (
                ""
                if segment.source.source == "hunt_results"
                else segment.source.flow_id
            )
        )
        row["_FlowRowNumber"] = int(
            row.get("_RowNumber") or segment.row_start + index + 1
        )
        row["_HuntId"] = segment.source.hunt_id
        identity = dict((client_identities or {}).get(client_id) or {})
        row["_Hostname"] = str(
            row.get("_Hostname") or row.get("Hostname") or identity.get("hostname") or ""
        )
        row["_Fqdn"] = str(
            row.get("_Fqdn") or row.get("Fqdn") or identity.get("fqdn") or ""
        )
    projection_hash = _sha256_json(
        {
            "profile_hash": str((profile or {}).get("_profile_hash") or ""),
            "fields": fields,
            "provenance_fields": [
                "_ClientId",
                "_FlowId",
                "_FlowRowNumber",
                "_HuntId",
                "_Hostname",
                "_Fqdn",
            ],
        }
    )
    return projected, fields, projection_hash


def segment_units(
    segment: flow_analysis_runtime.AcquiredSegment,
    *,
    profiles: dict[str, dict[str, Any]],
    source_references: Mapping[str, Mapping[str, Any]],
    maximum_tokens: int,
    encoding_name: str,
    client_identities: Mapping[str, Mapping[str, str]] | None = None,
    flow_ids_by_client: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    projected, _fields, projection_hash = _project_segment(
        segment,
        profiles,
        source_references[segment.source.source_id],
        client_identities,
        flow_ids_by_client,
    )
    raw_hash = _sha256_json(segment.rows)
    segment_revision = flow_analysis.segment_revision(
        segment_id=segment.segment_id,
        row_count=segment.row_count,
        content_sha256=raw_hash,
        flow_state_value=segment.flow_state,
        projection_hash=projection_hash,
    )
    planned = collection_analysis.plan_row_chunks(
        projected,
        maximum_tokens=maximum_tokens,
        encoding_name=encoding_name,
    )
    units: list[dict[str, Any]] = []
    for item in planned:
        relative_start = int(item["row_start"])
        relative_end = int(item["row_end"])
        absolute_start = segment.row_start + relative_start
        absolute_end = segment.row_start + relative_end
        rows = projected[relative_start:relative_end]
        unit_id = flow_analysis.sha256_identity(
            "unit",
            {
                "segment_id": segment.segment_id,
                "row_start": absolute_start,
                "row_end": absolute_end,
            },
        )
        revision = flow_analysis.sha256_identity(
            "unit-revision",
            {
                "unit_id": unit_id,
                "segment_revision": segment_revision,
                "content_sha256": _sha256_bytes(
                    collection_analysis.csv_text(rows).encode("utf-8")
                ),
            },
        )
        units.append(
            {
                "unit_id": unit_id,
                "revision": revision,
                "source_id": segment.source.source_id,
                "segment_id": segment.segment_id,
                "artifact": segment.source.artifact,
                "compatibility_key": flow_analysis.canonical_json(
                    {
                        "artifact": segment.source.artifact,
                        "profile": projection_hash,
                        "source": segment.source.source,
                    }
                ),
                "row_start": absolute_start,
                "row_end": absolute_end,
                "row_count": len(rows),
                "input_tokens": int(item["input_tokens"]),
                "rows": rows,
            }
        )
    segment_record = {
        "segment_id": segment.segment_id,
        "source_id": segment.source.source_id,
        "hunt_id": segment.source.hunt_id,
        "artifact": segment.source.artifact,
        "client_id": segment.source.client_id,
        "flow_id": segment.source.flow_id,
        "row_start": segment.row_start,
        "row_end": segment.row_end,
        "row_count": segment.row_count,
        "content_sha256": raw_hash,
        "flow_state": segment.flow_state,
        "projection_hash": projection_hash,
        "revision": segment_revision,
        "unit_ids": [str(unit["unit_id"]) for unit in units],
        "unit_revisions": [str(unit["revision"]) for unit in units],
        "provisional": segment.provisional,
    }
    return segment_record, units


def ensure_analysis_source_aliases(
    state: dict[str, Any],
    sources: Sequence[flow_analysis.FlowSource],
    *,
    scope_type: str,
    scope_id: str,
) -> dict[str, dict[str, Any]]:
    """Persist stable aliases and index them by the existing flow-source identity."""
    descriptors: list[dict[str, Any]] = []
    evidence_id_by_flow_source: dict[str, str] = {}
    for source in sources:
        evidence_source_id = evidence_references.evidence_source_id(
            scope_type=scope_type,
            scope_id=scope_id,
            org_id=source.org_id,
            client_id=source.client_id,
            flow_id=source.flow_id,
            artifact=source.artifact,
            source=source.source or source.artifact,
        )
        evidence_id_by_flow_source[source.source_id] = evidence_source_id
        descriptors.append(
            {
                "source_id": evidence_source_id,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "hunt_id": source.hunt_id,
                "org_id": source.org_id,
                "client_id": source.client_id,
                "flow_id": source.flow_id,
                "artifact": source.artifact,
                "source": source.source or source.artifact,
                "flow_source_id": source.source_id,
            }
        )
    state["source_aliases"] = evidence_references.ensure_source_aliases(
        state.get("source_aliases") or {},
        descriptors,
    )
    return {
        flow_source_id: state["source_aliases"][evidence_source_id]
        for flow_source_id, evidence_source_id in evidence_id_by_flow_source.items()
    }


def _streaming_chunk(
    units: Sequence[Mapping[str, Any]],
    *,
    analysis_id: str,
) -> dict[str, Any]:
    """Finalize one acquisition-ordered token chunk without retaining a plan."""
    ordered = [dict(unit) for unit in units]
    if not ordered:
        raise ValueError("streaming chunk requires at least one unit")
    compatibility = str(ordered[0].get("compatibility_key") or "")
    if not compatibility or any(
        str(unit.get("compatibility_key") or "") != compatibility
        for unit in ordered
    ):
        raise ValueError("streaming chunk units must have one compatibility key")
    unit_revisions = [str(unit["revision"]) for unit in ordered]
    chunk_id = flow_analysis.sha256_identity(
        "streaming-chunk",
        {
            "schema": STREAMING_CHUNK_SCHEMA_VERSION,
            "analysis_id": analysis_id,
            "unit_revisions": unit_revisions,
        },
    )
    return {
        "chunk_id": chunk_id,
        "compatibility_key": compatibility,
        "input_tokens": sum(int(unit.get("input_tokens") or 0) for unit in ordered),
        "row_count": sum(int(unit.get("row_count") or 0) for unit in ordered),
        "artifact": str(ordered[0]["artifact"]),
        "source_ids": sorted({str(unit["source_id"]) for unit in ordered}),
        "segment_ids": sorted({str(unit["segment_id"]) for unit in ordered}),
        "unit_ids": [str(unit["unit_id"]) for unit in ordered],
        "unit_revisions": unit_revisions,
        "units": ordered,
        "status": "planned",
    }


def iter_streaming_chunks(
    segments: Iterable[flow_analysis_runtime.AcquiredSegment],
    *,
    profiles: dict[str, dict[str, Any]],
    source_references: Mapping[str, Mapping[str, Any]],
    maximum_tokens: int,
    encoding_name: str,
    analysis_id: str,
    client_identities: Mapping[str, Mapping[str, str]] | None = None,
    flow_ids_by_client: Mapping[str, str] | None = None,
    on_segment: Callable[[int], None] | None = None,
) -> Iterable[dict[str, Any]]:
    """Project one segment at a time and emit acquisition-ordered token chunks."""
    pending: list[dict[str, Any]] = []
    pending_tokens = 0
    pending_compatibility = ""
    for segment in segments:
        _segment_record, planned_units = segment_units(
            segment,
            profiles=profiles,
            source_references=source_references,
            maximum_tokens=maximum_tokens,
            encoding_name=encoding_name,
            client_identities=client_identities,
            flow_ids_by_client=flow_ids_by_client,
        )
        if on_segment is not None:
            on_segment(segment.row_count)
        units = deque(planned_units)
        planned_units.clear()
        while units:
            unit = units.popleft()
            compatibility = str(unit["compatibility_key"])
            unit_tokens = int(unit["input_tokens"])
            if pending and (
                compatibility != pending_compatibility
                or pending_tokens + unit_tokens > maximum_tokens
            ):
                completed = _streaming_chunk(pending, analysis_id=analysis_id)
                pending = []
                pending_tokens = 0
                pending_compatibility = ""
                yield completed
            if not pending:
                pending_compatibility = compatibility
            pending.append(unit)
            pending_tokens += unit_tokens
        del units
        del segment
    if pending:
        yield _streaming_chunk(pending, analysis_id=analysis_id)


def _time_filter_segments(
    segments: Iterable[flow_analysis_runtime.AcquiredSegment],
    scopes: Mapping[str, analysis_time_scope.ResolvedTimeScope],
) -> Iterable[flow_analysis_runtime.AcquiredSegment]:
    for segment in segments:
        resolved = scopes.get(segment.source.artifact)
        if resolved is None or not resolved.scope.bounded:
            yield segment
            continue
        numbered = [
            {
                **dict(row),
                collection_analysis.SOURCE_ROW_NUMBER_FIELD: segment.row_start + index,
            }
            for index, row in enumerate(segment.rows, start=1)
        ]
        yield flow_analysis_runtime.AcquiredSegment(
            source=segment.source,
            segment_id=segment.segment_id + "-time-scope",
            row_start=segment.row_start,
            row_end=segment.row_end,
            rows=resolved.filter_rows(numbered),
            flow_state=segment.flow_state,
            provisional=segment.provisional,
        )


def build_runtime_plan(
    chunks: Sequence[Mapping[str, Any]],
    *,
    source_aliases: Mapping[str, Mapping[str, Any]],
    scope_type: str,
    scope_id: str,
    analysis_id: str,
    question: str,
    limits: Mapping[str, Any],
    encoding_name: str,
) -> tuple[dict[str, Any], dict[int, str], dict[str, dict[str, dict[str, Any]]]]:
    source_by_alias = {
        str(metadata.get("alias") or ""): {
            **dict(metadata),
            "source_id": str(source_id),
        }
        for source_id, metadata in source_aliases.items()
    }
    public_chunks: list[dict[str, Any]] = []
    chunk_csv: dict[int, str] = {}
    provenance: dict[str, dict[str, dict[str, Any]]] = {}
    artifact_tasks: list[dict[str, Any]] = []
    for index, raw in enumerate(sorted(chunks, key=lambda item: str(item["chunk_id"]))):
        chunk = dict(raw)
        chunk_id = str(chunk["chunk_id"])
        rows: list[dict[str, Any]] = []
        ref_map: dict[str, dict[str, Any]] = {}
        for unit in sorted(chunk["units"], key=lambda item: str(item["unit_id"])):
            for source_row in unit["rows"]:
                row = dict(source_row)
                ref = str(row.get("_SourceRef") or "")
                evidence_references.parse_source_reference(ref)
                if ref in ref_map:
                    raise RuntimeError(
                        f"Packed chunk {chunk_id} contains duplicate source reference {ref}."
                    )
                rows.append(row)
                alias, _row_number = evidence_references.parse_source_reference(ref)
                source_metadata = source_by_alias.get(alias)
                if source_metadata is None:
                    raise RuntimeError(
                        f"Packed chunk {chunk_id} uses unknown source alias {alias}."
                    )
                source_provenance = evidence_references.source_provenance(row)
                for key, value in source_metadata.items():
                    if key == "alias":
                        source_provenance["source_alias"] = str(value)
                    elif (
                        str(source_metadata.get("source") or "")
                        == "hunt_results"
                        and key in {"client_id", "flow_id"}
                    ):
                        continue
                    elif not source_provenance.get(key):
                        source_provenance[key] = value
                ref_map[ref] = source_provenance
        task_id = f"artifact-task-{chunk_id}"
        csv_evidence = collection_analysis.csv_text(rows)
        input_tokens = token_budget.estimate_tokens(csv_evidence, encoding_name)
        if input_tokens > int(limits["maximum_evidence_tokens_per_item"]):
            raise RuntimeError(
                f"Packed chunk {chunk_id} exceeds the evidence token ceiling "
                f"({input_tokens} > {limits['maximum_evidence_tokens_per_item']})."
            )
        public_chunk = {
            "chunk_index": index,
            "chunk_id": chunk_id,
            "artifact": str(chunk["artifact"]),
            "flow_id": "multi-flow",
            "component": str(chunk["artifact"]),
            "components": [str(chunk["artifact"])],
            "task_id": task_id,
            "task_chunk_index": 0,
            "task_chunk_count": 1,
            "row_start": 0,
            "row_end": len(rows),
            "row_count": len(rows),
            "input_tokens": input_tokens,
            "unit_ids": list(chunk["unit_ids"]),
            "unit_revisions": list(chunk["unit_revisions"]),
            "source_ids": list(chunk["source_ids"]),
            "segment_ids": list(chunk["segment_ids"]),
        }
        public_chunks.append(public_chunk)
        chunk_csv[index] = csv_evidence
        provenance[chunk_id] = ref_map
        artifact_tasks.append(
            {
                "task_id": task_id,
                "role": "artifact-analyst",
                "artifact": str(chunk["artifact"]),
                "flow_id": "multi-flow",
                "analysis_mode": "direct",
                "analysis_route": "high-volume",
                "analysis_task": analysis_limits.analysis_task("high-volume"),
                "components": [str(chunk["artifact"])],
                "chunk_indices": [index],
                "chunk_count": 1,
                "row_count": len(rows),
                "input_tokens": input_tokens,
            }
        )
    expected = [
        {
            "artifact": chunk["artifact"],
            "source_artifact": chunk["artifact"],
            "component": chunk["component"],
            "flow_id": chunk["flow_id"],
            "chunk_index": chunk["chunk_index"],
            "chunk_count": len(public_chunks),
            "row_start": chunk["row_start"],
            "row_end": chunk["row_end"],
            "row_count": chunk["row_count"],
            "input_tokens": chunk["input_tokens"],
            "task_id": chunk["task_id"],
            "task_chunk_index": 0,
            "task_chunk_count": 1,
        }
        for chunk in public_chunks
    ]
    plan_fingerprint = _sha256_json(
        {
            "scope_id": scope_id,
            "analysis_id": analysis_id,
            "chunks": [chunk["chunk_id"] for chunk in public_chunks],
        }
    )
    plan = {
        "schema_version": collection_analysis.ANALYSIS_PLAN_SCHEMA_VERSION,
        "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
        "source_aliases": {
            str(source_id): dict(metadata)
            for source_id, metadata in source_aliases.items()
        },
        "scope_type": scope_type,
        "scope_id": scope_id,
        "investigation_id": "",
        "hostname": "fleet" if scope_type == "hunt" else scope_id,
        "client_id": "",
        "collection_type": scope_type,
        "request_id": scope_id,
        "analysis_mode": "chunked" if len(public_chunks) > 1 else "direct",
        "analysis_limits": dict(limits),
        "token_estimator": token_budget.token_estimator_name(encoding_name),
        "total_rows": sum(int(chunk["row_count"]) for chunk in public_chunks),
        "chunk_count": len(public_chunks),
        "chunks": public_chunks,
        "artifact_tasks": artifact_tasks,
        "artifact_task_count": len(artifact_tasks),
        "expected_chunk_headers": expected,
        "source_fingerprint": _sha256_json(
            [revision for chunk in public_chunks for revision in chunk["unit_revisions"]]
        ),
        "plan_fingerprint": plan_fingerprint,
        "artifacts": [],
        "collection_failures": [],
        "evidence_persisted": False,
        "analysis_profile": "flow-analysis",
        "analysis_objectives": [
            "Answer the exact investigation question from every assigned row.",
            "Correlate client, flow, artifact, and source-row provenance.",
            "Return only grounded findings, relevant context, limitations, and bounded follow-up.",
        ],
        "question": question,
    }
    return plan, chunk_csv, provenance


def _add_provenance(result: dict[str, Any], refs: Mapping[str, Mapping[str, Any]]) -> None:
    for finding in result.get("findings") or []:
        for evidence in finding.get("evidence") or []:
            provenance = refs.get(str(evidence.get("ref") or ""))
            if provenance:
                evidence["source"] = dict(provenance)
    for item in result.get("relevant_context") or []:
        if not isinstance(item, dict):
            continue
        provenance = refs.get(str(item.get("ref") or ""))
        if provenance:
            item["source"] = dict(provenance)


def iter_streaming_chunk_work(
    chunks: Iterable[Mapping[str, Any]],
    *,
    source_aliases: Mapping[str, Mapping[str, Any]],
    scope_type: str,
    scope_id: str,
    analysis_id: str,
    question: str,
    limits: Mapping[str, Any],
    encoding_name: str,
    on_chunk: Callable[[Mapping[str, Any]], None] | None = None,
    analysis_guidance: Sequence[str] = (),
    allow_uplift_candidates: bool = False,
) -> Iterable[dict[str, Any]]:
    """Render one ephemeral prompt only when the worker pool requests work."""
    for ordinal, chunk in enumerate(chunks):
        plan, chunk_csv, provenance = build_runtime_plan(
            [chunk],
            source_aliases=source_aliases,
            scope_type=scope_type,
            scope_id=scope_id,
            analysis_id=analysis_id,
            question=question,
            limits=limits,
            encoding_name=encoding_name,
        )
        plan["analysis_objectives"] = [
            *list(plan.get("analysis_objectives") or []),
            *(str(value).strip() for value in analysis_guidance if str(value).strip()),
        ]
        plan["allow_uplift_candidates"] = bool(allow_uplift_candidates)
        public_chunk = dict(plan["chunks"][0])
        artifact_task = dict(plan["artifact_tasks"][0])
        csv_evidence = chunk_csv[0]
        source_rows = collection_analysis_runtime.source_rows_from_csv(
            csv_evidence,
            dict(plan["source_aliases"]),
        )
        chunk_id = str(public_chunk["chunk_id"])
        manifest = {
            "chunk_id": chunk_id,
            "ordinal": ordinal,
            "artifact": str(public_chunk["artifact"]),
            "row_count": int(public_chunk["row_count"]),
            "input_tokens": int(public_chunk["input_tokens"]),
        }
        if on_chunk is not None:
            on_chunk(manifest)
        validation_chunk = {
            key: public_chunk[key]
            for key in (
                "task_id",
                "artifact",
                "task_chunk_index",
                "task_chunk_count",
                "row_start",
                "row_end",
                "row_count",
            )
        }
        work = {
            "manifest": manifest,
            "chunk": validation_chunk,
            "artifact_task": artifact_task,
            "task": AgentRequest(
                task_id=f"{public_chunk['task_id']}-chunk-0",
                prompt=collection_analysis_runtime.render_chunk_prompt(
                    plan=plan,
                    chunk=public_chunk,
                    question=question,
                    csv_evidence=csv_evidence,
                ),
                output_name=f"chunk-{ordinal:06d}-{chunk_id}.txt",
                metadata={
                    "stage": "chunk",
                    "chunk_id": chunk_id,
                    "attempt": 1,
                    "analysis_routing": analysis_limits.stage_routing("chunk"),
                },
            ),
            "source_rows": source_rows,
            "provenance": provenance[chunk_id],
            "question": question,
            "allow_uplift_candidates": bool(allow_uplift_candidates),
            "correction_attempts": dict(plan.get("analysis_limits") or {}).get(
                "validation_correction_attempts", analysis_limits.DEFAULT_VALIDATION_CORRECTION_ATTEMPTS),
        }
        del csv_evidence
        del source_rows
        del provenance
        del plan
        del public_chunk
        del validation_chunk
        del artifact_task
        del chunk
        yield work
        del work


async def _execute_streaming_chunk_work_async(
    work: Mapping[str, Any],
    *,
    runner: AgentRunner,
    workdir: Path,
    runtime_dir: Path,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute, validate and optionally retry one isolated streaming chunk."""
    def release_ephemeral_payload() -> None:
        if isinstance(work, dict):
            work.pop("task", None)
            work.pop("source_rows", None)
            work.pop("provenance", None)

    base_task = work["task"]
    if not isinstance(base_task, AgentRequest):
        raise TypeError("streaming work task is invalid")
    chunk = dict(work["chunk"])
    source_rows = dict(work["source_rows"])
    task = base_task
    debug_index = prompt_debug.track_task(base_task)
    final_error = "chunk analysis failed"
    final_diagnostics: list[dict[str, Any]] = []
    attempt_failures: list[dict[str, Any]] = []
    correction_attempts = analysis_limits.correction_attempts(work.get(
        "correction_attempts", analysis_limits.DEFAULT_VALIDATION_CORRECTION_ATTEMPTS))
    for attempt in range(1, correction_attempts + 2):
        run = None
        failure_type = "agent_failed"
        error_class = ""
        initial_diagnostics: list[dict[str, Any]] = []
        response_sha256 = ""
        normalized: dict[str, Any] | None = None
        try:
            run = runner.run(
                task,
                workdir=workdir,
                output_dir=runtime_dir,
                progress_callback=(
                    None
                    if progress_callback is None
                    else lambda event: progress_callback(
                        analysis_cli_output.agent_event_progress(event)
                    )
                ),
            )
            if inspect.isawaitable(run):
                run = await run
            prompt_debug.response(
                debug_index, attempt=attempt, prompt=task.prompt,
                output=run.output if run.output or run.status == "succeeded" else None,
                status=run.status,
            )
            if run.output:
                response_sha256 = _sha256_bytes(run.output.encode("utf-8"))
            final_error = str(
                run.error
                or (
                    f"agent returned status {run.status}"
                    if run.status != "succeeded"
                    else ""
                )
            )
            failure_type = f"agent_{str(run.status or 'failed')}"
            final_diagnostics = []
            if run.status == "succeeded":
                try:
                    normalized = collection_analysis.validate_context_worker_result(
                        run.output,
                        artifact=str(chunk["artifact"]),
                        chunk_index=int(chunk["task_chunk_index"]),
                        chunk_count=int(chunk["task_chunk_count"]),
                        row_start=int(chunk["row_start"]),
                        row_end=int(chunk["row_end"]),
                        expected_row_count=int(chunk["row_count"]),
                        source_rows=source_rows,
                        allow_uplift_candidates=bool(
                            work.get("allow_uplift_candidates")
                        ),
                    )
                except (ValueError, collection_analysis.WorkerResultError) as exc:
                    final_error = str(exc)
                    failure_type = "validation_failed"
                    initial_diagnostics = recovery.validation_defects(exc)
                    final_diagnostics = list(initial_diagnostics)
                finally:
                    prompt_debug.validation(
                        debug_index, attempt,
                        "accepted" if normalized is not None else "rejected",
                    )
            if normalized is not None:
                artifact_result = collection_analysis_runtime._direct_artifact_result(
                    task=dict(work["artifact_task"]),
                    worker=normalized,
                )
                artifact_result["question"] = str(work["question"]).strip()
                _add_provenance(artifact_result, dict(work["provenance"]))
                if progress_callback is not None:
                    progress_callback(
                        {
                            "phase": "chunk",
                            "task_id": task.task_id,
                            "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                            "attempt": attempt,
                            "status": "accepted",
                        }
                    )
                outcome = {
                    "status": "accepted",
                    "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                    "attempts": attempt,
                    "result": artifact_result,
                    "attempt_failures": attempt_failures,
                }
                release_ephemeral_payload()
                return outcome
        except Exception as exc:  # executor failures must become bounded outcomes
            if run is None or inspect.isawaitable(run):
                prompt_debug.response(
                    debug_index, attempt=attempt, prompt=task.prompt,
                    output=None, status="executor_error",
                )
            final_error = str(exc)
            failure_type = "executor_error"
            error_class = type(exc).__name__
            final_diagnostics = []
        # Provider and transport retries are owned by AgentRunner. This second
        # model request is only a semantic correction for a successful provider
        # response that failed deterministic output validation.
        retryable = attempt <= correction_attempts and failure_type == "validation_failed"
        attempt_failures.append(
            _compact_chunk_attempt_failure(
                attempt=attempt,
                status="retrying" if retryable else "failed",
                failure_type=(
                    "input_limit"
                    if final_error.startswith(
                        "Agent prompt exceeds maximum input tokens"
                    )
                    else failure_type
                ),
                error=final_error,
                diagnostics=[*initial_diagnostics, *final_diagnostics],
            )
        )
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": "chunk",
                    "task_id": task.task_id,
                    "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                    "attempt": attempt,
                    "status": "retrying" if retryable else "failed",
                    "failure_type": (
                        "input_limit"
                        if final_error.startswith(
                            "Agent prompt exceeds maximum input tokens"
                        )
                        else failure_type
                    ),
                    "error": final_error[:MAX_FAILED_CHUNK_ERROR_CHARS],
                    "diagnostics": initial_diagnostics or final_diagnostics,
                    "response_sha256": response_sha256,
                    "error_class": error_class,
                }
            )
        if not retryable:
            break
        task = replace(
            base_task,
            prompt=collection_analysis_runtime.render_retry_prompt(
                base_task.prompt,
                error=final_error,
                diagnostics=final_diagnostics,
            ),
            output_name=base_task.output_name + f".retry-{attempt + 1}",
            metadata={**base_task.metadata, "attempt": attempt + 1},
        )
    outcome = {
        "status": "failed",
        "chunk_id": str(dict(work["manifest"])["chunk_id"]),
        "attempts": attempt,
        "error": final_error[:MAX_FAILED_CHUNK_ERROR_CHARS],
        "attempt_failures": attempt_failures,
    }
    release_ephemeral_payload()
    return outcome


async def execute_streaming_chunks_async(
    *,
    work_items: Iterable[Mapping[str, Any]],
    limits: Mapping[str, Any],
    encoding_name: str,
    spec: ResolvedAgentExecution,
    workdir: Path,
    runtime_dir: Path,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    active_callback: Callable[[int], None] | None = None,
    status_callback: Callable[[AnalysisPoolStatus], None] | None = None,
    analysis_queue: DynamicAnalysisQueue[Mapping[str, Any], dict[str, Any]] | None = None,
    shared_execute: Callable[..., Any] | None = None,
    lane_id: str | None = None,
) -> list[dict[str, Any]]:
    """Consume and validate chunks with bounded async queue backpressure."""
    runtime_limits = AgentRuntimeLimits(
        model_context_tokens=int(limits["model_context_tokens"]),
        operational_context_tokens=int(limits["operational_context_tokens"]),
        maximum_input_tokens=int(limits["maximum_input_tokens"]),
        maximum_output_tokens=int(limits["maximum_output_tokens"]),
        token_encoding=encoding_name,
    )
    runner: AgentRunner | None = None

    async def execute_one(work: Mapping[str, Any]) -> dict[str, Any]:
        nonlocal runner
        if shared_execute is None and runner is None:
            runner = create_agent_runner(
                spec,
                limits=runtime_limits,
                persist_runtime_files=False,
            )
        active_runner: Any = runner
        if shared_execute is not None:
            class SharedRunner:
                async def run(self, task: AgentRequest, **kwargs: Any) -> Any:
                    value = shared_execute(
                        task,
                        limits=runtime_limits,
                        progress_callback=kwargs.get("progress_callback"),
                    )
                    return await value if inspect.isawaitable(value) else value

            active_runner = SharedRunner()
        return await _execute_streaming_chunk_work_async(
            work,
            runner=active_runner,
            workdir=workdir,
            runtime_dir=runtime_dir,
            progress_callback=progress_callback,
        )

    pool_status = AnalysisPoolStatus()

    def report_local_status(**changes: Any) -> None:
        nonlocal pool_status
        values = asdict(pool_status)
        values.update(changes)
        pool_status = AnalysisPoolStatus(**values)
        if active_callback is not None:
            active_callback(pool_status.active)
        if status_callback is not None:
            status_callback(pool_status)

    def report_submitted() -> None:
        report_local_status(
            submitted=pool_status.submitted + 1,
            queued=pool_status.queued + 1,
        )

    async def enqueue_owned(
        resolved_lane_id: str,
        work: Mapping[str, Any],
    ) -> asyncio.Future[dict[str, Any]]:
        future = await scheduler.enqueue(
            resolved_lane_id,
            work,
            execute=execute_and_collect,
            weight=max(
                1,
                int(
                    dict(work.get("manifest") or {}).get("input_tokens")
                    or dict(work.get("chunk") or {}).get("input_tokens")
                    or 1
                ),
            ),
        )
        report_submitted()
        return future

    stop_production = threading.Event()
    owns_scheduler = analysis_queue is None
    scheduler = analysis_queue or DynamicAnalysisQueue[
        Mapping[str, Any], dict[str, Any]
    ](
        max_concurrency=spec.max_concurrency,
        prefetch=1,
        lane_queue_size=1,
    )

    async def execute_and_collect(work: Mapping[str, Any]) -> dict[str, Any]:
        report_local_status(
            queued=max(0, pool_status.queued - 1),
            active=pool_status.active + 1,
        )
        failed = False
        try:
            outcome = await execute_one(work)
            failed = str(outcome.get("status") or "") == "failed"
            if failed:
                stop_production.set()
                if owns_scheduler:
                    scheduler.request_stop()
            return outcome
        except BaseException:
            failed = True
            raise
        finally:
            report_local_status(
                active=max(0, pool_status.active - 1),
                completed=pool_status.completed + 1,
                failed=pool_status.failed + int(failed),
                stop_requested=stop_production.is_set(),
            )

    loop = asyncio.get_running_loop()

    owned_futures: list[asyncio.Future[dict[str, Any]]] = []

    def produce() -> bool:
        iterator = iter(work_items)
        exhausted = False
        pending_enqueue: concurrent.futures.Future[Any] | None = None
        try:
            while not stop_production.is_set():
                try:
                    work = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                manifest = dict(work.get("manifest") or {})
                chunk = dict(work.get("chunk") or {})
                resolved_lane_id = str(
                    lane_id
                    or manifest.get("lane_id")
                    or manifest.get("artifact")
                    or chunk.get("artifact")
                    or "unknown-artifact"
                )
                pending_enqueue = asyncio.run_coroutine_threadsafe(
                    enqueue_owned(
                        resolved_lane_id,
                        work,
                    ),
                    loop,
                )
                while True:
                    try:
                        queued = pending_enqueue.result(timeout=0.1)
                        break
                    except concurrent.futures.TimeoutError:
                        if stop_production.is_set():
                            pending_enqueue.cancel()
                            return False
                owned_futures.append(queued)
                pending_enqueue = None
        finally:
            if pending_enqueue is not None and not pending_enqueue.done():
                pending_enqueue.cancel()
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        return exhausted

    producer_task: asyncio.Task[bool] | None = None
    try:
        await scheduler.start()
        producer_task = asyncio.create_task(
            asyncio.to_thread(produce),
            name=f"analysis-producer:{lane_id or 'artifact'}",
        )
        exhausted = await asyncio.shield(producer_task)
        if exhausted and owns_scheduler:
            scheduler.mark_sources_exhausted()
        report_local_status(source_exhausted=exhausted)
        gathered = await asyncio.gather(*owned_futures, return_exceptions=True)
        errors = [value for value in gathered if isinstance(value, BaseException)]
        if errors:
            raise errors[0]
        outcomes = [dict(value) for value in gathered]
    except asyncio.CancelledError:
        stop_production.set()
        if producer_task is not None and not producer_task.done():
            try:
                await producer_task
            except Exception:
                pass
        for future in owned_futures:
            future.cancel()
        if owned_futures:
            await asyncio.gather(*owned_futures, return_exceptions=True)
        raise
    finally:
        if owns_scheduler:
            await scheduler.close()
        if runner is not None:
            await runner.close()
        try:
            runtime_dir.rmdir()
        except OSError:
            pass
    return outcomes


def cumulative_hunt_result(state: Mapping[str, Any]) -> dict[str, Any]:
    checkpoint = state.get("checkpoint")
    if isinstance(checkpoint, Mapping) and isinstance(
        checkpoint.get("result"), Mapping
    ):
        return copy.deepcopy(dict(checkpoint["result"]))
    return {}


def compact_hunt_result(state: Mapping[str, Any]) -> dict[str, Any]:
    result = cumulative_hunt_result(state)
    return analysis_summary.compact_result(result) if result else {}


def _timestamp_seconds(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        numeric = float(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    if numeric > 10**14:
        return numeric / 1_000_000
    if numeric > 10**11:
        return numeric / 1_000
    return numeric


def _flow_activity_seconds(row: Mapping[str, Any]) -> float | None:
    flow = flow_analysis.nested_flow(row)
    for key in (
        "active_time",
        "ActiveTime",
        "last_active",
        "LastActive",
        "create_time",
        "CreateTime",
    ):
        value = flow.get(key)
        if value is None:
            value = row.get(key)
        parsed = _timestamp_seconds(value)
        if parsed is not None:
            return parsed
    return None


def _inventory_artifacts(
    inventory_rows: Sequence[Mapping[str, Any]], selected: set[str]
) -> list[str]:
    available = sorted(
        {
            artifact
            for row in inventory_rows
            for artifact in flow_analysis.flow_result_sources(row)
        }
    )
    if not selected:
        return available
    return [
        artifact
        for artifact in available
        if any(
            artifact == requested or artifact.startswith(f"{requested}/")
            for requested in selected
        )
    ] or sorted(selected)


def _update_sources(
    inventory_rows: Sequence[Mapping[str, Any]],
    *,
    org_id: str,
    hunt_id: str,
    selected: set[str],
    cursor: str,
    cutoff: str,
    overlap: timedelta = timedelta(minutes=5),
) -> list[flow_analysis.FlowSource]:
    cursor_seconds = _timestamp_seconds(cursor)
    cutoff_seconds = _timestamp_seconds(cutoff)
    if cursor_seconds is None or cutoff_seconds is None:
        raise RuntimeError("Update analysis requires valid server cursor timestamps.")
    lower_bound = cursor_seconds - overlap.total_seconds()
    sources: dict[str, flow_analysis.FlowSource] = {}
    for row in inventory_rows:
        if flow_analysis.classify_flow(row) != flow_analysis.FLOW_SUCCESSFUL_TERMINAL:
            continue
        activity = _flow_activity_seconds(row)
        if activity is not None and not (lower_bound < activity <= cutoff_seconds):
            continue
        client_id, flow_id = flow_analysis.flow_identifiers(row)
        for artifact in flow_analysis.flow_result_sources(row):
            if selected and not any(
                artifact == requested or artifact.startswith(f"{requested}/")
                for requested in selected
            ):
                continue
            source = flow_analysis.FlowSource(
                org_id=org_id,
                client_id=client_id,
                flow_id=flow_id,
                artifact=artifact,
                hunt_id=hunt_id,
                state=flow_analysis.flow_state(row),
                watermark=flow_analysis.flow_watermark(row),
            )
            sources[source.source_id] = source
    return sorted(
        sources.values(), key=lambda item: (item.artifact, item.client_id, item.flow_id)
    )


async def _synthesize_transient_results(
    *,
    scope_id: str,
    results: Sequence[Mapping[str, Any]],
    question: str,
    spec: ResolvedAgentExecution,
    limits: Mapping[str, Any],
    encoding_name: str,
    workdir: Path,
    runtime_dir: Path,
    task_mode: str = "targeted_hunt",
    response_depth: str = "standard",
    shared_execute: Callable[..., Any] | None = None,
    schedule: Callable[
        [AgentRequest, Callable[[AgentRequest], Any]], Any
    ]
    | None = None,
    synthesis_mode: str = "full",
) -> dict[str, Any]:
    synthesis_policy.mode(synthesis_mode)
    if synthesis_mode == "none":
        result = synthesis_policy.preliminary(results, question=question, scope="hunt")
        return {"status": result["status"], "host_result": result, "tasks": []}
    plan = {
        "scope_type": "hunt",
        "scope_id": scope_id,
        "analysis_limits": dict(limits),
        "artifact_tasks": [
            {
                "task_id": str(result.get("task_id") or f"accepted-{index}"),
                "artifact": str(result.get("artifact") or "unknown"),
            }
            for index, result in enumerate(results)
        ],
        "collection_failures": [],
        "task_mode": task_mode,
        "response_depth": response_depth,
    }
    runtime_limits = collection_analysis_runtime.limits_from_plan(plan)
    runner: AgentRunner | None = None
    if shared_execute is None:
        runner = create_agent_runner(
            spec,
            limits=runtime_limits,
            persist_runtime_files=False,
        )

    async def execute_one(task: AgentRequest) -> Any:
        if shared_execute is not None:
            value = shared_execute(
                task,
                limits=runtime_limits,
                progress_callback=None,
            )
            return await value if inspect.isawaitable(value) else value
        if runner is None:
            raise RuntimeError("hunt synthesis runner was not initialized")
        return await runner.run(task, workdir=workdir, output_dir=runtime_dir)

    try:
        synthesis = await collection_analysis_runtime.execute_host_synthesis_from_artifact_results_async(
            plan=plan,
            artifact_results=[copy.deepcopy(dict(result)) for result in results],
            question=question,
            execute=execute_one,
            schedule=schedule,
        )
    finally:
        if runner is not None:
            await runner.close()
    try:
        runtime_dir.rmdir()
    except OSError:
        pass
    return synthesis


def _prune_checkpoint_source_aliases(
    state: dict[str, Any],
    result: Mapping[str, Any],
    *,
    current_source_ids: Iterable[str],
) -> None:
    """Drop superseded acquisition aliases not referenced by the checkpoint."""
    referenced_aliases: set[str] = set()
    for item in [
        *list(result.get("findings") or []),
        *list(result.get("relevant_context") or []),
        *list(dict(state.get("checkpoint", {}).get("accepted_result") or {}).get("findings") or []),
        *list(dict(state.get("checkpoint", {}).get("accepted_result") or {}).get("relevant_context") or []),
    ]:
        if not isinstance(item, Mapping):
            continue
        evidence_items = item.get("evidence") or [item]
        for evidence in evidence_items:
            if not isinstance(evidence, Mapping):
                continue
            reference = str(evidence.get("ref") or "")
            if reference:
                try:
                    alias, _row_number = evidence_references.parse_source_reference(
                        reference
                    )
                except ValueError:
                    continue
                referenced_aliases.add(alias)
            source_alias = str(dict(evidence.get("source") or {}).get("source_alias") or "")
            if source_alias:
                referenced_aliases.add(source_alias)
    current = {str(value) for value in current_source_ids}
    state["source_aliases"] = {
        str(source_id): dict(metadata)
        for source_id, metadata in dict(state.get("source_aliases") or {}).items()
        if str(source_id) in current
        or str(dict(metadata).get("alias") or "") in referenced_aliases
    }


def _detectraptor_evtx_stack_config(
    profile: Mapping[str, Any] | None,
) -> dict[str, int | float]:
    configured = dict(
        dict((profile or {}).get("review") or {}).get("evtx_stack") or {}
    )
    return {
        "minimum_rows": int(configured.get("minimum_rows") or 1_000),
        "minimum_estimated_chunks": int(
            configured.get("minimum_estimated_chunks") or 10
        ),
        "minimum_reduction_rows": int(
            configured.get("minimum_reduction_rows") or 100
        ),
        "minimum_reduction_percent": float(
            configured.get("minimum_reduction_percent") or 5
        ),
    }


def _estimated_detectraptor_chunks(
    partition: flow_analysis_runtime.DetectionPartition,
    *,
    maximum_evidence_tokens: int,
) -> int:
    evidence_chars = max(
        int(partition.total_evidence_chars),
        int(partition.row_count) * 256,
    )
    estimated_chunk_chars = maximum_evidence_tokens * 4
    return max(
        1,
        (evidence_chars + estimated_chunk_chars - 1) // estimated_chunk_chars,
    )


def _detectraptor_transport_diagnostic(
    exc: Exception,
    *,
    stage: str,
    attempt: int,
    elapsed_seconds: float = 0.0,
    rows_received: int = 0,
    retry_delay_seconds: float | None = None,
) -> dict[str, Any]:
    diagnostic = {
        "stage": stage,
        "attempt": int(attempt),
        "status": flow_analysis_runtime.grpc_status_name(exc) or "UNKNOWN",
        "error_class": type(exc).__name__,
        "elapsed_seconds": round(max(0.0, float(elapsed_seconds)), 4),
        "rows_received": max(0, int(rows_received)),
    }
    if retry_delay_seconds is not None:
        diagnostic["retry_delay_seconds"] = float(retry_delay_seconds)
    return diagnostic


async def _detectraptor_transport_retry_wait(
    api: Any,
    *,
    attempt: int,
    reconnect_lock: asyncio.Lock | None = None,
) -> float:
    """Reconnect once and apply the bounded DetectRaptor transport backoff."""
    delay = flow_analysis_runtime.detectraptor_retry_delay(attempt)
    if delay is None:
        raise RuntimeError("DetectRaptor transport retry loop is exhausted.")
    if reconnect_lock is None:
        flow_analysis_runtime.reconnect_query_client(api)
    else:
        async with reconnect_lock:
            flow_analysis_runtime.reconnect_query_client(api)
    await asyncio.sleep(delay)
    return delay


def _detectraptor_context_source(
    metadata: Mapping[str, Any],
    row: Mapping[str, Any],
    *,
    row_number: int,
) -> dict[str, Any]:
    """Build compact provenance for a targeted context-query row."""
    return {
        "scope_type": str(metadata.get("scope_type") or "hunt"),
        "scope_id": str(metadata.get("scope_id") or ""),
        "hunt_id": str(metadata.get("hunt_id") or ""),
        "org_id": str(metadata.get("org_id") or ""),
        "client_id": str(row.get("ClientId") or ""),
        "hostname": str(row.get("Computer") or ""),
        "fqdn": str(row.get("Fqdn") or ""),
        "flow_id": "",
        "artifact": flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT,
        "source": "targeted_exact_payload_context",
        "source_id": str(metadata.get("source_id") or ""),
        "source_alias": str(metadata.get("alias") or ""),
        "source_row_number": row_number,
    }


async def _analyze_detectraptor_partition(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    hunt_state: str,
    cutoff: str,
    partition: flow_analysis_runtime.DetectionPartition,
    stack_record: dict[str, Any],
    recovery_record: dict[str, Any],
    projection: Sequence[str] | None,
    time_predicate: str,
    time_environment: Mapping[str, str],
    detection_regex: str,
    source_references: Mapping[str, Mapping[str, Any]],
    source_aliases: Mapping[str, Mapping[str, Any]],
    profiles: Mapping[str, Mapping[str, Any]],
    client_identities: Mapping[str, Mapping[str, str]],
    flow_ids_by_client: Mapping[str, str],
    analysis_id: str,
    question: str,
    limits: Mapping[str, Any],
    maximum_tokens: int,
    encoding_name: str,
    spec: ResolvedAgentExecution,
    workdir: Path,
    shared_execute: Callable[..., Any] | None,
    analysis_queue: DynamicAnalysisQueue[Any, Any] | None,
    reconnect_lock: asyncio.Lock | None,
    query_timeout_seconds: int,
    persist_record: Callable[[str], None],
    progress: Callable[..., None],
    synthesis_mode: str = "full",
) -> dict[str, Any]:
    """Analyze and checkpoint one EVTX detection as the replayable unit."""
    partition_started = time.monotonic()
    stage_timings: dict[str, float] = {}
    partition_id = partition.partition_id
    resume_stage = str(recovery_record.get("stage") or "")
    provisional = str(hunt_state or "").strip().upper() not in {
        "FINISHED",
        "COMPLETED",
    }
    recovery_record.update(
        {
            "partition_id": partition_id,
            "detection": partition.detection,
            "status": "running",
            "stage": "census",
            "started_at": str(recovery_record.get("started_at") or flow_analysis.now_utc()),
            "heartbeat_at": flow_analysis.now_utc(),
            "discovered_row_count": int(partition.row_count),
            "provisional": provisional,
        }
    )
    recovery_record.setdefault("query_hashes", {})
    recovery_record.setdefault("transport_errors", [])
    recovery_record.setdefault("query_diagnostics", [])
    persist_record("census")

    census: flow_analysis_runtime.DetectionStackCensus | None = None
    large = bool(stack_record.get("large")) and partition.detection is not None
    census_started = time.monotonic()
    if large:
        census_values = dict(recovery_record.get("census") or {})
        if census_values:
            census = flow_analysis_runtime.DetectionStackCensus(
                partition_id=partition_id,
                row_count=int(census_values.get("row_count") or 0),
                group_count=int(census_values.get("group_count") or 0),
                singleton_group_count=int(
                    census_values.get("singleton_group_count") or 0
                ),
                largest_group_rows=int(census_values.get("largest_group_rows") or 0),
                query_sha256=str(census_values.get("query_sha256") or ""),
            )
        else:
            for attempt in range(
                1, flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS + 1
            ):
                recovery_record["attempt"] = attempt
                persist_record("census")
                attempt_started = time.monotonic()
                try:
                    census = await asyncio.to_thread(
                        flow_analysis_runtime.query_detectraptor_evtx_stack_census,
                        api,
                        hunt_id=hunt_id,
                        partition=partition,
                        time_predicate=time_predicate,
                        time_environment=time_environment,
                        detection_regex=detection_regex,
                        query_timeout_seconds=query_timeout_seconds,
                    )
                    recovery_record["query_diagnostics"] = [
                        *list(recovery_record.get("query_diagnostics") or []),
                        {
                            "stage": "census",
                            "attempt": attempt,
                            "status": "succeeded",
                            "elapsed_seconds": round(
                                time.monotonic() - attempt_started, 4
                            ),
                            "rows_received": 1,
                        },
                    ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
                    break
                except Exception as exc:
                    retryable = flow_analysis_runtime.is_retryable_read_only_transport_error(
                        exc, rows_received=0
                    )
                    if retryable:
                        retry_delay = flow_analysis_runtime.detectraptor_retry_delay(
                            attempt
                        )
                        recovery_record["transport_errors"] = [
                            *list(recovery_record.get("transport_errors") or []),
                            _detectraptor_transport_diagnostic(
                                exc,
                                stage="census",
                                attempt=attempt,
                                elapsed_seconds=time.monotonic() - attempt_started,
                                rows_received=0,
                                retry_delay_seconds=retry_delay,
                            ),
                        ][-MAX_DETECTRAPTOR_TRANSPORT_ERRORS:]
                        recovery_record["query_diagnostics"] = [
                            *list(recovery_record.get("query_diagnostics") or []),
                            dict(recovery_record["transport_errors"][-1]),
                        ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
                        persist_record("census")
                        if (
                            attempt
                            < flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS
                        ):
                            await _detectraptor_transport_retry_wait(
                                api,
                                attempt=attempt,
                                reconnect_lock=reconnect_lock,
                            )
                            continue
                        raise
                    stack_record.update(
                        {
                            "mode": "direct_fallback",
                            "fallback_reason": (
                                "census_failed_" + type(exc).__name__.casefold()
                            ),
                        }
                    )
                    census = None
                    break
        if census is not None:
            use_stack = (
                census.reduced_row_count
                >= int(stack_record["minimum_reduction_rows"])
                and census.reduction_percent
                >= float(stack_record["minimum_reduction_percent"])
            )
            stack_record.update(
                {
                    "source_row_count": census.row_count,
                    "represented_row_count": census.row_count,
                    "exact_group_count": census.group_count,
                    "singleton_group_count": census.singleton_group_count,
                    "largest_group_rows": census.largest_group_rows,
                    "reduced_row_count": census.reduced_row_count,
                    "reduction_percent": round(census.reduction_percent, 4),
                    "census_query_sha256": census.query_sha256,
                    "mode": "exact_stack" if use_stack else "direct_fallback",
                    "fallback_reason": (
                        "" if use_stack else "insufficient_consolidation"
                    ),
                }
            )
            recovery_record["census"] = {
                "row_count": census.row_count,
                "group_count": census.group_count,
                "singleton_group_count": census.singleton_group_count,
                "largest_group_rows": census.largest_group_rows,
                "query_sha256": census.query_sha256,
            }
            recovery_record["query_hashes"]["census"] = census.query_sha256
            persist_record("census_complete")
    stage_timings["census_seconds"] = round(
        time.monotonic() - census_started, 4
    )

    recovery_record["mode"] = str(stack_record.get("mode") or "direct")
    exact_stack = str(stack_record.get("mode") or "") == "exact_stack"
    if exact_stack and census is None:
        raise RuntimeError("DetectRaptor exact-stack census is unavailable.")
    local_manifests: dict[str, dict[str, Any]] = {}
    local_outcomes: list[dict[str, Any]] = []
    initial_results: list[dict[str, Any]] = []
    partition_stats: dict[str, Any] = {}
    acquired_model_rows = 0
    final_pool_status = AnalysisPoolStatus()
    stored_initial = recovery_record.get("initial_result")
    stored_query_hash = str(
        dict(recovery_record.get("query_hashes") or {}).get("initial_analysis")
        or ""
    )
    reuse_initial = (
        isinstance(stored_initial, Mapping)
        and str(recovery_record.get("initial_result_sha256") or "")
        == _sha256_json(_compact_synthesis_result(stored_initial))
        and int(recovery_record.get("acquired_row_count") or 0)
        >= int(partition.row_count)
        and int(recovery_record.get("model_row_count") or 0) >= 0
        and bool(stored_query_hash)
        and int(recovery_record.get("uplift_candidate_count") or 0) == 0
        and resume_stage
        in {
            "initial_accepted",
            "completed",
            "interrupted",
            "failed",
        }
    )
    if reuse_initial:
        acquired_model_rows = int(recovery_record.get("model_row_count") or 0)
        partition_stats = {
            "reviewed_row_count": int(
                recovery_record.get("acquired_row_count") or 0
            ),
            "model_group_count": acquired_model_rows,
            "query_sha256": stored_query_hash,
        }

    attempt_range = (
        ()
        if reuse_initial
        else range(1, flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS + 1)
    )
    analysis_started = time.monotonic()
    for attempt in attempt_range:
        attempt_started = time.monotonic()
        recovery_record.update(
            {
                "attempt": attempt,
                "status": "running",
                "stage": "initial_analysis",
                "heartbeat_at": flow_analysis.now_utc(),
            }
        )
        persist_record("initial_analysis")
        attempt_manifests: dict[str, dict[str, Any]] = {}
        attempt_outcomes: list[dict[str, Any]] = []
        attempt_results: list[dict[str, Any]] = []
        attempt_stats: dict[str, Any] = {}
        attempt_rows = 0
        attempt_pool_status = AnalysisPoolStatus()

        def on_segment(row_count: int) -> None:
            nonlocal attempt_rows
            attempt_rows += int(row_count)
            progress(
                phase="detectraptor_partition_analysis",
                active_detection=partition.detection,
                partition_id=partition_id,
                detection_stage="initial_analysis",
                attempt=attempt,
                acquired_row_count=attempt_rows,
            )

        def on_chunk(manifest: Mapping[str, Any]) -> None:
            chunk_id = str(manifest.get("chunk_id") or "")
            if not chunk_id or chunk_id in attempt_manifests:
                raise RuntimeError(
                    f"Duplicate or empty detection chunk ID: {chunk_id!r}"
                )
            attempt_manifests[chunk_id] = dict(manifest)

        def on_pool(pool_status: AnalysisPoolStatus) -> None:
            nonlocal attempt_pool_status
            attempt_pool_status = pool_status

        attempt_segments = (
            flow_analysis_runtime.iter_detectraptor_evtx_stack_segments(
                api,
                org_id=org_id,
                hunt_id=hunt_id,
                cutoff=cutoff,
                partition=partition,
                census=census,
                time_predicate=time_predicate,
                time_environment=time_environment,
                detection_regex=detection_regex,
                segment_rows=flow_analysis.DEFAULT_SEGMENT_ROWS,
                stats=attempt_stats,
                query_timeout_seconds=query_timeout_seconds,
            )
            if exact_stack and census is not None
            else flow_analysis_runtime.iter_detectraptor_evtx_detection_segments(
                api,
                org_id=org_id,
                hunt_id=hunt_id,
                cutoff=cutoff,
                partitions=[partition],
                projection=projection,
                time_predicate=time_predicate,
                time_environment=time_environment,
                detection_regex=detection_regex,
                segment_rows=flow_analysis.DEFAULT_SEGMENT_ROWS,
                stats=attempt_stats,
                query_timeout_seconds=query_timeout_seconds,
            )
        )
        chunks = iter_streaming_chunks(
            attempt_segments,
            profiles=profiles,
            source_references=source_references,
            maximum_tokens=maximum_tokens,
            encoding_name=encoding_name,
            analysis_id=analysis_id,
            client_identities=client_identities,
            flow_ids_by_client=flow_ids_by_client,
            on_segment=on_segment,
        )
        work_items = iter_streaming_chunk_work(
            chunks,
            source_aliases=source_aliases,
            scope_type="hunt",
            scope_id=hunt_id,
            analysis_id=analysis_id,
            question=question,
            limits=limits,
            encoding_name=encoding_name,
            on_chunk=on_chunk,
            analysis_guidance=_detectraptor_analysis_guidance(
                partition.detection
            ),
            allow_uplift_candidates=True,
        )
        try:
            outcomes = execute_streaming_chunks_async(
                work_items=work_items,
                limits=limits,
                encoding_name=encoding_name,
                spec=spec,
                workdir=workdir,
                runtime_dir=workdir / ".api-runtime",
                progress_callback=None,
                active_callback=None,
                status_callback=on_pool,
                analysis_queue=analysis_queue,
                shared_execute=shared_execute,
                lane_id=f"detectraptor:{partition_id}",
            )
            if inspect.isawaitable(outcomes):
                outcomes = await outcomes
            for raw_outcome in outcomes:
                outcome = dict(raw_outcome)
                attempt_outcomes.append(
                    {
                        str(key): copy.deepcopy(value)
                        for key, value in outcome.items()
                        if str(key) != "result"
                    }
                )
                if str(outcome.get("status") or "") != "accepted" or not isinstance(
                    outcome.get("result"), Mapping
                ):
                    raise RuntimeError(
                        "DetectRaptor detection chunk analysis was not accepted."
                    )
                attempt_results.append(dict(outcome["result"]))
        except Exception as exc:
            retryable = flow_analysis_runtime.is_retryable_read_only_transport_error(
                exc, rows_received=attempt_rows
            )
            if not retryable:
                raise
            retry_delay = flow_analysis_runtime.detectraptor_retry_delay(attempt)
            recovery_record["transport_errors"] = [
                *list(recovery_record.get("transport_errors") or []),
                _detectraptor_transport_diagnostic(
                    exc,
                    stage="initial_analysis",
                    attempt=attempt,
                    elapsed_seconds=time.monotonic() - attempt_started,
                    rows_received=attempt_rows,
                    retry_delay_seconds=retry_delay,
                ),
            ][-MAX_DETECTRAPTOR_TRANSPORT_ERRORS:]
            recovery_record["query_diagnostics"] = [
                *list(recovery_record.get("query_diagnostics") or []),
                dict(recovery_record["transport_errors"][-1]),
            ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
            persist_record("initial_analysis")
            if attempt >= flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS:
                raise
            await _detectraptor_transport_retry_wait(
                api,
                attempt=attempt,
                reconnect_lock=reconnect_lock,
            )
            continue
        local_manifests = attempt_manifests
        local_outcomes = attempt_outcomes
        initial_results = attempt_results
        partition_stats = attempt_stats
        acquired_model_rows = attempt_rows
        final_pool_status = attempt_pool_status
        recovery_record["query_diagnostics"] = [
            *list(recovery_record.get("query_diagnostics") or []),
            {
                "stage": "initial_analysis",
                "attempt": attempt,
                "status": "succeeded",
                "elapsed_seconds": round(time.monotonic() - attempt_started, 4),
                "rows_received": attempt_rows,
            },
        ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
        break
    else:  # pragma: no branch - bounded loop either succeeds or raises
        if not reuse_initial:
            raise RuntimeError("DetectRaptor partition retry loop exhausted.")

    if not reuse_initial and not initial_results and acquired_model_rows:
        raise RuntimeError("DetectRaptor partition produced no accepted results.")
    stage_timings["analysis_seconds"] = round(
        time.monotonic() - analysis_started, 4
    )
    synthesis_started = time.monotonic()
    initial_synthesis: Mapping[str, Any] | None = (
        dict(stored_initial) if reuse_initial and isinstance(stored_initial, Mapping) else None
    )
    if not reuse_initial and len(initial_results) == 1:
        initial_synthesis = copy.deepcopy(initial_results[0])
    elif not reuse_initial:
        for model_attempt in (1, 2):
            recovery_record["attempt"] = model_attempt
            persist_record("initial_synthesis")
            synthesis = _synthesize_transient_results(
                scope_id=f"{hunt_id}:{partition_id}",
                synthesis_mode=synthesis_mode,
                results=initial_results,
                question=question,
                spec=spec,
                limits=limits,
                encoding_name=encoding_name,
                workdir=workdir,
                runtime_dir=workdir / ".api-runtime",
                shared_execute=shared_execute,
                schedule=(
                    (
                        lambda task, worker: analysis_queue.enqueue(
                            f"detectraptor:{partition_id}:synthesis",
                            task,
                            execute=worker,
                            weight=max(1, len(str(task.prompt)) // 4),
                        )
                    )
                    if analysis_queue is not None
                    else None
                ),
            )
            if inspect.isawaitable(synthesis):
                synthesis = await synthesis
            if (
                str(synthesis.get("status") or "")
                in {"complete", "complete_with_failures"}
                and isinstance(synthesis.get("host_result"), Mapping)
            ):
                initial_synthesis = dict(synthesis["host_result"])
                break
            if model_attempt == 2:
                raise RuntimeError(
                    "DetectRaptor detection synthesis failed after a model-only retry."
                )
    if initial_synthesis is None:
        raise RuntimeError("DetectRaptor detection synthesis returned no result.")
    stage_timings["partition_synthesis_seconds"] = round(
        time.monotonic() - synthesis_started, 4
    )
    initial_synthesis = copy.deepcopy(dict(initial_synthesis))
    # Host synthesis intentionally returns an artifact-neutral object. Restore
    # the partition artifact before this result is reused as a synthesis input.
    initial_synthesis["artifact"] = str(
        initial_synthesis.get("artifact")
        or flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
    )
    uplift_rows = _detectraptor_uplift_rows(
        initial_results,
        partition_id=partition_id,
        detection=partition.detection,
    )
    recovery_record["acquired_row_count"] = int(
        partition_stats.get("reviewed_row_count") or acquired_model_rows
    )
    recovery_record["model_row_count"] = acquired_model_rows
    recovery_record["uplift_candidate_count"] = len(uplift_rows)
    recovery_record["group_count"] = int(
        partition_stats.get("model_group_count") or acquired_model_rows
    )
    recovery_record["query_hashes"]["initial_analysis"] = str(
        partition_stats.get("query_sha256")
        or next(
            (
                item.get("query_sha256")
                for item in partition_stats.get("partitions") or []
                if isinstance(item, Mapping)
            ),
            "",
        )
        or ""
    )

    selected_payloads: dict[str, str] = {}
    selected_metadata: dict[str, dict[str, Any]] = {}
    interesting_context: list[dict[str, Any]] = []
    context_query_hashes: list[str] = []
    context_row_count = 0
    context_started = time.monotonic()
    if exact_stack:
        for finding in initial_synthesis.get("findings") or []:
            if not isinstance(finding, Mapping):
                continue
            for evidence in finding.get("evidence") or []:
                if not isinstance(evidence, Mapping):
                    continue
                ref = str(evidence.get("ref") or "")
                fields = dict(evidence.get("fields") or {})
                if not ref or "Payload" not in fields:
                    continue
                payload = str(fields.get("Payload") or "")
                selected_payloads[ref] = payload
                selected_metadata.setdefault(
                    ref,
                    {
                        "summary": str(finding.get("summary") or ""),
                        "confidence": str(finding.get("confidence") or ""),
                        "count": max(1, int(fields.get("OccurrenceCount") or 1)),
                        "first_seen": fields.get("FirstSeen"),
                        "last_seen": fields.get("LastSeen"),
                        "payload_field": str(fields.get("PayloadField") or "EventData"),
                    },
                )
        recovery_record["selected_source_refs"] = sorted(selected_payloads)
        recovery_record.update(
            {
                "stage": "context_hydration",
                "attempt": 1,
                "heartbeat_at": flow_analysis.now_utc(),
            }
        )
        persist_record("context_hydration")
        context_by_ref: dict[str, list[dict[str, Any]]] = {}
        if selected_payloads:
            for attempt in range(
                1, flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS + 1
            ):
                recovery_record["attempt"] = attempt
                persist_record("context_hydration")
                attempt_started = time.monotonic()
                try:
                    context_by_ref, context_query_hashes = (
                        await asyncio.to_thread(
                            flow_analysis_runtime.query_detectraptor_evtx_stack_context,
                            api,
                            hunt_id=hunt_id,
                            partition=partition,
                            evidence_by_group=selected_payloads,
                            time_predicate=time_predicate,
                            time_environment=time_environment,
                            detection_regex=detection_regex,
                            query_timeout_seconds=query_timeout_seconds,
                        )
                    )
                    recovery_record["query_diagnostics"] = [
                        *list(recovery_record.get("query_diagnostics") or []),
                        {
                            "stage": "context_hydration",
                            "attempt": attempt,
                            "status": "succeeded",
                            "elapsed_seconds": round(
                                time.monotonic() - attempt_started, 4
                            ),
                            "rows_received": sum(
                                len(rows) for rows in context_by_ref.values()
                            ),
                        },
                    ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
                    break
                except Exception as exc:
                    retryable = (
                        flow_analysis_runtime.is_retryable_read_only_transport_error(
                            exc, rows_received=0
                        )
                    )
                    retry_delay = flow_analysis_runtime.detectraptor_retry_delay(
                        attempt
                    )
                    recovery_record["transport_errors"] = [
                        *list(recovery_record.get("transport_errors") or []),
                        _detectraptor_transport_diagnostic(
                            exc,
                            stage="context_hydration",
                            attempt=attempt,
                            elapsed_seconds=time.monotonic() - attempt_started,
                            rows_received=0,
                            retry_delay_seconds=retry_delay,
                        ),
                    ][-MAX_DETECTRAPTOR_TRANSPORT_ERRORS:]
                    recovery_record["query_diagnostics"] = [
                        *list(recovery_record.get("query_diagnostics") or []),
                        dict(recovery_record["transport_errors"][-1]),
                    ][-MAX_DETECTRAPTOR_QUERY_DIAGNOSTICS:]
                    persist_record("context_hydration")
                    if (
                        not retryable
                        or attempt
                        >= flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS
                    ):
                        raise
                    await _detectraptor_transport_retry_wait(
                        api,
                        attempt=attempt,
                        reconnect_lock=reconnect_lock,
                    )
        recovery_record["query_hashes"]["context_hydration"] = context_query_hashes

        partition_source = flow_analysis_runtime.detectraptor_evtx_partition_source(
            org_id=org_id,
            hunt_id=hunt_id,
            partition=partition,
            watermark=cutoff,
        )
        source_metadata = dict(
            source_references.get(partition_source.source_id) or {}
        )
        context_row_number = max(
            int(acquired_model_rows),
            int(census.group_count if census is not None else 0),
        )
        evidence_rows_by_ref: dict[str, list[dict[str, Any]]] = {}
        for ref, rows in context_by_ref.items():
            hydrated: list[dict[str, Any]] = []
            for row in rows:
                context_row_number += 1
                context_ref = evidence_references.format_source_reference(
                    str(source_metadata.get("alias") or ""), context_row_number
                )
                source = _detectraptor_context_source(
                    source_metadata, row, row_number=context_row_number
                )
                fields = {
                    "Detection": partition.detection or "",
                    "EventTime": row.get("EventTime"),
                    "ClientId": str(row.get("ClientId") or ""),
                    "Fqdn": str(row.get("Fqdn") or ""),
                    "Computer": str(row.get("Computer") or ""),
                    "Channel": row.get("Channel"),
                    "EventID": row.get("EventID"),
                    "Username": row.get("Username"),
                    "EvidencePath": row.get("EvidencePath"),
                }
                hydrated.append(
                    {
                        "source_ref": context_ref,
                        "source": source,
                        "fields": fields,
                    }
                )
            context_row_count += len(hydrated)
            evidence_rows_by_ref[ref] = [
                {
                    "artifact": flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT,
                    "ref": row["source_ref"],
                    "source": copy.deepcopy(row["source"]),
                    "fields": copy.deepcopy(row["fields"]),
                }
                for row in hydrated[:3]
            ]
            metadata = selected_metadata[ref]
            interesting_context.append(
                {
                    "partition_id": partition.partition_id,
                    "detection": partition.detection or "",
                    "source_ref": ref,
                    "confidence": metadata["confidence"],
                    "summary": metadata["summary"],
                    "payload_field": metadata["payload_field"],
                    "payload_sha256": hashlib.sha256(
                        selected_payloads[ref].encode("utf-8")
                    ).hexdigest(),
                    "count": metadata["count"],
                    "first_seen": metadata["first_seen"],
                    "last_seen": metadata["last_seen"],
                    "events": [
                        {
                            "source_ref": row["source_ref"],
                            "event_time": row["fields"].get("EventTime"),
                            "client_id": row["fields"].get("ClientId"),
                            "fqdn": row["fields"].get("Fqdn"),
                            "computer": row["fields"].get("Computer"),
                            "channel": row["fields"].get("Channel"),
                            "event_id": row["fields"].get("EventID"),
                            "username": row["fields"].get("Username"),
                            "evidence_path": row["fields"].get("EvidencePath"),
                        }
                        for row in hydrated
                    ],
                }
            )
        for finding in initial_synthesis.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            evidence_rows = list(finding.get("evidence") or [])
            existing_refs = {
                str(item.get("ref") or "")
                for item in evidence_rows
                if isinstance(item, Mapping)
            }
            for item in list(evidence_rows):
                if not isinstance(item, Mapping):
                    continue
                for hydrated in evidence_rows_by_ref.get(
                    str(item.get("ref") or ""), []
                ):
                    if str(hydrated["ref"]) not in existing_refs:
                        evidence_rows.append(hydrated)
                        existing_refs.add(str(hydrated["ref"]))
            finding["evidence"] = evidence_rows
    else:
        recovery_record["selected_source_refs"] = []

    stage_timings["context_hydration_seconds"] = round(
        time.monotonic() - context_started, 4
    )
    stage_timings["total_seconds"] = round(
        time.monotonic() - partition_started, 4
    )
    recovery_record["timings"] = copy.deepcopy(stage_timings)
    stack_record["timings"] = copy.deepcopy(stage_timings)

    compact_initial = _compact_synthesis_result(initial_synthesis)
    recovery_record["initial_result"] = compact_initial
    persist_record("initial_accepted")

    full_result = copy.deepcopy(compact_initial)
    result = _compact_synthesis_result(full_result)
    recovery_record.update(
        {
            "status": "completed",
            "stage": "completed",
            "completed_at": flow_analysis.now_utc(),
            "heartbeat_at": flow_analysis.now_utc(),
            "result": result,
            "mode": str(stack_record.get("mode") or "direct"),
        }
    )
    if exact_stack:
        stack_record.update(
            {
                "evidence_followup_group_count": len(selected_payloads),
                "evidence_followup_row_count": context_row_count,
                "evidence_followup_matching_event_count": sum(
                    int(item.get("count") or 0)
                    for item in selected_metadata.values()
                ),
                "group_review": {
                    "protocol": collection_analysis.CONTEXT_WORKER_PROTOCOL,
                    "reviewed_group_count": acquired_model_rows,
                    "reportable_group_count": len(selected_payloads),
                    "uplift_candidate_count": len(uplift_rows),
                    "chunk_count": len(local_manifests),
                    "retried_chunk_count": sum(
                        int(item.get("attempts") or 0) > 1
                        for item in local_outcomes
                    ),
                    "runtime_files_persisted": False,
                },
                "context_hydration": {
                    "selected_group_count": len(selected_payloads),
                    "row_count": context_row_count,
                    "query_count": len(context_query_hashes),
                    "query_hashes": context_query_hashes,
                    "semantic_ai_passes": 0,
                },
            }
        )
    persist_record("completed")
    return {
        "result": result,
        "transient_result": full_result,
        "stack_record": stack_record,
        "interesting_context": interesting_context,
        "uplift_candidates": uplift_rows,
        "stats": {
            "partition_id": partition_id,
            "detection": partition.detection,
            "discovered_row_count": int(partition.row_count),
            "reviewed_row_count": int(recovery_record.get("acquired_row_count") or 0),
            "model_group_count": int(recovery_record.get("model_row_count") or 0),
            "query_sha256": str(
                dict(recovery_record.get("query_hashes") or {}).get(
                    "initial_analysis"
                )
                or ""
            ),
            "timings": copy.deepcopy(stage_timings),
        },
        "manifests": local_manifests,
        "outcomes": local_outcomes,
        "pool_status": final_pool_status,
        "timings": copy.deepcopy(stage_timings),
    }


async def _analyze_hunt_flows_locked(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    hunt_state: str,
    reported_result_rows: int,
    target_execution_coverage: str | None,
    targeted_client_count: int | None,
    review_scope: str,
    question: str,
    task_mode: str,
    response_depth: str,
    hunt_root: Path,
    update: bool,
    selected_artifacts: Iterable[str],
    retire_specialized_artifacts: Iterable[str],
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot,
    analysis_configuration: analysis_limits.AnalysisLimits,
    debug_validation: bool,
    spec: ResolvedAgentExecution,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    analysis_queue: DynamicAnalysisQueue[Any, Any] | None = None,
    shared_execute: Callable[..., Any] | None = None,
    time_scope: analysis_time_scope.TimeScope | None = None,
    detection_regex: str = "",
    synthesis_mode: str = "full",
) -> dict[str, Any]:
    """Analyze a full hunt aggregate or explicitly merge newly completed flows."""
    if not question.strip():
        raise ValueError("hunt analysis question cannot be empty")
    resolved_policy = policy_snapshot
    profiles = resolved_policy.profiles
    requested_time_scope = time_scope or analysis_time_scope.TimeScope("all")
    analysis_configuration.validate()
    limits = analysis_configuration.as_dict()
    maximum_tokens = analysis_configuration.maximum_evidence_tokens_per_item
    encoding = analysis_configuration.token_encoding
    started_at = flow_analysis.now_utc()
    cutoff = flow_analysis_runtime.query_server_cutoff(api)
    inventory_rows = flow_analysis_runtime.enumerate_hunt_flows(api, hunt_id)
    classified = flow_analysis_runtime.classify_hunt_inventory(inventory_rows)
    if reported_result_rows and not inventory_rows:
        raise RuntimeError(
            f"Hunt {hunt_id} reports {reported_result_rows} result rows, but "
            "hunt_flows() returned an empty inventory."
        )
    selected = {str(value).strip() for value in selected_artifacts if str(value).strip()}
    artifacts = _inventory_artifacts(inventory_rows, selected)
    requested_detection_regex = str(detection_regex or "").strip()
    if requested_detection_regex and len(requested_detection_regex) > 512:
        raise RuntimeError("--detection-regex must not exceed 512 characters.")
    if requested_detection_regex and set(artifacts) != {
        flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
    }:
        raise RuntimeError(
            "--detection-regex requires only "
            "DetectRaptor.Windows.Detection.Evtx."
        )
    resolved_time_scopes = analysis_time_scope.resolve_all(
        artifacts,
        profiles,
        requested_time_scope,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    time_filter_provenance = analysis_time_scope.provenance(
        artifacts,
        profiles,
        requested_time_scope,
        resolved_time_scopes,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    live_projections = _live_projections(
        artifacts,
        profiles,
        resolved_time_scopes,
    )
    server_time_predicates = {
        artifact: resolved.predicate()
        for artifact, resolved in resolved_time_scopes.items()
        if resolved.scope.bounded
    }
    server_time_environment = requested_time_scope.environment()
    evtx_artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
    detectraptor_partition_limit = spec.max_concurrency
    detectraptor_query_timeout = (
        flow_analysis_runtime.detectraptor_query_timeout_seconds()
        if evtx_artifact in artifacts
        else flow_analysis_runtime.DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS
    )
    method = "update" if update else "full"
    if update and evtx_artifact in artifacts:
        raise RuntimeError(
            "--update is not supported for detection-partitioned "
            "DetectRaptor.Windows.Detection.Evtx analysis; run a full analysis."
        )
    if (
        reported_result_rows
        and classified[flow_analysis.FLOW_SUCCESSFUL_TERMINAL]
        and not artifacts
    ):
        raise RuntimeError(
            f"Hunt {hunt_id} reports {reported_result_rows} result rows and "
            "successful terminal flows, but no result artifacts were identified."
        )
    aggregate_sources = [
        flow_analysis_runtime.aggregate_hunt_source(
            org_id=org_id, hunt_id=hunt_id, artifact=artifact, watermark=cutoff
        )
        for artifact in artifacts
    ]
    evtx_profile = artifact_profiles.resolve_profile(evtx_artifact, profiles)
    evtx_stack_config = _detectraptor_evtx_stack_config(evtx_profile)
    profile_hash = profile_identity(
        aggregate_sources, profiles, artifact_names=selected or set(artifacts)
    )
    analysis_id = analysis_id_for(
        scope_type="hunt",
        question=question,
        profile_hash=profile_hash,
        policy_limits=limits,
        spec=spec,
        task_mode=task_mode,
        response_depth=response_depth,
        time_scope=requested_time_scope,
        runtime_scope={
            "artifact_policy_sha256": resolved_policy.policy_sha256,
            **(
                {
                "analysis_mode": "detectraptor-evtx-auto",
                "recovery_schema": DETECTRAPTOR_RECOVERY_SCHEMA_VERSION,
                "prompt_policy_version": DETECTRAPTOR_PROMPT_POLICY_VERSION,
                "uplift_schema_version": DETECTRAPTOR_UPLIFT_SCHEMA_VERSION,
                "org_id": org_id,
                "stack_key_version": (
                    flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_KEY_VERSION
                ),
                "detection_regex": requested_detection_regex,
                "stack_policy": evtx_stack_config,
                }
                if evtx_artifact in artifacts
                else {}
            ),
        },
    )
    analysis_root = hunt_root / "analysis"
    state_path = analysis_root / STATE_FILENAME
    report_path = hunt_root / REPORT_FILENAME
    archived_state = archive_incompatible_state(
        state_path,
        analysis_id=analysis_id,
    )
    if archived_state is not None and report_path.is_file():
        archived_report = archived_state.parent / report_path.name
        if not archived_report.exists():
            atomic_io.write_text_atomic(
                archived_report,
                report_path.read_text(encoding="utf-8"),
            )
    state = load_state(
        state_path,
        scope_type="hunt",
        scope_id=hunt_id,
        analysis_id=analysis_id,
    )
    active_run_id = flow_analysis.run_identifier(
        scope_id=hunt_id,
        analysis_id=analysis_id,
        inventory_identity=[method, cutoff],
    )
    if not debug_validation and isinstance(state.get("last_validation_debug"), Mapping):
        state["last_validation_debug"] = {
            **dict(state["last_validation_debug"]),
            "current_run": False,
        }
    prior_checkpoint = dict(state.get("checkpoint") or {})
    prior_result = prior_checkpoint.get("result")
    if update and not isinstance(prior_result, Mapping):
        raise RuntimeError(
            "--update requires a successful full hunt analysis checkpoint first."
        )

    evtx_partitions: list[flow_analysis_runtime.DetectionPartition] = []
    evtx_stack_state: dict[str, Any] = {}
    evtx_discovery_stats: dict[str, Any] = {}
    if evtx_artifact in artifacts:
        try:
            for discovery_attempt in range(
                1, flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS + 1
            ):
                discovery_started = time.monotonic()
                try:
                    evtx_partitions = (
                        flow_analysis_runtime.discover_detectraptor_evtx_partitions(
                            api,
                            hunt_id=hunt_id,
                            time_predicate=server_time_predicates.get(
                                evtx_artifact, ""
                            ),
                            time_environment=server_time_environment,
                            detection_regex=requested_detection_regex,
                            stats=evtx_discovery_stats,
                            query_timeout_seconds=detectraptor_query_timeout,
                        )
                    )
                    evtx_discovery_stats.update(
                        {
                            "attempt": discovery_attempt,
                            "status": "succeeded",
                            "elapsed_seconds": round(
                                time.monotonic() - discovery_started, 4
                            ),
                            "query_timeout_seconds": detectraptor_query_timeout,
                        }
                    )
                    break
                except Exception as exc:
                    if (
                        not flow_analysis_runtime.is_retryable_read_only_transport_error(
                            exc, rows_received=0
                        )
                        or discovery_attempt
                        >= flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS
                    ):
                        raise
                    await _detectraptor_transport_retry_wait(
                        api,
                        attempt=discovery_attempt,
                    )
            if requested_detection_regex and not evtx_partitions:
                raise RuntimeError(
                    "--detection-regex matched no in-scope Detection.Name values."
                )
        except Exception as exc:
            completed_at = flow_analysis.now_utc()
            failure = {
                "run_id": active_run_id,
                "status": "failed",
                "method": method,
                "phase": "failed",
                "started_at": started_at,
                "completed_at": completed_at,
                "heartbeat_at": completed_at,
                "server_cutoff": cutoff,
                "time_scope": requested_time_scope.canonical(),
                "failure_stage": "detection_discovery",
                "failure_reason": str(exc)[:MAX_FAILED_CHUNK_ERROR_CHARS],
                "acquired_row_count": 0,
                "source_exhausted": False,
            }
            previous_active = state.get("active_analysis")
            runs = list(state.get("runs") or [])
            if isinstance(previous_active, Mapping) and str(
                previous_active.get("status") or ""
            ) == "running":
                runs.append(
                    {
                        **copy.deepcopy(dict(previous_active)),
                        "status": "interrupted",
                        "detected_at": completed_at,
                        "last_phase": str(
                            previous_active.get("phase") or "unknown"
                        ),
                    }
                )
            state["active_analysis"] = failure
            state["runs"] = _deduplicate_runs([*runs, failure])
            write_state(state_path, state)
            raise

        stack_records: list[dict[str, Any]] = []
        for partition in evtx_partitions:
            estimated_chunks = _estimated_detectraptor_chunks(
                partition,
                maximum_evidence_tokens=int(
                    limits["maximum_evidence_tokens_per_item"]
                ),
            )
            large = (
                partition.row_count >= int(evtx_stack_config["minimum_rows"])
                or estimated_chunks
                >= int(evtx_stack_config["minimum_estimated_chunks"])
            )
            record: dict[str, Any] = {
                "partition_id": partition.partition_id,
                "detection": partition.detection,
                "discovered_row_count": partition.row_count,
                "source_row_count": partition.row_count,
                "total_evidence_chars": partition.total_evidence_chars,
                "average_evidence_chars": round(
                    partition.total_evidence_chars / partition.row_count, 2
                )
                if partition.row_count
                else 0.0,
                "max_evidence_chars": partition.max_evidence_chars,
                "rows_over_preview": partition.rows_over_preview,
                "estimated_evidence_tokens": (
                    partition.total_evidence_chars + 3
                )
                // 4,
                "estimated_direct_chunks": estimated_chunks,
                "mode": "direct",
                "exact_group_count": 0,
                "represented_row_count": partition.row_count,
                "evidence_followup_group_count": 0,
                "evidence_followup_row_count": 0,
                "large": large,
                "minimum_reduction_rows": int(
                    evtx_stack_config["minimum_reduction_rows"]
                ),
                "minimum_reduction_percent": float(
                    evtx_stack_config["minimum_reduction_percent"]
                ),
            }
            stack_records.append(record)
        evtx_stack_state = {
            "schema_version": 2,
            "artifact": evtx_artifact,
            "analysis_mode": "automatic-exact-stack",
            "stack_key_version": (
                flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_KEY_VERSION
            ),
            "detection_regex": requested_detection_regex,
            "time_scope": requested_time_scope.canonical(),
            "discovery_query_sha256": str(
                evtx_discovery_stats.get("query_sha256") or ""
            ),
            "time_predicate": str(
                evtx_discovery_stats.get("time_predicate") or ""
            ),
            "matched_detection_count": len(evtx_partitions),
            "policy": copy.deepcopy(evtx_stack_config),
            "runtime_exclusions_applied": 0,
            "partitions": stack_records,
        }

    if update:
        cursor = str(state.get("inventory", {}).get("last_successful_check_at") or "")
        exact_sources = _update_sources(
            inventory_rows,
            org_id=org_id,
            hunt_id=hunt_id,
            selected=selected,
            cursor=cursor,
            cutoff=cutoff,
        )
        source_groups = flow_analysis_runtime.batched_source_groups(exact_sources)
        acquisition_sources = [group[0] for group in source_groups]
        segments = flow_analysis_runtime.iter_batched_flow_segments(
            api,
            exact_sources,
            projections=live_projections,
            time_predicates=server_time_predicates,
            time_environment=server_time_environment,
        )
    else:
        exact_sources = []
        generic_artifacts = [
            artifact for artifact in artifacts if artifact != evtx_artifact
        ]
        evtx_sources = [
            flow_analysis_runtime.detectraptor_evtx_partition_source(
                org_id=org_id,
                hunt_id=hunt_id,
                partition=partition,
                watermark=cutoff,
            )
            for partition in evtx_partitions
        ]
        acquisition_sources = [
            source
            for source in aggregate_sources
            if source.artifact != evtx_artifact
        ] + evtx_sources
        evtx_detection_partition_stats: dict[str, Any] = {}
        segments = flow_analysis_runtime.iter_hunt_result_segments(
            api,
            org_id=org_id,
            hunt_id=hunt_id,
            artifacts=generic_artifacts,
            cutoff=cutoff,
            projections=live_projections,
            time_predicates=server_time_predicates,
            time_environment=server_time_environment,
        )

    segments = _time_filter_segments(segments, resolved_time_scopes)
    if update:
        evtx_detection_partition_stats = {}

    validation_debug_path = analysis_root / VALIDATION_DEBUG_FILENAME
    validation_debug_attempts: dict[tuple[str, int], dict[str, Any]] = {}
    validation_debug_base = {
        "schema_version": VALIDATION_DEBUG_SCHEMA_VERSION,
        "operation_id": operation_log.current_operation_id(),
        "scope_type": "hunt",
        "scope_id": hunt_id,
        "analysis_id": analysis_id,
        "run_id": active_run_id,
        "method": method,
        "started_at": started_at,
        "server_cutoff": cutoff,
        "time_scope": requested_time_scope.canonical(),
        "raw_rows_persisted": False,
        "prompts_persisted": False,
        "model_output_persisted": False,
        "runtime_files_persisted": False,
        "maximum_attempt_records": MAX_VALIDATION_DEBUG_ATTEMPTS,
        "maximum_file_bytes": MAX_VALIDATION_DEBUG_BYTES,
    }
    validation_debug_reference: dict[str, Any] = {}
    if debug_validation:
        write_validation_debug(
            validation_debug_path,
            validation_debug_base,
            (),
            status="running",
        )
        validation_debug_reference = {
            "run_id": active_run_id,
            "path": str(validation_debug_path),
            "sha256": sha256_file(validation_debug_path),
            "status": "running",
            "current_run": True,
        }
    status_state = copy.deepcopy(state)
    status_state["task_mode"] = task_mode
    status_state["response_depth"] = response_depth
    status_state["time_filter"] = copy.deepcopy(time_filter_provenance)
    previous_active = status_state.get("active_analysis")
    if isinstance(previous_active, Mapping) and str(
        previous_active.get("status") or ""
    ) == "running":
        interrupted = {
            key: copy.deepcopy(previous_active[key])
            for key in (
                "run_id",
                "method",
                "started_at",
                "server_cutoff",
                "inventory_flow_count",
                "acquired_row_count",
                "emitted_chunk_count",
                "planned_chunk_count",
                "submitted_chunk_count",
                "completed_chunk_count",
                "abandoned_chunk_count",
                "active_agent_count",
                "acquisition_paused",
                "source_exhausted",
                "stop_requested",
                "accepted_chunk_count",
                "failed_chunk_count",
                "chunk_attempt_failure_count",
                "chunk_attempt_failures_truncated",
                "chunk_attempt_failures",
            )
            if key in previous_active
        }
        interrupted.update(
            {
                "status": "interrupted",
                "detected_at": flow_analysis.now_utc(),
                "last_phase": str(previous_active.get("phase") or "unknown"),
                "last_heartbeat_at": str(
                    previous_active.get("heartbeat_at") or ""
                ),
            }
        )
        status_state["runs"] = _deduplicate_runs(
            [*list(status_state.get("runs") or []), interrupted]
        )
    status_state["active_analysis"] = {
        "run_id": active_run_id,
        "status": "running",
        "method": method,
        "phase": "inventory_complete",
        "started_at": started_at,
        "heartbeat_at": flow_analysis.now_utc(),
        "server_cutoff": cutoff,
        "time_scope": requested_time_scope.canonical(),
        "inventory_flow_count": len(inventory_rows),
        "candidate_flow_count": len(exact_sources) if update else len(inventory_rows),
        "acquired_row_count": 0,
        "emitted_chunk_count": 0,
        "planned_chunk_count": 0,
        "submitted_chunk_count": 0,
        "completed_chunk_count": 0,
        "abandoned_chunk_count": 0,
        "active_agent_count": 0,
        "acquisition_paused": False,
        "source_exhausted": False,
        "stop_requested": False,
        "accepted_chunk_count": 0,
        "failed_chunk_count": 0,
        **(
            {"validation_debug": copy.deepcopy(validation_debug_reference)}
            if debug_validation
            else {}
        ),
    }
    evtx_recovery: dict[str, Any] = {}
    if evtx_artifact in artifacts:
        api_config = getattr(api, "api_config", "")
        safe_server_identity = str(getattr(api, "server_identity", "") or "")
        server_scope = (
            safe_server_identity
            if safe_server_identity
            else flow_analysis.sha256_identity(
                "detectraptor-conservative-server-scope",
                {
                    "api_config": str(api_config or ""),
                    "org_id": org_id,
                    "client_type": type(api).__name__,
                    "unverified_instance": (
                        "" if api_config else str(id(api))
                    ),
                },
            )
        )
        query_contract_sha256 = flow_analysis.sha256_identity(
            "detectraptor-query-contract-v1",
            {
                "discovery": flow_analysis_runtime.DETECTRAPTOR_EVTX_DETECTION_DISCOVERY_VQL,
                "census": flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_CENSUS_VQL,
                "groups": flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_GROUPS_VQL,
                "context": flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_CONTEXT_VQL,
                "projection": list(live_projections.get(evtx_artifact) or []),
                "stack_key_version": flow_analysis_runtime.DETECTRAPTOR_EVTX_STACK_KEY_VERSION,
                "output_contract": OUTPUT_CONTRACT,
                "prompt_policy_version": DETECTRAPTOR_PROMPT_POLICY_VERSION,
                "uplift_schema_version": DETECTRAPTOR_UPLIFT_SCHEMA_VERSION,
            },
        )
        recovery_contract = {
            "analysis_id": analysis_id,
            "server_scope": server_scope,
            "org_id": org_id,
            "hunt_id": hunt_id,
            "artifact": evtx_artifact,
            "time_scope": requested_time_scope.canonical(),
            "detection_regex": requested_detection_regex,
            "profile_sha256": profile_hash,
            "discovery_query_sha256": str(
                evtx_discovery_stats.get("query_sha256") or ""
            ),
            "query_contract_sha256": query_contract_sha256,
        }
        recovery_contract_sha256 = _sha256_json(recovery_contract)
        previous_recovery = status_state.get("detectraptor_recovery")
        if (
            isinstance(previous_recovery, Mapping)
            and int(previous_recovery.get("schema_version") or 0)
            == DETECTRAPTOR_RECOVERY_SCHEMA_VERSION
            and str(previous_recovery.get("contract_sha256") or "")
            == recovery_contract_sha256
        ):
            evtx_recovery = copy.deepcopy(dict(previous_recovery))
        else:
            evtx_recovery = {
                "schema_version": DETECTRAPTOR_RECOVERY_SCHEMA_VERSION,
                "contract": recovery_contract,
                "contract_sha256": recovery_contract_sha256,
                "created_at": flow_analysis.now_utc(),
                "partitions": [],
            }
        prior_by_id = {
            str(item.get("partition_id") or ""): dict(item)
            for item in evtx_recovery.get("partitions") or []
            if isinstance(item, Mapping)
        }
        current_recovery_partitions: list[dict[str, Any]] = []
        for partition in evtx_partitions:
            record = prior_by_id.get(partition.partition_id, {})
            compatible_completed = (
                str(record.get("status") or "") == "completed"
                and isinstance(record.get("result"), Mapping)
                and int(record.get("acquired_row_count") or 0)
                >= int(partition.row_count)
            )
            if not compatible_completed:
                if str(record.get("status") or "") == "running":
                    record.update(
                        {
                            "status": "interrupted",
                            "stage": "interrupted",
                            "interrupted_at": flow_analysis.now_utc(),
                        }
                    )
                elif int(record.get("acquired_row_count") or 0) < int(
                    partition.row_count
                ):
                    record = {}
                record.setdefault("status", "pending")
                record.setdefault("stage", "pending")
            record.update(
                {
                    "partition_id": partition.partition_id,
                    "detection": partition.detection,
                    "discovered_row_count": int(partition.row_count),
                }
            )
            current_recovery_partitions.append(record)
        evtx_recovery["partitions"] = current_recovery_partitions
        evtx_recovery["updated_at"] = flow_analysis.now_utc()
        status_state["detectraptor_recovery"] = evtx_recovery
    progress_lock = threading.RLock()
    last_progress_write = 0.0
    task_statuses: dict[str, str] = {}
    active_attempt_failures: dict[tuple[str, int], dict[str, Any]] = {}

    def persist_progress(
        *,
        phase: str | None = None,
        status: str | None = None,
        force: bool = False,
        **counts: Any,
    ) -> None:
        nonlocal last_progress_write
        with progress_lock:
            active = status_state.setdefault("active_analysis", {})
            if phase:
                active["phase"] = phase
            if status:
                active["status"] = status
            for key, value in counts.items():
                active[str(key)] = value
            active["heartbeat_at"] = flow_analysis.now_utc()
            if progress_callback is not None:
                progress_callback(
                    {
                        "phase": str(active.get("phase") or "running"),
                        "status": str(active.get("status") or "running"),
                        "hunt_id": hunt_id,
                        "acquired": int(active.get("acquired_row_count") or 0),
                        "emitted": int(active.get("emitted_chunk_count") or 0),
                        "accepted": int(active.get("accepted_chunk_count") or 0),
                        "failed": int(active.get("failed_chunk_count") or 0),
                        "active": int(active.get("active_agent_count") or 0),
                        "submitted": int(active.get("submitted_chunk_count") or 0),
                        "completed": int(active.get("completed_chunk_count") or 0),
                        "force": bool(force),
                    }
                )
            current = time.monotonic()
            if (
                not force
                and current - last_progress_write
                < PROGRESS_WRITE_INTERVAL_SECONDS
            ):
                return
            write_state(state_path, status_state)
            last_progress_write = current

    def finalize_validation_debug(status: str, completed_at: str) -> dict[str, Any]:
        if not debug_validation:
            return {}
        write_validation_debug(
            validation_debug_path,
            validation_debug_base,
            validation_debug_attempts.values(),
            status=status,
            completed_at=completed_at,
        )
        validation_debug_reference.update(
            {
                "sha256": sha256_file(validation_debug_path),
                "status": status,
                "completed_at": completed_at,
                "current_run": True,
            }
        )
        return copy.deepcopy(validation_debug_reference)

    def capture_synthesis_debug(synthesis: Mapping[str, Any]) -> None:
        if not debug_validation:
            return
        for task_index, raw_task in enumerate(synthesis.get("tasks") or []):
            if not isinstance(raw_task, Mapping):
                continue
            task_id = str(raw_task.get("task_id") or f"synthesis-{task_index}")
            stage = str(raw_task.get("stage") or "hunt-synthesis")
            history = [
                dict(item)
                for item in raw_task.get("attempt_history") or []
                if isinstance(item, Mapping)
            ]
            if not history and str(raw_task.get("status") or "") != "accepted":
                history = [dict(raw_task)]
            for history_index, item in enumerate(history, start=1):
                item_status = str(item.get("status") or "failed")
                if item_status == "accepted":
                    continue
                attempt = max(1, int(item.get("attempt") or history_index))
                run = dict(item.get("run") or {})
                output = str(run.get("output") or "")
                event = {
                    "chunk_id": task_id,
                    "attempt": attempt,
                    "status": item_status,
                    "stage": stage,
                    "failure_type": (
                        "synthesis_validation_failed"
                        if item.get("diagnostics")
                        or str(run.get("status") or "") in {"", "succeeded"}
                        else f"agent_{str(run.get('status') or 'failed')}"
                    ),
                    "error": item.get("error") or "synthesis validation failed",
                    "diagnostics": item.get("diagnostics") or [],
                    "response_sha256": (
                        _sha256_bytes(output.encode("utf-8")) if output else ""
                    ),
                }
                validation_debug_attempts[(f"synthesis:{task_id}", attempt)] = (
                    validation_debug_attempt(
                        event,
                        {
                            "ordinal": MAX_VALIDATION_DEBUG_ATTEMPTS + task_index,
                            "artifact": "hunt-synthesis",
                            "row_count": 0,
                            "input_tokens": 0,
                        },
                    )
                )
        write_validation_debug(
            validation_debug_path,
            validation_debug_base,
            validation_debug_attempts.values(),
            status="running",
        )

    def chunk_progress(event: dict[str, Any]) -> None:
        if str(event.get("phase") or "") != "chunk":
            return
        task_id = str(event.get("task_id") or "")
        chunk_id = str(event.get("chunk_id") or "")
        task_status = str(event.get("status") or "")
        if not task_id or task_status not in {
            "accepted",
            "repaired",
            "retrying",
            "failed",
        }:
            return
        with progress_lock:
            if task_status in {"accepted", "failed"}:
                task_statuses[task_id] = task_status
            if task_status in {"repaired", "retrying", "failed"}:
                attempt = max(1, int(event.get("attempt") or 1))
                manifest = dict(emitted_chunks.get(chunk_id) or {})
                compact = _compact_chunk_attempt_failure(
                    attempt=attempt,
                    status=task_status,
                    failure_type=str(event.get("failure_type") or "unknown_failure"),
                    error=event.get("error") or "chunk analysis failed",
                    diagnostics=[
                        *list(event.get("diagnostics") or []),
                    ],
                )
                active_attempt_failures[(chunk_id, attempt)] = {
                    "chunk_id": chunk_id,
                    "ordinal": int(manifest.get("ordinal") or 0),
                    "artifact": str(manifest.get("artifact") or "unknown"),
                    "row_count": int(manifest.get("row_count") or 0),
                    "input_tokens": int(manifest.get("input_tokens") or 0),
                    **compact,
                }
                if debug_validation:
                    validation_debug_attempts[(chunk_id, attempt)] = (
                        validation_debug_attempt(event, manifest)
                    )
                    write_validation_debug(
                        validation_debug_path,
                        validation_debug_base,
                        validation_debug_attempts.values(),
                        status="running",
                    )
                    validation_debug_reference.update(
                        {
                            "sha256": sha256_file(validation_debug_path),
                            "status": "running",
                        }
                    )
            ordered_failures = sorted(
                active_attempt_failures.values(),
                key=lambda item: (
                    int(item["ordinal"]),
                    str(item["chunk_id"]),
                    int(item["attempt"]),
                ),
            )
            persist_progress(
                phase="chunk_analysis",
                force=task_status in {"repaired", "retrying", "failed"},
                accepted_chunk_count=sum(
                    value == "accepted" for value in task_statuses.values()
                ),
                failed_chunk_count=sum(
                    value == "failed" for value in task_statuses.values()
                ),
                chunk_attempt_failure_count=len(ordered_failures),
                chunk_attempt_failures_truncated=max(
                    0,
                    len(ordered_failures) - MAX_FAILED_CHUNK_ATTEMPTS_PER_RUN,
                ),
                chunk_attempt_failures=ordered_failures[
                    :MAX_FAILED_CHUNK_ATTEMPTS_PER_RUN
                ],
                **(
                    {
                        "validation_debug": copy.deepcopy(
                            validation_debug_reference
                        )
                    }
                    if debug_validation
                    else {}
                ),
            )

    persist_progress(force=True)
    working_state = copy.deepcopy(status_state)
    source_references = ensure_analysis_source_aliases(
        working_state,
        acquisition_sources,
        scope_type="hunt",
        scope_id=hunt_id,
    )
    status_state["source_aliases"] = copy.deepcopy(working_state["source_aliases"])
    identity_ids = {
        flow_analysis.flow_identifiers(row)[0]
        for row in inventory_rows
        if flow_analysis.flow_identifiers(row)[0]
    }
    client_identities = flow_analysis_runtime.query_client_identity_map(api, identity_ids)
    flow_ids_by_client: dict[str, str] = {}
    flow_sets_by_client: dict[str, set[str]] = {}
    for row in inventory_rows:
        client_id, flow_id = flow_analysis.flow_identifiers(row)
        if client_id and flow_id:
            flow_sets_by_client.setdefault(client_id, set()).add(flow_id)
    for client_id, flow_ids in flow_sets_by_client.items():
        if len(flow_ids) == 1:
            flow_ids_by_client[client_id] = next(iter(flow_ids))
    evtx_partition_results: list[dict[str, Any]] = []
    evtx_partition_manifests: dict[str, dict[str, Any]] = {}
    evtx_partition_outcomes: list[dict[str, Any]] = []
    evtx_pool_totals = {
        "submitted": 0,
        "completed": 0,
        "abandoned": 0,
    }
    context_output_path = analysis_root / DETECTRAPTOR_CONTEXT_FILENAME
    uplift_output_path = analysis_root / DETECTRAPTOR_UPLIFT_FILENAME
    run_output_root = (
        analysis_root
        / "runs"
        / _safe_output_component(analysis_id, fallback="unknown-analysis")
        / _safe_output_component(active_run_id, fallback="unknown-run")
    )
    run_context_output_path = run_output_root / DETECTRAPTOR_CONTEXT_FILENAME
    run_uplift_output_path = run_output_root / DETECTRAPTOR_UPLIFT_FILENAME
    run_report_path = run_output_root / REPORT_FILENAME
    analysis_root.joinpath("detectraptor-uplift-candidates.json").unlink(
        missing_ok=True
    )
    existing_context_output = _read_optional_mapping(context_output_path)
    if context_output_path.exists():
        legacy_analysis_id = _safe_output_component(
            existing_context_output.get("analysis_id"), fallback="unknown-analysis"
        )
        legacy_run_id = _safe_output_component(
            existing_context_output.get("run_id"),
            fallback=(
                "legacy-" + sha256_file(context_output_path)[:12]
            ),
        )
        legacy_root = analysis_root / "runs" / legacy_analysis_id / legacy_run_id
        legacy_context = legacy_root / DETECTRAPTOR_CONTEXT_FILENAME
        if not legacy_context.exists():
            atomic_io.write_text_atomic(
                legacy_context, context_output_path.read_text(encoding="utf-8")
            )
            if uplift_output_path.exists():
                atomic_io.write_text_atomic(
                    legacy_root / DETECTRAPTOR_UPLIFT_FILENAME,
                    uplift_output_path.read_text(encoding="utf-8"),
                )
            if report_path.exists():
                atomic_io.write_text_atomic(
                    legacy_root / REPORT_FILENAME,
                    report_path.read_text(encoding="utf-8"),
                )
    current_partition_ids = {item.partition_id for item in evtx_partitions}
    evtx_interesting_context: list[dict[str, Any]] = [
        dict(item)
        for item in existing_context_output.get("groups") or []
        if isinstance(item, Mapping)
        and str(item.get("partition_id") or "") in current_partition_ids
    ]
    evtx_uplift_candidates = _read_detectraptor_uplift_csv(
        uplift_output_path,
        analysis_id=analysis_id,
        partition_by_detection={
            item.detection: item.partition_id for item in evtx_partitions
        },
    )

    def _persist_detectraptor_outputs_unlocked(*, run_status: str) -> None:
        """Atomically publish accepted grouped work while analysis continues."""
        if evtx_artifact not in artifacts:
            return
        context_payload = {
                "schema_version": 1,
                "hunt_id": hunt_id,
                "analysis_id": analysis_id,
                "run_id": active_run_id,
                "status": run_status,
                "provisional": str(hunt_state or "").strip().upper()
                not in {"FINISHED", "COMPLETED"},
                "updated_at": flow_analysis.now_utc(),
                "group_count": len(evtx_interesting_context),
                "event_count": sum(
                    len(item.get("events") or [])
                    for item in evtx_interesting_context
                ),
                "groups": evtx_interesting_context,
            }
        for output_path in (context_output_path, run_context_output_path):
            atomic_io.write_json_atomic(
                output_path,
                context_payload,
                sort_keys=True,
            )
        merged_uplift, conflict_count = _merge_detectraptor_uplift_rows(
            evtx_uplift_candidates
        )
        uplift_sha256 = _write_detectraptor_uplift_csv(
            uplift_output_path,
            hunt_id=hunt_id,
            analysis_id=analysis_id,
            status=run_status,
            rows=merged_uplift,
        )
        _write_detectraptor_uplift_csv(
            run_uplift_output_path,
            hunt_id=hunt_id,
            analysis_id=analysis_id,
            status=run_status,
            rows=merged_uplift,
        )
        evtx_stack_state["whitelist_candidates"] = {
            "schema_version": DETECTRAPTOR_UPLIFT_SCHEMA_VERSION,
            "status": run_status,
            "path": f"analysis/{DETECTRAPTOR_UPLIFT_FILENAME}",
            "sha256": uplift_sha256,
            "candidate_count": len(merged_uplift),
            "global_count": sum(
                str(item.get("Scope") or "") == "global"
                for item in merged_uplift
            ),
            "site_count": sum(
                str(item.get("Scope") or "") == "site"
                for item in merged_uplift
            ),
            "scope_conflict_count": conflict_count,
            "payloads_persisted": bool(merged_uplift),
            "run_path": str(run_uplift_output_path.relative_to(hunt_root)),
        }
        evtx_stack_state["run_outputs"] = {
            "run_id": active_run_id,
            "root": str(run_output_root.relative_to(hunt_root)),
            "interesting_context": str(
                run_context_output_path.relative_to(hunt_root)
            ),
            "whitelist_candidates": str(
                run_uplift_output_path.relative_to(hunt_root)
            ),
            "report": str(run_report_path.relative_to(hunt_root)),
        }
        progress_lines = [
            "# Velociraptor hunt analysis",
            "",
            "## Analysis metadata",
            "",
            f"- Hunt: `{hunt_id}`",
            f"- Question: {question}",
            f"- Status: `{run_status}`",
            "- Report mode: progressive atomic checkpoint",
            "- Velociraptor source of truth: yes",
            "",
            "## DetectRaptor progress",
            "",
            "| Detection | Status | Stage | Rows | Groups | Reportable | Time |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for record in evtx_recovery.get("partitions") or []:
            census = dict(record.get("census") or {})
            progress_lines.append(
                f"| {_compact_specialized_text(record.get('detection') or '<unnamed>')} | "
                f"{_compact_specialized_text(record.get('status') or 'pending')} | "
                f"{_compact_specialized_text(record.get('stage') or 'pending')} | "
                f"{int(record.get('discovered_row_count') or 0)} | "
                f"{int(census.get('group_count') or record.get('group_count') or 0)} | "
                f"{len(record.get('selected_source_refs') or [])} | "
                f"{float(dict(record.get('timings') or {}).get('total_seconds') or 0):.2f}s |"
            )
        progress_lines.extend(
            ["", "## AI-selected findings - analyst review required", ""]
        )
        progress_lines.extend(
            _render_detectraptor_report_notes(
                [
                    *evtx_interesting_context,
                    *_detectraptor_direct_report_groups(evtx_recovery),
                ],
                context_ledger=f"analysis/{DETECTRAPTOR_CONTEXT_FILENAME}",
            )
        )
        progress_lines.extend(
            [
                "",
                "## Potential whitelist opportunities",
                "",
                f"- Candidates: {len(merged_uplift)}",
                f"- Global: {sum(str(item.get('Scope') or '') == 'global' for item in merged_uplift)}",
                f"- Site-specific: {sum(str(item.get('Scope') or '') == 'site' for item in merged_uplift)}",
                f"- Review file: `analysis/{DETECTRAPTOR_UPLIFT_FILENAME}`",
            ]
        )
        progress_lines.extend(
            [
                "",
                "## Output ledgers",
                "",
                f"- Interesting context: `analysis/{DETECTRAPTOR_CONTEXT_FILENAME}`",
                f"- Whitelist candidates: `analysis/{DETECTRAPTOR_UPLIFT_FILENAME}`",
            ]
        )
        report_text = "\n".join(progress_lines).rstrip() + "\n"
        for output_path in (report_path, run_report_path):
            atomic_io.write_text_atomic(output_path, report_text)

    def persist_detectraptor_outputs(*, run_status: str) -> None:
        with progress_lock:
            _persist_detectraptor_outputs_unlocked(run_status=run_status)
    if evtx_artifact in artifacts:
        recovery_by_id = {
            str(item.get("partition_id") or ""): item
            for item in evtx_recovery.get("partitions") or []
            if isinstance(item, dict)
        }
        stack_by_id = {
            str(item.get("partition_id") or ""): item
            for item in evtx_stack_state.get("partitions") or []
            if isinstance(item, dict)
        }
        partition_order = {
            partition.partition_id: index
            for index, partition in enumerate(evtx_partitions)
        }
        partition_stats_by_id: dict[str, dict[str, Any]] = {}
        partition_results_by_id: dict[str, dict[str, Any]] = {}
        active_partitions: dict[str, dict[str, Any]] = {}
        peak_active_partition_count = 0
        reused_partition_count = 0
        reanalyzed_partition_count = 0
        reconnect_lock = asyncio.Lock()
        partition_semaphore = asyncio.Semaphore(
            max(1, min(detectraptor_partition_limit, len(evtx_partitions) or 1))
        )

        def recovered_partition_result(
            partition: flow_analysis_runtime.DetectionPartition,
            recovery_record: Mapping[str, Any],
        ) -> dict[str, Any]:
            transient_result = copy.deepcopy(dict(recovery_record["result"]))
            # Schema-4 recovery written before artifact normalization remains
            # safely resumable without forcing an expensive partition replay.
            transient_result["artifact"] = str(
                transient_result.get("artifact") or evtx_artifact
            )
            return {
                "transient_result": transient_result,
                "stats": {
                    "partition_id": partition.partition_id,
                    "detection": partition.detection,
                    "discovered_row_count": int(partition.row_count),
                    "reviewed_row_count": int(
                        recovery_record.get("acquired_row_count") or 0
                    ),
                    "model_group_count": int(
                        recovery_record.get("model_row_count") or 0
                    ),
                    "query_sha256": str(
                        dict(recovery_record.get("query_hashes") or {}).get(
                            "initial_analysis"
                        )
                        or ""
                    ),
                    "timings": copy.deepcopy(
                        dict(recovery_record.get("timings") or {})
                    ),
                },
                "manifests": {},
                "outcomes": [],
                "pool_status": AnalysisPoolStatus(),
            }

        def publish_partition_payloads(
            partition_id: str,
            partition_result: Mapping[str, Any],
        ) -> None:
            with progress_lock:
                evtx_interesting_context[:] = [
                    item
                    for item in evtx_interesting_context
                    if str(item.get("partition_id") or "") != partition_id
                ]
                evtx_interesting_context.extend(
                    copy.deepcopy(partition_result.get("interesting_context") or [])
                )
                evtx_uplift_candidates[:] = [
                    item
                    for item in evtx_uplift_candidates
                    if str(item.get("partition_id") or "") != partition_id
                ]
                evtx_uplift_candidates.extend(
                    copy.deepcopy(partition_result.get("uplift_candidates") or [])
                )
                _persist_detectraptor_outputs_unlocked(run_status="running")

        async def analyze_partition(
            partition: flow_analysis_runtime.DetectionPartition,
        ) -> dict[str, Any]:
            partition_id = partition.partition_id
            recovery_record = recovery_by_id[partition_id]
            stack_record = stack_by_id[partition_id]

            def persist_detection_record(stage: str) -> None:
                nonlocal peak_active_partition_count
                with progress_lock:
                    recovery_record["stage"] = stage
                    recovery_record["heartbeat_at"] = flow_analysis.now_utc()
                    evtx_recovery["updated_at"] = flow_analysis.now_utc()
                    status_state["detectraptor_recovery"] = evtx_recovery
                    active_partitions[partition_id] = {
                        "detection": partition.detection,
                        "stage": stage,
                        "attempt": int(recovery_record.get("attempt") or 0),
                    }
                    active = status_state.setdefault("active_analysis", {})
                    peak_active_partition_count = max(
                        peak_active_partition_count, len(active_partitions)
                    )
                    active.update(
                        {
                            "phase": "detectraptor_partition_analysis",
                            "active_partition_count": len(active_partitions),
                            "active_partitions": copy.deepcopy(active_partitions),
                            "peak_active_partition_count": peak_active_partition_count,
                            "analysis_concurrency_limit": detectraptor_partition_limit,
                            "detectraptor_query_timeout_seconds": (
                                detectraptor_query_timeout
                            ),
                            "reused_partition_count": reused_partition_count,
                            "reanalyzed_partition_count": reanalyzed_partition_count,
                            "heartbeat_at": flow_analysis.now_utc(),
                        }
                    )
                    write_state(state_path, status_state)

            def partition_progress(**counts: Any) -> None:
                filtered = {
                    key: value
                    for key, value in counts.items()
                    if key
                    not in {
                        "active_detection",
                        "partition_id",
                        "detection_stage",
                        "phase",
                    }
                }
                persist_progress(
                    phase="detectraptor_partition_analysis",
                    active_partition_count=len(active_partitions),
                    **filtered,
                )

            async with partition_semaphore:
                try:
                    partition_result = await _analyze_detectraptor_partition(
                        api,
                        org_id=org_id,
                        hunt_id=hunt_id,
                        hunt_state=hunt_state,
                        cutoff=cutoff,
                        partition=partition,
                        stack_record=stack_record,
                        synthesis_mode=synthesis_mode,
                        recovery_record=recovery_record,
                        projection=live_projections.get(evtx_artifact),
                        time_predicate=server_time_predicates.get(evtx_artifact, ""),
                        time_environment=server_time_environment,
                        detection_regex=requested_detection_regex,
                        source_references=source_references,
                        source_aliases=working_state["source_aliases"],
                        profiles=profiles,
                        client_identities=client_identities,
                        flow_ids_by_client=flow_ids_by_client,
                        analysis_id=analysis_id,
                        question=question,
                        limits=limits,
                        maximum_tokens=maximum_tokens,
                        encoding_name=encoding,
                        spec=spec,
                        workdir=analysis_root,
                        shared_execute=shared_execute,
                        analysis_queue=analysis_queue,
                        reconnect_lock=reconnect_lock,
                        query_timeout_seconds=detectraptor_query_timeout,
                        persist_record=persist_detection_record,
                        progress=partition_progress,
                    )
                except Exception as exc:
                    completed_at = flow_analysis.now_utc()
                    recovery_record.update(
                        {
                            "status": "failed",
                            "stage": str(recovery_record.get("stage") or "unknown"),
                            "completed_at": completed_at,
                            "failure_type": type(exc).__name__,
                            "failure_reason": (
                                "transport_"
                                + flow_analysis_runtime.grpc_status_name(exc).casefold()
                                if flow_analysis_runtime.grpc_status_name(exc)
                                else "partition_stage_failed"
                            ),
                        }
                    )
                    with progress_lock:
                        active_partitions.pop(partition_id, None)
                        status_state["detectraptor_recovery"] = evtx_recovery
                        write_state(state_path, status_state)
                        _persist_detectraptor_outputs_unlocked(run_status="failed")
                    raise
                with progress_lock:
                    active_partitions.pop(partition_id, None)
                publish_partition_payloads(partition_id, partition_result)
                return partition_result

        pending: list[
            tuple[flow_analysis_runtime.DetectionPartition, asyncio.Task[Any]]
        ] = []
        for partition in evtx_partitions:
            recovery_record = recovery_by_id[partition.partition_id]
            stack_record = stack_by_id[partition.partition_id]
            if (
                str(recovery_record.get("status") or "") == "completed"
                and isinstance(recovery_record.get("result"), Mapping)
            ):
                reused_partition_count += 1
                census = dict(recovery_record.get("census") or {})
                stack_record.update(
                    {
                        "mode": str(recovery_record.get("mode") or "direct"),
                        "represented_row_count": int(
                            recovery_record.get("acquired_row_count") or 0
                        ),
                        "source_row_count": int(
                            recovery_record.get("acquired_row_count") or 0
                        ),
                        "model_row_count": int(
                            recovery_record.get("model_row_count") or 0
                        ),
                        "exact_group_count": int(census.get("group_count") or 0),
                        "singleton_group_count": int(census.get("singleton_group_count") or 0),
                        "largest_group_rows": int(census.get("largest_group_rows") or 0),
                        "census_query_sha256": str(census.get("query_sha256") or ""),
                        "analysis_query_sha256": str(
                            dict(recovery_record.get("query_hashes") or {}).get(
                                "initial_analysis"
                            )
                            or ""
                        ),
                        "timings": copy.deepcopy(
                            dict(recovery_record.get("timings") or {})
                        ),
                    }
                )
                partition_results_by_id[partition.partition_id] = recovered_partition_result(
                    partition, recovery_record
                )
            else:
                reanalyzed_partition_count += 1
                pending.append(
                    (
                        partition,
                        asyncio.create_task(
                            analyze_partition(partition),
                            name=f"detectraptor-{partition.partition_id}",
                        ),
                    )
                )

        evtx_stack_state["operations"] = {
            "analysis_concurrency_limit": detectraptor_partition_limit,
            "query_timeout_seconds": detectraptor_query_timeout,
            "retry_backoff_seconds": list(
                flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_BACKOFF_SECONDS
            ),
            "maximum_attempts": (
                flow_analysis_runtime.DETECTRAPTOR_TRANSPORT_ATTEMPTS
            ),
            "reused_partition_count": reused_partition_count,
            "reanalyzed_partition_count": reanalyzed_partition_count,
        }

        pending_values = await asyncio.gather(
            *(task for _partition, task in pending),
            return_exceptions=True,
        )
        failures: list[tuple[flow_analysis_runtime.DetectionPartition, BaseException]] = []
        for (partition, _task), value in zip(pending, pending_values):
            if isinstance(value, BaseException):
                failures.append((partition, value))
            else:
                partition_results_by_id[partition.partition_id] = dict(value)
        evtx_stack_state["operations"]["peak_active_partition_count"] = (
            peak_active_partition_count
        )
        if failures:
            failed_partition, failure = failures[0]
            completed_at = flow_analysis.now_utc()
            active = status_state.setdefault("active_analysis", {})
            active.update(
                {
                    "status": "failed",
                    "phase": "failed",
                    "completed_at": completed_at,
                    "failure_stage": "detectraptor_partition",
                    "failed_partition_id": failed_partition.partition_id,
                    "failed_detection": failed_partition.detection,
                    "partition_id": failed_partition.partition_id,
                    "active_detection": failed_partition.detection,
                    "detection_stage": str(
                        recovery_by_id[failed_partition.partition_id].get("stage")
                        or "unknown"
                    ),
                    "attempt": int(
                        recovery_by_id[failed_partition.partition_id].get("attempt")
                        or 0
                    ),
                    "failure_reason": str(failure)[:MAX_FAILED_CHUNK_ERROR_CHARS],
                }
            )
            status_state["runs"] = _deduplicate_runs(
                [
                    *list(status_state.get("runs") or []),
                    {
                        "run_id": active_run_id,
                        "method": method,
                        "status": "failed",
                        "started_at": started_at,
                        "completed_at": completed_at,
                        "server_cutoff": cutoff,
                        "failure_stage": "detectraptor_partition",
                        "active_detection": failed_partition.detection,
                        "partition_id": failed_partition.partition_id,
                        "detection_stage": str(
                            recovery_by_id[failed_partition.partition_id].get("stage")
                            or "unknown"
                        ),
                        "attempt": int(
                            recovery_by_id[failed_partition.partition_id].get("attempt")
                            or 0
                        ),
                    },
                ]
            )
            write_state(state_path, status_state)
            persist_detectraptor_outputs(run_status="failed")
            raise failure

        evtx_interesting_context.sort(
            key=lambda item: (
                partition_order.get(str(item.get("partition_id") or ""), 1 << 30),
                str(item.get("source_ref") or ""),
            )
        )
        evtx_uplift_candidates.sort(
            key=lambda item: (
                partition_order.get(str(item.get("partition_id") or ""), 1 << 30),
                str(item.get("PayloadSHA256") or ""),
            )
        )
        persist_detectraptor_outputs(run_status="running")
        for partition in evtx_partitions:
            partition_result = partition_results_by_id[partition.partition_id]
            transient_result = copy.deepcopy(
                dict(partition_result["transient_result"])
            )
            transient_result["artifact"] = str(
                transient_result.get("artifact") or evtx_artifact
            )
            evtx_partition_results.append(transient_result)
            partition_stats_by_id[partition.partition_id] = dict(
                partition_result["stats"]
            )
            for manifest in dict(partition_result["manifests"]).values():
                chunk_id = str(manifest["chunk_id"])
                if chunk_id in evtx_partition_manifests:
                    raise RuntimeError(
                        f"Duplicate EVTX partition chunk ID: {chunk_id!r}"
                    )
                evtx_partition_manifests[chunk_id] = dict(manifest)
            evtx_partition_outcomes.extend(partition_result["outcomes"])
            partition_pool = partition_result["pool_status"]
            evtx_pool_totals["submitted"] += int(partition_pool.submitted)
            evtx_pool_totals["completed"] += int(partition_pool.completed)
            evtx_pool_totals["abandoned"] += int(partition_pool.abandoned)

        partition_stats = [
            partition_stats_by_id[partition.partition_id]
            for partition in evtx_partitions
        ]
        group_reviews = [
            dict(record.get("group_review") or {})
            for record in stack_by_id.values()
            if isinstance(record.get("group_review"), Mapping)
        ]
        context_hydrations = [
            dict(record.get("context_hydration") or {})
            for record in stack_by_id.values()
            if isinstance(record.get("context_hydration"), Mapping)
        ]
        if group_reviews:
            evtx_stack_state["evidence_followup"] = {
                "selected_group_count": sum(
                    int(item.get("selected_group_count") or 0)
                    for item in context_hydrations
                ),
                "reviewed_group_count": sum(
                    int(item.get("reviewed_group_count") or 0)
                    for item in group_reviews
                ),
                "reportable_group_count": sum(
                    int(item.get("reportable_group_count") or 0)
                    for item in group_reviews
                ),
                "representative_row_count": sum(
                    int(item.get("row_count") or 0)
                    for item in context_hydrations
                ),
                "matching_event_count": sum(
                    int(item.get("count") or 0)
                    for item in evtx_interesting_context
                ),
                "protocol": collection_analysis.CONTEXT_WORKER_PROTOCOL,
                "semantic_ai_passes_after_chunk_review": 0,
            }
        evtx_detection_partition_stats.update(
            {
                "artifact": evtx_artifact,
                "discovery_query_count": 1,
                "partition_query_count": len(partition_stats),
                "partition_count": len(partition_stats),
                "discovered_row_count": sum(
                    int(item.get("discovered_row_count") or 0)
                    for item in partition_stats
                ),
                "reviewed_row_count": sum(
                    int(item.get("reviewed_row_count") or 0)
                    for item in partition_stats
                ),
                "model_group_count": sum(
                    int(item.get("model_group_count") or 0)
                    for item in partition_stats
                ),
                "partitions": partition_stats,
            }
        )
        active = status_state.setdefault("active_analysis", {})
        active.pop("active_partitions", None)
        active["active_partition_count"] = 0
    accepted_results: dict[str, dict[str, Any]] = {}
    emitted_chunks: dict[str, dict[str, Any]] = {}
    failed_outcomes: dict[str, dict[str, Any]] = {}
    chunk_outcomes: list[dict[str, Any]] = []
    reviewed_rows = 0
    final_pool_status = AnalysisPoolStatus()

    def segment_acquired(row_count: int) -> None:
        nonlocal reviewed_rows
        reviewed_rows += int(row_count)
        persist_progress(
            acquired_row_count=reviewed_rows,
        )

    def chunk_emitted(manifest: Mapping[str, Any]) -> None:
        chunk_id = str(manifest.get("chunk_id") or "")
        if not chunk_id or chunk_id in emitted_chunks:
            raise RuntimeError(f"Duplicate or empty streaming chunk ID: {chunk_id!r}")
        emitted_chunks[chunk_id] = dict(manifest)
        persist_progress(
            phase="chunk_analysis",
            force=len(emitted_chunks) == 1,
            emitted_chunk_count=len(emitted_chunks),
            planned_chunk_count=len(emitted_chunks),
            acquired_row_count=reviewed_rows,
        )

    def active_changed(active_count: int) -> None:
        persist_progress(
            phase="chunk_analysis",
            active_agent_count=int(active_count),
            acquisition_paused=int(active_count) >= int(spec.max_concurrency),
        )

    def pool_changed(pool_status: AnalysisPoolStatus) -> None:
        nonlocal final_pool_status
        final_pool_status = pool_status
        persist_progress(
            phase="chunk_analysis",
            force=(
                bool(pool_status.stop_requested)
                or (
                    bool(pool_status.source_exhausted)
                    and int(pool_status.active) == 0
                )
            ),
            submitted_chunk_count=int(pool_status.submitted),
            completed_chunk_count=int(pool_status.completed),
            abandoned_chunk_count=int(pool_status.abandoned),
            active_agent_count=int(pool_status.active),
            acquisition_paused=(
                int(pool_status.active) >= int(spec.max_concurrency)
            ),
            source_exhausted=bool(pool_status.source_exhausted),
            stop_requested=bool(pool_status.stop_requested),
        )

    persist_progress(phase="acquiring_results", force=True)
    chunks = iter_streaming_chunks(
        segments,
        profiles=profiles,
        source_references=source_references,
        maximum_tokens=maximum_tokens,
        encoding_name=encoding,
        analysis_id=analysis_id,
        client_identities=client_identities,
        flow_ids_by_client=flow_ids_by_client,
        on_segment=segment_acquired,
    )
    work_items = iter_streaming_chunk_work(
        chunks,
        source_aliases=working_state["source_aliases"],
        scope_type="hunt",
        scope_id=hunt_id,
        analysis_id=analysis_id,
        question=question,
        limits=limits,
        encoding_name=encoding,
        on_chunk=chunk_emitted,
    )

    def persist_acquisition_failure(exc: Exception) -> None:
        completed_at = flow_analysis.now_utc()
        persist_progress(
            phase="failed",
            status="failed",
            force=True,
            completed_at=completed_at,
            failure_stage="acquisition_or_chunk_planning",
            failure_reason=str(exc)[:MAX_FAILED_CHUNK_ERROR_CHARS],
        )
        failure_state = copy.deepcopy(status_state)
        failure_state["runs"] = _deduplicate_runs(
            [
                *list(failure_state.get("runs") or []),
                {
                    "run_id": active_run_id,
                    "method": method,
                    "status": "failed",
                    "time_scope": requested_time_scope.canonical(),
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "server_cutoff": cutoff,
                    "failure_stage": "acquisition_or_chunk_planning",
                    "acquired_row_count": reviewed_rows,
                    "emitted_chunk_count": len(emitted_chunks),
                    "detectraptor_evtx_detection_partitions": copy.deepcopy(
                        evtx_detection_partition_stats
                    ),
                },
            ]
        )
        write_state(state_path, failure_state)

    try:
        outcomes = execute_streaming_chunks_async(
            work_items=work_items,
            limits=limits,
            encoding_name=encoding,
            spec=spec,
            workdir=analysis_root,
            runtime_dir=analysis_root / ".api-runtime",
            progress_callback=chunk_progress,
            active_callback=active_changed,
            status_callback=pool_changed,
            analysis_queue=analysis_queue,
            shared_execute=shared_execute,
        )
        if inspect.isawaitable(outcomes):
            outcomes = await outcomes
    except Exception as exc:
        persist_acquisition_failure(exc)
        raise
    try:
        for outcome in outcomes:
            chunk_outcomes.append(
                {
                    str(key): copy.deepcopy(value)
                    for key, value in dict(outcome).items()
                    if str(key) != "result"
                }
            )
            chunk_id = str(outcome.get("chunk_id") or "")
            if str(outcome.get("status") or "") == "accepted" and isinstance(
                outcome.get("result"), Mapping
            ):
                accepted_results[chunk_id] = dict(outcome.pop("result"))
            else:
                failed_outcomes[chunk_id] = dict(outcome)
    except Exception as exc:
        persist_acquisition_failure(exc)
        raise

    persist_progress(phase="reconciling_accounting", force=True)
    if (
            not update
            and not requested_time_scope.bounded
            and reported_result_rows
            and reviewed_rows == 0
            and int(evtx_detection_partition_stats.get("reviewed_row_count") or 0)
            == 0
    ):
        raise RuntimeError(
            f"Hunt {hunt_id} reports {reported_result_rows} rows, but "
            "hunt_results() returned zero rows for the selected artifacts."
        )
    planned_chunk_count = len(emitted_chunks) + len(evtx_partition_manifests)
    failed_chunk_count = len(failed_outcomes)
    accounted_chunk_ids = set(accepted_results).union(failed_outcomes)
    if accounted_chunk_ids != set(emitted_chunks):
        missing = sorted(set(emitted_chunks).difference(accounted_chunk_ids))
        raise RuntimeError(
            "Streaming hunt analysis lost authoritative chunk accounting: "
            f"{', '.join(missing) or 'unexpected outcome'}"
        )
    emitted_row_count = sum(
        int(manifest.get("row_count") or 0) for manifest in emitted_chunks.values()
    )
    accepted_row_count = sum(
        int(emitted_chunks[chunk_id].get("row_count") or 0)
        for chunk_id in accepted_results
    )
    if not failed_chunk_count and emitted_row_count != reviewed_rows:
        raise RuntimeError(
            "Streaming hunt analysis row accounting does not match acquisition "
            f"({emitted_row_count} emitted != {reviewed_rows} acquired)."
        )
    successful_flows = classified[flow_analysis.FLOW_SUCCESSFUL_TERMINAL]
    completed_clients = {
        flow_analysis.flow_identifiers(row)[0]
        for row in successful_flows
        if flow_analysis.flow_identifiers(row)[0]
    }
    denominator = max(0, int(targeted_client_count or 0))
    evtx_source_rows = (
        int(evtx_detection_partition_stats.get("reviewed_row_count") or 0)
        if evtx_artifact in artifacts
        else 0
    )
    evtx_model_rows = (
        int(evtx_detection_partition_stats.get("model_group_count") or 0)
        if evtx_artifact in artifacts
        else 0
    )
    accounted_reviewed_rows = reviewed_rows + evtx_source_rows
    if accounted_reviewed_rows < reviewed_rows:
        raise RuntimeError("DetectRaptor EVTX source accounting underflowed.")
    if evtx_stack_state:
        acquired_by_partition = {
            str(item.get("partition_id") or ""): item
            for item in evtx_detection_partition_stats.get("partitions") or []
        }
        for record in evtx_stack_state.get("partitions") or []:
            acquired = acquired_by_partition.get(
                str(record.get("partition_id") or ""), {}
            )
            record["represented_row_count"] = int(
                acquired.get("reviewed_row_count")
                or record.get("represented_row_count")
                or 0
            )
            record["model_row_count"] = int(
                acquired.get("model_group_count")
                or acquired.get("reviewed_row_count")
                or 0
            )
            record["analysis_query_sha256"] = str(
                acquired.get("query_sha256") or ""
            )
            if record.get("mode") == "exact_stack":
                record["source_row_count"] = record["represented_row_count"]
                record["exact_group_count"] = record["model_row_count"]
                record["reduced_row_count"] = max(
                    0,
                    record["represented_row_count"] - record["model_row_count"],
                )
                record["reduction_percent"] = round(
                    (
                        record["reduced_row_count"]
                        * 100.0
                        / record["represented_row_count"]
                    )
                    if record["represented_row_count"]
                    else 0.0,
                    4,
                )
    completion_ratio = (
        min(1.0, len(completed_clients) / denominator) if denominator else None
    )
    completion_warning = (
        f"Only {completion_ratio:.1%} of targeted machines have completed; "
        "results may be materially incomplete."
        if completion_ratio is not None and completion_ratio < 0.70
        else ""
    )
    chunk_attempt_failures, chunk_attempt_failure_count = (
        _bounded_chunk_attempt_failures(
            [*evtx_partition_outcomes, *chunk_outcomes],
            {**evtx_partition_manifests, **emitted_chunks},
        )
    )
    accepted_chunk_total = len(accepted_results) + len(evtx_partition_manifests)
    terminal_chunk_total = accepted_chunk_total + failed_chunk_count
    submitted_chunk_total = max(
        int(final_pool_status.submitted) + int(evtx_pool_totals["submitted"]),
        terminal_chunk_total,
    )
    completed_chunk_total = max(
        int(final_pool_status.completed) + int(evtx_pool_totals["completed"]),
        terminal_chunk_total,
    )

    run_record = {
        "run_id": active_run_id,
        "method": method,
        "time_scope": requested_time_scope.canonical(),
        "started_at": started_at,
        "completed_at": flow_analysis.now_utc(),
        "server_cutoff": cutoff,
        "candidate_flow_count": len(exact_sources) if update else len(inventory_rows),
        "detectraptor_evtx_detection_partitions": copy.deepcopy(
            evtx_detection_partition_stats
        ),
        "acquired_row_count": accounted_reviewed_rows,
        "model_input_row_count": reviewed_rows + evtx_model_rows,
        "detectraptor_evtx_source_row_count": evtx_source_rows,
        "detectraptor_evtx_model_row_count": evtx_model_rows,
        "accounted_row_count": accounted_reviewed_rows,
        "reviewed_row_count": accepted_row_count + evtx_model_rows,
        "emitted_chunk_count": planned_chunk_count,
        "planned_chunk_count": planned_chunk_count,
        "submitted_chunk_count": submitted_chunk_total,
        "completed_chunk_count": completed_chunk_total,
        "abandoned_chunk_count": int(final_pool_status.abandoned)
        + int(evtx_pool_totals["abandoned"]),
        "accepted_chunk_count": accepted_chunk_total,
        "failed_chunk_count": failed_chunk_count,
        "recovered_chunk_count": len(
            {
                str(outcome.get("chunk_id") or "")
                for outcome in [*evtx_partition_outcomes, *chunk_outcomes]
                if str(outcome.get("status") or "") == "accepted"
                and outcome.get("attempt_failures")
            }
        ),
        "chunk_attempt_failure_count": chunk_attempt_failure_count,
        "chunk_attempt_failures_truncated": max(
            0, chunk_attempt_failure_count - len(chunk_attempt_failures)
        ),
        "chunk_attempt_failures": chunk_attempt_failures,
        "synthesis_status": "not_run",
        "synthesis_failures": [],
    }
    synthesis_inputs: list[Mapping[str, Any]] = []
    if update:
        synthesis_inputs.append(dict(prior_checkpoint.get("accepted_result") or prior_result))
    synthesis_inputs.extend(evtx_partition_results)
    synthesis_inputs.extend(
        accepted_results[chunk_id] for chunk_id in sorted(accepted_results)
    )
    accepted_candidates = _compact_synthesis_result(synthesis_policy.preliminary(
        synthesis_inputs, question=question, scope="hunt",
        failures=([f"{failed_chunk_count} chunk(s) were not accepted; coverage is incomplete."]
                  if failed_chunk_count else []),
    ))
    prior_coverage = dict(dict(prior_checkpoint.get("accepted_result") or prior_result or {}).get("coverage") or {}) if update else {}
    accepted_candidates["coverage"].update(
        planned_chunks=int(prior_coverage.get("planned_chunks") or 0) + planned_chunk_count,
        accepted_chunks=int(prior_coverage.get("accepted_chunks") or 0) + accepted_chunk_total,
        planned_rows=int(prior_coverage.get("planned_rows") or 0) + reviewed_rows + evtx_model_rows,
        reviewed_rows=int(prior_coverage.get("reviewed_rows") or 0) + accepted_row_count + evtx_model_rows,
        acquired_source_rows=int(prior_coverage.get("acquired_source_rows") or 0) + accounted_reviewed_rows,
        target_execution=str(target_execution_coverage or "unknown"),
        source_hunt_state=str(hunt_state or "unknown"),
    )
    if failed_chunk_count:
        run_record["status"] = "failed"
        completed_at = flow_analysis.now_utc()
        persist_progress(
            phase="failed",
            status="failed",
            force=True,
            completed_at=completed_at,
            failure_stage="chunk_analysis",
        )
        failure_state = copy.deepcopy(status_state)
        failure_state["partial_candidates"] = {
            "accepted_result": accepted_candidates,
            "accepted_fingerprint": synthesis_policy.fingerprint(accepted_candidates),
        }
        active_failure = failure_state.get("active_analysis")
        if isinstance(active_failure, dict):
            active_failure.pop("chunk_attempt_failure_count", None)
            active_failure.pop("chunk_attempt_failures_truncated", None)
            active_failure.pop("chunk_attempt_failures", None)
            active_failure.pop("validation_debug", None)
        debug_reference = finalize_validation_debug("failed", completed_at)
        if debug_reference:
            failure_state["last_validation_debug"] = debug_reference
            failure_state.setdefault("persistence_manifest", {})[
                "validation_debug"
            ] = "bounded_validation_debug"
        failure_state["runs"] = _deduplicate_runs(
            [*list(failure_state.get("runs") or []), run_record]
        )
        write_state(state_path, failure_state)
        raise RuntimeError(
            f"Hunt analysis failed closed: {failed_chunk_count} chunk(s) were not accepted. "
            "No synthesis checkpoint or update cursor was advanced."
        )

    persist_progress(
        phase="cumulative_synthesis",
        force=True,
        acquired_row_count=accounted_reviewed_rows,
        emitted_chunk_count=planned_chunk_count,
        planned_chunk_count=planned_chunk_count,
        submitted_chunk_count=int(run_record["submitted_chunk_count"]),
        completed_chunk_count=int(run_record["completed_chunk_count"]),
        abandoned_chunk_count=int(run_record["abandoned_chunk_count"]),
        accepted_chunk_count=int(run_record["accepted_chunk_count"]),
        failed_chunk_count=int(run_record["failed_chunk_count"]),
        active_agent_count=0,
        source_exhausted=True,
    )
    synthesis_exception: Exception | None = None
    try:
        synthesis = _synthesize_transient_results(
            scope_id=hunt_id,
            results=synthesis_inputs,
            synthesis_mode=synthesis_mode,
            question=question,
            spec=spec,
            limits=limits,
            encoding_name=encoding,
            workdir=analysis_root,
            runtime_dir=analysis_root / ".api-runtime",
            task_mode=task_mode,
            response_depth=response_depth,
            shared_execute=shared_execute,
            schedule=(
                (
                    lambda task, worker: analysis_queue.enqueue(
                        "hunt-synthesis",
                        task,
                        execute=worker,
                        weight=max(1, len(str(task.prompt)) // 4),
                    )
                )
                if analysis_queue is not None
                else None
            ),
        )
        if inspect.isawaitable(synthesis):
            synthesis = await synthesis
    except Exception as exc:
        synthesis_exception = exc
        synthesis = {
            "status": "failed",
            "tasks": [
                {
                    "task_id": "hunt-analysis-synthesis",
                    "stage": "hunt-synthesis",
                    "status": "failed",
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    )[:MAX_FAILED_CHUNK_ERROR_CHARS],
                }
            ],
        }
    capture_synthesis_debug(synthesis)
    synthesis_status = str(synthesis.get("status") or "failed")
    synthesis_failures = (
        []
        if synthesis_status == "complete"
        else _bounded_synthesis_failures(synthesis)
    )
    run_record["synthesis_status"] = synthesis_status
    run_record["synthesis_failures"] = synthesis_failures
    publishable_synthesis = (
        synthesis_status in {"complete", "complete_with_failures"}
        and isinstance(synthesis.get("host_result"), Mapping)
    )
    if not publishable_synthesis:
        run_record["status"] = "failed"
        completed_at = flow_analysis.now_utc()
        persist_progress(
            phase="failed",
            status="failed",
            force=True,
            completed_at=completed_at,
            failure_stage="cumulative_synthesis",
        )
        failure_state = copy.deepcopy(status_state)
        failure_state["partial_candidates"] = {
            "accepted_result": accepted_candidates,
            "accepted_fingerprint": synthesis_policy.fingerprint(accepted_candidates),
        }
        active_failure = failure_state.get("active_analysis")
        if isinstance(active_failure, dict):
            active_failure.pop("chunk_attempt_failure_count", None)
            active_failure.pop("chunk_attempt_failures_truncated", None)
            active_failure.pop("chunk_attempt_failures", None)
            active_failure.pop("validation_debug", None)
        debug_reference = finalize_validation_debug("failed", completed_at)
        if debug_reference:
            failure_state["last_validation_debug"] = debug_reference
            failure_state.setdefault("persistence_manifest", {})[
                "validation_debug"
            ] = "bounded_validation_debug"
        failure_state["runs"] = _deduplicate_runs(
            [*list(failure_state.get("runs") or []), run_record]
        )
        write_state(state_path, failure_state)
        persist_detectraptor_outputs(run_status="failed")
        error = RuntimeError(
            "Hunt synthesis failed closed; the prior checkpoint and update cursor were retained."
        )
        if synthesis_exception is not None:
            raise error from synthesis_exception
        raise error

    full_result = copy.deepcopy(dict(synthesis["host_result"]))
    if synthesis_mode == "none":
        full_result = copy.deepcopy(accepted_candidates)
    result = _compact_synthesis_result(full_result)
    if synthesis_mode == "full":
        result["findings"] = analysis_summary.consolidate_exact_findings(
            result.get("findings") or [], id_prefix="F"
        )
    working_state.pop("partial_candidates", None)
    prior_generation = int(prior_checkpoint.get("generation") or 0)
    prior_rows = int(prior_checkpoint.get("row_count") or 0) if update else 0
    working_state.update(
        {
            "schema_version": flow_analysis.SCHEMA_VERSION,
            "review_scope": review_scope,
            "analysis_method": method,
            "task_mode": task_mode,
            "response_depth": response_depth,
            "time_filter": copy.deepcopy(time_filter_provenance),
            "artifact_policy": resolved_policy.metadata(),
            "analysis_limits": analysis_configuration.as_dict(),
            "analysis_limits_identity": analysis_configuration.identity(),
            "analyst_agent": analyst_execution_metadata(spec),
            "persistence_manifest": {
                "state": "checkpoint_only",
                "report": "compact_checkpoint",
                "raw_rows": False,
                "prompts": False,
                "chunk_results": False,
            },
            "checkpoint": {
                "generation": prior_generation + 1,
                "completed_at": flow_analysis.now_utc(),
                "method": method,
                "artifacts": artifacts,
                "row_count": prior_rows + accounted_reviewed_rows,
                "last_update_row_count": accounted_reviewed_rows if update else 0,
                "result": result,
                "accepted_result": accepted_candidates,
                "accepted_fingerprint": synthesis_policy.fingerprint(accepted_candidates),
            },
            "synthesis": {
                "status": synthesis_status,
                "completed_at": flow_analysis.now_utc(),
                "input_result_count": len(synthesis_inputs),
                "failure_count": len(synthesis_failures),
            },
        }
    )
    counts = {key: len(value) for key, value in classified.items()}
    inventory = working_state.setdefault("inventory", {})
    inventory.update(
        {
            "scan_started_at": started_at,
            "scan_completed_at": flow_analysis.now_utc(),
            "terminal_observed_through": cutoff,
            "last_successful_check_at": cutoff,
            "last_full_analysis_at": (
                str(inventory.get("last_full_analysis_at") or "")
                if update
                else cutoff
            ),
            "flow_counts": counts,
            "reported_result_rows": max(0, int(reported_result_rows)),
            "targeted_client_count": denominator,
            "completed_client_count": len(completed_clients),
            "completion_ratio": completion_ratio,
            "completion_warning": completion_warning,
            "hunt_state": hunt_state,
        }
    )
    result_review = (
        "complete" if synthesis_status == "complete" else "partial"
    )
    target_coverage = str(target_execution_coverage or "unknown")
    working_state["coverage"] = {
        "result_review": result_review,
        "target_execution": target_coverage,
        "time_filter": str(time_filter_provenance["coverage"]),
        "overall": (
            "complete"
            if result_review == "complete"
            and target_coverage in {"complete", "not_assessed"}
            and time_filter_provenance["coverage"]
            in {"complete", "not_requested"}
            else "partial"
        ),
    }
    if evtx_stack_state:
        working_state["detectraptor_stack"] = copy.deepcopy(evtx_stack_state)
        working_state["persistence_manifest"]["detectraptor_stack"] = (
            "compact_state"
        )
        if synthesis_status == "complete":
            # Recovery is only an unfinished/degraded-run checkpoint. A fully
            # accepted publication retires it so a later ordinary full command
            # rebuilds from Velociraptor. A deterministic synthesis fallback
            # retains completed partitions for a synthesis-only retry.
            working_state.pop("detectraptor_recovery", None)
        elif evtx_recovery:
            working_state["detectraptor_recovery"] = copy.deepcopy(evtx_recovery)
            working_state["persistence_manifest"]["detectraptor_recovery"] = (
                "compact_unfinished_run_checkpoint"
            )
    else:
        working_state.pop("detectraptor_stack", None)
        working_state.pop("detectraptor_recovery", None)
    run_record["status"] = synthesis_status
    run_record["completed_at"] = flow_analysis.now_utc()
    debug_reference = finalize_validation_debug(
        synthesis_status,
        str(run_record["completed_at"]),
    )
    if debug_reference:
        working_state["last_validation_debug"] = debug_reference
        working_state["persistence_manifest"][
            "validation_debug"
        ] = "bounded_validation_debug"
    elif working_state.get("last_validation_debug"):
        working_state["persistence_manifest"][
            "validation_debug"
        ] = "bounded_validation_debug"
    working_state["runs"] = _deduplicate_runs(
        [*list(working_state.get("runs") or []), run_record]
    )
    _prune_checkpoint_source_aliases(
        working_state,
        result,
        current_source_ids=[
            str(metadata.get("source_id") or "")
            for metadata in source_references.values()
        ],
    )
    supplement_path = analysis_root / "finding-evidence.md"
    if analysis_summary.needs_finding_supplement(full_result):
        atomic_io.write_text_atomic(
            supplement_path,
            analysis_summary.render_finding_supplement(
                full_result, title="Hunt finding evidence"
            ),
        )
        working_state["finding_evidence_file"] = str(supplement_path)
    else:
        supplement_path.unlink(missing_ok=True)
        working_state.pop("finding_evidence_file", None)
    persist_progress(phase="publishing", force=True)
    working_state.pop("active_analysis", None)
    retired_specialized_artifacts = retire_specialized_analysis(
        working_state,
        retire_specialized_artifacts,
    )
    if retired_specialized_artifacts:
        analysis_root.joinpath("review-items.json").unlink(missing_ok=True)
        current_run = next(
            (
                record
                for record in reversed(list(working_state.get("runs") or []))
                if str(dict(record).get("run_id") or "") == active_run_id
            ),
            None,
        )
        if isinstance(current_run, dict):
            current_run["retired_specialized_artifacts"] = (
                retired_specialized_artifacts
            )
    if evtx_stack_state:
        persist_detectraptor_outputs(run_status=synthesis_status)
        evtx_stack_state.update(
            {
                "interesting_context_file": str(context_output_path),
                "whitelist_candidates_file": str(uplift_output_path),
                "interesting_group_count": len(evtx_interesting_context),
                "interesting_event_count": sum(
                    len(item.get("events") or [])
                    for item in evtx_interesting_context
                ),
            }
        )
        working_state["detectraptor_stack"] = copy.deepcopy(evtx_stack_state)
        working_state["persistence_manifest"].update(
            {
                "detectraptor_interesting_context": "separate_result_ledger",
                "detectraptor_whitelist_candidates": (
                    "selected_full_payload_candidates"
                ),
            }
        )
    compact_persisted_evidence(working_state)
    write_state(state_path, working_state)
    canonical_report_path = _write_canonical_hunt_report(
        hunt_root,
        question=question,
        flow_state=working_state,
        specialized_state=dict(
            working_state.get("specialized_analysis") or {}
        ),
    )
    if evtx_stack_state:
        atomic_io.write_text_atomic(
            run_report_path,
            canonical_report_path.read_text(encoding="utf-8"),
        )
    compact_result = compact_hunt_result(working_state)
    return {
        "action": "live_hunt_flow_analysis",
        "hunt_id": hunt_id,
        "analysis_method": method,
        "task_mode": task_mode,
        "response_depth": response_depth,
        "status": str(working_state["coverage"]["overall"]),
        "result_review_coverage": result_review,
        "target_execution_coverage": target_coverage,
        "review_scope": review_scope,
        "time_filter": copy.deepcopy(time_filter_provenance),
        "artifact_policy": resolved_policy.metadata(),
        "candidate_flow_count": len(exact_sources) if update else len(inventory_rows),
        "reviewed_row_count": accepted_row_count + evtx_model_rows,
        "accounted_row_count": accounted_reviewed_rows,
        "model_input_row_count": reviewed_rows + evtx_model_rows,
        "emitted_chunk_count": planned_chunk_count,
        "planned_chunk_count": planned_chunk_count,
        "accepted_chunk_count": len(accepted_results)
        + len(evtx_partition_manifests),
        "failed_chunk_count": 0,
        "synthesis_status": synthesis_status,
        "synthesis_failure_count": len(synthesis_failures),
        "analysis_state_file": str(state_path),
        "analysis_memory_file": str(report_path),
        "finding_evidence_file": str(working_state.get("finding_evidence_file") or ""),
        "analysis_result": compact_result,
        "chat_summary": _chat_summary_with_detectraptor_stack(
            analysis_summary.render_chat_summary(
                compact_result,
                title=f"Hunt {hunt_id} analysis summary",
                status=str(working_state["coverage"]["overall"]),
                coverage=working_state["coverage"],
            ),
            detectraptor_stack=evtx_stack_state,
            source_rows=evtx_source_rows,
            model_rows=evtx_model_rows,
        ),
        "run_id": str(run_record["run_id"]),
        "terminal_observed_through": cutoff,
        "completion_warning": completion_warning,
        "detectraptor_evtx_detection_partitions": copy.deepcopy(
            evtx_detection_partition_stats
        ),
        "detectraptor_stack": copy.deepcopy(evtx_stack_state),
        "detection_regex": requested_detection_regex,
        "detectraptor_interesting_context_file": str(
            evtx_stack_state.get("interesting_context_file") or ""
        ),
        "detectraptor_whitelist_candidates_file": str(
            evtx_stack_state.get("whitelist_candidates_file") or ""
        ),
        "raw_evidence_persisted": bool(evtx_uplift_candidates),
        "candidate_payloads_persisted": bool(evtx_uplift_candidates),
        "server_authoritative": True,
        **(
            {"validation_debug_file": str(validation_debug_path)}
            if debug_validation
            else {}
        ),
    }


def _hunt_debug_session(*args: Any, **kwargs: Any) -> agent_diagnostics.DebugSession | None:
    if not bool(kwargs.get("debug_validation", False)):
        return None
    hunt_root = Path(kwargs["hunt_root"])
    hunt_id = str(kwargs.get("hunt_id") or "unknown")
    return agent_diagnostics.DebugSession(
        hunt_root / "analysis" / VALIDATION_DEBUG_FILENAME,
        scope_type="hunt",
        scope_id=hunt_id,
        lane=("stream_update" if bool(kwargs.get("update", False)) else "stream_full"),
    )


@agent_diagnostics.auto_debug_scope(_hunt_debug_session)
def analyze_hunt_flows(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    hunt_state: str,
    reported_result_rows: int = 0,
    target_execution_coverage: str | None = None,
    targeted_client_count: int | None = None,
    review_scope: str = REVIEW_SCOPE_MANAGED_COLLECTION,
    question: str,
    task_mode: str = "targeted_hunt",
    response_depth: str = "",
    hunt_root: Path,
    update: bool = False,
    selected_artifacts: Iterable[str] = (),
    retire_specialized_artifacts: Iterable[str] = (),
    artifact_references: Iterable[str | Path] = (),
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot | None = None,
    limits: analysis_limits.AnalysisLimits,
    debug_validation: bool = False,
    spec: ResolvedAgentExecution,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    time_scope: analysis_time_scope.TimeScope | None = None,
    detection_regex: str = "",
    synthesis_mode: str = "full",
) -> dict[str, Any]:
    limits.validate()
    normalized_task_mode = normalize_profile_name(task_mode or "targeted_hunt")
    if normalized_task_mode not in PROFILE_NAMES:
        raise ValueError(f"Unknown task mode: {normalized_task_mode}")
    normalized_response_depth = normalize_response_depth(response_depth)
    if not normalized_response_depth:
        normalized_response_depth = load_agent_profile_config().profiles[
            normalized_task_mode
        ].default_depth
    if normalized_response_depth not in RESPONSE_DEPTH_NAMES:
        raise ValueError(f"Unknown response depth: {normalized_response_depth}")
    resolved_policy = artifact_policy.resolve_operation_policy(
        artifact_references=artifact_references,
        policy_snapshot=policy_snapshot,
    )
    analysis_root = hunt_root / "analysis"

    async def run_scope() -> dict[str, Any]:
        shared_runner: AgentRunner | None = None
        shared_limits: dict[str, Any] | None = None
        runner_lock = asyncio.Lock()
        analysis_queue: DynamicAnalysisQueue[Any, Any] = DynamicAnalysisQueue(
            max_concurrency=max(1, int(spec.max_concurrency)),
            prefetch=1,
            lane_queue_size=1,
            max_inflight_weight=(
                limits.maximum_evidence_tokens_per_item
                * max(1, int(spec.max_concurrency))
            ),
        )

        async def shared_execute(
            task: AgentRequest,
            *,
            limits: AgentRuntimeLimits,
            progress_callback: Callable[[dict[str, Any]], None] | None,
        ) -> Any:
            nonlocal shared_runner, shared_limits
            resolved_limits = asdict(limits)
            async with runner_lock:
                if shared_runner is None:
                    shared_runner = create_agent_runner(
                        spec,
                        limits=limits,
                        persist_runtime_files=False,
                    )
                    shared_limits = resolved_limits
                elif shared_limits != resolved_limits:
                    raise RuntimeError(
                        "Hunt artifact groups resolved incompatible analyst runtime limits."
                    )
                runner = shared_runner
            value = runner.run(
                task,
                workdir=analysis_root,
                output_dir=analysis_root / ".api-runtime",
                progress_callback=progress_callback,
            )
            return await value if inspect.isawaitable(value) else value

        lifecycle_state_path = analysis_root / STATE_FILENAME
        preexisting_state = _read_optional_mapping(lifecycle_state_path)
        preexisting_active = preexisting_state.get("active_analysis")
        preexisting_running = isinstance(preexisting_active, Mapping) and str(
            preexisting_active.get("status") or ""
        ) == "running"
        preexisting_running_run_id = (
            str(preexisting_active.get("run_id") or "")
            if preexisting_running
            else ""
        )
        preexisting_running_started_at = (
            str(preexisting_active.get("started_at") or "")
            if preexisting_running
            else ""
        )
        result: dict[str, Any] | None = None
        failure: Exception | None = None
        try:
            await analysis_queue.start()
            result = await _analyze_hunt_flows_locked(
                api,
                org_id=org_id,
                hunt_id=hunt_id,
                hunt_state=hunt_state,
                reported_result_rows=reported_result_rows,
                target_execution_coverage=target_execution_coverage,
                targeted_client_count=targeted_client_count,
                review_scope=review_scope,
                question=question,
                task_mode=normalized_task_mode,
                response_depth=normalized_response_depth,
                synthesis_mode=synthesis_mode,
                hunt_root=hunt_root,
                update=update,
                selected_artifacts=selected_artifacts,
                retire_specialized_artifacts=retire_specialized_artifacts,
                policy_snapshot=resolved_policy,
                analysis_configuration=limits,
                debug_validation=debug_validation,
                spec=spec,
                progress_callback=progress_callback,
                analysis_queue=analysis_queue,
                shared_execute=shared_execute,
                time_scope=time_scope,
                detection_regex=detection_regex,
            )
        except Exception as exc:
            failure = exc
            raise
        finally:
            cleanup_failure: Exception | None = None
            try:
                analysis_queue.mark_sources_exhausted()
                await analysis_queue.close()
                if shared_runner is not None:
                    value = shared_runner.close()
                    if inspect.isawaitable(value):
                        await value
            except Exception as exc:
                cleanup_failure = exc
            finally:
                terminal_error = failure or cleanup_failure
                if terminal_error is not None:
                    _terminalize_unhandled_active_analysis(
                        lifecycle_state_path,
                        terminal_error,
                        preexisting_running_run_id=preexisting_running_run_id,
                        preexisting_running_started_at=(
                            preexisting_running_started_at
                        ),
                    )
            if cleanup_failure is not None and failure is None:
                raise cleanup_failure

        if result is None:
            raise RuntimeError("Hunt analysis completed without a result.")
        try:
            _verify_completed_hunt_publication(
                lifecycle_state_path,
                result,
                debug_validation=debug_validation,
            )
        except Exception as exc:
            _terminalize_unhandled_active_analysis(
                lifecycle_state_path,
                exc,
                preexisting_running_run_id=preexisting_running_run_id,
                preexisting_running_started_at=preexisting_running_started_at,
            )
            raise
        return result

    return asyncio.run(run_scope())


def render_hunt_report(
    state: Mapping[str, Any],
    *,
    question: str,
    hunt_root: Path | None = None,
) -> str:
    result = compact_hunt_result(state)
    coverage = dict(state.get("coverage") or {})
    inventory = dict(state.get("inventory") or {})
    counts = dict(inventory.get("flow_counts") or {})
    checkpoint = dict(state.get("checkpoint") or {})
    detectraptor_stack = dict(state.get("detectraptor_stack") or {})
    detectraptor_recovery = dict(state.get("detectraptor_recovery") or {})
    active_analysis = dict(state.get("active_analysis") or {})
    latest_run = dict(list(state.get("runs") or [{}])[-1])
    time_filter = dict(state.get("time_filter") or {})
    lines = [
        "# Velociraptor hunt analysis",
        "",
        "## Analysis metadata",
        "",
        f"- Hunt: `{state.get('scope_id', '')}`",
        f"- Question: {question}",
        f"- Task mode: `{state.get('task_mode', 'targeted_hunt')}`",
        f"- Response depth: `{state.get('response_depth', 'standard')}`",
        f"- Review scope: `{state.get('review_scope', REVIEW_SCOPE_MANAGED_COLLECTION)}`",
        f"- Analysis method: `{state.get('analysis_method', 'full')}`",
        f"- Updated: `{state.get('updated_at', '')}`",
        "- Velociraptor source of truth: yes",
        "- Bulk raw result export: no",
        *(
            [
                f"- Analysis status: `{active_analysis.get('status')}`",
                f"- Failure stage: `{active_analysis.get('failure_stage') or 'unknown'}`",
                "- Failure reason: "
                f"{_compact_specialized_text(active_analysis.get('failure_reason') or 'unknown')}",
            ]
            if str(active_analysis.get("status") or "") == "failed"
            else []
        ),
        "",
        "## Coverage",
        "",
        f"- Result review: `{coverage.get('result_review', 'unknown')}`",
        f"- Target execution: `{coverage.get('target_execution', 'unknown')}`",
        f"- Analysis time filter: `{coverage.get('time_filter', time_filter.get('coverage', 'not_requested'))}`",
        f"- Overall: `{coverage.get('overall', 'unknown')}`",
        f"- Synthesis: `{dict(state.get('synthesis') or {}).get('status', 'unknown')}`",
        *(
            [
                "- Review boundary: all server-reported results for the selected hunt; "
                "target execution was not assessed."
            ]
            if state.get("review_scope") == REVIEW_SCOPE_AD_HOC
            else []
        ),
        f"- Successful terminal flows: {int(counts.get(flow_analysis.FLOW_SUCCESSFUL_TERMINAL) or 0)}",
        f"- Failed terminal flows: {int(counts.get(flow_analysis.FLOW_FAILED_TERMINAL) or 0)}",
        f"- Open flows deferred: {int(counts.get(flow_analysis.FLOW_OPEN) or 0)}",
        f"- Unknown-state flows deferred: {int(counts.get(flow_analysis.FLOW_UNKNOWN) or 0)}",
        f"- Cumulative reviewed rows: {int(checkpoint.get('row_count') or 0)}",
        f"- Last successful check: `{inventory.get('last_successful_check_at', '')}`",
    ]
    resolved_time_artifacts = dict(time_filter.get("resolved_artifacts") or {})
    collection_time_support = dict(
        time_filter.get("collection_time_bound_support") or {}
    )
    requested_fields = [
        str(value) for value in time_filter.get("requested_time_fields") or []
    ]
    lines.extend(
        [
            "",
            "## Analysis time filter",
            "",
            f"- Mode: `{time_filter.get('mode') or 'all'}`",
            f"- Requested after: `{time_filter.get('time_after') or ''}` (exclusive)",
            f"- Requested before: `{time_filter.get('time_before') or ''}` (exclusive)",
            "- Requested time fields: "
            + (
                ", ".join(f"`{value}`" for value in requested_fields)
                if requested_fields
                else "artifact defaults"
            ),
            f"- Coverage: `{time_filter.get('coverage') or 'not_requested'}`",
            "- Artifacts filtered: "
            + (
                ", ".join(
                    f"`{value}`"
                    for value in time_filter.get("filtered_artifacts") or []
                )
                or "none"
            ),
            "- Artifacts left unfiltered: "
            + (
                ", ".join(
                    f"`{value}`"
                    for value in time_filter.get("unfiltered_artifacts") or []
                )
                or "none"
            ),
            "- Collection `DateAfter`/`DateBefore` support is recorded separately "
            "and does not imply analysis-time support.",
        ]
    )
    if resolved_time_artifacts:
        lines.extend(
            [
                "",
                "| Artifact | Roles | Resolved expressions | Semantics | Collection bounds |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for artifact, raw_resolution in sorted(resolved_time_artifacts.items()):
            resolution = dict(raw_resolution or {})
            roles = [str(value) for value in resolution.get("roles") or []]
            expressions = dict(resolution.get("expressions") or {})
            semantics = dict(resolution.get("semantics") or {})
            expression_text = "; ".join(
                f"{role}: " + ", ".join(str(value) for value in expressions.get(role) or [])
                for role in roles
            )
            semantics_text = "; ".join(
                f"{role}: {semantics.get(role) or ''}" for role in roles
            )
            lines.append(
                "| "
                + " | ".join(
                    value.replace("|", "\\|")
                    for value in (
                        str(artifact),
                        ", ".join(roles),
                        expression_text,
                        semantics_text,
                        str(collection_time_support.get(artifact) or "unknown"),
                    )
                )
                + " |"
            )
    if detectraptor_stack:
        evidence_followup = dict(
            detectraptor_stack.get("evidence_followup") or {}
        )
        whitelist_candidates = dict(
            detectraptor_stack.get("whitelist_candidates") or {}
        )
        lines.extend(
            [
                "",
                "## DetectRaptor EVTX automatic review plan",
                "",
                f"- Detection regex: `{detectraptor_stack.get('detection_regex') or ''}`",
                f"- Matched detections: {int(detectraptor_stack.get('matched_detection_count') or 0)}",
                f"- Source rows accounted: {int(latest_run.get('detectraptor_evtx_source_row_count') or 0)}",
                f"- EVTX model rows/groups: {int(latest_run.get('detectraptor_evtx_model_row_count') or 0)}",
                f"- Full-payload groups reviewed: {int(evidence_followup.get('reviewed_group_count') or 0)}",
                f"- Reportable groups returned: {int(evidence_followup.get('reportable_group_count') or 0)}",
                "- Runtime exclusions applied: 0",
                f"- Interesting context ledger: `{detectraptor_stack.get('interesting_context_file') or ''}`",
                f"- Whitelist candidates: {int(whitelist_candidates.get('candidate_count') or 0)} "
                f"({int(whitelist_candidates.get('global_count') or 0)} global; "
                f"{int(whitelist_candidates.get('site_count') or 0)} site-specific)",
                f"- Whitelist review file: `{whitelist_candidates.get('path') or ''}`",
                "",
                "| Detection | Mode | Discovered | Source/represented | Exact groups | Reduction | Context hydration | Time |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for item in detectraptor_stack.get("partitions") or []:
            lines.append(
                f"| {_compact_specialized_text(item.get('detection') or '<missing>')} | "
                f"{_compact_specialized_text(item.get('mode') or 'unknown')} | "
                f"{int(item.get('discovered_row_count') or 0)} | "
                f"{int(item.get('source_row_count') or 0)} | "
                f"{int(item.get('exact_group_count') or 0)} | "
                f"{float(item.get('reduction_percent') or 0):.2f}% | "
                f"{int(item.get('evidence_followup_group_count') or 0)} groups; "
                f"context retrieved: {int(item.get('evidence_followup_row_count') or 0)}/"
                f"{int(item.get('evidence_followup_matching_event_count') or 0)} | "
                f"{float(dict(item.get('timings') or {}).get('total_seconds') or 0):.2f}s |"
            )
    elif detectraptor_recovery:
        recovery_partitions = [
            dict(item)
            for item in detectraptor_recovery.get("partitions") or []
            if isinstance(item, Mapping)
        ]
        completed_partitions = sum(
            str(item.get("status") or "") == "completed"
            for item in recovery_partitions
        )
        lines.extend(
            [
                "",
                "## DetectRaptor recovered partition coverage",
                "",
                f"- Completed partitions: {completed_partitions}/{len(recovery_partitions)}",
                "- Source rows discovered: "
                f"{sum(int(item.get('discovered_row_count') or 0) for item in recovery_partitions)}",
                "- Model rows/groups reviewed: "
                f"{sum(int(item.get('model_row_count') or 0) for item in recovery_partitions)}",
                "- Reportable exact groups: "
                f"{sum(len(item.get('selected_source_refs') or []) for item in recovery_partitions)}",
                "- Runtime exclusions applied: 0",
                "- Publication status: cumulative synthesis failed; these are "
                "recovered partition-level counts, not a successful final checkpoint.",
            ]
        )
    lines.extend(
        [
            "",
            "## Preliminary hunt analysis" if result.get("review_status") == "not_requested" else "## Hunt synthesis",
            "",
            str(result.get("answer") or "No completed result rows were available for synthesis."),
            "",
            (
                "## AI-selected findings - analyst review required"
                if detectraptor_stack
                else "## Findings"
            ),
            "",
        ]
    )
    lines.extend(analysis_summary.render_compact_findings(result))
    if detectraptor_stack or detectraptor_recovery:
        context_file = str(
            detectraptor_stack.get("interesting_context_file") or ""
        ).strip()
        if not context_file and hunt_root is not None:
            context_file = str(
                hunt_root / "analysis" / DETECTRAPTOR_CONTEXT_FILENAME
            )
        context_path = Path(context_file) if context_file else None
        if context_path is not None and not context_path.is_absolute() and hunt_root:
            context_path = hunt_root / context_path
        context_payload = (
            _read_optional_mapping(context_path)
            if context_path is not None
            else {}
        )
        context_groups = (
            list(context_payload.get("groups") or [])
            if str(context_payload.get("analysis_id") or "")
            == str(state.get("analysis_id") or "")
            and str(context_payload.get("hunt_id") or "")
            == str(state.get("scope_id") or "")
            else []
        )
        report_groups = [
            *context_groups,
            *_detectraptor_direct_report_groups(
                detectraptor_recovery
            ),
        ]
        if report_groups:
            context_link = (
                _relative_report_link(context_path, hunt_root=hunt_root)
                if hunt_root is not None and context_path is not None
                else context_file
            )
            lines.extend(
                [
                    "",
                    "## DetectRaptor interesting event notes",
                    "",
                    "Equivalent exact-payload assessments are consolidated here. "
                    "The separate ledger retains every hydrated event.",
                    "",
                    *_render_detectraptor_report_notes(
                        report_groups,
                        context_ledger=context_link,
                    ),
                ]
            )
        whitelist_path = ""
        if detectraptor_stack:
            whitelist_candidates = dict(
                detectraptor_stack.get("whitelist_candidates") or {}
            )
            whitelist_path = str(whitelist_candidates.get("path") or "")
        elif hunt_root is not None:
            candidate_path = (
                hunt_root / "analysis" / DETECTRAPTOR_UPLIFT_FILENAME
            )
            whitelist_candidates = _summarize_detectraptor_uplift_csv(
                candidate_path
            )
            if candidate_path.is_file():
                whitelist_path = _relative_report_link(
                    candidate_path,
                    hunt_root=hunt_root,
                )
        else:
            whitelist_candidates = {}
        if whitelist_path or whitelist_candidates.get("candidate_count"):
            lines.extend(
                [
                    "",
                    "## Potential whitelist opportunities",
                    "",
                    "These are AI-selected review candidates, not applied exclusions.",
                    f"- Candidates: {int(whitelist_candidates.get('candidate_count') or 0)}",
                    f"- Global: {int(whitelist_candidates.get('global_count') or 0)}",
                    f"- Site-specific: {int(whitelist_candidates.get('site_count') or 0)}",
                    f"- Full-payload review file: `{whitelist_path}`",
                ]
            )
    if state.get("finding_evidence_file"):
        lines.extend(
            [
                "",
                "## Supplementary selected evidence",
                "",
                "Full manager-selected values are available in "
                "[finding-evidence.md](analysis/finding-evidence.md).",
            ]
        )
    lines.extend(["", "## Limitations", ""])
    limitations = list(result.get("limitations") or [])
    if str(active_analysis.get("failure_stage") or "") == "cumulative_synthesis":
        limitations.append(
            "Cumulative synthesis failed. DetectRaptor partition assessments and "
            "hydrated event notes are recovered, but no successful cumulative "
            "checkpoint or result-review coverage was published."
        )
    if inventory.get("completion_warning"):
        limitations.append(str(inventory["completion_warning"]))
    if coverage.get("target_execution") not in {"complete", "not_assessed"}:
        limitations.append(
            "This is provisional current-terminal-flow reporting; collection is still "
            "open, failed, or unknown for one or more targets. Rerun analysis to add "
            "newly completed flows."
        )
    lines.extend(f"- {value}" for value in dict.fromkeys(limitations))
    if not limitations:
        lines.append("- None identified.")
    lines.extend(["", "## Bounded follow-up", ""])
    follow_up = list(result.get("bounded_follow_up") or [])
    if str(active_analysis.get("failure_stage") or "") == "cumulative_synthesis":
        follow_up.insert(
            0,
            "Rerun the same full analysis command to reuse compatible completed "
            "DetectRaptor partitions and retry cumulative synthesis.",
        )
    lines.extend(f"- {value}" for value in dict.fromkeys(follow_up))
    if not follow_up:
        lines.append("- Rerun the same command when additional flows complete.")
    return "\n".join(lines).rstrip() + "\n"


def _chat_summary_with_detectraptor_stack(
    summary: str,
    *,
    detectraptor_stack: Mapping[str, Any] | None = None,
    source_rows: int = 0,
    model_rows: int = 0,
) -> str:
    if not detectraptor_stack:
        return summary
    section: list[str] = []
    if detectraptor_stack:
        followup = dict(detectraptor_stack.get("evidence_followup") or {})
        whitelist = dict(detectraptor_stack.get("whitelist_candidates") or {})
        section.extend(
            [
                "### DetectRaptor EVTX automatic review",
                "",
                f"- Detection regex: `{detectraptor_stack.get('detection_regex') or ''}`",
                f"- Source rows accounted: {source_rows}",
                f"- Model rows/groups analyzed: {model_rows}",
                f"- Full-payload groups reviewed: {int(followup.get('reviewed_group_count') or 0)}",
                f"- AI-selected malicious/potentially malicious groups: {int(followup.get('reportable_group_count') or 0)}",
                f"- Potential whitelist candidates: {int(whitelist.get('candidate_count') or 0)} "
                f"({int(whitelist.get('global_count') or 0)} global; "
                f"{int(whitelist.get('site_count') or 0)} site-specific)",
                f"- Candidate review file: `{whitelist.get('path') or ''}`",
                "- Runtime exclusions: 0",
                "",
            ]
        )
    lines = summary.rstrip().splitlines()
    try:
        insertion = lines.index("### Assessment")
    except ValueError:
        insertion = min(len(lines), 1)
    rendered = "\n".join([*lines[:insertion], *section, *lines[insertion:]]).rstrip() + "\n"
    if len(rendered) <= analysis_summary.MAX_CHAT_SUMMARY_CHARS:
        return rendered
    suffix = (
        "\n\nChat summary reached its 32,000-character guard; consult the "
        "linked analysis report for remaining detail.\n"
    )
    return (
        rendered[: analysis_summary.MAX_CHAT_SUMMARY_CHARS - len(suffix)]
        .rsplit("\n", 1)[0]
        .rstrip()
        + suffix
    )


def render_specialized_hunt_section(
    state: Mapping[str, Any],
    *,
    hunt_root: Path,
) -> str:
    """Render compact specialized state without loading exact context rows."""
    artifacts = [
        (str(artifact), dict(item))
        for artifact, item in sorted(dict(state.get("artifacts") or {}).items())
        if isinstance(item, Mapping)
    ]
    hide_target_execution = autoruns_reporting.hide_unassessed_target_execution(state)
    lines = [
        "## Specialized analysis",
        "",
        f"- Status: `{state.get('status') or 'unknown'}`",
        f"- Result review: `{state.get('result_review_coverage') or 'unknown'}`",
    ]
    if not hide_target_execution:
        lines.append(
            f"- Target execution: `{state.get('target_execution_coverage') or 'unknown'}`"
        )
    lines.append(f"- Overall coverage: `{state.get('coverage') or 'unknown'}`")

    host_execution = dict(state.get("host_execution") or {})
    if host_execution:
        target_count = host_execution.get("target_count")
        denominator = (
            int(target_count or 0)
            if host_execution.get("denominator_basis") == "baseline_targets"
            else int(host_execution.get("responded_count") or 0)
        )
        denominator_label = (
            "baseline targets"
            if host_execution.get("denominator_basis") == "baseline_targets"
            else "responding hosts"
        )
        completed = int(host_execution.get("completed_count") or 0)
        terminal = int(host_execution.get("terminal_count") or 0)
        completed_percent = (
            (completed / denominator) * 100 if denominator else 0.0
        )
        terminal_percent = (
            (terminal / denominator) * 100 if denominator else 0.0
        )
        lines.extend(
            [
                "",
                "### Host execution",
                "",
                f"- Successfully completed: {completed}/{denominator} {denominator_label} ({completed_percent:.1f}%)",
                f"- Terminal execution: {terminal}/{denominator} {denominator_label} ({terminal_percent:.1f}%)",
                f"- Failed: {int(host_execution.get('failed_count') or 0)}; open: {int(host_execution.get('open_count') or 0)}; pending: {int(host_execution.get('pending_count') or 0)}",
            ]
        )
        if state.get("target_execution_coverage") == "not_assessed":
            if not hide_target_execution:
                lines.append(
                    "- Target execution was not assessed; completion applies only "
                    "to the server-reported result set."
                )
        elif host_execution.get("denominator_basis") != "baseline_targets":
            lines.append(
                "- Total targeted hosts: unknown because no saved baseline "
                "target scope is available."
            )

    lines.extend(
        [
            "",
            "### Artifact accounting",
            "",
            "| Artifact | Status | Source | Golden | Residual | Stack groups | Stack rows | Suspicious | Potential Golden | Context rows | Hosts |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for artifact, item in artifacts[:MAX_SPECIALIZED_ARTIFACTS]:
        workflow = dict(item.get("autoruns_residual_workflow") or {})
        golden = dict(item.get("autoruns_golden") or {})
        stack = dict(workflow.get("stack") or {})
        classification = dict(workflow.get("classification") or {})
        context = dict(workflow.get("suspicious_context") or {})
        generic_stack = dict(item.get("streaming_stack") or {})
        lines.append(
            f"| {_compact_specialized_text(artifact)} | "
            f"{_compact_specialized_text(item.get('status'))} | "
            f"{int(item.get('current_total') or 0)} | "
            f"{int(golden.get('matched_rows') or 0)} | "
            f"{int(golden.get('residual_rows') or item.get('analysis_scope_total') or 0)} | "
            f"{int(stack.get('group_count') or generic_stack.get('reviewed_group_count') or 0) + int(generic_stack.get('excluded_group_count') or 0)} | "
            f"{int(stack.get('represented_rows') or generic_stack.get('represented_row_count') or 0)} | "
            f"{int(classification.get('suspicious_count') or generic_stack.get('suspicious_group_count') or 0)} | "
            f"{int(classification.get('potential_golden_count') or 0)} | "
            f"{int(context.get('row_count') or 0)} | "
            f"{int(context.get('host_count') or 0)} |"
        )
    if not artifacts:
        lines.append("| None | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")
    if len(artifacts) > MAX_SPECIALIZED_ARTIFACTS:
        lines.append(
            f"\n{len(artifacts) - MAX_SPECIALIZED_ARTIFACTS} additional artifact(s) "
            "remain in specialized state."
        )

    golden_reductions = [
        (artifact, dict(item.get("autoruns_golden") or {}))
        for artifact, item in artifacts
        if isinstance(item.get("autoruns_golden"), Mapping)
        and item.get("autoruns_golden")
    ]
    if golden_reductions:
        lines.extend(["", "### Autoruns GoldenDB reduction", ""])
        for artifact, golden in golden_reductions[:MAX_SPECIALIZED_ARTIFACTS]:
            lines.append(
                f"- `{_compact_specialized_text(artifact)}`: "
                f"{int(golden.get('source_rows') or 0)} source; "
                f"{int(golden.get('matched_rows') or 0)} matched; "
                f"{int(golden.get('residual_rows') or 0)} residual; "
                f"database SHA-256 `{_compact_specialized_text(golden.get('database_sha256'))}`"
            )

    workflow_details: list[tuple[str, dict[str, Any]]] = []
    for artifact, item in artifacts:
        residual = item.get("autoruns_residual_workflow")
        if isinstance(residual, Mapping):
            workflow_details.append((artifact, dict(residual)))
        for mode, workflow in sorted(
            dict(item.get("autoruns_focused_workflows") or {}).items()
        ):
            if isinstance(workflow, Mapping):
                workflow_details.append(
                    (f"{artifact}: {mode}", dict(workflow))
                )
    generic_stack_details = [
        (artifact, dict(item.get("streaming_stack") or {}))
        for artifact, item in artifacts
        if isinstance(item.get("streaming_stack"), Mapping)
        and item.get("streaming_stack")
    ]
    if workflow_details or generic_stack_details:
        lines.extend(["", "### Streaming review", ""])
        for label, workflow in workflow_details[:MAX_SPECIALIZED_ARTIFACTS]:
            stack = dict(workflow.get("stack") or {})
            classification = dict(workflow.get("classification") or {})
            context = dict(workflow.get("suspicious_context") or {})
            ai_review = dict(workflow.get("ai_review") or {})
            potential = dict(classification.get("potential_golden") or {})
            candidate_output = dict(workflow.get("candidate_output") or {})
            lines.extend(
                [
                    f"#### {_compact_specialized_text(label)}",
                    "",
                    f"- Mode: `{_compact_specialized_text(workflow.get('mode') or 'unknown')}`; stage: `{_compact_specialized_text(workflow.get('stage') or 'unknown')}`",
                    f"- Residual stack: {int(stack.get('group_count') or 0)} groups representing {int(stack.get('represented_rows') or 0)} rows; persisted: `{bool(stack.get('persisted'))}`",
                    f"- Classification: {int(classification.get('suspicious_count') or 0)} suspicious; {int(classification.get('potential_golden_count') or 0)} potential GoldenDB",
                    f"- Exact context: {int(context.get('row_count') or 0)} rows across {int(context.get('host_count') or 0)} hosts; persisted: `{bool(context.get('persisted'))}`",
                ]
            )
            if candidate_output:
                lines.append(
                    "- Potential GoldenDB output: "
                    f"status `{_compact_specialized_text(candidate_output.get('status') or 'unknown')}`; "
                    f"action `{_compact_specialized_text(candidate_output.get('action') or 'unknown')}`; "
                    f"current run `{bool(candidate_output.get('current_run'))}`"
                )
            if ai_review:
                lines.append(
                    f"- AI review: model `{_compact_specialized_text(ai_review.get('model') or 'unknown')}`; "
                    f"{int(ai_review.get('reviewed_group_count') or 0)} groups; "
                    f"{int(ai_review.get('part_count') or 0)} transient part(s)"
                )
            potential_link = _relative_report_link(
                potential.get("path"), hunt_root=hunt_root
            )
            if potential_link:
                lines.append(
                    f"- Potential GoldenDB candidates: [{potential_link}]({potential_link}); "
                    f"SHA-256 `{_compact_specialized_text(potential.get('sha256'))}`"
                )
        for artifact, stack_review in generic_stack_details[
            :MAX_SPECIALIZED_ARTIFACTS
        ]:
            lines.extend(
                [
                    f"#### {_compact_specialized_text(artifact)}: generic stack",
                    "",
                    f"- Stack: `{_compact_specialized_text(stack_review.get('signature_stack_id') or 'unknown')}` within `{_compact_specialized_text(stack_review.get('scope_stack_id') or 'unknown')}`",
                    f"- AI coverage: {int(stack_review.get('reviewed_group_count') or 0)} groups representing {int(stack_review.get('represented_row_count') or 0) - int(stack_review.get('excluded_row_count') or 0)} rows",
                    f"- Classification: {int(stack_review.get('suspicious_group_count') or 0)} suspicious; {int(stack_review.get('notable_group_count') or 0)} notable; {int(stack_review.get('omitted_flagged_group_count') or 0)} flagged groups omitted by the compact-output guard",
                    f"- Analyst pool: model `{_compact_specialized_text(stack_review.get('model') or 'unknown')}`; {int(stack_review.get('part_count') or 0)} transient part(s); concurrency {int(stack_review.get('max_concurrency') or 0)}",
                ]
            )
            if stack_review.get("max_total_rows") is not None:
                lines.append(
                    f"- Stack threshold > {stack_review['max_total_rows']}: "
                    f"{int(stack_review.get('excluded_group_count') or 0)} groups / "
                    f"{int(stack_review.get('excluded_row_count') or 0)} records excluded "
                    "from AI; these entries remain unreviewed."
                )

    generic_leads: list[tuple[str, dict[str, Any]]] = []
    for artifact, item in artifacts:
        for pending in item.get("pending_reviews") or []:
            if (
                isinstance(pending, Mapping)
                and str(pending.get("kind") or "") == "normalized_stack"
                and isinstance(pending.get("streaming_ai_review"), Mapping)
            ):
                generic_leads.append((artifact, dict(pending)))
    if generic_leads:
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        generic_leads.sort(
            key=lambda pair: (
                severity_order.get(
                    str(
                        dict(pair[1].get("streaming_ai_review") or {}).get(
                            "severity"
                        )
                        or ""
                    ).casefold(),
                    5,
                ),
                int(pair[1].get("scope_row_count") or 0),
            )
        )
        lines.extend(["", "### Generic stack follow-up findings", ""])
        lines.append(
            "AI-selected aggregate groups were requeried for impacted endpoints "
            "and original source rows. Findings remain provisional pending "
            "operator disposition."
        )
        for artifact, pending in generic_leads[:MAX_SPECIALIZED_FINDINGS]:
            ai_review = dict(pending.get("streaming_ai_review") or {})
            impact = dict(pending.get("impact") or {})
            review_match = dict(pending.get("review_match") or {})
            dimensions = [
                str(value)
                for value in review_match.get("logical_dimensions") or []
            ]
            values = [
                str(value)
                for value in review_match.get("values") or []
            ]
            identity = "; ".join(
                f"{name}={value}"
                for name, value in zip(dimensions, values, strict=False)
            )
            lines.append(
                f"- **{_compact_specialized_text(artifact)} "
                f"{_compact_specialized_text(ai_review.get('severity') or 'info').upper()} "
                f"{_compact_specialized_text(ai_review.get('disposition') or 'notable')}:** "
                f"{_compact_specialized_text(ai_review.get('summary') or identity or 'Stack group')} — "
                f"{int(review_match.get('row_count') or pending.get('scope_row_count') or 0)} occurrence(s), "
                f"{int(impact.get('host_count') or 0)}/"
                f"{int(impact.get('host_denominator') or 0)} hosts "
                f"({float(impact.get('host_prevalence_percent') or 0):.1f}%), "
                f"{int(impact.get('rows_reviewed') or 0)} source row(s) reviewed; "
                f"exhaustive `{bool(impact.get('rows_exhaustive'))}`."
            )
            machines = [
                str(machine.get("fqdn") or machine.get("client_id") or "")
                for machine in impact.get("impacted_machines") or []
                if isinstance(machine, Mapping)
                and (machine.get("fqdn") or machine.get("client_id"))
            ]
            if machines:
                lines.append(
                    "  - Impacted machines: "
                    + ", ".join(
                        _compact_specialized_text(value)
                        for value in machines[:20]
                    )
                )
        if len(generic_leads) > MAX_SPECIALIZED_FINDINGS:
            lines.append(
                f"- {len(generic_leads) - MAX_SPECIALIZED_FINDINGS} additional "
                "follow-up finding(s) remain in specialized state."
            )

    reductions = [
        (artifact, reduction)
        for artifact, item in artifacts
        for reduction in item.get("scope_reductions") or []
        if isinstance(reduction, Mapping)
    ]
    if reductions:
        lines.extend(["", "### Data reduction", ""])
        for artifact, reduction in reductions[:MAX_SPECIALIZED_FINDINGS]:
            lines.append(
                f"- `{_compact_specialized_text(artifact)}` "
                f"{_compact_specialized_text(reduction.get('classification') or 'reduction')}: "
                f"{int(reduction.get('leading_rows') or 0)} leading rows; "
                f"{int(reduction.get('tail_rows') or 0)} tail rows; "
                f"accounting `{_compact_specialized_text(reduction.get('accounting_basis') or 'unknown')}`"
            )

    case_filters = [
        item
        for item in state.get("case_filters") or []
        if isinstance(item, Mapping)
    ]
    if case_filters:
        lines.extend(["", "### Filter decisions", ""])
        for item in case_filters[:MAX_SPECIALIZED_FINDINGS]:
            lines.append(
                f"- `{_compact_specialized_text(item.get('status') or 'unknown')}` "
                f"{_compact_specialized_text(item.get('reason') or 'No reason recorded.')} "
                f"({int(item.get('matched_rows') or 0)} matched rows)"
            )
    finding_summary = dict(state.get("specialized_finding_summary") or {})
    consolidated_findings = [
        item
        for item in list(finding_summary.get("groups") or [])
        if isinstance(item, Mapping)
    ]
    findings = [
        item
        for item in list(state.get("findings") or [])
        if isinstance(item, Mapping)
    ]
    lines.extend(["", "### Specialized findings", ""])
    if consolidated_findings:
        manager = dict(finding_summary.get("manager") or {})
        lines.append(
            f"- Consolidation: `{finding_summary.get('mode') or 'unknown'}`; "
            f"{int(finding_summary.get('covered_source_group_count') or 0)}/"
            f"{int(finding_summary.get('source_group_count') or 0)} exact "
            "group(s) covered."
        )
        if manager:
            lines.append(
                "- Manager telemetry: "
                f"model `{_compact_specialized_text(manager.get('model') or 'none')}`; "
                f"elapsed {float(manager.get('elapsed_seconds') or 0):.3f}s; "
                f"cache hit `{bool(manager.get('cache_hit'))}`; "
                f"fallback `{_compact_specialized_text(manager.get('fallback_reason') or 'none')}`."
            )
        for finding in consolidated_findings[:MAX_SPECIALIZED_FINDINGS]:
            summary = _compact_specialized_text(
                finding.get("summary") or "Finding recorded"
            )
            artifact_names = ", ".join(
                _compact_specialized_text(value)
                for value in finding.get("artifacts") or ["unknown"]
            )
            count = int(finding.get("record_count") or 0)
            repeated = f" ({count} records)" if count > 1 else ""
            lines.append(f"- **{artifact_names}:** {summary}{repeated}")
        if len(consolidated_findings) > MAX_SPECIALIZED_FINDINGS:
            lines.append(
                f"- {len(consolidated_findings) - MAX_SPECIALIZED_FINDINGS} "
                "additional consolidated finding group(s) remain in specialized state."
            )
        for limitation in finding_summary.get("limitations") or []:
            lines.append(f"- Limitation: {_compact_specialized_text(limitation)}")
    elif findings:
        for finding in findings[:MAX_SPECIALIZED_FINDINGS]:
            summary = _compact_specialized_text(
                finding.get("summary") or finding.get("title") or "Finding recorded"
            )
            artifact = _compact_specialized_text(
                finding.get("artifact") or "unknown"
            )
            lines.append(f"- **{artifact}:** {summary}")
        if len(findings) > MAX_SPECIALIZED_FINDINGS:
            lines.append(
                f"- {len(findings) - MAX_SPECIALIZED_FINDINGS} additional finding(s) "
                "remain in specialized state."
            )
    else:
        lines.append("- No specialized finding summaries have been recorded.")

    autoruns_contexts: list[
        tuple[str, Mapping[str, Any], list[Mapping[str, Any]]]
    ] = []
    for artifact, item in artifacts:
        workflow = dict(item.get("autoruns_residual_workflow") or {})
        context = dict(workflow.get("suspicious_context") or {})
        examples = [
            example
            for example in (
                context.get("representative_items")
                or context.get("items")
                or []
            )
            if isinstance(example, Mapping)
        ]
        if examples:
            autoruns_contexts.append((artifact, context, examples))
        for mode, focused_workflow in sorted(
            dict(item.get("autoruns_focused_workflows") or {}).items()
        ):
            if not isinstance(focused_workflow, Mapping):
                continue
            focused_context = dict(
                focused_workflow.get("suspicious_context") or {}
            )
            focused_examples = [
                example
                for example in (
                    focused_context.get("representative_items")
                    or focused_context.get("items")
                    or []
                )
                if isinstance(example, Mapping)
            ]
            if focused_examples:
                autoruns_contexts.append(
                    (f"{artifact}: {mode}", focused_context, focused_examples)
                )
    if autoruns_contexts:
        lines.extend(["", "### Representative specialized context", ""])
        for artifact, context, examples in autoruns_contexts[
            :MAX_SPECIALIZED_ARTIFACTS
        ]:
            lines.extend(
                [
                    f"#### {_compact_specialized_text(artifact)}",
                    "",
                    *autoruns_reporting.render_context(
                        examples,
                        heading_level=5,
                        context_group_count=int(
                            context.get("context_group_count")
                            or context.get("identity_count")
                            or len(examples)
                        ),
                        max_groups=MAX_SPECIALIZED_EXAMPLES,
                        max_endpoints_per_group=10,
                    ),
                ]
            )
        if len(autoruns_contexts) > MAX_SPECIALIZED_ARTIFACTS:
            lines.append(
                f"- {len(autoruns_contexts) - MAX_SPECIALIZED_ARTIFACTS} "
                "additional Autoruns workflow context set(s) remain in "
                "specialized state."
            )
    pending_count = sum(
        len(item.get("pending_reviews") or [])
        for _, item in artifacts
    )
    lines.extend(["", "### Next action", ""])
    if str(state.get("result_review_coverage") or "") == "complete":
        lines.append("- No unreviewed result rows remain at the recorded watermark.")
    elif pending_count:
        lines.append(
            f"- Resolve {pending_count} pending structured review item(s), then rerun analysis."
        )
    else:
        lines.append("- Complete the remaining bounded review and rerun analysis.")
    if str(state.get("target_execution_coverage") or "") == "not_assessed":
        lines.append(
            "- Do not translate result-set completion into fleet-wide execution coverage."
        )
    return "\n".join(lines).rstrip() + "\n"


def render_canonical_hunt_report(
    *,
    hunt_root: Path,
    question: str,
    flow_state: Mapping[str, Any] | None = None,
    specialized_state: Mapping[str, Any] | None = None,
    autoruns_csv: Path | None = None,
) -> str:
    flow = dict(flow_state or {})
    specialized = dict(specialized_state or {})
    sections: list[str] = []
    has_flow_analysis = bool(
        flow.get("checkpoint") or flow.get("runs") or flow.get("synthesis")
    )
    if flow.get("scope_id") and has_flow_analysis:
        sections.append(
            render_hunt_report(
                flow,
                question=question,
                hunt_root=hunt_root,
            ).rstrip()
        )
    else:
        sections.append(
            "\n".join(
                [
                    "# Velociraptor hunt analysis",
                    "",
                    "## Analysis metadata",
                    "",
                    f"- Hunt: `{specialized.get('hunt_id') or hunt_root.name}`",
                    f"- Question: {question}",
                    f"- Task mode: `{specialized.get('task_mode', 'targeted_hunt')}`",
                    f"- Response depth: `{specialized.get('response_depth', 'standard')}`",
                    "- Velociraptor source of truth: yes",
                    "- Bulk raw result export: no",
                    "",
                    "## Hunt synthesis",
                    "",
                    "The specialized analyzer has refreshed the compact hunt state. "
                    "Bounded reduction and review detail is included below.",
                ]
            )
        )
    if specialized and (specialized.get("artifacts") or not specialized.get("autoruns_review")):
        sections.append(
            render_specialized_hunt_section(
                specialized,
                hunt_root=hunt_root,
            ).rstrip()
        )
    if specialized.get("autoruns_review"):
        from vraptor.autoruns import publication as autoruns_publication
        sections.append(autoruns_publication.render_section(
            specialized["autoruns_review"],
            autoruns_csv or hunt_root / "analysis" / "autoruns_review.csv"))
    return "\n\n".join(sections).rstrip() + "\n"


def _write_canonical_hunt_report(
    hunt_root: Path,
    *,
    question: str,
    flow_state: Mapping[str, Any] | None = None,
    specialized_state: Mapping[str, Any] | None = None,
) -> Path:
    report_path = hunt_root / REPORT_FILENAME
    atomic_io.write_text_atomic(
        report_path,
        render_canonical_hunt_report(
            hunt_root=hunt_root,
            question=question,
            flow_state=flow_state,
            specialized_state=specialized_state,
        ),
    )
    return report_path


def refresh_canonical_hunt_report(
    hunt_root: Path,
    *,
    question: str,
    specialized_state: Mapping[str, Any] | None = None,
) -> Path:
    """Atomically refresh the sole coordinator-owned root hunt report."""
    analysis_root = hunt_root / "analysis"
    canonical = _read_optional_mapping(analysis_root / STATE_FILENAME)
    return _write_canonical_hunt_report(
        hunt_root,
        question=question,
        flow_state=canonical,
        specialized_state=(
            dict(specialized_state)
            if specialized_state is not None
            else dict(canonical.get("specialized_analysis") or {})
        ),
    )
