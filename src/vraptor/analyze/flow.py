"""Shared deterministic planning for server-resident Velociraptor flow analysis.

This module deliberately contains no Velociraptor client or analyst-agent calls.
Host and hunt coordinators own acquisition and execution; this module owns the
stable identities, terminal-flow classification, logical segmentation and frozen
best-fit packing shared by both workflows.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 7
SEGMENT_SCHEMA_VERSION = 1
DEFAULT_SEGMENT_ROWS = 5_000
DEFAULT_SEGMENT_BYTES = 32 * 1024 * 1024
DEFAULT_ACQUISITION_WINDOW_ROWS = 100_000
DEFAULT_TRANSPORT_ROWS = 5_000
MAX_ADAPTIVE_TRANSPORT_ROWS = 20_000
SMALL_TRANSPORT_RESPONSE_BYTES = 2 * 1024 * 1024
SMALL_TRANSPORT_REQUIRED_RESPONSES = 2
MAX_SMALL_RESPONSE_ROW_BYTES = 64 * 1024

FLOW_OPEN = "open"
FLOW_SUCCESSFUL_TERMINAL = "successful_terminal"
FLOW_FAILED_TERMINAL = "failed_terminal"
FLOW_UNKNOWN = "unknown"

OPEN_STATE_TOKENS = {
    "RUNNING",
    "IN_PROGRESS",
    "WAITING",
    "QUEUED",
    "PENDING",
}
SUCCESS_STATE_TOKENS = {"FINISHED", "COMPLETED", "COMPLETE", "SUCCESS"}
FAILURE_STATE_FRAGMENTS = (
    "FAIL",
    "ERROR",
    "CANCEL",
    "TIMEOUT",
    "TIMED_OUT",
    "UNRESPONSIVE",
    "ABORT",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def sha256_identity(prefix: str, value: Any, *, length: int = 32) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}-v1-{digest[:length]}"


def nested_flow(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("Flow")
    return value if isinstance(value, Mapping) else row


def flow_state(row: Mapping[str, Any]) -> str:
    flow = nested_flow(row)
    return str(
        row.get("State")
        or row.get("state")
        or flow.get("State")
        or flow.get("state")
        or ""
    ).strip().upper()


def classify_flow(row_or_state: Mapping[str, Any] | str) -> str:
    state = (
        flow_state(row_or_state)
        if isinstance(row_or_state, Mapping)
        else str(row_or_state or "").strip().upper()
    )
    if state in OPEN_STATE_TOKENS:
        return FLOW_OPEN
    if state in SUCCESS_STATE_TOKENS:
        return FLOW_SUCCESSFUL_TERMINAL
    if any(fragment in state for fragment in FAILURE_STATE_FRAGMENTS):
        return FLOW_FAILED_TERMINAL
    return FLOW_UNKNOWN


def flow_identifiers(row: Mapping[str, Any]) -> tuple[str, str]:
    flow = nested_flow(row)
    client_id = str(
        row.get("ClientId")
        or row.get("client_id")
        or flow.get("ClientId")
        or flow.get("client_id")
        or ""
    ).strip()
    flow_id = str(
        row.get("FlowId")
        or row.get("flow_id")
        or flow.get("FlowId")
        or flow.get("flow_id")
        or flow.get("session_id")
        or ""
    ).strip()
    return client_id, flow_id


def flow_result_sources(row: Mapping[str, Any]) -> tuple[str, ...]:
    flow = nested_flow(row)
    values = (
        flow.get("artifacts_with_results")
        or flow.get("ArtifactsWithResults")
        or row.get("artifacts_with_results")
        or row.get("ArtifactsWithResults")
        or []
    )
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return ()
    return tuple(sorted({str(value).strip() for value in values if str(value).strip()}))


def flow_reported_rows(row: Mapping[str, Any]) -> int:
    flow = nested_flow(row)
    for key in (
        "total_collected_rows",
        "total_rows",
        "TotalCollectedRows",
        "TotalRows",
    ):
        value = flow.get(key)
        if value is None:
            value = row.get(key)
        try:
            if value is not None:
                return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return 0


def flow_watermark(row: Mapping[str, Any]) -> str:
    client_id, flow_id = flow_identifiers(row)
    return sha256_identity(
        "flowmark",
        {
            "client_id": client_id,
            "flow_id": flow_id,
            "state": flow_state(row),
            "reported_rows": flow_reported_rows(row),
            "result_sources": flow_result_sources(row),
        },
    )


@dataclass(frozen=True)
class FlowSource:
    org_id: str
    client_id: str
    flow_id: str
    artifact: str
    source: str = ""
    hunt_id: str = ""
    state: str = ""
    watermark: str = ""

    @property
    def source_id(self) -> str:
        return source_identifier(
            org_id=self.org_id,
            client_id=self.client_id,
            flow_id=self.flow_id,
            artifact=self.artifact,
            source=self.source,
        )

    @property
    def compatibility_key(self) -> str:
        return canonical_json(
            {
                "artifact": self.artifact,
                "source": self.source,
            }
        )


def source_identifier(
    *,
    org_id: str,
    client_id: str,
    flow_id: str,
    artifact: str,
    source: str = "",
) -> str:
    return sha256_identity(
        "source",
        {
            "org_id": org_id,
            "client_id": client_id,
            "flow_id": flow_id,
            "artifact": artifact,
            "source": source,
        },
    )


def segment_identifier(source_id: str, row_start: int, row_end: int) -> str:
    if row_start < 0 or row_end <= row_start:
        raise ValueError("segment row range must be non-empty and increasing")
    return sha256_identity(
        "segment",
        {
            "schema": SEGMENT_SCHEMA_VERSION,
            "source_id": source_id,
            "row_start": row_start,
            "row_end": row_end,
        },
    )


def segment_revision(
    *,
    segment_id: str,
    row_count: int,
    content_sha256: str,
    flow_state_value: str,
    projection_hash: str,
) -> str:
    return sha256_identity(
        "segment-revision",
        {
            "segment_id": segment_id,
            "row_count": row_count,
            "content_sha256": content_sha256,
            "flow_state": flow_state_value,
            "projection_hash": projection_hash,
        },
    )


def analysis_identity(
    *,
    scope_type: str,
    question: str,
    profile_hash: str,
    runtime_policy: Mapping[str, Any],
    output_contract: str,
) -> str:
    return sha256_identity(
        "analysis",
        {
            "scope_type": scope_type,
            "question": question.strip(),
            "profile_hash": profile_hash,
            "runtime_policy": dict(runtime_policy),
            "output_contract": output_contract,
        },
    )


def run_identifier(
    *,
    scope_id: str,
    analysis_id: str,
    inventory_identity: Iterable[str],
) -> str:
    return sha256_identity(
        "run",
        {
            "scope_id": scope_id,
            "analysis_id": analysis_id,
            "inventory": sorted(set(inventory_identity)),
        },
    )


def transport_rows_after_observations(
    observations: Iterable[Mapping[str, Any]],
    *,
    current_rows: int = DEFAULT_TRANSPORT_ROWS,
    variable_large_rows: bool = False,
) -> int:
    """Promote only consistently tiny response packets to 20,000 rows."""
    current = max(1, int(current_rows))
    if variable_large_rows or current != DEFAULT_TRANSPORT_ROWS:
        return current
    recent = list(observations)[-SMALL_TRANSPORT_REQUIRED_RESPONSES:]
    if len(recent) < SMALL_TRANSPORT_REQUIRED_RESPONSES:
        return current
    if all(
        int(item.get("row_count") or 0) >= DEFAULT_TRANSPORT_ROWS
        and int(item.get("payload_bytes") or 0) <= SMALL_TRANSPORT_RESPONSE_BYTES
        and int(item.get("max_row_bytes") or 0) <= MAX_SMALL_RESPONSE_ROW_BYTES
        for item in recent
    ):
        return MAX_ADAPTIVE_TRANSPORT_ROWS
    return current


def initial_state(*, scope_type: str, scope_id: str, analysis_id: str) -> dict[str, Any]:
    timestamp = now_utc()
    return {
        "schema_version": SCHEMA_VERSION,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "analysis_id": analysis_id,
        "created_at": timestamp,
        "updated_at": timestamp,
        "inventory": {
            "scan_started_at": "",
            "scan_completed_at": "",
            "terminal_observed_through": "",
            "last_successful_check_at": "",
            "last_full_analysis_at": "",
            "flow_counts": {},
        },
        "source_aliases": {},
        "checkpoint": {},
        "runs": [],
        "coverage": {
            "result_review": "incomplete",
            "target_execution": "unknown",
            "overall": "incomplete",
        },
        "evidence_persisted": False,
    }
