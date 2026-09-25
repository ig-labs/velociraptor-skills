"""Shared final-output and progress contracts for Velociraptor analysis CLIs."""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from collections.abc import Mapping
from typing import Any, TextIO

from vraptor.autoruns import reporting as autoruns_reporting
from vraptor.logging import operations as operation_log


OUTPUT_FORMATS = ("text", "json")
DEFAULT_OUTPUT_FORMAT = "text"
DEFAULT_HEARTBEAT_SECONDS = 20.0
DEFAULT_PROGRESS_THROTTLE_SECONDS = 1.0
MAX_PROGRESS_VALUE_CHARS = 160
MAX_PROGRESS_TASK_STATES = 1024

_PROGRESS_KEYS = (
    "command",
    "operation_id",
    "provider",
    "model",
    "reasoning_effort",
    "protocol",
    "hunt_id",
    "hostname",
    "client_id",
    "request_id",
    "artifact",
    "flow_id",
    "task_id",
    "mode",
    "acquired",
    "emitted",
    "accepted",
    "failed",
    "active",
    "submitted",
    "completed",
    "total",
    "rows",
    "groups",
    "chunks",
    "retries",
    "attempt",
    "characters",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "local_output_tokens",
    "finish_reason",
    "error_classification",
    "provider_status",
    "provider_error_code",
    "provider_error_param",
    "retryable",
    "retry_after_seconds",
    "retry_delay_seconds",
    "elapsed_seconds",
    "heartbeat",
)
_AGENT_METADATA_KEYS = {
    "characters",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "local_output_tokens",
    "finish_reason",
    "error_classification",
    "provider_status",
    "provider_error_code",
    "provider_error_param",
    "retryable",
    "retry_after_seconds",
}
_IMMEDIATE_STATUSES = {
    "complete",
    "complete_with_failures",
    "failed",
    "retrying",
    "interrupted",
    "planned",
}
_UNTHROTTLED_PROVIDER_EVENTS = {
    "request_started",
    "request_completed",
    "retry_scheduled",
    "request_failed",
    "request_timed_out",
    "request_cancelled",
}
_TERMINAL_PROVIDER_EVENTS = {
    "request_completed",
    "request_failed",
    "request_timed_out",
    "request_cancelled",
}


def _positive_progress_interval(value: str) -> float:
    interval = float(value)
    if interval <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return interval


def add_progress_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared live-progress options without changing stdout."""
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Suppress live DFIR-STATUS markers on stderr.",
    )
    parser.add_argument(
        "--progress-interval-seconds",
        type=_positive_progress_interval,
        default=DEFAULT_HEARTBEAT_SECONDS,
        help="Seconds between DFIR-STATUS heartbeats while an operation is waiting.",
    )


def add_analysis_output_args(parser: argparse.ArgumentParser) -> None:
    """Add deterministic final-output and live-progress options."""
    parser.add_argument(
        "--format",
        choices=OUTPUT_FORMATS,
        default=DEFAULT_OUTPUT_FORMAT,
        dest="output_format",
        help=(
            "Final stdout format. Text is the default for operator runs; use "
            "JSON only when an explicit downstream integration parses the "
            "structured response."
        ),
    )
    add_progress_args(parser)


def emit_final_result(
    payload: Mapping[str, Any],
    *,
    output_format: str = DEFAULT_OUTPUT_FORMAT,
    stream: TextIO | None = None,
) -> None:
    """Write exactly one final result to stdout or an injected stream."""
    target = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(dict(payload), indent=2, sort_keys=False), file=target)
        return
    if output_format != "text":
        raise ValueError(f"unsupported analysis output format {output_format!r}")
    print(render_final_text(payload), file=target)


def _first_value(payload: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return ""


def _coverage_lines(coverage: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for label, keys in (
        ("Result review", ("result_review", "result_review_status")),
        ("Target execution", ("target_execution", "target_execution_status")),
        ("Overall coverage", ("overall", "coverage_state")),
    ):
        value = _first_value(coverage, *keys)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def _count_lines(payload: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for label, keys in (
        ("Hunts", ("hunt_count",)),
        ("Artifact tasks", ("artifact_task_count",)),
        ("Chunks", ("chunk_count", "emitted_chunk_count")),
        ("Chunks accepted", ("accepted_chunk_count",)),
        ("Chunks failed", ("failed_chunk_count",)),
        ("Rows reviewed", ("reviewed_rows", "reviewed_row_count")),
        ("Groups reviewed", ("reviewed_groups", "review_item_count")),
        ("Findings", ("finding_count",)),
        ("Retries", ("retry_count",)),
    ):
        value = _first_value(payload, *keys)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def _path_lines(payload: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for label, keys in (
        (
            "Report",
            ("host_report_file", "report_file", "analysis_memory_file", "analysis_file"),
        ),
        ("State", ("host_state_file", "state_file", "analysis_state_file")),
        ("Checkpoint", ("request_checkpoint_file",)),
        ("Plan", ("analysis_plan_file",)),
        ("Output", ("output",)),
        ("Debug", ("validation_debug_file",)),
        ("Progress log", ("progress_log_file", "operation_log_file")),
    ):
        value = _first_value(payload, *keys)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def _representative_analysis(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    analyses = payload.get("analyses")
    if isinstance(analyses, list) and len(analyses) == 1:
        item = analyses[0]
        if isinstance(item, Mapping):
            return item
    return payload


def render_final_text(payload: Mapping[str, Any]) -> str:
    """Render a bounded, non-evidentiary final CLI result."""
    root = dict(payload)
    representative = dict(_representative_analysis(root))
    has_nested_representative = (
        isinstance(root.get("analyses"), list)
        and len(root.get("analyses") or []) == 1
    )
    is_host = bool(root.get("request_id") or root.get("hostname"))
    if is_host:
        identity = _first_value(root, "hostname", "client_id") or "unknown"
        title = f"Host analysis: {identity}"
    else:
        hunt_ids = [
            str(item.get("hunt_id") or "").strip()
            for item in root.get("analyses") or []
            if isinstance(item, Mapping) and str(item.get("hunt_id") or "").strip()
        ]
        identity = _first_value(root, "group") or ", ".join(hunt_ids)
        identity = identity or _first_value(representative, "hunt_id") or "unknown"
        title = f"Hunt analysis: {identity}"

    analyses = [
        dict(item)
        for item in root.get("analyses") or []
        if isinstance(item, Mapping)
    ]
    status = _first_value(root, "status") or _first_value(
        representative, "status", "analysis_status", "overall_status"
    )
    if not status and analyses:
        statuses = {
            _first_value(item, "status", "analysis_status", "overall_status")
            or "unknown"
            for item in analyses
        }
        status = next(iter(statuses)) if len(statuses) == 1 else "mixed"
    lines = [title, f"Overall: {status or 'unknown'}"]
    ai_status = _first_value(root, "ai_review_status") or _first_value(representative, "ai_review_status")
    if ai_status:
        lines.append(f"AI review: {ai_status}")
    source_status = _first_value(
        representative,
        "source_status",
        "hunt_status",
        "source_hunt_status",
    )
    if source_status:
        lines.append(f"Source: {source_status}")

    coverage = representative.get("coverage")
    if not isinstance(coverage, Mapping):
        coverage = root.get("coverage")
    if not isinstance(coverage, Mapping):
        coverage = {
            "result_review": representative.get("result_review_coverage"),
            "target_execution": representative.get("target_execution_coverage"),
            "overall": representative.get("coverage"),
        }
    if isinstance(coverage, Mapping):
        display_coverage = dict(coverage)
        if autoruns_reporting.hide_unassessed_target_execution(
            {**representative, "coverage": coverage}
        ):
            display_coverage.pop("target_execution", None)
            display_coverage.pop("target_execution_status", None)
        lines.extend(_coverage_lines(display_coverage))
    lines.extend(_count_lines(root))
    if has_nested_representative:
        lines.extend(_count_lines(representative))
    if len(analyses) > 1:
        lines.append("")
        for item in analyses:
            hunt_id = _first_value(item, "hunt_id") or "unknown"
            item_status = _first_value(
                item, "status", "analysis_status", "overall_status"
            ) or "unknown"
            review = _first_value(item, "result_review_coverage")
            target = _first_value(item, "target_execution_coverage")
            details = [f"status={item_status}"]
            if review:
                details.append(f"result_review={review}")
            if target and not autoruns_reporting.hide_unassessed_target_execution(item):
                details.append(f"target_execution={target}")
            lines.append(f"Hunt {hunt_id}: " + "; ".join(details))

    summary = str(root.get("chat_summary") or representative.get("chat_summary") or "").strip()
    if not summary:
        summary = "No chat summary was returned. Consult the linked analysis report."
    lines.extend(["", summary])

    paths = _path_lines(root)
    if has_nested_representative:
        for line in _path_lines(representative):
            if line not in paths:
                paths.append(line)
    if paths:
        lines.extend(["", *paths])
    return "\n".join(lines).rstrip()


def _safe_token(value: Any) -> str:
    text = re.sub(r"\s+", "_", str(value).strip())
    text = re.sub(r"[^A-Za-z0-9._:/@+\-=]", "_", text)
    if len(text) > MAX_PROGRESS_VALUE_CHARS:
        text = text[:MAX_PROGRESS_VALUE_CHARS].rstrip("_")
    return text or "-"


def agent_event_progress(event: Any) -> dict[str, Any]:
    """Return the safe lifecycle fields from one AgentEvent."""
    result = {
        "phase": "provider",
        "status": getattr(event, "type", "request_unknown"),
        "provider": getattr(event, "provider", ""),
        "model": getattr(event, "model", ""),
        "protocol": getattr(event, "protocol", ""),
        "request_id": getattr(event, "request_id", ""),
        "task_id": getattr(event, "task_id", ""),
        "attempt": getattr(event, "attempt", 0),
    }
    metadata = getattr(event, "metadata", {})
    if isinstance(metadata, Mapping):
        result.update(
            {key: metadata[key] for key in _AGENT_METADATA_KEYS if key in metadata}
        )
        if "delay_seconds" in metadata:
            result["retry_delay_seconds"] = metadata["delay_seconds"]
    return result


class ProgressReporter:
    """Emit throttled evidence-free progress markers and silent-wait heartbeats."""

    def __init__(
        self,
        *,
        scope: str,
        scope_id: str = "",
        enabled: bool = True,
        stream: TextIO | None = None,
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
        throttle_seconds: float = DEFAULT_PROGRESS_THROTTLE_SECONDS,
        monotonic: Any = time.monotonic,
    ) -> None:
        self.scope = _safe_token(scope)
        self.scope_id = _safe_token(scope_id) if scope_id else ""
        self.enabled = enabled
        self.stream = stream or sys.stderr
        self.heartbeat_seconds = max(0.0, float(heartbeat_seconds))
        self.throttle_seconds = max(0.0, float(throttle_seconds))
        self._monotonic = monotonic
        self._operation_logger = operation_log.current_session()
        self._operation_id = (
            self._operation_logger.operation_id if self._operation_logger else ""
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state: dict[str, Any] = {"phase": "starting", "status": "running"}
        self._last_by_key: dict[str, tuple[str, str, float]] = {}
        self._task_states: dict[str, str] = {}
        self._task_total = 0
        self._task_completed = 0
        self._task_failed = 0

    def start(self, *, phase: str = "starting", **fields: Any) -> None:
        self.emit(phase=phase, status="running", force=True, **fields)
        if (
            self.heartbeat_seconds <= 0
            or self._thread is not None
            or (not self.enabled and self._operation_logger is None)
        ):
            return
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"dfir-status-{self.scope}",
            daemon=True,
        )
        self._thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_seconds):
            self.heartbeat()

    def _render(self, state: Mapping[str, Any]) -> str:
        parts = [
            "DFIR-STATUS",
            "v=1",
            f"scope={self.scope}",
        ]
        if self.scope_id:
            parts.append(f"id={self.scope_id}")
        operation_id = self._operation_id or operation_log.current_operation_id()
        if operation_id:
            parts.append(f"operation_id={operation_id}")
        parts.extend(
            [
                f"phase={_safe_token(state.get('phase') or 'unknown')}",
                f"status={_safe_token(state.get('status') or 'running')}",
            ]
        )
        for key in _PROGRESS_KEYS:
            value = state.get(key)
            if value in (None, "", False):
                continue
            parts.append(f"{key}={_safe_token(value)}")
        return " ".join(parts)

    def _write_locked(self, state: Mapping[str, Any], now: float) -> None:
        logger = self._operation_logger or operation_log.current_session()
        suppress_file_heartbeat = bool(
            logger is not None
            and state.get("heartbeat")
            and state.get("phase") != "provider"
            and logger.has_active_query
        )
        if logger is not None and not suppress_file_heartbeat:
            provider_status = str(state.get("status") or "")
            if provider_status in {"request_accepted", "usage_updated", "output_progress"}:
                log_level = "debug"
            elif provider_status in {"request_failed", "request_timed_out"}:
                log_level = "error"
            elif provider_status in {"retry_scheduled", "request_cancelled"}:
                log_level = "warning"
            else:
                log_level = "info"
            logger.emit(
                "progress",
                level=log_level,
                component=self.scope,
                scope=self.scope,
                scope_id=self.scope_id,
                stage=state.get("phase") or "unknown",
                phase=state.get("phase") or "unknown",
                status=state.get("status") or "running",
                **{key: state[key] for key in _PROGRESS_KEYS if key in state},
            )
        if self.enabled:
            try:
                print(self._render(state), file=self.stream, flush=True)
            except (OSError, ValueError):
                self.enabled = False
                if self._operation_logger is None and not operation_log.is_active():
                    self._stop.set()
    @staticmethod
    def _event_key(state: Mapping[str, Any]) -> str:
        for key in ("task_id", "request_id", "artifact", "hunt_id", "flow_id"):
            value = str(state.get(key) or "").strip()
            if value:
                return f"{key}:{value}"
        return "scope"

    @staticmethod
    def _bounded_remember(target: dict[str, Any], key: str, value: Any) -> None:
        if key not in target and len(target) >= MAX_PROGRESS_TASK_STATES:
            target.pop(next(iter(target)), None)
        target[key] = value

    def _track_task_lifecycle(self, state: Mapping[str, Any]) -> None:
        if str(state.get("phase") or "") != "provider":
            return
        status = str(state.get("status") or "")
        if status not in _UNTHROTTLED_PROVIDER_EVENTS:
            return
        task_key = self._event_key(state)
        previous = self._task_states.get(task_key)
        if status == "request_started":
            if previous is None:
                self._task_total += 1
            self._bounded_remember(self._task_states, task_key, "active")
            return
        if status == "retry_scheduled":
            self._bounded_remember(self._task_states, task_key, "active")
            return
        if status == "request_completed" and previous != status:
            self._task_completed += 1
        elif status in _TERMINAL_PROVIDER_EVENTS and previous != status:
            self._task_failed += 1
        self._bounded_remember(self._task_states, task_key, status)

    def emit(
        self,
        *,
        phase: str,
        status: str = "running",
        force: bool = False,
        **fields: Any,
    ) -> None:
        safe_fields = {key: fields[key] for key in _PROGRESS_KEYS if key in fields}
        with self._lock:
            self._state = {"phase": phase, "status": status, **safe_fields}
            self._track_task_lifecycle(self._state)
            now = float(self._monotonic())
            event_key = self._event_key(self._state)
            previous = self._last_by_key.get(
                event_key,
                ("", "", float("-inf")),
            )
            immediate = (
                force
                or phase != previous[0]
                or status != previous[1]
                or status in _IMMEDIATE_STATUSES
                or (
                    phase == "provider"
                    and status in _UNTHROTTLED_PROVIDER_EVENTS
                )
            )
            if immediate or now - previous[2] >= self.throttle_seconds:
                self._write_locked(self._state, now)
                self._bounded_remember(
                    self._last_by_key,
                    event_key,
                    (phase, status, now),
                )

    def update(self, event: Mapping[str, Any]) -> None:
        """Translate a coordinator event without forwarding arbitrary values."""
        phase = str(event.get("phase") or self._state.get("phase") or "running")
        status = str(event.get("status") or "running")
        fields = {key: event[key] for key in _PROGRESS_KEYS if key in event}
        if "accepted_chunks" in event:
            fields["accepted"] = event["accepted_chunks"]
        if "failed_chunks" in event:
            fields["failed"] = event["failed_chunks"]
        if "active_agents" in event:
            fields["active"] = event["active_agents"]
        force = bool(event.get("force")) or status in _IMMEDIATE_STATUSES
        self.emit(phase=phase, status=status, force=force, **fields)

    def heartbeat(self) -> None:
        if not self.enabled and self._operation_logger is None:
            return
        with self._lock:
            state = {**self._state, "heartbeat": 1}
            if self._task_states:
                state.update(
                    {
                        "active": sum(
                            1
                            for task_status in self._task_states.values()
                            if task_status == "active"
                        ),
                        "completed": self._task_completed,
                        "failed": self._task_failed,
                        "total": self._task_total,
                    }
                )
            self._write_locked(state, float(self._monotonic()))

    def close(self, *, status: str, phase: str = "complete", **fields: Any) -> None:
        self.emit(phase=phase, status=status, force=True, **fields)
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=min(1.0, self.heartbeat_seconds + 0.1))
