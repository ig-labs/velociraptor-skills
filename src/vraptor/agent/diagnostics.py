"""Bounded, value-free diagnostics for provider-backed analyst execution."""

from __future__ import annotations

import contextvars
import copy
import functools
import hashlib
import json
import re
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit, urlunsplit

from vraptor.common import atomic_io


SCHEMA_VERSION = 3
MAX_ATTEMPTS = 512
MAX_VALIDATION_FAILURES = 512
MAX_FILE_BYTES = 1024 * 1024
MAX_TEXT_CHARS = 256
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_ACTIVE_SESSION: contextvars.ContextVar["DebugSession | None"] = (
    contextvars.ContextVar("dfir_agent_debug_session", default=None)
)
_SESSIONS_BY_PATH: dict[Path, "DebugSession"] = {}
_REGISTRY_LOCK = threading.Lock()
T = TypeVar("T")


def _now_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_identifier(value: Any) -> str:
    text = " ".join(str(value or "").split())[:MAX_TEXT_CHARS]
    if not text:
        return ""
    if _SAFE_IDENTIFIER.fullmatch(text):
        return text
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_error_text(value: Any) -> str:
    """Retain normalized provider errors while rejecting obvious payload text."""

    text = " ".join(str(value or "").split())[:MAX_TEXT_CHARS]
    if not text:
        return ""
    text = re.sub(r"(?i)(api[_ -]?key|authorization|bearer)\s*[:=]\s*\S+", r"\1=<redacted>", text)
    text = re.sub(r"(?i)https?://\S+", "<url-redacted>", text)
    return text


def _safe_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not parsed.scheme or not parsed.hostname:
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _mapping(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Mapping):
        return dict(value)
    return {
        key: getattr(value, key)
        for key in (
            "type",
            "task_id",
            "provider",
            "model",
            "protocol",
            "timestamp",
            "attempt",
            "request_id",
            "metadata",
            "status",
            "elapsed_seconds",
            "attempt_count",
            "error",
            "error_classification",
            "provider_status",
            "provider_error_code",
            "provider_error_param",
            "retryable",
            "retry_after_seconds",
            "usage",
            "finish_reason",
            "max_output_tokens_requested",
            "max_output_tokens_sent",
            "local_output_tokens",
        )
        if hasattr(value, key)
    }


def _safe_configuration(value: Mapping[str, Any]) -> dict[str, Any]:
    sources = value.get("field_sources")
    return {
        "provider": _safe_identifier(value.get("provider")),
        "model": _safe_identifier(value.get("model")),
        "protocol": _safe_identifier(value.get("protocol")),
        "base_url": _safe_url(value.get("base_url")),
        "auth_mode": _safe_identifier(value.get("auth_mode")),
        "api_version": _safe_identifier(value.get("api_version")),
        "reasoning_effort": _safe_identifier(value.get("reasoning_effort")),
        "harness": _safe_identifier(value.get("harness")),
        "harness_profile": _safe_identifier(value.get("harness_profile")),
        "harness_config_path": str(value.get("harness_config_path") or "")[:512],
        "credential_variable": _safe_identifier(value.get("credential_variable")),
        "credential_present": bool(value.get("credential_present")),
        "default_query_keys": sorted(
            _safe_identifier(item) for item in value.get("default_query_keys") or []
        ),
        "default_header_keys": sorted(
            _safe_identifier(item) for item in value.get("default_header_keys") or []
        ),
        "field_sources": {
            _safe_identifier(key): _safe_identifier(item)
            for key, item in dict(sources or {}).items()
        },
    }


class DebugSession(AbstractContextManager["DebugSession"]):
    """Thread-safe, atomically refreshed diagnostic session."""

    def __init__(
        self,
        path: Path,
        *,
        scope_type: str,
        scope_id: str,
        lane: str,
        request_id: str = "",
        run_id: str = "",
    ) -> None:
        self.path = path.expanduser().resolve()
        self.lock = threading.RLock()
        self.token: contextvars.Token[DebugSession | None] | None = None
        self.requests: dict[str, dict[str, Any]] = {}
        self.attempts: dict[tuple[str, int], dict[str, Any]] = {}
        self.validation_failures: list[dict[str, Any]] = []
        self.stages: dict[str, dict[str, Any]] = {}
        self.payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "scope_type": _safe_identifier(scope_type),
            "scope_id": _safe_identifier(scope_id),
            "lane": _safe_identifier(lane),
            "request_id": _safe_identifier(request_id),
            "run_id": _safe_identifier(run_id or uuid.uuid4().hex),
            "status": "running",
            "created_at": _now_utc(),
            "updated_at": _now_utc(),
            "retention": "bounded_value_free_provider_and_validation_diagnostics",
            "configuration": {},
            "summary": {},
            "stages": [],
            "provider_attempts": [],
            "attempt_failure_count": 0,
            "attempt_failures_truncated": 0,
            "attempt_failures": [],
            "raw_rows_persisted": False,
            "prompts_persisted": False,
            "model_output_persisted": False,
            "raw_provider_payloads_persisted": False,
            "raw_stderr_persisted": False,
            "runtime_files_persisted": False,
        }

    def __enter__(self) -> "DebugSession":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _REGISTRY_LOCK:
            _SESSIONS_BY_PATH[self.path] = self
        self.token = _ACTIVE_SESSION.set(self)
        self.flush()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc is not None:
            self.record_stage(
                "runtime",
                status="failed",
                error_class=type(exc).__name__,
                error=_safe_error_text(exc),
            )
            self.finalize("failed")
        elif self.payload.get("status") == "running":
            self.finalize("complete")
        if self.token is not None:
            _ACTIVE_SESSION.reset(self.token)
            self.token = None
        with _REGISTRY_LOCK:
            if _SESSIONS_BY_PATH.get(self.path) is self:
                _SESSIONS_BY_PATH.pop(self.path, None)

    def record_request(
        self,
        request: Any,
        *,
        configuration: Mapping[str, Any],
        limits: Mapping[str, Any] | None,
        retry_policy: Mapping[str, Any],
        timeout_policy: Mapping[str, Any],
        input_tokens_estimated: int,
        max_output_tokens_requested: int | None,
        max_output_tokens_sent: bool,
    ) -> None:
        raw = _mapping(request)
        task_id = _safe_identifier(raw.get("task_id"))
        metadata = dict(raw.get("metadata") or {})
        with self.lock:
            self.payload["configuration"] = _safe_configuration(configuration)
            self.requests[task_id] = {
                "task_id": task_id,
                "stage": _safe_identifier(metadata.get("stage") or "analysis"),
                "input_tokens_estimated": max(0, int(input_tokens_estimated or 0)),
                "stream": bool(raw.get("stream", True)),
                "request_options": {
                    "output_schema_present": bool(raw.get("output_schema")),
                    "max_output_tokens_requested": max_output_tokens_requested,
                    "max_output_tokens_sent": max_output_tokens_sent,
                },
                "limits": {
                    key: item
                    for key, item in dict(limits or {}).items()
                    if key
                    in {
                        "model_context_tokens",
                        "operational_context_tokens",
                        "maximum_input_tokens",
                        "maximum_output_tokens",
                        "token_encoding",
                    }
                },
                "retry_policy": {
                    key: item
                    for key, item in retry_policy.items()
                    if key in {"max_retries", "initial_backoff_seconds", "maximum_backoff_seconds"}
                },
                "timeout_policy": {
                    key: item
                    for key, item in timeout_policy.items()
                    if key in {"connect_seconds", "read_seconds", "total_seconds", "idle_stream_seconds"}
                },
            }
            self.flush()

    def record_event(self, event: Any) -> None:
        raw = _mapping(event)
        event_type = str(raw.get("type") or "")
        task_id = _safe_identifier(raw.get("task_id"))
        attempt_number = max(1, int(raw.get("attempt") or 1))
        metadata = dict(raw.get("metadata") or {})
        with self.lock:
            key = (task_id, attempt_number)
            record = self.attempts.setdefault(
                key,
                {
                    "task_id": task_id,
                    "stage": self.requests.get(task_id, {}).get("stage", "analysis"),
                    "attempt": attempt_number,
                    "provider": _safe_identifier(raw.get("provider")),
                    "model": _safe_identifier(raw.get("model")),
                    "protocol": _safe_identifier(raw.get("protocol")),
                    "status": "running",
                },
            )
            record["last_event"] = _safe_identifier(event_type)
            record["updated_at"] = str(raw.get("timestamp") or _now_utc())
            request_id = _safe_identifier(raw.get("request_id"))
            if request_id:
                record["provider_request_id"] = request_id
            if event_type == "request_started":
                record["started_at"] = record["updated_at"]
            elif event_type == "request_accepted":
                record["accepted_at"] = record["updated_at"]
            elif event_type == "request_completed":
                record["status"] = "succeeded"
                record["completed_at"] = record["updated_at"]
            elif event_type in {"request_failed", "request_timed_out", "request_cancelled"}:
                record["status"] = (
                    "timeout" if event_type == "request_timed_out" else "failed"
                )
                record["completed_at"] = record["updated_at"]
            elif event_type == "retry_scheduled":
                record["status"] = "retrying"
            for source, destination in (
                ("error_classification", "error_classification"),
                ("provider_error_code", "provider_error_code"),
                ("provider_error_param", "provider_error_param"),
            ):
                value = _safe_identifier(metadata.get(source))
                if value:
                    record[destination] = value
            for source in ("provider_status", "input_tokens", "output_tokens", "total_tokens", "cached_input_tokens"):
                value = metadata.get(source)
                if isinstance(value, (int, float)):
                    record[source] = int(value)
            for source in (
                "local_output_tokens",
                "max_output_tokens_requested",
            ):
                value = metadata.get(source)
                if isinstance(value, (int, float)):
                    record[source] = int(value)
            if "max_output_tokens_sent" in metadata:
                record["max_output_tokens_sent"] = bool(
                    metadata.get("max_output_tokens_sent")
                )
            finish_reason = _safe_identifier(metadata.get("finish_reason"))
            if finish_reason:
                record["finish_reason"] = finish_reason
            for source in ("delay_seconds", "retry_after_seconds"):
                value = metadata.get(source)
                if isinstance(value, (int, float)):
                    record[source] = round(float(value), 6)
            if "retryable" in metadata:
                record["retryable"] = bool(metadata.get("retryable"))
            if event_type != "output_progress":
                self.flush()

    def record_result(self, result: Any) -> None:
        raw = _mapping(result)
        task_id = _safe_identifier(raw.get("task_id"))
        attempt_number = max(1, int(raw.get("attempt_count") or 1))
        with self.lock:
            record = self.attempts.setdefault(
                (task_id, attempt_number),
                {
                    "task_id": task_id,
                    "stage": self.requests.get(task_id, {}).get("stage", "analysis"),
                    "attempt": attempt_number,
                },
            )
            record.update(
                {
                    "provider": _safe_identifier(raw.get("provider")),
                    "model": _safe_identifier(raw.get("model")),
                    "protocol": _safe_identifier(raw.get("protocol")),
                    "status": _safe_identifier(raw.get("status")),
                    "elapsed_seconds": round(float(raw.get("elapsed_seconds") or 0), 6),
                    "error_classification": _safe_identifier(raw.get("error_classification")),
                    "provider_status": raw.get("provider_status"),
                    "provider_error_code": _safe_identifier(raw.get("provider_error_code")),
                    "provider_error_param": _safe_identifier(raw.get("provider_error_param")),
                    "retryable": bool(raw.get("retryable")),
                    "retry_after_seconds": raw.get("retry_after_seconds"),
                    "finish_reason": _safe_identifier(raw.get("finish_reason")),
                    "usage": {
                        key: int(item)
                        for key, item in dict(raw.get("usage") or {}).items()
                        if isinstance(item, (int, float))
                    },
                    "max_output_tokens_requested": raw.get(
                        "max_output_tokens_requested"
                    ),
                    "max_output_tokens_sent": bool(
                        raw.get("max_output_tokens_sent")
                    ),
                    "local_output_tokens": raw.get("local_output_tokens"),
                }
            )
            request_id = _safe_identifier(raw.get("request_id"))
            if request_id:
                record["provider_request_id"] = request_id
            error = _safe_error_text(raw.get("error"))
            if error:
                record["error"] = error
            self.flush()

    def record_stage(self, name: str, *, status: str, **metadata: Any) -> None:
        with self.lock:
            record = self.stages.setdefault(
                _safe_identifier(name), {"stage": _safe_identifier(name)}
            )
            record["status"] = _safe_identifier(status)
            record["updated_at"] = _now_utc()
            for key, value in metadata.items():
                if isinstance(value, bool):
                    record[_safe_identifier(key)] = value
                elif isinstance(value, (int, float)):
                    record[_safe_identifier(key)] = value
                elif key in {"error", "message"}:
                    text = str(value or "")
                    record[f"{_safe_identifier(key)}_length"] = len(text)
                    record[f"{_safe_identifier(key)}_sha256"] = hashlib.sha256(
                        text.encode("utf-8")
                    ).hexdigest()
                else:
                    record[_safe_identifier(key)] = _safe_identifier(value)
            self.flush()

    def update_validation(
        self,
        base: Mapping[str, Any],
        attempts: Iterable[Mapping[str, Any]],
        *,
        status: str,
        completed_at: str = "",
    ) -> dict[str, Any]:
        ordered = [copy.deepcopy(dict(item)) for item in attempts]
        ordered.sort(
            key=lambda item: (
                int(item.get("ordinal") or 0),
                str(item.get("chunk_id") or ""),
                int(item.get("attempt") or 0),
            )
        )
        with self.lock:
            for key in (
                "scope_type",
                "scope_id",
                "request_id",
                "run_id",
                "lane",
                "operation_id",
            ):
                value = base.get(key)
                if value:
                    self.payload[key] = _safe_identifier(value)
            for key in ("artifact_diagnostics", "candidate_output"):
                if key in base:
                    self.payload[key] = copy.deepcopy(base[key])
            self.validation_failures = ordered[:MAX_VALIDATION_FAILURES]
            self.payload["attempt_failure_count"] = len(ordered)
            self.payload["attempt_failures_truncated"] = max(
                0, len(ordered) - len(self.validation_failures)
            )
            self.payload["status"] = _safe_identifier(status)
            if completed_at:
                self.payload["completed_at"] = completed_at
            self.flush()
            return copy.deepcopy(self.payload)

    def finalize(self, status: str, *, completed_at: str = "") -> dict[str, Any]:
        with self.lock:
            self.payload["status"] = _safe_identifier(status)
            self.payload["completed_at"] = completed_at or _now_utc()
            self.flush()
            return copy.deepcopy(self.payload)

    def _render(self) -> dict[str, Any]:
        attempts = sorted(
            self.attempts.values(),
            key=lambda item: (
                str(item.get("task_id") or ""),
                int(item.get("attempt") or 0),
            ),
        )[-MAX_ATTEMPTS:]
        usage: dict[str, int] = {}
        for item in attempts:
            for key, value in dict(item.get("usage") or {}).items():
                usage[key] = usage.get(key, 0) + int(value)
        task_ids = {str(item.get("task_id") or "") for item in attempts}
        payload = copy.deepcopy(self.payload)
        payload["updated_at"] = _now_utc()
        payload["summary"] = {
            "request_count": len(task_ids),
            "attempt_count": len(attempts),
            "succeeded_attempt_count": sum(
                str(item.get("status") or "") == "succeeded" for item in attempts
            ),
            "failed_attempt_count": sum(
                str(item.get("status") or "") in {"failed", "timeout", "cancelled"}
                for item in attempts
            ),
            "retry_scheduled_count": sum(
                str(item.get("last_event") or "") == "retry_scheduled"
                or str(item.get("status") or "") == "retrying"
                for item in attempts
            ),
            "elapsed_seconds": round(
                sum(float(item.get("elapsed_seconds") or 0) for item in attempts), 6
            ),
            "usage": usage,
        }
        payload["requests"] = [self.requests[key] for key in sorted(self.requests)][
            -MAX_ATTEMPTS:
        ]
        payload["provider_attempts"] = attempts
        payload["stages"] = [self.stages[key] for key in sorted(self.stages)]
        payload["attempt_failures"] = copy.deepcopy(self.validation_failures)
        return payload

    def flush(self) -> None:
        with self.lock:
            payload = self._render()
            while payload["provider_attempts"] and len(
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ) > MAX_FILE_BYTES:
                payload["provider_attempts"].pop(0)
                payload["summary"]["attempt_records_truncated"] = (
                    payload["summary"].get("attempt_records_truncated", 0) + 1
                )
            while payload["attempt_failures"] and len(
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ) > MAX_FILE_BYTES:
                payload["attempt_failures"].pop()
                payload["attempt_failures_truncated"] += 1
            while payload["requests"] and len(
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ) > MAX_FILE_BYTES:
                payload["requests"].pop(0)
                payload["summary"]["request_records_truncated"] = (
                    payload["summary"].get("request_records_truncated", 0) + 1
                )
            while payload["stages"] and len(
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ) > MAX_FILE_BYTES:
                payload["stages"].pop(0)
                payload["summary"]["stage_records_truncated"] = (
                    payload["summary"].get("stage_records_truncated", 0) + 1
                )
            diagnostics = payload.get("artifact_diagnostics")
            while isinstance(diagnostics, list) and diagnostics and len(
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
            ) > MAX_FILE_BYTES:
                diagnostics.pop()
                payload["artifact_diagnostics_truncated"] = int(
                    payload.get("artifact_diagnostics_truncated") or 0
                ) + 1
            atomic_io.write_json_atomic(self.path, payload, sort_keys=True)


def current_session() -> DebugSession | None:
    return _ACTIVE_SESSION.get()


def session_for_path(path: Path) -> DebugSession | None:
    resolved = path.expanduser().resolve()
    session = current_session()
    if session is not None and session.path == resolved:
        return session
    with _REGISTRY_LOCK:
        return _SESSIONS_BY_PATH.get(resolved)


def auto_debug_scope(
    resolver: Callable[..., DebugSession | None],
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Activate a resolved session around a public analysis entry point."""

    def decorate(function: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> T:
            if current_session() is not None:
                return function(*args, **kwargs)
            session = resolver(*args, **kwargs)
            if session is None:
                return function(*args, **kwargs)
            with session:
                result = function(*args, **kwargs)
                result_status = (
                    str(result.get("status") or "complete")
                    if isinstance(result, Mapping)
                    else "complete"
                )
                if session.payload.get("status") == "running":
                    session.finalize(result_status)
                return result

        return wrapped

    return decorate
