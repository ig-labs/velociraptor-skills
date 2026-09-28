"""Human-readable, bounded progress logging for Velociraptor workflows."""

from __future__ import annotations

import contextvars
import errno
import fcntl
import hashlib
import os
import re
import socket
import stat
import subprocess
import threading
import time
import uuid
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping


MAX_EVENTS = 4096
MAX_FILE_BYTES = 1024 * 1024
MAX_LOG_FILES = 4
MAX_IDENTIFIER_CHARS = 256
MAX_SERVER_MESSAGE_CHARS = 512
MAX_TASK_STATES = 2048
LOG_FILENAME = "velociraptor-progress.log"
LOCK_SUFFIX = ".lock"
LOCK_TIMEOUT_SECONDS = 2.0
LOCK_POLL_SECONDS = 0.01
DEBUG_ENV_VAR = "VELO_PROGRESS_FILE_DEBUG"
OPERATION_ID_RE = re.compile(r"^op-v1-[0-9a-f]{16}$")
SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:/@+\-=]{1,256}$")
SAFE_ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z "
    r"(?:DEBUG|INFO|WARNING|ERROR) \[op-v1-[0-9a-f]{16}\] .+$"
)
LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
TERMINAL_EVENTS = {"command_completed", "command_failed", "command_interrupted"}
PROTECTED_EVENTS = TERMINAL_EVENTS | {"operation_summary"}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"", "0", "false", "no", "off"}
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [^-\r\n]*(?:PRIVATE KEY|CERTIFICATE)[^-\r\n]*-----.*?"
    r"(?:-----END [^-\r\n]+-----|$)",
    re.IGNORECASE | re.DOTALL,
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?authorization[\"']?\s*[:=]\s*"
    r"[\"']?(?:bearer|basic)\s+[^\s,;\"']+[\"']?"
)
_CREDENTIAL_FIELD_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?(?:api[_ -]?key|password|passwd|secret|"
    r"access[_ -]?token|refresh[_ -]?token|session[_ -]?(?:id|token)|token|"
    r"client[_ -]?(?:secret|private[_ -]?key)|private[_ -]?key|cookie)"
    r"[\"']?\s*[:=]\s*(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s,;]+)"
)
_BEARER_RE = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"
)
_KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-[A-Za-z0-9_-]{16,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[A-Za-z0-9_-]{20,}|"
    r"AKIA[A-Z0-9]{16}|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r")(?![A-Za-z0-9])"
)

IDENTIFIER_FIELDS = {
    "process_started",
    "log_host",
    "analysis_mode",
    "artifact",
    "artifacts",
    "bundle",
    "certificate_status",
    "client_id",
    "command",
    "collection_type",
    "component",
    "engagement_id",
    "error_category",
    "error_class",
    "error_classification",
    "finish_reason",
    "flow_id",
    "grpc_code",
    "hostname",
    "hunt_id",
    "log_level",
    "mode",
    "message_category",
    "model",
    "reasoning_effort",
    "org_id",
    "phase",
    "protocol",
    "provider",
    "provider_error_code",
    "provider_error_param",
    "purpose",
    "query_name",
    "query_instance_id",
    "request_id",
    "scope",
    "scope_id",
    "server_identity",
    "server_message_mode",
    "server_profile",
    "stage",
    "status",
    "target_mode",
    "task_id",
}
INTEGER_FIELDS = {
    "pid",
    "log_schema",
    "matched_rows",
    "group_bins",
    "cache_rows",
    "accepted",
    "acquired",
    "active",
    "attempt",
    "artifact_count",
    "batch",
    "batches",
    "chunks",
    "characters",
    "certificate_days_remaining",
    "completed",
    "emitted",
    "env_key_count",
    "error_length",
    "events_dropped",
    "exit_code",
    "failed",
    "groups",
    "heartbeat",
    "max_row",
    "max_row_bytes",
    "max_wait",
    "message_redactions",
    "model_attempts",
    "payload_bytes",
    "provider_status",
    "queries_completed",
    "queries_failed",
    "queries_started",
    "query_chars",
    "response_part",
    "responses",
    "retention_pruned",
    "retries",
    "rows",
    "server_messages",
    "server_query_id",
    "server_timestamp",
    "server_total_rows",
    "submitted",
    "tasks_cancelled",
    "tasks_completed",
    "tasks_failed",
    "tasks_started",
    "tasks_timed_out",
    "timeout_seconds",
    "total",
    "total_tokens",
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "local_output_tokens",
    "progress_bytes_scanned",
    "progress_completed",
    "progress_rows_scanned",
    "progress_total",
}
INTEGER_FIELDS |= {
    "part", "selected_identities", "matched_identities", "missing_identities",
    "omitted_identities", "source_rows", "residual_rows", "populated_rows",
    "group_count", "request_bytes", "request_max_bytes",
}
IDENTIFIER_FIELDS |= {"error_code"}

FLOAT_FIELDS = {
    "source_acquisition_seconds",
    "model_execution_seconds",
    "first_batch_ms",
    "consumer_pause_ms",
    "duration_ms",
    "elapsed_seconds",
    "progress_elapsed_seconds",
    "progress_percent",
    "retry_after_seconds",
    "retry_delay_seconds",
    "server_idle_seconds",
}
BOOLEAN_FIELDS = {
    "debug",
    "message_truncated",
    "regenerate",
    "response_has_data",
    "retryable",
}
HASH_FIELDS = {"error_sha256", "query_sha256", "identity_reference"}
TEXT_FIELDS = {"server_message", "error_detail"}
ALLOWED_EVENT_FIELDS = (
    IDENTIFIER_FIELDS
    | INTEGER_FIELDS
    | FLOAT_FIELDS
    | BOOLEAN_FIELDS
    | HASH_FIELDS
    | TEXT_FIELDS
)

NORMAL_FIELD_ORDER = (
    "part", "error_code", "selected_identities", "matched_identities", "missing_identities",
    "source_rows", "residual_rows", "populated_rows", "group_count",
    "command",
    "pid",
    "process_started",
    "log_host",
    "log_schema",
    "log_level",
    "server_message_mode",
    "engagement_id",
    "server_profile",
    "scope",
    "scope_id",
    "artifact",
    "artifacts",
    "artifact_count",
    "hostname",
    "client_id",
    "hunt_id",
    "flow_id",
    "request_id",
    "task_id",
    "provider",
    "model",
    "reasoning_effort",
    "query_name",
    "query_instance_id",
    "timeout_seconds",
    "purpose",
    "bundle",
    "collection_type",
    "analysis_mode",
    "target_mode",
    "mode",
    "debug",
    "status",
    "attempt",
    "completed",
    "total",
    "active",
    "accepted",
    "failed",
    "rows",
    "matched_rows",
    "group_bins",
    "cache_rows",
    "server_idle_seconds",
    "progress_completed",
    "progress_total",
    "progress_percent",
    "progress_rows_scanned",
    "progress_bytes_scanned",
    "progress_elapsed_seconds",
    "groups",
    "chunks",
    "retries",
    "model_attempts",
    "tasks_started",
    "tasks_completed",
    "tasks_failed",
    "tasks_timed_out",
    "tasks_cancelled",
    "queries_started",
    "queries_completed",
    "queries_failed",
    "batches",
    "responses",
    "server_total_rows",
    "server_messages",
    "server_message",
    "error_detail",
    "message_redactions",
    "message_truncated",
    "elapsed_seconds",
    "duration_ms",
    "exit_code",
    "error_class",
    "error_category",
    "error_classification",
    "grpc_code",
    "certificate_status",
    "certificate_days_remaining",
    "finish_reason",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "local_output_tokens",
)
DEBUG_FIELD_ORDER = (
    "first_batch_ms", "consumer_pause_ms", "identity_reference",
    "omitted_identities", "source_rows", "residual_rows", "populated_rows", "group_count",
    "component",
    "scope",
    "scope_id",
    "stage",
    "phase",
    "protocol",
    "org_id",
    "batch",
    "payload_bytes",
    "max_row_bytes",
    "response_part",
    "server_query_id",
    "server_timestamp",
    "response_has_data",
    "message_category",
    "query_chars",
    "env_key_count",
    "timeout_seconds",
    "max_wait",
    "max_row",
    "events_dropped",
    "retention_pruned",
    "regenerate",
    "retryable",
    "retry_after_seconds",
    "retry_delay_seconds",
    "provider_status",
    "provider_error_code",
    "provider_error_param",
    "characters",
)
EVENT_MESSAGES = {
    "api_config_fetch_started": "Fetching the Velociraptor API configuration",
    "api_config_fetch_completed": "Velociraptor API configuration fetched",
    "api_config_fetch_failed": "Velociraptor API configuration fetch failed",
    "api_connect_started": "Connecting to the Velociraptor API",
    "api_connect_completed": "Connected to the Velociraptor API",
    "api_connection_closed": "Closed the Velociraptor API connection",
    "api_reconnect_started": "Reconnecting to the Velociraptor API",
    "api_query_started": "Velociraptor query started",
    "api_query_batch": "Velociraptor query returned a batch",
    "api_query_completed": "Velociraptor query completed",
    "api_query_stalled": "No recent response from Velociraptor",
    "api_query_resumed": "Velociraptor response resumed",
    "analysis_count_completed": "Count completed",
    "api_query_unbounded": "No timeout configured for expensive Velociraptor query",
    "api_query_waiting": "Still waiting for the Velociraptor query",
    "api_server_response": "Velociraptor server response received",
    "api_server_message": "Velociraptor server message received",
    "api_org_retry": "Retrying the query against another organization",
    "command_started": "Command started",
    "command_completed": "Command completed",
    "command_failed": "Command failed",
    "command_interrupted": "Command interrupted",
    "command_context": "Command scope selected",
    "credential_validated": "Velociraptor API credential validated",
    "log_truncated": "Progress log limit reached; further details were dropped",
    "operation_summary": "Operation summary",
    "readiness_started": "Readiness checks started",
    "readiness_validated": "Readiness checks passed",
    "readiness_completed": "Readiness checks completed",
    "retention_pruned": "Old progress log rotated",
    "stage_failed": "Step failed",
}

SERVER_MESSAGE_TEXT = {
    "disk_spill": "GROUP BY switched to slower disk processing",
    "cache_ready": "Server lookup cache ready",
    "query_started": "Server started query execution",
    "response_sent": "Server sending a response batch",
    "cancelled": "Velociraptor reported query cancellation",
    "not_found": "Velociraptor reported that a requested object was not found",
    "parse_error": "Velociraptor reported a VQL parse error",
    "permission_denied": "Velociraptor reported a permission error",
    "progress": "Velociraptor reported server-side progress",
    "resource_limit": "Velociraptor reported a resource limit",
    "server_error": "Velociraptor reported a server error",
    "timeout": "Velociraptor reported a query timeout",
    "unknown": "Velociraptor returned an unclassified server message",
}

_ACTIVE_SESSION: contextvars.ContextVar["OperationLogger | None"] = (
    contextvars.ContextVar("dfir_velociraptor_operation_log", default=None)
)
_QUERY_CONTEXT: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "velociraptor_query_context", default={}
)


@contextmanager
def query_context(**fields: Any) -> Iterator[None]:
    token = _QUERY_CONTEXT.set({**_QUERY_CONTEXT.get(), **_normalized_fields(fields)})
    try:
        yield
    finally:
        _QUERY_CONTEXT.reset(token)


def current_query_context() -> dict[str, Any]:
    return dict(_QUERY_CONTEXT.get())


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def process_snapshot(pid: int) -> tuple[str, str]:
    """Read local state and start identity without command lines or credentials."""
    if pid <= 0:
        return "unknown", ""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat=", "-o", "lstart="],
            capture_output=True, text=True, timeout=2,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown", ""
    parts = result.stdout.split()
    if result.returncode == 1 and not parts:
        return "exited", ""
    if result.returncode or len(parts) < 6:
        return "unknown", ""
    state = "stopped" if "T" in parts[0].upper() else "exited" if "Z" in parts[0] else "alive"
    return state, "_".join(parts[1:])


def _safe_identifier(value: Any) -> str:
    text = " ".join(str(value or "").split())[:MAX_IDENTIFIER_CHARS]
    if not text:
        return ""
    if SAFE_IDENTIFIER_RE.fullmatch(text):
        return text
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_hash(value: Any) -> str:
    text = str(value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def sanitize_server_message(
    value: Any,
    *,
    secrets: Iterable[str] = (),
) -> tuple[str, int, bool]:
    """Return bounded one-line server text with credential material removed."""
    text = str(value or "")
    redactions = 0
    for secret in sorted(
        {str(item) for item in secrets if len(str(item)) >= 4},
        key=len,
        reverse=True,
    ):
        occurrences = text.count(secret)
        if occurrences:
            text = text.replace(secret, "<redacted>")
            redactions += occurrences
    for pattern, replacement in (
        (_PEM_BLOCK_RE, "<redacted-pem>"),
        (_AUTHORIZATION_RE, "authorization=<redacted>"),
        (_CREDENTIAL_FIELD_RE, "credential=<redacted>"),
        (_BEARER_RE, "credential=<redacted>"),
        (_URL_CREDENTIAL_RE, r"\1<redacted>@"),
        (_KNOWN_TOKEN_RE, "<redacted-token>"),
    ):
        text, count = pattern.subn(replacement, text)
        redactions += count
    one_line = " ".join(text.split())
    one_line = "".join(char for char in one_line if char.isprintable())
    truncated = len(one_line) > MAX_SERVER_MESSAGE_CHARS
    if truncated:
        one_line = one_line[: MAX_SERVER_MESSAGE_CHARS - 3].rstrip() + "..."
    return one_line or "<empty>", redactions, truncated


def _normalized_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in fields.items():
        if key not in ALLOWED_EVENT_FIELDS or value in (None, ""):
            continue
        if key in IDENTIFIER_FIELDS:
            safe_value = _safe_identifier(value)
            if safe_value:
                normalized[key] = safe_value
        elif key in INTEGER_FIELDS:
            if isinstance(value, bool):
                normalized[key] = int(value)
            elif isinstance(value, (int, float)):
                normalized[key] = int(value)
        elif key in FLOAT_FIELDS and isinstance(value, (int, float)):
            normalized[key] = round(float(value), 3)
        elif key in BOOLEAN_FIELDS:
            normalized[key] = bool(value)
        elif key in HASH_FIELDS:
            normalized[key] = _safe_hash(value)
        elif key in TEXT_FIELDS:
            safe_text, _, _ = sanitize_server_message(value)
            normalized[key] = safe_text
    return normalized


def _env_flag_enabled(
    name: str,
    environ: Mapping[str, str] | None = None,
) -> bool:
    source = os.environ if environ is None else environ
    raw = str(source.get(name, "")).strip().lower()
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be one of: true, false, 1, 0, yes, no, on, off"
    )


def _env_debug_enabled(environ: Mapping[str, str] | None = None) -> bool:
    return _env_flag_enabled(DEBUG_ENV_VAR, environ)


@dataclass(frozen=True)
class LogOptions:
    level: str = "info"
    explicit_path: Path | None = None
    persist: bool = True


def extract_global_options(argv: list[str]) -> tuple[list[str], LogOptions]:
    """Remove logging-only options and resolve file-debug precedence."""

    remaining: list[str] = []
    explicit_level: str | None = None
    explicit_path: Path | None = None
    persist = True
    command_debug = "--debug" in argv
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--no-log-file":
            persist = False
            index += 1
            continue
        if item.startswith("--log-level="):
            explicit_level = item.split("=", 1)[1].strip().lower()
            index += 1
            continue
        if item == "--log-level":
            if index + 1 >= len(argv):
                raise ValueError("--log-level requires a value")
            explicit_level = argv[index + 1].strip().lower()
            index += 2
            continue
        if item.startswith("--log-file="):
            explicit_path = Path(item.split("=", 1)[1]).expanduser().resolve()
            index += 1
            continue
        if item == "--log-file":
            if index + 1 >= len(argv):
                raise ValueError("--log-file requires a path")
            explicit_path = Path(argv[index + 1]).expanduser().resolve()
            index += 2
            continue
        remaining.append(item)
        index += 1
    if explicit_level is not None and explicit_level not in LEVELS:
        raise ValueError("--log-level must be one of: debug, info, warning, error")
    if explicit_path is not None and not persist:
        raise ValueError("--log-file cannot be combined with --no-log-file")
    level = explicit_level or (
        "debug" if command_debug or _env_debug_enabled() else "info"
    )
    return remaining, LogOptions(
        level=level,
        explicit_path=explicit_path,
        persist=persist,
    )


def _words(value: str) -> str:
    return value.replace("_", " ").strip()


def _progress_message(fields: Mapping[str, Any]) -> str:
    phase = _words(str(fields.get("phase") or fields.get("stage") or "work"))
    status = _words(str(fields.get("status") or "running"))
    if fields.get("heartbeat"):
        return f"Still working: {phase}"
    if phase == "provider":
        if status.startswith("request "):
            return f"Model {status}"
        return f"Model request {status}"
    if phase == status:
        return status.capitalize()
    if status == "running":
        return f"Working on {phase}"
    return f"{phase.capitalize()} {status}"


def _event_message(event: str, fields: Mapping[str, Any]) -> str:
    if event == "progress":
        return _progress_message(fields)
    if event == "api_server_message":
        return SERVER_MESSAGE_TEXT.get(
            str(fields.get("message_category") or "unknown"),
            SERVER_MESSAGE_TEXT["unknown"],
        )
    return EVENT_MESSAGES.get(event, _words(event).capitalize())


def _format_line(
    *,
    timestamp: str,
    level: str,
    operation_id: str,
    event: str,
    fields: Mapping[str, Any],
    include_debug_fields: bool = False,
) -> str:
    message = _event_message(event, fields)
    ordered = list(NORMAL_FIELD_ORDER)
    if event.startswith("autoruns_"):
        ordered.extend(("stage", "batch"))
    if event == "stage_failed":
        ordered.append("stage")
    if event == "api_server_message":
        ordered.append("message_category")
    if include_debug_fields:
        ordered.extend(DEBUG_FIELD_ORDER)
    details: list[str] = []
    seen: set[str] = set()
    for key in ordered:
        if key in seen or key not in fields:
            continue
        seen.add(key)
        value = fields[key]
        if key in {"server_query_id", "server_total_rows"} and value == 0:
            continue
        if event.startswith("api_") and key in {"component", "stage"}:
            continue
        if event == "api_server_message" and key in {"response_part", "server_query_id"}:
            continue
        if event == "progress" and key in {"status", "phase"}:
            continue
        if key == "status" and event in EVENT_MESSAGES and event != "stage_failed":
            continue
        if key == "server_message":
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
            details.append(f'{key}="{escaped}"')
        elif key == "duration_ms":
            details.append(f"duration={float(value) / 1000:.1f}s")
        elif key == "elapsed_seconds":
            details.append(f"elapsed={float(value):.0f}s")
        elif key == "server_idle_seconds":
            details.append(f"server_silent={float(value):.0f}s")
        else:
            label = (
                "response_rows"
                if key == "rows" and event.startswith("api_query_")
                else "query"
                if key == "query_name"
                else "query_id"
                if key == "query_instance_id"
                else key
            )
            details.append(f"{label}={value}")
    suffix = " | " + " ".join(details) if details else ""
    return f"{timestamp} {level.upper()} [{operation_id}] {message}{suffix}\n"


class LogLockTimeout(OSError):
    """The shared progress-log lock was not acquired within the time limit."""


def lock_path_for(log_path: Path) -> Path:
    return log_path.with_name(log_path.name + LOCK_SUFFIX)


@contextmanager
def _exclusive_log_lock(
    log_path: Path,
    *,
    timeout_seconds: float = LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Hold the engagement's cross-process append and rotation lock."""
    lock_path = lock_path_for(log_path)
    if lock_path.is_symlink():
        raise OSError(f"Progress log lock must not be a symlink: {lock_path}")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        lock_stat = os.fstat(descriptor)
        if not stat.S_ISREG(lock_stat.st_mode):
            raise OSError(f"Progress log lock is not a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                if time.monotonic() >= deadline:
                    raise LogLockTimeout(
                        f"Timed out waiting for progress log lock: {lock_path}"
                    ) from exc
                time.sleep(LOCK_POLL_SECONDS)
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class OperationLogger(AbstractContextManager["OperationLogger"]):
    """Append one operation to the shared human-readable progress log."""

    def __init__(self, command: str, *, options: LogOptions | None = None) -> None:
        if options is None:
            options = LogOptions(level="debug" if _env_debug_enabled() else "info")
        self.options = options
        self.command = _safe_identifier(command) or "velociraptor"
        self.operation_id = f"op-v1-{uuid.uuid4().hex[:16]}"
        self.created_at = now_utc()
        self.started_monotonic = time.monotonic()
        self.path: Path | None = None
        self._buffer: list[tuple[str, str, dict[str, Any], bool]] = []
        self._lock = threading.RLock()
        self._event_count = 0
        self._byte_count = 0
        self._events_dropped = 0
        self._truncation_written = False
        self._finalized = False
        self._token: contextvars.Token[OperationLogger | None] | None = None
        self._retention_pruned = 0
        self._query_sequence = 0
        self._active_query_ids: set[str] = set()
        self._command_context: dict[str, Any] = {}
        self._summary = {
            "model_attempts": 0,
            "queries_completed": 0,
            "queries_failed": 0,
            "queries_started": 0,
            "retries": 0,
            "rows": 0,
            "batches": 0,
            "tasks_cancelled": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_started": 0,
            "tasks_timed_out": 0,
        }
        self._task_states: dict[str, str] = {}

    def __enter__(self) -> "OperationLogger":
        self._token = _ACTIVE_SESSION.set(self)
        if self.options.explicit_path is not None and self.options.persist:
            self.bind_path(self.options.explicit_path)
        _, process_started = process_snapshot(os.getpid())
        self.emit(
            "command_started",
            pid=os.getpid(),
            process_started=process_started,
            log_host=socket.gethostname(),
            log_schema=2,
            component="cli",
            command=self.command,
            log_level=self.options.level,
            server_message_mode="sanitized_text",
            status="running",
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc is not None and not self._finalized:
            status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
            self.record_exception(exc, stage="runtime", status=status)
            self.finalize(status=status, exit_code=130 if status == "interrupted" else 1)
        elif not self._finalized:
            self.finalize(status="complete", exit_code=0)
        if self._token is not None:
            _ACTIVE_SESSION.reset(self._token)
            self._token = None

    @property
    def is_bound(self) -> bool:
        return self.path is not None

    @property
    def has_active_query(self) -> bool:
        with self._lock:
            return bool(self._active_query_ids)

    def next_query_instance_id(self) -> str:
        with self._lock:
            self._query_sequence += 1
            return f"q-{self._query_sequence:04d}"

    def bind_case(self, case_root: Path, engagement_id: str) -> Path | None:
        if not self.options.persist or self.path is not None:
            return self.path
        normalized = str(engagement_id or "").strip()
        if not SAFE_ENGAGEMENT_RE.fullmatch(normalized) or normalized in {".", ".."}:
            return None
        root = Path(case_root).expanduser().resolve()
        return self.bind_path(root / normalized / "logs" / LOG_FILENAME)

    def bind_path(self, path: Path) -> Path | None:
        if not self.options.persist or self.path is not None:
            return self.path
        candidate = Path(path).expanduser()
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve()
        with self._lock:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            try:
                with _exclusive_log_lock(resolved):
                    if resolved.exists() and (
                        resolved.is_symlink() or not resolved.is_file()
                    ):
                        return None
                    self._retention_pruned = self._rotate_if_needed(resolved)
                    self._ensure_log_file(resolved)
            except (OSError, ValueError):
                return None
            self.path = resolved
            buffered = list(self._buffer)
            self._buffer.clear()
            for event, level, fields, terminal in buffered:
                self._append_event(event, level, fields, terminal=terminal)
            if self._retention_pruned:
                self.emit(
                    "retention_pruned",
                    level="debug",
                    component="progress_log",
                    status="complete",
                    retention_pruned=self._retention_pruned,
                )
        return self.path

    def _ensure_log_file(self, path: Path) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise OSError(f"Progress log is not a regular file: {path}")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _rotate_if_needed(self, path: Path, incoming_bytes: int = 0) -> int:
        if (
            not path.exists()
            or path.stat().st_size + max(0, incoming_bytes) <= MAX_FILE_BYTES
        ):
            return 0
        oldest = path.with_name(f"{path.name}.{MAX_LOG_FILES - 1}")
        if oldest.exists() and oldest.is_file() and not oldest.is_symlink():
            oldest.unlink()
        for index in range(MAX_LOG_FILES - 2, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            target = path.with_name(f"{path.name}.{index + 1}")
            if source.exists() and source.is_file() and not source.is_symlink():
                source.replace(target)
        path.replace(path.with_name(f"{path.name}.1"))
        return 1

    def _remember_task_state(self, task_key: str, status: str) -> None:
        if not task_key:
            return
        if task_key not in self._task_states and len(self._task_states) >= MAX_TASK_STATES:
            removable = next(
                (
                    key
                    for key, value in self._task_states.items()
                    if value != "active"
                ),
                next(iter(self._task_states)),
            )
            self._task_states.pop(removable, None)
        self._task_states[task_key] = status

    def _observe_event(self, event: str, fields: Mapping[str, Any]) -> None:
        query_instance_id = str(fields.get("query_instance_id") or "")
        if event == "api_query_started":
            self._summary["queries_started"] += 1
            if query_instance_id:
                self._active_query_ids.add(query_instance_id)
        elif event == "api_query_completed":
            self._summary["queries_completed"] += 1
            self._summary["rows"] += int(fields.get("rows") or 0)
            self._summary["batches"] += int(fields.get("batches") or 0)
            self._active_query_ids.discard(query_instance_id)
        elif event == "stage_failed" and fields.get("stage") == "api_query":
            self._summary["queries_failed"] += 1
            self._active_query_ids.discard(query_instance_id)
        if event != "progress" or fields.get("phase") != "provider":
            return
        status = str(fields.get("status") or "")
        task_key = str(fields.get("task_id") or fields.get("request_id") or "")
        previous = self._task_states.get(task_key) if task_key else None
        if status == "request_started":
            self._summary["model_attempts"] += 1
            if not task_key or previous is None:
                self._summary["tasks_started"] += 1
            self._remember_task_state(task_key, "active")
        elif status == "retry_scheduled":
            self._summary["retries"] += 1
            self._remember_task_state(task_key, "active")
        elif status == "request_completed":
            if previous != "completed":
                self._summary["tasks_completed"] += 1
            self._remember_task_state(task_key, "completed")
        elif status == "request_failed":
            if previous != "failed":
                self._summary["tasks_failed"] += 1
            self._remember_task_state(task_key, "failed")
        elif status == "request_timed_out":
            if previous != "timed_out":
                self._summary["tasks_timed_out"] += 1
            self._remember_task_state(task_key, "timed_out")
        elif status == "request_cancelled":
            if previous != "cancelled":
                self._summary["tasks_cancelled"] += 1
            self._remember_task_state(task_key, "cancelled")

    def _summary_fields(self) -> dict[str, int]:
        fields = {key: value for key, value in self._summary.items() if value}
        active = sum(
            1 for state in self._task_states.values() if state == "active"
        )
        if active:
            fields["active"] = active
        if self._events_dropped:
            fields["events_dropped"] = self._events_dropped
        if self._retention_pruned:
            fields["retention_pruned"] = self._retention_pruned
        return fields

    def emit(self, event: str, *, level: str = "info", **fields: Any) -> None:
        normalized_level = str(level or "info").lower()
        if normalized_level not in LEVELS:
            normalized_level = "info"
        normalized_event = str(event or "").strip().lower()
        if not EVENT_NAME_RE.fullmatch(normalized_event):
            normalized_event = "invalid_event"
        protected = normalized_event in PROTECTED_EVENTS
        normalized_fields = _normalized_fields({**current_query_context(), **fields})
        with self._lock:
            if normalized_event == "command_context":
                self._command_context.update({
                    key: value for key, value in normalized_fields.items()
                    if key in {"hunt_id", "artifact", "client_id", "hostname", "request_id", "scope", "scope_id"}
                })
            normalized_fields = {**self._command_context, **normalized_fields}
            self._observe_event(normalized_event, normalized_fields)
            if (
                not protected
                and LEVELS[normalized_level] < LEVELS[self.options.level]
            ):
                return
            if self.path is None:
                if len(self._buffer) < 128:
                    self._buffer.append(
                        (normalized_event, normalized_level, normalized_fields, protected)
                    )
                else:
                    self._events_dropped += 1
                return
            self._append_event(
                normalized_event,
                normalized_level,
                normalized_fields,
                terminal=protected,
            )

    def _append_event(
        self,
        event: str,
        level: str,
        fields: Mapping[str, Any],
        *,
        terminal: bool = False,
    ) -> None:
        if self.path is None:
            return
        line = _format_line(
            timestamp=now_utc(),
            level=level,
            operation_id=self.operation_id,
            event=event,
            fields=fields,
            include_debug_fields=self.options.level == "debug",
        )
        encoded = line.encode("utf-8")
        event_limit = MAX_EVENTS if terminal else max(1, MAX_EVENTS - 3)
        if self._event_count >= event_limit:
            self._events_dropped += 1
            if not terminal:
                self._write_truncation_event()
                return
        try:
            with _exclusive_log_lock(self.path):
                self._retention_pruned += self._rotate_if_needed(
                    self.path,
                    incoming_bytes=len(encoded),
                )
                self._ensure_log_file(self.path)
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY
                    | os.O_APPEND
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    written = 0
                    while written < len(encoded):
                        written += os.write(descriptor, encoded[written:])
                finally:
                    os.close(descriptor)
        except (OSError, ValueError):
            self._events_dropped += 1
            return
        self._event_count += 1
        self._byte_count += len(encoded)

    def _write_truncation_event(self) -> None:
        if self._truncation_written or self.path is None:
            return
        self._truncation_written = True
        self._append_event(
            "log_truncated",
            "warning",
            {
                "component": "progress_log",
                "status": "partial",
                "events_dropped": self._events_dropped,
            },
            terminal=True,
        )

    def record_exception(
        self,
        exc: BaseException,
        *,
        stage: str,
        status: str = "failed",
        category: str = "runtime_error",
        **fields: Any,
    ) -> None:
        text = str(exc or "")
        self.emit(
            "stage_failed",
            level="error",
            command=self.command,
            stage=stage,
            status=status,
            error_class=type(exc).__name__,
            error_category=category,
            error_length=len(text),
            error_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            **fields,
        )

    def finalize(self, *, status: str, exit_code: int) -> None:
        with self._lock:
            if self._finalized:
                return
            self._finalized = True
            event = (
                "command_interrupted"
                if status == "interrupted"
                else "command_completed"
                if exit_code == 0
                else "command_failed"
            )
            self.emit(
                "operation_summary",
                level="info",
                component="progress_log",
                command=self.command,
                status=status,
                elapsed_seconds=time.monotonic() - self.started_monotonic,
                **self._summary_fields(),
            )
            self.emit(
                event,
                level="info" if exit_code == 0 else "error",
                component="cli",
                command=self.command,
                status=status,
                exit_code=exit_code,
                elapsed_seconds=time.monotonic() - self.started_monotonic,
                events_dropped=self._events_dropped,
            )


def current_session() -> OperationLogger | None:
    return _ACTIVE_SESSION.get()


def current_operation_id() -> str:
    session = current_session()
    return session.operation_id if session is not None else ""


def is_active() -> bool:
    return current_session() is not None


def correlation_metadata() -> dict[str, str]:
    session = current_session()
    if session is None:
        return {}
    result = {"operation_id": session.operation_id}
    if session.path is not None:
        result["progress_log_file"] = str(session.path)
    return result


def bind_case(case_root: Path, engagement_id: str) -> Path | None:
    session = current_session()
    return session.bind_case(case_root, engagement_id) if session is not None else None


def emit(event: str, *, level: str = "info", **fields: Any) -> None:
    session = current_session()
    if session is not None:
        session.emit(event, level=level, **fields)


def record_exception(
    exc: BaseException,
    *,
    stage: str,
    status: str = "failed",
    category: str = "runtime_error",
    **fields: Any,
) -> None:
    session = current_session()
    if session is not None:
        session.record_exception(
            exc,
            stage=stage,
            status=status,
            category=category,
            **fields,
        )


def validate_log(path: Path) -> list[str]:
    """Validate and return one bounded human-readable progress log."""

    original = Path(path).expanduser()
    resolved = original.resolve()
    stat_result = resolved.stat()
    if original.is_symlink() or not resolved.is_file():
        raise ValueError(f"Progress log is not a regular file: {resolved}")
    if stat_result.st_size > MAX_FILE_BYTES:
        raise ValueError(f"Progress log exceeds {MAX_FILE_BYTES} bytes: {resolved}")
    if stat.S_IMODE(stat_result.st_mode) != 0o600:
        raise ValueError(f"Progress log permissions must be 0600: {resolved}")
    lines = resolved.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"Progress log is empty: {resolved}")
    for line_number, line in enumerate(lines, start=1):
        if not LOG_LINE_RE.fullmatch(line):
            raise ValueError(
                f"Progress log line {line_number} has an invalid format: {resolved}"
            )
    return lines
