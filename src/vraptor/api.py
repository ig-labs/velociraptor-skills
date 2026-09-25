from __future__ import annotations
from vraptor.resources import resource_root

import hashlib
import json
import math
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc

from vraptor.logging import operations as operation_log


DEFAULT_ORG_ID = "root"
DEFAULT_GRPC_MAX_MESSAGE_BYTES = 64 * 1024 * 1024
VQL_ERROR_LOG_RE = re.compile(
    r"(?im)(?:^|\s)(?:error|fatal)(?:\s|:)|"
    r"\b(?:parse|syntax)\s+error\b|"
    r"\bvql\b.*\berror\b|"
    r"\bquery\b.*\bfailed\b"
)
QUERY_SOURCE_NAMES = (
    "hunt_results",
    "hunt_flows",
    "hunt_info",
    "flow_results",
    "artifact_definitions",
    "inventory_get",
    "source",
    "scope",
    "gui_users",
    "clients",
    "hunts",
    "flows",
)
QUERY_HEARTBEAT_SECONDS = 30.0
QUERY_STALL_SECONDS = 60.0
QUERY_QUIET_HEARTBEAT_SECONDS = 300.0
MAX_SERVER_LOG_MESSAGES_PER_QUERY = 100
MAX_SERVER_LOG_CHARS = 64 * 1024
SERVER_MESSAGE_SECRET_ENV_NAME_RE = re.compile(
    r"(?:^|_)(?:API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|CREDENTIAL)$",
    re.IGNORECASE,
)
SERVER_ERROR_CATEGORIES = {
    "cancelled",
    "not_found",
    "parse_error",
    "permission_denied",
    "resource_limit",
    "server_error",
    "timeout",
}
MAX_SAFE_PROGRESS_INTEGER = (1 << 63) - 1
SAFE_SERVER_PROGRESS_KEY_ALIASES = {
    "bytes_scanned": ("progress_bytes_scanned", "integer"),
    "completed": ("progress_completed", "integer"),
    "elapsed": ("progress_elapsed_seconds", "elapsed"),
    "elapsed_seconds": ("progress_elapsed_seconds", "elapsed"),
    "percent": ("progress_percent", "percent"),
    "percentage": ("progress_percent", "percent"),
    "progress_percent": ("progress_percent", "percent"),
    "rows_scanned": ("progress_rows_scanned", "integer"),
    "scanned_bytes": ("progress_bytes_scanned", "integer"),
    "scanned_rows": ("progress_rows_scanned", "integer"),
    "total": ("progress_total", "integer"),
}
_SAFE_PROGRESS_KEY_PATTERN = "|".join(
    re.escape(key).replace("_", r"[\s_-]+")
    for key in sorted(SAFE_SERVER_PROGRESS_KEY_ALIASES, key=len, reverse=True)
)
_SAFE_PROGRESS_LABEL_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])(?P<key>{_SAFE_PROGRESS_KEY_PATTERN})\s*[:=]"
)
_SAFE_PROGRESS_PAIR_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])(?P<key>{_SAFE_PROGRESS_KEY_PATTERN})\s*[:=]\s*"
    r"(?P<value>[+-]?(?:(?:\d{1,3}(?:,\d{3})+)|(?:\d{1,20}))(?:\.\d+)?)"
    r"\s*(?P<suffix>%|milliseconds?|msecs?|ms|seconds?|secs?|s)?"
    r"(?=$|[\s,;|])"
)


class InventoryNotFoundError(RuntimeError):
    """A query reported only the exact missing inventory-entry diagnostic."""


@dataclass(frozen=True)
class QueryBatch:
    """One streamed API response with transport-size observations."""

    rows: list[dict[str, Any]]
    payload_bytes: int
    row_count: int
    max_row_bytes: int
    response_part: int


def resolve_org_id(org_id: str | None) -> str:
    if not org_id:
        from .settings import active_value, current
        org_id = active_value("org_id") if current() else os.environ.get("VELO_LOCAL_ORG_ID")
    text = str(org_id or "").strip()
    if not text:
        return DEFAULT_ORG_ID
    if text.startswith("orgs/"):
        stripped = text.removeprefix("orgs/").strip()
        return stripped or DEFAULT_ORG_ID
    return text


def org_id_candidates(org_id: str | None) -> list[str]:
    primary = resolve_org_id(org_id)
    candidates = [primary]
    fallback = f"orgs/{primary}"
    if fallback != primary:
        candidates.append(fallback)
    return candidates


def grpc_max_message_bytes() -> int:
    """Use the same validated cap for transport and request-size planning."""
    from .settings import active_value, current, _validate_value
    raw = (active_value("grpc_max_message_bytes") if current()
           else os.environ.get("VELO_GRPC_MAX_MESSAGE_BYTES"))
    limit = int(raw or DEFAULT_GRPC_MAX_MESSAGE_BYTES)
    _validate_value("grpc_max_message_bytes", limit, "message_bytes")
    return limit


def build_vql_request(
    vql: str,
    env: dict[str, str] | None = None,
    *,
    org_id: str = DEFAULT_ORG_ID,
    timeout: int = 0,
    max_wait: int = 1,
    max_row: int = 1000,
) -> api_pb2.VQLCollectorArgs:
    """Build the wire request shared by transport and byte-bound planning."""
    return api_pb2.VQLCollectorArgs(
        org_id=org_id,
        max_wait=max_wait,
        max_row=max_row,
        timeout=timeout,
        Query=[api_pb2.VQLRequest(Name="query", VQL=vql)],
        env=[api_pb2.VQLEnv(key=key, value=value)
             for key, value in sorted((env or {}).items())],
    )


def is_org_not_found_error(exc: Exception) -> bool:
    details = getattr(exc, "details", None)
    detail_text = details() if callable(details) else str(exc)
    return "org not found" in detail_text.lower()


def describe_query(vql: str, query_name: str) -> str:
    """Return a safe purpose label without retaining or rendering VQL text."""
    selected = str(query_name or "").strip()
    if selected and selected != "inline":
        return selected
    lowered = vql.lower()
    action = next(
        (
            name
            for name in ("collect_client", "hunt_add", "hunt_update")
            if re.search(rf"\b{name}\s*\(", lowered)
        ),
        "",
    )
    if action:
        return f"{action}.execute"
    source = next(
        (name for name in QUERY_SOURCE_NAMES if re.search(rf"\b{name}\s*\(", lowered)),
        "server",
    )
    if re.search(r"\bgroup\s+by\s+(?!\s|true\b)", lowered):
        purpose = "group"
    elif re.search(r"\bcount\s*\(", lowered):
        purpose = "count"
    elif re.search(r"\border\s+by\b", lowered):
        purpose = "ordered_read"
    else:
        purpose = "read"
    return f"{source}.{purpose}"


def classify_server_log(message: str) -> str:
    """Classify one server message without returning or retaining its content."""
    lowered = str(message or "").lower()
    if re.search(r"permission denied|access denied|unauthori[sz]ed|forbidden", lowered):
        return "permission_denied"
    if re.search(r"parse error|syntax error|failed to parse|vql parser", lowered):
        return "parse_error"
    if re.search(r"deadline exceeded|timed? out|timeout", lowered):
        return "timeout"
    if re.search(r"cancelled|canceled|cancellation", lowered):
        return "cancelled"
    if re.search(r"resource exhausted|resource limit|memory limit|too large", lowered):
        return "resource_limit"
    if re.search(r"not found|does not exist|unknown artifact", lowered):
        return "not_found"
    if VQL_ERROR_LOG_RE.search(message):
        return "server_error"
    if re.search(r"(?i)GROUP BY:.*bins exceeded.*file based operation", message):
        return "disk_spill"
    if re.search(r"Filled cache with \d+ rows\s*$", message):
        return "cache_ready"
    if message.strip() == "Starting query execution.":
        return "query_started"
    if re.fullmatch(r"Time \d+: query: Sending response part \d+ [\d.]+ [A-Za-z]+ \(\d+ rows\)\.", message.strip()):
        return "response_sent"
    if re.search(r"\b(?:info|progress|complete|completed|rows?|running)\b", lowered):
        return "progress"
    return "unknown"


def _safe_response_integer(response: Any, field: str) -> int:
    try:
        return int(getattr(response, field, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _normalized_progress_key(value: str) -> str:
    return re.sub(r"[\s-]+", "_", str(value).strip().lower())


def _safe_progress_number(
    value: Any,
    *,
    kind: str,
    suffix: str = "",
    text_value: bool = False,
) -> int | float | None:
    if isinstance(value, bool):
        return None
    normalized_suffix = suffix.strip().lower()
    if kind == "integer":
        if normalized_suffix:
            return None
        if text_value:
            cleaned = str(value).replace(",", "")
            if not re.fullmatch(r"\+?\d+", cleaned):
                return None
            integer = int(cleaned)
        elif isinstance(value, int):
            integer = value
        elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
            integer = int(value)
        else:
            return None
        if integer < 0 or integer > MAX_SAFE_PROGRESS_INTEGER:
            return None
        return integer
    try:
        number = float(str(value).replace(",", "") if text_value else value)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    if kind == "percent":
        if normalized_suffix not in {"", "%"} or number > 100:
            return None
        return number
    if kind == "elapsed":
        multipliers = {
            "": 1.0,
            "s": 1.0,
            "sec": 1.0,
            "secs": 1.0,
            "second": 1.0,
            "seconds": 1.0,
            "ms": 0.001,
            "msec": 0.001,
            "msecs": 0.001,
            "millisecond": 0.001,
            "milliseconds": 0.001,
        }
        multiplier = multipliers.get(normalized_suffix)
        if multiplier is None:
            return None
        seconds = number * multiplier
        return seconds if seconds <= MAX_SAFE_PROGRESS_INTEGER else None
    return None


def extract_safe_server_progress(message: str) -> dict[str, int | float]:
    """Extract allow-listed numeric progress without returning message text."""
    text = str(message or "").strip()
    if not text:
        return {}
    if text.startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except (TypeError, ValueError):
            return {}
        if not isinstance(payload, dict):
            return {}
        extracted: dict[str, int | float] = {}
        for raw_key, raw_value in payload.items():
            definition = SAFE_SERVER_PROGRESS_KEY_ALIASES.get(
                _normalized_progress_key(str(raw_key))
            )
            if definition is None:
                continue
            output_key, kind = definition
            parsed = _safe_progress_number(raw_value, kind=kind)
            if parsed is None:
                return {}
            if output_key in extracted and extracted[output_key] != parsed:
                return {}
            extracted[output_key] = parsed
        return extracted

    labels = list(_SAFE_PROGRESS_LABEL_RE.finditer(text))
    if not labels:
        return {}
    pairs = list(_SAFE_PROGRESS_PAIR_RE.finditer(text))
    if {match.start() for match in labels} != {match.start() for match in pairs}:
        return {}
    extracted = {}
    for match in pairs:
        definition = SAFE_SERVER_PROGRESS_KEY_ALIASES.get(
            _normalized_progress_key(match.group("key"))
        )
        if definition is None:
            return {}
        output_key, kind = definition
        parsed = _safe_progress_number(
            match.group("value"),
            kind=kind,
            suffix=match.group("suffix") or "",
            text_value=True,
        )
        if parsed is None:
            return {}
        if output_key in extracted and extracted[output_key] != parsed:
            return {}
        extracted[output_key] = parsed
    if (
        "progress_completed" in extracted
        and "progress_total" in extracted
        and extracted["progress_completed"] > extracted["progress_total"]
    ):
        return {}
    return extracted


class _QueryHeartbeat:
    """Emit bounded long-query heartbeats to the captured operation log."""

    def __init__(
        self,
        query_name: str,
        query_instance_id: str,
        started: float,
        snapshot: Any,
        logger: operation_log.OperationLogger | None,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.query_name = query_name
        self.query_instance_id = query_instance_id
        self.started = started
        self.snapshot = snapshot
        self.logger = logger
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.stalled_reported = False
        self.last_emitted = started
        self.last_activity = started
        self.first_wait_emitted = False
        self.context = {**operation_log.current_query_context(), **(context or {})}

    def start(self) -> None:
        if self.logger is None or QUERY_HEARTBEAT_SECONDS <= 0:
            return
        self.thread = threading.Thread(
            target=self._run,
            name="velociraptor-query-progress",
            daemon=True,
        )
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.wait(QUERY_HEARTBEAT_SECONDS):
            self.tick(time.monotonic())

    def tick(self, now: float) -> None:
        """Report silence, never infer a remote stall from missing messages."""
        if self.logger is None:
            return
        state = self.snapshot()
        activity = float(state.get("last_server_activity", self.started))
        idle_seconds = max(0.0, now - activity)
        resumed = self.stalled_reported and activity > self.last_activity
        if activity > self.last_activity:
            self.stalled_reported = False
        self.last_activity = activity
        newly_silent = idle_seconds >= QUERY_STALL_SECONDS and not self.stalled_reported
        if newly_silent:
            self.stalled_reported = True
        if not (
            resumed or newly_silent or not self.first_wait_emitted
            or now - self.last_emitted >= QUERY_QUIET_HEARTBEAT_SECONDS
        ):
            return
        self.first_wait_emitted = True
        self.last_emitted = now
        event = "api_query_waiting"
        if newly_silent:
            event = "api_query_stalled"
        elif resumed:
            event = "api_query_resumed"
        self.logger.emit(
            event,
            level="warning" if newly_silent else "info",
            component="velociraptor_api",
            stage="query",
            status="awaiting_response",
            query_name=self.query_name,
            query_instance_id=self.query_instance_id,
            batches=int(state.get("batches") or 0),
            rows=int(state.get("rows") or 0),
            responses=int(state.get("responses") or 0),
            server_messages=int(state.get("server_messages") or 0),
            heartbeat=1,
            elapsed_seconds=now - self.started,
            server_idle_seconds=idle_seconds,
            **self.context,
        )

    def close(self) -> None:
        self.stop_event.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=0.5)




class VeloApiClient:
    def __init__(
        self,
        api_config: Path,
        org_id: str | None = None,
        *,
        reference_dir: Path | None = None,
        query_timeout_seconds: int = 0,
    ):
        if (not isinstance(query_timeout_seconds, int)
                or isinstance(query_timeout_seconds, bool) or query_timeout_seconds < 0):
            raise ValueError("query_timeout_seconds must be a non-negative integer.")
        self.query_timeout_seconds = query_timeout_seconds
        self.api_config = api_config
        self.org_id = resolve_org_id(org_id)
        self.reference_dir = reference_dir or (
            resource_root() / "vql"
        )
        self._channel: grpc.Channel | None = None
        self._stub: api_pb2_grpc.APIStub | None = None
        self.server_identity = ""
        self._operation_logger = operation_log.current_session()
        self._log_secret_values = tuple(
            value
            for key, raw_value in sorted(os.environ.items())
            if SERVER_MESSAGE_SECRET_ENV_NAME_RE.search(key)
            and len(value := str(raw_value or "")) >= 4
        )

    def _log_session(self) -> operation_log.OperationLogger | None:
        current = operation_log.current_session()
        if current is not None:
            self._operation_logger = current
        return self._operation_logger

    def _emit(self, event: str, *, level: str = "info", **fields: Any) -> None:
        logger = self._log_session()
        if logger is not None:
            logger.emit(event, level=level, **fields)

    def _record_exception(self, exc: BaseException, **fields: Any) -> None:
        logger = self._log_session()
        if logger is not None:
            logger.record_exception(exc, **fields)

    def _server_progress_fields(
        self,
        message: str,
        category: str,
    ) -> dict[str, int | float]:
        if category != "progress":
            return {}
        return extract_safe_server_progress(message)

    def _server_message_fields(
        self,
        message: str,
        category: str,
        *,
        source_truncated: bool = False,
    ) -> dict[str, Any]:
        server_message, redactions, message_truncated = (
            operation_log.sanitize_server_message(
                message,
                secrets=self._log_secret_values,
            )
        )
        result: dict[str, Any] = {
            "server_message": server_message,
        }
        if redactions:
            result["message_redactions"] = redactions
        if source_truncated or message_truncated:
            result["message_truncated"] = True
        if not source_truncated:
            result.update(self._server_progress_fields(message, category))
            if category == "cache_ready":
                match = re.search(r"Filled cache with (\d+) rows\s*$", message)
                if match:
                    result["cache_rows"] = int(match.group(1))
                    result.pop("server_message", None)
            elif category == "disk_spill":
                match = re.search(r"GROUP BY:\s*(\d+) bins exceeded", message)
                if match:
                    result["group_bins"] = int(match.group(1))
        return result

    def __enter__(self) -> "VeloApiClient":
        self.reconnect()
        return self

    def _open_channel(self) -> None:
        """Build one authenticated channel from the configured API file."""
        started = time.monotonic()
        self._emit(
            "api_connect_started",
            component="velociraptor_api",
            stage="connect",
            status="running",
            org_id=resolve_org_id(self.org_id),
        )
        try:
            config = pyvelociraptor.LoadConfigFile(str(self.api_config))
            config_secrets = tuple(
                str(config.get(key) or "")
                for key in ("ca_certificate", "client_cert", "client_private_key")
                if str(config.get(key) or "")
            )
            self._log_secret_values = tuple(
                dict.fromkeys((*self._log_secret_values, *config_secrets))
            )
            self.server_identity = hashlib.sha256(
                json.dumps(
                    {
                        "api_connection_string": str(
                            config.get("api_connection_string") or ""
                        ),
                        "ca_certificate": str(config.get("ca_certificate") or ""),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            creds = grpc.ssl_channel_credentials(
                root_certificates=config["ca_certificate"].encode("utf8"),
                private_key=config["client_private_key"].encode("utf8"),
                certificate_chain=config["client_cert"].encode("utf8"),
            )
            max_message_bytes = grpc_max_message_bytes()
            options = (
                ("grpc.ssl_target_name_override", "VelociraptorServer"),
                ("grpc.max_receive_message_length", max_message_bytes),
                ("grpc.max_send_message_length", max_message_bytes),
            )
            self._channel = grpc.secure_channel(
                config["api_connection_string"],
                creds,
                options,
            )
            self._stub = api_pb2_grpc.APIStub(self._channel)
        except BaseException as exc:
            self._record_exception(exc, stage="api_connect")
            raise
        self._emit(
            "api_connect_completed",
            component="velociraptor_api",
            stage="connect",
            status="complete",
            org_id=resolve_org_id(self.org_id),
            server_identity=self.server_identity,
            duration_ms=(time.monotonic() - started) * 1000,
        )

    def close(self) -> None:
        """Close the current channel and make the client explicitly disconnected."""
        channel = self._channel
        self._channel = None
        self._stub = None
        if channel is not None:
            channel.close()
            self._emit(
                "api_connection_closed",
                level="debug",
                component="velociraptor_api",
                stage="connect",
                status="complete",
                server_identity=self.server_identity,
            )

    def reconnect(self) -> None:
        """Replace a failed channel without changing query or authentication scope."""
        self._emit(
            "api_reconnect_started",
            component="velociraptor_api",
            stage="connect",
            status="running",
            org_id=resolve_org_id(self.org_id),
        )
        self.close()
        self._open_channel()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def query(
        self,
        vql: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
        query_name: str = "inline",
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for batch in self.query_batches(
            vql,
            env,
            timeout=timeout,
            max_wait=max_wait,
            max_row=max_row,
            query_name=query_name,
        ):
            rows.extend(batch)
        return rows

    def query_batches(
        self,
        vql: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
        query_name: str = "inline",
    ) -> Iterator[list[dict[str, Any]]]:
        for batch in self.query_batches_with_metadata(
            vql,
            env,
            timeout=timeout,
            max_wait=max_wait,
            max_row=max_row,
            query_name=query_name,
        ):
            yield batch.rows

    def query_batches_with_metadata(
        self,
        vql: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
        query_name: str = "inline",
    ) -> Iterator[QueryBatch]:
        if self._stub is None:
            raise RuntimeError("Velociraptor API client is not connected.")

        # Apply the operator's per-query ceiling even when callers explicitly
        # request the historical unlimited timeout (0). Preserve shorter limits.
        if self.query_timeout_seconds:
            timeout = (
                min(timeout, self.query_timeout_seconds)
                if timeout > 0 else self.query_timeout_seconds
            )
        query_name = describe_query(vql, query_name)

        candidates = org_id_candidates(self.org_id)
        started = time.monotonic()
        logger = self._log_session()
        query_scope = {
            field: env[key]
            for key, field in (
                ("HuntId", "hunt_id"), ("ArtifactName", "artifact"),
                ("ClientId", "client_id"), ("FlowId", "flow_id"),
            )
            if env and env.get(key)
        }

        def emit_query(event: str, **fields: Any) -> None:
            self._emit(event, **{**query_scope, **fields})

        query_instance_id = (
            logger.next_query_instance_id() if logger is not None else ""
        )
        query_sha256 = hashlib.sha256(vql.encode("utf-8")).hexdigest()
        first_batch_ms = None
        consumer_pause_ms = 0.0
        batch_count = 0
        row_count = 0
        payload_bytes = 0
        response_count = 0
        server_message_count = 0
        server_message_signatures: set[tuple[str, str]] = set()
        detected_server_error = ""
        last_server_activity = started
        inside_server_pem_block = False
        emit_query(
            "api_query_started",
            component="velociraptor_api",
            stage="query",
            status="running",
            query_name=query_name,
            query_instance_id=query_instance_id,
            query_sha256=query_sha256,
            query_chars=len(vql),
            env_key_count=len(env or {}),
            org_id=resolve_org_id(self.org_id),
            timeout_seconds=timeout,
            max_wait=max_wait,
            max_row=max_row,
            server_identity=self.server_identity,
        )
        if timeout <= 0 and query_name.endswith(
            (".count", ".group", ".ordered_read")
        ):
            emit_query(
                "api_query_unbounded",
                level="warning",
                component="velociraptor_api",
                stage="query",
                status="running",
                query_name=query_name,
                query_instance_id=query_instance_id,
            )
        heartbeat = _QueryHeartbeat(
            query_name,
            query_instance_id,
            started,
            lambda: {
                "batches": batch_count,
                "rows": row_count,
                "responses": response_count,
                "server_messages": server_message_count,
                "last_server_activity": last_server_activity,
            },
            logger,
            context=query_scope,
        )
        heartbeat.start()
        last_error: Exception | None = None
        try:
            for candidate_org_id in candidates:
                request = build_vql_request(
                    vql, env,
                    org_id=candidate_org_id,
                    max_wait=max_wait,
                    max_row=max_row,
                    timeout=timeout,
                )
                try:
                    query_errors: list[tuple[str, str]] = []
                    inventory_not_found_only = True
                    query_error_signatures: set[tuple[str, str]] = set()
                    responses = (
                        self._stub.Query(request, timeout=timeout)
                        if timeout > 0
                        else self._stub.Query(request)
                    )
                    for response in responses:
                        last_server_activity = time.monotonic()
                        response_count += 1
                        log_text = str(getattr(response, "log", "") or "")
                        log_text_truncated = len(log_text) > MAX_SERVER_LOG_CHARS
                        if log_text_truncated:
                            inventory_not_found_only = False
                        response_has_error = False
                        response_part = _safe_response_integer(response, "part")
                        server_query_id = _safe_response_integer(
                            response,
                            "query_id",
                        )
                        server_total_rows = _safe_response_integer(
                            response,
                            "total_rows",
                        )
                        response_has_data = bool(getattr(response, "Response", ""))
                        if not response_has_data and (server_query_id or server_total_rows):
                            emit_query(
                                "api_server_response",
                                level="debug",
                                component="velociraptor_api",
                                stage="query",
                                status="running",
                                query_name=query_name,
                                query_instance_id=query_instance_id,
                                response_part=response_part,
                                server_query_id=server_query_id,
                                server_timestamp=_safe_response_integer(
                                    response,
                                    "timestamp",
                                ),
                                server_total_rows=server_total_rows,
                                response_has_data=response_has_data,
                                elapsed_seconds=time.monotonic() - started,
                            )
                        for message in log_text[:MAX_SERVER_LOG_CHARS].splitlines():
                            if not message.strip():
                                continue
                            upper_message = message.strip().upper()
                            if inside_server_pem_block:
                                if upper_message.startswith("-----END "):
                                    inside_server_pem_block = False
                                continue
                            if (
                                upper_message.startswith("-----BEGIN ")
                                and (
                                    "PRIVATE KEY" in upper_message
                                    or "CERTIFICATE" in upper_message
                                )
                            ):
                                inside_server_pem_block = not (
                                    "-----END " in upper_message
                                )
                            category = classify_server_log(message)
                            if category in {"query_started", "response_sent"}:
                                continue
                            message_hash = hashlib.sha256(
                                message.encode("utf-8")
                            ).hexdigest()
                            signature = (category, message_hash)
                            if category in SERVER_ERROR_CATEGORIES:
                                response_has_error = True
                                inventory_not_found_only = (
                                    inventory_not_found_only
                                    and message.strip().lower() == "inventory_get: not found"
                                )
                                if (
                                    signature not in query_error_signatures
                                    and len(query_errors)
                                    < MAX_SERVER_LOG_MESSAGES_PER_QUERY
                                ):
                                    query_errors.append((category, message_hash))
                                    query_error_signatures.add(signature)
                            if signature in server_message_signatures:
                                continue
                            if (
                                server_message_count
                                >= MAX_SERVER_LOG_MESSAGES_PER_QUERY
                            ):
                                continue
                            server_message_signatures.add(signature)
                            server_message_count += 1
                            emit_query(
                                "api_server_message",
                                level=(
                                    "error"
                                    if category in SERVER_ERROR_CATEGORIES
                                    else "warning"
                                    if category == "disk_spill"
                                    else "info"
                                ),
                                component="velociraptor_api",
                                stage="query",
                                status=(
                                    "failed"
                                    if category in SERVER_ERROR_CATEGORIES
                                    else "running"
                                ),
                                query_name=query_name,
                                query_instance_id=query_instance_id,
                                message_category=category,
                                response_part=response_part,
                                server_query_id=server_query_id,
                                **self._server_message_fields(
                                    message,
                                    category,
                                    source_truncated=log_text_truncated,
                                ),
                            )
                        if (
                            log_text
                            and VQL_ERROR_LOG_RE.search(log_text)
                            and not response_has_error
                        ):
                            category = classify_server_log(log_text)
                            if category not in SERVER_ERROR_CATEGORIES:
                                category = "server_error"
                            inventory_not_found_only = False
                            message_hash = hashlib.sha256(
                                log_text.encode("utf-8")
                            ).hexdigest()
                            signature = (category, message_hash)
                            if (
                                signature not in query_error_signatures
                                and len(query_errors)
                                < MAX_SERVER_LOG_MESSAGES_PER_QUERY
                            ):
                                query_errors.append((category, message_hash))
                                query_error_signatures.add(signature)
                            if (
                                signature not in server_message_signatures
                                and server_message_count
                                < MAX_SERVER_LOG_MESSAGES_PER_QUERY
                            ):
                                server_message_signatures.add(signature)
                                server_message_count += 1
                                emit_query(
                                    "api_server_message",
                                    level="error",
                                    component="velociraptor_api",
                                    stage="query",
                                    status="failed",
                                    query_name=query_name,
                                    query_instance_id=query_instance_id,
                                    message_category=category,
                                    response_part=response_part,
                                    server_query_id=server_query_id,
                                    **self._server_message_fields(
                                        log_text[:MAX_SERVER_LOG_CHARS],
                                        category,
                                        source_truncated=log_text_truncated,
                                    ),
                                )
                        if response.Response:
                            batch = json.loads(response.Response)
                            if not isinstance(batch, list):
                                raise RuntimeError(
                                    "Velociraptor API response was not a row array."
                                )
                            if batch:
                                result_batch = QueryBatch(
                                    rows=batch,
                                    payload_bytes=len(response.Response.encode("utf-8")),
                                    row_count=len(batch),
                                    max_row_bytes=max(
                                        (
                                            len(
                                                json.dumps(
                                                    row,
                                                    ensure_ascii=False,
                                                    sort_keys=True,
                                                    separators=(",", ":"),
                                                    default=str,
                                                ).encode("utf-8")
                                            )
                                            for row in batch
                                        ),
                                        default=0,
                                    ),
                                    response_part=(
                                        int(getattr(response, "part"))
                                        if isinstance(getattr(response, "part", 0), int)
                                        else 0
                                    ),
                                )
                                if first_batch_ms is None:
                                    first_batch_ms = (time.monotonic() - started) * 1000
                                batch_count += 1
                                row_count += result_batch.row_count
                                payload_bytes += result_batch.payload_bytes
                                emit_query(
                                    "api_query_batch",
                                    level="debug",
                                    component="velociraptor_api",
                                    stage="query",
                                    status="running",
                                    query_name=query_name,
                                    query_instance_id=query_instance_id,
                                    batch=batch_count,
                                    rows=result_batch.row_count,
                                    payload_bytes=result_batch.payload_bytes,
                                    max_row_bytes=result_batch.max_row_bytes,
                                    response_part=result_batch.response_part,
                                    server_query_id=server_query_id,
                                    server_total_rows=server_total_rows,
                                    elapsed_seconds=time.monotonic() - started,
                                )
                                yielded_at = time.monotonic()
                                try:
                                    yield result_batch
                                finally:
                                    consumer_pause_ms += (time.monotonic() - yielded_at) * 1000
                    if query_errors:
                        detected_server_error = query_errors[0][0]
                        categories = ",".join(
                            sorted({category for category, _hash in query_errors})
                        )
                        fingerprints = ",".join(
                            message_hash[:12] for _category, message_hash in query_errors
                        )
                        error_type = (
                            InventoryNotFoundError
                            if inventory_not_found_only
                            else RuntimeError
                        )
                        raise error_type(
                            "Velociraptor reported a query error "
                            f"(categories={categories}; fingerprints={fingerprints})."
                        )
                except grpc.RpcError as exc:
                    last_error = exc
                    if (
                        is_org_not_found_error(exc)
                        and candidate_org_id != candidates[-1]
                    ):
                        emit_query(
                            "api_org_retry",
                            level="warning",
                            component="velociraptor_api",
                            stage="query",
                            status="retrying",
                            query_name=query_name,
                            query_instance_id=query_instance_id,
                            attempt=candidates.index(candidate_org_id) + 1,
                        )
                        continue
                    raise
                emit_query(
                    "api_query_timing", level="debug",
                    query_instance_id=query_instance_id, query_name=query_name,
                    first_batch_ms=first_batch_ms, consumer_pause_ms=consumer_pause_ms,
                    duration_ms=(time.monotonic() - started) * 1000,
                )
                emit_query(
                    "api_query_completed",
                    component="velociraptor_api",
                    stage="query",
                    status="complete",
                    query_name=query_name,
                    query_instance_id=query_instance_id,
                    query_sha256=query_sha256,
                    batches=batch_count,
                    responses=response_count,
                    rows=row_count,
                    payload_bytes=payload_bytes,
                    server_messages=server_message_count,
                    duration_ms=(time.monotonic() - started) * 1000,
                )
                return
            if last_error is not None:
                raise last_error
            raise RuntimeError(
                "Velociraptor API query failed without returning a response."
            )
        except BaseException as exc:
            code_value = getattr(exc, "code", "")
            code = code_value() if callable(code_value) else code_value
            self._record_exception(
                exc,
                stage="api_query",
                grpc_code=str(getattr(code, "name", code) or ""),
                query_name=query_name,
                query_instance_id=query_instance_id,
                query_sha256=query_sha256,
                batches=batch_count,
                responses=response_count,
                rows=row_count,
                server_messages=server_message_count,
                duration_ms=(time.monotonic() - started) * 1000,
                category=detected_server_error or "runtime_error",
                **query_scope,
            )
            raise
        finally:
            heartbeat.close()

    def query_file(
        self,
        filename: str,
        env: dict[str, str] | None = None,
        *,
        timeout: int = 0,
        max_wait: int = 1,
        max_row: int = 1000,
    ) -> list[dict[str, Any]]:
        vql = (self.reference_dir / filename).read_text(encoding="utf-8")
        return self.query(
            vql,
            env=env,
            timeout=timeout,
            max_wait=max_wait,
            max_row=max_row,
            query_name=filename,
        )
