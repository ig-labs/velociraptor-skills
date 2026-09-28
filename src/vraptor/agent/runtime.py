"""Provider-neutral, bounded API execution for DFIR analyst workers."""

from __future__ import annotations

import asyncio
import inspect
import json
import random
import shutil
import time
import uuid
import weakref
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, TypeVar

from vraptor.agent import diagnostics as agent_diagnostics
from vraptor.common import atomic_io
from vraptor.common import token_budget
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import VALID_AGENT_PROVIDERS


PoolItem = TypeVar("PoolItem")
PoolResult = TypeVar("PoolResult")
ProgressCallback = Callable[["AgentEvent"], None]
PoolStatusCallback = Callable[["AnalysisPoolStatus"], None]
_PROVIDER_GATES: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[tuple[str, str, str], "_ProviderGate"]
] = weakref.WeakKeyDictionary()
RATE_LIMIT_FALLBACK_SECONDS = 60.0


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ProviderCapabilities:
    streaming: bool = True
    structured_output: bool = False
    json_mode: bool = False
    remote_cancellation: bool = False
    background_execution: bool = False
    stored_response_retrieval: bool = False
    tool_calling: bool = False
    usage_reporting: bool = True
    reasoning_configuration: bool = False
    request_output_token_limit: bool = False
    stateless_operation: bool = True

    def supports(self, feature: str) -> bool:
        if not hasattr(self, feature):
            raise ValueError(f"Unknown provider capability: {feature}")
        return bool(getattr(self, feature))


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 2
    initial_backoff_seconds: float = 1.0
    maximum_backoff_seconds: float = 30.0
    jitter_ratio: float = 0.2

    def validate(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be zero or greater")
        if self.initial_backoff_seconds < 0 or self.maximum_backoff_seconds < 0:
            raise ValueError("retry backoff values must be zero or greater")
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError("maximum retry backoff cannot be below initial backoff")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("retry jitter_ratio must be between zero and one")


@dataclass(frozen=True)
class TimeoutPolicy:
    connect_seconds: float = 10.0
    read_seconds: float = 120.0
    total_seconds: float = 600.0
    idle_stream_seconds: float = 120.0

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(frozen=True)
class AgentUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cached_input_tokens: int = 0

    def as_dict(self) -> dict[str, int]:
        payload = asdict(self)
        if not payload["total_tokens"]:
            payload["total_tokens"] = payload["input_tokens"] + payload["output_tokens"]
        return payload


@dataclass(frozen=True)
class AgentError:
    classification: str
    message: str
    retryable: bool = False
    provider_status: int | None = None
    request_id: str = ""
    retry_after_seconds: float | None = None
    retry_after_source: str = ""
    provider_error_code: str = ""
    provider_error_param: str = ""
    usage: AgentUsage = AgentUsage()
    finish_reason: str = ""


@dataclass(frozen=True)
class AgentEvent:
    type: str
    task_id: str
    provider: str
    model: str
    protocol: str
    timestamp: str
    attempt: int
    request_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentRequest:
    task_id: str
    prompt: str
    output_name: str
    metadata: Mapping[str, Any]
    output_schema: str | Mapping[str, Any] = ""
    required_capabilities: frozenset[str] = frozenset({"streaming", "stateless_operation"})
    stream: bool = True
    max_output_tokens: int | None = None


@dataclass(frozen=True)
class ProviderResponse:
    output: str
    request_id: str = ""
    usage: AgentUsage = AgentUsage()
    finish_reason: str = ""
    protocol: str = ""


@dataclass(frozen=True)
class AgentResult:
    task_id: str
    status: str
    output: str
    output_file: str
    events_file: str
    manifest_file: str
    elapsed_seconds: float
    provider: str = ""
    model: str = ""
    protocol: str = ""
    request_id: str = ""
    attempt_count: int = 0
    error: str = ""
    error_classification: str = ""
    usage: Mapping[str, int] | None = None
    finish_reason: str = ""
    provider_status: int | None = None
    provider_error_code: str = ""
    provider_error_param: str = ""
    retryable: bool = False
    retry_after_seconds: float | None = None
    retry_after_source: str = ""
    max_output_tokens_requested: int | None = None
    max_output_tokens_sent: bool = False
    local_output_tokens: int | None = None


@dataclass(frozen=True)
class AgentRuntimeLimits:
    model_context_tokens: int
    operational_context_tokens: int
    maximum_input_tokens: int
    maximum_output_tokens: int
    token_encoding: str

    def validate(self) -> None:
        values = {
            "model_context_tokens": self.model_context_tokens,
            "operational_context_tokens": self.operational_context_tokens,
            "maximum_input_tokens": self.maximum_input_tokens,
            "maximum_output_tokens": self.maximum_output_tokens,
        }
        for name, value in values.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if self.operational_context_tokens > self.model_context_tokens:
            raise ValueError("operational_context_tokens cannot exceed model_context_tokens")
        if self.maximum_input_tokens + self.maximum_output_tokens > self.operational_context_tokens:
            raise ValueError("input and output ceilings cannot exceed the operational context")
        if not self.token_encoding.strip():
            raise ValueError("token_encoding cannot be empty")


OUTPUT_LIMIT_ERROR_CLASSIFICATIONS = frozenset(
    {"output_limit_reached", "output_too_large"}
)


def is_output_limit_failure(value: AgentResult | AgentError | str) -> bool:
    """Return whether one normalized failure is a deterministic output limit."""
    classification = (
        value
        if isinstance(value, str)
        else str(getattr(value, "error_classification", "") or "")
        or str(getattr(value, "classification", "") or "")
    )
    return classification in OUTPUT_LIMIT_ERROR_CLASSIFICATIONS


def effective_output_token_limit(
    request: AgentRequest,
    limits: AgentRuntimeLimits | None,
) -> int | None:
    """Resolve one local ceiling; requests may tighten but never widen limits."""
    request_limit = request.max_output_tokens
    if request_limit is not None and request_limit <= 0:
        raise ValueError("max_output_tokens must be greater than zero")
    runtime_limit = limits.maximum_output_tokens if limits is not None else None
    candidates = [
        value for value in (request_limit, runtime_limit) if value is not None
    ]
    return min(candidates) if candidates else None


@dataclass(frozen=True)
class AnalysisPoolStatus:
    """Bounded, value-free status for the shared analysis scheduler."""

    submitted: int = 0
    queued: int = 0
    active: int = 0
    completed: int = 0
    failed: int = 0
    abandoned: int = 0
    source_exhausted: bool = False
    stop_requested: bool = False


class CancellationToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise AgentCancelled("agent request was cancelled")


class AgentProviderException(RuntimeError):
    def __init__(self, error: AgentError):
        super().__init__(error.message)
        self.error = error


class AgentCancelled(RuntimeError):
    pass


class AgentOperationTimeout(TimeoutError):
    pass


async def _await_with_deadline(
    awaitable: Any,
    *,
    cancellation: CancellationToken,
    deadline: float,
) -> Any:
    """Await one operation while enforcing cancellation and a shared deadline."""

    operation = asyncio.ensure_future(awaitable)
    cancellation_wait = asyncio.create_task(cancellation.wait())
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            operation.cancel()
            try:
                await operation
            except asyncio.CancelledError:
                pass
            raise AgentOperationTimeout("agent operation exceeded total timeout")
        done, _pending = await asyncio.wait(
            {operation, cancellation_wait},
            timeout=remaining,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if operation in done:
            return await operation
        operation.cancel()
        try:
            await operation
        except asyncio.CancelledError:
            pass
        if cancellation_wait in done:
            raise AgentCancelled("agent request was cancelled")
        raise AgentOperationTimeout("agent operation exceeded total timeout")
    except asyncio.CancelledError:
        operation.cancel()
        try:
            await operation
        except asyncio.CancelledError:
            pass
        raise
    finally:
        cancellation_wait.cancel()
        try:
            await cancellation_wait
        except asyncio.CancelledError:
            pass


class _ProviderGate:
    def __init__(self, limit: int):
        self.limit = limit
        self.active = 0
        self.cooldown_until = 0.0
        self.condition = asyncio.Condition()

    async def tighten(self, limit: int) -> None:
        async with self.condition:
            self.limit = min(self.limit, limit)
            self.condition.notify_all()

    async def acquire(self, cancellation: CancellationToken) -> None:
        async with self.condition:
            while True:
                cancellation.raise_if_cancelled()
                cooldown_remaining = self.cooldown_until - time.monotonic()
                if self.active < self.limit and cooldown_remaining <= 0:
                    self.active += 1
                    return
                try:
                    await asyncio.wait_for(
                        self.condition.wait(),
                        timeout=max(0.001, min(0.1, cooldown_remaining))
                        if cooldown_remaining > 0
                        else 0.1,
                    )
                except TimeoutError:
                    pass

    async def defer(self, delay_seconds: float) -> None:
        if delay_seconds <= 0:
            return
        async with self.condition:
            self.cooldown_until = max(
                self.cooldown_until,
                time.monotonic() + delay_seconds,
            )
            self.condition.notify_all()

    async def release(self) -> None:
        async with self.condition:
            self.active -= 1
            self.condition.notify()


async def _provider_gate(configuration: ResolvedAgentExecution) -> _ProviderGate | None:
    provider_concurrency = configuration.route.max_concurrency
    if provider_concurrency is None:
        return None
    loop = asyncio.get_running_loop()
    gates = _PROVIDER_GATES.setdefault(loop, {})
    key = (
        configuration.provider,
        configuration.protocol,
        configuration.base_url,
    )
    gate = gates.get(key)
    if gate is None:
        gate = _ProviderGate(provider_concurrency)
        gates[key] = gate
    else:
        await gate.tighten(provider_concurrency)
    return gate


class ProviderAdapter(Protocol):
    configuration: ResolvedAgentExecution

    def capabilities(self) -> ProviderCapabilities: ...

    async def close(self) -> None: ...

    async def execute(
        self,
        request: AgentRequest,
        *,
        progress_callback: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        attempt: int = 1,
    ) -> ProviderResponse: ...


class AgentRunner(Protocol):
    async def run(
        self,
        request: AgentRequest,
        *,
        workdir: Path,
        output_dir: Path,
        progress_callback: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        replace_existing: bool = False,
    ) -> AgentResult: ...

    def capabilities(self) -> ProviderCapabilities: ...

    async def close(self) -> None: ...


def validate_spec(spec: ResolvedAgentExecution) -> None:
    if not spec.enabled:
        raise RuntimeError("Analyst API execution is disabled.")
    if spec.provider not in VALID_AGENT_PROVIDERS:
        raise RuntimeError(f"Unsupported analyst provider: {spec.provider}")
    if not spec.model.strip():
        raise RuntimeError("Analyst model cannot be empty.")
    if spec.timeout_seconds <= 0:
        raise RuntimeError("Analyst timeout must be greater than zero.")
    if spec.max_retries < 0:
        raise RuntimeError("Analyst max retries must be zero or greater.")
    if spec.max_concurrency <= 0:
        raise RuntimeError("Analyst concurrency must be greater than zero.")


def _schema_payload(
    schema: str | Mapping[str, Any], *, workdir: Path
) -> Mapping[str, Any] | None:
    if not schema:
        return None
    if isinstance(schema, Mapping):
        return dict(schema)
    path = Path(schema).expanduser()
    if not path.is_absolute():
        path = workdir / path
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError(f"Agent output schema does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Agent output schema must be a JSON object")
    return payload


def validate_structured_output(output: str, schema: Mapping[str, Any]) -> None:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Agent returned invalid JSON: {exc.msg}") from exc
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required to validate structured analyst output"
        ) from exc
    try:
        jsonschema.validate(payload, schema)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "root"
        raise RuntimeError(f"Agent output failed JSON schema validation at {location}") from exc


def sanitize_error(message: object, secrets: Iterable[str]) -> str:
    sanitized = str(message or "")
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized[:2000]


def _path_exists(path: Path) -> bool:
    """Return true for regular paths and dangling symbolic links."""

    return path.exists() or path.is_symlink()


def _validate_existing_bundle(paths: Iterable[Path]) -> tuple[Path, ...]:
    existing: list[Path] = []
    for path in paths:
        if not _path_exists(path):
            continue
        if path.is_symlink():
            raise RuntimeError(
                f"Agent output bundle cannot contain symbolic links: {path}"
            )
        if not path.is_file():
            raise RuntimeError(f"Agent output bundle path is not a file: {path}")
        existing.append(path)
    return tuple(existing)


def _previous_analysis_path(output_dir: Path) -> Path:
    previous_root = output_dir / "previous-analysis"
    if _path_exists(previous_root):
        if previous_root.is_symlink() or not previous_root.is_dir():
            raise RuntimeError(
                f"Previous analysis path must be a real directory: {previous_root}"
            )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    while True:
        candidate = previous_root / f"{timestamp}-{uuid.uuid4().hex[:12]}"
        if not _path_exists(candidate):
            return candidate


def _move_path(source: Path, destination: Path) -> None:
    """Move one file on the same filesystem; isolated for rollback testing."""

    source.replace(destination)


def _publish_replacement(
    *,
    staged_paths: tuple[Path, ...],
    canonical_paths: tuple[Path, ...],
    archive_dir: Path,
) -> None:
    """Archive the current bundle and promote a validated replacement."""

    archive_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive_dir.mkdir(mode=0o700)
    archived: list[tuple[Path, Path]] = []
    promoted: list[Path] = []
    try:
        for canonical in canonical_paths:
            if not _path_exists(canonical):
                continue
            archived_path = archive_dir / canonical.name
            _move_path(canonical, archived_path)
            archived.append((archived_path, canonical))
        for staged, canonical in zip(staged_paths, canonical_paths, strict=True):
            _move_path(staged, canonical)
            promoted.append(canonical)
    except Exception as exc:
        rollback_errors: list[str] = []
        for canonical in reversed(promoted):
            try:
                canonical.unlink(missing_ok=True)
            except OSError as rollback_exc:
                rollback_errors.append(f"remove {canonical}: {rollback_exc}")
        for archived_path, canonical in reversed(archived):
            try:
                _move_path(archived_path, canonical)
            except OSError as rollback_exc:
                rollback_errors.append(
                    f"restore {canonical} from {archived_path}: {rollback_exc}"
                )
        if not rollback_errors:
            try:
                archive_dir.rmdir()
            except OSError:
                pass
            raise RuntimeError(
                "Could not publish replacement analysis; previous analysis was restored."
            ) from exc
        raise RuntimeError(
            "Could not publish replacement analysis and rollback was incomplete: "
            + "; ".join(rollback_errors)
        ) from exc


class ApiAgentRunner:
    """Execute independent, stateless requests through one provider adapter."""

    def __init__(
        self,
        adapter: ProviderAdapter,
        *,
        limits: AgentRuntimeLimits | None = None,
        retry_policy: RetryPolicy | None = None,
        timeout_policy: TimeoutPolicy | None = None,
        persist_runtime_files: bool = True,
        sleeper: Callable[[float], Any] = asyncio.sleep,
        random_source: Callable[[], float] = random.random,
    ):
        if limits is not None:
            limits.validate()
        self.adapter = adapter
        self.limits = limits
        self.retry_policy = retry_policy or RetryPolicy()
        self.retry_policy.validate()
        self.timeout_policy = timeout_policy or TimeoutPolicy()
        self.timeout_policy.validate()
        self.persist_runtime_files = persist_runtime_files
        self._sleep = sleeper
        self._random = random_source

    def capabilities(self) -> ProviderCapabilities:
        return self.adapter.capabilities()

    async def close(self) -> None:
        """Close the adapter's shared async client, when it owns one."""
        close = getattr(self.adapter, "close", None)
        if close is None:
            return
        result = close()
        if inspect.isawaitable(result):
            await result

    async def __aenter__(self) -> "ApiAgentRunner":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    def _preflight(self, request: AgentRequest) -> None:
        capabilities = self.capabilities()
        required = set(request.required_capabilities)
        if self.adapter.configuration.reasoning_effort:
            required.add("reasoning_configuration")
        missing = sorted(
            feature
            for feature in required
            if not capabilities.supports(feature)
        )
        if missing:
            raise AgentProviderException(
                AgentError(
                    classification="unsupported_capability",
                    message="Provider does not support required capabilities: "
                    + ", ".join(missing),
                )
            )
        if request.output_schema and not (
            capabilities.structured_output or capabilities.json_mode
        ):
            raise AgentProviderException(
                AgentError(
                    classification="unsupported_capability",
                    message="Provider does not support structured or JSON output",
                )
            )

    def _backoff(
        self,
        retry_index: int,
        retry_after: float | None,
        *,
        classification: str,
        retry_after_source: str = "",
    ) -> tuple[float, str]:
        if retry_after is not None:
            return max(0.0, retry_after), retry_after_source or "provider"
        if classification == "rate_limit":
            jitter = (
                RATE_LIMIT_FALLBACK_SECONDS
                * self.retry_policy.jitter_ratio
                * self._random()
            )
            return RATE_LIMIT_FALLBACK_SECONDS + jitter, "minute_limit_fallback"
        base = min(
            self.retry_policy.initial_backoff_seconds * (2 ** max(0, retry_index - 1)),
            self.retry_policy.maximum_backoff_seconds,
        )
        jitter = base * self.retry_policy.jitter_ratio * self._random()
        return (
            min(base + jitter, self.retry_policy.maximum_backoff_seconds),
            "exponential_backoff",
        )

    async def run(
        self,
        request: AgentRequest,
        *,
        workdir: Path,
        output_dir: Path,
        progress_callback: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        replace_existing: bool = False,
    ) -> AgentResult:
        workdir = workdir.resolve()
        output_dir = output_dir.resolve()
        try:
            output_dir.relative_to(workdir)
        except ValueError as exc:
            raise RuntimeError(
                f"Agent output directory must remain below {workdir}: {output_dir}"
            ) from exc
        output_dir.mkdir(parents=True, exist_ok=True)
        requested_output_path = output_dir / request.output_name
        if requested_output_path.is_symlink():
            raise RuntimeError(
                f"Agent output bundle cannot contain symbolic links: {requested_output_path}"
            )
        output_path = requested_output_path.resolve()
        try:
            output_path.relative_to(output_dir)
        except ValueError as exc:
            raise RuntimeError(f"Agent output must remain below {output_dir}: {output_path}") from exc
        if output_path == output_dir or output_path.is_dir():
            raise RuntimeError(f"Invalid agent output path: {output_path}")
        events_path = output_path.with_suffix(output_path.suffix + ".events.jsonl")
        manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
        canonical_paths = (output_path, events_path, manifest_path)
        existing_bundle = (
            _validate_existing_bundle(canonical_paths)
            if self.persist_runtime_files
            else ()
        )
        if existing_bundle and not replace_existing:
            existing_text = ", ".join(str(path) for path in existing_bundle)
            raise RuntimeError(
                "Agent output already exists. Use replace_existing=True to replace it "
                "after a successful run (standalone CLI: --replace): "
                f"{existing_text}"
            )

        schema = _schema_payload(request.output_schema, workdir=workdir)
        input_tokens = token_budget.estimate_tokens(
            request.prompt,
            self.limits.token_encoding if self.limits else None,
        )
        if self.limits and input_tokens > self.limits.maximum_input_tokens:
            raise RuntimeError(
                "Agent prompt exceeds maximum input tokens "
                f"({input_tokens} > {self.limits.maximum_input_tokens})."
            )
        token = cancellation or CancellationToken()
        config = self.adapter.configuration
        capabilities = self.capabilities()
        output_token_limit = effective_output_token_limit(request, self.limits)
        output_token_limit_sent = bool(
            output_token_limit is not None
            and capabilities.request_output_token_limit
        )
        diagnostics = agent_diagnostics.current_session()
        if diagnostics is not None:
            diagnostics.record_request(
                request,
                configuration=config.public_dict(),
                limits=asdict(self.limits) if self.limits else None,
                retry_policy=asdict(self.retry_policy),
                timeout_policy=asdict(self.timeout_policy),
                input_tokens_estimated=input_tokens,
                max_output_tokens_requested=output_token_limit,
                max_output_tokens_sent=output_token_limit_sent,
            )
        self._preflight(request)
        gate = await _provider_gate(config)
        secret_values = [
            config.inputs.api_key,
            *config.inputs.default_headers.values(),
            config.inputs.azure_client_secret.get("client_secret", ""),
        ]
        events: list[AgentEvent] = []
        last_progress = 0.0

        def emit(event_type: str, attempt: int, **metadata: Any) -> None:
            nonlocal last_progress
            request_id = str(metadata.pop("request_id", ""))
            event = AgentEvent(
                type=event_type,
                task_id=request.task_id,
                provider=config.provider,
                model=config.model,
                protocol=config.protocol,
                timestamp=now_utc(),
                attempt=attempt,
                request_id=request_id,
                metadata=metadata,
            )
            events.append(event)
            if diagnostics is not None:
                diagnostics.record_event(event)
            if progress_callback is None:
                return
            now = time.monotonic()
            if event_type == "output_progress" and now - last_progress < 0.25:
                return
            last_progress = now
            progress_callback(event)

        started_at = now_utc()
        started = time.monotonic()
        deadline = started + self.timeout_policy.total_seconds
        final_response: ProviderResponse | None = None
        final_error: AgentError | None = None
        last_usage = AgentUsage()
        last_finish_reason = ""
        last_local_output_tokens: int | None = None
        status = "failed"
        attempt_count = 0
        for attempt in range(1, self.retry_policy.max_retries + 2):
            attempt_count = attempt
            last_usage = AgentUsage()
            last_finish_reason = ""
            last_local_output_tokens = None
            attempt_retry_delay: float | None = None
            attempt_retry_delay_source = ""
            try:
                token.raise_if_cancelled()
                emit(
                    "request_started",
                    attempt,
                    max_output_tokens_requested=output_token_limit,
                    max_output_tokens_sent=output_token_limit_sent,
                )
                provider_request = replace(
                    request,
                    output_schema=schema,
                    max_output_tokens=(
                        output_token_limit if output_token_limit_sent else None
                    ),
                )
                if gate is not None:
                    await _await_with_deadline(
                        gate.acquire(token),
                        cancellation=token,
                        deadline=deadline,
                    )
                try:
                    try:
                        response = await _await_with_deadline(
                            self.adapter.execute(
                                provider_request,
                                progress_callback=lambda event: emit(
                                    event.type,
                                    attempt,
                                    request_id=event.request_id,
                                    **dict(event.metadata),
                                ),
                                cancellation=token,
                                attempt=attempt,
                            ),
                            cancellation=token,
                            deadline=deadline,
                        )
                    except AgentProviderException as exc:
                        if (
                            gate is not None
                            and exc.error.classification == "rate_limit"
                        ):
                            (
                                attempt_retry_delay,
                                attempt_retry_delay_source,
                            ) = self._backoff(
                                attempt,
                                exc.error.retry_after_seconds,
                                classification=exc.error.classification,
                                retry_after_source=exc.error.retry_after_source,
                            )
                            await gate.defer(attempt_retry_delay)
                        raise
                finally:
                    if gate is not None:
                        await gate.release()
                token.raise_if_cancelled()
                output = response.output.strip()
                last_usage = response.usage
                last_finish_reason = response.finish_reason
                if not output:
                    raise AgentProviderException(
                        AgentError(
                            classification="malformed_response",
                            message="Provider completed without final output",
                            request_id=response.request_id,
                            usage=response.usage,
                            finish_reason=response.finish_reason,
                        )
                    )
                output_tokens = token_budget.estimate_tokens(
                    output,
                    self.limits.token_encoding if self.limits else None,
                )
                last_local_output_tokens = output_tokens
                if (
                    output_token_limit is not None
                    and output_tokens > output_token_limit
                ):
                    raise AgentProviderException(
                        AgentError(
                            classification="output_too_large",
                            message=(
                                "Agent output exceeds maximum output tokens "
                                f"({output_tokens} > {output_token_limit})"
                            ),
                            request_id=response.request_id,
                            usage=response.usage,
                            finish_reason=response.finish_reason,
                        )
                    )
                if schema is not None:
                    validate_structured_output(output, schema)
                if time.monotonic() >= deadline:
                    raise AgentOperationTimeout(
                        "agent operation exceeded total timeout"
                    )
                final_response = ProviderResponse(
                    output=output,
                    request_id=response.request_id,
                    usage=response.usage,
                    finish_reason=response.finish_reason,
                    protocol=response.protocol or config.protocol,
                )
                status = "succeeded"
                emit(
                    "request_completed",
                    attempt,
                    request_id=response.request_id,
                    finish_reason=response.finish_reason,
                    local_output_tokens=output_tokens,
                    max_output_tokens_requested=output_token_limit,
                    max_output_tokens_sent=output_token_limit_sent,
                    **response.usage.as_dict(),
                )
                break
            except AgentCancelled as exc:
                final_error = AgentError("cancelled", str(exc), retryable=False)
                status = "cancelled"
                emit("request_cancelled", attempt)
                break
            except AgentOperationTimeout as exc:
                final_error = AgentError("timeout", str(exc), retryable=False)
                status = "timeout"
            except TimeoutError as exc:
                final_error = AgentError("timeout", str(exc), retryable=True)
                status = "timeout"
            except AgentProviderException as exc:
                final_error = exc.error
                last_usage = final_error.usage
                last_finish_reason = final_error.finish_reason
                status = "timeout" if final_error.classification == "timeout" else "failed"
            except RuntimeError as exc:
                final_error = AgentError("invalid_response", str(exc), retryable=False)
                status = "failed"
            if final_error is None:
                break
            can_retry = (
                final_error.retryable
                and attempt <= self.retry_policy.max_retries
                and not token.cancelled
            )
            if not can_retry:
                terminal_event = "request_timed_out" if final_error.classification == "timeout" else "request_failed"
                emit(
                    terminal_event,
                    attempt,
                    request_id=final_error.request_id,
                    error_classification=final_error.classification,
                    provider_status=final_error.provider_status,
                    provider_error_code=final_error.provider_error_code,
                    provider_error_param=final_error.provider_error_param,
                    retryable=final_error.retryable,
                    retry_after_seconds=final_error.retry_after_seconds,
                    retry_after_source=final_error.retry_after_source,
                    finish_reason=last_finish_reason,
                    local_output_tokens=last_local_output_tokens,
                    max_output_tokens_requested=output_token_limit,
                    max_output_tokens_sent=output_token_limit_sent,
                    **last_usage.as_dict(),
                )
                break
            if attempt_retry_delay is None:
                delay, delay_source = self._backoff(
                    attempt,
                    final_error.retry_after_seconds,
                    classification=final_error.classification,
                    retry_after_source=final_error.retry_after_source,
                )
            else:
                delay = attempt_retry_delay
                delay_source = attempt_retry_delay_source
            emit(
                "retry_scheduled",
                attempt,
                request_id=final_error.request_id,
                delay_seconds=delay,
                delay_source=delay_source,
                error_classification=final_error.classification,
                provider_status=final_error.provider_status,
                provider_error_code=final_error.provider_error_code,
                provider_error_param=final_error.provider_error_param,
                retryable=final_error.retryable,
                retry_after_seconds=final_error.retry_after_seconds,
                retry_after_source=final_error.retry_after_source,
                finish_reason=last_finish_reason,
                local_output_tokens=last_local_output_tokens,
                max_output_tokens_requested=output_token_limit,
                max_output_tokens_sent=output_token_limit_sent,
                **last_usage.as_dict(),
            )
            sleep_result = self._sleep(delay)
            if inspect.isawaitable(sleep_result):
                try:
                    await _await_with_deadline(
                        sleep_result,
                        cancellation=token,
                        deadline=deadline,
                    )
                except AgentCancelled as exc:
                    final_error = AgentError("cancelled", str(exc), retryable=False)
                    status = "cancelled"
                    emit("request_cancelled", attempt)
                    break
                except AgentOperationTimeout as exc:
                    final_error = AgentError("timeout", str(exc), retryable=False)
                    status = "timeout"
                    emit(
                        "request_timed_out",
                        attempt,
                        error_classification="timeout",
                        retryable=False,
                    )
                    break

        elapsed = round(time.monotonic() - started, 6)
        event_text = "".join(
            json.dumps(asdict(event), sort_keys=True) + "\n" for event in events
        )
        error_message = sanitize_error(
            final_error.message if final_error else "",
            secret_values,
        )
        replacement_archive = (
            _previous_analysis_path(output_dir)
            if self.persist_runtime_files and final_response and existing_bundle
            else None
        )
        persist_result_files = self.persist_runtime_files and (
            final_response is not None or not existing_bundle
        )
        manifest = {
            "schema_version": 3,
            "task_id": request.task_id,
            "status": status,
            "started_at": started_at,
            "completed_at": now_utc(),
            "elapsed_seconds": elapsed,
            "attempt_count": attempt_count,
            "error": error_message,
            "error_classification": final_error.classification if final_error else "",
            "provider_status": final_error.provider_status if final_error else None,
            "provider_error_code": final_error.provider_error_code if final_error else "",
            "provider_error_param": final_error.provider_error_param if final_error else "",
            "retryable": bool(final_error.retryable) if final_error else False,
            "retry_after_seconds": final_error.retry_after_seconds if final_error else None,
            "retry_after_source": final_error.retry_after_source if final_error else "",
            "input_tokens_estimated": input_tokens,
            "usage": (
                final_response.usage.as_dict()
                if final_response
                else last_usage.as_dict()
            ),
            "finish_reason": (
                final_response.finish_reason
                if final_response
                else last_finish_reason
            ),
            "local_output_tokens": last_local_output_tokens,
            "provider": config.public_dict(),
            "limits": asdict(self.limits) if self.limits else None,
            "retry_policy": asdict(self.retry_policy),
            "timeout_policy": asdict(self.timeout_policy),
            "request_options": {
                "output_schema_present": schema is not None,
                "max_output_tokens_requested": output_token_limit,
                "max_output_tokens_sent": output_token_limit_sent,
                "replace_existing": replace_existing,
            },
            "metadata": dict(request.metadata),
            "output_file": (
                str(output_path) if persist_result_files and final_response else ""
            ),
            "events_file": str(events_path) if persist_result_files else "",
            "previous_analysis_directory": str(replacement_archive or ""),
            "request_id": final_response.request_id if final_response else (final_error.request_id if final_error else ""),
            "protocol": final_response.protocol if final_response else config.protocol,
            "prompt_persisted": False,
            "reasoning_trace_persisted": False,
        }
        if persist_result_files:
            if final_response is not None and replacement_archive is not None:
                staging_dir = atomic_io.create_work_directory(
                    output_dir,
                    prefix="agent-replacement",
                )
                staged_paths = tuple(
                    staging_dir / path.name for path in canonical_paths
                )
                try:
                    await asyncio.to_thread(
                        atomic_io.write_text_atomic,
                        staged_paths[0],
                        final_response.output,
                    )
                    await asyncio.to_thread(
                        atomic_io.write_text_atomic,
                        staged_paths[1],
                        event_text,
                    )
                    await asyncio.to_thread(
                        atomic_io.write_json_atomic,
                        staged_paths[2],
                        manifest,
                        sort_keys=True,
                    )
                    await asyncio.to_thread(
                        _publish_replacement,
                        staged_paths=staged_paths,
                        canonical_paths=canonical_paths,
                        archive_dir=replacement_archive,
                    )
                finally:
                    await asyncio.to_thread(shutil.rmtree, staging_dir, True)
            else:
                if final_response is not None:
                    await asyncio.to_thread(
                        atomic_io.write_text_atomic,
                        output_path,
                        final_response.output,
                    )
                await asyncio.to_thread(
                    atomic_io.write_text_atomic,
                    events_path,
                    event_text,
                )
                await asyncio.to_thread(
                    atomic_io.write_json_atomic,
                    manifest_path,
                    manifest,
                    sort_keys=True,
                )
        result = AgentResult(
            task_id=request.task_id,
            status=status,
            output=final_response.output if final_response else "",
            output_file=(
                str(output_path) if persist_result_files and final_response else ""
            ),
            events_file=str(events_path) if persist_result_files else "",
            manifest_file=str(manifest_path) if persist_result_files else "",
            elapsed_seconds=elapsed,
            provider=config.provider,
            model=config.model,
            protocol=final_response.protocol if final_response else config.protocol,
            request_id=final_response.request_id if final_response else (final_error.request_id if final_error else ""),
            attempt_count=attempt_count,
            error=error_message,
            error_classification=final_error.classification if final_error else "",
            usage=(
                final_response.usage.as_dict()
                if final_response
                else last_usage.as_dict()
            ),
            finish_reason=(
                final_response.finish_reason
                if final_response
                else last_finish_reason
            ),
            provider_status=final_error.provider_status if final_error else None,
            provider_error_code=final_error.provider_error_code if final_error else "",
            provider_error_param=final_error.provider_error_param if final_error else "",
            retryable=bool(final_error.retryable) if final_error else False,
            retry_after_seconds=final_error.retry_after_seconds if final_error else None,
            retry_after_source=final_error.retry_after_source if final_error else "",
            max_output_tokens_requested=output_token_limit,
            max_output_tokens_sent=output_token_limit_sent,
            local_output_tokens=last_local_output_tokens,
        )
        if diagnostics is not None:
            diagnostics.record_result(result)
        return result


async def run_item_pool(
    items: Iterable[PoolItem],
    *,
    max_concurrency: int,
    execute: Callable[[PoolItem], Any],
    on_status_change: PoolStatusCallback | None = None,
    stop_when: Callable[[PoolResult], bool] | None = None,
    on_result: Callable[[PoolItem, PoolResult], Any] | None = None,
    retain_results: bool = True,
) -> list[tuple[PoolItem, PoolResult]]:
    """Run arbitrary transient items through one bounded async queue lane."""

    from vraptor.analyze.scheduler import AnalysisLane
    from vraptor.analyze.scheduler import AsyncAnalysisScheduler
    from vraptor.analyze.scheduler import SchedulerStatus

    async def execute_item(item: PoolItem) -> PoolResult:
        value = execute(item)
        return await value if inspect.isawaitable(value) else value

    def status_changed(status: SchedulerStatus) -> None:
        if on_status_change is None:
            return
        on_status_change(
            AnalysisPoolStatus(
                submitted=status.produced,
                queued=status.queued,
                active=status.active,
                completed=status.completed,
                failed=status.failed,
                abandoned=status.abandoned,
                source_exhausted=status.source_exhausted,
                stop_requested=status.stop_requested,
            )
        )

    scheduler = AsyncAnalysisScheduler[PoolItem, PoolResult](
        max_concurrency=max_concurrency,
        on_status_change=status_changed if on_status_change is not None else None,
    )

    async def result_ready(scheduled: Any) -> None:
        if on_result is None:
            return
        value = on_result(scheduled.item, scheduled.result)
        if inspect.isawaitable(value):
            await value

    scheduled = await scheduler.run(
        [AnalysisLane("items", items)],
        execute=execute_item,
        stop_when=stop_when,
        on_result=result_ready if on_result is not None else None,
        retain_results=retain_results,
    )
    return [(result.item, result.result) for result in scheduled]
