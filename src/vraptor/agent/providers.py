"""Native SDK adapters for provider-neutral analyst execution."""

from __future__ import annotations

import asyncio
import inspect
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Mapping

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.codex_app_server import CODEX_PROHIBITED_ITEM_TYPES
from vraptor.agent.codex_app_server import CodexAppServerClient
from vraptor.agent.codex_app_server import CodexAppServerError
from vraptor.agent.codex_app_server import acquire_shared_codex_client
from vraptor.agent.codex_app_server import invalidate_shared_codex_client
from vraptor.agent.codex_app_server import release_shared_codex_client
from vraptor.agent.runtime import AgentCancelled
from vraptor.agent.runtime import AgentError
from vraptor.agent.runtime import AgentEvent
from vraptor.agent.runtime import AgentProviderException
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentUsage
from vraptor.agent.runtime import CancellationToken
from vraptor.agent.runtime import ProgressCallback
from vraptor.agent.runtime import ProviderCapabilities
from vraptor.agent.runtime import ProviderResponse
from vraptor.agent.runtime import TimeoutPolicy
from vraptor.agent.runtime import now_utc


def _get(value: object, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _integer(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) else 0


def _usage(value: object) -> AgentUsage:
    if value is None:
        return AgentUsage()
    input_tokens = _integer(
        _get(value, "input_tokens", _get(value, "prompt_tokens", 0))
    )
    output_tokens = _integer(
        _get(value, "output_tokens", _get(value, "completion_tokens", 0))
    )
    total_tokens = _integer(_get(value, "total_tokens", 0))
    details = _get(value, "input_tokens_details", {})
    cached = _integer(_get(details, "cached_tokens", 0))
    # Anthropic reports uncached input separately from cache reads/writes.
    cache_read = _integer(_get(value, "cache_read_input_tokens", 0))
    cache_creation = _integer(_get(value, "cache_creation_input_tokens", 0))
    input_tokens += cache_read + cache_creation
    cached += cache_read
    return AgentUsage(input_tokens, output_tokens, total_tokens, cached)


def _response_text(response: object) -> str:
    direct = _get(response, "output_text", "")
    if isinstance(direct, str) and direct:
        return direct
    parts: list[str] = []
    for item in _get(response, "output", []) or []:
        item_type = str(_get(item, "type", ""))
        if item_type and item_type != "message":
            continue
        for content in _get(item, "content", []) or []:
            content_type = str(_get(content, "type", ""))
            if content_type and content_type not in {"output_text", "text"}:
                continue
            text = _get(content, "text", "")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _header(error: BaseException, name: str) -> str:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        return ""
    try:
        return str(headers.get(name) or headers.get(name.lower()) or "")
    except AttributeError:
        return ""


def _normalized_exception(error: BaseException, provider: str) -> AgentProviderException:
    name = error.__class__.__name__.lower()
    status = getattr(error, "status_code", None)
    if not isinstance(status, int):
        status = getattr(getattr(error, "response", None), "status_code", None)
    request_id = str(
        getattr(error, "request_id", "")
        or _header(error, "x-request-id")
        or _header(error, "request-id")
    )
    retry_after: float | None = None
    retry_after_source = ""
    raw_retry_after_ms = _header(error, "retry-after-ms")
    raw_retry_after = _header(error, "retry-after")
    if raw_retry_after_ms:
        try:
            retry_after = max(0.0, float(raw_retry_after_ms) / 1000.0)
            retry_after_source = "retry-after-ms"
        except ValueError:
            retry_after = None
    if retry_after is None and raw_retry_after:
        try:
            retry_after = max(0.0, float(raw_retry_after))
            retry_after_source = "retry-after"
        except ValueError:
            retry_after = None
    body = getattr(error, "body", None)
    error_detail = _get(body, "error", body)
    provider_error_code = str(
        _get(error_detail, "code", getattr(error, "code", "")) or ""
    )
    provider_error_param = str(
        _get(error_detail, "param", getattr(error, "param", "")) or ""
    )
    normalized_provider_error_code = provider_error_code.strip().casefold()
    if status in {401, 403} or "authentication" in name or "permission" in name:
        classification, retryable = "authentication", False
    elif (
        status == 429
        or "ratelimit" in name
        or "rate_limit" in name
        or normalized_provider_error_code == "rate_limit_exceeded"
    ):
        classification, retryable = "rate_limit", True
    elif status is not None and status >= 500:
        classification, retryable = "provider_overload" if status == 529 else "server_error", True
    elif "timeout" in name:
        classification, retryable = "timeout", True
    elif "connection" in name:
        classification, retryable = "connection", True
    elif status is not None and 400 <= status < 500:
        classification, retryable = "invalid_request", False
    else:
        classification, retryable = "provider_error", False
    message = f"{provider} {classification}"
    if status is not None:
        message += f" (HTTP {status})"
    return AgentProviderException(
        AgentError(
            classification=classification,
            message=message,
            retryable=retryable,
            provider_status=status,
            request_id=request_id,
            retry_after_seconds=retry_after,
            retry_after_source=retry_after_source,
            provider_error_code=provider_error_code,
            provider_error_param=provider_error_param,
        )
    )


def _response_terminal_exception(
    response: object,
    provider: str,
) -> AgentProviderException | None:
    """Return a safe provider error for a non-completed Responses result."""
    status = str(_get(response, "status", "") or "").strip().casefold()
    if not status or status == "completed":
        return None
    request_id = str(_get(response, "_request_id", "") or _get(response, "id", ""))
    error = _get(response, "error")
    error_code = str(_get(error, "code", "") or "")
    incomplete = _get(response, "incomplete_details")
    incomplete_reason = str(_get(incomplete, "reason", "") or "")
    provider_error_code = error_code or incomplete_reason
    usage = _usage(_get(response, "usage"))
    finish_reason = incomplete_reason if incomplete_reason else status
    if status == "failed" and error_code == "rate_limit_exceeded":
        classification, retryable = "rate_limit", True
    elif status == "failed" and error_code in {"server_error", "vector_store_timeout"}:
        classification, retryable = "server_error", True
    elif status == "failed" and error_code:
        classification, retryable = "invalid_request", False
    elif status == "incomplete" and incomplete_reason == "max_output_tokens":
        classification, retryable = "output_limit_reached", False
    elif status == "incomplete":
        classification, retryable = "incomplete_response", False
    else:
        classification, retryable = "provider_error", False
    return AgentProviderException(
        AgentError(
            classification=classification,
            message=f"{provider} {classification}",
            retryable=retryable,
            request_id=request_id,
            provider_error_code=provider_error_code,
            usage=usage,
            finish_reason=finish_reason,
        )
    )


def _schema(request: AgentRequest) -> Mapping[str, Any] | None:
    return request.output_schema if isinstance(request.output_schema, Mapping) else None


@dataclass
class _BaseAdapter:
    configuration: ResolvedAgentExecution
    timeout_policy: TimeoutPolicy
    client: Any = None
    credential: Any = None

    async def close(self) -> None:
        try:
            if self.client is not None:
                close = getattr(self.client, "close", None)
                if callable(close):
                    result = close()
                    if inspect.isawaitable(result):
                        await result
                self.client = None
        finally:
            if self.credential is not None:
                close = getattr(self.credential, "close", None)
                if callable(close):
                    result = close()
                    if inspect.isawaitable(result):
                        await result
                self.credential = None

    def _event(
        self,
        request: AgentRequest,
        event_type: str,
        attempt: int,
        *,
        request_id: str = "",
        **metadata: Any,
    ) -> AgentEvent:
        return AgentEvent(
            type=event_type,
            task_id=request.task_id,
            provider=self.configuration.provider,
            model=self.configuration.model,
            protocol=self.configuration.protocol,
            timestamp=now_utc(),
            attempt=attempt,
            request_id=request_id,
            metadata=metadata,
        )

    def _emit(
        self,
        callback: ProgressCallback | None,
        request: AgentRequest,
        event_type: str,
        attempt: int,
        *,
        request_id: str = "",
        **metadata: Any,
    ) -> None:
        if callback is not None:
            callback(
                self._event(
                    request,
                    event_type,
                    attempt,
                    request_id=request_id,
                    **metadata,
                )
            )


class OpenAIResponsesAdapter(_BaseAdapter):
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            structured_output=True,
            json_mode=True,
            tool_calling=True,
            reasoning_configuration=True,
            request_output_token_limit=True,
        )

    def _build_client(self) -> Any:
        try:
            from openai import AsyncOpenAI, Timeout
        except ImportError as exc:
            raise RuntimeError("Install the openai package for OpenAI API execution") from exc
        options: dict[str, Any] = {
            "api_key": self.configuration.inputs.api_key,
            "timeout": Timeout(
                self.timeout_policy.total_seconds,
                connect=self.timeout_policy.connect_seconds,
                read=min(
                    self.timeout_policy.read_seconds,
                    self.timeout_policy.idle_stream_seconds,
                ),
                write=self.timeout_policy.read_seconds,
                pool=self.timeout_policy.connect_seconds,
            ),
            "max_retries": 0,
        }
        if self.configuration.base_url:
            options["base_url"] = self.configuration.base_url
        if self.configuration.default_query:
            options["default_query"] = dict(self.configuration.default_query)
        if self.configuration.inputs.default_headers:
            options["default_headers"] = dict(self.configuration.inputs.default_headers)
        return AsyncOpenAI(**options)

    def _request_options(self, request: AgentRequest) -> dict[str, Any]:
        options: dict[str, Any] = {
            "model": self.configuration.model,
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": request.prompt},
                    ],
                }
            ],
            "store": False,
        }
        if self.configuration.reasoning_effort:
            options["reasoning"] = {"effort": self.configuration.reasoning_effort}
        if request.max_output_tokens is not None:
            options["max_output_tokens"] = request.max_output_tokens
        schema = _schema(request)
        if schema is not None:
            options["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "dfir_agent_output",
                    "schema": dict(schema),
                    "strict": True,
                }
            }
        return options

    async def execute(
        self,
        request: AgentRequest,
        *,
        progress_callback: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        attempt: int = 1,
    ) -> ProviderResponse:
        if self.client is None:
            self.client = self._build_client()
        client = self.client
        options = self._request_options(request)
        started = time.monotonic()
        try:
            if not request.stream:
                response = await client.responses.create(**options)
                if time.monotonic() - started > self.timeout_policy.total_seconds:
                    raise TimeoutError("provider request exceeded total operation timeout")
                terminal_error = _response_terminal_exception(
                    response, self.configuration.provider
                )
                if terminal_error is not None:
                    raise terminal_error
                request_id = str(_get(response, "_request_id", "") or _get(response, "id", ""))
                usage = _usage(_get(response, "usage"))
                self._emit(progress_callback, request, "request_accepted", attempt, request_id=request_id)
                self._emit(progress_callback, request, "usage_updated", attempt, request_id=request_id, **usage.as_dict())
                return ProviderResponse(
                    output=_response_text(response),
                    request_id=request_id,
                    usage=usage,
                    finish_reason=str(_get(response, "status", "")),
                    protocol="responses",
                )
            stream = await client.responses.create(stream=True, **options)
            text_parts: list[str] = []
            final: Any = None
            request_id = ""
            try:
                async for event in stream:
                    if time.monotonic() - started > self.timeout_policy.total_seconds:
                        raise TimeoutError("provider stream exceeded total operation timeout")
                    if cancellation is not None:
                        cancellation.raise_if_cancelled()
                    event_type = str(_get(event, "type", _get(event, "event", "")))
                    if event_type == "response.created":
                        response = _get(event, "response")
                        request_id = str(_get(response, "id", ""))
                        self._emit(progress_callback, request, "request_accepted", attempt, request_id=request_id)
                    elif event_type == "response.output_text.delta":
                        delta = str(_get(event, "delta", ""))
                        text_parts.append(delta)
                        self._emit(progress_callback, request, "output_progress", attempt, request_id=request_id, characters=len(delta))
                    elif event_type in {
                        "response.completed",
                        "response.failed",
                        "response.incomplete",
                    }:
                        final = _get(event, "response")
            finally:
                close = getattr(stream, "close", None)
                if callable(close):
                    close_result = close()
                    if inspect.isawaitable(close_result):
                        await close_result
            if final is None:
                getter = getattr(stream, "get_final_response", None)
                if callable(getter):
                    final = getter()
                    if inspect.isawaitable(final):
                        final = await final
            terminal_error = _response_terminal_exception(
                final, self.configuration.provider
            )
            if terminal_error is not None:
                raise terminal_error
            output = "".join(text_parts) or _response_text(final)
            usage = _usage(_get(final, "usage"))
            final_request_id = str(
                _get(final, "_request_id", "") or _get(final, "id", request_id)
            )
            self._emit(
                progress_callback,
                request,
                "usage_updated",
                attempt,
                request_id=final_request_id,
                **usage.as_dict(),
            )
            return ProviderResponse(
                output=output,
                request_id=final_request_id,
                usage=usage,
                finish_reason=str(_get(final, "status", "")),
                protocol="responses",
            )
        except AgentCancelled:
            raise
        except AgentProviderException:
            raise
        except Exception as exc:
            raise _normalized_exception(exc, self.configuration.provider) from exc


_CODEX_ANALYST_INSTRUCTIONS = (
    "You are a text-only DFIR analyst. Analyze only the evidence and instructions "
    "inside the supplied user message and return only the requested report or JSON. "
    "Do not use shell commands, files, network access, web search, MCP, plugins, "
    "skills, images, dynamic tools, or subagents. Do not request approval or user input."
)


def _codex_usage(value: object) -> AgentUsage:
    total = _get(value, "total", {})
    return AgentUsage(
        input_tokens=_integer(_get(total, "inputTokens", 0)),
        output_tokens=_integer(_get(total, "outputTokens", 0)),
        total_tokens=_integer(_get(total, "totalTokens", 0)),
        cached_input_tokens=_integer(_get(total, "cachedInputTokens", 0)),
    )


def _codex_turn_error(
    turn: object,
    request_id: str,
    usage: AgentUsage = AgentUsage(),
) -> AgentProviderException:
    error = _get(turn, "error", {})
    info = _get(error, "codexErrorInfo")
    if isinstance(info, Mapping):
        info_name = str(next(iter(info), "other"))
    else:
        info_name = str(info or "other")
    classifications = {
        "badRequest": ("invalid_request", False),
        "contextWindowExceeded": ("invalid_request", False),
        "cyberPolicy": ("provider_policy", False),
        "internalServerError": ("server_error", True),
        "responseStreamConnectionFailed": ("connection", True),
        "responseStreamDisconnected": ("connection", True),
        "serverOverloaded": ("provider_overload", True),
        "unauthorized": ("authentication", False),
        "usageLimitExceeded": ("rate_limit", True),
    }
    classification, retryable = classifications.get(
        info_name, ("provider_error", False)
    )
    return AgentProviderException(
        AgentError(
            classification=classification,
            message=f"openai {classification}",
            retryable=retryable,
            request_id=request_id,
            provider_error_code=info_name,
            usage=usage,
            finish_reason=str(_get(turn, "status", "failed") or "failed"),
        )
    )


class CodexAppServerAdapter(_BaseAdapter):
    """Execute ephemeral, text-only analyst turns through Codex-managed auth."""

    def __init__(
        self,
        configuration: ResolvedAgentExecution,
        timeout_policy: TimeoutPolicy,
        client: Any = None,
    ):
        super().__init__(configuration, timeout_policy, client)
        self._shared_client = False
        self._temp_directory = tempfile.TemporaryDirectory(
            prefix="ai-skills-codex-analyst-"
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            structured_output=True,
            json_mode=True,
            remote_cancellation=True,
            reasoning_configuration=True,
            tool_calling=False,
        )

    async def _client(self) -> Any:
        if self.client is None:
            self.client = await acquire_shared_codex_client(
                connect_timeout=self.timeout_policy.connect_seconds
            )
            self._shared_client = True
        return self.client

    async def close(self) -> None:
        client = self.client
        self.client = None
        try:
            if client is not None:
                if self._shared_client and isinstance(client, CodexAppServerClient):
                    await release_shared_codex_client(client)
                elif not self._shared_client:
                    close = getattr(client, "close", None)
                    if callable(close):
                        result = close()
                        if inspect.isawaitable(result):
                            await result
        finally:
            self._temp_directory.cleanup()

    async def _interrupt(self, client: Any, thread_id: str, turn_id: str) -> None:
        if not thread_id or not turn_id:
            return
        try:
            await asyncio.wait_for(
                client.request(
                    "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}
                ),
                timeout=min(2.0, self.timeout_policy.connect_seconds),
            )
        except (Exception, asyncio.CancelledError):
            return

    def _thread_params(self) -> dict[str, Any]:
        workdir = self._temp_directory.name
        return {
            "model": self.configuration.model,
            "modelProvider": "openai",
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "cwd": workdir,
            "baseInstructions": _CODEX_ANALYST_INSTRUCTIONS,
            "developerInstructions": _CODEX_ANALYST_INSTRUCTIONS,
            "dynamicTools": [],
            "environments": [],
            "ephemeral": True,
            "experimentalRawEvents": False,
            "multiAgentMode": "explicitRequestOnly",
            "runtimeWorkspaceRoots": [],
            "selectedCapabilityRoots": [],
            "config": {
                "mcp_servers": {},
                "features": {"web_search": False},
                "project_doc_max_bytes": 0,
                "tools": {"web_search": False},
            },
        }

    def _turn_params(
        self, request: AgentRequest, thread_id: str
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": request.prompt}],
            "approvalPolicy": "never",
            "cwd": self._temp_directory.name,
            "environments": [],
            "runtimeWorkspaceRoots": [],
            "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
        }
        if self.configuration.reasoning_effort:
            params["effort"] = self.configuration.reasoning_effort
        schema = _schema(request)
        if schema is not None:
            params["outputSchema"] = dict(schema)
        return params

    async def execute(
        self,
        request: AgentRequest,
        *,
        progress_callback: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
        attempt: int = 1,
    ) -> ProviderResponse:
        token = cancellation or CancellationToken()
        client = await self._client()
        thread_id = ""
        turn_id = ""
        queue: asyncio.Queue[dict[str, Any]] | None = None
        usage = AgentUsage()
        completed_items: list[object] = []
        policy_violation = False
        try:
            token.raise_if_cancelled()
            thread_result = await client.request("thread/start", self._thread_params())
            thread_id = str(_get(_get(thread_result, "thread", {}), "id", ""))
            if not thread_id:
                raise AgentProviderException(
                    AgentError(
                        "malformed_response",
                        "Codex app-server did not return a thread identifier",
                    )
                )
            queue = client.subscribe(thread_id)
            turn_result = await client.request(
                "turn/start", self._turn_params(request, thread_id)
            )
            turn = _get(turn_result, "turn", {})
            turn_id = str(_get(turn, "id", ""))
            if not turn_id:
                raise AgentProviderException(
                    AgentError(
                        "malformed_response",
                        "Codex app-server did not return a turn identifier",
                    )
                )
            self._emit(
                progress_callback,
                request,
                "request_accepted",
                attempt,
                request_id=turn_id,
            )
            while True:
                event_wait = asyncio.create_task(queue.get())
                cancellation_wait = asyncio.create_task(token.wait())
                done, pending = await asyncio.wait(
                    {event_wait, cancellation_wait},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for pending_task in pending:
                    pending_task.cancel()
                if cancellation_wait in done:
                    await self._interrupt(client, thread_id, turn_id)
                    raise AgentCancelled("agent request was cancelled")
                message = event_wait.result()
                method = str(message.get("method", ""))
                params = message.get("params", {})
                event_turn_id = str(_get(params, "turnId", ""))
                if event_turn_id and event_turn_id != turn_id:
                    continue
                if method in {
                    "client/connection/closed",
                    "client/queue/overflow",
                }:
                    raise AgentProviderException(
                        AgentError(
                            "connection",
                            "Codex app-server connection failed",
                            retryable=True,
                            request_id=turn_id,
                        )
                    )
                if method == "client/request/rejected":
                    policy_violation = True
                    await self._interrupt(client, thread_id, turn_id)
                    continue
                if method in {"item/started", "item/completed"}:
                    item = _get(params, "item", {})
                    item_type = str(_get(item, "type", ""))
                    if item_type in CODEX_PROHIBITED_ITEM_TYPES:
                        policy_violation = True
                        await self._interrupt(client, thread_id, turn_id)
                    elif method == "item/completed":
                        completed_items.append(item)
                        if item_type == "agentMessage":
                            self._emit(
                                progress_callback,
                                request,
                                "output_progress",
                                attempt,
                                request_id=turn_id,
                                characters=len(str(_get(item, "text", ""))),
                            )
                    continue
                if method == "thread/tokenUsage/updated":
                    usage = _codex_usage(_get(params, "tokenUsage", {}))
                    continue
                if method != "turn/completed":
                    continue
                completed_turn = _get(params, "turn", {})
                completed_items.extend(_get(completed_turn, "items", []) or [])
                status = str(_get(completed_turn, "status", ""))
                if policy_violation:
                    raise AgentProviderException(
                        AgentError(
                            "policy_violation",
                            "Codex analyst turn attempted a prohibited tool or interaction",
                            request_id=turn_id,
                            usage=usage,
                            finish_reason=status,
                        )
                    )
                if status == "failed":
                    raise _codex_turn_error(completed_turn, turn_id, usage)
                if status == "interrupted":
                    raise AgentCancelled("agent request was interrupted")
                if status != "completed":
                    raise AgentProviderException(
                        AgentError(
                            "provider_error",
                            "Codex app-server returned an unknown turn status",
                            request_id=turn_id,
                            usage=usage,
                            finish_reason=status,
                        )
                    )
                final_messages = [
                    str(_get(item, "text", ""))
                    for item in completed_items
                    if str(_get(item, "type", "")) == "agentMessage"
                    and str(_get(item, "phase", "")) == "final_answer"
                    and str(_get(item, "text", ""))
                ]
                if not final_messages:
                    final_messages = [
                        str(_get(item, "text", ""))
                        for item in completed_items
                        if str(_get(item, "type", "")) == "agentMessage"
                        and str(_get(item, "text", ""))
                    ]
                self._emit(
                    progress_callback,
                    request,
                    "usage_updated",
                    attempt,
                    request_id=turn_id,
                    **usage.as_dict(),
                )
                return ProviderResponse(
                    output=final_messages[-1] if final_messages else "",
                    request_id=turn_id,
                    usage=usage,
                    finish_reason=status,
                    protocol="codex_app_server",
                )
        except asyncio.CancelledError:
            await asyncio.shield(self._interrupt(client, thread_id, turn_id))
            raise
        except CodexAppServerError as exc:
            classification = (
                "provider_overload" if exc.code == -32001 else "connection"
            )
            if (
                classification == "connection"
                and self._shared_client
                and isinstance(client, CodexAppServerClient)
            ):
                await invalidate_shared_codex_client(client)
                self.client = None
                self._shared_client = False
            raise AgentProviderException(
                AgentError(
                    classification=classification,
                    message=f"openai {classification}",
                    retryable=True,
                    request_id=turn_id,
                    provider_error_code=str(exc.code),
                )
            ) from exc
        finally:
            if queue is not None:
                client.unsubscribe(thread_id, queue)


class AzureOpenAIResponsesAdapter(OpenAIResponsesAdapter):
    def _build_client(self) -> Any:
        try:
            from openai import AsyncOpenAI, Timeout
        except ImportError as exc:
            raise RuntimeError("Install the openai package for Azure OpenAI execution") from exc
        api_key: Any = self.configuration.inputs.api_key
        if self.configuration.auth_mode == "entra":
            try:
                from azure.identity.aio import (
                    ClientSecretCredential,
                    DefaultAzureCredential,
                    get_bearer_token_provider,
                )
            except ImportError as exc:
                raise RuntimeError(
                    "Install azure-identity for AZURE_OPENAI_AUTH_MODE=entra"
                ) from exc
            self.credential = (
                ClientSecretCredential(**self.configuration.inputs.azure_client_secret)
                if self.configuration.inputs.azure_client_secret
                else DefaultAzureCredential()
            )
            api_key = get_bearer_token_provider(
                self.credential,
                "https://cognitiveservices.azure.com/.default",
            )
        default_query = dict(self.configuration.default_query)
        if self.configuration.api_version:
            default_query["api-version"] = self.configuration.api_version
        return AsyncOpenAI(
            api_key=api_key,
            base_url=self.configuration.base_url,
            default_query=default_query or None,
            default_headers=dict(self.configuration.inputs.default_headers) or None,
            timeout=Timeout(
                self.timeout_policy.total_seconds,
                connect=self.timeout_policy.connect_seconds,
                read=min(self.timeout_policy.read_seconds, self.timeout_policy.idle_stream_seconds),
                write=self.timeout_policy.read_seconds,
                pool=self.timeout_policy.connect_seconds,
            ),
            max_retries=0,
        )


def adapter_for(
    configuration: ResolvedAgentExecution,
    *,
    timeout_policy: TimeoutPolicy,
    client: Any = None,
) -> _BaseAdapter:
    if configuration.protocol == "codex_app_server":
        return CodexAppServerAdapter(configuration, timeout_policy, client)
    if configuration.provider == "anthropic":
        from vraptor.agent.additional_providers import (
            AnthropicMessagesAdapter,
            ClaudeAgentSDKAdapter,
        )

        adapter = (
            ClaudeAgentSDKAdapter
            if configuration.protocol == "claude_agent_sdk"
            else AnthropicMessagesAdapter
        )
        return adapter(configuration, timeout_policy, client)
    if configuration.provider == "openai":
        return OpenAIResponsesAdapter(configuration, timeout_policy, client)
    if configuration.provider == "azure_openai":
        return AzureOpenAIResponsesAdapter(configuration, timeout_policy, client)
    raise RuntimeError(f"No adapter registered for provider {configuration.provider}")
