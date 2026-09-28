from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from vraptor.agent.config import HydratedProviderInputs
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.providers import AzureOpenAIResponsesAdapter
from vraptor.agent.providers import CodexAppServerAdapter
from vraptor.agent.providers import OpenAIResponsesAdapter
from vraptor.agent.providers import _normalized_exception
from vraptor.agent.providers import adapter_for
from vraptor.agent.codex_app_server import CodexAppServerError
from vraptor.agent.runtime import AgentCancelled
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentProviderException
from vraptor.agent.runtime import CancellationToken
from vraptor.agent.runtime import TimeoutPolicy


TIMEOUTS = TimeoutPolicy(1, 2, 3, 2)


def provider_execution(
    provider: str,
    model: str,
    protocol: str,
    *,
    base_url: str = "",
    auth_mode: str = "api_key",
    api_key: str = "",
    api_version: str = "",
    default_query: dict[str, str] | None = None,
    default_headers: dict[str, str] | None = None,
    max_concurrency: int | None = None,
    reasoning_effort: str = "",
) -> ResolvedAgentExecution:
    return ResolvedAgentExecution(
        route=ResolvedAgentRoute(
            provider=provider,
            model=model,
            protocol=protocol,
            base_url=base_url,
            auth_mode=auth_mode,
            api_version=api_version,
            default_query=default_query or {},
            max_concurrency=max_concurrency,
            reasoning_effort=reasoning_effort,
        ),
        inputs=HydratedProviderInputs(
            api_key=api_key,
            default_headers=default_headers or {},
            credential_present=bool(api_key) or auth_mode in {"entra", "codex_managed"},
        ),
    )


def request(**overrides):
    values = {
        "task_id": "task",
        "prompt": "evidence",
        "output_name": "out.txt",
        "metadata": {},
    }
    values.update(overrides)
    return AgentRequest(**values)


class FakeResponseStream(list):
    def __init__(self, values):
        super().__init__(values)
        self.closed = False

    def __aiter__(self):
        self._iterator = iter(self)
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration as exc:
            raise StopAsyncIteration from exc

    async def close(self):
        self.closed = True


class FakeResponses:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class FakeCodexClient:
    def __init__(self, events=(), error=None):
        self.events = list(events)
        self.error = error
        self.calls = []
        self.queue = None
        self.closed = False

    async def request(self, method, params):
        self.calls.append((method, params))
        if self.error is not None and method == "thread/start":
            raise self.error
        if method == "thread/start":
            return {"thread": {"id": "thread-1"}}
        if method == "turn/start":
            assert self.queue is not None
            for event in self.events:
                self.queue.put_nowait(event)
            return {"turn": {"id": "turn-1", "status": "inProgress", "items": []}}
        return {}

    def subscribe(self, thread_id):
        self.queue = asyncio.Queue()
        return self.queue

    def unsubscribe(self, thread_id, queue):
        self.queue = None

    async def close(self):
        self.closed = True


class ProviderAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_codex_app_server_returns_ephemeral_text_only_turn(self):
        events = [
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "type": "agentMessage",
                        "id": "message-1",
                        "phase": "final_answer",
                        "text": "done",
                    },
                },
            },
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "tokenUsage": {
                        "total": {
                            "inputTokens": 4,
                            "cachedInputTokens": 1,
                            "outputTokens": 2,
                            "totalTokens": 6,
                        }
                    },
                },
            },
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {
                        "id": "turn-1",
                        "status": "completed",
                        "items": [],
                    },
                },
            },
        ]
        client = FakeCodexClient(events)
        config = provider_execution(
            "openai",
            "gpt",
            "codex_app_server",
            auth_mode="codex_managed",
            max_concurrency=50,
        )
        adapter = CodexAppServerAdapter(config, TIMEOUTS, client)

        result = await adapter.execute(
            request(output_schema={"type": "object"}, max_output_tokens=64_000)
        )

        self.assertEqual(result.output, "done")
        self.assertEqual(result.request_id, "turn-1")
        self.assertEqual(result.usage.total_tokens, 6)
        thread_params = client.calls[0][1]
        self.assertTrue(thread_params["ephemeral"])
        self.assertEqual(thread_params["sandbox"], "read-only")
        self.assertEqual(thread_params["dynamicTools"], [])
        self.assertEqual(thread_params["environments"], [])
        self.assertEqual(thread_params["config"]["project_doc_max_bytes"], 0)
        turn_params = client.calls[1][1]
        self.assertFalse(turn_params["sandboxPolicy"]["networkAccess"])
        self.assertEqual(turn_params["outputSchema"], {"type": "object"})
        self.assertNotIn("max_output_tokens", turn_params)
        self.assertFalse(adapter.capabilities().request_output_token_limit)
        await adapter.close()
        self.assertTrue(client.closed)

    async def test_codex_app_server_interrupts_prohibited_tool_item(self):
        client = FakeCodexClient(
            [
                {
                    "method": "item/started",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "item": {"type": "commandExecution", "id": "tool-1"},
                    },
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {
                            "id": "turn-1",
                            "status": "interrupted",
                            "items": [],
                        },
                    },
                },
            ]
        )
        config = provider_execution(
            "openai", "gpt", "codex_app_server", auth_mode="codex_managed"
        )
        adapter = CodexAppServerAdapter(config, TIMEOUTS, client)

        with self.assertRaises(AgentProviderException) as raised:
            await adapter.execute(request())

        self.assertEqual(raised.exception.error.classification, "policy_violation")
        self.assertTrue(any(call[0] == "turn/interrupt" for call in client.calls))
        await adapter.close()

    async def test_codex_app_server_maps_overload_as_retryable(self):
        client = FakeCodexClient(error=CodexAppServerError(-32001))
        config = provider_execution(
            "openai", "gpt", "codex_app_server", auth_mode="codex_managed"
        )
        adapter = CodexAppServerAdapter(config, TIMEOUTS, client)

        with self.assertRaises(AgentProviderException) as raised:
            await adapter.execute(request())

        self.assertEqual(raised.exception.error.classification, "provider_overload")
        self.assertTrue(raised.exception.error.retryable)
        await adapter.close()

    async def test_codex_app_server_cancellation_interrupts_remote_turn(self):
        client = FakeCodexClient()
        token = CancellationToken()
        config = provider_execution(
            "openai", "gpt", "codex_app_server", auth_mode="codex_managed"
        )
        adapter = CodexAppServerAdapter(config, TIMEOUTS, client)

        running = asyncio.create_task(
            adapter.execute(request(), cancellation=token)
        )
        while len(client.calls) < 2:
            await asyncio.sleep(0)
        token.cancel()

        with self.assertRaises(AgentCancelled):
            await running
        self.assertTrue(any(call[0] == "turn/interrupt" for call in client.calls))
        await adapter.close()

    def test_codex_app_server_adapter_is_selected_by_protocol(self):
        config = provider_execution(
            "openai", "gpt", "codex_app_server", auth_mode="codex_managed"
        )
        selected = adapter_for(config, timeout_policy=TIMEOUTS, client=FakeCodexClient())
        self.assertIsInstance(selected, CodexAppServerAdapter)

    def test_invalid_request_preserves_safe_provider_code_and_parameter(self):
        error = RuntimeError("raw provider body")
        error.status_code = 400
        error.request_id = "req-400"
        error.body = {
            "error": {
                "code": "invalid_parameter",
                "param": "max_output_tokens",
            }
        }

        normalized = _normalized_exception(error, "azure_openai").error

        self.assertEqual(normalized.classification, "invalid_request")
        self.assertEqual(normalized.provider_status, 400)
        self.assertEqual(normalized.request_id, "req-400")
        self.assertEqual(normalized.provider_error_code, "invalid_parameter")
        self.assertEqual(normalized.provider_error_param, "max_output_tokens")
        self.assertNotIn("raw provider body", normalized.message)

    def test_body_only_rate_limit_code_is_retryable(self):
        error = RuntimeError("raw provider body")
        error.body = {"error": {"code": "rate_limit_exceeded"}}

        normalized = _normalized_exception(error, "azure_openai").error

        self.assertEqual(normalized.classification, "rate_limit")
        self.assertTrue(normalized.retryable)
        self.assertEqual(normalized.provider_error_code, "rate_limit_exceeded")

    def test_retry_after_ms_precedes_retry_after_seconds(self):
        error = RuntimeError("raw provider body")
        error.status_code = 429
        error.response = SimpleNamespace(
            status_code=429,
            headers={"retry-after-ms": "1250", "retry-after": "30"},
        )

        normalized = _normalized_exception(error, "azure_openai").error

        self.assertEqual(normalized.retry_after_seconds, 1.25)
        self.assertEqual(normalized.retry_after_source, "retry-after-ms")

    async def test_responses_adapters_share_successful_stream_normalization(self):
        adapter_types = ((AzureOpenAIResponsesAdapter, "azure_openai"),)
        for adapter_type, provider in adapter_types:
            with self.subTest(provider=provider):
                final = SimpleNamespace(
                    id=f"{provider}-response",
                    status="completed",
                    usage=SimpleNamespace(
                        input_tokens=2, output_tokens=1, total_tokens=3
                    ),
                    output_text="done",
                )
                stream = FakeResponseStream(
                    [
                        SimpleNamespace(
                            type="response.created",
                            response=SimpleNamespace(id=f"{provider}-response"),
                        ),
                        SimpleNamespace(
                            type="response.output_text.delta", delta="done"
                        ),
                        SimpleNamespace(type="response.completed", response=final),
                    ]
                )
                config = provider_execution(
                    provider,
                    "model",
                    "responses",
                    base_url=f"https://{provider}.invalid/v1/",
                    api_key="secret",
                )
                client = SimpleNamespace(responses=FakeResponses(stream))
                result = await adapter_type(config, TIMEOUTS, client).execute(
                    request(max_output_tokens=321)
                )
                self.assertEqual(result.output, "done")
                self.assertEqual(result.usage.total_tokens, 3)
                self.assertTrue(stream.closed)
                self.assertEqual(client.responses.calls[0]["max_output_tokens"], 321)
                nonstream_client = SimpleNamespace(
                    responses=FakeResponses(final)
                )
                nonstream = await adapter_type(
                    config, TIMEOUTS, nonstream_client
                ).execute(request(stream=False))
                self.assertEqual(nonstream.output, "done")

    async def test_openai_streaming_extracts_text_usage_and_request_id(self):
        final = SimpleNamespace(
            id="resp-1",
            status="completed",
            usage=SimpleNamespace(input_tokens=4, output_tokens=2, total_tokens=6),
            output_text="ignored",
        )
        stream = FakeResponseStream(
            [
                SimpleNamespace(type="response.created", response=SimpleNamespace(id="resp-1")),
                SimpleNamespace(type="response.output_text.delta", delta="hel"),
                SimpleNamespace(type="response.output_text.delta", delta="lo"),
                SimpleNamespace(type="response.completed", response=final),
            ]
        )
        client = SimpleNamespace(responses=FakeResponses(stream))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")
        result = await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(
            request(max_output_tokens=123)
        )
        self.assertEqual(result.output, "hello")
        self.assertEqual(result.request_id, "resp-1")
        self.assertEqual(result.usage.total_tokens, 6)
        self.assertEqual(result.finish_reason, "completed")
        self.assertTrue(stream.closed)
        options = client.responses.calls[0]
        self.assertFalse(options["store"])
        self.assertEqual(
            options["input"],
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "evidence"},
                    ],
                }
            ],
        )
        self.assertNotIn("instructions", options)
        self.assertNotIn("tools", options)
        self.assertEqual(options["max_output_tokens"], 123)

    async def test_openai_failed_stream_preserves_safe_retryable_error(self):
        final = SimpleNamespace(
            id="resp-failed",
            status="failed",
            error=SimpleNamespace(code="server_error", message="sensitive detail"),
            incomplete_details=None,
        )
        stream = FakeResponseStream(
            [SimpleNamespace(type="response.failed", response=final)]
        )
        client = SimpleNamespace(responses=FakeResponses(stream))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")

        with self.assertRaises(AgentProviderException) as raised:
            await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(request())

        self.assertEqual(raised.exception.error.classification, "server_error")
        self.assertTrue(raised.exception.error.retryable)
        self.assertEqual(raised.exception.error.provider_error_code, "server_error")
        self.assertEqual(raised.exception.error.request_id, "resp-failed")
        self.assertNotIn("sensitive detail", str(raised.exception))
        self.assertTrue(stream.closed)

    async def test_openai_incomplete_stream_is_not_returned_as_success(self):
        final = SimpleNamespace(
            id="resp-incomplete",
            status="incomplete",
            error=None,
            incomplete_details=SimpleNamespace(reason="max_output_tokens"),
            usage=SimpleNamespace(input_tokens=4, output_tokens=3, total_tokens=7),
            output_text='{"partial":true}',
        )
        stream = FakeResponseStream(
            [
                SimpleNamespace(
                    type="response.output_text.delta", delta='{"partial":true}'
                ),
                SimpleNamespace(type="response.incomplete", response=final),
            ]
        )
        client = SimpleNamespace(responses=FakeResponses(stream))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")

        with self.assertRaises(AgentProviderException) as raised:
            await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(request())

        self.assertEqual(raised.exception.error.classification, "output_limit_reached")
        self.assertFalse(raised.exception.error.retryable)
        self.assertEqual(
            raised.exception.error.provider_error_code, "max_output_tokens"
        )
        self.assertEqual(raised.exception.error.finish_reason, "max_output_tokens")
        self.assertEqual(raised.exception.error.usage.total_tokens, 7)
        self.assertTrue(stream.closed)

    async def test_other_incomplete_reason_remains_incomplete_response(self):
        final = SimpleNamespace(
            id="resp-incomplete",
            status="incomplete",
            error=None,
            incomplete_details=SimpleNamespace(reason="content_filter"),
            usage=None,
        )
        client = SimpleNamespace(responses=FakeResponses(final))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")

        with self.assertRaises(AgentProviderException) as raised:
            await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(
                request(stream=False)
            )

        self.assertEqual(raised.exception.error.classification, "incomplete_response")
        self.assertEqual(raised.exception.error.finish_reason, "content_filter")

    async def test_responses_adapters_forward_output_token_ceiling(self):
        response = SimpleNamespace(
            id="resp", output_text="done", usage=None, status="completed"
        )
        adapter_types = (
            (OpenAIResponsesAdapter, "openai"),
            (AzureOpenAIResponsesAdapter, "azure_openai"),
        )
        for adapter_type, provider in adapter_types:
            with self.subTest(provider=provider):
                client = SimpleNamespace(responses=FakeResponses(response))
                config = provider_execution(
                    provider,
                    "model",
                    "responses",
                    base_url=f"https://{provider}.invalid/v1/",
                    api_key="secret",
                )
                await adapter_type(config, TIMEOUTS, client).execute(
                    request(stream=False, max_output_tokens=64_000)
                )
                self.assertEqual(
                    client.responses.calls[0]["max_output_tokens"], 64_000
                )
                self.assertTrue(
                    adapter_type(config, TIMEOUTS, client)
                    .capabilities()
                    .request_output_token_limit
                )

    async def test_openai_structured_output_uses_responses_json_schema(self):
        response = SimpleNamespace(
            id="resp", output_text='{"ok":true}', usage=None, status="completed"
        )
        client = SimpleNamespace(responses=FakeResponses(response))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")
        schema = {"type": "object"}
        await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(
            request(stream=False, output_schema=schema)
        )
        self.assertEqual(
            client.responses.calls[0]["text"]["format"]["schema"], schema
        )

    async def test_reasoning_configuration_is_mapped_to_responses(self):
        openai_response = SimpleNamespace(
            id="resp", output_text="{}", usage=None, status="completed"
        )
        openai_client = SimpleNamespace(responses=FakeResponses(openai_response))
        openai_config = provider_execution(
            "openai", "gpt", "responses", api_key="secret", reasoning_effort="high"
        )
        await OpenAIResponsesAdapter(openai_config, TIMEOUTS, openai_client).execute(
            request(stream=False)
        )
        self.assertEqual(
            openai_client.responses.calls[0]["reasoning"], {"effort": "high"}
        )

    def test_azure_client_construction_separates_endpoint_and_key_auth(self):
        config = provider_execution(
            "azure_openai",
            "deployment",
            "responses",
            base_url="https://example.openai.azure.com/openai/v1/",
            api_key="secret",
            api_version="preview",
        )
        with mock.patch("openai.AsyncOpenAI") as client_class:
            AzureOpenAIResponsesAdapter(config, TIMEOUTS)._build_client()
        kwargs = client_class.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "secret")
        self.assertEqual(kwargs["default_query"], {"api-version": "preview"})
        self.assertEqual(kwargs["max_retries"], 0)

    def test_azure_entra_auth_constructs_a_bearer_token_provider(self):
        config = provider_execution(
            "azure_openai",
            "deployment",
            "responses",
            base_url="https://example.openai.azure.com/openai/v1/",
            auth_mode="entra",
        )
        with (
            mock.patch("azure.identity.aio.DefaultAzureCredential") as credential,
            mock.patch(
                "azure.identity.aio.get_bearer_token_provider",
                return_value="token-provider",
            ) as token_provider,
            mock.patch("openai.AsyncOpenAI") as client_class,
        ):
            AzureOpenAIResponsesAdapter(config, TIMEOUTS)._build_client()
        credential.assert_called_once_with()
        token_provider.assert_called_once()
        self.assertEqual(client_class.call_args.kwargs["api_key"], "token-provider")

    def test_native_sdk_client_construction_uses_configured_auth_and_base_url(self):
        with mock.patch("openai.AsyncOpenAI") as openai_client:
            OpenAIResponsesAdapter(
                provider_execution(
                    "openai",
                    "gpt",
                    "responses",
                    base_url="https://openai.invalid/v1/",
                    api_key="openai-secret",
                ),
                TIMEOUTS,
            )._build_client()
        self.assertEqual(openai_client.call_args.kwargs["api_key"], "openai-secret")
        self.assertEqual(
            openai_client.call_args.kwargs["base_url"], "https://openai.invalid/v1/"
        )

    def test_custom_headers_are_passed_without_exposing_values(self):
        config = provider_execution(
            "openai",
            "gpt",
            "responses",
            base_url="https://openai.invalid/v1",
            api_key="api-secret",
            default_headers={"X-Test-Header": "header-secret"},
        )
        with mock.patch("openai.AsyncOpenAI") as client_class:
            OpenAIResponsesAdapter(config, TIMEOUTS)._build_client()
        kwargs = client_class.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "api-secret")
        self.assertEqual(kwargs["base_url"], "https://openai.invalid/v1")
        self.assertEqual(
            kwargs["default_headers"],
            {"X-Test-Header": "header-secret"},
        )
        self.assertNotIn("api-secret", repr(config))
        self.assertNotIn("header-secret", repr(config))

    def test_adapter_selection_rejects_unsupported_provider(self):
        unsupported = provider_execution("unsupported", "model", "responses")
        with self.assertRaisesRegex(RuntimeError, "No adapter registered"):
            adapter_for(unsupported, timeout_policy=TIMEOUTS)

    async def test_local_cancellation_closes_openai_stream(self):
        token = CancellationToken()

        class CancellingStream(FakeResponseStream):
            def __aiter__(self):
                token.cancel()
                return super().__aiter__()

        stream = CancellingStream([SimpleNamespace(type="response.output_text.delta", delta="x")])
        client = SimpleNamespace(responses=FakeResponses(stream))
        config = provider_execution("openai", "gpt", "responses", api_key="secret")
        with self.assertRaisesRegex(Exception, "cancelled"):
            await OpenAIResponsesAdapter(config, TIMEOUTS, client).execute(
                request(), cancellation=token
            )
        self.assertTrue(stream.closed)


if __name__ == "__main__":
    unittest.main()
