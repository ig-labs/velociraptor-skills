import asyncio
import json
import os
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock

import httpx
import pytest
from vraptor.agent.additional_providers import (
    AnthropicMessagesAdapter,
    ClaudeAgentSDKAdapter,
)
from vraptor.agent.config import (
    HydratedProviderInputs,
    ResolvedAgentExecution,
    ResolvedAgentRoute,
    hydrate_agent_execution,
)
from vraptor.agent.factory import create_agent_runner
from vraptor.agent.runtime import AgentProviderException, AgentRequest, TimeoutPolicy


def execution(provider, protocol):
    return ResolvedAgentExecution(
        route=ResolvedAgentRoute(
            provider=provider,
            model="test-model",
            protocol=protocol,
            base_url="http://inference.test",
            model_context_tokens=32768,
            model_max_output_tokens=4096,
        ),
        inputs=HydratedProviderInputs(api_key="test-key"),
    )


def request(**kwargs):
    return AgentRequest(
        task_id="test",
        prompt="Return READY",
        output_name="result.txt",
        metadata={},
        **kwargs,
    )


@pytest.mark.parametrize(
    "stop,expected",
    [
        ("end_turn", "succeeded"),
        ("max_tokens", "failed"),
        ("tool_use", "failed"),
        (None, "failed"),
    ],
)
@pytest.mark.parametrize("effort", ["", "low", "medium", "high", "xhigh", "max"])
def test_anthropic_real_sdk_terminal_contract(tmp_path, stop, expected, effort):
    AsyncAnthropic = pytest.importorskip("anthropic").AsyncAnthropic
    captured = []

    def respond(req):
        captured.append(json.loads(req.content))
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "READY"}],
                "stop_reason": stop,
                "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            },
        )

    async def run():
        client = AsyncAnthropic(
            api_key="test",
            base_url="http://inference.test",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
        )
        selected = execution("anthropic", "messages")
        selected = replace(
            selected, route=replace(selected.route, reasoning_effort=effort)
        )
        runner = create_agent_runner(selected, client=client)
        try:
            return await runner.run(
                request(stream=False), workdir=tmp_path, output_dir=tmp_path
            )
        finally:
            await runner.close()

    result = asyncio.run(run())
    assert result.status == expected
    assert captured[0]["max_tokens"] <= 4096
    if effort:
        assert captured[0]["output_config"]["effort"] == effort
    else:
        assert "output_config" not in captured[0]
    assert (tmp_path / "result.txt").exists() == (expected == "succeeded")


@pytest.mark.parametrize(
    "model,thinking",
    [
        ("claude-opus-5-5", {"type": "adaptive"}),
        ("claude-haiku-5-5", {"type": "adaptive"}),
        ("custom-claude", {"type": "adaptive"}),
        # Adaptive thinking starts with Claude 4.6.
        ("claude-opus-4-5-20251101", None),
    ],
)
def test_anthropic_effort_sends_adaptive_thinking_only_where_supported(
    model, thinking
):
    selected = execution("anthropic", "messages")
    selected = replace(
        selected, route=replace(selected.route, model=model, reasoning_effort="low")
    )
    options = AnthropicMessagesAdapter(
        selected, TimeoutPolicy(), client=object()
    )._request_options(request())
    assert options.get("thinking") == thinking
    assert options["output_config"]["effort"] == "low"


@pytest.mark.parametrize("effort", ["", "low", "medium", "high", "xhigh", "max"])
def test_claude_sdk_uses_real_options_with_mocked_execution(effort, monkeypatch):
    ResultMessage = pytest.importorskip("claude_agent_sdk").ResultMessage
    captured = []
    inherited_credentials = {
        "ANTHROPIC_API_KEY": "unused-api-key",
        "ANTHROPIC_AUTH_TOKEN": "unused-auth-token",
        "CLAUDE_CODE_OAUTH_TOKEN": "unused-oauth-token",
    }
    for name, value in inherited_credentials.items():
        monkeypatch.setenv(name, value)

    async def query(**kwargs):
        captured.append(kwargs["options"])
        yield ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=False,
            num_turns=1,
            session_id="test-session",
            result="READY",
            usage={"input_tokens": 5, "output_tokens": 1},
        )

    async def run():
        selected = execution("anthropic", "claude_agent_sdk")
        selected = replace(
            selected, route=replace(selected.route, reasoning_effort=effort)
        )
        adapter = ClaudeAgentSDKAdapter(selected, TimeoutPolicy())
        return await adapter.execute(request())

    with mock.patch("claude_agent_sdk.query", query):
        assert asyncio.run(run()).output == "READY"
    options = captured[0]
    assert options.effort == (effort or None)
    assert options.tools == [] and options.setting_sources == []
    assert options.strict_mcp_config and options.mcp_servers == {}
    assert options.permission_mode == "dontAsk"
    for name, value in inherited_credentials.items():
        assert options.env[name] == ""
        assert os.environ[name] == value
    assert json.loads(options.settings)["disableAllHooks"]
    from claude_agent_sdk._internal.transport.subprocess_cli import (
        SubprocessCLITransport,
    )

    transport = SubprocessCLITransport(prompt="synthetic", options=options)
    transport._cli_path = (
        "claude"  # Exercise argument generation without a login/process.
    )
    command = transport._build_command()
    assert command[command.index("--tools") + 1] == ""
    assert "--setting-sources=" in command and "--strict-mcp-config" in command
    assert "--no-session-persistence" in command
    if effort:
        assert command[command.index("--effort") + 1] == effort


def test_anthropic_api_still_hydrates_inherited_key():
    route = ResolvedAgentRoute(
        provider="anthropic", model="haiku", protocol="messages", auth_mode="api_key"
    )
    selected = hydrate_agent_execution(
        route, environment={"ANTHROPIC_API_KEY": "test-api-key"}
    )
    assert selected.inputs.api_key == "test-api-key"
    assert selected.inputs.credential_present
    assert selected.auth_mode == "api_key"


def test_claude_sdk_stream_uses_shared_heartbeat_until_message_completes():
    import io

    pytest.importorskip("claude_agent_sdk")
    from claude_agent_sdk import (
        AssistantMessage,
        ResultMessage,
        TextBlock,
        ThinkingBlock,
    )
    from claude_agent_sdk.types import StreamEvent
    from vraptor.analyze.cli_output import ProgressReporter

    stream = io.StringIO()
    now = [0.0]
    reporter = ProgressReporter(scope="host", stream=stream, monotonic=lambda: now[0])
    reporter.emit(phase="provider", status="request_started", task_id="test")
    progress = []

    def on_progress(event):
        progress.append(event)
        reporter.emit(phase="provider", status=event.type, task_id=event.task_id)

    async def query(**kwargs):
        assert kwargs["options"].include_partial_messages
        for index in range(60):
            now[0] += 1
            yield StreamEvent(
                uuid=str(index),
                session_id="test-session",
                event={
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "private fragment"},
                },
            )
            assert progress == []
            if now[0] % reporter.heartbeat_seconds == 0:
                reporter.heartbeat()
        yield AssistantMessage(
            content=[ThinkingBlock(thinking="private reasoning", signature="test")],
            model="test-model",
        )
        assert progress == []
        yield AssistantMessage(content=[TextBlock(text="READY")], model="test-model")
        yield ResultMessage(
            subtype="success",
            duration_ms=60000,
            duration_api_ms=60000,
            is_error=False,
            num_turns=1,
            session_id="test-session",
            result="READY",
        )

    async def run():
        return await ClaudeAgentSDKAdapter(
            execution("anthropic", "claude_agent_sdk"), TimeoutPolicy()
        ).execute(request(), progress_callback=on_progress)

    with mock.patch("claude_agent_sdk.query", query):
        assert asyncio.run(run()).output == "READY"
    assert len(progress) == 1
    assert progress[0].metadata == {"characters": 5}
    lines = stream.getvalue().splitlines()
    assert len(lines) == 5  # Start, three heartbeats, completed-message progress.
    assert sum("heartbeat=1" in line for line in lines) == 3
    assert "private" not in stream.getvalue()


@pytest.mark.parametrize("streamed", [False, True])
def test_claude_sdk_rejects_tool_blocks(streamed):
    pytest.importorskip("claude_agent_sdk")
    from claude_agent_sdk import AssistantMessage, ToolUseBlock
    from claude_agent_sdk.types import StreamEvent

    async def query(**kwargs):
        if streamed:
            yield StreamEvent(
                uuid="test",
                session_id="test-session",
                event={
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "tool_use", "name": "Bash"},
                },
            )
            pytest.fail("Streamed tool use must be rejected immediately")
        yield AssistantMessage(
            content=[ToolUseBlock(id="action", name="Bash", input={})],
            model="test-model",
        )

    async def run():
        return await ClaudeAgentSDKAdapter(
            execution("anthropic", "claude_agent_sdk"), TimeoutPolicy()
        ).execute(request())

    with (
        mock.patch("claude_agent_sdk.query", query),
        pytest.raises(AgentProviderException),
    ):
        asyncio.run(run())


STOP_CLASSIFICATIONS = [
    ("max_tokens", "output_limit_reached"),
    ("model_context_window_exceeded", "context_window_exceeded"),
    ("refusal", "refusal"),
    ("tool_use", "incomplete_response"),
]


@pytest.mark.parametrize("stop,classification", STOP_CLASSIFICATIONS)
def test_anthropic_stop_reasons_are_classified(stop, classification):
    adapter = AnthropicMessagesAdapter(
        execution("anthropic", "messages"), TimeoutPolicy(), client=object()
    )
    response = SimpleNamespace(stop_reason=stop, id="msg_1", usage=None, content=[])
    with pytest.raises(AgentProviderException) as raised:
        adapter._finish(response)
    assert raised.value.error.classification == classification
    assert raised.value.error.finish_reason == stop


@pytest.mark.parametrize("stop,classification", STOP_CLASSIFICATIONS)
def test_claude_sdk_rejects_incomplete_success_result(stop, classification):
    ResultMessage = pytest.importorskip("claude_agent_sdk").ResultMessage

    async def query(**kwargs):
        yield ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=False,
            num_turns=1,
            session_id="test-session",
            result="partial",
            stop_reason=stop,
            usage={"input_tokens": 5, "output_tokens": 2},
        )

    async def run():
        return await ClaudeAgentSDKAdapter(
            execution("anthropic", "claude_agent_sdk"), TimeoutPolicy()
        ).execute(request())

    with (
        mock.patch("claude_agent_sdk.query", query),
        pytest.raises(AgentProviderException) as raised,
    ):
        asyncio.run(run())
    assert raised.value.error.classification == classification
    assert raised.value.error.usage.status == "reported"
    assert raised.value.error.usage.as_dict()["total_tokens"] == 7
    assert raised.value.error.request_id == "test-session"


@pytest.mark.parametrize(
    "api_stop,result_stop,classification",
    [
        ("max_tokens", "stop_sequence", "output_limit_reached"),
        ("model_context_window_exceeded", "stop_sequence", "context_window_exceeded"),
        ("refusal", "refusal", "refusal"),
        (None, "refusal", "refusal"),
        (None, "stop_sequence", "incomplete_response"),
    ],
)
@pytest.mark.parametrize("result", ["partial", "Prompt is too long: 210000 tokens > 200000 maximum"])
def test_claude_sdk_classifies_cli_error_results(
    api_stop, result_stop, classification, result
):
    # Claude Code reports these stops as is_error results; the streamed
    # message_delta carries the API stop reason.
    pytest.importorskip("claude_agent_sdk")
    from claude_agent_sdk import ResultMessage
    from claude_agent_sdk.types import StreamEvent

    async def query(**kwargs):
        if api_stop:
            yield StreamEvent(
                uuid="delta",
                session_id="test-session",
                event={
                    "type": "message_delta",
                    "delta": {"stop_reason": api_stop, "stop_sequence": None},
                    "usage": {"output_tokens": 2},
                },
            )
        yield ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=1,
            session_id="test-session",
            result=result,
            stop_reason=result_stop,
        )

    async def run():
        return await ClaudeAgentSDKAdapter(
            execution("anthropic", "claude_agent_sdk"), TimeoutPolicy()
        ).execute(request())

    with (
        mock.patch("claude_agent_sdk.query", query),
        pytest.raises(AgentProviderException) as raised,
    ):
        asyncio.run(run())
    if result.startswith("Prompt is too long") and result_stop != "refusal":
        # Claude Code's own text when the prompt exceeds its window.
        classification = "context_window_exceeded"
        expected = "model_context_window_exceeded"
    else:
        expected = result_stop if classification == "incomplete_response" else (
            api_stop or result_stop
        )
    assert raised.value.error.classification == classification
    assert raised.value.error.finish_reason == expected


@pytest.mark.parametrize("enabled", [True, False])
def test_claude_sdk_passes_disabled_1m_context_to_claude_code(enabled):
    pytest.importorskip("claude_agent_sdk")
    from claude_agent_sdk import ResultMessage

    seen = {}

    async def query(**kwargs):
        seen.update(kwargs["options"].env)
        yield ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=False,
            num_turns=1,
            session_id="test-session",
            result="READY",
        )

    selected = execution("anthropic", "claude_agent_sdk")
    selected = replace(
        selected, route=replace(selected.route, claude_code_1m_context=enabled)
    )

    async def run():
        return await ClaudeAgentSDKAdapter(selected, TimeoutPolicy()).execute(
            request()
        )

    with mock.patch("claude_agent_sdk.query", query):
        assert asyncio.run(run()).output == "READY"
    # Settings from vraptor .env files must reach Claude Code as budgeted.
    assert ("CLAUDE_CODE_DISABLE_1M_CONTEXT" in seen) is not enabled
    if not enabled:
        assert seen["CLAUDE_CODE_DISABLE_1M_CONTEXT"] == "1"


def test_anthropic_unexpected_action_preserves_usage():
    adapter = AnthropicMessagesAdapter(execution("anthropic", "messages"), TimeoutPolicy())
    with pytest.raises(AgentProviderException) as raised:
        adapter._finish({
            "id": "msg-actions", "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 2},
            "content": [{"type": "tool_use"}],
        })
    assert raised.value.error.usage.status == "reported"
    assert raised.value.error.usage.as_dict()["total_tokens"] == 7
    assert raised.value.error.request_id == "msg-actions"


def test_anthropic_stream_failure_preserves_latest_cumulative_counts():
    class BrokenMessageStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def __aiter__(self):
            yield {"type": "message_start", "message": {
                "id": "msg-partial", "usage": {
                    "input_tokens": 5, "output_tokens": 0,
                    "cache_read_input_tokens": 10, "cache_creation_input_tokens": 3,
                },
            }}
            for count in (1, 2, 2):
                yield {"type": "message_delta", "usage": {"output_tokens": count}}
            raise ConnectionError("provider disconnected")

    progress = []
    adapter = AnthropicMessagesAdapter(
        execution("anthropic", "messages"), TimeoutPolicy(),
        client=SimpleNamespace(messages=SimpleNamespace(stream=lambda **_kwargs: BrokenMessageStream())),
    )
    with pytest.raises(AgentProviderException) as raised:
        asyncio.run(adapter.execute(request(), progress_callback=progress.append))
    assert raised.value.error.usage.status == "partial"
    assert raised.value.error.usage.as_dict()["total_tokens"] == 20
    assert raised.value.error.usage.cached_input_tokens == 10
    assert raised.value.error.request_id == "msg-partial"
    assert [event.metadata["output_tokens"] for event in progress if event.type == "usage_updated"] == [0, 1, 2, 2]


@pytest.mark.parametrize("is_error,subtype", [(True, "error_during_execution"), (False, "error_max_turns")])
def test_claude_unsuccessful_result_preserves_usage(is_error, subtype):
    ResultMessage = pytest.importorskip("claude_agent_sdk").ResultMessage

    async def query(**_kwargs):
        yield ResultMessage(
            subtype=subtype, duration_ms=1, duration_api_ms=1, is_error=is_error,
            num_turns=1, session_id="failed-session", result="partial",
            usage={"input_tokens": 5, "output_tokens": 2},
        )

    adapter = ClaudeAgentSDKAdapter(execution("anthropic", "claude_agent_sdk"), TimeoutPolicy())
    with mock.patch("claude_agent_sdk.query", query), pytest.raises(AgentProviderException) as raised:
        asyncio.run(adapter.execute(request()))
    assert raised.value.error.usage.status == "reported"
    assert raised.value.error.usage.as_dict()["total_tokens"] == 7
    assert raised.value.error.request_id == "failed-session"


def test_anthropic_real_sdk_streaming_and_cache_usage(tmp_path):
    AsyncAnthropic = pytest.importorskip("anthropic").AsyncAnthropic
    events = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {
                    "input_tokens": 5,
                    "output_tokens": 0,
                    "cache_read_input_tokens": 10,
                    "cache_creation_input_tokens": 3,
                },
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "READY"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 1},
        },
        {"type": "message_stop"},
    ]
    body = "".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
    )

    async def run():
        transport = httpx.MockTransport(
            lambda req: httpx.Response(
                200, text=body, headers={"content-type": "text/event-stream"}
            )
        )
        client = AsyncAnthropic(
            api_key="test",
            base_url="http://inference.test",
            http_client=httpx.AsyncClient(transport=transport),
        )
        runner = create_agent_runner(execution("anthropic", "messages"), client=client)
        try:
            return await runner.run(request(), workdir=tmp_path, output_dir=tmp_path)
        finally:
            await runner.close()

    result = asyncio.run(run())
    assert result.status == "succeeded" and result.output == "READY"
    assert result.usage["input_tokens"] == 18
    assert result.usage["cached_input_tokens"] == 10


def test_claude_sdk_timeout_closes_iterator_and_removes_session(tmp_path):
    pytest.importorskip("claude_agent_sdk")
    from dataclasses import replace

    directories, closed = [], []

    async def query(**kwargs):
        directories.append(kwargs["options"].cwd)
        try:
            await asyncio.sleep(10)
            yield None
        finally:
            closed.append(True)

    async def run():
        selected = execution("anthropic", "claude_agent_sdk")
        selected = replace(
            selected, route=replace(selected.route, timeout_seconds=1, max_retries=0)
        )
        runner = create_agent_runner(selected)
        try:
            return await runner.run(request(), workdir=tmp_path, output_dir=tmp_path)
        finally:
            await runner.close()

    with mock.patch("claude_agent_sdk.query", query):
        result = asyncio.run(run())
    from pathlib import Path

    assert result.status == "timeout"
    assert closed and all(not Path(directory).exists() for directory in directories)
    assert not (tmp_path / "result.txt").exists()
