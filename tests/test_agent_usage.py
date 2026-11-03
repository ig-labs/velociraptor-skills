"""Reported usage stays distinct from compatibility totals across attempts."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from test_agent_providers import FakeResponses, FakeResponseStream, provider_execution
from test_agent_runtime import FakeAdapter, limits, request
from vraptor.agent.additional_providers import AnthropicMessagesAdapter
from vraptor.agent.providers import (
    OpenAIResponsesAdapter,
    _normalized_exception,
    _usage,
)
from vraptor.agent.runtime import (
    AgentCancelled,
    AgentError,
    AgentProviderException,
    ApiAgentRunner,
    CancellationToken,
    ProviderResponse,
    RetryPolicy,
    TimeoutPolicy,
)


class ReportedUsageTests(unittest.TestCase):
    def test_presence_and_normalized_shape(self):
        raw = {'input_tokens': 10, 'output_tokens': 0,
               'input_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 8},
               'output_tokens_details': {'reasoning_tokens': 0}}
        usage = _usage(raw)
        self.assertEqual(usage.raw_usage, raw)
        self.assertEqual(usage.as_dict(), {'input_tokens': 10, 'output_tokens': 0,
                                          'total_tokens': 10, 'cached_input_tokens': 0})
        self.assertNotIn('total_tokens', usage.raw_usage)
        self.assertIsNone(_usage(None).raw_usage)
        self.assertEqual(_usage({}).raw_usage, {})

    def test_sdk_serialization_excludes_unset_defaults(self):
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("Optional AI SDK serialization dependency is unavailable")

        class Usage(BaseModel):
            input_tokens: int = 0
            output_tokens: int = 0

        self.assertEqual(_usage(Usage(input_tokens=0)).raw_usage, {'input_tokens': 0})
        self.assertEqual(_usage(Usage(input_tokens=0)).status, "partial")
        self.assertEqual(_usage(Usage()).status, "unavailable")
        self.assertEqual(_usage(Usage(input_tokens=0, output_tokens=0)).status, "reported")

    def test_chat_usage_aliases_and_numeric_details(self):
        raw = {'prompt_tokens': 9, 'completion_tokens': 4,
               'prompt_tokens_details': {'cached_tokens': 3},
               'completion_tokens_details': {'reasoning_tokens': 2}}
        result = _usage(raw)
        self.assertEqual(result.raw_usage, raw)
        self.assertEqual(result.cached_input_tokens, 3)
        self.assertEqual(result.as_dict()['total_tokens'], 13)

    def test_anthropic_input_remains_inclusive_and_raw_unchanged(self):
        raw = {'input_tokens': 5, 'output_tokens': 1, 'cache_read_input_tokens': 10,
               'cache_creation_input_tokens': 3}
        result = _usage(raw)
        self.assertEqual(result.raw_usage, raw)
        self.assertEqual(result.as_dict()['input_tokens'], 18)
        self.assertEqual(result.as_dict()['cached_input_tokens'], 10)

    def test_usage_never_retains_text_or_unbounded_tree(self):
        raw = {'input_tokens': 1, 'output_tokens': None, 'secret': 'do-not-retain',
               'headers': {'Authorization': 'do-not-retain'}, 'ok': True,
               'negative': -1, 'bad/key': 5}
        actual = _usage(raw).raw_usage
        self.assertEqual(actual, {'input_tokens': 1, 'output_tokens': None, 'headers': {}})
        self.assertNotIn('do-not-retain', json.dumps(actual))
        self.assertEqual(len(_usage({f'counter_{i}': i for i in range(200)}).raw_usage), 128)

    def test_error_usage_is_separate_from_error_body(self):
        class APIError(Exception):
            status_code = 500
            def __init__(self):
                self.body = {'usage': {'input_tokens': 2, 'output_tokens': 0},
                             'error': {'code': 'server_error', 'message': 'sensitive'}}

        error = _normalized_exception(APIError(), 'openai').error
        self.assertEqual(error.usage.raw_usage, {'input_tokens': 2, 'output_tokens': 0})
        self.assertNotIn('sensitive', str(error))

    def test_anthropic_terminal_and_tool_failures_keep_usage(self):
        selected = provider_execution('anthropic', 'test', 'messages')
        adapter = AnthropicMessagesAdapter(selected, TimeoutPolicy(1, 1, 2, 1))
        for stop, content in [('max_tokens', []), ('end_turn', [{'type': 'tool_use'}])]:
            with self.subTest(stop=stop), self.assertRaises(AgentProviderException) as raised:
                adapter._finish({'id': 'msg-1', 'stop_reason': stop, 'content': content,
                                 'usage': {'input_tokens': 5, 'output_tokens': 1}})
            self.assertEqual(raised.exception.error.usage.raw_usage,
                             {'input_tokens': 5, 'output_tokens': 1})


class AttemptUsageTests(unittest.IsolatedAsyncioTestCase):
    async def run_outcomes(self, outcomes, **request_options):
        adapter = FakeAdapter(outcomes)
        runner = ApiAgentRunner(adapter, limits=limits(),
                                retry_policy=RetryPolicy(max_retries=2),
                                timeout_policy=TimeoutPolicy(1, 1, 2, 1),
                                sleeper=lambda _: None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await runner.run(request(**request_options), workdir=root, output_dir=root)
            manifest = json.loads(Path(result.manifest_file).read_text())
        self.assertEqual(manifest['attempt_usage'], list(result.attempt_usage))
        self.assertEqual(manifest['raw_usage'], result.raw_usage)
        for entry in result.attempt_usage:
            self.assertGreaterEqual(entry['elapsed_seconds'], 0)
        return result

    async def test_unknown_retry_is_explicit_and_success_clears_error(self):
        result = await self.run_outcomes([
            AgentProviderException(AgentError('connection', 'network', True, request_id='bad')),
            ProviderResponse('ok', 'good', _usage({'input_tokens': 10, 'output_tokens': 2})),
        ])
        self.assertEqual(result.status, 'succeeded')
        self.assertEqual(result.error, '')
        self.assertEqual(result.attempt_count, 2)
        self.assertIsNone(result.attempt_usage[0]['usage'])
        self.assertEqual(result.attempt_usage[0]['request_id'], 'bad')
        self.assertEqual(result.attempt_usage[0]['status'], 'failed')
        self.assertEqual(result.attempt_usage[1]['request_id'], 'good')
        self.assertEqual(result.usage['total_tokens'], 12)
        self.assertEqual(result.raw_usage, result.attempt_usage[1]['usage'])

    async def test_known_failed_attempt_is_not_replaced_by_final_usage(self):
        first = _usage({'input_tokens': 3, 'output_tokens': 1})
        final = _usage({'input_tokens': 7, 'output_tokens': 2})
        result = await self.run_outcomes([
            AgentProviderException(AgentError('server_error', 'retry', True, usage=first)),
            ProviderResponse('ok', 'done', final),
        ])
        self.assertEqual(result.attempt_usage[0]['usage'], first.raw_usage)
        self.assertEqual(result.attempt_usage[1]['usage'], final.raw_usage)
        self.assertEqual(result.usage['total_tokens'], 9)

    async def test_incomplete_failure_retains_reported_zero(self):
        raw = {'input_tokens': 12, 'output_tokens': 0}
        result = await self.run_outcomes([
            AgentProviderException(AgentError('output_limit_reached', 'incomplete',
                                              request_id='incomplete', usage=_usage(raw))),
        ])
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.raw_usage, raw)
        self.assertEqual(len(result.attempt_usage), 1)

    async def test_schema_rejection_retains_observed_usage_and_id(self):
        raw = {'input_tokens': 4, 'output_tokens': 2}
        result = await self.run_outcomes([ProviderResponse('{}', 'schema', _usage(raw))],
                                        output_schema={'type': 'object', 'required': ['value']})
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.raw_usage, raw)
        self.assertEqual(result.request_id, 'schema')
        self.assertEqual(result.attempt_usage[0]['request_id'], 'schema')

    async def test_cancellation_retains_usage_if_adapter_observed_it(self):
        raw = {'input_tokens': 4, 'output_tokens': 2}
        result = await self.run_outcomes([AgentCancelled('cancelled', request_id='cancel', usage=_usage(raw))])
        self.assertEqual(result.status, 'cancelled')
        self.assertEqual(result.raw_usage, raw)
        self.assertEqual(result.attempt_usage[0]['request_id'], 'cancel')

    async def test_responses_incomplete_preserves_nested_usage(self):
        raw = {'input_tokens': 3, 'output_tokens': 2,
               'input_tokens_details': {'cache_write_tokens': 0}}
        response = SimpleNamespace(id='incomplete', status='incomplete', usage=raw,
                                   incomplete_details={'reason': 'max_output_tokens'})
        adapter = OpenAIResponsesAdapter(provider_execution('openai', 'test', 'responses'),
                                        TimeoutPolicy(1, 1, 2, 1),
                                        SimpleNamespace(responses=FakeResponses(response)))
        with self.assertRaises(AgentProviderException) as raised:
            await adapter.execute(request(stream=False))
        self.assertEqual(raised.exception.error.usage.raw_usage, raw)


class ExplicitCacheBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def adapter(self):
        return OpenAIResponsesAdapter(provider_execution('openai', 'test', 'responses'),
                                      TimeoutPolicy(1, 1, 2, 1))

    async def test_default_request_shape_unchanged(self):
        options = self.adapter()._request_options(request(prompt='policy dynamic'))
        self.assertEqual(options['input'][0]['content'],
                         [{'type': 'input_text', 'text': 'policy dynamic'}])
        self.assertNotIn('extra_body', options)

    async def test_explicit_split_preserves_every_character(self):
        prompt = 'Policy ✓\nDynamic evidence'
        options = self.adapter()._request_options(request(prompt=prompt, prompt_cache_prefix_chars=9))
        blocks = options['input'][0]['content']
        self.assertEqual(''.join(block['text'] for block in blocks), prompt)
        self.assertEqual(blocks[0]['prompt_cache_breakpoint'], {'mode': 'explicit'})
        self.assertNotIn('prompt_cache_breakpoint', blocks[1])
        self.assertEqual(options['extra_body'], {'prompt_cache_options': {'mode': 'explicit'}})

    async def test_invalid_boundary_fails_before_provider_call(self):
        for prefix in [0, -1, 99, True, 1.0, '3']:
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as directory:
                adapter = FakeAdapter()
                runner = ApiAgentRunner(adapter, limits=limits())
                with self.assertRaises(ValueError):
                    await runner.run(request(prompt='abc', prompt_cache_prefix_chars=prefix),
                                     workdir=Path(directory), output_dir=Path(directory))
                self.assertEqual(adapter.calls, 0)

    async def test_unsupported_protocol_fails_before_provider_call(self):
        adapter = FakeAdapter(protocol='messages')
        runner = ApiAgentRunner(adapter, limits=limits())
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'Responses protocol'):
            await runner.run(request(prompt='abc', prompt_cache_prefix_chars=2),
                             workdir=Path(directory), output_dir=Path(directory))
        self.assertEqual(adapter.calls, 0)


class CleanupUsageTests(unittest.IsolatedAsyncioTestCase):
    def adapter(self, stream, timeout=1):
        return OpenAIResponsesAdapter(provider_execution('openai', 'test', 'responses'),
                                      TimeoutPolicy(1, 1, timeout, 1),
                                      SimpleNamespace(responses=FakeResponses(stream)))

    def events(self):
        return [{'type': 'response.completed', 'response': {
            'id': 'terminal-1', 'status': 'completed', 'output_text': 'ok',
            'usage': {'input_tokens': 9, 'output_tokens': 2}}}]

    async def test_stream_close_failure_retains_terminal_usage(self):
        class BrokenClose(FakeResponseStream):
            async def close(self):
                raise ConnectionError('close failed')

        with self.assertRaises(AgentProviderException) as raised:
            await self.adapter(BrokenClose(self.events())).execute(request())
        self.assertEqual(raised.exception.error.request_id, 'terminal-1')
        self.assertEqual(raised.exception.error.usage.raw_usage,
                         {'input_tokens': 9, 'output_tokens': 2})

    async def test_close_cancellation_and_timeout_keep_terminal_usage(self):
        for cancelled in (True, False):
            with self.subTest(cancelled=cancelled), tempfile.TemporaryDirectory() as directory:
                token = CancellationToken()

                class BlockingClose(FakeResponseStream):
                    async def close(self, trigger=cancelled, cancellation=token):
                        if trigger:
                            cancellation.cancel()
                        await asyncio.Event().wait()

                adapter = self.adapter(BlockingClose(self.events()))
                runner = ApiAgentRunner(adapter, retry_policy=RetryPolicy(max_retries=0),
                                        timeout_policy=TimeoutPolicy(1, 1, .02, 1))
                result = await runner.run(request(), workdir=Path(directory),
                                          output_dir=Path(directory), cancellation=token)
                self.assertEqual(result.status, 'cancelled' if cancelled else 'timeout')
                self.assertEqual(result.request_id, 'terminal-1')
                self.assertEqual(result.raw_usage, {'input_tokens': 9, 'output_tokens': 2})
                self.assertEqual(result.attempt_usage[0]['usage'], result.raw_usage)
