from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import vraptor.agent.runtime as agent_runtime
from vraptor.agent.config import HydratedProviderInputs
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.runtime import AgentError
from vraptor.agent.runtime import AgentProviderException
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentResult
from vraptor.agent.runtime import AgentRuntimeLimits
from vraptor.agent.runtime import AgentUsage
from vraptor.agent.runtime import ApiAgentRunner
from vraptor.agent.runtime import CancellationToken
from vraptor.agent.runtime import ProviderCapabilities
from vraptor.agent.runtime import ProviderResponse
from vraptor.agent.runtime import RetryPolicy
from vraptor.agent.runtime import TimeoutPolicy
from vraptor.agent.runtime import run_item_pool
from vraptor.artifacts import persistence as persistence_policy


class FakeAdapter:
    def __init__(
        self,
        outcomes=None,
        *,
        capabilities=None,
        secret="test-secret",
        provider="openai",
        protocol="responses",
        base_url="",
        max_concurrency=None,
        reasoning_effort="",
    ):
        self.configuration = ResolvedAgentExecution(
            route=ResolvedAgentRoute(
            provider=provider,
            model="test-model",
            protocol=protocol,
            base_url=base_url,
            max_concurrency=max_concurrency,
            reasoning_effort=reasoning_effort,
            ),
            inputs=HydratedProviderInputs(api_key=secret),
        )
        self.outcomes = list(outcomes or [ProviderResponse("ok", "req-1", AgentUsage(2, 1, 3))])
        self.calls = 0
        self.last_request = None
        self._capabilities = capabilities or ProviderCapabilities(
            structured_output=True,
            json_mode=True,
        )

    def capabilities(self):
        return self._capabilities

    async def execute(self, request, **_kwargs):
        self.calls += 1
        self.last_request = request
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class BlockingAdapter(FakeAdapter):
    def __init__(self, **kwargs):
        super().__init__(outcomes=[], **kwargs)
        self.started = asyncio.Event()
        self.cancelled = False

    async def execute(self, request, **_kwargs):
        self.calls += 1
        self.last_request = request
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


def limits(**overrides):
    values = {
        "model_context_tokens": 100,
        "operational_context_tokens": 90,
        "maximum_input_tokens": 60,
        "maximum_output_tokens": 30,
        "token_encoding": "cl100k_base",
    }
    values.update(overrides)
    return AgentRuntimeLimits(**values)


def request(**overrides):
    values = {
        "task_id": "task-1",
        "prompt": "review evidence",
        "output_name": "result.json",
        "metadata": {"artifact": "test"},
    }
    values.update(overrides)
    return AgentRequest(**values)


async def run_agent_items(tasks, **kwargs):
    return [result for _, result in await run_item_pool(tasks, **kwargs)]


class AgentRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def runner(self, adapter=None, **kwargs):
        return ApiAgentRunner(
            adapter or FakeAdapter(),
            limits=limits(),
            retry_policy=kwargs.pop("retry_policy", RetryPolicy(max_retries=0)),
            timeout_policy=kwargs.pop(
                "timeout_policy", TimeoutPolicy(1, 1, 2, 1)
            ),
            sleeper=kwargs.pop("sleeper", lambda _delay: None),
            **kwargs,
        )

    def write_existing_bundle(self, output_dir: Path) -> dict[Path, bytes]:
        output_dir.mkdir(parents=True, exist_ok=True)
        paths = {
            output_dir / "result.json": b"old report\n",
            output_dir / "result.json.events.jsonl": b'{"type":"old"}\n',
            output_dir / "result.json.manifest.json": b'{"status":"old"}\n',
        }
        for path, content in paths.items():
            path.write_bytes(content)
        return paths

    async def test_success_atomically_publishes_output_events_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner().run(request(), workdir=root, output_dir=root / "analysis")
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(Path(result.output_file).read_text(), "ok")
            manifest = json.loads(Path(result.manifest_file).read_text())
            self.assertEqual(manifest["provider"]["provider"], "openai")
            self.assertNotIn("api_key", manifest["provider"])
            self.assertFalse(manifest["prompt_persisted"])
            self.assertFalse(manifest["reasoning_trace_persisted"])
            self.assertFalse(
                manifest["request_options"]["max_output_tokens_sent"]
            )
            self.assertEqual(
                manifest["request_options"]["max_output_tokens_requested"], 30
            )
            self.assertEqual(manifest["local_output_tokens"], result.local_output_tokens)
            event_types = [json.loads(line)["type"] for line in Path(result.events_file).read_text().splitlines()]
            self.assertEqual(event_types, ["request_started", "request_completed"])

    async def test_existing_bundle_requires_explicit_replace_before_provider_call(
        self,
    ):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = self.write_existing_bundle(root / "analysis")
            with self.assertRaisesRegex(RuntimeError, "replace_existing=True"):
                await self.runner(adapter).run(
                    request(), workdir=root, output_dir=root / "analysis"
                )
            self.assertEqual(adapter.calls, 0)
            for path, content in existing.items():
                self.assertEqual(path.read_bytes(), content)

    async def test_successful_replace_archives_old_bundle_and_promotes_new_bundle(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "analysis"
            existing = self.write_existing_bundle(output_dir)
            result = await self.runner().run(
                request(),
                workdir=root,
                output_dir=output_dir,
                replace_existing=True,
            )

            self.assertEqual(result.status, "succeeded")
            self.assertEqual(Path(result.output_file).read_text(), "ok")
            archives = list((output_dir / "previous-analysis").iterdir())
            self.assertEqual(len(archives), 1)
            archive = archives[0]
            self.assertRegex(archive.name, r"^\d{8}T\d{6}Z-[0-9a-f]{12}$")
            for path, content in existing.items():
                self.assertEqual((archive / path.name).read_bytes(), content)
            manifest = json.loads(Path(result.manifest_file).read_text())
            self.assertTrue(manifest["request_options"]["replace_existing"])
            self.assertEqual(
                Path(manifest["previous_analysis_directory"]).resolve(),
                archive.resolve(),
            )

    async def test_replacement_history_passes_live_analysis_persistence_audit(self):
        old_event = {
            "type": "request_completed",
            "task_id": "standalone-analysis",
            "provider": "openai",
            "model": "test-model",
            "protocol": "responses",
            "timestamp": "2026-08-23T14:25:00Z",
            "attempt": 1,
            "request_id": "req-old",
            "metadata": {"total_tokens": 3},
        }
        state = {
            "source_type": "hunt",
            "hunt_id": "H.1",
            "hunt_state": "FINISHED",
            "status": "complete",
            "coverage": "complete",
            "target_execution_coverage": "complete",
            "result_review_coverage": "complete",
            "artifacts": {"Artifact.Test": {"status": "complete"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "analysis"
            output_dir.mkdir()
            report = output_dir / "review.md"
            events = output_dir / "review.md.events.jsonl"
            manifest = output_dir / "review.md.manifest.json"
            report.write_text("# Old review\n", encoding="utf-8")
            events.write_text(json.dumps(old_event) + "\n", encoding="utf-8")
            manifest.write_text('{"status":"succeeded"}\n', encoding="utf-8")

            result = await self.runner().run(
                request(output_name="review.md"),
                workdir=root,
                output_dir=output_dir,
                replace_existing=True,
            )
            audit = persistence_policy.audit_analysis_tree(output_dir, state)

            self.assertEqual(result.status, "succeeded")
            self.assertTrue(report.is_file())
            self.assertTrue(events.is_file())
            self.assertTrue(manifest.is_file())
            archive = next((output_dir / "previous-analysis").iterdir())
            self.assertTrue((archive / report.name).is_file())
            self.assertTrue((archive / events.name).is_file())
            self.assertTrue((archive / manifest.name).is_file())
            classes = {
                item["path"]: item["classification"]
                for item in audit["files"]
            }
            self.assertEqual(
                classes["review.md.events.jsonl"],
                "bounded_agent_runtime_events",
            )

    async def test_failed_timeout_and_cancelled_replacements_preserve_old_bundle(
        self,
    ):
        failure_cases = (
            (
                "failed",
                FakeAdapter([ProviderResponse('{"ok": "wrong"}')]),
                request(
                    output_schema={
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                    }
                ),
                None,
            ),
            (
                "timeout",
                FakeAdapter(
                    [AgentProviderException(AgentError("timeout", "timed out", False))]
                ),
                request(),
                None,
            ),
            ("cancelled", FakeAdapter(), request(), "cancel"),
        )
        for expected_status, adapter, agent_request, cancellation in failure_cases:
            with (
                self.subTest(status=expected_status),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                output_dir = root / "analysis"
                existing = self.write_existing_bundle(output_dir)
                token = CancellationToken()
                if cancellation:
                    token.cancel()
                result = await self.runner(adapter).run(
                    agent_request,
                    workdir=root,
                    output_dir=output_dir,
                    cancellation=token if cancellation else None,
                    replace_existing=True,
                )

                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.output_file, "")
                self.assertEqual(result.events_file, "")
                self.assertEqual(result.manifest_file, "")
                for path, content in existing.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assertFalse((output_dir / "previous-analysis").exists())

    async def test_replace_promotion_failure_restores_old_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "analysis"
            existing = self.write_existing_bundle(output_dir)
            original_move = agent_runtime._move_path

            def fail_staged_promotion(source, destination):
                if source.parent.name.startswith(".agent-replacement-"):
                    raise OSError("simulated promotion failure")
                return original_move(source, destination)

            with mock.patch.object(
                agent_runtime,
                "_move_path",
                side_effect=fail_staged_promotion,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "previous analysis was restored",
                ):
                    await self.runner().run(
                        request(),
                        workdir=root,
                        output_dir=output_dir,
                        replace_existing=True,
                    )

            for path, content in existing.items():
                self.assertEqual(path.read_bytes(), content)
            previous_root = output_dir / "previous-analysis"
            self.assertEqual(list(previous_root.iterdir()), [])
            self.assertEqual(
                list(output_dir.glob(".agent-replacement-*")),
                [],
            )

    async def test_structured_output_is_validated_before_publication(self):
        adapter = FakeAdapter([ProviderResponse('{"ok": true}')])
        schema = {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(adapter).run(
                request(output_schema=schema), workdir=root, output_dir=root / "analysis"
            )
            self.assertEqual(result.status, "succeeded")

    async def test_invalid_structured_output_is_not_published(self):
        adapter = FakeAdapter([ProviderResponse('{"ok": "wrong"}')])
        schema = {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(adapter).run(
                request(output_schema=schema), workdir=root, output_dir=root / "analysis"
            )
            self.assertEqual(result.status, "failed")
            self.assertFalse((root / "analysis" / "result.json").exists())

    async def test_malformed_empty_response_is_not_published(self):
        adapter = FakeAdapter([ProviderResponse("", "req-empty")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(adapter).run(
                request(), workdir=root, output_dir=root / "analysis"
            )
            self.assertEqual(result.error_classification, "malformed_response")
            self.assertFalse((root / "analysis" / "result.json").exists())

    async def test_unsupported_required_capability_fails_before_evidence_submission(self):
        adapter = FakeAdapter(capabilities=ProviderCapabilities(streaming=False))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(AgentProviderException, "streaming"):
                await self.runner(adapter).run(request(), workdir=root, output_dir=root / "analysis")
            self.assertEqual(adapter.calls, 0)

    async def test_configured_reasoning_requires_provider_capability_before_submission(self):
        adapter = FakeAdapter(
            capabilities=ProviderCapabilities(reasoning_configuration=False),
            reasoning_effort="high",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(AgentProviderException, "reasoning_configuration"):
                await self.runner(adapter).run(
                    request(), workdir=root, output_dir=root / "analysis"
                )
        self.assertEqual(adapter.calls, 0)

    async def test_output_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "remain below"):
                await self.runner().run(
                    request(output_name="../escape.txt"),
                    workdir=root,
                    output_dir=root / "analysis",
                )

    async def test_paths_with_spaces_and_quotes_are_supported(self):
        with tempfile.TemporaryDirectory(prefix='case "quoted" ') as directory:
            root = Path(directory)
            result = await self.runner().run(
                request(output_name='result "quoted".txt'),
                workdir=root,
                output_dir=root / "analysis folder",
            )
            self.assertEqual(result.status, "succeeded")

    async def test_transient_failure_retries_with_distinct_attempt_events(self):
        retryable = AgentProviderException(AgentError("rate_limit", "slow", True, 429, retry_after_seconds=0))
        adapter = FakeAdapter([retryable, ProviderResponse("ok", "req-2")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(max_retries=1, initial_backoff_seconds=0, maximum_backoff_seconds=0),
            ).run(request(), workdir=root, output_dir=root / "analysis")
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(result.attempt_count, 2)
            events = [json.loads(line) for line in Path(result.events_file).read_text().splitlines()]
            self.assertIn("retry_scheduled", [event["type"] for event in events])
            self.assertEqual({event["attempt"] for event in events}, {1, 2})

    async def test_provider_retry_after_is_not_capped_at_thirty_seconds(self):
        retryable = AgentProviderException(
            AgentError(
                "rate_limit",
                "slow",
                True,
                429,
                retry_after_seconds=75,
                retry_after_source="retry-after",
            )
        )
        adapter = FakeAdapter([retryable, ProviderResponse("ok", "req-2")])
        delays = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(max_retries=1),
                sleeper=delays.append,
            ).run(request(), workdir=root, output_dir=root / "analysis")

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(delays, [75])

    def test_rate_limit_without_retry_header_uses_minute_fallback(self):
        runner = self.runner(
            retry_policy=RetryPolicy(jitter_ratio=0),
        )
        delay, source = runner._backoff(
            1,
            None,
            classification="rate_limit",
        )
        self.assertEqual(delay, 60)
        self.assertEqual(source, "minute_limit_fallback")

    async def test_timeout_retry_exhaustion_is_terminal_and_not_published(self):
        timeout = AgentProviderException(
            AgentError("timeout", "provider timeout", True)
        )
        adapter = FakeAdapter([timeout, timeout])
        delays = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(
                    max_retries=1,
                    initial_backoff_seconds=0.5,
                    maximum_backoff_seconds=1,
                    jitter_ratio=0,
                ),
                sleeper=delays.append,
            ).run(request(), workdir=root, output_dir=root / "analysis")
            self.assertEqual(result.status, "timeout")
            self.assertEqual(result.attempt_count, 2)
            self.assertEqual(delays, [0.5])
            self.assertFalse((root / "analysis" / "result.json").exists())

    async def test_two_configured_retries_make_three_attempts_total(self):
        timeout = AgentProviderException(
            AgentError("timeout", "provider timeout", True)
        )
        adapter = FakeAdapter([timeout, timeout, timeout])
        delays = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(
                    max_retries=2,
                    initial_backoff_seconds=0,
                    maximum_backoff_seconds=0,
                    jitter_ratio=0,
                ),
                sleeper=delays.append,
            ).run(request(), workdir=root, output_dir=root / "analysis")

        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.attempt_count, 3)
        self.assertEqual(adapter.calls, 3)
        self.assertEqual(delays, [0, 0])

    async def test_total_timeout_interrupts_blocked_provider_call(self):
        adapter = BlockingAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(max_retries=3),
                timeout_policy=TimeoutPolicy(1, 1, 0.05, 1),
            ).run(request(), workdir=root, output_dir=root / "analysis")

            events = [
                json.loads(line)["type"]
                for line in Path(result.events_file).read_text().splitlines()
            ]
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.error_classification, "timeout")
        self.assertEqual(result.attempt_count, 1)
        self.assertLess(result.elapsed_seconds, 0.5)
        self.assertTrue(adapter.cancelled)
        self.assertIn("request_timed_out", events)

    async def test_total_timeout_includes_retry_backoff(self):
        retryable = AgentProviderException(
            AgentError("rate_limit", "slow", True, 429)
        )
        adapter = FakeAdapter([retryable, ProviderResponse("too-late")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(
                    max_retries=1,
                    initial_backoff_seconds=1,
                    maximum_backoff_seconds=1,
                    jitter_ratio=0,
                ),
                timeout_policy=TimeoutPolicy(1, 1, 0.05, 1),
                sleeper=asyncio.sleep,
            ).run(request(), workdir=root, output_dir=root / "analysis")

        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.attempt_count, 1)
        self.assertEqual(adapter.calls, 1)
        self.assertLess(result.elapsed_seconds, 0.5)

    async def test_cancellation_interrupts_blocked_provider_call(self):
        adapter = BlockingAdapter()
        token = CancellationToken()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operation = asyncio.create_task(
                self.runner(adapter).run(
                    request(),
                    workdir=root,
                    output_dir=root / "analysis",
                    cancellation=token,
                )
            )
            await asyncio.wait_for(adapter.started.wait(), timeout=0.5)
            token.cancel()
            result = await asyncio.wait_for(operation, timeout=0.5)

        self.assertEqual(result.status, "cancelled")
        self.assertEqual(result.attempt_count, 1)
        self.assertTrue(adapter.cancelled)

    async def test_total_timeout_includes_provider_gate_wait(self):
        active_adapter = BlockingAdapter(max_concurrency=1)
        waiting_adapter = BlockingAdapter(max_concurrency=1)
        active_cancellation = CancellationToken()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = asyncio.create_task(
                self.runner(
                    active_adapter,
                    timeout_policy=TimeoutPolicy(1, 1, 1, 1),
                ).run(
                    request(task_id="active", output_name="active.json"),
                    workdir=root,
                    output_dir=root / "analysis",
                    cancellation=active_cancellation,
                )
            )
            await asyncio.wait_for(active_adapter.started.wait(), timeout=0.5)
            waiting = await self.runner(
                waiting_adapter,
                timeout_policy=TimeoutPolicy(1, 1, 0.05, 1),
            ).run(
                request(task_id="waiting", output_name="waiting.json"),
                workdir=root,
                output_dir=root / "analysis",
            )
            active_cancellation.cancel()
            active_result = await asyncio.wait_for(active, timeout=0.5)

        self.assertEqual(waiting.status, "timeout")
        self.assertEqual(waiting_adapter.calls, 0)
        self.assertEqual(active_result.status, "cancelled")

    async def test_authentication_failure_is_not_retried_and_secret_is_redacted(self):
        for provider, inputs in (
            ("openai", HydratedProviderInputs(api_key="test-secret")),
            ("azure_openai", HydratedProviderInputs(azure_client_secret={"client_secret": "test-secret"})),
        ):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as directory:
                adapter = FakeAdapter([
                    AgentProviderException(AgentError("authentication", "bad test-secret", False, 401))
                ], provider=provider)
                adapter.configuration = replace(adapter.configuration, inputs=inputs)
                root = Path(directory)
                result = await self.runner(adapter, retry_policy=RetryPolicy(max_retries=3)).run(
                    request(), workdir=root, output_dir=root / "analysis"
                )
                self.assertEqual(adapter.calls, 1)
                self.assertNotIn("test-secret", result.error)
                self.assertIn("[REDACTED]", result.error)
                self.assertNotIn("test-secret", Path(result.manifest_file).read_text())

    async def test_cancelled_request_is_not_retried_or_published(self):
        token = CancellationToken()
        token.cancel()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(retry_policy=RetryPolicy(max_retries=3)).run(
                request(), workdir=root, output_dir=root / "analysis", cancellation=token
            )
            self.assertEqual(result.status, "cancelled")
            self.assertEqual(result.attempt_count, 1)
            self.assertFalse((root / "analysis" / "result.json").exists())

    async def test_input_and_output_size_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "maximum input"):
                await self.runner().run(
                    request(prompt="word " * 1000), workdir=root, output_dir=root / "analysis"
                )
            adapter = FakeAdapter(
                [
                    ProviderResponse(
                        "word " * 1000,
                        "req-large",
                        AgentUsage(2, 1000, 1002),
                        "completed",
                    )
                ]
            )
            result = await ApiAgentRunner(
                adapter,
                limits=limits(maximum_output_tokens=1),
                retry_policy=RetryPolicy(max_retries=3),
                timeout_policy=TimeoutPolicy(1, 1, 2, 1),
            ).run(request(), workdir=root, output_dir=root / "analysis")
            self.assertEqual(result.error_classification, "output_too_large")
            self.assertEqual(adapter.calls, 1)
            self.assertEqual(result.finish_reason, "completed")
            self.assertEqual(result.usage["output_tokens"], 1000)
            self.assertGreater(result.local_output_tokens, 1)
            manifest = json.loads(Path(result.manifest_file).read_text())
            self.assertEqual(manifest["finish_reason"], "completed")
            self.assertEqual(manifest["usage"]["output_tokens"], 1000)
            self.assertEqual(
                manifest["local_output_tokens"], result.local_output_tokens
            )

    async def test_default_output_limit_is_local_and_not_sent_to_provider(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            await self.runner(adapter).run(
                request(), workdir=root, output_dir=root / "analysis"
            )
        self.assertIsNone(adapter.last_request.max_output_tokens)

    async def test_supported_provider_receives_effective_output_limit(self):
        capabilities = ProviderCapabilities(
            structured_output=True,
            json_mode=True,
            request_output_token_limit=True,
        )
        for requested, expected in ((10, 10), (100, 30), (None, 30)):
            with self.subTest(requested=requested), tempfile.TemporaryDirectory() as directory:
                adapter = FakeAdapter(capabilities=capabilities)
                root = Path(directory)
                result = await self.runner(adapter).run(
                    request(max_output_tokens=requested),
                    workdir=root,
                    output_dir=root / "analysis",
                )

                self.assertEqual(adapter.last_request.max_output_tokens, expected)
                self.assertEqual(result.max_output_tokens_requested, expected)
                self.assertTrue(result.max_output_tokens_sent)
                manifest = json.loads(Path(result.manifest_file).read_text())
                self.assertEqual(
                    manifest["request_options"]["max_output_tokens_requested"],
                    expected,
                )
                self.assertTrue(
                    manifest["request_options"]["max_output_tokens_sent"]
                )

    async def test_nonpositive_request_output_limit_fails_before_provider_call(self):
        for value in (0, -1):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                adapter = FakeAdapter()
                root = Path(directory)
                with self.assertRaisesRegex(ValueError, "greater than zero"):
                    await self.runner(adapter).run(
                        request(max_output_tokens=value),
                        workdir=root,
                        output_dir=root / "analysis",
                    )
                self.assertEqual(adapter.calls, 0)

    async def test_provider_output_limit_failure_is_not_retried(self):
        failure = AgentProviderException(
            AgentError(
                "output_limit_reached",
                "openai output limit reached",
                retryable=False,
                request_id="req-limit",
                usage=AgentUsage(5, 30, 35),
                finish_reason="max_output_tokens",
            )
        )
        adapter = FakeAdapter([failure])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = await self.runner(
                adapter,
                retry_policy=RetryPolicy(max_retries=3),
            ).run(request(), workdir=root, output_dir=root / "analysis")

        self.assertEqual(adapter.calls, 1)
        self.assertEqual(result.error_classification, "output_limit_reached")
        self.assertEqual(result.finish_reason, "max_output_tokens")
        self.assertEqual(result.usage["total_tokens"], 35)

    async def test_reported_usage_and_local_output_measurement_remain_distinct(self):
        adapter = FakeAdapter(
            [
                ProviderResponse(
                    "accepted output",
                    "req-usage",
                    AgentUsage(4, 3, 7),
                    "completed",
                )
            ]
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            agent_runtime.token_budget,
            "estimate_tokens",
            side_effect=[5, 7],
        ):
            root = Path(directory)
            result = await self.runner(adapter).run(
                request(), workdir=root, output_dir=root / "analysis"
            )
            manifest = json.loads(Path(result.manifest_file).read_text())

        self.assertEqual(result.usage["output_tokens"], 3)
        self.assertEqual(result.local_output_tokens, 7)
        self.assertEqual(manifest["usage"]["output_tokens"], 3)
        self.assertEqual(manifest["local_output_tokens"], 7)

    async def test_item_pool_retains_item_result_association(self):
        tasks = [request(task_id="a"), request(task_id="b")]
        results = await run_item_pool(
            tasks,
            max_concurrency=2,
            execute=lambda item: AgentResult(
                item.task_id,
                "succeeded",
                item.task_id,
                "",
                "",
                "",
                0,
            ),
        )
        self.assertEqual(
            {item.task_id: result.task_id for item, result in results},
            {"a": "a", "b": "b"},
        )

    async def test_item_pool_uses_bounded_scheduler_and_reports_status(self):
        statuses = []
        tasks = [request(task_id=str(index)) for index in range(5)]

        results = await run_agent_items(
            tasks,
            max_concurrency=2,
            execute=lambda item: AgentResult(
                item.task_id,
                "succeeded",
                item.task_id,
                "",
                "",
                "",
                0,
            ),
            on_status_change=statuses.append,
        )

        self.assertEqual(
            [result.task_id for result in results],
            ["0", "1", "2", "3", "4"],
        )
        self.assertTrue(statuses)
        self.assertLessEqual(max(status.active for status in statuses), 2)
        self.assertTrue(
            all(
                status.submitted
                == (
                    status.queued
                    + status.completed
                    + status.active
                    + status.abandoned
                )
                for status in statuses
            )
        )
        self.assertEqual(statuses[-1].submitted, 5)
        self.assertEqual(statuses[-1].completed, 5)
        self.assertEqual(statuses[-1].failed, 0)
        self.assertEqual(statuses[-1].abandoned, 0)
        self.assertTrue(statuses[-1].source_exhausted)

    async def test_provider_gate_enforces_shared_concurrency(self):
        class TrackingAdapter(FakeAdapter):
            def __init__(self):
                super().__init__(
                    [ProviderResponse("one"), ProviderResponse("two")],
                    base_url="https://limit-test.invalid",
                    max_concurrency=1,
                )
                self.active = 0
                self.maximum_active = 0
                self.lock = asyncio.Lock()

            async def execute(self, request, **kwargs):
                async with self.lock:
                    self.active += 1
                    self.maximum_active = max(self.maximum_active, self.active)
                try:
                    await asyncio.sleep(0.03)
                    return await super().execute(request, **kwargs)
                finally:
                    async with self.lock:
                        self.active -= 1

        adapter = TrackingAdapter()
        runner = self.runner(adapter)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [
                request(task_id="one", output_name="one.txt"),
                request(task_id="two", output_name="two.txt"),
            ]
            results = await run_agent_items(
                tasks,
                max_concurrency=2,
                execute=lambda item: runner.run(
                    item, workdir=root, output_dir=root / "analysis"
                ),
            )
        self.assertEqual([result.status for result in results], ["succeeded", "succeeded"])
        self.assertEqual(adapter.maximum_active, 1)

    async def test_rate_limit_cooldown_blocks_queued_sibling_requests(self):
        retryable = AgentProviderException(
            AgentError(
                "rate_limit",
                "slow",
                True,
                429,
                retry_after_seconds=0.05,
                retry_after_source="retry-after",
            )
        )

        class CooldownAdapter(FakeAdapter):
            def __init__(self):
                super().__init__(
                    [
                        retryable,
                        ProviderResponse("ok-one"),
                        ProviderResponse("ok-two"),
                    ],
                    base_url="https://cooldown-test.invalid",
                    max_concurrency=1,
                )
                self.call_times = []

            async def execute(self, request, **kwargs):
                self.call_times.append(asyncio.get_running_loop().time())
                return await super().execute(request, **kwargs)

        adapter = CooldownAdapter()
        runner = self.runner(
            adapter,
            retry_policy=RetryPolicy(max_retries=1, jitter_ratio=0),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = await run_agent_items(
                [
                    request(task_id="one", output_name="one.txt"),
                    request(task_id="two", output_name="two.txt"),
                ],
                max_concurrency=2,
                execute=lambda item: runner.run(
                    item,
                    workdir=root,
                    output_dir=root / "analysis",
                ),
            )

        self.assertEqual([result.status for result in results], ["succeeded", "succeeded"])
        self.assertEqual(len(adapter.call_times), 3)
        self.assertGreaterEqual(
            min(adapter.call_times[1:]) - adapter.call_times[0],
            0.04,
        )

    async def test_distinct_provider_gates_do_not_block_each_other(self):
        arrived = 0
        barrier = asyncio.Event()
        arrival_lock = asyncio.Lock()

        class BarrierAdapter(FakeAdapter):
            async def execute(self, request, **kwargs):
                nonlocal arrived
                async with arrival_lock:
                    arrived += 1
                    if arrived == 2:
                        barrier.set()
                await asyncio.wait_for(barrier.wait(), timeout=1)
                return await super().execute(request, **kwargs)

        adapters = {
            "openai": BarrierAdapter(
                provider="openai",
                base_url="https://cross-provider-openai.invalid",
                max_concurrency=1,
            ),
            "azure_openai": BarrierAdapter(
                provider="azure_openai",
                base_url="https://cross-provider-azure.invalid",
                max_concurrency=1,
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [
                request(task_id="openai", output_name="openai.txt"),
                request(task_id="azure_openai", output_name="azure.txt"),
            ]
            results = await run_agent_items(
                tasks,
                max_concurrency=2,
                execute=lambda item: self.runner(adapters[item.task_id]).run(
                    item, workdir=root, output_dir=root / "analysis"
                ),
            )
        self.assertEqual([result.status for result in results], ["succeeded", "succeeded"])
        self.assertCountEqual(
            [result.provider for result in results], ["openai", "azure_openai"]
        )

    async def test_distinct_protocol_gates_do_not_block_each_other(self):
        arrived = 0
        barrier = asyncio.Event()
        arrival_lock = asyncio.Lock()

        class BarrierAdapter(FakeAdapter):
            async def execute(self, request, **kwargs):
                nonlocal arrived
                async with arrival_lock:
                    arrived += 1
                    if arrived == 2:
                        barrier.set()
                await asyncio.wait_for(barrier.wait(), timeout=1)
                return await super().execute(request, **kwargs)

        adapters = {
            "api": BarrierAdapter(max_concurrency=1, protocol="responses"),
            "codex": BarrierAdapter(
                max_concurrency=1, protocol="codex_app_server"
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [
                request(task_id="api", output_name="api.txt"),
                request(task_id="codex", output_name="codex.txt"),
            ]
            results = await run_agent_items(
                tasks,
                max_concurrency=2,
                execute=lambda item: self.runner(adapters[item.task_id]).run(
                    item, workdir=root, output_dir=root / "analysis"
                ),
            )
        self.assertEqual([result.status for result in results], ["succeeded", "succeeded"])

    async def test_cancellation_is_isolated_between_workers(self):
        cancelled = CancellationToken()
        cancelled.cancel()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [request(task_id="cancelled"), request(task_id="healthy")]
            pooled = await run_item_pool(
                tasks,
                max_concurrency=2,
                execute=lambda item: self.runner().run(
                    item,
                    workdir=root,
                    output_dir=root / item.task_id,
                    cancellation=cancelled if item.task_id == "cancelled" else None,
                ),
            )
        results = {item.task_id: result for item, result in pooled}
        self.assertEqual(results["cancelled"].status, "cancelled")
        self.assertEqual(results["healthy"].status, "succeeded")

if __name__ == "__main__":
    unittest.main()
