"""Accounting at the shared provider boundary, independent of UI progress."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from test_agent_runtime import FakeAdapter, request
from vraptor.agent import runtime
from vraptor.agent.providers import _usage
from vraptor.artifacts import persistence


class SnapshotAdapter(FakeAdapter):
    def __init__(self, *, block=False, missing_final=False):
        super().__init__()
        self.block = block
        self.missing_final = missing_final
        self.started = asyncio.Event()

    async def execute(self, request, *, progress_callback, attempt, **kwargs):
        for count in (5, 5, 8):
            progress_callback(runtime.AgentEvent(
                type="usage_updated", task_id=request.task_id,
                provider="openai", model="test-model", protocol="responses",
                timestamp=runtime.now_utc(), attempt=attempt, request_id="stream-1",
                metadata={"input_tokens": count, "output_tokens": 2,
                          "total_tokens": count + 2, "usage_status": "partial"},
            ))
        self.started.set()
        if self.block:
            await asyncio.Event().wait()
        return runtime.ProviderResponse(
            "ok", "stream-1",
            runtime.AgentUsage() if self.missing_final else runtime.AgentUsage(8, 3, 11),
        )


class AgentUsageLoggingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.records = []
        logger = SimpleNamespace(record_token_usage=lambda **row: self.records.append(row))
        patch = mock.patch.object(runtime.operation_log, "current_session", return_value=logger)
        patch.start()
        self.addCleanup(patch.stop)

    def runner(self, adapter=None, **kwargs):
        return runtime.ApiAgentRunner(
            adapter or FakeAdapter(),
            retry_policy=kwargs.pop("retry_policy", runtime.RetryPolicy(max_retries=0)),
            timeout_policy=kwargs.pop("timeout_policy", runtime.TimeoutPolicy(1, 1, 5, 1)),
            sleeper=kwargs.pop("sleeper", lambda _: None),
            persist_runtime_files=kwargs.pop("persist_runtime_files", False),
            **kwargs,
        )

    async def run_request(self, runner=None, task=None, **kwargs):
        return await (runner or self.runner()).run(
            task or request(), workdir=self.root, output_dir=self.root / "output", **kwargs
        )

    def test_known_zero_differs_from_missing_usage_without_changing_numeric_contract(self):
        self.assertEqual(runtime.AgentUsage().status, "unavailable")
        zero = runtime.AgentUsage(availability="reported")
        self.assertEqual(zero.status, "reported")
        self.assertEqual(zero.as_dict(), {
            "input_tokens": 0, "output_tokens": 0,
            "total_tokens": 0, "cached_input_tokens": 0,
        })
        self.assertEqual(runtime.AgentUsage(2, 1).status, "reported")
        self.assertEqual(runtime.AgentUsage(2, availability="partial").status, "partial")

    async def test_success_counts_final_snapshot_once_without_progress_callback(self):
        result = await self.run_request(self.runner(SnapshotAdapter(), persist_runtime_files=True))
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(self.records), 1)
        record = self.records[0]
        self.assertEqual(record["usage"]["total_tokens"], 11)
        self.assertEqual(record["usage_status"], "reported")
        self.assertEqual(record["request_id"], "stream-1")
        self.assertEqual(record["status"], "succeeded")
        self.assertGreaterEqual(record["elapsed_seconds"], 0)
        event_path = Path(result.events_file)
        classification = persistence.classify_analysis_file(
            event_path, analysis_root=event_path.parent, source_ids=["source-test"]
        )
        self.assertEqual(classification["classification"], "bounded_agent_runtime_events")

    async def test_retry_preserves_usage_of_both_attempts(self):
        error = runtime.AgentProviderException(runtime.AgentError(
            "server_error", "retry", retryable=True,
            request_id="failed-request", usage=runtime.AgentUsage(3, 2, 5),
        ))
        runner = self.runner(FakeAdapter(outcomes=[error, runtime.ProviderResponse(
            "ok", "success-request", runtime.AgentUsage(2, 1, 3)
        )]), retry_policy=runtime.RetryPolicy(max_retries=1))
        result = await self.run_request(runner)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual([row["attempt"] for row in self.records], [1, 2])
        self.assertEqual([row["status"] for row in self.records], ["failed", "succeeded"])
        self.assertEqual(sum(row["usage"]["total_tokens"] for row in self.records), 8)
        self.assertEqual(len({row["invocation_id"] for row in self.records}), 1)

    async def test_correction_ordinal_survives_transport_retries(self):
        error = runtime.AgentProviderException(runtime.AgentError(
            "server_error", "retry", retryable=True,
            request_id="failed-request", usage=runtime.AgentUsage(3, 2, 5),
        ))
        runner = self.runner(FakeAdapter(outcomes=[error, runtime.ProviderResponse(
            "ok", "success-request", runtime.AgentUsage(2, 1, 3)
        )]), retry_policy=runtime.RetryPolicy(max_retries=1))
        await self.run_request(runner, request(metadata={"attempt": 3, "stage": "host-synthesis"}))
        self.assertEqual([row["attempt"] for row in self.records], [1, 2])
        self.assertEqual([row["correction_attempt"] for row in self.records], [2, 2])
        self.assertEqual(sum(row["usage"]["total_tokens"] for row in self.records), 8)

    async def test_validation_correction_counts_both_successful_provider_responses(self):
        from vraptor.analyze import runtime as analysis_runtime

        runner = self.runner(FakeAdapter(outcomes=[
            runtime.ProviderResponse("invalid", "initial", runtime.AgentUsage(3, 2, 5)),
            runtime.ProviderResponse("valid", "corrected", runtime.AgentUsage(4, 2, 6)),
        ]))

        def validate(_task, output):
            if output != "valid":
                raise ValueError("synthesis story is missing a required section")
            return {"status": "complete"}

        accepted, _ = await analysis_runtime._validated_pool_async(
            [request(metadata={"stage": "host-synthesis"})], max_concurrency=1,
            execute=lambda task: self.run_request(runner, task), validate=validate,
        )
        self.assertTrue(accepted)
        self.assertEqual([row["correction_attempt"] for row in self.records], [0, 1])
        self.assertEqual([row["status"] for row in self.records], ["succeeded", "succeeded"])
        self.assertEqual(sum(row["usage"]["total_tokens"] for row in self.records), 11)

    async def test_missing_usage_remains_unavailable(self):
        await self.run_request(self.runner(FakeAdapter(outcomes=[runtime.ProviderResponse("ok")])))
        self.assertEqual(self.records[0]["usage_status"], "unavailable")

    async def test_ledger_and_manifest_preserve_retry_counters_without_double_counting(self):
        failed_raw = {"input_tokens": 5, "output_tokens": 2,
                      "output_tokens_details": {"reasoning_tokens": 1}}
        final_raw = {"input_tokens": 8, "output_tokens": 3,
                     "input_tokens_details": {"cached_tokens": 4, "cache_write_tokens": 2}}
        error = runtime.AgentProviderException(runtime.AgentError(
            "server_error", "retry", retryable=True, request_id="failed",
            usage=_usage(failed_raw),
        ))
        runner = self.runner(FakeAdapter(outcomes=[error, runtime.ProviderResponse(
            "ok", "succeeded", _usage(final_raw),
        )]), retry_policy=runtime.RetryPolicy(max_retries=1), persist_runtime_files=True)
        result = await self.run_request(runner)
        manifest = json.loads(Path(result.manifest_file).read_text())
        self.assertEqual(result.raw_usage, final_raw)
        self.assertEqual([row["usage"] for row in result.attempt_usage], [failed_raw, final_raw])
        self.assertEqual(manifest["attempt_usage"], list(result.attempt_usage))
        self.assertEqual([row["request_id"] for row in self.records], ["failed", "succeeded"])
        self.assertEqual(sum(row["usage"]["total_tokens"] for row in self.records), 18)
        self.assertEqual(self.records[-1]["usage"]["cached_input_tokens"], 4)
        self.assertNotIn("raw_usage", self.records[-1])

    async def test_empty_reported_object_remains_distinct_from_absent_raw_usage(self):
        result = await self.run_request(self.runner(FakeAdapter(outcomes=[
            runtime.ProviderResponse("ok", "empty", _usage({})),
        ])))
        self.assertEqual(result.raw_usage, {})
        self.assertEqual(result.attempt_usage[0]["usage"], {})
        self.assertEqual(self.records[0]["usage_status"], "unavailable")

    async def test_missing_final_usage_keeps_latest_partial_snapshot(self):
        events = []
        result = await self.run_request(
            self.runner(SnapshotAdapter(missing_final=True)),
            progress_callback=events.append,
        )
        self.assertEqual(self.records[0]["usage_status"], "partial")
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 10)
        self.assertEqual(result.usage["total_tokens"], 10)
        completed = next(event for event in events if event.type == "request_completed")
        self.assertEqual(completed.metadata["total_tokens"], 10)

    async def test_unavailable_usage_does_not_emit_known_zero_progress_counters(self):
        events = []
        await self.run_request(
            self.runner(FakeAdapter(outcomes=[runtime.ProviderResponse("ok", "unknown-usage")])),
            progress_callback=events.append,
        )
        completed = next(event for event in events if event.type == "request_completed")
        self.assertNotIn("total_tokens", completed.metadata)
        self.assertEqual(self.records[0]["usage_status"], "unavailable")

    async def test_missing_final_usage_reconciles_ledger_and_progress_without_conflict(self):
        from vraptor.logging.usage_report import summarize

        for adapter, expected in (
            (SnapshotAdapter(missing_final=True), 10),
            (FakeAdapter(outcomes=[runtime.ProviderResponse("ok", "unknown-usage")]), 0),
        ):
            with self.subTest(expected=expected):
                with runtime.operation_log.OperationLogger("analyze") as logger:
                    logger.bind_case(self.root, f"usage-{expected}")

                    def progress(event):
                        logger.emit("progress", phase="provider", status=event.type,
                                    request_id=event.request_id, task_id=event.task_id,
                                    attempt=event.attempt, **event.metadata)

                    with mock.patch.object(runtime.operation_log, "current_session", return_value=logger):
                        await self.run_request(self.runner(adapter), progress_callback=progress)
                report = summarize(logger.token_usage_path.parent)
                self.assertEqual(report["operation_count"], 1)
                self.assertEqual(report["totals"]["total_tokens"], expected)
                codes = {issue["code"] for issue in report["coverage"]["issues"]}
                self.assertNotIn("conflicting_request_counters", codes)
                self.assertNotIn("operation_excluded_due_to_conflict", codes)
                self.assertFalse(report["latest_operation"]["usage_complete"])

    async def test_timeout_preserves_latest_snapshot_without_summing_updates(self):
        runner = self.runner(SnapshotAdapter(block=True),
                             timeout_policy=runtime.TimeoutPolicy(1, 1, 0.05, 1))
        result = await self.run_request(runner)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0]["usage_status"], "partial")
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 10)

    async def test_task_cancellation_flushes_partial_usage(self):
        adapter = SnapshotAdapter(block=True)
        task = asyncio.create_task(self.run_request(self.runner(adapter)))
        await adapter.started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0]["status"], "cancelled")
        self.assertEqual(self.records[0]["usage_status"], "partial")
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 10)

    async def test_cancellation_token_flushes_partial_usage(self):
        adapter = SnapshotAdapter(block=True)
        token = runtime.CancellationToken()
        task = asyncio.create_task(self.run_request(self.runner(adapter), cancellation=token))
        await adapter.started.wait()
        token.cancel()
        result = await task
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0]["usage_status"], "partial")

    async def test_cancel_during_retry_delay_does_not_duplicate_failed_attempt(self):
        token = runtime.CancellationToken()

        async def cancel_sleep(_):
            token.cancel()
            await asyncio.sleep(0)

        error = runtime.AgentProviderException(runtime.AgentError(
            "server_error", "retry", retryable=True, usage=runtime.AgentUsage(3, 2, 5),
        ))
        runner = self.runner(FakeAdapter(outcomes=[error]), sleeper=cancel_sleep,
                             retry_policy=runtime.RetryPolicy(max_retries=1))
        result = await self.run_request(runner, cancellation=token)
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 5)

    async def test_pre_cancelled_request_does_not_record_an_undispatched_attempt(self):
        token = runtime.CancellationToken()
        token.cancel()
        result = await self.run_request(cancellation=token)
        self.assertEqual(result.status, "cancelled")
        self.assertEqual(self.records, [])

    async def test_output_validation_failure_keeps_reported_usage(self):
        adapter = FakeAdapter(outcomes=[runtime.ProviderResponse(
            "not JSON", "invalid-output", runtime.AgentUsage(5, 2, 7)
        )])
        result = await self.run_request(self.runner(adapter), request(output_schema={"type": "object"}))
        self.assertEqual(result.status, "failed")
        self.assertEqual(self.records[0]["usage_status"], "reported")
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 7)

    async def test_usage_is_recorded_before_result_file_publication(self):
        with (mock.patch.object(runtime.atomic_io, "write_text_atomic", side_effect=OSError("disk full")), self.assertRaises(OSError)):
            await self.run_request(self.runner(persist_runtime_files=True))
        self.assertEqual(len(self.records), 1)
        self.assertEqual(self.records[0]["usage"]["total_tokens"], 3)

    async def test_concurrent_runtime_requests_write_one_operation_summary(self):
        with runtime.operation_log.OperationLogger("analyze") as logger:
            logger.bind_case(self.root, "example-case")
            with mock.patch.object(runtime.operation_log, "current_session", return_value=logger):
                await asyncio.gather(*(
                    self.run_request(task=request(output_name=f"{i}.txt"))
                    for i in range(20)
                ))
        rows = [json.loads(line) for line in logger.token_usage_path.read_text().splitlines()]
        self.assertEqual([row["event"] for row in rows], ["operation_started"] + ["request_usage"] * 20 + ["operation_summary"])
        self.assertEqual(len({row["invocation_id"] for row in rows if row["event"] == "request_usage"}), 20)
        summary = rows[-1]
        self.assertEqual(summary["total_tokens"], 60)
        self.assertEqual(summary["attempts"], 20)
        self.assertEqual(summary["groups"][0]["reported_requests"], 20)
        self.assertTrue(summary["usage_complete"])
        self.assertTrue(summary["log_complete"])


if __name__ == "__main__":
    unittest.main()
