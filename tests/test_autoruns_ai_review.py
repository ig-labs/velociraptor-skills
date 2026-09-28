import asyncio
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.autoruns import ai_review as autoruns_ai_review


def _test_execution(
    *,
    model: str = "test-model",
    max_concurrency: int = 1,
) -> ResolvedAgentExecution:
    return ResolvedAgentExecution(
        route=ResolvedAgentRoute(
            provider="openai",
            model=model,
            protocol="responses",
            timeout_seconds=60,
            max_retries=1,
            max_concurrency=max_concurrency,
        )
    )


def classification_response(*, suspicious=(), potential_golden=()):
    lines = [
        f"SUSPICIOUS\t{item['row_id']}\t{item['severity']}\t{item['reason']}"
        for item in suspicious
    ]
    lines.extend(
        f"POTENTIAL_GOLDEN\t{item['row_id']}\t{item['reason']}"
        for item in potential_golden
    )
    return "\n".join([*lines, "END"])


def focused_response(recommendations):
    return "\n".join(
        [
            *("\t".join(
                (
                    "RECOMMENDATION",
                    item["review_id"],
                    item["disposition"],
                    item["severity"],
                    item["confidence"],
                    str(item["drilldown_recommended"]).lower(),
                    item["reason"],
                )
            ) for item in recommendations),
            "END",
        ]
    )


class AutorunsAiReviewTest(unittest.TestCase):
    def test_line_v2_prompt_contract_is_stable(self):
        csv_text = "RowId,ExampleCategory,ImagePath,LaunchString,Signer,Total\n"
        general = autoruns_ai_review._prompt(
            csv_text=csv_text,
            part_number=1,
            part_count=0,
            row_count=0,
        )
        focused = autoruns_ai_review._focused_stack_prompt(
            csv_text=csv_text,
            part_number=1,
            part_count=0,
            row_count=0,
            use_case="autoruns-lolbin",
        )

        self.assertIn("SUSPICIOUS<TAB>RowId<TAB>severity<TAB>reason", general)
        self.assertIn("finish with END", focused)
        self.assertNotIn("required JSON", general)

    def test_review_protocols_preserve_tabs_in_final_reason(self):
        suspicious, potential_golden = autoruns_ai_review._validate_result(
            "SUSPICIOUS\t1\thigh\tSuspicious\tlaunch.\n"
            "POTENTIAL_GOLDEN\t2\tStable\tupdater.\nEND",
            rows=[{"RowId": "1"}, {"RowId": "2"}],
        )
        focused = autoruns_ai_review._validate_focused_result(
            "RECOMMENDATION\treview-1\tnotable\tlow\thigh\ttrue\tConfirm\towner.\nEND",
            rows=[{"ReviewId": "review-1"}],
        )

        self.assertEqual(suspicious[0]["reason"], "Suspicious\tlaunch.")
        self.assertEqual(potential_golden[0]["reason"], "Stable\tupdater.")
        self.assertEqual(focused[0]["reason"], "Confirm\towner.")

    def test_streaming_review_is_lazy_bounded_and_persists_no_parts(self):
        yielded = 0
        observed_at_first_execute = []
        observed_row_ids = []

        def rows():
            nonlocal yielded
            for index in range(100):
                yielded += 1
                yield {
                    "ImagePath": rf"c:\program files\vendor\app-{index}.exe",
                    "LaunchString": f"app-{index}.exe --background",
                    "Signer": "(verified) vendor",
                    "ExampleCategory": "Logon",
                    "Total": 1,
                }

        def execute(**kwargs):
            if not observed_at_first_execute:
                observed_at_first_execute.append(yielded)
            csv_text = kwargs["prompt"].rsplit("CSV:\n", 1)[1]
            supplied = list(csv.DictReader(io.StringIO(csv_text)))
            observed_row_ids.extend(row["RowId"] for row in supplied)
            return classification_response(), {"input_tokens": len(supplied)}

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            result = autoruns_ai_review.classify_streaming_rows(
                rows(),
                workdir=workdir,
                maximum_evidence_tokens=180,
                token_encoding="cl100k_base",
                executor=execute,
                execution=_test_execution(),
            )
            files = list(workdir.iterdir())

        self.assertEqual(result["manifest"]["reviewed_group_count"], 100)
        self.assertEqual(result["manifest"]["represented_row_count"], 100)
        self.assertGreater(result["manifest"]["part_count"], 1)
        self.assertLess(observed_at_first_execute[0], 100)
        self.assertEqual(observed_row_ids, [str(index) for index in range(1, 101)])
        self.assertFalse(result["manifest"]["runtime_files_persisted"])
        self.assertEqual(files, [])

    def test_streaming_timing_separates_acquisition_and_concurrent_calls(self):
        clock = [0.0]

        def rows():
            for index in range(2):
                clock[0] += 5
                yield {"ImagePath": f"app{index}", "Total": 1}

        async def pool(parts, *, execute, on_result, **kwargs):
            materialized = list(parts)
            await asyncio.gather(*(
                run_part(part, execute, on_result) for part in materialized
            ))

        async def run_part(part, execute, on_result):
            on_result(part, await execute(part))

        entered = 0
        released = asyncio.Event()

        async def execute(**kwargs):
            nonlocal entered
            entered += 1
            if entered == 2:
                clock[0] += 7
                released.set()
            await released.wait()
            return classification_response(), {}

        def chunks(rows, **kwargs):
            for index, row in enumerate(rows, 1):
                yield index, [row], "unused", 1

        with (
            mock.patch.object(autoruns_ai_review, "time") as fake_time,
            mock.patch.object(autoruns_ai_review, "_iter_chunks_with_fields", chunks),
            mock.patch.object(autoruns_ai_review.agent_runtime, "run_item_pool", pool),
            mock.patch.object(autoruns_ai_review.operation_log, "emit") as emit,
        ):
            fake_time.monotonic.side_effect = lambda: clock[0]
            manifest = autoruns_ai_review.classify_streaming_rows(
                rows(), workdir=Path("."), executor=execute,
                execution=_test_execution(max_concurrency=2),
            )["manifest"]
        self.assertEqual(manifest["source_acquisition_seconds"], 10)
        self.assertEqual(manifest["model_execution_seconds"], 7)
        self.assertEqual(manifest["duration_seconds"], 17)
        timing = [call for call in emit.call_args_list
                  if call.args == ("autoruns_review_timing",)]
        self.assertEqual(timing[0].kwargs["model_execution_seconds"], 7)

    def test_streaming_timing_includes_retried_model_calls(self):
        clock = [0.0]
        attempts = 0

        def execute(**kwargs):
            nonlocal attempts
            attempts += 1
            clock[0] += 3
            return ("BROKEN" if attempts == 1 else classification_response()), {}

        with mock.patch.object(autoruns_ai_review, "time") as fake_time:
            fake_time.monotonic.side_effect = lambda: clock[0]
            manifest = autoruns_ai_review.classify_streaming_rows(
                [{"ImagePath": "app", "Total": 1}], workdir=Path("."),
                executor=execute, execution=_test_execution(),
            )["manifest"]
        self.assertEqual(manifest["source_acquisition_seconds"], 0)
        self.assertEqual(manifest["model_execution_seconds"], 6)
        self.assertEqual(manifest["duration_seconds"], 6)
        self.assertEqual(manifest["retried_part_count"], 1)

    def test_streaming_timing_includes_preacquired_summary(self):
        with mock.patch.object(autoruns_ai_review, "time") as fake_time:
            fake_time.monotonic.return_value = 100
            manifest = autoruns_ai_review.classify_streaming_rows(
                [{"ImagePath": "app", "Total": 1}], workdir=Path("."),
                executor=lambda **kwargs: (classification_response(), {}),
                execution=_test_execution(), initial_source_acquisition_seconds=75,
            )["manifest"]
        self.assertEqual(manifest["source_acquisition_seconds"], 75)
        self.assertEqual(manifest["model_execution_seconds"], 0)
        self.assertEqual(manifest["duration_seconds"], 75)

    def test_streaming_acquisition_and_model_intervals_can_overlap(self):
        clock = [0.0]
        released = asyncio.Event()
        entered = 0

        def rows():
            for index in range(2):
                clock[0] += 5
                yield {"ImagePath": f"app{index}", "Total": 1}

        def chunks(rows, **kwargs):
            for index, row in enumerate(rows, 1):
                yield index, [row], "unused", 1

        async def execute(**kwargs):
            nonlocal entered
            entered += 1
            if entered == 2:
                clock[0] += 7
                released.set()
            await released.wait()
            return classification_response(), {}

        async def run_part(part, execute, on_result):
            on_result(part, await execute(part))

        async def pool(parts, *, execute, on_result, **kwargs):
            iterator = iter(parts)
            first = asyncio.create_task(run_part(next(iterator), execute, on_result))
            await asyncio.sleep(0)  # Start a model call before acquiring part two.
            second = asyncio.create_task(run_part(next(iterator), execute, on_result))
            await asyncio.gather(first, second)
            list(iterator)  # Exhaust and validate the source.

        with (
            mock.patch.object(autoruns_ai_review, "time") as fake_time,
            mock.patch.object(autoruns_ai_review, "_iter_chunks_with_fields", chunks),
            mock.patch.object(autoruns_ai_review.agent_runtime, "run_item_pool", pool),
        ):
            fake_time.monotonic.side_effect = lambda: clock[0]
            manifest = autoruns_ai_review.classify_streaming_rows(
                rows(), workdir=Path("."), executor=execute,
                execution=_test_execution(max_concurrency=2),
            )["manifest"]
        self.assertEqual(manifest["source_acquisition_seconds"], 10)
        self.assertEqual(manifest["model_execution_seconds"], 12)
        self.assertEqual(manifest["duration_seconds"], 17)

    def test_streaming_timing_rejects_invalid_preacquisition(self):
        for value in (-1, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaisesRegex(
                autoruns_ai_review.AutorunsAiReviewError, "finite and nonnegative"
            ):
                autoruns_ai_review.classify_streaming_rows(
                    [], workdir=Path("."), initial_source_acquisition_seconds=value,
                )

    def test_streaming_review_reports_each_safe_attempt_failure(self):
        attempts = 0
        diagnostics = mock.Mock()

        def execute(**kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return "BROKEN\nEND", {}
            raise RuntimeError(
                "provider API request failed: openai provider_error"
            )

        rows = [
            {
                "ImagePath": r"c:\program files\vendor\app.exe",
                "LaunchString": "app.exe --background",
                "Signer": "(verified) vendor",
                "ExampleCategory": "Logon",
                "Total": 1,
            }
        ]
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(
                autoruns_ai_review.agent_diagnostics,
                "current_session",
                return_value=diagnostics,
            ),
            self.assertRaisesRegex(
                autoruns_ai_review.AutorunsAiReviewError,
                r"provider API request failed: openai provider_error.*"
                r"attempt 1: unsupported_record.*"
                r"attempt 2: provider_request_failed",
            ),
        ):
            autoruns_ai_review.classify_streaming_rows(
                rows,
                workdir=Path(temp_dir),
                maximum_evidence_tokens=1_000,
                token_encoding="cl100k_base",
                executor=execute,
                execution=_test_execution(),
            )

        self.assertEqual(attempts, 2)
        self.assertEqual(diagnostics.record_stage.call_count, 2)
        self.assertEqual(
            diagnostics.record_stage.call_args_list[0].kwargs["failure_category"],
            "unsupported_record",
        )
        self.assertEqual(
            diagnostics.record_stage.call_args_list[1].kwargs["failure_category"],
            "provider_request_failed",
        )

    def test_streaming_review_keeps_duplicate_identity_guard(self):
        row = {
            "ImagePath": r"c:\program files\vendor\app.exe",
            "LaunchString": "app.exe --background",
            "Signer": "(verified) vendor",
            "ExampleCategory": "Logon",
            "Total": 1,
        }

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            self.assertRaisesRegex(
                autoruns_ai_review.AutorunsAiReviewError,
                "duplicate identity",
            ),
        ):
            autoruns_ai_review.classify_streaming_rows(
                [row, dict(row)],
                workdir=Path(temp_dir),
                maximum_evidence_tokens=1_000,
                token_encoding="cl100k_base",
                executor=lambda **_kwargs: ("END", {}),
                execution=_test_execution(),
            )

    def test_focused_streaming_review_persists_no_queue_or_part_files(self):
        def execute(**kwargs):
            csv_text = kwargs["prompt"].rsplit("CSV:\n", 1)[1]
            supplied = list(csv.DictReader(io.StringIO(csv_text)))
            return focused_response(
                [
                    {
                        "review_id": row["ReviewId"],
                        "disposition": "notable",
                        "severity": "low",
                        "confidence": "high",
                        "drilldown_recommended": True,
                        "reason": "Confirm the remote-management owner.",
                    }
                    for row in supplied
                ]
            ), {"input_tokens": len(supplied)}

        rows = [
            {
                field: (
                    f"review-{index}"
                    if field == "ReviewId"
                    else "value"
                )
                for field in autoruns_ai_review.FOCUSED_REVIEW_FIELDS
            }
            for index in range(3)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            result = autoruns_ai_review.review_focused_rows_streaming(
                iter(rows),
                workdir=workdir,
                use_case="autoruns-rmm",
                maximum_evidence_tokens=200,
                executor=execute,
                execution=_test_execution(),
            )
            files = list(workdir.iterdir())

        self.assertEqual(len(result["recommendations"]), 3)
        self.assertEqual(result["manifest"]["reviewed_group_count"], 3)
        self.assertFalse(result["manifest"]["runtime_files_persisted"])
        self.assertEqual(files, [])

    def test_api_review_uses_shared_transient_runner(self):
        route = ResolvedAgentRoute(
            provider="openai",
            model="gpt-default",
            protocol="responses",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=4,
        )
        execution = ResolvedAgentExecution(route=route)
        runner = mock.Mock()
        runner.run.return_value = autoruns_ai_review.agent_runtime.AgentResult(
            task_id="autoruns-test",
            status="succeeded",
            output="END",
            output_file="",
            events_file="",
            manifest_file="",
            elapsed_seconds=1.0,
            usage={"input_tokens": 10, "output_tokens": 5},
        )

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(
                autoruns_ai_review,
                "create_agent_runner",
                return_value=runner,
            ) as runner_type,
        ):
            workdir = Path(temp_dir)
            active_runner = autoruns_ai_review._review_runner(execution=execution)
            payload, usage = asyncio.run(autoruns_ai_review.run_agent_text_async(
                prompt="review these rows",
                workdir=workdir,
                runner=active_runner,
            ))

        runner_execution = runner_type.call_args.args[0]
        self.assertIs(runner_execution, execution)
        self.assertFalse(runner_type.call_args.kwargs["persist_runtime_files"])
        task = runner.run.call_args.args[0]
        self.assertEqual(task.prompt, "review these rows")
        self.assertEqual(task.output_schema, "")
        self.assertEqual(runner.run.call_args.kwargs["workdir"], workdir)
        self.assertEqual(
            runner.run.call_args.kwargs["output_dir"],
            workdir / ".api-runtime",
        )
        self.assertEqual(payload, "END")
        self.assertEqual(usage["input_tokens"], 10)

    def test_review_rejects_unknown_or_duplicate_row_ids(self):
        rows = [
            {
                "RowId": "1",
                "ExampleCategory": "Logon",
                "ImagePath": "one.exe",
                "LaunchString": "one.exe",
                "Signer": "",
                "Total": "1",
            }
        ]
        with self.assertRaises(autoruns_ai_review.AutorunsAiReviewError):
            autoruns_ai_review._validate_result(
                "SUSPICIOUS\t2\thigh\tUnknown row.\nEND",
                rows=rows,
            )

    def test_stream_row_id_is_the_one_based_aggregate_row_number(self):
        rows = [
            {
                "RowId": "1",
                "ExampleCategory": "Scheduled Tasks",
                "ImagePath": r"c:\windows\system32\cmd.exe",
                "LaunchString": r"cmd.exe /c reg add hklm\system /v insecure /d 1",
                "Signer": "(verified) microsoft windows",
                "Total": "2",
            }
        ]
        payload = "SUSPICIOUS\t1\thigh\tSigned command changes a security setting.\nEND"

        suspicious, potential = autoruns_ai_review._validate_result(
            payload,
            rows=rows,
        )
        self.assertEqual(suspicious[0]["row_id"], 1)
        self.assertEqual(potential, [])

    def test_classification_line_protocol_requires_integer_row_ids(self):
        rows = [{"RowId": "1"}]
        with self.assertRaisesRegex(
            autoruns_ai_review.AutorunsAiReviewError,
            "invalid RowId representation",
        ):
            autoruns_ai_review._validate_result(
                "SUSPICIOUS\tone\thigh\tConcrete suspicious launch behavior.\nEND",
                rows=rows,
            )

    def test_empty_stack_completes_without_model_call(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            def executor(**kwargs):
                raise AssertionError("model should not be called")

            result = autoruns_ai_review.classify_streaming_rows(
                iter(()),
                workdir=root,
                executor=executor,
            )
            self.assertEqual(list(root.iterdir()), [])

        self.assertEqual(result["suspicious_rows"], [])
        self.assertEqual(result["potential_golden_rows"], [])
        self.assertEqual(result["manifest"]["reviewed_group_count"], 0)
        self.assertEqual(result["manifest"]["part_count"], 0)

    def test_focused_review_caps_rows_per_part(self):
        rows = [
            {
                field: (
                    f"review-{index}"
                    if field == "ReviewId"
                    else "value"
                )
                for field in autoruns_ai_review.FOCUSED_REVIEW_FIELDS
            }
            for index in range(401)
        ]

        chunks = list(autoruns_ai_review._iter_chunks_with_fields(
            rows,
            fieldnames=autoruns_ai_review.FOCUSED_REVIEW_FIELDS,
            maximum_evidence_tokens=200_000,
            token_encoding="o200k_base",
            maximum_rows_per_part=200,
        ))

        self.assertEqual([len(part[1]) for part in chunks], [200, 200, 1])


if __name__ == "__main__":
    unittest.main()
