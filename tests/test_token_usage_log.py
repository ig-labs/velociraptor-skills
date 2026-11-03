from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from vraptor.logging import operations, token_usage


def _record(logger, index=0, **overrides):
    values = {
        "invocation_id": f"invocation-{index}",
        "task_id": "task-1",
        "request_id": f"request-{index}",
        "provider": "openai",
        "model": "test-model",
        "protocol": "responses",
        "attempt": 1,
        "status": "succeeded",
        "elapsed_seconds": 0.2,
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "cached_input_tokens": 4,
        },
        "usage_status": "reported",
        "stage": "analysis",
    }
    logger.record_token_usage(**{**values, **overrides})


def _write_usage_process(directory, worker):
    with operations.OperationLogger("analyze") as logger:
        logger.bind_case(Path(directory), "case-test")
        with ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(lambda index: _record(logger, f"{worker}-{index}"), range(25)))


def _rows(path, *, include_lifecycle=False):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    return rows if include_lifecycle else [row for row in rows if row["event"] != "operation_started"]


class TokenUsageLoggingTests(unittest.TestCase):
    def test_correction_and_transport_retries_are_distinct_and_deduplicated(self):
        ledger = token_usage.TokenUsageLedger()
        base = {"provider": "openai", "model": "test", "status": "succeeded",
                "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
                "usage_status": "reported"}
        ledger.record(invocation_id="initial", attempt=1, **base)
        ledger.record(invocation_id="corrected", attempt=1, correction_attempt=1, **base)
        ledger.record(invocation_id="corrected", attempt=2, correction_attempt=1, **base)
        self.assertIsNone(ledger.record(invocation_id="corrected", attempt=2, correction_attempt=1, **base))
        result = ledger.summary()
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["retry_attempts"], 2)
        self.assertEqual(result["transport_retry_attempts"], 1)
        self.assertEqual(result["correction_attempts"], 1)
        self.assertEqual(result["total_tokens"], 9)

    def bind(self, directory, *, level="info", persist=True):
        logger = operations.OperationLogger(
            "analyze", options=operations.LogOptions(level=level, persist=persist)
        )
        logger.bind_case(Path(directory), "case-test")
        return logger

    def test_case_path_and_single_summary_with_retry_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.bind(directory) as logger:
                _record(logger, status="failed")
                _record(logger, attempt=2)
                _record(logger, attempt=2)  # Duplicate terminal delivery.
                _record(logger, 1, model="second-model")
                logger.finalize(status="complete", exit_code=0)
                logger.finalize(status="complete", exit_code=0)
            path = Path(directory) / "case-test/logs/token-usage.jsonl"
            rows = _rows(path)
            self.assertEqual(sum(row["event"] == "operation_started" for row in _rows(path, include_lifecycle=True)), 1)
            self.assertEqual(len(rows), 4)
            self.assertEqual([row["event"] for row in rows], ["request_usage"] * 3 + ["operation_summary"])
            summary = rows[-1]
            self.assertEqual(summary["attempts"], 3)
            self.assertEqual(summary["retry_attempts"], 1)
            self.assertEqual(summary["total_tokens"], 45)
            self.assertEqual(summary["cached_input_tokens"], 12)
            self.assertTrue(summary["usage_complete"])
            self.assertTrue(summary["log_complete"])
            self.assertEqual(len(summary["groups"]), 2)
            group = next(row for row in summary["groups"] if row["model"] == "test-model")
            self.assertEqual(group["statuses"], {"failed": 1, "succeeded": 1})
            self.assertEqual(group["total_tokens"], 30)
            self.assertEqual({row["operation_id"] for row in rows}, {logger.operation_id})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(operations.lock_path_for(path).stat().st_mode), 0o600)

    def test_unknown_usage_is_null_and_reported_zero_is_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.bind(directory) as logger:
                _record(logger, usage={}, usage_status="unavailable", status="timeout")
                _record(logger, 1, usage={}, usage_status="reported")
                _record(logger, 2, usage={"input_tokens": 7, "total_tokens": 7}, usage_status="partial")
            rows = _rows(logger.token_usage_path)
            for key in token_usage.TOKEN_FIELDS:
                self.assertIsNone(rows[0][key])
                self.assertEqual(rows[1][key], 0)
            self.assertFalse(rows[-1]["usage_complete"])
            self.assertEqual(rows[-1]["unavailable_requests"], 1)
            self.assertEqual(rows[-1]["partial_requests"], 1)
            self.assertEqual(rows[-1]["reported_requests"], 1)
            self.assertEqual(rows[-1]["total_tokens"], 7)

    def test_explicit_destination_gets_distinct_sibling(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.log"
            with operations.OperationLogger(
                "analyze", options=operations.LogOptions(explicit_path=path)
            ) as logger:
                _record(logger)
            self.assertEqual(logger.token_usage_path, path.with_name("custom-token-usage.jsonl").resolve())
            self.assertEqual(len(_rows(logger.token_usage_path)), 2)

    def test_no_ai_requests_create_explicit_zero_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.bind(directory) as logger:
                logger.emit("api_query_completed", rows=5)
            rows = _rows(logger.token_usage_path, include_lifecycle=True)
            self.assertEqual([row["event"] for row in rows], ["operation_started", "operation_summary"])
            self.assertEqual(rows[-1]["attempts"], 0)
            self.assertEqual(rows[-1]["total_tokens"], 0)
            self.assertTrue(rows[-1]["usage_complete"])

    def test_persistence_optout_does_not_create_any_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.bind(directory, persist=False) as logger:
                _record(logger)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(logger.token_usage_summary()["attempts"], 1)
            self.assertFalse(logger.token_usage_summary()["persistence_enabled"])

    def test_progress_replays_levels_and_caps_do_not_affect_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(operations, "MAX_EVENTS", 1), self.bind(directory, level="error") as logger:
                for index in range(30):
                    logger.emit("progress", phase="provider", status="request_completed", task_id="task-1", total_tokens=15)
                    _record(logger, index)
            rows = _rows(logger.token_usage_path)
            self.assertEqual(len(rows), 31)
            self.assertEqual(rows[-1]["total_tokens"], 450)

    def test_twenty_threads_share_one_exact_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.bind(directory) as logger, ThreadPoolExecutor(max_workers=20) as pool:
                list(pool.map(lambda index: _record(logger, index), range(100)))
            rows = _rows(logger.token_usage_path)
            self.assertEqual(len(rows), 101)
            self.assertEqual(rows[-1]["attempts"], 100)
            self.assertEqual(rows[-1]["total_tokens"], 1500)

    def test_multiple_processes_append_complete_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            context = multiprocessing.get_context("spawn")
            processes = [
                context.Process(target=_write_usage_process, args=(directory, worker))
                for worker in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
            rows = _rows(Path(directory) / "case-test/logs/token-usage.jsonl")
            requests = [row for row in rows if row["event"] == "request_usage"]
            summaries = [row for row in rows if row["event"] == "operation_summary"]
            self.assertEqual(len(requests), 100)
            self.assertEqual(len(summaries), 4)
            self.assertEqual(sum(row["total_tokens"] for row in requests), 1500)
            self.assertEqual(sum(row["total_tokens"] for row in summaries), 1500)

    def test_rotation_preserves_json_lines_and_summary_total(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(operations, "MAX_FILE_BYTES", 2500), self.bind(directory) as logger:
                for index in range(30):
                    _record(logger, index)
            path = logger.token_usage_path
            retained = [path, *sorted(path.parent.glob(path.name + ".[0-9]"))]
            self.assertEqual(len(retained), operations.MAX_LOG_FILES)
            for candidate in retained:
                self.assertTrue(_rows(candidate))
                self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            self.assertEqual(_rows(path)[-1]["total_tokens"], 450)

    def test_file_or_lock_symlink_does_not_touch_target(self):
        for lock in (False, True):
            with self.subTest(lock=lock), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "target"
                target.write_text("untouched")
                with contextlib.redirect_stderr(io.StringIO()) as warnings, self.bind(directory) as logger:
                    path = logger.token_usage_path
                    linked = operations.lock_path_for(path) if lock else path
                    linked.unlink(missing_ok=True)
                    linked.symlink_to(target)
                    _record(logger)
                self.assertEqual(target.read_text(), "untouched")
                self.assertIn("usage records are incomplete", warnings.getvalue())
                self.assertEqual(logger._token_usage.records_dropped, 2)

    def test_lock_failure_is_counted_and_does_not_interrupt_run(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()) as warnings, self.bind(directory) as logger:
                with mock.patch.object(operations, "_exclusive_log_lock", side_effect=operations.LogLockTimeout("busy")):
                    _record(logger)
                    _record(logger, 1)
                _record(logger, 2)
            rows = _rows(logger.token_usage_path)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]["records_dropped"], 2)
            self.assertFalse(rows[-1]["log_complete"])
            self.assertEqual(rows[-1]["total_tokens"], 45)
            self.assertEqual(warnings.getvalue().count("Warning:"), 1)
            self.assertIn("usage_records_dropped=2", logger.path.read_text())

    def test_interruption_has_one_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KeyboardInterrupt), self.bind(directory) as logger:
                _record(logger, status="cancelled", usage_status="partial")
                raise KeyboardInterrupt()
            summary = _rows(logger.token_usage_path)[-1]
            self.assertEqual(summary["status"], "interrupted")
            self.assertEqual(summary["exit_code"], 130)
            self.assertFalse(summary["usage_complete"])

    def test_failed_partial_append_rolls_back_before_next_record(self):
        real_write = os.write
        calls = 0

        def partial_write(descriptor, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(descriptor, data[:17])
            raise OSError("disk full")

        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stderr(io.StringIO()), self.bind(directory) as logger:
                _record(logger, 0)
                with mock.patch.object(operations.os, "write", side_effect=partial_write):
                    _record(logger, 1)
                _record(logger, 2)
            rows = _rows(logger.token_usage_path)
            self.assertEqual([row["invocation_id"] for row in rows[:-1]], ["invocation-0", "invocation-2"])
            self.assertEqual(rows[-1]["records_dropped"], 1)
            self.assertFalse(rows[-1]["log_complete"])
            self.assertEqual(rows[-1]["total_tokens"], 45)

    def test_known_credential_shapes_are_scrubbed_from_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = "sk-" + "a" * 32
            with self.bind(directory) as logger:
                _record(logger, request_id=secret, stage="review evidence containing spaces")
            text = logger.token_usage_path.read_text()
            self.assertNotIn(secret, text)
            self.assertNotIn("review evidence containing spaces", text)
            self.assertNotIn("prompt", text)


if __name__ == "__main__":
    unittest.main()
