from __future__ import annotations

import io
import json
import os
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor import api
from vraptor.hunt import live as live_hunt_analysis
from vraptor.logging import operations as operation_log
from vraptor.logging import command as operation_log_cli


class LoggingMonitoringTests(unittest.TestCase):
    def test_native_messages_and_batch_are_useful_without_duplicate_transport_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = api.VeloApiClient(Path(directory) / "unused.yaml")
            client._stub = mock.Mock()
            client._stub.Query.return_value = [
                SimpleNamespace(Response="", log="Starting query execution."),
                SimpleNamespace(Response="", log="memoize SELECT sensitive FROM scope(): Filled cache with 3216 rows"),
                SimpleNamespace(Response="", log="GROUP BY: 30001 bins exceeded, Switching to slower file based operation"),
                SimpleNamespace(Response="", log="Time 42: query: Sending response part 0 22 B (1 rows)."),
                SimpleNamespace(Response=json.dumps([{"RowCount": 12500}]), log="", part=0),
            ]
            with operation_log.OperationLogger(
                "hunt.analyze", options=operation_log.LogOptions(level="debug", explicit_path=path)
            ) as logger:
                logger.emit("command_context", hunt_id="H.example", artifact="Test.Autoruns")
                count = live_hunt_analysis.exact_count(
                    client, "SELECT count() AS RowCount FROM hunt_results() GROUP BY TRUE",
                    {"HuntId": "H.example", "ArtifactName": "Test.Autoruns"},
                    purpose="count-source-rows",
                )
            self.assertEqual(count, 12500)
            text = path.read_text()
            self.assertIn("matched_rows=12500", text)
            self.assertIn("response_rows=1", text)
            self.assertIn("purpose=count-source-rows", text)
            self.assertIn("cache_rows=3216", text)
            self.assertIn("group_bins=30001", text)
            spill = next(line for line in text.splitlines() if "group_bins=" in line)
            self.assertIn("WARNING", spill)
            self.assertNotIn("Step failed", text)
            self.assertNotIn("Starting query execution.", text)
            self.assertNotIn("Sending response part", text)
            self.assertNotIn("server response received", text)
            self.assertNotIn("SELECT sensitive", text)
            self.assertEqual(text.count("query returned a batch"), 1)
            selected = operation_log_cli._filter_lines(text.splitlines(), hunt_id="H.example")
            self.assertTrue(any("query started" in line for line in selected))
            self.assertTrue(any("query completed" in line for line in selected))

    def test_group_query_is_not_mislabelled_as_count(self):
        self.assertEqual(api.describe_query("SELECT count() FROM hunt_results() GROUP BY Path", "inline"), "hunt_results.group")
        self.assertEqual(api.describe_query("SELECT count() FROM hunt_results() GROUP BY TRUE", "inline"), "hunt_results.count")

    def test_silence_reminders_are_bounded_and_activity_resets_warning(self):
        logger = mock.Mock()
        state = {"last_server_activity": 0.0, "responses": 1}
        heartbeat = api._QueryHeartbeat("hunt_results.group", "q-0001", 0.0, lambda: state, logger)
        for second in range(30, 901, 30):
            heartbeat.tick(float(second))
        events = [call.args[0] for call in logger.emit.call_args_list]
        self.assertEqual(events.count("api_query_stalled"), 1)
        self.assertLessEqual(len(events), 5)
        state.update(last_server_activity=910.0, responses=2)
        heartbeat.tick(930.0)
        self.assertEqual(logger.emit.call_args.args[0], "api_query_resumed")
        heartbeat.tick(990.0)
        self.assertEqual(logger.emit.call_args.args[0], "api_query_stalled")
        self.assertTrue(all(call.kwargs["status"] == "awaiting_response" for call in logger.emit.call_args_list))

    def test_quoted_server_text_cannot_spoof_hunt_or_pid(self):
        line = operation_log._format_line(
            timestamp="2026-09-05T00:00:00Z", level="info", operation_id="op-v1-1111111111111111",
            event="api_server_message", fields={"hunt_id": "H.real", "server_message": 'text hunt_id=H.fake pid=123 "quote"'},
        )
        self.assertFalse(operation_log_cli._filter_lines([line], hunt_id="H.fake"))
        self.assertEqual(operation_log_cli._line_fields(line)["hunt_id"], "H.real")
        self.assertNotIn("pid", operation_log_cli._line_fields(line))

    def test_status_uses_start_identity_and_never_calls_silence_a_remote_stall(self):
        now = datetime(2026, 9, 5, tzinfo=timezone.utc)
        lines = []
        for index in range(1, 5):
            lines.append(operation_log._format_line(
                timestamp="2026-09-04T23:00:00Z", level="info",
                operation_id=f"op-v1-{index:016x}", event="command_started",
                fields={"command": "hunt.analyze", "pid": index, "process_started": "original", "log_host": socket.gethostname(), "hunt_id": "H.example", "artifact": "Test.Autoruns"},
            ))
        with mock.patch.object(operation_log, "process_snapshot", side_effect=[("stopped", "original"), ("alive", "reused"), ("exited", ""), ("alive", "original")]):
            records = operation_log_cli._operation_status(lines, now=now)
        self.assertEqual([record["state"] for record in records], ["stopped", "exited-pid-reused", "exited", "alive"])
        self.assertIn("overlap", records[0])
        self.assertIn("overlap", records[3])
        self.assertNotIn("overlap", records[1])
        self.assertTrue(all(record["stale"] == "yes" for record in records))

    def test_status_old_logs_have_unknown_process_and_do_not_mutate_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test-case" / "logs" / operation_log.LOG_FILENAME
            path.parent.mkdir(parents=True)
            original = operation_log._format_line(
                timestamp="2026-09-04T23:00:00Z", level="info",
                operation_id="op-v1-1111111111111111", event="command_started",
                fields={"command": "hunt.analyze", "hunt_id": "H.example"},
            )
            path.write_text(original)
            path.chmod(0o600)
            out = io.StringIO()
            with redirect_stdout(out), mock.patch.object(operation_log, "process_snapshot") as process:
                result = operation_log_cli.main(["status", "--case-root", directory, "--id", "test-case"])
            self.assertEqual(result, 0)
            process.assert_not_called()
            self.assertIn("UNKNOWN", out.getvalue())
            self.assertIn("remote query state: unknown", out.getvalue())
            self.assertEqual(path.read_text(), original)

    def test_process_reader_fails_closed_and_current_pid_has_identity(self):
        state, identity = operation_log.process_snapshot(os.getpid())
        self.assertEqual(state, "alive")
        self.assertTrue(identity)
        with mock.patch.object(operation_log.subprocess, "run", side_effect=OSError):
            self.assertEqual(operation_log.process_snapshot(os.getpid()), ("unknown", ""))

    def test_query_context_is_nested_and_heartbeat_captures_it(self):
        with operation_log.query_context(purpose="outer", artifact="Test.One"):
            with operation_log.query_context(purpose="inner"):
                heartbeat = api._QueryHeartbeat("test", "q-1", 0.0, lambda: {}, mock.Mock())
            self.assertEqual(operation_log.current_query_context()["purpose"], "outer")
        self.assertEqual(operation_log.current_query_context(), {})
        heartbeat.tick(30.0)
        self.assertEqual(heartbeat.logger.emit.call_args.kwargs["purpose"], "inner")
        self.assertEqual(heartbeat.logger.emit.call_args.kwargs["artifact"], "Test.One")

    def test_stream_context_is_restored_between_rows_and_on_failure(self):
        seen = []

        def batches(*args, **kwargs):
            seen.append(operation_log.current_query_context())
            yield [{"Total": 1}, {"Total": 2}]
            seen.append(operation_log.current_query_context())
            raise RuntimeError("query failed")

        client = SimpleNamespace(query_batches=batches)
        rows = live_hunt_analysis.iter_query_rows(
            client, vql="test", env={"HuntId": "H.example"}, purpose="build-scope-groups",
        )
        with operation_log.query_context(purpose="outer"):
            self.assertEqual(next(rows), {"Total": 1})
            self.assertEqual(operation_log.current_query_context(), {"purpose": "outer"})
            self.assertEqual(next(rows), {"Total": 2})
            with self.assertRaises(RuntimeError):
                next(rows)
            self.assertEqual(operation_log.current_query_context(), {"purpose": "outer"})
        self.assertEqual([context["purpose"] for context in seen], ["build-scope-groups"] * 2)
        self.assertEqual(operation_log.current_query_context(), {})

    def test_status_terminal_and_foreign_host_do_not_probe_local_pid(self):
        lines = []
        for index, host in enumerate((socket.gethostname(), "foreign.example"), start=1):
            lines.append(operation_log._format_line(
                timestamp="2026-09-04T23:00:00Z", level="info",
                operation_id=f"op-v1-{index:016x}", event="command_started",
                fields={"command": "hunt.analyze", "pid": 123, "process_started": "original", "log_host": host},
            ))
        lines.append(operation_log._format_line(
            timestamp="2026-09-04T23:01:00Z", level="info",
            operation_id="op-v1-0000000000000001", event="command_completed", fields={},
        ))
        with mock.patch.object(operation_log, "process_snapshot") as process:
            records = operation_log_cli._operation_status(lines)
        process.assert_not_called()
        self.assertEqual([record["state"] for record in records], ["completed", "unknown"])

    def test_failed_count_does_not_emit_a_successful_count(self):
        client = mock.Mock()
        client.query.side_effect = RuntimeError("query failed")
        with mock.patch.object(operation_log, "emit") as emit:
            with self.assertRaises(RuntimeError):
                live_hunt_analysis.exact_count(client, "test", {}, purpose="count-source-rows")
        emit.assert_not_called()
        self.assertEqual(operation_log.current_query_context(), {})


if __name__ == "__main__":
    unittest.main()
