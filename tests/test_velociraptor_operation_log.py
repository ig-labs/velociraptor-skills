from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import stat
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.analyze import cli_output as analysis_cli_output
from vraptor import legacy_cli as velociraptor_cli
from vraptor.logging import operations as operation_log
from vraptor.logging import command as operation_log_cli
from vraptor import api as velociraptor_api
from vraptor.api import VeloApiClient


def _write_progress_process(
    path_value: str,
    worker_index: int,
    event_count: int,
    max_file_bytes: int,
) -> None:
    operation_log.MAX_FILE_BYTES = max_file_bytes
    path = Path(path_value)
    with operation_log.OperationLogger(
        f"worker.{worker_index}",
        options=operation_log.LogOptions(explicit_path=path),
    ) as logger:
        for event_index in range(event_count):
            logger.emit(
                "test_event",
                component="multiprocess_test",
                task_id=f"worker-{worker_index}-{event_index}",
            )
        logger.finalize(status="complete", exit_code=0)


def _hold_progress_lock(path_value: str, ready: object) -> None:
    with operation_log._exclusive_log_lock(Path(path_value), timeout_seconds=5):
        ready.set()
        time.sleep(30)


class VelociraptorOperationLogTest(unittest.TestCase):
    def test_environment_and_cli_enable_debug_file_logging(self):
        with mock.patch.dict(
            os.environ,
            {operation_log.DEBUG_ENV_VAR: "true"},
            clear=False,
        ):
            args, options = operation_log.extract_global_options(
                ["collect", "status"]
            )
            self.assertEqual(args, ["collect", "status"])
            self.assertEqual(options.level, "debug")

            args, options = operation_log.extract_global_options(
                ["hunt", "analyze", "--debug"]
            )
            self.assertEqual(args, ["hunt", "analyze", "--debug"])
            self.assertEqual(options.level, "debug")

            _, options = operation_log.extract_global_options(
                ["collect", "status", "--log-level", "info"]
            )
            self.assertEqual(options.level, "info")

    def test_invalid_debug_environment_value_fails_closed(self):
        with mock.patch.dict(
            os.environ,
            {operation_log.DEBUG_ENV_VAR: "sometimes"},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, operation_log.DEBUG_ENV_VAR):
                operation_log.extract_global_options(["collect", "status"])

    def test_output_preflight_logs_file_reason_and_remediation(self):
        from vraptor.artifacts import persistence as persistence_policy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis = root / "analysis"
            analysis.mkdir()
            bad = analysis / "old.sqlite"
            bad.write_text("fixture")
            with operation_log.OperationLogger(
                "hunt.analyze", options=operation_log.LogOptions(level="info"),
            ) as logger:
                log_path = logger.bind_case(root, "IR1234")
                with self.assertRaises(persistence_policy.PersistencePolicyError):
                    persistence_policy.preflight_analysis_tree(analysis, ["hunt:H.1"])
                logger.emit("stage_failed", error_detail="password=hunter2\nfailed")
            text = log_path.read_text()
            self.assertIn("output_preflight", text)
            self.assertIn(str(bad), text)
            self.assertIn("Unclassified raw-result-like", text)
            self.assertIn("rerun the same command", text)
            self.assertNotIn("hunter2", text)

    def test_log_is_human_readable_private_and_never_contains_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "PRIVATE-KEY-MATERIAL"
            raw_vql = "SELECT secret FROM evidence_rows()"
            with operation_log.OperationLogger(
                "collect.analyze",
                options=operation_log.LogOptions(level="info"),
            ) as logger:
                path = logger.bind_case(root, "IR1234")
                logger.emit(
                    "test_event",
                    component="test",
                    status="running",
                    client_id="C.1234",
                    raw_vql=raw_vql,
                    credential=secret,
                    query_name="unsafe name with spaces",
                )
                logger.finalize(status="complete", exit_code=0)

            self.assertIsNotNone(path)
            assert path is not None
            text = path.read_text(encoding="utf-8")
            lines = operation_log.validate_log(path)
            self.assertEqual(path.name, operation_log.LOG_FILENAME)
            self.assertNotIn(secret, text)
            self.assertNotIn(raw_vql, text)
            self.assertNotIn("{", text)
            self.assertIn("Command started", text)
            self.assertIn("command=collect.analyze", text)
            self.assertIn("log_level=info", text)
            self.assertIn("server_message_mode=sanitized_text", text)
            self.assertIn("Command completed", text)
            self.assertIn("query=sha256:", text)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(lines)

    def test_standard_progress_includes_model_and_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "hunt.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                reporter = analysis_cli_output.ProgressReporter(
                    scope="hunt",
                    scope_id="H.1",
                    enabled=False,
                )
                reporter.start(phase="provider", provider="openai", model="gpt-5.6")
                heartbeat = threading.Thread(target=reporter.heartbeat)
                heartbeat.start()
                heartbeat.join()
                reporter.close(
                    status="complete",
                    provider="openai",
                    model="gpt-5.6",
                )
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("Model request running", text)
            self.assertIn("provider=openai", text)
            self.assertIn("model=gpt-5.6", text)
            self.assertIn("Still working: provider", text)
            self.assertIn(logger.operation_id, text)

    def test_provider_event_wording_is_not_redundant(self):
        line = operation_log._format_line(
            timestamp="2026-09-04T00:00:00Z",
            level="info",
            operation_id="op-v1-0123456789abcdef",
            event="progress",
            fields={"phase": "provider", "status": "request_started"},
        )
        self.assertIn("Model request started", line)
        self.assertNotIn("request request", line)

    def test_log_show_defaults_to_current_file_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with operation_log.OperationLogger("collect.status") as logger:
                path = logger.bind_case(root, "IR1234")
                logger.finalize(status="complete", exit_code=0)
            assert path is not None

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = operation_log_cli.main(
                    ["show", "--case-root", str(root), "--id", "IR1234"]
                )
            self.assertEqual(result, 0)
            self.assertIn("Command completed", stdout.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                invalid_result = operation_log_cli.main(
                    [
                        "show",
                        "--case-root",
                        str(root),
                        "--id",
                        "IR1234",
                        "--file",
                        "../engagement.json",
                    ]
                )
            self.assertEqual(invalid_result, 1)
            self.assertIn("progress log", stderr.getvalue())

    def test_log_show_filters_operation_level_and_time(self):
        now = datetime.now(timezone.utc)
        lines = [
            operation_log._format_line(
                timestamp=(now - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
                level="error",
                operation_id="op-v1-1111111111111111",
                event="stage_failed",
                fields={"stage": "old"},
            ).rstrip(),
            operation_log._format_line(
                timestamp=now.isoformat().replace("+00:00", "Z"),
                level="info",
                operation_id="op-v1-2222222222222222",
                event="progress",
                fields={"phase": "collection", "status": "running"},
            ).rstrip(),
            operation_log._format_line(
                timestamp=now.isoformat().replace("+00:00", "Z"),
                level="warning",
                operation_id="op-v1-2222222222222222",
                event="progress",
                fields={"phase": "provider", "status": "retry_scheduled"},
            ).rstrip(),
        ]

        selected = operation_log_cli._filter_lines(
            lines,
            operation="op-v1-2222222222222222",
            level="warning",
            since=operation_log_cli._parse_since("30m", now=now),
        )

        self.assertEqual(len(selected), 1)
        self.assertIn("Model request retry scheduled", selected[0])

    def test_log_show_filters_scope_hunt_and_task_exactly(self):
        timestamp = "2026-09-04T00:00:00Z"
        lines = [
            operation_log._format_line(
                timestamp=timestamp,
                level="info",
                operation_id=f"op-v1-{index:016x}",
                event="progress",
                fields={
                    "phase": "provider",
                    "status": "request_started",
                    "scope": scope,
                    "scope_id": hunt_id,
                    "hunt_id": hunt_id,
                    "task_id": task_id,
                },
            ).rstrip()
            for index, (scope, hunt_id, task_id) in enumerate(
                (
                    ("hunt", "H.123", "artifact-1"),
                    ("hunt", "H.1234", "artifact-10"),
                    ("host", "H.123", "artifact-1"),
                ),
                start=1,
            )
        ]

        selected = operation_log_cli._filter_lines(
            lines,
            scope="hunt",
            hunt_id="H.123",
            task_id="artifact-1",
        )

        self.assertEqual(selected, [lines[0]])

    def test_since_parser_accepts_duration_and_rejects_naive_timestamp(self):
        now = datetime(2026, 9, 4, tzinfo=timezone.utc)
        self.assertEqual(
            operation_log_cli._parse_since("2h", now=now),
            now - timedelta(hours=2),
        )
        with self.assertRaisesRegex(ValueError, "timezone"):
            operation_log_cli._parse_since("2026-09-04T10:00:00")

    def test_follow_reader_handles_log_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            first = operation_log._format_line(
                timestamp="2026-09-04T00:00:00Z",
                level="info",
                operation_id="op-v1-1111111111111111",
                event="command_started",
                fields={"command": "hunt.status"},
            )
            second = operation_log._format_line(
                timestamp="2026-09-04T00:01:00Z",
                level="info",
                operation_id="op-v1-2222222222222222",
                event="command_started",
                fields={"command": "hunt.analyze"},
            )
            path.write_text(first, encoding="utf-8")
            path.chmod(0o600)
            initial = path.stat()
            identity = (initial.st_dev, initial.st_ino)
            path.replace(path.with_name(path.name + ".1"))
            path.write_text(second, encoding="utf-8")
            path.chmod(0o600)

            new_identity, offset, pending, lines = (
                operation_log_cli._read_follow_chunk(
                    path,
                    identity,
                    initial.st_size,
                    "",
                )
            )

            self.assertNotEqual(new_identity, identity)
            self.assertEqual(offset, len(second.encode("utf-8")))
            self.assertEqual(pending, "")
            self.assertEqual(lines, [second.rstrip()])

    def test_event_cap_preserves_terminal_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with mock.patch.object(operation_log, "MAX_EVENTS", 3):
                with operation_log.OperationLogger(
                    "hunt.status",
                    options=operation_log.LogOptions(explicit_path=path),
                ) as logger:
                    for index in range(20):
                        logger.emit("poll", component="test", attempt=index)
                    logger.finalize(status="complete", exit_code=0)
            lines = operation_log.validate_log(path)
            self.assertLessEqual(path.stat().st_size, operation_log.MAX_FILE_BYTES)
            self.assertIn("Command completed", lines[-1])
            self.assertTrue(any("Progress log limit reached" in line for line in lines))

    def test_api_debug_records_purpose_and_counts_but_not_vql_env_or_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client.server_identity = "a" * 64
            client._stub = mock.Mock()
            client._stub.Query.return_value = [
                SimpleNamespace(
                    Response=json.dumps([{"Evidence": "RAW-ROW-SECRET"}]),
                    log="",
                    part=1,
                )
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(
                    level="debug",
                    explicit_path=path,
                ),
            ) as logger:
                rows = client.query(
                    "SELECT count() FROM hunt_results(hunt_id='H.secret')",
                    {"Token": "ENV-SECRET"},
                )
                logger.finalize(status="complete", exit_code=0)

            self.assertEqual(rows, [{"Evidence": "RAW-ROW-SECRET"}])
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("RAW-ROW-SECRET", text)
            self.assertNotIn("ENV-SECRET", text)
            self.assertNotIn("SELECT count", text)
            self.assertIn("query=hunt_results.count", text)
            self.assertIn("Velociraptor query returned a batch", text)
            self.assertIn("rows=1", text)
            self.assertNotIn("query_sha256=", text)
            self.assertNotIn("server_identity=", text)

    def test_api_logs_useful_server_text_with_credentials_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            secret = "plain-custom-provider-key"
            with mock.patch.dict(
                os.environ,
                {"CUSTOM_PROVIDER_API_KEY": secret},
                clear=False,
            ):
                client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            evidence_path = "C:/Evidence/Host01/alice/autoruns.csv"
            client._stub.Query.return_value = [
                SimpleNamespace(
                    Response="",
                    log=(
                        f"ERROR: VQL parse error scanning {evidence_path} "
                        f"provider rejected {secret}"
                    ),
                    part=4,
                    query_id=7,
                    timestamp=12345,
                    total_rows=19,
                )
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(level="debug", explicit_path=path),
            ) as logger:
                with self.assertRaisesRegex(RuntimeError, "categories=parse_error"):
                    client.query("SELECT secret FROM scope()")
                logger.finalize(status="failed", exit_code=1)

            text = path.read_text(encoding="utf-8")
            self.assertNotIn(secret, text)
            self.assertNotIn("SELECT secret", text)
            self.assertIn(evidence_path, text)
            self.assertIn("provider rejected <redacted>", text)
            self.assertIn("message_redactions=1", text)
            self.assertIn("Velociraptor reported a VQL parse error", text)
            self.assertIn("message_category=parse_error", text)
            self.assertIn("server_query_id=7", text)
            self.assertIn("server_total_rows=19", text)
            self.assertNotIn("message_length=", text)
            self.assertNotIn("message_sha256=", text)

    def test_numeric_server_progress_is_extracted_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            message = (
                "Progress completed=12 total=20 percent=60% "
                "rows scanned=1,234 bytes_scanned=4096 elapsed=1500ms"
            )
            client._stub.Query.return_value = [
                SimpleNamespace(Response="", log=message, part=1, query_id=9)
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(
                    level="info",
                    explicit_path=path,
                ),
            ) as logger:
                client.query("SELECT count() FROM hunt_results()")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            for expected in (
                "progress_completed=12",
                "progress_total=20",
                "progress_percent=60.0",
                "progress_rows_scanned=1234",
                "progress_bytes_scanned=4096",
                "progress_elapsed_seconds=1.5",
                "message_category=progress",
                f'server_message="{message}"',
            ):
                self.assertIn(expected, text)
            self.assertNotIn("message_length=", text)
            self.assertNotIn("message_sha256=", text)
            self.assertIn("No timeout configured for expensive", text)
            self.assertIn("timeout_seconds=0", text)

    def test_server_text_preserves_context_and_redacts_credential_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            evidence_path = "C:/Evidence/Host01/alice/secret.db"
            api_key = "very-secret-api-key-value"
            message = json.dumps(
                {
                    "completed": 4,
                    "total": 10,
                    "percent": 40,
                    "path": evidence_path,
                    "username": "alice",
                    "status_text": "Scanning confidential evidence",
                    "api_key": api_key,
                }
            )
            client._stub.Query.return_value = [
                SimpleNamespace(Response="", log=message, part=1)
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(
                    level="info",
                    explicit_path=path,
                ),
            ) as logger:
                client.query("SELECT count() FROM hunt_results()")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("progress_completed=4", text)
            self.assertIn("progress_total=10", text)
            self.assertIn("progress_percent=40.0", text)
            self.assertIn(evidence_path, text)
            self.assertIn("alice", text)
            self.assertIn("Scanning confidential evidence", text)
            self.assertIn("credential=<redacted>", text)
            self.assertIn("message_redactions=1", text)
            self.assertNotIn(api_key, text)

    def test_server_message_sanitizer_is_single_line_and_bounded(self):
        secret = "configured-secret-value"
        message = (
            "Scanning host01\n"
            "password=hunter2 "
            f"token={secret} "
            f"Authorization: Basic {'A' * 64} "
            f"detail={'x ' * 400}"
        )

        sanitized, redactions, truncated = operation_log.sanitize_server_message(
            message,
            secrets=(secret,),
        )

        self.assertNotIn("\n", sanitized)
        self.assertNotIn("hunter2", sanitized)
        self.assertNotIn(secret, sanitized)
        self.assertNotIn("A" * 64, sanitized)
        self.assertGreaterEqual(redactions, 3)
        self.assertTrue(truncated)
        self.assertLessEqual(len(sanitized), operation_log.MAX_SERVER_MESSAGE_CHARS)

        file_hash = "a" * 64
        sanitized_hash, _, _ = operation_log.sanitize_server_message(
            f"Verified SHA256 {file_hash}"
        )
        self.assertIn(file_hash, sanitized_hash)

        pem_body = "MII" + "A" * 80
        sanitized_pem, pem_redactions, _ = operation_log.sanitize_server_message(
            "-----BEGIN " "PRIVATE KEY-----\n"
            f"{pem_body}\n"
            "-----END " "PRIVATE KEY-----"
        )
        self.assertEqual(sanitized_pem, "<redacted-pem>")
        self.assertEqual(pem_redactions, 1)

    def test_api_server_logging_omits_multiline_pem_body(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            pem_body = "MII" + "A" * 80
            client._stub.Query.return_value = [
                SimpleNamespace(
                    Response="",
                    log=(
                        "Starting TLS check\n"
                        "-----BEGIN " "PRIVATE KEY-----\n"
                        f"{pem_body}\n"
                        "-----END " "PRIVATE KEY-----\n"
                        "TLS check complete"
                    ),
                    part=1,
                )
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                client.query("SELECT * FROM scope()")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("Starting TLS check", text)
            self.assertIn("<redacted-pem>", text)
            self.assertIn("TLS check complete", text)
            self.assertNotIn(pem_body, text)

    def test_malformed_server_progress_keeps_text_without_numeric_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            message = "Progress completed=5 total=not-a-number rows_scanned=500"
            client._stub.Query.return_value = [
                SimpleNamespace(Response="", log=message, part=1)
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(
                    level="debug",
                    explicit_path=path,
                ),
            ) as logger:
                client.query("SELECT count() FROM hunt_results()")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("message_category=progress", text)
            self.assertIn(f'server_message="{message}"', text)
            self.assertNotIn("progress_completed=", text)
            self.assertNotIn("progress_total=", text)
            self.assertNotIn("progress_rows_scanned=", text)
            self.assertNotIn("message_length=", text)
            self.assertNotIn("message_sha256=", text)

    def test_long_api_query_emits_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")

            class SlowStub:
                def Query(self, request):
                    time.sleep(0.03)
                    return iter([SimpleNamespace(Response="", log="", part=1)])

            client._stub = SlowStub()
            with (
                mock.patch.object(velociraptor_api, "QUERY_HEARTBEAT_SECONDS", 0.01),
                operation_log.OperationLogger(
                    "query",
                    options=operation_log.LogOptions(explicit_path=path),
                ) as logger,
            ):
                client.query("SELECT * FROM hunt_flows(hunt_id=HuntId)")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("Still waiting for the Velociraptor query", text)
            self.assertIn("query=hunt_flows.read", text)
            self.assertIn("query_id=q-0001", text)
            self.assertIn("server_silent=", text)
            self.assertIn("elapsed=", text)

    def test_repeated_queries_have_distinct_local_instance_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            client = VeloApiClient(Path(directory) / "api.yaml")
            client._stub = mock.Mock()
            client._stub.Query.return_value = [
                SimpleNamespace(Response="", log="", part=1)
            ]
            with operation_log.OperationLogger(
                "query",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                client.query("SELECT * FROM clients()")
                client.query("SELECT * FROM clients()")
                logger.finalize(status="complete", exit_code=0)

            query_starts = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if "Velociraptor query started" in line
            ]
            self.assertEqual(len(query_starts), 2)
            self.assertIn("query_id=q-0001", query_starts[0])
            self.assertIn("query_id=q-0002", query_starts[1])

    def test_query_stall_warning_is_emitted_once_until_activity_resumes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            started = time.monotonic() - 10
            with (
                mock.patch.object(velociraptor_api, "QUERY_HEARTBEAT_SECONDS", 0.01),
                mock.patch.object(velociraptor_api, "QUERY_STALL_SECONDS", 0.01),
                operation_log.OperationLogger(
                    "query",
                    options=operation_log.LogOptions(explicit_path=path),
                ) as logger,
            ):
                heartbeat = velociraptor_api._QueryHeartbeat(
                    "hunt_results.count",
                    "q-0001",
                    started,
                    lambda: {
                        "batches": 0,
                        "rows": 0,
                        "responses": 0,
                        "server_messages": 0,
                        "last_server_activity": started,
                    },
                    logger,
                )
                heartbeat.start()
                time.sleep(0.04)
                heartbeat.close()
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("No recent response from Velociraptor"), 1)
            self.assertIn("server_silent=", text)
            self.assertIn("responses=0", text)
            self.assertIn("server_messages=0", text)

    def test_generic_stage_heartbeat_is_suppressed_while_query_is_active(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "hunt.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                reporter = analysis_cli_output.ProgressReporter(
                    scope="hunt",
                    scope_id="H.1",
                    enabled=False,
                    heartbeat_seconds=0,
                    throttle_seconds=0,
                )
                reporter.start(phase="collection")
                logger.emit(
                    "api_query_started",
                    query_name="hunt_results.count",
                    query_instance_id="q-0001",
                )
                reporter.heartbeat()
                logger.emit(
                    "api_query_completed",
                    query_name="hunt_results.count",
                    query_instance_id="q-0001",
                )
                reporter.heartbeat()
                reporter.close(status="complete")
                logger.finalize(status="complete", exit_code=0)

            progress_heartbeats = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if "Still working: collection" in line
            ]
            self.assertEqual(len(progress_heartbeats), 1)

    def test_model_lifecycle_includes_safe_usage_retry_and_task_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            secret = "RAW-PROVIDER-BODY"
            event = SimpleNamespace(
                type="retry_scheduled",
                provider="openai",
                model="gpt-5.6",
                protocol="responses",
                request_id="req_123",
                task_id="artifact-4",
                attempt=2,
                metadata={
                    "error_classification": "rate_limit",
                    "provider_status": 429,
                    "delay_seconds": 3.5,
                    "input_tokens": 1200,
                    "output_tokens": 100,
                    "total_tokens": 1300,
                    "raw_body": secret,
                },
            )
            with operation_log.OperationLogger(
                "hunt.analyze",
                options=operation_log.LogOptions(level="debug", explicit_path=path),
            ) as logger:
                reporter = analysis_cli_output.ProgressReporter(
                    scope="hunt",
                    enabled=False,
                    heartbeat_seconds=0,
                    throttle_seconds=0,
                )
                reporter.update(analysis_cli_output.agent_event_progress(event))
                reporter.close(status="complete")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("Model request retry scheduled", text)
            self.assertIn("task_id=artifact-4", text)
            self.assertIn("error_classification=rate_limit", text)
            self.assertIn("provider_status=429", text)
            self.assertIn("retry_delay_seconds=3.5", text)
            self.assertIn("total_tokens=1300", text)
            self.assertNotIn(secret, text)

    def test_parallel_task_terminal_events_are_not_throttled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "hunt.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                reporter = analysis_cli_output.ProgressReporter(
                    scope="hunt",
                    enabled=False,
                    heartbeat_seconds=0,
                    throttle_seconds=60,
                )

                def complete_task(index: int) -> None:
                    reporter.update(
                        {
                            "phase": "provider",
                            "status": "request_started",
                            "task_id": f"task-{index}",
                            "provider": "openai",
                            "model": "gpt-5.6",
                        }
                    )
                    reporter.update(
                        {
                            "phase": "provider",
                            "status": "request_completed",
                            "task_id": f"task-{index}",
                            "provider": "openai",
                            "model": "gpt-5.6",
                        }
                    )

                workers = [
                    threading.Thread(target=complete_task, args=(index,))
                    for index in range(20)
                ]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join()
                reporter.close(status="complete")
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("Model request started"), 20)
            self.assertEqual(text.count("Model request completed"), 20)
            self.assertIn("tasks_started=20", text)
            self.assertIn("tasks_completed=20", text)

    def test_heartbeat_reports_aggregate_parallel_task_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "host.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                reporter = analysis_cli_output.ProgressReporter(
                    scope="host",
                    enabled=False,
                    heartbeat_seconds=0,
                    throttle_seconds=60,
                )
                for task_id in ("task-1", "task-2"):
                    reporter.update(
                        {
                            "phase": "provider",
                            "status": "request_started",
                            "task_id": task_id,
                        }
                    )
                reporter.update(
                    {
                        "phase": "provider",
                        "status": "request_completed",
                        "task_id": "task-1",
                    }
                )
                reporter.heartbeat()
                reporter.close(status="complete")
                logger.finalize(status="complete", exit_code=0)

            heartbeat = next(
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if "Still working: provider" in line
            )
            self.assertIn("active=1", heartbeat)
            self.assertIn("completed=1", heartbeat)
            self.assertIn("total=2", heartbeat)

    def test_operation_summary_separates_queries_tasks_and_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "hunt.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                logger.emit(
                    "api_query_started",
                    query_name="hunt_flows.read",
                )
                logger.emit(
                    "api_query_completed",
                    query_name="hunt_flows.read",
                    rows=31,
                    batches=2,
                )
                for task_id, terminal_status in (
                    ("task-1", "request_completed"),
                    ("task-2", "request_failed"),
                ):
                    logger.emit(
                        "progress",
                        phase="provider",
                        status="request_started",
                        task_id=task_id,
                    )
                    if task_id == "task-1":
                        logger.emit(
                            "progress",
                            phase="provider",
                            status="retry_scheduled",
                            task_id=task_id,
                        )
                        logger.emit(
                            "progress",
                            phase="provider",
                            status="request_started",
                            task_id=task_id,
                            attempt=2,
                        )
                    logger.emit(
                        "progress",
                        phase="provider",
                        status=terminal_status,
                        task_id=task_id,
                    )
                logger.finalize(status="complete", exit_code=0)

            summary = next(
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if "Operation summary" in line
            )
            for expected in (
                "queries_started=1",
                "queries_completed=1",
                "model_attempts=3",
                "tasks_started=2",
                "tasks_completed=1",
                "tasks_failed=1",
                "retries=1",
                "rows=31",
                "batches=2",
            ):
                self.assertIn(expected, summary)

    def test_api_client_keeps_operation_logger_in_worker_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            with operation_log.OperationLogger(
                "hunt.snapshot",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                client = VeloApiClient(Path(directory) / "api.yaml")
                client._stub = mock.Mock()
                client._stub.Query.return_value = [
                    SimpleNamespace(Response="[]", log="", part=1)
                ]
                worker = threading.Thread(
                    target=lambda: client.query("SELECT * FROM scope()")
                )
                worker.start()
                worker.join()
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("Velociraptor query started", text)
            self.assertIn("Velociraptor query completed", text)
            self.assertIn("queries_completed=1", text)

    def test_multiple_processes_append_complete_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            context = multiprocessing.get_context("spawn")
            processes = [
                context.Process(
                    target=_write_progress_process,
                    args=(str(path), index, 25, operation_log.MAX_FILE_BYTES),
                )
                for index in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)

            lines = operation_log.validate_log(path)
            self.assertEqual(len(lines), 4 * (25 + 3))
            self.assertEqual(
                sum("Command completed" in line for line in lines),
                4,
            )
            self.assertEqual(
                stat.S_IMODE(operation_log.lock_path_for(path).stat().st_mode),
                0o600,
            )

    def test_concurrent_rotation_keeps_only_valid_log_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            context = multiprocessing.get_context("spawn")
            processes = [
                context.Process(
                    target=_write_progress_process,
                    args=(str(path), index, 100, 4096),
                )
                for index in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)

            log_files = [
                path if index == 0 else path.with_name(f"{path.name}.{index}")
                for index in range(operation_log.MAX_LOG_FILES)
            ]
            retained = [candidate for candidate in log_files if candidate.exists()]
            self.assertGreater(len(retained), 1)
            self.assertLessEqual(len(retained), operation_log.MAX_LOG_FILES)
            for candidate in retained:
                self.assertTrue(operation_log.validate_log(candidate))

    def test_process_termination_releases_progress_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            path.parent.mkdir(parents=True, exist_ok=True)
            context = multiprocessing.get_context("spawn")
            ready = context.Event()
            holder = context.Process(
                target=_hold_progress_lock,
                args=(str(path), ready),
            )
            holder.start()
            self.assertTrue(ready.wait(timeout=5))
            holder.terminate()
            holder.join(timeout=5)

            with operation_log.OperationLogger(
                "collect.status",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                logger.finalize(status="complete", exit_code=0)

            self.assertIn(
                "Command completed",
                path.read_text(encoding="utf-8"),
            )

    def test_log_lock_timeout_does_not_interrupt_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            logger = operation_log.OperationLogger(
                "collect.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            )
            with logger:
                with mock.patch.object(
                    operation_log,
                    "_exclusive_log_lock",
                    side_effect=operation_log.LogLockTimeout("busy"),
                ):
                    logger.emit("test_event", task_id="task-1")
                    logger.finalize(status="complete", exit_code=0)

            self.assertGreaterEqual(logger._events_dropped, 2)

    def test_command_context_excludes_question_paths_and_unknown_options(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / operation_log.LOG_FILENAME
            secret = "SECRET-QUESTION-CONTENT"
            with operation_log.OperationLogger(
                "collect.analyze",
                options=operation_log.LogOptions(explicit_path=path),
            ) as logger:
                velociraptor_cli._record_command_context(
                    [
                        "collect",
                        "analyze",
                        "--id",
                        "IR9009",
                        "--server-profile",
                        "lab7",
                        "--client-id",
                        "C.1234",
                        "--artifact",
                        "Windows.Sysinternals.Autoruns",
                        "--question",
                        secret,
                        "--case-root",
                        "/customer/private/path",
                    ]
                )
                logger.finalize(status="complete", exit_code=0)

            text = path.read_text(encoding="utf-8")
            self.assertIn("engagement_id=IR9009", text)
            self.assertIn("server_profile=lab7", text)
            self.assertIn("artifact=Windows.Sysinternals.Autoruns", text)
            self.assertNotIn(secret, text)
            self.assertNotIn("/customer/private/path", text)

    def test_rotation_keeps_current_and_three_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_dir = root / "IR1234" / "logs"
            log_dir.mkdir(parents=True)
            current = log_dir / operation_log.LOG_FILENAME
            current.write_bytes(b"x" * operation_log.MAX_FILE_BYTES)
            current.chmod(0o600)
            for index in range(1, operation_log.MAX_LOG_FILES):
                rotated = log_dir / f"{operation_log.LOG_FILENAME}.{index}"
                rotated.write_text("old\n", encoding="utf-8")
                rotated.chmod(0o600)
            with operation_log.OperationLogger("hunt.status") as logger:
                logger.bind_case(root, "IR1234")
                logger.finalize(status="complete", exit_code=0)
            self.assertEqual(
                len(
                    [
                        path
                        for path in log_dir.glob(f"{operation_log.LOG_FILENAME}*")
                        if path.name != operation_log.LOG_FILENAME + operation_log.LOCK_SUFFIX
                    ]
                ),
                operation_log.MAX_LOG_FILES,
            )
            self.assertIn("Command started", current.read_text(encoding="utf-8"))

    def test_log_inspection_does_not_append_to_progress_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with operation_log.OperationLogger("collect.status") as logger:
                path = logger.bind_case(root, "IR1234")
                logger.finalize(status="complete", exit_code=0)
            assert path is not None
            before = path.read_bytes()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = velociraptor_cli.main(
                    ["logs", "show", "--case-root", str(root), "--id", "IR1234"]
                )
            self.assertEqual(result, 0)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
