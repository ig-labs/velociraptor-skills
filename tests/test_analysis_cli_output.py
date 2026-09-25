from __future__ import annotations

import argparse
import io
import json
import unittest
from pathlib import Path

from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.analyze import command as collection_analysis_cli
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.hunt import command as hunt_workflow


class AnalysisCliOutputTests(unittest.TestCase):
    def test_autoruns_target_coverage_display_preserves_structured_state(self) -> None:
        for artifacts, target, hidden in (
            (["IG.Windows.Sysinternals.Autoruns"], "not_assessed", True),
            (["Windows.Sysinternals.Autoruns"], "not_assessed", True),
            (["IG.Windows.Sysinternals.Autoruns"], "incomplete", False),
            (["IG.Windows.Sysinternals.Autoruns"], "complete", False),
            (
                ["IG.Windows.Sysinternals.Autoruns", "Windows.System.Pslist"],
                "not_assessed",
                False,
            ),
            ([], "not_assessed", False),
        ):
            with self.subTest(artifacts=artifacts, target=target):
                state = {
                    "hunt_id": "H.1",
                    "status": "complete",
                    "result_review_coverage": "complete",
                    "target_execution_coverage": target,
                    "artifacts": {artifact: {} for artifact in artifacts},
                    "host_execution": {"failed_count": 2},
                }
                original = json.loads(json.dumps(state))
                report = flow_analysis_coordinator.render_specialized_hunt_section(
                    state, hunt_root=Path("/unused")
                )
                self.assertEqual(hidden, "Target execution:" not in report)
                self.assertEqual(
                    target != "not_assessed" or hidden,
                    "Target execution was not assessed" not in report,
                )
                self.assertIn("Failed: 2", report)
                for payload in (
                    state,
                    {"analyses": [state]},
                    {"analyses": [state, state]},
                    {
                        **state,
                        "selected_artifacts": artifacts,
                        "coverage": {
                            "target_execution": target,
                            "result_review": "complete",
                        },
                    },
                ):
                    rendered = analysis_cli_output.render_final_text(payload)
                    self.assertEqual(
                        hidden,
                        "Target execution:" not in rendered
                        and "target_execution=" not in rendered,
                    )
                stream = io.StringIO()
                analysis_cli_output.emit_final_result(
                    state, output_format="json", stream=stream
                )
                self.assertEqual(original, json.loads(stream.getvalue()))
                self.assertEqual(original, state)

    def test_output_arguments_default_to_text(self) -> None:
        parser = argparse.ArgumentParser()
        analysis_cli_output.add_analysis_output_args(parser)
        args = parser.parse_args([])
        self.assertEqual("text", args.output_format)
        self.assertFalse(args.no_progress)
        self.assertEqual(20.0, args.progress_interval_seconds)
        self.assertEqual("json", parser.parse_args(["--format", "json"]).output_format)

    def test_output_help_reserves_json_for_explicit_integrations(self) -> None:
        parser = argparse.ArgumentParser()
        analysis_cli_output.add_analysis_output_args(parser)
        help_text = " ".join(parser.format_help().split())

        self.assertIn("Text is the default for operator runs", help_text)
        self.assertIn("use JSON only", help_text)
        self.assertIn("explicit downstream integration", help_text)

    def test_progress_interval_must_be_positive(self) -> None:
        parser = argparse.ArgumentParser()
        analysis_cli_output.add_progress_args(parser)
        self.assertEqual(
            2.5,
            parser.parse_args(["--progress-interval-seconds", "2.5"])
            .progress_interval_seconds,
        )
        with self.assertRaises(SystemExit):
            parser.parse_args(["--progress-interval-seconds", "0"])

    def test_host_and_hunt_analysis_parsers_default_to_text(self) -> None:
        self.assertEqual(
            "text",
            collection_analysis_cli.build_parser()
            .parse_args(["--client-id", "C.1"])
            .output_format,
        )
        hunt_args = hunt_workflow.parse_args(
            ["analyze", "--hunt-id", "H.1", "--id", "IR1"]
        )
        self.assertEqual("text", hunt_args.output_format)
        self.assertEqual(
            "json",
            hunt_workflow.parse_args(
                [
                    "analyze",
                    "--hunt-id",
                    "H.1",
                    "--id",
                    "IR1",
                    "--format",
                    "json",
                    "--no-progress",
                ]
            ).output_format,
        )

    def test_host_text_contains_summary_status_and_paths(self) -> None:
        rendered = analysis_cli_output.render_final_text(
            {
                "status": "complete_with_failures",
                "hostname": "host01",
                "request_id": "REQ-1",
                "artifact_task_count": 2,
                "chat_summary": "## Host summary\n\nUseful result.",
                "host_report_file": "/case/analysis-host.md",
                "host_state_file": "/case/host-analysis-state.json",
            }
        )
        self.assertIn("Host analysis: host01", rendered)
        self.assertIn("Overall: complete_with_failures", rendered)
        self.assertIn("Artifact tasks: 2", rendered)
        self.assertIn("Useful result.", rendered)
        self.assertIn("Report: /case/analysis-host.md", rendered)

    def test_hunt_text_uses_group_and_coverage(self) -> None:
        rendered = analysis_cli_output.render_final_text(
            {
                "action": "live_hunt_group_analysis",
                "group": "DR-1",
                "hunt_count": 1,
                "analyses": [
                    {
                        "hunt_id": "H.1",
                        "status": "complete",
                        "coverage": {
                            "result_review": "complete",
                            "target_execution": "not_assessed",
                        },
                    }
                ],
                "chat_summary": "## Hunt summary\n\nNo reportable findings.",
                "output": "/case/hunts",
            }
        )
        self.assertIn("Hunt analysis: DR-1", rendered)
        self.assertIn("Result review: complete", rendered)
        self.assertIn("Target execution: not_assessed", rendered)
        self.assertIn("Output: /case/hunts", rendered)

    def test_group_text_reports_mixed_per_hunt_status(self) -> None:
        rendered = analysis_cli_output.render_final_text(
            {
                "group": "DR-1",
                "analyses": [
                    {"hunt_id": "H.1", "status": "complete"},
                    {
                        "hunt_id": "H.2",
                        "status": "partial",
                        "result_review_coverage": "partial",
                    },
                ],
                "chat_summary": "Summary",
            }
        )
        self.assertIn("Overall: mixed", rendered)
        self.assertIn("Hunt H.1: status=complete", rendered)
        self.assertIn("Hunt H.2: status=partial; result_review=partial", rendered)

    def test_json_output_preserves_payload(self) -> None:
        stream = io.StringIO()
        payload = {"status": "complete", "chat_summary": "summary"}
        analysis_cli_output.emit_final_result(
            payload, output_format="json", stream=stream
        )
        self.assertEqual(payload, json.loads(stream.getvalue()))

    def test_default_text_is_smaller_than_structured_json(self) -> None:
        payload = {
            "status": "complete",
            "hostname": "host01",
            "request_id": "REQ-1",
            "chat_summary": "## Summary\n\nNo reportable findings.",
            "analysis_result": {
                "status": "complete",
                "findings": [
                    {
                        "id": f"F{index}",
                        "summary": "Repeated structured finding metadata",
                        "sources": [{"ref": f"S0001-R{index}"}],
                    }
                    for index in range(20)
                ],
            },
        }
        text_output = analysis_cli_output.render_final_text(payload)
        json_output = json.dumps(payload, indent=2)
        self.assertLess(len(text_output), len(json_output))

    def test_progress_uses_stderr_contract_and_drops_unknown_fields(self) -> None:
        stream = io.StringIO()
        reporter = analysis_cli_output.ProgressReporter(
            scope="hunt",
            scope_id="H.1",
            stream=stream,
            heartbeat_seconds=0,
            throttle_seconds=0,
        )
        reporter.start(phase="inventory")
        reporter.update(
            {
                "phase": "analyst_review",
                "status": "running",
                "accepted_chunks": 4,
                "active_agents": 2,
                "raw_evidence": "SECRET-EVIDENCE-VALUE",
                "error": "provider response body",
            }
        )
        reporter.close(status="complete")
        output = stream.getvalue()
        self.assertIn("DFIR-STATUS v=1 scope=hunt id=H.1", output)
        self.assertIn("phase=analyst_review", output)
        self.assertIn("accepted=4", output)
        self.assertIn("active=2", output)
        self.assertNotIn("SECRET-EVIDENCE-VALUE", output)
        self.assertNotIn("provider response body", output)

    def test_progress_allows_collection_accounting_fields(self) -> None:
        stream = io.StringIO()
        reporter = analysis_cli_output.ProgressReporter(
            scope="collection",
            scope_id="IR1",
            stream=stream,
            heartbeat_seconds=0,
            throttle_seconds=0,
        )
        reporter.emit(
            phase="submitting",
            command="queue",
            artifact="Generic.Client.Info",
            flow_id="F.1234",
            completed=1,
            total=2,
            elapsed_seconds=1.25,
        )
        output = stream.getvalue()
        self.assertIn("scope=collection id=IR1", output)
        self.assertIn("command=queue", output)
        self.assertIn("flow_id=F.1234", output)
        self.assertIn("completed=1", output)
        self.assertIn("total=2", output)
        self.assertIn("elapsed_seconds=1.25", output)

    def test_heartbeat_reuses_only_sanitized_state(self) -> None:
        stream = io.StringIO()
        reporter = analysis_cli_output.ProgressReporter(
            scope="host",
            scope_id="host 01",
            stream=stream,
            heartbeat_seconds=0,
        )
        reporter.emit(
            phase="provider wait",
            artifact="Windows.System.Pslist\nINJECTED=1",
            force=True,
        )
        reporter.heartbeat()
        lines = stream.getvalue().splitlines()
        self.assertEqual(2, len(lines))
        self.assertIn("id=host_01", lines[-1])
        self.assertIn("heartbeat=1", lines[-1])
        self.assertNotIn("\nINJECTED", lines[-1])


if __name__ == "__main__":
    unittest.main()
