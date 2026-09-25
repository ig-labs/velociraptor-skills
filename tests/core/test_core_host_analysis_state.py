from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vraptor.analyze import checkpoints as host_analysis_state


def flow(**overrides):
    value = {
        "artifact": "Artifact.Test",
        "artifact_name": "Artifact.Test",
        "flow_id": "F.1",
        "flow_state": "FINISHED",
        "created": "1",
        "last_active": "2",
        "total_rows": 10,
        "is_finished": True,
        "available_result_components": ["Artifact.Test"],
        "run_identity_sha256": "run",
    }
    value.update(overrides)
    return value


def payload(*items):
    return {
        "request_id": "request-1",
        "state_file": "/case/request.json",
        "all_artifacts_expected_complete": True,
        "artifact_flows": list(items),
    }


class HostAnalysisStateTest(unittest.TestCase):
    def make_state(self):
        return host_analysis_state.new_state(
            hostname="host01",
            client_id="C.1",
            request_id="request-1",
            analysis_identity="analysis",
        )

    def test_reconcile_schedules_terminal_artifact(self):
        state = self.make_state()

        runnable = host_analysis_state.reconcile(
            state,
            payload=payload(flow()),
            analysis_identity="analysis",
        )

        self.assertEqual([item["artifact"] for item in runnable], ["Artifact.Test"])
        self.assertEqual(
            state["artifacts"]["Artifact.Test"]["analysis_status"], "pending"
        )

    def test_reconcile_defers_open_and_failed_without_output(self):
        state = self.make_state()

        runnable = host_analysis_state.reconcile(
            state,
            payload=payload(
                flow(artifact="Open", flow_id="F.2", is_finished=False),
                flow(
                    artifact="Failed",
                    flow_id="F.3",
                    flow_state="ERROR",
                    total_rows=0,
                    available_result_components=[],
                ),
            ),
            analysis_identity="analysis",
        )

        self.assertEqual(runnable, [])
        self.assertEqual(state["artifacts"]["Open"]["analysis_status"], "waiting")
        self.assertEqual(
            state["artifacts"]["Failed"]["analysis_status"], "source_failed"
        )

    def test_completed_artifact_is_reused_only_when_source_matches(self):
        state = self.make_state()
        item = flow()
        host_analysis_state.reconcile(
            state,
            payload=payload(item),
            analysis_identity="analysis",
        )
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "artifact.md"
            report.write_text("# report\n", encoding="utf-8")
            host_analysis_state.mark_artifact_complete(
                state,
                "Artifact.Test",
                status="complete",
                result={"artifact": "Artifact.Test", "status": "complete"},
                plan_summary={"source_fingerprint": "source"},
                report_file=report,
            )
            reused = host_analysis_state.reconcile(
                state,
                payload=payload(item),
                analysis_identity="analysis",
            )
            reset = host_analysis_state.reconcile(
                state,
                payload=payload(item),
                analysis_identity="analysis",
                reset_artifacts=["Artifact.Test"],
            )
            self.assertEqual([value["artifact"] for value in reset], ["Artifact.Test"])
            self.assertEqual(
                state["artifacts"]["Artifact.Test"]["analysis_status"],
                "pending",
            )
            changed = host_analysis_state.reconcile(
                state,
                payload=payload(flow(total_rows=11)),
                analysis_identity="analysis",
            )

        self.assertEqual(reused, [])
        self.assertEqual([value["artifact"] for value in changed], ["Artifact.Test"])

    def test_degraded_result_uses_binary_complete_component_status(self):
        state = self.make_state()
        host_analysis_state.reconcile(
            state,
            payload=payload(flow()),
            analysis_identity="analysis",
        )
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "artifact.md"
            report.write_text("# partial\n", encoding="utf-8")
            host_analysis_state.mark_artifact_complete(
                state,
                "Artifact.Test",
                status="complete_with_failures",
                result={
                    "artifact": "Artifact.Test",
                    "status": "complete_with_failures",
                },
                plan_summary={"source_fingerprint": "source"},
                report_file=report,
            )

        self.assertEqual(
            state["artifacts"]["Artifact.Test"]["analysis_status"],
            "complete",
        )
        self.assertEqual(
            state["artifacts"]["Artifact.Test"]["result_status"],
            "complete_with_failures",
        )

    def test_running_artifact_is_retried_and_explicit_reset_is_validated(self):
        state = self.make_state()
        state["artifacts"] = {
            "Artifact.Test": {
                "artifact": "Artifact.Test",
                "analysis_status": "running",
            }
        }

        runnable = host_analysis_state.reconcile(
            state,
            payload=payload(flow()),
            analysis_identity="analysis",
        )

        self.assertEqual(len(runnable), 1)
        with self.assertRaisesRegex(ValueError, "not present"):
            host_analysis_state.reconcile(
                state,
                payload=payload(flow()),
                analysis_identity="analysis",
                reset_artifacts=["Artifact.Missing"],
            )

    def test_failed_artifact_is_terminal_until_explicit_reset(self):
        state = self.make_state()
        item = flow()
        host_analysis_state.reconcile(
            state,
            payload=payload(item),
            analysis_identity="analysis",
        )
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "artifact.md"
            report.write_text("# failed\n", encoding="utf-8")
            host_analysis_state.mark_artifact_failed(
                state,
                "Artifact.Test",
                error_class="RuntimeError",
                result={"artifact": "Artifact.Test", "status": "failed"},
                report_file=report,
            )

            reused = host_analysis_state.reconcile(
                state,
                payload=payload(item),
                analysis_identity="analysis",
            )
            reset = host_analysis_state.reconcile(
                state,
                payload=payload(item),
                analysis_identity="analysis",
                reset_artifacts=["Artifact.Test"],
            )

        self.assertEqual(reused, [])
        self.assertEqual([value["artifact"] for value in reset], ["Artifact.Test"])

    def test_failed_artifact_is_included_in_request_checkpoint(self):
        state = self.make_state()
        state["time_filter"] = {
            "coverage": "complete",
            "time_after": "2026-01-01T00:00:00Z",
            "filtered_artifacts": ["Artifact.Test"],
        }
        item = flow()
        host_analysis_state.reconcile(
            state,
            payload=payload(item),
            analysis_identity="analysis",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "artifact.md"
            checkpoint_path = root / "request-analysis.json"
            report.write_text("# failed\n", encoding="utf-8")
            host_analysis_state.mark_artifact_failed(
                state,
                "Artifact.Test",
                error_class="RuntimeError",
                result={"artifact": "Artifact.Test", "status": "failed"},
                report_file=report,
            )
            checkpoint = host_analysis_state.write_request_checkpoint(
                checkpoint_path,
                state=state,
                question="What happened?",
                host_result={"status": "failed"},
                status="failed",
                task_mode="host_forensics",
                response_depth="deep",
            )

        self.assertEqual(checkpoint["status"], "failed")
        self.assertEqual(checkpoint["task_mode"], "host_forensics")
        self.assertEqual(checkpoint["response_depth"], "deep")
        self.assertEqual(checkpoint["time_filter"]["coverage"], "complete")
        self.assertEqual(checkpoint["artifact_summaries"][0]["analysis_status"], "failed")
        self.assertEqual(checkpoint["artifact_summaries"][0]["error_class"], "RuntimeError")

    def test_missing_or_noncanonical_artifact_report_invalidates_cache(self):
        state = self.make_state()
        item = flow()
        host_analysis_state.reconcile(
            state,
            payload=payload(item),
            analysis_identity="analysis",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical_root = root / "artifact-analysis"
            report = root / "outside.md"
            report.write_text("# report\n", encoding="utf-8")
            host_analysis_state.mark_artifact_complete(
                state,
                "Artifact.Test",
                status="complete",
                result={"artifact": "Artifact.Test", "status": "complete"},
                plan_summary={"source_fingerprint": "source"},
                report_file=report,
            )

            noncanonical = host_analysis_state.reconcile(
                state,
                payload=payload(item),
                analysis_identity="analysis",
                report_root=canonical_root,
            )

        self.assertEqual(
            [value["artifact"] for value in noncanonical],
            ["Artifact.Test"],
        )

    def test_unknown_schema_is_rebuilt_and_state_is_atomic_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            original_state = json.dumps({"schema_version": 999})
            original_report = "# Historical host report\n"
            path.write_text(original_state, encoding="utf-8")
            (path.parent / "analysis-host.md").write_text(
                original_report,
                encoding="utf-8",
            )
            state = host_analysis_state.load_or_initialize(
                path,
                hostname="host01",
                client_id="C.1",
                request_id="request-1",
                analysis_identity="analysis",
            )
            host_analysis_state.persist(path, state)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse((path.parent / "previous-analysis").exists())
            self.assertEqual(
                (path.parent / "analysis-host.md").read_text(encoding="utf-8"),
                original_report,
            )

        self.assertEqual(saved["schema_version"], host_analysis_state.SCHEMA_VERSION)
        self.assertEqual(saved["request_id"], "request-1")

    def test_persist_omits_transient_running_status(self):
        state = self.make_state()
        state["status"] = "running"
        state["synthesis"] = {"status": "running", "started_at": "now"}
        state["artifacts"] = {
            "Artifact.Test": {
                "artifact": "Artifact.Test",
                "analysis_status": "running",
                "started_at": "now",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            host_analysis_state.persist(path, state)
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertNotIn("status", saved)
        self.assertNotIn("synthesis", saved)
        self.assertNotIn("analysis_status", saved["artifacts"]["Artifact.Test"])
        self.assertNotIn("started_at", saved["artifacts"]["Artifact.Test"])


if __name__ == "__main__":
    unittest.main()
