from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from vraptor.analyze import forward as collection_analysis_forward
from vraptor.analyze import checkpoints as host_analysis_state


class CollectionAnalysisForwardTest(unittest.TestCase):
    def _write_outputs(
        self,
        case_root: Path,
        *,
        status: str,
        provisional: bool = False,
    ) -> dict[str, object]:
        host_root = case_root / "IR1" / "systems" / "host01"
        request_analysis = (
            host_root / "collection" / "requests" / "request-1" / "analysis"
        )
        artifact_report = request_analysis / "artifact-analysis" / "Artifact.Test.md"
        artifact_report.parent.mkdir(parents=True)
        artifact_report.write_text("# Artifact.Test\n", encoding="utf-8")
        state = host_analysis_state.new_state(
            hostname="host01",
            client_id="C.1",
            request_id="request-1",
            analysis_identity="analysis",
        )
        state["artifacts"] = {
            "Artifact.Test": {
                "artifact": "Artifact.Test",
                "artifact_name": "Artifact.Test",
                "flow_id": "F.1",
                "velociraptor_state": "FINISHED",
                "source_fingerprint": "source",
                "analysis_status": status,
                "attempts": 2,
                "report_file": str(artifact_report),
                "report_sha256": hashlib.sha256(artifact_report.read_bytes()).hexdigest(),
                "result": {},
                "plan_summary": {},
            }
        }
        checkpoint_path = request_analysis / "request-analysis.json"
        checkpoint = host_analysis_state.write_request_checkpoint(
            checkpoint_path,
            state=state,
            question="What is relevant?",
            host_result={
                "coverage": {"planned_rows": 5, "reviewed_rows": 4},
                "domain_assessments": {
                    "execution": {"status": "unknown_due_to_coverage"}
                },
            },
            status=status,
        )
        state["status"] = status
        state["synthesis"] = {
            "status": status,
            "request_checkpoint_file": str(checkpoint_path),
            "request_checkpoint_sha256": hashlib.sha256(
                checkpoint_path.read_bytes()
            ).hexdigest(),
        }
        state_path = host_root / "host-analysis-state.json"
        host_analysis_state.persist(state_path, state)
        host_report = host_root / "analysis-host.md"
        host_report.write_text(
            "> Provisional running report\n" if provisional else "# Final report\n",
            encoding="utf-8",
        )
        return {
            "status": status,
            "hostname": "host01",
            "client_id": "C.1",
            "request_id": "request-1",
            "request_checkpoint_file": str(checkpoint_path),
            "host_state_file": str(state_path),
            "host_report_file": str(host_report),
            "artifact_report_files": {"Artifact.Test": str(artifact_report)},
            "analysis_result": checkpoint["result"],
        }

    def test_command_is_saved_request_only(self):
        command = collection_analysis_forward.build_saved_request_command(
            repo_root=Path("/repo"),
            case_root=Path("/cases"),
            investigation_id="IR1",
            hostname="host01",
            client_id="C.1",
            request_id="request-1",
            question="What is relevant?",
        )

        self.assertIn("--request-id", command)
        self.assertNotIn("--host", command)
        self.assertNotIn("--collection-type", command)
        self.assertNotIn("--artifact", command)
        self.assertNotIn("--force-run", command)
        self.assertEqual("json", command[command.index("--format") + 1])
        self.assertIn("--no-progress", command)

    def test_validate_outputs_checks_hashes_coverage_and_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            case_root = Path(directory)
            result = self._write_outputs(
                case_root,
                status="complete_with_failures",
            )

            validation = collection_analysis_forward.validate_forward_outputs(
                result,
                case_root=case_root,
                investigation_id="IR1",
                hostname="host01",
                client_id="C.1",
                request_id="request-1",
                saw_provisional_report=True,
            )

        self.assertEqual(validation["status"], "complete_with_failures")
        self.assertEqual(validation["planned_rows"], 5)
        self.assertEqual(validation["reviewed_rows"], 4)
        self.assertEqual(validation["retried_tasks"], ["Artifact.Test"])
        self.assertTrue(validation["saw_provisional_report"])

    def test_validate_outputs_rejects_provisional_or_mismatched_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            case_root = Path(directory)
            result = self._write_outputs(
                case_root,
                status="complete",
                provisional=True,
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "canonical host report remained provisional",
            ):
                collection_analysis_forward.validate_forward_outputs(
                    result,
                    case_root=case_root,
                    investigation_id="IR1",
                    hostname="host01",
                    client_id="C.1",
                    request_id="request-1",
                    saw_provisional_report=True,
                )


if __name__ == "__main__":
    unittest.main()
