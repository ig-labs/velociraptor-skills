"""No-model preparation must not acquire AI credentials or publish reviewed state."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import preparation
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.artifacts import policy as artifact_policy
from vraptor.analyze import command as host
from vraptor.analyze import flow_runtime as runtime
from vraptor.analyze import coordinator
from vraptor.hunt import command as hunt_workflow
from vraptor.hunt import analysis as hunt_analysis
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.artifacts import persistence as persistence_policy
from tests.core.test_core_collection_analysis_cli import (
    args, plan, collection_payload, run_analysis,
)
from tests.test_flow_analysis import flow_row


class SkipAiTest(unittest.TestCase):
    def test_host_skip_ai_prepares_without_credentials_or_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(host.collection, "CASE_ROOT", Path(directory)), \
             mock.patch.object(host, "resolve_collection", return_value=(
                 "host01", collection_payload(), "reused_existing_flows")), \
             mock.patch.object(host, "build_workload", return_value=(plan(), {0: "SECRET_EVIDENCE"})), \
             mock.patch.object(host, "resolve_agent_execution", side_effect=AssertionError("credentials")), \
             mock.patch.object(host, "execute_incremental_analysis_async", side_effect=AssertionError("model")):
            result = run_analysis(object(), args(skip_ai=True))
            self.assertEqual(result["ai_review_status"], "skipped")
            self.assertFalse(result["review_complete"])
            saved = Path(result["analysis_plan_file"]).read_text()
            self.assertNotIn("SECRET_EVIDENCE", saved)
            self.assertEqual(json.loads(saved)["ai_review_status"], "skipped")
            self.assertEqual(len(list(Path(directory).rglob("*.json"))), 1)

    def test_skip_ai_rejects_reset_and_incremental_review_options(self):
        with self.assertRaisesRegex(RuntimeError, "reset"):
            run_analysis(object(), args(skip_ai=True, reset_analysis=True, request_id="r1"))
        values = hunt_workflow.parse_args([
            "analyze", "--id", "test", "--hunt-id", "H.1", "--skip-ai", "--update"])
        with self.assertRaisesRegex(RuntimeError, "omit --update"):
            hunt_workflow.command_analyze(values)

    def test_skip_ai_is_available_on_every_analysis_entry_point(self):
        self.assertTrue(host.build_parser().parse_args([
            "--id", "test", "--client-id", "C.1", "--question", "test", "--skip-ai"]).skip_ai)
        self.assertTrue(hunt_workflow.parse_args([
            "analyze", "--id", "test", "--hunt-id", "H.1", "--skip-ai"]).skip_ai)
        self.assertTrue(hunt_analysis.parse_args(["--snapshot", "/fixture/snapshot.json", "--skip-ai"]).skip_ai)

    def prepare(self, directory, rows, *, fail=False, artifact="Artifact.Test", time_scope=None):
        source = runtime.aggregate_hunt_source(
            org_id="root", hunt_id="H.1", artifact=artifact, watermark="cutoff")
        def stream(*_args, **_kwargs):
            yield runtime.AcquiredSegment(source=source, segment_id="segment1", row_start=0,
                row_end=len(rows), rows=rows, flow_state="aggregate")
            if fail:
                raise RuntimeError("source interrupted")
        with mock.patch.object(runtime, "query_server_cutoff", return_value="cutoff"), \
             mock.patch.object(runtime, "enumerate_hunt_flows", return_value=[flow_row("C.1", "F.1", artifact=artifact)]), \
             mock.patch.object(runtime, "iter_hunt_result_segments", side_effect=stream), \
             mock.patch.object(coordinator, "create_agent_runner", side_effect=AssertionError("model")):
            return preparation.prepare_hunt(object(), org_id="root", hunt_id="H.1",
                hunt_root=Path(directory), selected_artifacts=[artifact],
                policy=artifact_policy.load_artifact_policy(),
                limits=analysis_limits.resolve_analysis_limits({}),
                time_scope=time_scope or analysis_time_scope.TimeScope("all"))

    def test_live_preparation_counts_without_retaining_evidence_or_review_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory)/"analysis/hunt-analysis-state.json"
            state_path.parent.mkdir()
            state_path.write_text('{"previous":"preserve"}')
            result = self.prepare(directory, [{"Value":"PRIVATE_EVIDENCE"}, {"Value":"two"}])
            self.assertEqual(result["row_count"], 2)
            self.assertEqual(result["acquired_row_count"], 2)
            self.assertGreater(result["chunk_count"], 0)
            self.assertEqual(result["reviewed_row_count"], 0)
            self.assertFalse(result["review_complete"])
            saved = Path(result["analysis_plan_file"]).read_text()
            self.assertNotIn("PRIVATE_EVIDENCE", saved)
            persistence_policy.preflight_analysis_tree(Path(directory)/"analysis", ["hunt:H.1"])
            self.assertEqual(state_path.read_text(), '{"previous":"preserve"}')

    def test_live_preparation_failure_preserves_previous_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.prepare(directory, [{"Value":"old"}])
            path = Path(result["analysis_plan_file"])
            before = path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "source interrupted"):
                self.prepare(directory, [{"Value":"partial"}], fail=True)
            self.assertEqual(path.read_bytes(), before)

    def test_empty_preparation_does_not_claim_ai_review(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.prepare(directory, [])
            self.assertEqual(result["row_count"], 0)
            self.assertEqual(result["ai_review_status"], "skipped")
            self.assertFalse(result["review_complete"])

    def test_specialized_stack_skip_bypasses_both_ai_stages(self):
        from tests.test_live_hunt_analysis import FakePivotApi, request
        from vraptor.hunt import live
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(live, "resolve_agent_execution", side_effect=AssertionError("credentials")), \
             mock.patch.object(coordinator, "consolidate_specialized_findings", side_effect=AssertionError("model")):
            result = live.analyze_live_hunt(FakePivotApi(), investigation_id="IR1",
                hunt_row={"hunt_id":"H.sample", "state":"FINISHED"},
                request=request("DetectRaptor.Windows.Detection.Applications"),
                hunt_root=Path(directory)/"H.sample", direct_row_limit=1000, sample_rows=25,
                skip_ai=True, autoruns_ai_review_enabled=True)
            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["result_review_coverage"], "not_reviewed")
            self.assertFalse(result["review_complete"])
            self.assertEqual(result["coverage"], "incomplete")
            state = json.loads((Path(directory)/"H.sample/analysis/hunt-analysis-state.json").read_text())
            self.assertEqual(state["specialized_analysis"]["ai_review_status"], "skipped")
            self.assertNotEqual(state["coverage"]["overall"], "complete")
            self.assertGreater(result["review_item_count"], 0)

    def test_generic_command_routes_skip_before_model_resolution(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            api_path = root / "api.yaml"
            api_path.write_text("fixture")
            values = hunt_workflow.parse_args([
                "analyze", "--id", "test", "--hunt-id", "H.1", "--artifact", "Artifact.Test",
                "--api-client", str(api_path), "--case-root", directory, "--skip-ai"])
            row = dict(hunt_id="H.1", state="FINISHED", artifacts=["Artifact.Test"])
            for name, value in (
                ("discover_hunt_rows", [row]), ("retry_missing_clients", {"status":"disabled"}),
                ("analysis_status_for_row", row),
                ("request_for_selected_row", SimpleNamespace(expected_specs=[SimpleNamespace(artifact="Artifact.Test")])),
            ):
                stack.enter_context(mock.patch.object(hunt_workflow, name, return_value=value))
            stack.enter_context(mock.patch.object(hunt_workflow, "VeloApiClient"))
            stack.enter_context(mock.patch.object(hunt_workflow, "resolve_agent_execution", side_effect=AssertionError("credentials")))
            prepare = stack.enter_context(mock.patch.object(preparation, "prepare_hunt", return_value={
                "hunt_id":"H.1", "status":"prepared", "ai_review_status":"skipped", "review_complete":False}))
            result = hunt_workflow.command_analyze(values)
            prepare.assert_called_once()
            self.assertEqual(result["ai_review_status"], "skipped")
            self.assertFalse(result["review_complete"])

    def test_detectraptor_preparation_uses_partition_scope_and_selected_regex(self):
        artifact = runtime.DETECTRAPTOR_EVTX_ARTIFACT
        from types import SimpleNamespace
        partition = SimpleNamespace(partition_id="p1", detection="Example", row_count=1)
        source = runtime.detectraptor_evtx_partition_source(
            org_id="root", hunt_id="H.1", partition=partition, watermark="cutoff")
        segment = runtime.AcquiredSegment(source=source, segment_id="s1", row_start=0, row_end=1,
            rows=[{"Detection":"Example", "EventData":"test"}], flow_state="aggregate")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(runtime, "query_server_cutoff", return_value="cutoff"), \
             mock.patch.object(runtime, "enumerate_hunt_flows", return_value=[flow_row("C.1", "F.1", artifact=artifact)]), \
             mock.patch.object(runtime, "discover_detectraptor_evtx_partitions", return_value=[partition]) as discover, \
             mock.patch.object(runtime, "iter_detectraptor_evtx_detection_segments", return_value=iter([segment])) as stream, \
             mock.patch.object(runtime, "iter_hunt_result_segments", return_value=iter([])) as generic:
            result = preparation.prepare_hunt(object(), org_id="root", hunt_id="H.1",
                hunt_root=Path(directory), selected_artifacts=[artifact],
                policy=artifact_policy.load_artifact_policy(),
                limits=analysis_limits.resolve_analysis_limits({}),
                time_scope=analysis_time_scope.TimeScope("all"), detection_regex="^Example$")
            self.assertEqual(result["row_count"], 1)
            self.assertEqual(discover.call_args.kwargs["detection_regex"], "^Example$")
            self.assertEqual(stream.call_args.kwargs["detection_regex"], "^Example$")
            self.assertEqual(generic.call_args.kwargs["artifacts"], [])

    def test_text_output_identifies_skipped_review_and_plan(self):
        output = analysis_cli_output.render_final_text(dict(
            status="planned", ai_review_status="skipped", analysis_plan_file="/fixture/analysis-plan.json"))
        self.assertIn("AI review: skipped", output)
        self.assertIn("Plan: /fixture/analysis-plan.json", output)

    def test_preparation_preserves_mapped_time_filter_and_unknown_artifacts(self):
        scope = analysis_time_scope.TimeScope.from_values(
            after="2026-08-01T00:00:00Z", before="2026-08-02T00:00:00Z", roles=["mtime"])
        rows = [
            {"LastModified0x10":"2026-08-01T12:00:00Z", "OSPath":"in-scope"},
            {"LastModified0x10":"2026-07-01T12:00:00Z", "OSPath":"outside-scope"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            result = self.prepare(directory, rows, artifact="Windows.NTFS.MFT", time_scope=scope)
            self.assertEqual(result["row_count"], 1)
            unfiltered = self.prepare(directory, rows, time_scope=scope)
            self.assertEqual(unfiltered["row_count"], 2)
