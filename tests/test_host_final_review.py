"""Synthetic publication-review contracts. No live evidence or model calls."""
import asyncio
import copy
import unittest

from vraptor.analyze import summary as analysis_summary
from vraptor.analyze import final_review as host_final_review
from vraptor.analyze import runtime
from test_collection_analysis_runtime import artifact_result, successful, spec, profiles, payload, TEST_LIMITS
from vraptor.analyze import host as collection_analysis
from pathlib import Path


def autoruns():
    result = artifact_result(0, artifact="Windows.Sysinternals.Autoruns")
    labels = ["Administrative policy bypass", "Configured RMM", "Missing-file registration",
              "Unverified signature", "Corroborated malicious persistence"]
    commands = ["powershell -ExecutionPolicy Bypass maintenance.ps1", "RemoteSupport.exe",
                "missing.exe", "unknown.exe", "payload.exe"]
    result["coverage"] = dict(planned_chunks=1, accepted_chunks=1, planned_rows=5, reviewed_rows=5)
    result["findings"] = [{"id": f"F{i}", "confidence": "high", "domains": ["Persistence"],
                           "summary": label, "evidence": [{"ref": f"S0001-R{i}",
                           "artifact": result["artifact"], "chunk_index": 0, "chunk_count": 1,
                           "fields": {"Command": commands[i-1], "ProcessCorroboration": i == 5},
                           "source": {"flow_id": "F.synthetic", "source_row_number": i}}]}
                          for i, label in enumerate(labels, 1)]
    return result


def review_output(*, malicious=True):
    dispositions = [
        "DISPOSITION\tA0001:F1\tomit\t-\tS0001-R1\tPolicy bypass alone is consistent with maintenance; no incident link established.",
        "DISPOSITION\tA0001:F2\trelevant_context\t-\tS0001-R2\tConfigured remote support affects interpretation; authorization and execution remain unknown.",
        "DISPOSITION\tA0001:F3\tomit\t-\tS0001-R3\tMissing registration target alone does not establish execution or incident relevance.",
        "DISPOSITION\tA0001:F4\tinvestigative_lead\t-\tS0001-R4\tSignature verification is incomplete; check exact file identity and provenance.",
        ("DISPOSITION\tA0001:F5\tsupported_finding\tM1\tS0001-R5\tExecution corroborates malicious persistence and affects containment."
         if malicious else "DISPOSITION\tA0001:F5\tinvestigative_lead\t-\tS0001-R5\tResolve provenance before concluding incident relevance."),
    ]
    return "\n".join(["ANSWER", "One supported persistence finding." if malicious else "No supported findings; leads remain unresolved.",
        "FINDINGS", *( ["FINDING\tM1\thigh\tPersistence\tCorroborated malicious persistence.", "EVIDENCE\tM1\tS0001-R5"] if malicious else ["None."]),
        "RELEVANT_CONTEXT", "None.", "LIMITATIONS", "Authorization coverage is incomplete.",
        "FOLLOW_UP", "Validate the exact payload process and contain the affected host if confirmed.",
        "DISPOSITIONS", *dispositions, "END"])


def run_review(results, output, *, plan=None, calls=None):
    def execute(task):
        if calls is not None:
            calls.append(task)
        return successful(task, output)
    return asyncio.run(runtime.execute_host_synthesis_from_artifact_results_async(
        plan=plan or {"task_mode": "incident_response"}, artifact_results=results,
        question="Does this persistence affect incident containment?", execute=execute))


class HostFinalReviewTest(unittest.TestCase):
    def test_confidence_increase_is_rejected_with_actionable_defect(self):
        inputs = [autoruns()]
        inputs[0]["findings"][-1]["confidence"] = "low"
        run = run_review(inputs, review_output())
        self.assertEqual(run["host_result"]["final_review"]["status"], "failed")
        defect = run["tasks"][0]["attempt_history"][-1]["diagnostics"][0]
        self.assertEqual(defect["code"], "unsupported_confidence_increase")
        self.assertEqual(defect["allowed"], ["low"])

    def test_routine_entries_downgraded_and_malicious_entry_retained(self):
        inputs = [autoruns()]
        before = copy.deepcopy(inputs)
        calls = []
        reviewed = run_review(inputs, review_output(), calls=calls)["host_result"]
        self.assertEqual(inputs, before)
        self.assertEqual(len(calls), 1)
        self.assertEqual(reviewed["finding_count"], 1)
        self.assertEqual(reviewed["findings"][0]["evidence"][0]["ref"], "S0001-R5")
        self.assertEqual(reviewed["final_review"]["candidate_count"], 5)
        self.assertEqual(len(reviewed["final_review"]["dispositions"]), 5)
        self.assertEqual(len(reviewed["investigative_leads"]), 1)
        self.assertEqual(reviewed["relevant_context"][0]["ref"], "S0001-R2")
        self.assertEqual(reviewed["investigative_leads"][0]["source"]["flow_id"], "F.synthetic")
        self.assertNotIn("_full_fields", analysis_summary.compact_result(reviewed)["investigative_leads"][0])
        self.assertIn('"ProcessCorroboration": true', calls[0].prompt)
        self.assertIn('"reviewed_rows": 5', calls[0].prompt)
        for marker in ("original question", "GoldenDB mismatch", "incident_response", "configured persistence", "benign explanations"):
            self.assertIn(marker, calls[0].prompt)

    def test_selected_profile_and_source_reduction_reach_reviewer(self):
        calls = []
        plan = {"task_mode": "targeted_hunt", "analysis_profile": "standalone",
                "analysis_objectives": ["Identify relevant security observations"],
                "artifacts": [{"artifact": "Windows.Sysinternals.Autoruns",
                               "strategy_metadata": {"input_rows": 20,
                               "known_good_filtered_rows": 15, "residual_rows": 5}}]}
        run_review([autoruns()], review_output(), plan=plan, calls=calls)
        self.assertIn('"known_good_filtered_rows": 15', calls[0].prompt)
        self.assertIn('"task_mode": "targeted_hunt"', calls[0].prompt)
        self.assertIn('"analysis_profile": "standalone"', calls[0].prompt)

    def test_single_artifact_single_chunk_runs_final_review(self):
        plan, chunks = collection_analysis.build_analysis_workload(
            object(), payload(1, 1), limits=TEST_LIMITS, collection_type="triage", profiles=profiles(1),
            query_rows=lambda *_: [{"When": "2026-09-01T00:00:00Z", "Command": "maintenance"}])
        stages = []
        def execute(task):
            stages.append(task.metadata["stage"])
            output = "RESULT\tno_reportable_findings\nEND" if task.metadata["stage"] == "chunk" else (
                "ANSWER\nNo supported findings in accepted evidence.\nFINDINGS\nNone.\nRELEVANT_CONTEXT\nNone.\n"
                "LIMITATIONS\nNo execution telemetry.\nFOLLOW_UP\nNone.\nDISPOSITIONS\nNone.\nEND")
            return successful(task, output)
        result = asyncio.run(runtime.execute_analysis_workload_async(
            plan=plan, chunk_csv=chunks, question="What executed?", spec=spec(),
            workdir=Path("/synthetic"), output_dir=Path("/synthetic"), execute=execute))
        self.assertEqual(stages, ["chunk", "host-synthesis"])
        self.assertEqual(result["host_result"]["final_review"]["status"], "complete")
        self.assertEqual(result["host_result"]["finding_count"], 0)

    def test_multiple_artifacts_share_one_final_review(self):
        calls = []
        result = run_review([autoruns(), artifact_result(1)], review_output(), calls=calls)
        self.assertEqual([t.metadata["stage"] for t in calls], ["host-synthesis"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["host_result"]["coverage"]["reviewed_rows"], 7)

    def test_zero_supported_findings_and_partial_coverage(self):
        candidate = autoruns()
        candidate["status"] = "complete_with_failures"
        candidate["coverage"].update(planned_rows=10, planned_chunks=2)
        candidate["limitations"] = ["Second chunk unavailable."]
        result = run_review([candidate], review_output(malicious=False))["host_result"]
        self.assertEqual(result["status"], "complete_with_failures")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["final_review"]["status"], "complete")
        self.assertEqual(result["coverage"]["reviewed_rows"], 5)
        self.assertIn("Second chunk unavailable.", result["limitations"])

    def test_invalid_review_retries_twice_and_keeps_candidates_provisional(self):
        inputs = [autoruns()]
        before = copy.deepcopy(inputs)
        invalid = [
            review_output().replace("DISPOSITIONS\n", ""),
            review_output().replace("A0001:F1\tomit", "A0001:F2\tomit"),
            review_output().replace("A0001:F1\tomit", "A0001:F99\tomit"),
            review_output().replace("S0001-R1\tPolicy", "S0001-R99\tPolicy"),
            review_output().replace("S0001-R1\tPolicy", "S0001-R2\tPolicy"),
            review_output().replace("supported_finding\tM1", "supported_finding\tM9"),
            review_output().replace("\tExecution corroborates malicious persistence and affects containment.", "\t"),
        ]
        for output in invalid:
            with self.subTest(output=output[-80:]):
                calls = []
                result = run_review(inputs, output, calls=calls)
                self.assertEqual(len(calls), 3)
                self.assertEqual(result["status"], "complete_with_failures")
                self.assertEqual(result["host_result"]["findings"], [])
                self.assertEqual(result["host_result"]["final_review"]["status"], "failed")
                self.assertEqual(inputs, before)
        # A retry consumes the same accepted result, with no acquisition/chunk API.
        self.assertEqual(run_review(inputs, review_output())["status"], "complete")

    def test_dispositions_control_reports_and_compact_state(self):
        candidate = autoruns()
        reviewed = run_review([candidate], review_output())["host_result"]
        publication = host_final_review.artifact_publication(candidate, reviewed)
        for result in (reviewed, publication):
            result["finding_count"] = 77  # stale pre-review count must never win
            compact = analysis_summary.compact_result(result)
            self.assertEqual(compact["finding_count"], 1)
            self.assertEqual(analysis_summary.compact_result(compact)["finding_count"], 1)
            self.assertEqual(compact["final_review"], reviewed["final_review"])
            for report in (analysis_summary.render_chat_summary(result), analysis_summary.render_artifact_report(result)):
                self.assertIn("Corroborated malicious persistence", report)
                self.assertIn("Unresolved investigative leads", report)
                self.assertIn("Candidate dispositions", report)
                self.assertNotIn("### F1", report)
                self.assertNotIn("Administrative policy bypass", report)

    def test_hunt_synthesis_contract_is_unchanged(self):
        plain = "ANSWER\nNo findings.\nFINDINGS\nNone.\nRELEVANT_CONTEXT\nNone.\nLIMITATIONS\nNone.\nFOLLOW_UP\nNone.\nEND"
        result = run_review([artifact_result(0), artifact_result(1)], plain, plan={"scope_type": "hunt"})
        self.assertEqual(result["status"], "complete")
        self.assertNotIn("final_review", result["host_result"])
