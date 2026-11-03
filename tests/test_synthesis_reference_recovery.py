"""Synthetic reference-role failures and correction; no live evidence or APIs."""

import asyncio
import copy
import json

import pytest
from test_collection_analysis_runtime import successful
from test_host_final_review import autoruns, review_output, run_review
from vraptor.analyze import recovery, runtime


def candidate_with_context():
    result = autoruns()
    result["relevant_context"] = [{
        "ref": "S0002-R1", "chunk_index": 0, "chunk_count": 1,
        "finding_id": "", "context_type": "environment",
        "summary": "Inventory context.", "fields": {"Name": "PRIVATE_CONTEXT_VALUE"},
        "source": {"flow_id": "F.synthetic"},
    }]
    return result


def invalid_review(kind):
    output = review_output()
    if kind == "context_as_evidence":
        return output.replace("EVIDENCE\tM1\tS0001-R5", "EVIDENCE\tM1\tS0002-R1")
    if kind == "wrong_candidate":
        return output.replace("S0001-R1\tPolicy", "S0001-R2\tPolicy")
    if kind == "evidence_as_context":
        return output.replace("RELEVANT_CONTEXT\nNone.",
                              "RELEVANT_CONTEXT\nCONTEXT\t-\tS0001-R2\tenvironment\tSupport inventory.")
    return output.replace("One supported persistence finding.", "Review S0099-R1.")


@pytest.mark.parametrize("kind,code,reason", [
    ("context_as_evidence", "unavailable_source", "context_only_reference"),
    ("wrong_candidate", "candidate_reference_mismatch", "wrong_candidate_reference"),
    ("evidence_as_context", "unavailable_context", "evidence_only_reference"),
    ("unknown_reference", "unavailable_source", None),
])
def test_reference_errors_reach_correction_and_diagnostics(kind, code, reason):
    inputs = [candidate_with_context()]
    before = copy.deepcopy(inputs)
    calls = []

    def execute(task):
        calls.append(task)
        return successful(task, invalid_review(kind) if len(calls) == 1 else review_output())

    run = asyncio.run(runtime.execute_host_synthesis_from_artifact_results_async(
        plan={"synthesis_mode": "full"}, artifact_results=inputs,
        question="Assess persistence", execute=execute,
    ))
    assert run["host_result"]["final_review"]["status"] == "complete"
    assert len(calls) == 2
    assert all(task.metadata["stage"] == "host-synthesis" for task in calls)
    assert inputs == before
    record = recovery.task_diagnostics(run["tasks"][0])
    defect = record["attempt_history"][0]["defects"][0]
    assert defect["code"] == code
    if reason:
        assert defect["reason"] == reason
    assert defect["allowed"]
    correction = calls[1].prompt.split("RETRY CORRECTION", 1)[1]
    assert code in correction
    assert "PRIVATE_CONTEXT_VALUE" not in correction
    assert "PRIVATE_CONTEXT_VALUE" not in json.dumps(record)
    if kind == "context_as_evidence":
        assert "S0002-R1" not in defect["allowed"]
    if kind == "evidence_as_context":
        assert defect["allowed"] == ["S0002-R1"]
    if kind == "wrong_candidate":
        assert defect["allowed"] == ["S0001-R1"]


def test_invalid_context_remains_rejected_after_retry_budget():
    inputs = [autoruns()]
    before = copy.deepcopy(inputs)
    calls = []
    run = run_review(inputs, invalid_review("evidence_as_context"), calls=calls)
    assert len(calls) == 3
    assert run["host_result"]["final_review"]["status"] == "failed"
    assert run["host_result"]["findings"] == []
    assert inputs == before
    for attempt in recovery.task_diagnostics(run["tasks"][0])["attempt_history"]:
        assert attempt["defects"][0]["code"] == "unavailable_context"
        assert attempt["defects"][0]["allowed"] == []
    assert "Allowed CONTEXT references: []" in calls[0].prompt


def test_valid_context_and_downgraded_candidates_keep_exact_provenance():
    output = review_output().replace(
        "RELEVANT_CONTEXT\nNone.",
        "RELEVANT_CONTEXT\nCONTEXT\t-\tS0002-R1\tenvironment\tInventory context.",
    )
    calls = []
    run = run_review([candidate_with_context()], output, calls=calls)
    assert len(calls) == 1
    assert 'Allowed CONTEXT references: ["S0002-R1"]' in calls[0].prompt
    context = {r["ref"]: r for r in run["host_result"]["relevant_context"]}
    assert set(context) == {"S0002-R1", "S0001-R2"}
    assert context["S0002-R1"]["fields"] == {"Name": "PRIVATE_CONTEXT_VALUE"}
    assert context["S0001-R2"]["source"]["flow_id"] == "F.synthetic"


@pytest.mark.parametrize("missing_target", [False, True])
def test_supported_candidate_mapping_is_corrected_with_exact_diagnostics(missing_target):
    inputs = [autoruns()]
    extra = copy.deepcopy(inputs[0]["findings"][-1]["evidence"][0])
    extra["ref"] = "S0001-R6"
    extra["source"]["source_row_number"] = 6
    inputs[0]["findings"][-1]["evidence"].append(extra)
    before = copy.deepcopy(inputs)
    invalid = (
        review_output().replace("supported_finding\tM1", "supported_finding\tM9")
        if missing_target else review_output().replace("\tS0001-R5\tExecution", "\tS0001-R5,S0001-R6\tExecution")
    )
    calls = []

    def execute(task):
        calls.append(task)
        return successful(task, invalid if len(calls) == 1 else review_output())

    run = asyncio.run(runtime.execute_host_synthesis_from_artifact_results_async(
        plan={"synthesis_mode": "full"}, artifact_results=inputs,
        question="Assess persistence", execute=execute,
    ))
    assert run["host_result"]["final_review"]["status"] == "complete"
    assert len(calls) == 2
    assert inputs == before
    defect = recovery.task_diagnostics(run["tasks"][0])["attempt_history"][0]["defects"][0]
    assert defect["candidate_id"] == "A0001:F5"
    assert defect["finding_id"] == ("M9" if missing_target else "M1")
    assert defect["code"] == ("missing_mapped_finding" if missing_target else "mapped_finding_evidence_mismatch")
    assert defect["allowed"] == (["M1"] if missing_target else ["S0001-R5"])
    if not missing_target:
        assert defect["missing"] == ["S0001-R6"]
    assert defect["code"] in calls[1].prompt.split("RETRY CORRECTION", 1)[1]


def test_invalid_mapping_does_not_publish_after_exhausted_corrections():
    calls = []
    invalid = review_output().replace("supported_finding\tM1", "supported_finding\tM9")
    run = run_review([autoruns()], invalid, calls=calls)
    assert len(calls) == 3
    assert run["host_result"]["final_review"]["status"] == "failed"
    assert run["host_result"]["findings"] == []
    assert all(a["defects"][0]["code"] == "missing_mapped_finding"
               for a in recovery.task_diagnostics(run["tasks"][0])["attempt_history"])
