"""Confidence formatting is tolerated without converting priority into certainty."""

import json

import pytest
from vraptor.analyze import host, recovery, runtime


def worker(confidence):
    return host.validate_context_worker_result(
        f"RESULT\tfindings\nFINDING\tF1\t{confidence}\tExecution\tExecution observed.\n"
        "EVIDENCE\tF1\tS0001-R1\nEND",
        artifact="Artifact.Test",
        chunk_index=0,
        chunk_count=1,
        row_start=0,
        row_end=1,
        expected_row_count=1,
        source_rows={"S0001-R1": {"Command": "whoami"}},
    )


def synthesis(confidence):
    return host.validate_analysis_story(
        "ANSWER\nExecution observed.\nFINDINGS\n"
        f"FINDING\tM1\t{confidence}\tExecution\tExecution observed.\n"
        "EVIDENCE\tM1\tS0001-R1\nRELEVANT_CONTEXT\nNone.\n"
        "LIMITATIONS\nIntent unknown.\nFOLLOW_UP\nReview intent.\nEND",
        task="execution",
        question="Was execution observed?",
        expected_chunks=[{
            "artifact": "Artifact.Test", "chunk_index": 0, "chunk_count": 1,
            "row_start": 0, "row_end": 1, "row_count": 1,
        }],
        accepted_chunks={"chunk-1": worker("medium")},
    )


@pytest.mark.parametrize("validate", [worker, synthesis])
@pytest.mark.parametrize("value,expected", [
    ("low", "low"), ("medium", "medium"), ("high", "high"),
    (" HIGH ", "high"), ("Medium", "medium"), (" low ", "low"),
])
def test_confidence_normalizes_only_formatting(validate, value, expected):
    finding = validate(value)["findings"][0]
    assert finding["confidence"] == expected
    assert finding["report_priority"] == "unranked"


@pytest.mark.parametrize("validate", [worker, synthesis])
@pytest.mark.parametrize("value", ["critical", " INFORMATIONAL ", "unranked"])
def test_priority_is_rejected_with_safe_correction_details(validate, value):
    with pytest.raises(host.WorkerResultError) as caught:
        validate(value)
    defect = caught.value.diagnostics[0]
    assert defect["code"] == "invalid_confidence"
    assert defect["allowed"] == ["high", "low", "medium"]
    assert defect["reason"] == "priority_used_as_confidence"
    assert defect["received"] == value.strip().casefold()
    retained = recovery.task_diagnostics({"attempt_history": [{
        "status": "failed", "run": {"status": "succeeded"},
        "diagnostics": caught.value.diagnostics,
    }]})
    assert "priority_used_as_confidence" in json.dumps(retained)
    assert value.strip().casefold() in json.dumps(retained)


@pytest.mark.parametrize("validate", [worker, synthesis])
@pytest.mark.parametrize("value", ["0.95", "95%", "moderate", "private-source-marker", ""])
def test_unsupported_confidence_is_not_inferred_or_logged(validate, value):
    with pytest.raises(host.WorkerResultError) as caught:
        validate(value)
    defect = caught.value.diagnostics[0]
    assert defect["reason"] == "unsupported_confidence"
    assert "received" not in defect
    assert "private-source-marker" not in str(caught.value)
    assert "private-source-marker" not in json.dumps(caught.value.diagnostics)


def test_both_prompts_separate_confidence_from_priority():
    chunk = runtime.render_chunk_prompt(
        plan={"collection_type": "triage", "request_id": "test"},
        chunk={"artifact": "Artifact.Test", "task_chunk_index": 0,
               "task_chunk_count": 1, "row_start": 0, "row_end": 1, "row_count": 1},
        question="Was execution observed?",
        csv_evidence="_SourceRef,Command\nS0001-R1,whoami\n",
    )
    story = runtime.render_synthesis_prompt(
        task="execution", question="Was execution observed?",
        accepted_chunks={"chunk-1": worker("medium")}, failures={},
    )
    for prompt in (chunk, story):
        assert "FINDING<TAB>id<TAB>low|medium|high<TAB>tactics<TAB>text" in prompt
        assert "Never use critical, informational, or unranked as confidence" in prompt
