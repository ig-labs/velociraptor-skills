"""Priority controls presentation without changing acceptance or confidence."""
import asyncio
import copy
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_collection_analysis_runtime as runtime_fixtures
from test_host_final_review import artifact_result, autoruns, review_output, run_review
from vraptor.analyze import (
    final_review,
    host,
    recovery,
    report_priority,
    reporting,
    runtime,
    summary,
)


def test_late_high_priority_displaces_low_priority_without_discarding_findings():
    findings = [
        {"id": f"L{i:03}", "report_priority": "low", "confidence": "high"}
        for i in range(20)
    ]
    findings.append({"id": "H1", "report_priority": "high", "confidence": "low"})
    before = copy.deepcopy(findings)
    ranked = report_priority.rank_findings(findings)
    assert ranked[0]["id"] == "H1"
    assert len(ranked[:20]) == 20
    assert ranked[20]["id"] == "L019"
    assert len(ranked) == 21
    assert findings == before


def test_ranking_does_not_depend_on_completion_order():
    findings = [
        {"id": f"F{i:03}", "report_priority": level, "summary": f"Item {i}"}
        for i, level in enumerate(report_priority.PRIORITIES * 10)
    ]
    expected = report_priority.rank_findings(findings)
    for seed in range(10):
        random.Random(seed).shuffle(findings)
        assert report_priority.rank_findings(findings) == expected


def test_legacy_findings_are_unranked_not_confidence_ranked():
    findings = [{"id": "B", "confidence": "high"}, {"id": "A", "confidence": "low"}]
    ranked = report_priority.rank_findings(findings)
    assert [item["id"] for item in ranked] == ["A", "B"]
    assert {item["report_priority"] for item in ranked} == {"unranked"}
    assert all(item["priority_rationale"] == "" for item in ranked)


def test_unranked_precedes_low_and_numbered_ids_have_natural_order():
    findings = [{"id": "F10"}, {"id": "F2"}, {"id": "F1"},
                {"id": "low", "report_priority": "low"}]
    assert [item["id"] for item in report_priority.rank_findings(findings)] == ["F1", "F2", "F10", "low"]


@pytest.mark.parametrize("legacy", [
    {"severity": "HIGH"}, {"Severity": "high"}, {"ai_review": {"severity": "high"}},
])
def test_explicit_legacy_severity_is_preserved(legacy):
    assert report_priority.priority_metadata(legacy) == {
        "report_priority": "high", "priority_rationale": "Existing explicit severity: high.",
    }


def test_priority_has_precedence_over_severity_and_confidence():
    assert report_priority.priority_metadata({
        "report_priority": "low", "severity": "critical", "confidence": "high",
        "priority_rationale": "Limited impact in the reviewed scope.",
    }) == {
        "report_priority": "low", "priority_rationale": "Limited impact in the reviewed scope.",
    }
    assert report_priority.priority_metadata({"severity": "info"})["report_priority"] == "informational"
    assert report_priority.priority_metadata({"report_priority": "invalid", "severity": "critical"})["report_priority"] == "unranked"


def with_priority(record="PRIORITY\tM1\thigh\tCorroborated persistence requires prompt containment review."):
    return review_output().replace("EVIDENCE\tM1\t", record + "\nEVIDENCE\tM1\t")


def test_priority_is_added_by_existing_final_review_without_extra_calls():
    calls = []
    result = run_review([autoruns()], with_priority(), calls=calls)["host_result"]
    finding = result["findings"][0]
    assert len(calls) == 1
    assert finding["report_priority"] == "high"
    assert finding["priority_rationale"] == "Corroborated persistence requires prompt containment review."
    assert finding["confidence"] == "high"
    assert finding["evidence"][0]["ref"] == "S0001-R5"
    assert result["priority_schema_version"] == 1
    assert result["final_review"]["version"] == 4
    assert "not evidence confidence" in calls[0].prompt
    published = final_review.artifact_publication(autoruns(), result)
    assert published["findings"][0]["report_priority"] == "high"


def test_old_review_without_priority_is_still_valid():
    calls = []
    result = run_review([autoruns()], review_output(), calls=calls)["host_result"]
    assert result["final_review"]["status"] == "complete"
    assert result["findings"][0]["report_priority"] == "unranked"
    assert len(calls) == 1


@pytest.mark.parametrize("record", [
    "PRIORITY\tM99\thigh\tUnknown finding.",
    "PRIORITY\tM1\turgent\tInvalid priority.",
    "PRIORITY\tM1\thigh\t",
    "PRIORITY\tM1\thigh",
    "PRIORITY\tM1\thigh\tFirst.\nPRIORITY\tM1\tlow\tDuplicate.",
])
def test_invalid_priority_cannot_publish_supported_findings(record):
    result = run_review([autoruns()], with_priority(record))["host_result"]
    assert result["final_review"]["status"] == "failed"
    assert result["findings"] == []


def test_hunt_synthesis_accepts_same_priority_record():
    output = with_priority().split("DISPOSITIONS")[0] + "END"
    result = run_review([autoruns(), artifact_result(1)], output, plan={"scope_type": "hunt"})["host_result"]
    assert result["findings"][0]["report_priority"] == "high"
    assert "final_review" not in result


def test_follow_up_limit_only_changes_rendering_not_acceptance_or_prompt():
    additional = "\n".join(f"Bounded action {i}." for i in range(2, 7))
    output = review_output().replace("DISPOSITIONS", additional + "\nDISPOSITIONS")
    prompts = []
    for limit in (1, 2, 5):
        with reporting.reporting_scope(reporting.ReportingPolicy(follow_up_actions=limit)):
            calls = []
            result = run_review([autoruns()], output, calls=calls)["host_result"]
            rendered = summary.render_follow_up(result)
        assert result["final_review"]["status"] == "complete"
        assert len(result["bounded_follow_up"]) == 6
        assert len(calls) == 1
        assert f"Bounded action {limit + 1}." not in "\n".join(rendered)
        prompts.append(calls[0].prompt)
    assert len(set(prompts)) == 1


def test_set_and_frozenset_ties_are_stable_across_python_hash_seeds():
    script = """
import json
from vraptor.analyze.report_priority import rank_findings, priority_key
findings = [
    {"summary": "same", "observed": {"alpha", "omega", "beta", "gamma"},
     "nested": {"endpoints": frozenset({"host-z", "host-a"}), "refs": {("S2", 2), ("S1", 1)}}},
    {"summary": "same", "observed": {"theta", "epsilon", "delta", "mu"},
     "nested": {"endpoints": frozenset({"host-x", "host-b"}), "refs": {("S4", 4), ("S3", 3)}}},
]
print(json.dumps([priority_key(item)[-1] for item in rank_findings(findings)]))
"""
    outputs = []
    for seed in (1, 7, 37, 211):
        completed = subprocess.run(
            [sys.executable, "-c", script], check=True, capture_output=True, text=True,
            env={**os.environ, "PYTHONHASHSEED": str(seed),
                 "PYTHONPATH": str(Path(report_priority.__file__).resolve().parents[2])},
        )
        outputs.append(json.loads(completed.stdout))
    assert all(output == outputs[0] for output in outputs)
    assert len(outputs[0]) == 2


def worker_output(priority="high"):
    priority_line = (
        f"PRIORITY\tF1\t{priority}\tMaterial evidence merits prompt investigation.\n"
        if priority is not None else ""
    )
    return (
        "RESULT\tfindings\nFINDING\tF1\tmedium\tExecution\tQuestion-relevant execution.\n"
        + priority_line + "EVIDENCE\tF1\tS0001-R1\nEND"
    )


def parse_worker(output, **kwargs):
    return host.validate_context_worker_result(
        output, artifact="Artifact.0", chunk_index=0, chunk_count=1,
        row_start=0, row_end=1, expected_row_count=1,
        source_rows={"S0001-R1": {"Command": "synthetic.exe"}},
        **kwargs,
    )


def test_chunk_priority_survives_preliminary_publication_and_synthesis_input():
    worker = parse_worker(worker_output())
    assert worker["findings"][0]["report_priority"] == "high"
    assert "PRIORITY\tF1\thigh\t" in runtime._compact_worker_result(worker)
    artifact = runtime._direct_artifact_result(
        task={"task_id": "A1", "artifact": "Artifact.0"}, worker=worker,
    )
    assert artifact["findings"][0]["report_priority"] == "high"
    assert artifact["findings"][0]["confidence"] == "medium"
    assert artifact["findings"][0]["evidence"][0]["ref"] == "S0001-R1"


def test_legacy_chunk_is_accepted_as_unranked():
    assert parse_worker(worker_output(None))["findings"][0]["report_priority"] == "unranked"


@pytest.mark.parametrize("output", [
    worker_output("urgent"),
    worker_output().replace("PRIORITY\tF1", "PRIORITY\tF2"),
    worker_output().replace("EVIDENCE", "PRIORITY\tF1\tlow\tDuplicate.\nEVIDENCE"),
])
def test_invalid_chunk_priority_is_rejected(output):
    with pytest.raises(host.WorkerResultError, match="PRIORITY"):
        parse_worker(output)


@pytest.mark.parametrize("level", report_priority.PRIORITIES)
@pytest.mark.parametrize("scope", ["host", "hunt"])
def test_four_priorities_work_in_host_and_hunt_prompts_and_validation(level, scope):
    output = with_priority(f"PRIORITY\tM1\t{level}\tEvidence-proportionate urgency.")
    if scope == "hunt":
        output = output.split("DISPOSITIONS")[0] + "END"
    calls = []
    artifacts = [autoruns(), artifact_result(1)] if scope == "hunt" else [autoruns()]
    result = run_review(artifacts, output, plan={"scope_type": scope}, calls=calls)["host_result"]
    assert result["findings"][0]["report_priority"] == level
    assert "<critical|high|medium|low>" in calls[0].prompt
    assert "<critical|high|medium|low|informational" not in calls[0].prompt
    assert "FINDING, PRIORITY, and EVIDENCE" in calls[0].prompt


@pytest.mark.parametrize("level", ["informational", "unranked"])
def test_new_output_cannot_assign_legacy_only_priorities(level):
    with pytest.raises(host.WorkerResultError, match="PRIORITY"):
        parse_worker(worker_output(level))
    result = run_review([autoruns()], with_priority(f"PRIORITY\tM1\t{level}\tLegacy label."))["host_result"]
    assert result["final_review"]["status"] == "failed"


@pytest.mark.parametrize("level", report_priority.RETAINED_PRIORITIES)
def test_recovery_preserves_priority_confidence_rationale_and_references(level):
    worker = parse_worker(worker_output(level), allow_legacy_priority=True)
    original = copy.deepcopy(worker)
    restored = parse_worker(recovery.worker_text(worker), allow_legacy_priority=True)
    assert restored == original
    assert worker == original


def test_legacy_informational_is_retained_without_reclassification():
    result = {"findings": [{"id": "F1", "summary": "Saved observation", "confidence": "high",
                            "report_priority": "informational"},
                           {"id": "F2", "summary": "Old finding", "confidence": "low"}]}
    original = copy.deepcopy(result)
    compact = summary.compact_result(result)
    text = "\n".join(summary.render_compact_findings(compact))
    assert "Report priority: `informational`" in text
    assert "Report priority: `Not assessed`" in text
    assert compact["findings"][0]["report_priority"] == "unranked"
    assert result == original


@pytest.mark.parametrize("level", ["high", "informational", "unranked"])
def test_runtime_restores_saved_priority_without_new_inference(tmp_path, level):
    plan, chunks = runtime_fixtures.CollectionAnalysisRuntimeTest().build(
        artifact_count=1, rows=[{"Command": "synthetic.exe"}], limit=1000,
    )
    cached = parse_worker(worker_output(level), allow_legacy_priority=True)

    def unexpected(*args, **kwargs):
        raise AssertionError("Accepted chunk should be reused without model calls")

    run = asyncio.run(runtime.execute_analysis_workload_async(
        plan=plan, chunk_csv=chunks, question="What happened?", spec=runtime_fixtures.spec(),
        workdir=tmp_path, output_dir=tmp_path, execute=unexpected,
        perform_scope_synthesis=False,
        chunk_recovery=SimpleNamespace(get=lambda task: copy.deepcopy(cached), accept=unexpected),
    ))
    assert run["artifact_results"][0]["findings"][0]["report_priority"] == level
    assert run["tasks"][0]["reused"] is True
