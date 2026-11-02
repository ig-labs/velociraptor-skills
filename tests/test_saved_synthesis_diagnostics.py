"""Saved synthesis diagnostics remain bounded and never retain model bodies."""

import asyncio
import json
from pathlib import Path

import pytest
from test_collection_analysis_runtime import TEST_LIMITS, spec, successful
from test_host_final_review import review_output
from test_synthesis_modes import make_checkpoint
from vraptor.analyze import recovery, reporting, saved
from vraptor.artifacts import persistence
from vraptor.logging import operations


def run_summary(path, execute):
    return asyncio.run(saved.summarize(path, execution=spec(), limits=TEST_LIMITS, execute=execute))


def test_failed_summary_saves_attempt_diagnostics_without_changing_accepted_inputs(tmp_path):
    path = make_checkpoint(tmp_path)
    before = json.loads(path.read_text())["artifact_summaries"]
    original_diagnostics = tmp_path / "analysis-diagnostics.json"
    original_diagnostics.write_text('{"original": true}')
    calls = []

    def execute(task):
        calls.append(task)
        output = review_output().replace("supported_finding\tM1", "supported_finding\tM9")
        return successful(task, output.replace("One supported persistence finding.", "PRIVATE_MODEL_OUTPUT"))

    with operations.OperationLogger("summarize", options=operations.LogOptions(persist=False)) as logger:
        result = run_summary(path, execute)
    assert result["status"] == "complete_with_failures"
    assert result["model_calls"] == 3
    assert result["operation_id"] == logger.operation_id
    diagnostic_path = Path(result["diagnostics_file"])
    diagnostic = json.loads(diagnostic_path.read_text())
    assert diagnostic["operation_id"] == result["operation_id"]
    assert diagnostic["started_at"] <= diagnostic["completed_at"]
    assert diagnostic["status"] == "complete_with_failures"
    assert len(diagnostic["provider_calls"]) == 3
    assert all(c["started_at"] <= c["completed_at"] for c in diagnostic["provider_calls"])
    attempts = diagnostic["tasks"][0]["attempt_history"]
    assert len(attempts) == 3
    assert all(a["defects"][0]["code"] == "missing_mapped_finding" for a in attempts)
    assert "PRIVATE_MODEL_OUTPUT" not in diagnostic_path.read_text()
    assert "payload.exe" not in diagnostic_path.read_text()
    assert original_diagnostics.read_text() == '{"original": true}'
    assert json.loads(path.read_text())["artifact_summaries"] == before
    saved.load_accepted(path)
    assert persistence.classify_analysis_file(
        diagnostic_path, analysis_root=tmp_path, source_ids=["synthetic"]
    )["classification"] == "compact_state"


def test_cache_hit_refreshes_diagnostics_with_zero_calls(tmp_path):
    path = make_checkpoint(tmp_path)
    first = run_summary(path, lambda task: successful(task, review_output()))
    assert first["model_calls"] == 1
    second = run_summary(path, lambda task: pytest.fail("cache hit dispatched model"))
    diagnostic = json.loads(Path(second["diagnostics_file"]).read_text())
    assert second["reused"]
    assert diagnostic["reused"]
    assert diagnostic["model_calls"] == 0
    assert diagnostic["provider_calls"] == diagnostic["tasks"] == []
    assert diagnostic["completed_at"]


def test_cache_hit_republishes_with_current_reporting_policy(tmp_path):
    path = make_checkpoint(tmp_path)
    first = run_summary(path, lambda task: successful(task, review_output()))
    report = Path(first["report"])
    original = report.read_text()
    checkpoint_before = path.read_bytes()
    with reporting.reporting_scope(reporting.ReportingPolicy(preview_chars=8)):
        second = run_summary(path, lambda task: pytest.fail("cache hit dispatched model"))
    assert second["reused"] and second["model_calls"] == 0
    assert second["report"] == first["report"]
    assert report.read_text() != original
    assert path.read_bytes() == checkpoint_before


def test_model_supplied_identifiers_are_not_retained_as_diagnostic_text(tmp_path):
    path = make_checkpoint(tmp_path)
    output = review_output().replace("supported_finding\tM1", "supported_finding\tPRIVATE_SOURCE_VALUE")
    result = run_summary(path, lambda task: successful(task, output))
    diagnostics = Path(result["diagnostics_file"]).read_text()
    assert "PRIVATE_SOURCE_VALUE" not in diagnostics
    assert "missing_mapped_finding" in diagnostics
    defect = json.loads(diagnostics)["tasks"][0]["attempt_history"][0]["defects"][0]
    assert defect["allowed"] == ["M1"]
    assert defect["candidate_id"] == "A0001:F5"


def test_checkpoint_conflict_retains_diagnostics_but_does_not_publish(tmp_path):
    path = make_checkpoint(tmp_path)

    def execute(task):
        changed = json.loads(path.read_text())
        changed["concurrent_change"] = True
        path.write_text(json.dumps(changed))
        return successful(task, review_output())

    with pytest.raises(RuntimeError, match="changed during"):
        run_summary(path, execute)
    assert json.loads(path.read_text())["concurrent_change"]
    assert not (tmp_path / "synthesis-summary.md").exists()
    diagnostic = json.loads((tmp_path / "synthesis-diagnostics.json").read_text())
    assert diagnostic["status"] == "failed"
    assert diagnostic["error_category"] == "checkpoint_changed"
    assert diagnostic["tasks"][0]["status"] == "accepted"


def test_cancelled_summary_keeps_checkpoint_and_attempt_timing(tmp_path):
    path = make_checkpoint(tmp_path)
    before = path.read_bytes()

    async def execute(task):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        run_summary(path, execute)
    assert path.read_bytes() == before
    diagnostic = json.loads((tmp_path / "synthesis-diagnostics.json").read_text())
    assert diagnostic["status"] == "interrupted"
    assert diagnostic["provider_calls"][0]["status"] == "interrupted"
    assert diagnostic["provider_calls"][0]["completed_at"]
    assert diagnostic["model_calls"] == 1


def test_cancelled_correction_preserves_previous_validation_diagnostics(tmp_path):
    path = make_checkpoint(tmp_path)
    before = path.read_bytes()
    calls = []

    async def execute(task):
        calls.append(task)
        if len(calls) == 2:
            raise asyncio.CancelledError()
        return successful(task, review_output().replace("supported_finding\tM1", "supported_finding\tM9"))

    with pytest.raises(asyncio.CancelledError):
        run_summary(path, execute)
    assert path.read_bytes() == before
    diagnostic = json.loads((tmp_path / "synthesis-diagnostics.json").read_text())
    assert diagnostic["status"] == "interrupted"
    assert diagnostic["model_calls"] == 2
    assert diagnostic["tasks"][0]["attempt_history"][0]["defects"][0]["code"] == "missing_mapped_finding"


def test_runner_initialization_failure_is_not_left_running(tmp_path, monkeypatch):
    path = make_checkpoint(tmp_path)

    def fail(*args, **kwargs):
        raise RuntimeError("PRIVATE_PROVIDER_ERROR")

    monkeypatch.setattr(saved, "create_agent_runner", fail)
    with pytest.raises(RuntimeError, match="PRIVATE_PROVIDER_ERROR"):
        asyncio.run(saved.summarize(path, execution=spec(), limits=TEST_LIMITS))
    diagnostic_path = tmp_path / "synthesis-diagnostics.json"
    diagnostic = json.loads(diagnostic_path.read_text())
    assert diagnostic["status"] == "failed"
    assert diagnostic["error_category"] == "runner_initialization_failed"
    assert "PRIVATE_PROVIDER_ERROR" not in diagnostic_path.read_text()


def test_task_diagnostics_bounds_attempts_and_defects():
    result = recovery.task_diagnostics({"attempt_history": [{
        "run": {"attempt_count": 2},
        "diagnostics": [{"code": "missing_mapped_finding", "allowed": ["M1"] * 100} for _ in range(100)],
    }] * 20})
    assert len(result["attempt_history"]) == 7
    assert result["omitted_attempt_count"] == 13
    first = result["attempt_history"][0]
    assert len(first["defects"]) == 50
    assert first["omitted_defect_count"] == 50
    assert len(first["defects"][0]["allowed"]) == 50
    assert first["provider_attempts"] == 2


def test_task_diagnostics_give_each_limit_stop_its_own_message():
    categories = ("context_window_exceeded", "refusal", "input_limit")
    result = recovery.task_diagnostics({"attempt_history": [
        {"run": {"status": "failed", "error_classification": category}}
        for category in categories
    ]})
    attempts = result["attempt_history"]
    assert [item["category"] for item in attempts] == list(categories)
    fallback = recovery.task_diagnostics({"attempt_history": [
        {"run": {"status": "failed", "error_classification": "unlisted"}}
    ]})["attempt_history"][0]["message"]
    messages = [item["message"] for item in attempts]
    assert len(set(messages)) == 3
    assert fallback not in messages
