"""Synthetic correction/recovery regression tests; no live evidence or provider."""

import asyncio
import json

import pytest
import test_collection_analysis_runtime as runtime_fixtures
from test_collection_analysis_runtime import (
    chunk_output,
    spec,
    successful,
    synthesis_output,
)
from vraptor.agent.runtime import AgentRequest, AgentResult
from vraptor.analyze import limits, recovery, runtime, summary


def test_default_correction_succeeds_on_third_attempt_and_transport_is_not_retried():
    task = AgentRequest(
        task_id="test", prompt="input", output_name="test", metadata={"stage": "chunk"}
    )
    calls = []

    def execute(current):
        calls.append(current)
        return successful(current, "ok" if len(calls) == 3 else "bad")

    def validate(_task, output):
        if output != "ok":
            raise ValueError("invalid response")
        return {"status": "complete"}

    accepted, records = asyncio.run(
        runtime._validated_pool_async(
            [task], max_concurrency=1, execute=execute, validate=validate
        )
    )
    assert accepted["test"]["status"] == "complete"
    assert records["test"]["attempts"] == 3
    assert [t.metadata.get("attempt", 1) for t in calls] == [1, 2, 3]
    assert calls[-1].output_name.endswith("retry-3")
    failed = AgentResult(
        task_id="test",
        status="failed",
        output="",
        output_file="",
        events_file="",
        manifest_file="",
        elapsed_seconds=1,
        error_classification="authentication",
    )
    accepted, records = asyncio.run(
        runtime._validated_pool_async(
            [task], max_concurrency=1, execute=lambda _task: failed, validate=validate
        )
    )
    assert not accepted
    assert records["test"]["attempts"] == 1


@pytest.mark.parametrize("value", [-1, 6, True, 1.5, "bad"])
def test_invalid_correction_budget_is_rejected(value):
    with pytest.raises(ValueError):
        limits.correction_attempts(value)


def test_correction_environment_zero_is_a_valid_override():
    resolved = limits.resolve_analysis_limits(
        {
            "AI_SKILLS_ANALYST_AGENT_VALIDATION_CORRECTION_ATTEMPTS": "0",
            "AI_SKILLS_ANALYST_AGENT_SYNTHESIS_CORRECTION_ATTEMPTS": "4",
        }
    )
    assert resolved.validation_correction_attempts == 0
    assert resolved.synthesis_correction_attempts == 4
    assert (
        resolved.provenance_dict()["validation_correction_attempts"]["kind"]
        == "environment"
    )


@pytest.mark.parametrize("failed_stage", ["chunk", "artifact-synthesis"])
def test_failed_stage_retry_reuses_accepted_chunks_and_rehydrates_current_source(
    tmp_path,
    failed_stage,
):
    rows = [
        {"When": str(i), "Command": "PRIVATE_SOURCE_VALUE_" + "x" * 250}
        for i in range(4)
    ]
    plan, chunks = runtime_fixtures.CollectionAnalysisRuntimeTest().build(
        artifact_count=1, rows=rows, limit=150
    )
    assert len(chunks) > 1
    failed_task = next(iter(plan["chunks"]))["task_id"] + "-chunk-0"
    calls = []
    fail = True

    def execute(task):
        calls.append((task.metadata["stage"], task.task_id))
        if task.metadata["stage"] == "chunk":
            return successful(
                task,
                "bad"
                if fail and failed_stage == "chunk" and task.task_id == failed_task
                else chunk_output(task),
            )
        return successful(
            task,
            "bad"
            if fail and failed_stage == "artifact-synthesis"
            else synthesis_output(task),
        )

    checkpoint = tmp_path / "recovery.json"

    def run(reuse, identity="same"):
        return asyncio.run(
            runtime.execute_analysis_workload_async(
                plan=plan,
                chunk_csv=chunks,
                question="What happened?",
                spec=spec(),
                workdir=tmp_path,
                output_dir=tmp_path,
                execute=execute,
                perform_scope_synthesis=False,
                chunk_recovery=recovery.ChunkRecovery(
                    checkpoint, identity, reuse=reuse
                ),
            )
        )

    run(False)
    before = list(calls)
    if failed_stage == "chunk":
        assert sum(task_id == failed_task for _, task_id in before) == 3
    else:
        assert sum(stage == "artifact-synthesis" for stage, _ in before) == 3
    assert "PRIVATE_SOURCE_VALUE" not in checkpoint.read_text()
    fail = False
    result = run(True)
    retried = calls[len(before) :]
    assert [task_id for stage, task_id in retried if stage == "chunk"] == (
        [failed_task] if failed_stage == "chunk" else []
    )
    assert result["status"] == "complete"
    before = len(calls)
    run(True, identity="changed-question-or-source")
    assert sum(stage == "chunk" for stage, _ in calls[before:]) == len(chunks)


def test_corrupt_checkpoint_is_not_reused(tmp_path):
    path = tmp_path / "recovery.json"
    task = AgentRequest(task_id="test", prompt="input", output_name="test", metadata={})
    cache = recovery.ChunkRecovery(path, "identity", reuse=False)
    cache.accept(
        task, {"result": "no_reportable_findings", "fields": {"Secret": "excluded"}}
    )
    saved = json.loads(path.read_text())
    saved["accepted"]["test"]["result"]["result"] = "findings"
    path.write_text(json.dumps(saved))
    assert recovery.ChunkRecovery(path, "identity", reuse=True).get(task) is None
    assert "excluded" not in path.read_text()


def test_failure_diagnostics_retain_defects_without_provider_or_evidence_values():
    record = {
        "task_id": "test",
        "stage": "host-synthesis",
        "status": "failed",
        "attempts": 3,
        "attempt_history": [
            {
                "attempt": 3,
                "status": "failed",
                "error": "PRIVATE_ERROR",
                "diagnostics": [
                    {
                        "code": "candidate_reference_mismatch",
                        "candidate_id": "A0001:F1",
                        "allowed": ["S0001-R2"],
                        "value": "PRIVATE_VALUE",
                    }
                ],
                "run": {
                    "status": "succeeded",
                    "output": "PRIVATE_OUTPUT",
                    "elapsed_seconds": 4,
                },
            }
        ],
    }
    result = recovery.task_diagnostics(record)
    assert "PRIVATE" not in json.dumps(result)
    last = result["attempt_history"][-1]
    assert last["category"] == "validation_failed"
    assert last["defects"][0]["allowed"] == ["S0001-R2"]
    assert last["defects"][0]["candidate_id"] == "A0001:F1"


def test_report_does_not_confuse_exposed_rows_with_collection_completion():
    text = summary.render_artifact_report(
        {
            "artifact": "Test",
            "status": "complete",
            "coverage": {"planned_rows": 3, "reviewed_rows": 3},
            "collection_coverage": {"status": "partial", "flow_state": "UNRESPONSIVE"},
            "limitations": [
                "LIMITATION\tNo execution evidence.",
                "no EXECUTION evidence.",
            ],
        }
    )
    assert "Review coverage: 3/3 exposed rows" in text
    assert "Collection coverage: `partial`; flow `UNRESPONSIVE`" in text
    assert text.count("No execution evidence.") == 1
    assert "LIMITATION\t" not in text
