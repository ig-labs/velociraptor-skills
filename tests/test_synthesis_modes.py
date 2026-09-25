"""No live services: synthesis selection, saved-result reuse and reference repair."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from unittest import mock

import pytest
import test_collection_analysis_runtime as runtime_fixture
import test_flow_analysis as flow_fixture
from test_collection_analysis_runtime import (
    TEST_LIMITS,
    chunk_output,
    spec,
    successful,
    synthesis_output,
)
from test_flow_analysis import FakeFlowApi, flow_row
from test_host_final_review import autoruns, review_output, run_review
from vraptor.analyze import (
    checkpoints,
    coordinator,
    final_review,
    runtime,
    saved,
    summary,
    synthesis,
)
from vraptor.analyze.references import normalize_response_references


@pytest.mark.parametrize("scope", ["host", "hunt"])
@pytest.mark.parametrize("artifacts", [1, 2])
def test_none_does_not_invoke_scope_model(scope, artifacts):
    inputs = [autoruns() for _ in range(artifacts)]

    def forbidden(_task):
        pytest.fail("preliminary mode dispatched synthesis")

    run = asyncio.run(
        runtime.execute_host_synthesis_from_artifact_results_async(
            plan={"scope_type": scope, "synthesis_mode": "none"},
            artifact_results=inputs,
            question="Assess",
            execute=forbidden,
        )
    )
    result = run["host_result"]
    assert result["review_status"] == "not_requested"
    assert result["status"] == "complete"
    assert len({f["id"] for f in result["findings"]}) == 5 * artifacts
    assert result["coverage"]["reviewed_rows"] == 5 * artifacts
    assert not run["tasks"]
    assert "final synthesis not requested" in summary.analysis_stage(result)


def test_none_preserves_partial_coverage_and_context_links():
    first = autoruns()
    first["relevant_context"] = [
        {"finding_id": "F1", "ref": "S0001-R1", "fields": {"Name": "x"}}
    ]
    failed = {
        "artifact": "failed",
        "status": "failed",
        "coverage": {"planned_rows": 10, "planned_chunks": 1},
        "limitations": ["source failed"],
    }
    result = synthesis.preliminary([first, failed], question="Assess")
    assert result["status"] == "complete_with_failures"
    assert result["coverage"]["planned_rows"] == 15
    assert result["coverage"]["reviewed_rows"] == 5
    assert result["relevant_context"][0]["finding_id"] == result["findings"][0]["id"]


def test_large_result_paging_keeps_exact_provenance():
    result = synthesis.preliminary([autoruns()], question="Assess")
    page = synthesis.page(result, limit=2)
    assert page["matching_candidates"] == 5
    assert page["undisplayed_candidates"] == 3
    assert page["next_offset"] == 2
    assert synthesis.page(result, reference="S0001-R5")["returned_candidates"] == 1
    assert synthesis.page(result, host="unknown")["returned_candidates"] == 0


def make_checkpoint(tmp_path):
    report = tmp_path / "artifact.md"
    report.write_text("synthetic accepted report")
    state = checkpoints.new_state(
        hostname="test",
        client_id="C.test",
        request_id="test",
        analysis_identity="identity",
    )
    state["artifacts"] = {
        "test": {
            "artifact": "test",
            "analysis_status": "complete",
            "accepted_result": autoruns(),
            "report_file": str(report),
            "report_sha256": saved.sha256_file(report),
        }
    }
    path = tmp_path / "request-analysis.json"
    checkpoints.write_request_checkpoint(
        path,
        state=state,
        question="Assess",
        host_result={},
        status="complete",
        task_mode="incident_response",
        response_depth="standard",
    )
    return path


def test_saved_summary_reuses_without_reanalyzing_and_invalidates_only_review(tmp_path):
    path = make_checkpoint(tmp_path)
    before = json.loads(path.read_text())["artifact_summaries"]
    calls = []

    def execute(task):
        calls.append(task.metadata["stage"])
        return successful(task, review_output())

    async def run(execution):
        return await saved.summarize(
            path, execution=execution, limits=TEST_LIMITS, execute=execute
        )

    first = asyncio.run(run(spec()))
    assert first["status"] == "complete"
    assert calls == ["host-synthesis"]
    second = asyncio.run(run(spec()))
    assert second["reused"] and second["model_calls"] == 0
    altered = replace(spec(), route=replace(spec().route, reasoning_effort="medium"))
    assert not asyncio.run(run(altered))["reused"]
    assert calls == ["host-synthesis", "host-synthesis"]
    assert json.loads(path.read_text())["artifact_summaries"] == before


def test_saved_summary_rejects_modified_report(tmp_path):
    path = make_checkpoint(tmp_path)
    (tmp_path / "artifact.md").write_text("modified")
    with pytest.raises(ValueError, match="report"):
        saved.load_accepted(path)


def test_reference_repairs_do_not_guess_or_cross_sources():
    text, repairs = normalize_response_references(
        "S1-R01 S001-R0001 S2-R01 S1-R3", ["S0001-R1", "S0002-R1"]
    )
    assert text == "S0001-R1 S0001-R1 S0002-R1 S1-R3"
    assert repairs == 3
    assert (
        normalize_response_references("S1-R1", ["S0001-R1", "S00001-R1"])[0] == "S1-R1"
    )


def test_final_review_repairs_padding_and_duplicate_evidence_without_retry():
    output = review_output().replace("S0001-R5", "S1-R0005")
    output = output.replace("\tS0001-R1\tPolicy", "\tS1-R1,S0001-R01\tPolicy")
    calls = []
    run = run_review([autoruns()], output, calls=calls)
    assert run["status"] == "complete"
    assert len(calls) == 1
    assert run["host_result"]["local_reference_repairs"] > 0


def test_wrong_candidate_reference_still_fails_with_received_ids():
    run = run_review(
        [autoruns()],
        review_output().replace("\tS0001-R1\tPolicy", "\tS0001-R2\tPolicy"),
    )
    defect = run["tasks"][0]["attempt_history"][0]["diagnostics"][0]
    assert defect["reason"] == "wrong_candidate_reference"
    assert defect["received"] == ["S0001-R2"]
    assert run["status"] != "complete"


@pytest.mark.parametrize("artifact_count", [1, 2])
@pytest.mark.parametrize("row_count", [1, 8])
def test_call_budget_for_single_and_multiple_artifacts(artifact_count, row_count):
    rows = [
        {"When": f"2026-08-10T00:{i:02d}:00Z", "Command": "x " * 80}
        for i in range(row_count)
    ]
    plan, chunks = runtime_fixture.CollectionAnalysisRuntimeTest().build(
        artifact_count=artifact_count, rows=rows, limit=150
    )
    counts = {}
    for mode in ("full", "none"):
        calls = []

        def execute(task, calls=calls):
            calls.append(task.metadata["stage"])
            return successful(
                task,
                chunk_output(task) if calls[-1] == "chunk" else synthesis_output(task),
            )

        run = asyncio.run(
            runtime.execute_analysis_workload_async(
                plan={**plan, "synthesis_mode": mode},
                chunk_csv=chunks,
                question="Assess",
                spec=spec(),
                workdir=Path("/synthetic"),
                output_dir=Path("/synthetic"),
                execute=execute,
            )
        )
        assert run["status"] == "complete"
        counts[mode] = calls
        assert calls.count("chunk") == plan["chunk_count"]
        if mode == "none":
            assert set(calls) == {"chunk"}
            assert (
                run["host_result"]["coverage"]["reviewed_rows"]
                == artifact_count * row_count
            )
    assert len(counts["full"]) - len(counts["none"]) == 1 + (
        artifact_count if row_count > 1 else 0
    )


def test_hunt_none_preserves_retrievable_candidates_and_avoids_synthesis(tmp_path):
    fixture = flow_fixture.FlowAnalysisTest()
    api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "one"}]})
    with (
        mock.patch.object(
            coordinator,
            "execute_streaming_chunks_async",
            side_effect=fixture.accepted_streaming_chunks,
        ),
        mock.patch.object(
            coordinator,
            "create_agent_runner",
            side_effect=AssertionError("unexpected synthesis"),
        ),
    ):
        coordinator.analyze_hunt_flows(
            api,
            org_id="root",
            hunt_id="H.1",
            hunt_state="RUNNING",
            reported_result_rows=1,
            question="Assess",
            hunt_root=tmp_path,
            selected_artifacts=["Artifact.Test"],
            limits=TEST_LIMITS,
            spec=fixture.spec(),
            synthesis_mode="none",
        )
    path = tmp_path / "analysis" / "hunt-analysis-state.json"
    stored, accepted, _ = saved.load_accepted(path)
    assert accepted[0]["review_status"] == "not_requested"
    assert accepted[0]["findings"]
    assert (
        stored["checkpoint"]["result"]["findings"][0]["id"]
        == accepted[0]["findings"][0]["id"]
    )


def test_candidate_preview_is_bounded_and_more_evidence_is_addressable():
    result = synthesis.preliminary([autoruns()], question="Assess")
    finding = result["findings"][0]
    row = finding["evidence"][0]
    finding["evidence"] = [
        {**row, "ref": f"S0001-R{i}", "fields": {"Blob": "x" * 50_000}}
        for i in range(1, 31)
    ]
    page = synthesis.page(result, candidate=finding["id"])
    assert len(json.dumps(page).encode()) < 128_000
    assert page["findings"][0]["evidence_next_offset"] == 10
    assert page["findings"][0]["evidence"][0]["truncated_fields"] == ["fields"]
    assert (
        synthesis.page(result, reference="S0001-R30")["findings"][0]["evidence"][0][
            "ref"
        ]
        == "S0001-R30"
    )


def test_summary_refuses_concurrent_checkpoint_change(tmp_path):
    path = make_checkpoint(tmp_path)

    def execute(task):
        changed = json.loads(path.read_text())
        changed["concurrent_change"] = True
        path.write_text(json.dumps(changed))
        return successful(task, review_output())

    with pytest.raises(RuntimeError, match="changed during"):
        asyncio.run(
            saved.summarize(path, execution=spec(), limits=TEST_LIMITS, execute=execute)
        )
    assert json.loads(path.read_text())["concurrent_change"]


def test_reviewed_artifact_no_longer_carries_preliminary_labels():
    candidate = autoruns()
    candidate.update(review_status="not_requested", synthesis_mode="none")
    reviewed = run_review([autoruns()], review_output())["host_result"]
    published = final_review.artifact_publication(candidate, reviewed)
    assert published["review_status"] == "complete"
    assert published["synthesis_mode"] == "full"


def test_summary_cache_checks_policy_evidence_and_result_integrity():
    inputs = {
        "results": [autoruns()],
        "question": "Assess",
        "plan": {},
        "execution": {},
    }
    key = synthesis.cache_key(**inputs)
    record = synthesis.cache_record({"status": "complete", "answer": "test"}, key)
    assert synthesis.cached_result(record, key)
    for field, value in (
        ("question", "Different question"),
        ("plan", {"artifacts": [{"strategy": "changed"}]}),
        ("execution", {"model": "changed"}),
    ):
        assert synthesis.cache_key(**{**inputs, field: value}) != key
    record["result"]["answer"] = "modified"
    assert synthesis.cached_result(record, key) is None


def test_failed_hunt_partial_candidates_do_not_replace_published_checkpoint(tmp_path):
    partial = synthesis.preliminary(
        [autoruns()], question="Assess", scope="hunt", failures=["One chunk failed"]
    )
    path = tmp_path / "hunt-analysis-state.json"
    path.write_text(
        json.dumps(
            {
                "checkpoint": {"generation": 7, "result": {"answer": "old"}},
                "partial_candidates": {
                    "accepted_result": partial,
                    "accepted_fingerprint": synthesis.fingerprint(partial),
                },
            }
        )
    )
    before = path.read_bytes()
    _, artifacts, _ = saved.load_accepted(path)
    assert artifacts[0]["status"] == "complete_with_failures"
    assert artifacts[0]["findings"]
    assert path.read_bytes() == before


@pytest.mark.parametrize("selected", [None, "none", "full"])
def test_host_and_hunt_cli_default_to_preliminary(selected):
    from vraptor.analyze.command import build_parser
    from vraptor.hunt.command import parse_args

    option = [] if selected is None else ["--synthesis", selected]
    host = build_parser().parse_args(["--client-id", "C.test", *option])
    hunt = parse_args(["analyze", "--id", "test", "--hunt-id", "H.test", *option])
    assert host.synthesis == hunt.synthesis == (selected or "none")


def test_correction_retry_retains_defects_from_earlier_attempts():
    from vraptor.agent.runtime import AgentRequest
    from vraptor.analyze.host import WorkerResultError

    prompts = []
    task = AgentRequest(task_id="accumulated", prompt="ORIGINAL", output_name="out.txt", metadata={"stage": "chunk"})

    def execute(current):
        prompts.append(current.prompt)
        return successful(current, str(len(prompts)))

    def validate(_task, output):
        if output != "3":
            raise WorkerResultError("invalid", diagnostics=[{"code": "defect_" + output}])
        return {"status": "complete"}

    accepted, records = runtime_fixture.validated_pool(
        [task], max_concurrency=1, execute=execute, validate=validate,
        correction_attempts=2,
    )
    assert accepted["accumulated"]["status"] == "complete"
    assert records["accumulated"]["attempts"] == 3
    assert '"code":"defect_1"' in prompts[1]
    assert '"code":"defect_1"' in prompts[2]
    assert '"code":"defect_2"' in prompts[2]
    assert prompts[2].count("RETRY CORRECTION") == 1
