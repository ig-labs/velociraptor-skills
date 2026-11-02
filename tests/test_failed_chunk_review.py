"""Failed-chunk review records, waivers and opt-in evidence; no live provider."""

import asyncio
import json
import re
import stat
from types import SimpleNamespace
from unittest import mock

import pytest
import test_collection_analysis_runtime as runtime_fixtures
from test_collection_analysis_runtime import (
    chunk_output,
    spec,
    successful,
    synthesis_output,
)
from vraptor.agent.runtime import AgentResult
from vraptor.analyze import (
    chunk_repair,
    command,
    coordinator,
    prompt_debug,
    recovery,
    runtime,
    summary,
)
from vraptor.artifacts import persistence

SCOPE = {"kind": "host", "client_id": "C.1", "request_id": "R1"}


def _failure(task_id="artifact-task-1-chunk-0", **inputs):
    return {
        "task_id": task_id,
        "stage": "chunk",
        "status": "failed",
        "attempts": 1,
        "inputs": {"input_sha256": "a" * 64, "row_start": 1, "row_end": 4, **inputs},
        "attempt_history": [
            {
                "attempt": 1,
                "status": "failed",
                "category": "validation_failed",
                "defects": [{"code": "invalid_reference"}],
            }
        ],
    }


def _record(ledger, key="Artifact.0:artifact-task-1-chunk-0", **inputs):
    ledger.record_failure(
        key,
        _failure(key.split(":", 1)[1], **inputs),
        identity={"artifact": "Artifact.0", "flow_id": "F.1"},
        budget={"validation_correction_attempts": 2, "provider_max_retries": 2},
        next_steps={"retry": "vraptor collect analyze --retry-failed"},
    )
    return key


def test_exhausted_chunk_is_recorded_and_a_waiver_publishes_the_accepted_chunks(tmp_path):
    rows = [
        {"When": str(i), "Command": "PRIVATE_SOURCE_VALUE_" + "x" * 250}
        for i in range(4)
    ]
    plan, chunks = runtime_fixtures.CollectionAnalysisRuntimeTest().build(
        artifact_count=1, rows=rows, limit=150
    )
    assert len(chunks) > 1
    failed_task = next(iter(plan["chunks"]))["task_id"] + "-chunk-0"
    key = f"Artifact.0:{failed_task}"
    path = tmp_path / "failed-chunks.json"
    ledger = recovery.FailedChunkLedger(path, SCOPE)
    calls = []

    def execute(task):
        calls.append(task.task_id)
        if task.metadata["stage"] == "chunk":
            output = "PRIVATE_MODEL_OUTPUT" if task.task_id == failed_task else chunk_output(task)
            return successful(task, output)
        return successful(task, synthesis_output(task))

    def chunk_failed(task, record, prompts):
        assert len(prompts) == 3 and "RETRY CORRECTION" in prompts[-1]
        ledger.record_failure(
            f"Artifact.0:{task.task_id}",
            recovery.task_diagnostics(record),
            identity={"artifact": "Artifact.0", "flow_id": "F.1"},
            budget={"validation_correction_attempts": 2, "provider_max_retries": 2},
            next_steps={"retry": "retry"},
        )

    def run(**callbacks):
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
                    tmp_path / "recovery.json", "same", reuse=True
                ),
                **callbacks,
            )
        )

    first = run(chunk_failed=chunk_failed)
    assert not command.artifact_analysis_run_is_cacheable(first)
    assert "PRIVATE" not in path.read_text()
    entry = ledger.entries()[key]
    assert (entry["status"], entry["attempts"], entry["failure_count"]) == ("failed", 3, 1)
    assert entry["final"]["category"] == "validation_failed"
    assert [item["status"] for item in entry["attempt_history"]] == [
        "retrying", "retrying", "failed",
    ]
    assert all(
        item["started_at"] <= item["completed_at"] for item in entry["attempt_history"]
    )
    assert re.fullmatch(r"S[0-9]+-R[0-9]+", entry["inputs"]["first_reference"])
    assert re.fullmatch(r"[0-9a-f]{64}", entry["inputs"]["input_sha256"])
    assert entry["inputs"]["row_start"] <= entry["inputs"]["row_end"]

    reloaded = recovery.FailedChunkLedger(path, SCOPE)
    assert reloaded.find(failed_task) == key
    reloaded.waive(key, "Rows reviewed manually in Velociraptor")
    before = len(calls)
    second = run(
        chunk_waiver=lambda task: reloaded.waiver(
            f"Artifact.0:{task.task_id}", recovery.fingerprint(task.prompt)
        )
    )
    assert failed_task not in calls[before:]
    assert second["status"] == "complete_with_failures"
    assert command.artifact_analysis_run_is_cacheable(second)
    waived = next(task for task in second["tasks"] if task["task_id"] == failed_task)
    assert waived["status"] == "waived"
    assert "Rows reviewed manually" in waived["error"]


def test_ledger_survives_reload_and_keeps_history_after_resolution(tmp_path):
    path = tmp_path / "failed-chunks.json"
    key = _record(recovery.FailedChunkLedger(path, SCOPE))
    ledger = recovery.FailedChunkLedger(path, SCOPE)
    _record(ledger)
    assert ledger.entries()[key]["failure_count"] == 2
    ledger.resolve(key)
    entry = recovery.FailedChunkLedger(path, SCOPE).entries()[key]
    assert entry["status"] == "resolved" and entry["resolved_at"]
    assert entry["attempt_history"]
    assert recovery.FailedChunkLedger(path, {**SCOPE, "request_id": "R2"}).entries() == {}


def test_waiver_needs_a_reason_and_lapses_when_the_input_changes(tmp_path):
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    key = _record(ledger)
    with pytest.raises(ValueError):
        ledger.waive(key, "   ")
    ledger.waive(key, "Benign installer noise")
    with pytest.raises(ValueError):
        ledger.waive(key, "again")
    assert ledger.waiver(key, "a" * 64) == "Benign installer noise"
    assert ledger.waiver(key, "b" * 64) is None
    ledger.revoke_waivers()
    entry = ledger.entries()[key]
    assert entry["status"] == "failed" and entry["decision"]["revoked_at"]


def test_a_failure_after_the_input_changed_marks_the_waiver_lapsed(tmp_path):
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    key = _record(ledger)
    ledger.waive(key, "Benign installer noise")
    _record(ledger, input_sha256="b" * 64)
    entry = ledger.entries()[key]
    assert entry["status"] == "failed" and entry["decision"]["lapsed_at"]
    assert entry["decision"]["input_sha256"] == "a" * 64
    line = summary.failed_chunk_line(recovery.failed_chunk_summary(key, entry))
    assert line.endswith(f"An earlier waiver lapsed: the chunk input changed. Key `{key}`.")
    ledger.waive(key, "Reviewed again")
    ledger.revoke_waivers()
    _record(ledger)
    assert "lapsed_at" not in ledger.entries()[key]["decision"]


def test_a_waiver_lapses_only_on_a_changed_input_and_survives_the_repair_record(tmp_path):
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    key = _record(ledger)
    ledger.waive(key, "Benign installer noise")
    _record(ledger)
    assert "lapsed_at" not in ledger.entries()[key]["decision"]

    ledger.waive(key, "Benign installer noise")
    changed = _failure(key.split(":", 1)[1], input_sha256="b" * 64)
    for repair in ({"outcome": "pending"}, {"outcome": "failed"}):
        ledger.record_failure(
            key, {**changed, "repair": repair},
            identity={"artifact": "Artifact.0"}, budget={}, next_steps={},
        )
    entry = ledger.entries()[key]
    assert (entry["failure_count"], entry["repair"]["outcome"]) == (3, "failed")
    assert recovery.failed_chunk_summary(key, entry)["waiver"] == "lapsed"


def test_replanned_artifact_supersedes_chunks_it_no_longer_has(tmp_path):
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    kept = _record(ledger, "Artifact.0:artifact-task-1-chunk-0")
    dropped = _record(ledger, "Artifact.0:artifact-task-1-chunk-70")
    ledger.supersede("Artifact.0", {kept})
    assert set(ledger.entries("failed")) == {kept}
    assert ledger.entries()[dropped]["status"] == "superseded"


def test_ledger_drops_resolved_entries_first(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, "FAILED_CHUNK_ENTRY_LIMIT", 2)
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    first = _record(ledger, "Artifact.0:artifact-task-1-chunk-0")
    ledger.resolve(first)
    _record(ledger, "Artifact.0:artifact-task-1-chunk-1")
    _record(ledger, "Artifact.0:artifact-task-1-chunk-2")
    assert first not in ledger.entries()
    assert ledger.payload["omitted_chunk_count"] == 1


def test_ledger_keeps_only_identity_references_and_hashes(tmp_path):
    path = tmp_path / "failed-chunks.json"
    ledger = recovery.FailedChunkLedger(path, SCOPE)
    _record(ledger, first_reference="S0001-R1", last_reference="PRIVATE_VALUE", flow_id="F.1")
    entry = next(iter(ledger.entries().values()))
    assert entry["inputs"]["first_reference"] == "S0001-R1"
    assert "last_reference" not in entry["inputs"]
    assert "PRIVATE" not in path.read_text()
    record = persistence.classify_analysis_file(
        path, analysis_root=tmp_path, source_ids=["source-1"]
    )
    assert record["classification"] == "compact_state"


def test_terminal_hunt_failures_survive_the_attempt_cap():
    retrying = [
        {"chunk_id": f"{index:064x}", "ordinal": index, "attempt": 1, "status": "retrying"}
        for index in range(25)
    ]
    terminal = {"chunk_id": "f" * 64, "ordinal": 70, "attempt": 3, "status": "failed"}
    kept = coordinator._cap_attempt_failures([*retrying, terminal])
    assert len(kept) == coordinator.MAX_FAILED_CHUNK_ATTEMPTS_PER_RUN
    assert kept[-1] == terminal
    assert [item["ordinal"] for item in kept] == sorted(item["ordinal"] for item in kept)


def test_failed_chunk_evidence_is_written_only_when_requested(tmp_path):
    record = {
        "attempt_history": [
            {"error": "full validator message", "run": {"output": "raw response"}},
            {"error": "second message", "run": {"output": ""}},
        ]
    }
    assert prompt_debug.capture_failed_chunk(
        key="k", prompts=["prompt"], record=record, source_ids=["source-1"]
    ) is None
    with prompt_debug.session(tmp_path, 0, keep_failed=True):
        reference = prompt_debug.capture_failed_chunk(
            key="Artifact.0:task", prompts=["prompt one", "prompt two"],
            record=record, source_ids=["source-1"],
        )
    assert [(item["attempt"], item["kind"]) for item in reference["files"]] == [
        (1, "prompt"), (1, "response"), (1, "error"), (2, "prompt"), (2, "error"),
    ]
    directory = tmp_path / "debug" / "failed-chunks"
    saved = next(directory.iterdir())
    assert (saved / "failed-001.attempt-001.response.txt").read_text() == "raw response"
    assert stat.S_IMODE((saved / "failed-001.attempt-001.prompt.txt").stat().st_mode) == 0o600
    manifest = json.loads((saved / "manifest.json").read_text())
    assert manifest["chunks"][0]["persistence"]["classification"] == "interoperability_export"


def test_summary_and_failure_result_name_the_failed_chunk():
    chunk = {
        "key": "Artifact.0:artifact-task-1-chunk-70",
        "artifact": "Artifact.0",
        "status": "failed",
        "attempts": 3,
        "category": "validation_failed",
        "defect_codes": ["invalid_reference"],
        "row_start": 6900,
        "row_end": 7000,
        "task_chunk_index": 70,
        "task_chunk_count": 71,
        "first_reference": "S0003-R6901",
        "last_reference": "S0003-R7000",
    }
    line = summary.failed_chunk_line(chunk)
    assert "chunk 71/71 rows 6901-7000 (S0003-R6901..S0003-R7000)" in line
    assert "failed after 3 attempts: validation_failed; invalid_reference" in line
    rendered = summary.render_chat_summary(
        {
            "status": "complete_with_failures",
            "troubleshooting": {
                "diagnostics_file": "analysis-diagnostics.json",
                "failed_stages": [{"stage": "chunk", "task_id": "artifact-task-1-chunk-70"}],
                "failed_chunks_file": "failed-chunks.json",
                "failed_chunks": [chunk],
            },
        }
    )
    assert "Failed chunk record: `failed-chunks.json`" in rendered
    assert "--waive-failed-chunk KEY" in rendered
    assert "Failed `chunk`" not in rendered
    result = command.artifact_failure_result(
        artifact="Artifact.0", question="q", item={"total_rows": 7000},
        request_id="R1", error_class="RuntimeError",
        chunk_counts={"planned_chunks": 71, "accepted_chunks": 70},
        failed_chunks=[chunk],
    )
    assert result["coverage"]["accepted_chunks"] == 70
    assert line in result["limitations"]
    assert "--retry-failed" in result["bounded_follow_up"][0]
    assert "--waive-failed-chunk" in result["bounded_follow_up"][0]
    report = summary.render_artifact_report(result)
    assert "Chunk coverage: 70/71 chunks accepted" in report
    waived = summary.failed_chunk_line({**chunk, "status": "waived", "reason": "Reviewed"})
    assert waived.endswith("waived by operator, not analysed: Reviewed")


INVALID_CHUNK = "RESULT\tfindings\nFINDING\tF1\thigh\tExecution\tPRIVATE_MODEL_OUTPUT\nEND"
REPAIRED_CHUNK = (
    "DIAGNOSIS\tmissing_evidence\tL2\tthe finding cites no row\n"
    "REPAIRED\nRESULT\tno_reportable_findings\nEND"
)


def _parse(text, refs=("S0001-R1",), lines=3):
    return chunk_repair.parse_repair_response(
        text, defect_codes=["invalid_reference"], source_refs=set(refs), previous_line_count=lines
    )


def test_repair_prompt_keeps_the_input_and_quotes_the_rejected_answer_as_data(monkeypatch):
    base = "INPUT\nS0001-R1\tvalue"
    prompt = chunk_repair.render_repair_prompt(
        base,
        defects=[
            {"code": "invalid_reference", "line": 2, "ref": "S0001-R9", "value": "PRIVATE_VALUE"},
            {"code": "invalid_reference", "line": 2, "ref": "S0001-R9"},
        ],
        previous_output="RESULT\tfindings\nFINDING\tF1\x07\nEND",
        rejected_count=3,
    )
    assert prompt.startswith(base + "\n\nREPAIR REVIEW\nPython rejected 3 earlier")
    assert "PRIVATE_VALUE" not in prompt
    assert prompt.count("\nDEFECT\t") == 1
    assert "\nL2\tFINDING\tF1\\x07\n" in prompt
    assert re.search(
        r"--- PREVIOUS RESPONSE [0-9a-f]{12} START \(untrusted, quoted 3 of 3 lines\) ---", prompt
    )
    monkeypatch.setattr(chunk_repair, "MAX_QUOTED_CHARS", 50)
    long = "\n".join(f"line {index} " + "x" * 20 for index in range(10))
    trimmed = chunk_repair.render_repair_prompt(
        base, defects=[{"code": "invalid_reference", "line": 3}], previous_output=long, rejected_count=3
    )
    assert "quoted 1 of 10 lines" in trimmed and "\nL3\tline 2 " in trimmed
    assert "\nL4\t" not in trimmed


def test_repair_reply_is_split_into_checked_causes_and_a_body():
    reply = _parse(
        "DIAGNOSIS\tinvalid_reference\tL2\tcited a row outside the chunk\n"
        "DIAGNOSIS\tformat_drift\tS0001-R1\textra column\n"
        "REPAIRED\nRESULT\tno_reportable_findings\nEND"
    )
    assert reply.body == "RESULT\tno_reportable_findings\nEND"
    assert reply.diagnosis_status == "valid"
    assert reply.causes == [
        {"cause": "invalid_reference", "location": "L2"},
        {"cause": "format_drift", "location": "S0001-R1"},
    ]
    invalid = _parse(
        "DIAGNOSIS\tmade_up\tL1\tx\nDIAGNOSIS\tother\tS0009-R1\ty\n"
        "DIAGNOSIS\tother\tL9\tz\nREPAIRED\nEND"
    )
    assert invalid.diagnosis_status == "invalid" and invalid.body == "END"
    assert invalid.causes == [{"cause": "other", "location": "-"}] * 2
    unrepairable = _parse("DIAGNOSIS\tmissing_evidence\t-\trows cut\nUNREPAIRABLE\tmissing_evidence\nEND")
    assert (unrepairable.body, unrepairable.unrepairable) == (None, "missing_evidence")
    assert _parse("RESULT\tno_reportable_findings\nEND").body is None
    record = chunk_repair.summary(reply, outcome="repaired", attempt=4, findings_before=1, findings_after=0)
    assert "cited a row" not in json.dumps(record)
    assert re.fullmatch(r"[0-9a-f]{64}", record["explanation_sha256"])
    assert recovery.safe_repair(record) == record
    assert recovery.safe_repair({**record, "causes": [{"cause": "PRIVATE value", "location": "x"}]}).get(
        "causes"
    ) is None


def test_repair_limit_comes_from_the_flag_then_the_environment(monkeypatch):
    assert chunk_repair.resolve_limit(0) == 0 and chunk_repair.resolve_limit("7") == 7
    for bad in (21, "-1", True, "x"):
        with pytest.raises(ValueError):
            chunk_repair.resolve_limit(bad)
    monkeypatch.setenv(chunk_repair.LIMIT_ENVIRONMENT, "2")
    assert chunk_repair.resolve_limit() == 2
    with chunk_repair.session(0) as policy:
        assert policy is None and chunk_repair.active() is None
    with chunk_repair.session(1) as policy:
        assert chunk_repair.active() is policy
        assert policy.claim() and not policy.claim()
    assert chunk_repair.active() is None


def _repair_workload(
    tmp_path, *, failing, repair_output, limit=4, chunk_recovery=None, command="PRIVATE_SOURCE_VALUE_",
):
    rows = [{"When": str(i), "Command": command + "x" * 250} for i in range(4)]
    plan, chunks = runtime_fixtures.CollectionAnalysisRuntimeTest().build(
        artifact_count=1, rows=rows, limit=150
    )
    prefix = next(iter(plan["chunks"]))["task_id"] + "-chunk-"
    failed = {prefix + str(index) for index in failing}
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    events, repair_prompts, calls = [], [], []

    def execute(task):
        calls.append(task.task_id)
        if task.metadata["stage"] != "chunk":
            return successful(task, synthesis_output(task))
        if task.metadata.get("repair"):
            repair_prompts.append(task.prompt)
            return successful(task, repair_output)
        return successful(task, INVALID_CHUNK if task.task_id in failed else chunk_output(task))

    def log(kind, task, record, prompts=None):
        key = f"Artifact.0:{task.task_id}"
        events.append((kind, task.task_id, dict(record.get("repair") or {}).get("outcome")))
        if kind == "repaired":
            ledger.resolve(key, repair=record.get("repair"))
            return
        ledger.record_failure(
            key, recovery.task_diagnostics(record),
            identity={"artifact": "Artifact.0", "flow_id": "F.1"},
            budget={"validation_correction_attempts": 2, "provider_max_retries": 2},
            next_steps={"retry": "retry"},
        )

    with chunk_repair.session(limit):
        result = asyncio.run(runtime.execute_analysis_workload_async(
            plan=plan, chunk_csv=chunks, question="What happened?", spec=spec(),
            workdir=tmp_path, output_dir=tmp_path, execute=execute,
            perform_scope_synthesis=False, chunk_recovery=chunk_recovery,
            chunk_exhausted=lambda task, record: log("exhausted", task, record),
            chunk_repaired=lambda task, record, prompts: log("repaired", task, record, prompts),
            chunk_failed=lambda task, record, prompts: log("failed", task, record, prompts),
        ))
    return result, ledger, events, repair_prompts, calls, sorted(failed)


def test_routes_without_model_calls_ignore_an_invalid_repair_limit(tmp_path, monkeypatch, capsys):
    from vraptor.hunt import command as hunt

    monkeypatch.setenv(chunk_repair.LIMIT_ENVIRONMENT, "99")
    seen = []

    def analyzed(*_args, **_kwargs):
        seen.append(chunk_repair.active())
        return {"status": "planned", "analyses": []}

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}\n", encoding="utf-8")
    live = ["analyze", "--id", "IR1", "--case-root", str(tmp_path), "--hunt-id", "H.1", "--no-progress"]
    with mock.patch.object(hunt, "validate_live_engagement", return_value=None), mock.patch.object(
        hunt, "command_analyze", side_effect=analyzed
    ):
        assert hunt.main(["analyze", "--snapshot", str(snapshot), "--no-progress"]) == 0
        assert hunt.main([*live, "--skip-ai"]) == 0
        assert hunt.main(live) == 1
    context = SimpleNamespace(
        engagement_id="IR1", server_profile="test", case_root=tmp_path,
        api_client=tmp_path / "api.yaml", state_path=tmp_path / "engagement.json",
    )
    host = ["--id", "IR1", "--client-id", "C.1", "--no-progress"]
    with (
        mock.patch.object(command.engagement_context, "resolve", return_value=context),
        mock.patch.object(command.operation_log, "bind_case"),
        mock.patch.object(command.collection, "CASE_ROOT", tmp_path),
        mock.patch.object(command, "VeloApiClient"),
        mock.patch.object(command, "run_analysis_async", new_callable=mock.AsyncMock, side_effect=analyzed),
    ):
        for flag in ("--skip-ai", "--plan-only", "--rebuild-host-summary"):
            assert asyncio.run(command.async_main([*host, flag])) == 0
        assert asyncio.run(command.async_main(host)) == 1
    assert seen == [None] * 5
    assert capsys.readouterr().err.count("chunk repair limit must be an integer from 0 to 20") == 2
    with pytest.raises(SystemExit):
        hunt.parse_args(["analyze", "--snapshot", str(snapshot), "--chunk-repair-limit", "2"])


def test_exhausted_chunk_is_logged_then_repaired_in_the_same_run(tmp_path):
    checkpoint = recovery.ChunkRecovery(tmp_path / "recovery.json", "same", reuse=True)
    result, ledger, events, prompts, calls, [task_id] = _repair_workload(
        tmp_path, failing=[0], repair_output=REPAIRED_CHUNK, chunk_recovery=checkpoint,
    )
    assert events == [("exhausted", task_id, "pending"), ("repaired", task_id, "repaired")]
    assert calls.count(task_id) == 4
    [prompt] = prompts
    assert "\nREPAIR REVIEW\n" in prompt and "\nL2\tFINDING\tF1\thigh" in prompt
    record = next(item for item in result["tasks"] if item["task_id"] == task_id)
    assert (record["status"], record["attempts"]) == ("accepted", 4)
    assert record["repair"]["causes"] == [{"cause": "missing_evidence", "location": "L2"}]
    assert (record["repair"]["findings_before"], record["repair"]["findings_after"]) == (1, 0)
    [artifact] = result["artifact_results"]
    assert artifact["coverage"]["repaired_chunks"] == 1
    [line] = [item for item in artifact["limitations"] if "AI repair" in item]
    assert "accepted after AI repair (missing_evidence at L2); verify these rows in Velociraptor." in line
    assert "The rejected answers had 1 finding(s); the accepted answer has 0." in line
    assert "Chunk coverage: 2/2 chunks accepted (1 after AI repair)" in summary.render_artifact_report(artifact)
    entry = ledger.entries()[f"Artifact.0:{task_id}"]
    assert (entry["status"], entry["failure_count"]) == ("resolved", 1)
    assert entry["resolution"]["by"] == "repair" and entry["repair"]["outcome"] == "repaired"
    assert "PRIVATE" not in ledger.path.read_text()
    assert checkpoint.payload["accepted"][task_id]["repair"]["outcome"] == "repaired"

    resumed, _ledger, events, _prompts, calls, _failed = _repair_workload(
        tmp_path, failing=[0], repair_output=REPAIRED_CHUNK,
        chunk_recovery=recovery.ChunkRecovery(tmp_path / "recovery.json", "same", reuse=True),
    )
    assert events == [] and task_id not in calls
    assert resumed["artifact_results"][0]["coverage"]["repaired_chunks"] == 1
    assert line in resumed["artifact_results"][0]["limitations"]


def test_failed_repair_counts_one_failure_and_the_cap_skips_later_chunks(tmp_path):
    result, ledger, events, prompts, _calls, failed = _repair_workload(
        tmp_path, failing=[0, 1], repair_output="DIAGNOSIS\tother\t-\tunsure\nEND", limit=1,
    )
    assert len(prompts) == 1
    records = {item["task_id"]: item for item in result["tasks"] if item["task_id"] in failed}
    outcomes = sorted(record["repair"]["outcome"] for record in records.values())
    assert outcomes == ["failed", "skipped"]
    skipped = next(record for record in records.values() if record["repair"]["outcome"] == "skipped")
    assert (skipped["attempts"], skipped["repair"]["reason"]) == (3, "repair_limit_reached")
    assert [kind for kind, *_rest in events].count("failed") == 2
    entries = ledger.entries("failed")
    assert {entry["failure_count"] for entry in entries.values()} == {1}
    repaired_entry = next(entry for entry in entries.values() if entry["repair"]["outcome"] == "failed")
    assert repaired_entry["attempts"] == 4
    assert repaired_entry["attempt_history"][-1]["defects"] == [{"code": "repair_missing_body"}]
    lines = [summary.failed_chunk_line(recovery.failed_chunk_summary(key, entry)) for key, entry in entries.items()]
    assert any("An AI repair call also failed (other)." in line for line in lines)
    assert any("AI repair was skipped: per-run repair limit reached." in line for line in lines)


def test_repair_is_off_without_a_session_and_for_provider_failures(tmp_path):
    rows = [{"When": "1", "Command": "x"}]
    plan, chunks = runtime_fixtures.CollectionAnalysisRuntimeTest().build(
        artifact_count=1, rows=rows, limit=10_000
    )
    seen = []

    def execute(task):
        seen.append(task.metadata.get("repair", False))
        if task.metadata["stage"] == "chunk":
            raise RuntimeError("Agent prompt exceeds maximum input tokens: 9 > 1\nPRIVATE detail")
        return successful(task, synthesis_output(task))

    with chunk_repair.session(4):
        result = asyncio.run(runtime.execute_analysis_workload_async(
            plan=plan, chunk_csv=chunks, question="q", spec=spec(), workdir=tmp_path,
            output_dir=tmp_path, execute=execute, perform_scope_synthesis=False,
        ))
    [record] = [item for item in result["tasks"] if item["stage"] == "chunk"]
    assert record["attempts"] == 1 and "repair" not in record and True not in seen
    last = record["attempt_history"][-1]["run"]
    assert last["error_classification"] == "input_limit"
    assert last["error"] == "Agent prompt exceeds maximum input tokens: 9 > 1"
    diagnostics = recovery.task_diagnostics(record)
    assert diagnostics["attempt_history"][-1]["category"] == "input_limit"


VALID_HUNT_CHUNK = (
    "RESULT\tfindings\nFINDING\tF1\thigh\tExecution\tSuspicious event.\n"
    "EVIDENCE\tF1\tS0001-R1\nEND"
)


def _hunt_chunk_work():
    chunk = coordinator._streaming_chunk(
        [{
            "unit_id": "unit-1", "revision": "revision-1", "source_id": "source-1",
            "segment_id": "segment-1", "artifact": "Artifact.Test",
            "compatibility_key": "Artifact.Test/profile", "row_count": 1, "input_tokens": 10,
            "rows": [{"_SourceRef": "S0001-R1", "Value": "one"}],
        }],
        analysis_id="analysis-1",
    )
    return next(iter(coordinator.iter_streaming_chunk_work(
        [chunk],
        source_aliases={"source-1": {
            "alias": "S0001", "scope_type": "hunt", "scope_id": "H.1", "hunt_id": "H.1",
            "org_id": "root", "artifact": "Artifact.Test", "source": "hunt_results",
        }},
        scope_type="hunt", scope_id="H.1", analysis_id="analysis-1",
        question="What is suspicious?",
        limits={
            "model_context_tokens": 16_000, "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000, "maximum_output_tokens": 2_000,
            "instruction_reserve_tokens": 1_000, "prior_context_reserve_tokens": 0,
            "safety_reserve_tokens": 1_000, "maximum_evidence_tokens_per_item": 8_000,
        },
        encoding_name="cl100k_base",
    )))


def test_streaming_hunt_chunk_is_repaired_without_leaking_the_rejected_answer(tmp_path):
    calls = []

    class Runner:
        def run(self, task, **_kwargs):
            calls.append(bool(task.metadata.get("repair")))
            output = (
                "DIAGNOSIS\tinvalid_evidence_record\tL3\textra column\nREPAIRED\n" + VALID_HUNT_CHUNK
                if task.metadata.get("repair")
                else VALID_HUNT_CHUNK.replace("S0001-R1", "S0001-R1\tPRIVATE")
            )
            return AgentResult(
                task_id=task.task_id, status="succeeded", output=output, output_file="",
                events_file="", manifest_file="", elapsed_seconds=0.0,
            )

    with chunk_repair.session(4):
        outcome = asyncio.run(coordinator._execute_streaming_chunk_work_async(
            _hunt_chunk_work(), runner=Runner(), workdir=tmp_path, runtime_dir=tmp_path / ".api-runtime",
        ))
    assert calls == [False, False, False, True]
    assert outcome["status"] == "accepted"
    assert outcome["repair"]["outcome"] == "repaired"
    assert outcome["repair"]["causes"] == [{"cause": "invalid_evidence_record", "location": "L3"}]
    assert [item["status"] for item in outcome["attempt_failures"]] == ["retrying"] * 3
    assert any("accepted after AI repair" in line for line in outcome["result"]["limitations"])
    review = outcome["review"]
    assert review["attempts"] == 4 and review["repair"]["outcome"] == "repaired"
    assert "PRIVATE" not in json.dumps(review) and outcome["evidence"] is None

    with chunk_repair.session(0):
        unrepaired = asyncio.run(coordinator._execute_streaming_chunk_work_async(
            _hunt_chunk_work(), runner=Runner(), workdir=tmp_path, runtime_dir=tmp_path / ".api-runtime",
        ))
    assert unrepaired["status"] == "failed" and "repair" not in unrepaired["review"]


def test_resume_command_keeps_the_model_and_repair_settings():
    from vraptor.hunt.command import parse_args

    args = command.build_parser().parse_args([
        "--client-id", "C.test", "--model", "fixture-model", "--max-output-tokens", "4000",
        "--chunk-repair-limit", "0",
    ])
    resume = command.resume_analysis_command(args, {"client_id": "C.test", "request_id": "r1"})
    assert "--model fixture-model" in resume and "--max-output-tokens 4000" in resume
    assert "--chunk-repair-limit 0" in resume
    assert parse_args(["analyze", "--id", "t", "--hunt-id", "H.t", "--chunk-repair-limit", "2"]).chunk_repair_limit == 2
    with pytest.raises(SystemExit):
        command.build_parser().parse_args(["--client-id", "C.test", "--chunk-repair-limit", "21"])


class _HuntRunner:
    """Breaks the first chunk it sees; the repair call returns ``repair``."""

    def __init__(
        self,
        repair="DIAGNOSIS\tformat_drift\tL1\tnot a protocol record\nREPAIRED\n"
        "RESULT\tno_reportable_findings\nEND",
        broken=True,
    ):
        self.calls, self.first, self.repair, self.broken = [], None, repair, broken

    async def run(self, task, **_kwargs):
        repairing = bool(task.metadata.get("repair"))
        self.calls.append((task.metadata.get("stage"), task.task_id, repairing))
        if task.metadata.get("stage") != "chunk":
            output = synthesis_output(task)
        else:
            self.first = self.first or task.task_id
            output = (
                self.repair
                if repairing
                else "PRIVATE_MODEL_OUTPUT" if self.broken and task.task_id == self.first
                else "RESULT\tno_reportable_findings\nEND"
            )
        return AgentResult(
            task_id=task.task_id, status="succeeded", output=output, output_file="",
            events_file="", manifest_file="", elapsed_seconds=0.0,
        )

    async def close(self):
        pass


def _analyze_hunt(tmp_path, api, artifact, runner=None, **kwargs):
    from dataclasses import replace
    from unittest import mock

    import test_flow_analysis

    runner = runner or _HuntRunner()
    with mock.patch.object(coordinator, "create_agent_runner", return_value=runner), \
            mock.patch.object(coordinator.asyncio, "sleep", new=mock.AsyncMock()), \
            chunk_repair.session(4) as policy:
        result = coordinator.analyze_hunt_flows(
            api, org_id="root", hunt_id="H.1", hunt_state="RUNNING",
            reported_result_rows=sum(len(rows) for rows in api.rows.values()),
            target_execution_coverage="partial", targeted_client_count=0,
            question="What is suspicious?", hunt_root=tmp_path, selected_artifacts=[artifact],
            limits=replace(test_flow_analysis.TEST_LIMITS, maximum_evidence_tokens_per_item=1_000),
            spec=test_flow_analysis.FlowAnalysisTest().spec(), **kwargs,
        )
    state = json.loads((tmp_path / "analysis" / "hunt-analysis-state.json").read_text())
    ledger = json.loads((tmp_path / "analysis" / coordinator.FAILED_CHUNKS_FILENAME).read_text())
    return result, state["runs"][-1], ledger, runner, policy


@pytest.mark.parametrize("synthesis_mode", ["full", "none"])
def test_hunt_publishes_the_repair_label_and_logs_the_chunk(tmp_path, synthesis_mode):
    from test_flow_analysis import FakeFlowApi, flow_row

    rows = {
        ("C.1", "F.1"): [{"Value": f"one {i} " + "alpha " * 300} for i in range(6)],
        ("C.2", "F.2"): [{"Value": f"two {i} " + "beta " * 300} for i in range(6)],
    }
    api = FakeFlowApi([flow_row("C.1", "F.1"), flow_row("C.2", "F.2")], rows)
    result, run, ledger, runner, _policy = _analyze_hunt(
        tmp_path, api, "Artifact.Test", synthesis_mode=synthesis_mode,
    )
    [chunk_id] = run["repaired_chunk_ids"]
    entry = ledger["chunks"][chunk_id]
    assert (entry["status"], entry["resolution"]["by"], entry["failure_count"]) == ("resolved", "repair", 1)
    assert "PRIVATE_MODEL_OUTPUT" not in json.dumps(ledger)
    assert [call for call in runner.calls if call[2]]
    published = result["analysis_result"]
    [line] = [item for item in published["limitations"] if "accepted after AI repair" in item]
    assert f"Key `{chunk_id}`" in line and "chunk 1/1" not in line
    assert published["coverage"]["repaired_chunks"] == 1


def _detectraptor_hunt():
    from test_flow_analysis import FakeFlowApi, flow_row
    from vraptor.analyze import flow_runtime
    from vraptor.analyze import time_scope

    artifact = flow_runtime.DETECTRAPTOR_EVTX_ARTIFACT
    api = FakeFlowApi(
        [flow_row("C.1", "F.1", artifact=artifact)],
        {("C.1", "F.1"): [
            {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:20:00Z"},
            {"Detection": {"Name": "Rare"}, "EventTime": "2026-08-13T09:30:00Z"},
            {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:40:00Z"},
        ]},
    )
    scope = time_scope.TimeScope.from_values(
        after="2026-08-13T09:00:00Z", before="2026-08-13T10:00:00Z",
    )
    return api, artifact, scope


def test_detectraptor_partition_repair_is_logged(tmp_path):
    api, artifact, scope = _detectraptor_hunt()
    _result, run, ledger, _runner, policy = _analyze_hunt(tmp_path, api, artifact, time_scope=scope)
    assert policy.used == 1
    [chunk_id] = run["repaired_chunk_ids"]
    assert ledger["chunks"][chunk_id]["resolution"]["by"] == "repair"
    assert ledger["chunks"][chunk_id]["artifact"] == artifact


def test_detectraptor_partition_chunk_that_fails_every_attempt_is_recorded(tmp_path):
    api, artifact, scope = _detectraptor_hunt()
    path = tmp_path / "analysis" / coordinator.FAILED_CHUNKS_FILENAME
    with pytest.raises(RuntimeError) as raised:
        _analyze_hunt(tmp_path, api, artifact, runner=_HuntRunner(repair="PRIVATE_MODEL_OUTPUT"),
                      time_scope=scope)
    ledger = json.loads(path.read_text())
    [chunk_id] = ledger["chunks"]
    entry = ledger["chunks"][chunk_id]
    assert re.fullmatch(recovery._IDENTITY_PATTERNS["chunk_id"], chunk_id)
    assert str(raised.value).endswith(f"Review {path} (chunks: {chunk_id}).")
    assert (entry["status"], entry["stage"], entry["artifact"], entry["hunt_id"]) == (
        "failed", "chunk", artifact, "H.1")
    assert (entry["attempts"], entry["final"]["category"], entry["repair"]["outcome"]) == (
        4, "validation_failed", "failed")
    assert "PRIVATE_MODEL_OUTPUT" not in path.read_text()
    state = json.loads((tmp_path / "analysis" / "hunt-analysis-state.json").read_text())
    run = state["runs"][-1]
    assert (run["failure_stage"], run["failed_chunks_file"], run["failed_chunk_ids"]) == (
        "detectraptor_partition", str(path), [chunk_id])

    # The rerun reviews the failed partition again and resolves its entry.
    _result, run, ledger, _runner, _policy = _analyze_hunt(
        tmp_path, api, artifact, runner=_HuntRunner(broken=False), time_scope=scope)
    assert run["status"] == "complete"
    assert ledger["chunks"][chunk_id]["status"] == "resolved"
    assert ledger["chunks"][chunk_id]["resolution"] == {"by": "acceptance"}


def _rare_partition_fails():
    from unittest import mock

    real = coordinator._analyze_detectraptor_partition

    async def rare_fails(*args, **kwargs):
        if kwargs["partition"].detection == "Rare":
            raise RuntimeError("partition stage failed")
        return await real(*args, **kwargs)

    return mock.patch.object(coordinator, "_analyze_detectraptor_partition", new=rare_fails)


def test_detectraptor_partition_completed_in_a_failed_run_updates_the_record(tmp_path):
    api, artifact, scope = _detectraptor_hunt()
    path = tmp_path / "analysis" / coordinator.FAILED_CHUNKS_FILENAME
    state_path = tmp_path / "analysis" / "hunt-analysis-state.json"
    with _rare_partition_fails():
        # Run 1: the Rare stage fails and a Common chunk fails every attempt. The
        # chunk is recorded against Common and the error names both failures.
        with pytest.raises(
            RuntimeError,
            match=r"^Hunt analysis failed closed: .* DetectRaptor partition Rare also "
            r"failed: partition stage failed$",
        ):
            _analyze_hunt(tmp_path, api, artifact,
                          runner=_HuntRunner(repair="PRIVATE_MODEL_OUTPUT"), time_scope=scope)
        run = json.loads(state_path.read_text())["runs"][-1]
        [chunk_id] = run["failed_chunk_ids"]
        assert run["active_detection"] == "Common"
        assert len(run["failed_partition_ids"]) == 2
        assert run["partition_id"] in run["failed_partition_ids"]
        rerun = json.loads(path.read_text())["chunks"][chunk_id]["next"]["rerun"]
        assert "reuses completed ones" in rerun
        # Run 2: Common is accepted; only the Rare stage failure remains.
        with pytest.raises(RuntimeError, match=r"^partition stage failed$"):
            _analyze_hunt(tmp_path, api, artifact, runner=_HuntRunner(broken=False), time_scope=scope)
        assert json.loads(state_path.read_text())["runs"][-1]["active_detection"] == "Rare"
    # The second run completed that partition; later runs reuse it without outcomes.
    [entry] = json.loads(path.read_text())["chunks"].values()
    assert entry["resolution"] == {"by": "acceptance"}

    path.unlink()
    with _rare_partition_fails(), pytest.raises(RuntimeError, match=r"^partition stage failed$"):
        _analyze_hunt(tmp_path / "repaired", api, artifact, time_scope=scope)
    ledger = json.loads((tmp_path / "repaired" / "analysis" / coordinator.FAILED_CHUNKS_FILENAME).read_text())
    [(chunk_id, entry)] = ledger["chunks"].items()
    assert entry["resolution"]["by"] == "repair"
    state = json.loads((tmp_path / "repaired" / "analysis" / "hunt-analysis-state.json").read_text())
    assert state["runs"][-1]["repaired_chunk_ids"] == [chunk_id]


def _pending_then(ledger, key, repair, *, history_tail=(), evidence=None):
    failure = _failure(key.split(":", 1)[1])
    failure["attempt_history"].extend(history_tail)
    ledger.record_failure(
        key, {**failure, **({"repair": repair} if repair else {})},
        identity={"artifact": "Artifact.0"}, budget={}, next_steps={}, evidence=evidence,
    )


def test_ledger_pairs_only_a_pending_record_with_its_own_repair_result(tmp_path):
    ledger = recovery.FailedChunkLedger(tmp_path / "failed-chunks.json", SCOPE)
    key = "Artifact.0:artifact-task-1-chunk-0"
    timeout = {"attempt": 4, "status": "failed", "category": "timeout", "repair": True, "defects": [
        {"code": "repair_missing_body"}]}
    _pending_then(ledger, key, {"outcome": "pending"})
    _pending_then(ledger, key, {"outcome": "failed", "attempt": 4, "findings_before": 0},
                  history_tail=[timeout], evidence={"directory": "/case/debug/run1"})
    entry = ledger.entries()[key]
    assert entry["failure_count"] == 1
    assert entry["final"]["category"] == "validation_failed"
    assert entry["final"]["defect_codes"] == ["invalid_reference"]
    assert entry["repair"]["category"] == "timeout"
    assert "(timeout)" in summary.failed_chunk_line(recovery.failed_chunk_summary(key, entry))
    # An interrupted repair leaves a pending record; the next run's failure is new.
    _pending_then(ledger, key, {"outcome": "pending"})
    _pending_then(ledger, key, None)
    entry = ledger.entries()[key]
    # A later failure without an export keeps the pointer to the earlier one.
    assert entry["failure_count"] == 3
    assert entry["evidence"] == {"directory": "/case/debug/run1", "failure": 1}
    _pending_then(ledger, key, {"outcome": "pending"})
    ledger.resolve(key)
    entry = ledger.entries()[key]
    assert entry["resolution"] == {"by": "acceptance"} and "repair" not in entry


def test_repair_prompt_separates_earlier_defects_and_must_fit_the_input_limit():
    prompt = chunk_repair.render_repair_prompt(
        "INPUT",
        defects=[{"code": "invalid_context_type", "line": 4}],
        earlier_defects=[{"code": "unsupported_tactic", "line": 7}],
        previous_output="\n".join(f"line {index}" for index in range(1, 9)),
        rejected_count=3,
    )
    assert '\nDEFECT\t{"code":"invalid_context_type","line":4}\n' in prompt
    assert '\nEARLIER_DEFECT\t{"code":"unsupported_tactic"}\n' in prompt
    arguments = dict(
        defects=[{"code": "invalid_context_type", "line": 4}], earlier_defects=[],
        previous_output="\n".join("x" * 50 for _ in range(40)), rejected_count=3,
    )
    full = chunk_repair.build_repair_prompt("INPUT", fits=None, **arguments)
    assert "quoted 40 of 40 lines" in full
    cited = chunk_repair.build_repair_prompt("INPUT", fits=lambda text: len(text) < len(full), **arguments)
    assert "quoted 1 of 40 lines" in cited
    assert chunk_repair.build_repair_prompt("INPUT", fits=lambda _text: False, **arguments) is None
    fits = chunk_repair.input_fits(10, "cl100k_base")
    assert fits("short") and not fits("word " * 50)
    assert chunk_repair.input_fits(None, "cl100k_base") is None


def test_repair_is_skipped_without_a_slot_when_the_prompt_cannot_fit(tmp_path, monkeypatch):
    monkeypatch.setattr(chunk_repair, "input_fits", lambda *_args: lambda text: "REPAIR REVIEW" not in text)
    result, ledger, events, prompts, _calls, [task_id] = _repair_workload(
        tmp_path, failing=[0], repair_output=REPAIRED_CHUNK, limit=1,
    )
    assert prompts == [] and [kind for kind, *_rest in events] == ["failed"]
    record = next(item for item in result["tasks"] if item["task_id"] == task_id)
    assert (record["attempts"], record["repair"]["reason"]) == (3, "repair_prompt_too_large")
    line = summary.failed_chunk_line(recovery.failed_chunk_summary(
        f"Artifact.0:{task_id}", ledger.entries()[f"Artifact.0:{task_id}"]
    ))
    assert "AI repair was skipped: the repair prompt would exceed the input limit." in line


def test_host_diagnosis_may_cite_only_the_chunk_references(tmp_path):
    output = REPAIRED_CHUNK.replace(
        "REPAIRED", "DIAGNOSIS\tother\tS2024-R7\tnot a chunk row\nREPAIRED"
    )
    result, _ledger, _events, _prompts, _calls, [task_id] = _repair_workload(
        tmp_path, failing=[0], repair_output=output, command="net use \\\\FILESRV-S2024-R7\\share ",
    )
    record = next(item for item in result["tasks"] if item["task_id"] == task_id)
    assert record["repair"]["diagnosis_status"] == "invalid"
    assert {"cause": "other", "location": "-"} in record["repair"]["causes"]
    assert "S2024-R7" not in json.dumps(result["artifact_results"])


def test_shared_hunt_runner_applies_the_input_limit_to_the_repair_prompt(tmp_path):
    import test_flow_analysis
    from vraptor.common import token_budget

    work = _hunt_chunk_work()
    limits = {
        "model_context_tokens": 16_000, "operational_context_tokens": 12_000,
        "maximum_input_tokens": 10_000, "maximum_output_tokens": 2_000,
    }
    invalid = VALID_HUNT_CHUNK.replace("S0001-R1", "S0001-R1\tPRIVATE") + "\n" + "\n".join(
        f"FINDING\tF{index}\thigh\tExecution\tfiller text for a long answer" for index in range(2, 1000)
    )
    sent = []

    def shared_execute(task, *, limits, progress_callback=None):
        tokens = token_budget.estimate_tokens(task.prompt, limits.token_encoding)
        if tokens > limits.maximum_input_tokens:
            raise RuntimeError(f"Agent prompt exceeds maximum input tokens ({tokens} > {limits.maximum_input_tokens}).")
        sent.append(task.prompt)
        output = (
            "DIAGNOSIS\tinvalid_evidence_record\t-\textra column\nREPAIRED\n" + VALID_HUNT_CHUNK
            if task.metadata.get("repair") else invalid
        )
        return AgentResult(
            task_id=task.task_id, status="succeeded", output=output, output_file="",
            events_file="", manifest_file="", elapsed_seconds=0.0,
        )

    with chunk_repair.session(4) as policy:
        [outcome] = asyncio.run(coordinator.execute_streaming_chunks_async(
            work_items=[work], limits=limits, encoding_name="cl100k_base",
            spec=test_flow_analysis.FlowAnalysisTest().spec(), workdir=tmp_path,
            runtime_dir=tmp_path / ".api-runtime", shared_execute=shared_execute,
        ))
    assert policy.used == 1 and outcome["status"] == "accepted"
    [repair_prompt] = [prompt for prompt in sent if "REPAIR REVIEW" in prompt]
    quoted, total = map(int, re.search(r"quoted ([0-9]+) of ([0-9]+) lines", repair_prompt).groups())
    assert quoted < total == len(invalid.splitlines())
