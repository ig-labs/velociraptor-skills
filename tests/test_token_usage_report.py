"""Usage reports preserve source logs and reconcile requests without doubling totals."""

import json

import pytest
from vraptor import cli
from vraptor.agent.providers import _usage
from vraptor.logging import operations
from vraptor.logging.usage_report import summarize

OP = "op-v1-1111111111111111"
OTHER = "op-v1-2222222222222222"
STAMP = "2026-10-28T01:00:00Z"


def request(op=OP, request_id="r1", **changes):
    return {"schema_version": 1, "event": "request_usage", "operation_id": op,
            "timestamp": STAMP, "invocation_id": "inv1", "attempt": 1, "request_id": request_id,
            "input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cached_input_tokens": 4,
            "usage_status": "reported", **changes}


def summary(op=OP, **changes):
    return {**request(op), "event": "operation_summary", "attempts": 1,
            "usage_complete": True, "log_complete": True, **changes}


def write(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    path.chmod(0o600)


def progress(op=OP, request_id="r1", message="Model request completed"):
    return (f"{STAMP} INFO [{op}] {message} | request_id={request_id} task_id=task1 attempt=1 "
            "input_tokens=10 output_tokens=5 total_tokens=15 cached_input_tokens=4\n")


def test_latest_operation_differs_from_retained_total_and_sources_stay_unchanged(tmp_path):
    ledger = tmp_path / "token-usage.jsonl"
    write(ledger, [request(), summary()])
    old = tmp_path / "velociraptor-progress.log"
    old.write_text(progress() + progress(OTHER, "r2"))
    old.chmod(0o600)
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 30
    assert report["latest_operation"]["total_tokens"] == 15
    assert report["coverage"]["progress_requests_added"] == 1
    assert report["requests"] == 2
    assert {issue["code"] for issue in report["coverage"]["issues"]} == {"operation_summary_unavailable"}
    assert summarize(tmp_path, ledger_only=True)["totals"]["total_tokens"] == 15
    assert before == {p: p.read_bytes() for p in tmp_path.iterdir()}


def test_rotated_requests_and_duplicate_summaries_count_once(tmp_path):
    write(tmp_path / "token-usage.jsonl.1", [request(), summary()])
    write(tmp_path / "token-usage.jsonl", [summary()])
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 15
    assert report["coverage"]["ledger_requests"] == 1


def test_summary_retains_totals_when_request_rows_rotated_out(tmp_path):
    write(tmp_path / "token-usage.jsonl", [summary()])
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 15
    assert report["operations"][0]["requests_covered_only_by_summary"] == 1
    assert report["lifetime_complete"] is False


def test_zero_model_call_operation_has_explicit_complete_zero_usage(tmp_path):
    write(tmp_path / "token-usage.jsonl", [
        {"schema_version": 1, "event": "operation_started", "operation_id": OP,
         "timestamp": STAMP, "status": "running"},
        summary(attempts=0, input_tokens=0, output_tokens=0, total_tokens=0,
                cached_input_tokens=0, status="complete", retry_attempts=0,
                transport_retry_attempts=0, correction_attempts=0),
    ])
    report = summarize(tmp_path)
    assert report["coverage"]["retained_records_consistent"]
    assert report["requests"] == 0
    assert report["operation_count"] == 1
    assert report["latest_operation"]["usage_complete"]
    assert report["latest_operation"]["status"] == "complete"
    assert report["retry_totals"] == {"retry_attempts": 0, "transport_retry_attempts": 0, "correction_attempts": 0}


@pytest.mark.parametrize("with_request", [False, True])
def test_unfinished_ledger_operation_keeps_known_usage_without_claiming_zero_or_completion(tmp_path, with_request):
    rows = [{"schema_version": 1, "event": "operation_started", "operation_id": OP,
             "timestamp": STAMP, "status": "running"}]
    if with_request:
        rows.append(request())
    write(tmp_path / "token-usage.jsonl", rows)
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == (15 if with_request else 0)
    assert report["latest_operation"]["status"] == "unfinished"
    assert not report["latest_operation"]["operation_complete"]
    assert not report["latest_operation"]["usage_complete"]
    assert "operation_without_terminal_summary" in {i["code"] for i in report["coverage"]["issues"]}


def test_interrupted_operation_preserves_status_and_partial_usage(tmp_path):
    write(tmp_path / "token-usage.jsonl", [request(usage_status="partial"),
          summary(status="interrupted", usage_complete=False)])
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 15
    assert report["latest_operation"]["status"] == "interrupted"
    assert report["latest_operation"]["operation_complete"]
    assert not report["latest_operation"]["usage_complete"]
    assert report["retry_totals"]["correction_attempts"] is None


def test_summaries_report_both_retry_types_without_doubling_tokens(tmp_path):
    write(tmp_path / "token-usage.jsonl", [
        request(request_id="r1"), request(request_id="r2", invocation_id="inv2"),
        request(request_id="r3", invocation_id="inv2", attempt=2),
        summary(attempts=3, input_tokens=30, output_tokens=15, total_tokens=45,
                cached_input_tokens=12, retry_attempts=2, transport_retry_attempts=1,
                correction_attempts=1, status="failed"),
    ])
    report = summarize(tmp_path)
    assert report["coverage"]["retained_records_consistent"]
    assert report["totals"]["total_tokens"] == 45
    assert report["retry_totals"] == {"retry_attempts": 2, "transport_retry_attempts": 1, "correction_attempts": 1}


def test_zero_attempt_summary_cannot_claim_nonzero_tokens(tmp_path):
    write(tmp_path / "token-usage.jsonl", [summary(attempts=0)])
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 0
    assert "invalid_operation_summary" in {i["code"] for i in report["coverage"]["issues"]}


@pytest.mark.parametrize("bad", [
    request(input_tokens=11, total_tokens=16),
    summary(input_tokens=11, total_tokens=16),
    request(op=OTHER),
])
def test_conflicts_are_flagged_and_excluded(tmp_path, bad):
    write(tmp_path / "token-usage.jsonl", [request(), summary(), bad])
    report = summarize(tmp_path)
    assert not report["coverage"]["retained_records_consistent"]
    assert report["totals"]["total_tokens"] == 0


def test_unknown_usage_is_not_presented_as_complete(tmp_path):
    write(tmp_path / "token-usage.jsonl", [request(input_tokens=None, output_tokens=None,
          total_tokens=None, cached_input_tokens=None, usage_status="unavailable")])
    report = summarize(tmp_path)
    assert report["totals"]["total_tokens"] == 0
    assert not report["coverage"]["retained_records_consistent"]


def test_unfinished_progress_request_is_a_coverage_gap(tmp_path):
    path = tmp_path / "velociraptor-progress.log"
    path.write_text(progress(message="Model request started"))
    path.chmod(0o600)
    assert "progress_requests_without_terminal_usage" in {i["code"] for i in summarize(tmp_path)["coverage"]["issues"]}


@pytest.mark.parametrize("mode", ["symlink", "partial", "malformed", "unsafe_permissions"])
def test_unsafe_or_incomplete_sources_never_produce_trusted_totals(tmp_path, mode):
    path = tmp_path / "token-usage.jsonl"
    write(path, [request()])
    if mode == "symlink":
        path.rename(tmp_path / "target")
        path.symlink_to(tmp_path / "target")
    elif mode == "partial":
        path.write_text(path.read_text().rstrip())
    elif mode == "malformed":
        path.write_text('not-json\n')
    else:
        path.chmod(0o644)
    report = summarize(tmp_path)
    assert report["coverage"]["issues"]
    assert report["totals"]["total_tokens"] == 0


def test_usage_cli_is_offline_and_does_not_bind_a_log(tmp_path, monkeypatch, capsys):
    path = tmp_path / "case1" / "logs"
    path.mkdir(parents=True)
    write(path / "token-usage.jsonl", [request(), summary()])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "invalid"))
    (tmp_path / "invalid" / "vraptor").mkdir(parents=True)
    (tmp_path / "invalid" / "vraptor" / "config.toml").write_text("[invalid")
    assert cli.main(["logs", "usage", "--case-root", str(tmp_path), "--id", "case1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["totals"]["total_tokens"] == 15
    assert list(path.iterdir()) == [path / "token-usage.jsonl"]


@pytest.mark.parametrize("provider,raw,expected,cached", [
    ("openai", {"input_tokens": 18, "output_tokens": 2,
                "input_tokens_details": {"cached_tokens": 10}}, 20, 10),
    ("anthropic", {"input_tokens": 5, "output_tokens": 2,
                   "cache_read_input_tokens": 10, "cache_creation_input_tokens": 3}, 20, 10),
])
def test_command_output_reports_provider_normalized_usage_without_log_files(capsys, provider, raw, expected, cached):
    with operations.OperationLogger("analyze", options=operations.LogOptions(persist=False)) as logger:
        usage = _usage(raw)
        logger.record_token_usage(invocation_id="inv1", task_id="task1", request_id="r1",
                                  provider=provider, model="test", protocol="responses" if provider == "openai" else "messages",
                                  attempt=1, status="succeeded", elapsed_seconds=1,
                                  usage=usage.as_dict(), usage_status=usage.status)
        payload = operations.correlation_metadata()
        assert payload["token_usage"]["total_tokens"] == expected
        assert payload["token_usage"]["cached_input_tokens"] == cached
        assert payload["token_usage"]["persistence_enabled"] is False
        logger.finalize(status="complete", exit_code=0)
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err.count("Vraptor token usage (this command)") == 1
