"""Standalone analyst and user ledger integration without provider network calls."""

import json

import pytest
from test_agent_runtime import FakeAdapter
from test_run_analyst_agent import load_module, resolved_execution
from vraptor import cli
from vraptor.agent.runtime import (
    AgentError,
    AgentProviderException,
    ApiAgentRunner,
    RetryPolicy,
)
from vraptor.logging import operations


@pytest.mark.parametrize("failure", [False, True])
def test_standalone_counts_real_runner_attempt_and_preserves_stdout(tmp_path, monkeypatch, capsys, failure):
    module = load_module()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(module, "resolve_agent_execution", lambda *a, **kw: resolved_execution())
    adapter = FakeAdapter([AgentProviderException(AgentError("authentication", "Synthetic failure"))]) if failure else FakeAdapter()
    monkeypatch.setattr(module, "create_agent_runner", lambda *a, **kw: ApiAgentRunner(
        adapter, retry_policy=RetryPolicy(max_retries=0), persist_runtime_files=False,
    ))
    (tmp_path / "prompt.md").write_text("Assess the synthetic row.")
    (tmp_path / "input.csv").write_text("Value\nsynthetic\n")
    args = ["--workdir", str(tmp_path), "--prompt-file", "prompt.md", "--input", "input.csv",
            "--output", "report.md"]
    if failure:
        with pytest.raises(SystemExit):
            module.main(args)
    else:
        assert module.main(args) == 0
    output = capsys.readouterr()
    ledger = operations.user_log_directory() / "token-usage.jsonl"
    records = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [r["event"] for r in records] == ["operation_started", "request_usage", "operation_summary"]
    assert len({r["operation_id"] for r in records}) == 1
    assert records[-1]["attempts"] == 1
    assert records[-1]["status"] == ("failed" if failure else "complete")
    if failure:
        assert not records[-1]["usage_complete"]
        assert records[1]["input_tokens"] is None
    else:
        assert records[-1]["total_tokens"] == 3
        payload = json.loads(output.out)
        assert payload["operation_id"] == records[-1]["operation_id"]
        assert payload["token_usage"]["total_tokens"] == 3
    assert adapter.calls == 1
    assert "Assess the synthetic row" not in ledger.read_text()


def test_global_usage_report_is_read_only_and_needs_no_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    operations.run_operation(["ai", "doctor"], lambda _: 0)
    capsys.readouterr()
    directory = operations.user_log_directory()
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    from vraptor import settings
    monkeypatch.setattr(settings, "resolve", lambda *a, **kw: pytest.fail("Must not load settings"))
    assert cli.main(["logs", "usage", "--global", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["totals"]["total_tokens"] == 0
    assert payload["requests"] == 0
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
