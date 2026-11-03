"""Root CLI lifecycle with mocked providers; no live services or user-state writes."""

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_agent_runtime import FakeAdapter
from test_collection_analysis_runtime import TEST_LIMITS
from test_host_final_review import review_output
from test_synthesis_modes import make_checkpoint
from vraptor import cli, legacy_cli, settings
from vraptor.agent import factory, manage, runtime
from vraptor.analyze import limits, model_options, saved
from vraptor.logging import operations
from vraptor.paths import EnvironmentLayer, RepositoryEnvironment


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    environment_layers = RepositoryEnvironment(
        EnvironmentLayer("process", "", {"HOME": str(tmp_path)}),
        EnvironmentLayer("repository_dotenv", "", {}),
        EnvironmentLayer("shared_dotenv", "", {}),
    )
    snapshot = SimpleNamespace(environment_layers=environment_layers, value=lambda name, profile=None: str(tmp_path / "cases") if name == "case_root" else None)
    monkeypatch.setattr(settings, "resolve", lambda *a, **k: snapshot)
    assert operations.current_session() is None
    yield
    assert operations.current_session() is None


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def assert_lifecycle(path, *, attempts, tokens, status="complete", code=0):
    records = rows(path)
    assert [r["event"] for r in records] == ["operation_started", *(["request_usage"] * attempts), "operation_summary"]
    assert len({r["operation_id"] for r in records}) == 1
    summary = records[-1]
    assert summary["attempts"] == attempts
    assert summary["total_tokens"] == tokens
    assert summary["status"] == status
    assert summary["exit_code"] == code
    assert summary["log_complete"]
    return records


def install_runner(monkeypatch, outputs):
    adapter = FakeAdapter(outcomes=[runtime.ProviderResponse(text, f"response-{i}", runtime.AgentUsage(8, 3, 11)) for i, text in enumerate(outputs)])
    adapter.configuration = replace(adapter.configuration, inputs=replace(adapter.configuration.inputs, credential_present=True))

    def build(*args, **kwargs):
        assert operations.current_session().is_bound or not operations.current_session().options.persist
        return runtime.ApiAgentRunner(adapter, persist_runtime_files=False)

    monkeypatch.setattr(factory, "create_agent_runner", build)
    monkeypatch.setattr(saved, "create_agent_runner", build)
    monkeypatch.setattr(model_options, "resolve", lambda *a, **k: (adapter.configuration, TEST_LIMITS))
    monkeypatch.setattr(manage, "resolve_agent_execution", lambda **k: adapter.configuration)
    monkeypatch.setattr(limits, "resolve_analysis_limits", lambda **k: TEST_LIMITS)
    monkeypatch.setattr(manage, "version", lambda name: "3.31.0")
    return adapter


def test_root_ai_test_logs_usage_to_user_state(monkeypatch, tmp_path, capsys):
    install_runner(monkeypatch, ["READY"])
    assert cli.main(["ai", "test"]) == 0
    payload = json.loads(capsys.readouterr().out)
    path = tmp_path / "state/vraptor/logs/token-usage.jsonl"
    records = assert_lifecycle(path, attempts=1, tokens=11)
    assert payload["token_usage"]["total_tokens"] == 11
    assert payload["operation_id"] == records[0]["operation_id"]


@pytest.mark.parametrize("with_id", [False, True])
def test_root_summarize_then_cache_hit_logs_once(monkeypatch, tmp_path, capsys, with_id):
    directory = tmp_path / "cases/CASE1/systems/host/collection/requests/test/analysis"
    directory.mkdir(parents=True)
    path = make_checkpoint(directory)
    adapter = install_runner(monkeypatch, [review_output()])
    args = ["summarize", "--checkpoint", str(path), "--format", "json", "--no-progress"]
    if with_id:
        args += ["--id=CASE1", "--case-root", str(tmp_path / "cases")]
    assert cli.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    ledger = tmp_path / "cases/CASE1/logs/token-usage.jsonl"
    assert_lifecycle(ledger, attempts=1, tokens=11)
    assert first["token_usage"]["total_tokens"] == 11
    assert cli.main(args) == 0
    second = json.loads(capsys.readouterr().out)
    records = rows(ledger)
    assert records[-2]["event"] == "operation_started"
    assert records[-1]["attempts"] == records[-1]["total_tokens"] == 0
    assert second["token_usage"]["attempts"] == 0
    assert second["reused"]
    assert adapter.calls == 1
    assert first["operation_id"] != second["operation_id"]
    assert not (tmp_path / "state").exists()


def test_failed_summarize_retains_all_correction_usage(monkeypatch, tmp_path, capsys):
    path = make_checkpoint(tmp_path)
    install_runner(monkeypatch, ["bad", "bad", "bad"])
    assert cli.main(["summarize", "--checkpoint", str(path), "--format", "json", "--no-progress"]) == 2
    payload = json.loads(capsys.readouterr().out)
    records = assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=3, tokens=33, status="failed", code=2)
    assert payload["token_usage"]["total_tokens"] == 33
    assert records[-1]["correction_attempts"] == 2


def test_root_and_legacy_share_one_operation(monkeypatch, tmp_path, capsys):
    def dispatch(args):
        session = operations.current_session()
        assert session.is_bound
        print(json.dumps(operations.correlation_metadata()))
        return 0
    monkeypatch.setattr(legacy_cli, "_dispatch", dispatch)
    assert cli.main(["collect", "status", "--investigation-id", "CASE1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    records = assert_lifecycle(tmp_path / "cases/CASE1/logs/token-usage.jsonl", attempts=0, tokens=0)
    assert payload["operation_id"] == records[0]["operation_id"]
    assert payload["token_usage"]["attempts"] == 0


def test_help_as_question_does_not_disable_logging(monkeypatch, tmp_path):
    seen = []
    def analyze(args):
        seen.append(operations.current_session())
        assert settings.current() is not None
        return 0
    monkeypatch.setattr(cli, "analyze", analyze)
    assert cli.main(["analyze", "--question", "help"]) == 0
    assert seen[0] is not None
    assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=0, tokens=0)


def test_initialization_logs_without_precreating_the_case(monkeypatch, tmp_path, capsys):
    from vraptor import workspace

    monkeypatch.setattr(workspace, "configuration_checks", dict)
    root = tmp_path / "cases"
    args = ["setup", "init", "--id", "CASE1", "--case-root", str(root)]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "initialized"
    assert {path.name for path in (root / "CASE1").iterdir()} == {"AGENTS.md"}
    assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=0, tokens=0)
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "reused"


@pytest.mark.parametrize("args", [
    ["query", "--id", "lab7", "--vql", "SELECT 1 FROM scope()"],
    ["clients", "list", "--id", "lab7"],
])
def test_instance_only_id_alias_does_not_create_a_case(monkeypatch, tmp_path, args):
    from vraptor import query

    monkeypatch.setattr(query, "main", lambda argv: 0)
    assert cli.main(args) == 0
    assert not (tmp_path / "cases").exists()
    assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=0, tokens=0)


def test_initialization_keeps_configuration_error_category(monkeypatch, tmp_path):
    from vraptor import workspace

    def fail(*args, **kwargs):
        raise ValueError("invalid local configuration")

    received = []
    monkeypatch.setattr(settings, "resolve", fail)
    monkeypatch.setattr(workspace, "main", lambda args, **kwargs: received.append(kwargs) or 0)
    assert cli.main(["setup", "init", "--id", "CASE1", "--case-root", str(tmp_path)]) == 0
    assert received == [{"configuration_error": "ValueError"}]


@pytest.mark.parametrize("exception,status,code", [(SystemExit(0), "complete", 0), (SystemExit(2), "failed", 2), (KeyboardInterrupt(), "interrupted", 130), (asyncio.CancelledError(), "interrupted", 130), (RuntimeError("failure"), "failed", 1)])
def test_exception_exit_records_terminal_status(tmp_path, exception, status, code):
    def dispatch(args):
        raise exception
    with pytest.raises(type(exception)):
        operations.run_operation(["synthetic"], dispatch)
    assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=0, tokens=0, status=status, code=code)


def test_global_logging_options_and_optout(monkeypatch, tmp_path, capsys):
    install_runner(monkeypatch, ["READY"])
    assert cli.main(["ai", "test", "--no-log-file"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["token_usage"]["total_tokens"] == 11
    assert not payload["token_usage"]["persistence_enabled"]
    assert not (tmp_path / "state").exists()
    path = tmp_path / "explicit.log"
    install_runner(monkeypatch, ["READY"])
    assert cli.main(["ai", "test", "--log-file", str(path)]) == 0
    capsys.readouterr()
    assert_lifecycle(tmp_path / "explicit-token-usage.jsonl", attempts=1, tokens=11)
    assert cli.main(["ai", "test", "--log-file", str(path), "--no-log-file"]) == 2
    assert len(rows(tmp_path / "explicit-token-usage.jsonl")) == 3


def test_help_and_log_inspection_do_not_write(tmp_path, capsys):
    with pytest.raises(SystemExit) as result:
        cli.main(["ai", "test", "--help"])
    assert result.value.code == 0
    capsys.readouterr()
    assert not (tmp_path / "state").exists()


def test_bad_checkpoint_layout_falls_back_and_explicit_failure_is_visible(tmp_path, capsys):
    checkpoint = tmp_path / "random/request-analysis.json"
    checkpoint.parent.mkdir()
    checkpoint.write_text("{}")
    operations.run_operation(["synthetic", "--checkpoint", str(checkpoint)], lambda args: 0)
    assert_lifecycle(tmp_path / "state/vraptor/logs/token-usage.jsonl", attempts=0, tokens=0)
    blocker = tmp_path / "blocked"
    blocker.write_text("file")
    received = []
    operations.run_operation(["synthetic", "--log-file", str(blocker / "log")], lambda args: received.append(operations.correlation_metadata()) or 0)
    assert received[0]["token_usage"]["persistence_error"]
    assert not received[0]["token_usage"]["log_complete"]
    assert "incomplete" in capsys.readouterr().err


def test_explicit_log_symlink_is_not_followed(tmp_path, capsys):
    target = tmp_path / "target.log"
    target.write_text("preserve")
    link = tmp_path / "linked.log"
    link.symlink_to(target)
    received = []
    operations.run_operation(["synthetic", "--log-file", str(link)], lambda args: received.append(operations.correlation_metadata()) or 0)
    assert target.read_text() == "preserve"
    assert not received[0]["token_usage"]["log_complete"]
    assert "incomplete" in capsys.readouterr().err


def test_binding_error_does_not_replace_original_exception(monkeypatch, tmp_path):
    def dispatch(args):
        raise RuntimeError("original failure")
    monkeypatch.setattr(operations, "bind_cli_destination", lambda args: (_ for _ in ()).throw(OSError("bind failed")))
    with pytest.raises(RuntimeError, match="original failure"):
        operations.run_operation(["synthetic"], dispatch, defer_binding=True)
