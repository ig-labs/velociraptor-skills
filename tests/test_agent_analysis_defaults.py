"""Shared token settings resolve without inference or native credential access."""

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest
from vraptor.agent import command, manage, sources
from vraptor.agent.config import resolve_agent_execution
from vraptor.analyze import limits
from vraptor.paths import repository_environment

DEFAULTS = {
    "context_window_tokens": 360000,
    "max_input_tokens": 272000,
    "token_encoding": "o200k_base",
    "max_analysis_item_tokens": 200000,
    "max_output_tokens": 64000,
    "validation_correction_attempts": 2,
    "synthesis_correction_attempts": 2,
}


def write_config(tmp_path, settings, profile=None):
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "analysis_defaults": settings,
                "selection": {"default_profile": "test"},
                "profiles": {
                    "test": profile
                    or {"provider": "openai", "transport": "api", "model": "test"}
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def setup_args(path):
    return manage.parser_for("setup").parse_args(
        ["--provider", "openai", "--model", "test", "--config-file", str(path)]
    )


@pytest.mark.parametrize(
    "settings",
    [
        {"max_input_tokens": 0},
        {"max_input_tokens": -1},
        {"max_input_tokens": True},
        {"max_input_tokens": "272000"},
        {"token_encoding": ""},
        {"token_encoding": 123},
        {"chunk_size_tokens": 200000},
        {"max_analysis_item_rows": 50000},
    ],
)
def test_invalid_shared_settings_rejected(settings):
    with pytest.raises(RuntimeError, match="analysis_defaults"):
        sources.normalize_document({"schema_version": 2, "analysis_defaults": settings})


def test_setup_populates_and_preserves_partial_defaults(tmp_path):
    path = tmp_path / "agents.toml"
    with mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True):
        result = manage.setup(setup_args(path))
        assert result["analysis_defaults"] == DEFAULTS
        assert sources.read_config(path)["analysis_defaults"] == DEFAULTS
        assert "Check" in result["token_limits_note"]
        assert "# Check these token budgets" in path.read_text()
        partial = {"max_analysis_item_tokens": 150000, "token_encoding": "cl100k_base"}
        write_config(tmp_path, partial)
        previous = path.read_bytes()
        result = manage.setup(setup_args(path))
    assert result["analysis_defaults"] == {**DEFAULTS, **partial}
    assert sources.read_config(path)["analysis_defaults"] == {**DEFAULTS, **partial}
    assert path.with_suffix(".toml.bak").read_bytes() == previous


@pytest.mark.parametrize(
    "settings",
    [{"max_input_tokens": 1}, {"token_encoding": "missing-encoding"}],
)
def test_setup_rejects_invalid_budgets_before_writing(tmp_path, settings):
    path = write_config(tmp_path, settings)
    backup = path.with_suffix(".toml.bak")
    backup.write_text("previous backup")
    before = path.read_bytes()
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        pytest.raises(ValueError),
    ):
        args = setup_args(path)
        args.auto_token_budgets = False
        manage.setup(args)
    assert path.read_bytes() == before
    assert backup.read_text() == "previous backup"
    assert set(tmp_path.iterdir()) == {path, backup}


def test_token_only_planning_does_not_import_native_source(tmp_path):
    path = write_config(
        tmp_path,
        {"max_analysis_item_tokens": 150000},
        {"source": {"kind": "codex", "path": str(tmp_path / "missing.toml")}},
    )
    layers = repository_environment(
        tmp_path,
        process_environment={
            "HOME": str(tmp_path),
            "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path),
        },
    )
    with mock.patch.object(sources, "read_config", wraps=sources.read_config) as read:
        resolved = limits.resolve_analysis_limits(environment_layers=layers)
    read.assert_called_once_with(path)
    assert resolved.maximum_evidence_tokens_per_item == 150000


def test_toml_snapshot_is_immutable_and_reused_by_limits(tmp_path):
    path = write_config(tmp_path, {"max_analysis_item_tokens": 150000})
    with mock.patch.object(sources, "read_config", wraps=sources.read_config) as read:
        execution = resolve_agent_execution(
            repo_root=tmp_path,
            cli_values={"config_file": str(path)},
            process_environment={"HOME": str(tmp_path)},
            allow_missing_credentials=True,
        )
        path.unlink()
        resolved = limits.resolve_analysis_limits({}, execution=execution)
    read.assert_called_once_with(path)
    with pytest.raises(TypeError):
        execution.route.analysis_defaults["max_analysis_item_tokens"] = 1
    assert resolved.maximum_evidence_tokens_per_item == 150000
    assert resolved.identity() != limits.resolve_analysis_limits({}).identity()
    assert resolved.provenance_dict()["maximum_evidence_tokens_per_item"] == {
        "kind": "analysis_defaults",
        "name": "analysis_defaults.max_analysis_item_tokens",
        "location": str(path),
        "explicit": True,
    }


def test_environment_overrides_toml_with_provenance(tmp_path):
    path = write_config(tmp_path, DEFAULTS)
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/.env").write_text(
        "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS=150000\nAI_SKILLS_MAX_OUTPUT_TOKENS=40000\n"
    )
    (tmp_path / ".env").write_text(
        "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS=140000\nAI_SKILLS_MAX_INPUT_TOKENS=260000\n"
    )
    layers = repository_environment(
        tmp_path,
        process_environment={
            "HOME": str(tmp_path),
            "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path),
            "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "130000",
            "AI_SKILLS_MAX_OUTPUT_TOKENS": "",
        },
    )
    resolved = limits.resolve_analysis_limits(environment_layers=layers)
    assert resolved.maximum_evidence_tokens_per_item == 130000
    assert resolved.maximum_input_tokens == 260000
    assert resolved.maximum_output_tokens == 40000
    provenance = resolved.provenance_dict()
    assert (
        provenance["maximum_evidence_tokens_per_item"]["kind"] == "process_environment"
    )
    assert provenance["maximum_input_tokens"]["kind"] == "repository_dotenv"
    assert provenance["maximum_output_tokens"]["kind"] == "shared_dotenv"
    assert provenance["token_encoding"]["kind"] == "analysis_defaults"


def test_cli_explicit_config_reuses_shared_limits_and_model_clamps(
    tmp_path, monkeypatch, capsys
):
    path = write_config(
        tmp_path,
        {"max_analysis_item_tokens": 150000},
        {
            "provider": "anthropic",
            "model": "test",
            "model_context_tokens": 32768,
            "model_max_output_tokens": 4096,
        },
    )
    # Route defaults bind REPO_ROOT at import time; isolate it explicitly.
    monkeypatch.setattr(
        command,
        "resolve_agent_execution",
        lambda **kwargs: resolve_agent_execution(repo_root=tmp_path, **kwargs),
    )
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch.object(sources, "read_config", wraps=sources.read_config) as read,
    ):
        assert command.main(["--config-file", str(path)]) == 0
    read.assert_called_once_with(path)
    payload = json.loads(capsys.readouterr().out)["analysis_limits"]["effective"]
    assert payload["model_context_tokens"] == 32768
    assert payload["maximum_input_tokens"] + payload["maximum_output_tokens"] <= 32768
    assert payload["maximum_output_tokens"] <= 4096
    assert payload["maximum_evidence_tokens_per_item"] < 150000


def test_explicit_empty_environment_defaults_ignore_personal_config(tmp_path):
    with (
        mock.patch.dict(
            "os.environ",
            {"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(tmp_path / "missing")},
        ),
        mock.patch.object(
            sources, "read_config", side_effect=AssertionError("unexpected read")
        ),
    ):
        assert limits.resolve_analysis_limits({}).maximum_input_tokens == 272000


def test_offline_doctor_reports_custom_toml_budgets(tmp_path, monkeypatch):
    path = write_config(tmp_path, {"max_analysis_item_tokens": 150000})
    monkeypatch.setattr(
        manage,
        "resolve_agent_execution",
        lambda **kwargs: resolve_agent_execution(repo_root=tmp_path, **kwargs),
    )
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    args = manage.parser_for("doctor").parse_args(["--config-file", str(path)])
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch.object(
            manage, "model_metadata", side_effect=AssertionError("live query")
        ),
        mock.patch.object(sources, "read_config", wraps=sources.read_config) as read,
    ):
        payload, status = asyncio.run(manage.inspect_or_test("doctor", args))
    read.assert_called_once_with(path)
    assert status == 1  # Missing API credential is reported offline.
    assert payload["inference"] == "not_tested"
    budget = payload["configuration"]["analysis_limits"]
    assert budget["effective"]["maximum_evidence_tokens_per_item"] == 150000
    assert (
        budget["sources"]["maximum_evidence_tokens_per_item"]["kind"]
        == "analysis_defaults"
    )


def test_example_matches_canonical_defaults():
    path = Path(__file__).resolve().parents[1] / "config/analyst-agents.example.toml"
    document = sources.normalize_document(sources.read_config(path))
    assert (
        document["analysis_defaults"] == DEFAULTS == limits.default_analysis_settings()
    )


@pytest.mark.parametrize("managed_login", [False, True])
@pytest.mark.parametrize("supply_limits", [False, True])
@pytest.mark.parametrize(
    "settings",
    [
        DEFAULTS,
        {
            "context_window_tokens": 150000,
            "max_input_tokens": 100000,
            "token_encoding": "cl100k_base",
            "max_analysis_item_tokens": 30000,
            "max_output_tokens": 20000,
        },
    ],
)
def test_claude_shared_budgets_reach_planning_and_runner(
    tmp_path, managed_login, supply_limits, settings
):
    from vraptor.agent.factory import create_agent_runner

    if managed_login:
        source = tmp_path / "claude-settings.json"
        source.write_text('{"model":"claude-test"}')
        profile = {
            "source": {"kind": "claude_code", "path": str(source)},
            "transport": "claude_agent_sdk",
        }
    else:
        profile = {"provider": "anthropic", "transport": "api", "model": "claude-test"}
    path = write_config(tmp_path, settings, profile)
    execution = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    effective = limits.resolve_analysis_limits({}, execution=execution).for_execution(
        execution
    )
    for key, field in limits.TOML_FIELDS.items():
        assert getattr(effective, field) == settings.get(key, DEFAULTS[key])
        assert effective.provenance_dict()[field]["kind"] == (
            "analysis_defaults" if key in settings else "application_default"
        )
    path.unlink()
    with (
        mock.patch.object(
            sources, "read_config", side_effect=AssertionError("unexpected config read")
        ),
        mock.patch.object(
            limits,
            "repository_environment",
            side_effect=AssertionError("unexpected environment read"),
        ),
    ):
        runner = create_agent_runner(
            execution,
            limits=effective.runtime_limits() if supply_limits else None,
            client=object(),
        )
    assert runner.limits == effective.runtime_limits()
