"""Report budgets preserve model identity and resolve without inference."""

import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from vraptor.agent import manage, sources
from vraptor.agent.cli import agent_configuration_payload, application_defaults_payload
from vraptor.agent.config import resolve_agent_execution
from vraptor.analyze import limits, reporting
from vraptor.paths import EnvironmentLayer, RepositoryEnvironment


def layers(tmp_path, **variables):
    return RepositoryEnvironment(
        EnvironmentLayer("process", "", {"HOME": str(tmp_path), **variables}),
        EnvironmentLayer("repository_dotenv", str(tmp_path / ".env"), {}),
        EnvironmentLayer("shared_dotenv", str(tmp_path / "shared.env"), {}),
    )


def document(tmp_path, profile=None, shared=None):
    path = tmp_path / "analyst-agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "reporting": shared or {},
                "profiles": {
                    "work": {
                        "provider": "openai",
                        "model": "gpt-6-luna",
                        "max_input_tokens": 272000,
                        "max_output_tokens": 128000,
                        **(profile or {}),
                    }
                },
            }
        )
    )
    return path


def test_config_roundtrip_and_precedence(tmp_path):
    path = document(
        tmp_path,
        {"reporting": {"detailed_findings": 18, "examples_per_finding": 5}},
        {"detailed_findings": 12, "context_items": 7},
    )
    env = layers(tmp_path, VRAPTOR_REPORT_DETAILED_FINDINGS="22")
    policy = reporting.resolve_reporting_policy(
        cli_values={"config_file": str(path)}, environment_layers=env
    )
    assert (
        policy.detailed_findings,
        policy.context_items,
        policy.examples_per_finding,
    ) == (22, 7, 5)
    assert policy.public_dict()["sources"]["detailed_findings"]["kind"] == "process"
    overridden = reporting.resolve_reporting_policy(
        cli_values={"config_file": str(path), "detailed_findings": 9},
        environment_layers=env,
    )
    assert overridden.detailed_findings == 9
    assert overridden.public_dict()["sources"]["detailed_findings"]["kind"] == "cli"
    assert (
        sources.normalize_document(sources.read_config(path))["reporting"][
            "context_items"
        ]
        == 7
    )


def test_cli_beats_invalid_lower_environment(tmp_path):
    policy = reporting.resolve_reporting_policy(
        cli_values={"detailed_findings": 6},
        environment_layers=layers(tmp_path, VRAPTOR_REPORT_DETAILED_FINDINGS="bad"),
    )
    assert policy.detailed_findings == 6


@pytest.mark.parametrize("value", [0, -1, True, "max", "12"])
def test_reject_invalid_values(value):
    with pytest.raises(ValueError):
        reporting.ReportingPolicy(detailed_findings=value)


def test_unknown_policy_field_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown fields"):
        sources.normalize_document({"schema_version": 2, "reporting": {"other": 1}})


def test_scope_restores_after_failure():
    baseline = reporting.current_policy()
    with (
        pytest.raises(RuntimeError),
        reporting.reporting_scope(reporting.ReportingPolicy(detailed_findings=4)),
    ):
        assert reporting.current_policy().detailed_findings == 4
        raise RuntimeError("stop")
    assert reporting.current_policy() == baseline


def test_extract_options_respects_delimiter():
    args, values = reporting.extract_options(
        [
            "reports",
            "render",
            "--report-detailed-findings=4",
            "--",
            "--report-chat-chars",
            "5",
        ]
    )
    assert args == ["reports", "render", "--", "--report-chat-chars", "5"]
    assert values == {"detailed_findings": 4}


def test_operational_non_ai_commands_do_not_read_agent_config():
    with patch(
        "vraptor.agent.sources.load_document", side_effect=AssertionError("read config")
    ):
        for args in (
            ["setup", "init"],
            ["logs", "usage"],
            ["clients", "list"],
            ["analyze", "--help"],
        ):
            assert reporting.run_with_policy(args, lambda forwarded: forwarded) == args


def test_render_scope_requires_no_runner_or_credentials(tmp_path, monkeypatch):
    path = document(tmp_path, {"reporting": {"detailed_findings": 17}})
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch(
        "vraptor.agent.config.resolve_agent_execution",
        side_effect=AssertionError("model resolution"),
    ):
        result = reporting.run_with_policy(
            [
                "reports",
                "render",
                "--ai-config-file",
                str(path),
                "--report-examples-per-finding",
                "2",
            ],
            lambda args: (args, reporting.current_policy().as_dict()),
        )
    assert result[1]["detailed_findings"] == 17
    assert result[1]["examples_per_finding"] == 2
    assert "--report-examples-per-finding" not in result[0]


def test_reporting_does_not_change_execution_identity_and_doctor_exposes_source(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    path = document(tmp_path, {"reporting": {"detailed_findings": 17}})
    env = {"HOME": str(tmp_path)}
    with patch.dict("os.environ", env, clear=True):
        execution = resolve_agent_execution(
            cli_values={"config_file": str(path)},
            repo_root=tmp_path,
            process_environment=env,
            allow_missing_credentials=True,
        )
        changed = replace(execution.route, reporting_profile={"detailed_findings": 5})
        assert changed.identity() == execution.route.identity()
        payload = agent_configuration_payload(
            execution, limits.resolve_analysis_limits(execution=execution)
        )
        assert payload["reporting"]["effective"]["detailed_findings"] == 17
        assert (
            payload["reporting"]["sources"]["detailed_findings"]["kind"]
            == "execution_profile"
        )
        json.dumps(payload)
        assert (
            application_defaults_payload()["reporting"]["effective"][
                "detailed_findings"
            ]
            == 20
        )


@pytest.mark.parametrize(
    "profile",
    [
        {"max_input_tokens": "max", "max_output_tokens": "max"},
        {
            "max_input_tokens": "max",
            "max_output_tokens": "max",
            "model_context_tokens": 400000,
            "model_max_output_tokens": 64000,
        },
    ],
)
def test_max_token_config_resolves_to_selected_deployment(
    tmp_path, monkeypatch, profile
):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    path = document(tmp_path, profile)
    env = {"HOME": str(tmp_path)}
    with patch.dict("os.environ", env, clear=True):
        execution = resolve_agent_execution(
            cli_values={"config_file": str(path)},
            repo_root=tmp_path,
            process_environment=env,
            allow_missing_credentials=True,
        )
        budget = limits.resolve_analysis_limits(execution=execution).for_execution(
            execution
        )
    assert budget.maximum_output_tokens == profile.get(
        "model_max_output_tokens", 128000
    )
    assert budget.maximum_input_tokens == 272000


def test_max_token_unknown_model_requires_explicit_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    path = document(
        tmp_path, {"model": "unknown-deployment", "max_output_tokens": "max"}
    )
    env = {"HOME": str(tmp_path)}
    with patch.dict("os.environ", env, clear=True):
        execution = resolve_agent_execution(
            cli_values={"config_file": str(path)},
            repo_root=tmp_path,
            process_environment=env,
            allow_missing_credentials=True,
        )
        with pytest.raises(limits.AnalysisLimitsError, match="recognized model"):
            limits.resolve_analysis_limits(execution=execution)


def test_numeric_environment_supersedes_saved_max(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    path = document(tmp_path, {"max_output_tokens": "max"})
    env = {"HOME": str(tmp_path), "AI_SKILLS_MAX_OUTPUT_TOKENS": "64000"}
    with patch.dict("os.environ", env, clear=True):
        execution = resolve_agent_execution(
            cli_values={"config_file": str(path)},
            repo_root=tmp_path,
            process_environment=env,
            allow_missing_credentials=True,
        )
        budget = limits.resolve_analysis_limits(execution=execution).for_execution(
            execution
        )
    assert budget.maximum_output_tokens == 64000


def test_environment_max_and_numeric_cli_override(tmp_path, monkeypatch):
    import argparse

    from vraptor.analyze import model_options

    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    path = document(tmp_path, {"max_output_tokens": 32000})
    env = {"HOME": str(tmp_path), "AI_SKILLS_MAX_OUTPUT_TOKENS": "max"}
    with patch.dict("os.environ", env, clear=True):
        execution = resolve_agent_execution(
            cli_values={"config_file": str(path)},
            repo_root=tmp_path,
            process_environment=env,
            allow_missing_credentials=True,
        )
        assert (
            limits.resolve_analysis_limits(execution=execution).maximum_output_tokens
            == 128000
        )
        parser = argparse.ArgumentParser()
        model_options.add_arguments(parser)
        args = parser.parse_args(
            ["--ai-config-file", str(path), "--max-output-tokens", "64000"]
        )
        result, _ = model_options.resolve(args, allow_missing_credentials=True)
        assert (
            limits.resolve_analysis_limits(execution=result).maximum_output_tokens
            == 64000
        )


def test_delimiter_protects_config_selectors():
    _, values = reporting.extract_options(
        ["reports", "render", "--", "--ai-config-file", "not-a-config"]
    )
    assert values == {}


def test_selected_dotenv_beats_repository_and_shared(tmp_path):
    env = replace(
        layers(tmp_path, VRAPTOR_REPORT_DETAILED_FINDINGS=""),
        selected=EnvironmentLayer(
            "selected_dotenv", "case.env", {"VRAPTOR_REPORT_DETAILED_FINDINGS": "6"}
        ),
        repository=EnvironmentLayer(
            "repository_dotenv", "repo.env", {"VRAPTOR_REPORT_DETAILED_FINDINGS": "7"}
        ),
        shared=EnvironmentLayer(
            "shared_dotenv", "shared.env", {"VRAPTOR_REPORT_DETAILED_FINDINGS": "8"}
        ),
    )
    policy = reporting.resolve_reporting_policy(environment_layers=env)
    assert policy.detailed_findings == 6
    assert policy.sources["detailed_findings"]["kind"] == "selected_dotenv"


def test_doctor_payload_uses_invocation_overrides_without_reresolving(tmp_path):
    path = document(tmp_path)
    execution = resolve_agent_execution(
        cli_values={"config_file": str(path)},
        repo_root=tmp_path,
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    with (
        reporting.reporting_scope(reporting.ReportingPolicy(detailed_findings=4)),
        patch.object(
            reporting,
            "resolve_reporting_policy",
            side_effect=AssertionError("resolved twice"),
        ),
    ):
        payload = agent_configuration_payload(execution, limits.AnalysisLimits())
    assert payload["reporting"]["effective"]["detailed_findings"] == 4


def test_token_max_respects_explicit_environment_without_route(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    env = {
        "HOME": str(tmp_path),
        "AI_SKILLS_ANALYST_AGENT_PROVIDER": "openai",
        "AI_SKILLS_ANALYST_AGENT_MODEL": "gpt-6-luna",
        "AI_SKILLS_MAX_OUTPUT_TOKENS": "max",
    }
    budget = limits.resolve_analysis_limits(environment=env)
    assert budget.maximum_output_tokens == 128000


@pytest.mark.parametrize('field', ['chat_chars', 'compact_markdown_bytes'])
def test_publication_budgets_reserve_minimum_navigation(field):
    with pytest.raises(ValueError, match='at least 512'):
        reporting.ReportingPolicy(**{field: 511})
    assert reporting.ReportingPolicy(**{field: 512}).as_dict()[field] == 512


@pytest.mark.parametrize("command", [
    ["analyze"], ["summarize"], ["analysis-results"], ["reports", "render"],
    ["collect", "analyze"], ["hunt", "analyze"], ["hunt", "run"],
    ["hunt", "analyze-saved"],
])
def test_supported_report_routes_resolve_saved_policy_without_overrides(tmp_path, monkeypatch, command):
    path = document(tmp_path, {"reporting": {"detailed_findings": 7}})
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("AI_SKILLS_ANALYST_AGENT_CONFIG_FILE", str(path))
    with patch("vraptor.agent.config.resolve_agent_execution", side_effect=AssertionError("inference setup")):
        actual = reporting.run_with_policy(command, lambda args: reporting.current_policy().detailed_findings)
    assert actual == 7
    assert reporting.active_policy() is None


@pytest.mark.parametrize("command", [["hunt", "native", "review-results"], ["hunt", "status"]])
def test_query_only_hunt_routes_do_not_require_model_configuration(command):
    with patch("vraptor.agent.sources.load_document", side_effect=AssertionError("read config")):
        assert reporting.run_with_policy(command, lambda args: args) == command
