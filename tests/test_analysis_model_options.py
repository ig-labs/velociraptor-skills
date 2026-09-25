"""Run-only model overrides exercise real settings and limit resolvers offline."""

import argparse
import asyncio
from unittest import mock

import pytest

from vraptor import cli
from vraptor.agent import factory, manage
from vraptor.agent.config import resolve_agent_execution
from vraptor.analyze import command, limits, model_options
from vraptor.hunt import command as hunt


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    with mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True):
        yield


def configuration(tmp_path, **profile):
    path = tmp_path / "analyst-agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "profiles": {
                    "work": {
                        "provider": "anthropic",
                        "model": "claude-sonnet-5",
                        "max_input_tokens": 128000,
                        "max_output_tokens": 32000,
                        **profile,
                    }
                },
            }
        )
    )
    return path


def arguments(path, *flags):
    parser = argparse.ArgumentParser()
    model_options.add_arguments(parser)
    return parser.parse_args(["--ai-config-file", str(path), *flags])


def resolve(path, *flags):
    before = path.read_bytes()
    result = model_options.resolve(
        arguments(path, *flags),
        allow_missing_credentials=True,
        resolver=lambda **kw: resolve_agent_execution(repo_root=path.parent, **kw),
    )
    assert path.read_bytes() == before
    assert not path.with_suffix(".toml.bak").exists()
    return result


@pytest.mark.parametrize(
    "provider,model,output,input_tokens",
    [
        ("anthropic", "claude-sonnet-5", "max", 872000),
        ("anthropic", "claude-sonnet-5", "32000", 968000),
        ("anthropic", "claude-haiku-4-5-20251001", "max", 136000),
        ("anthropic", "haiku", "max", 136000),
        ("anthropic", "sonnet", "max", 872000),
        ("anthropic", "opus", "max", 872000),
        ("anthropic", "fable", "max", 872000),
        ("openai", "gpt-6-sol", "max", 272000),
    ],
)
def test_maximum_uses_selected_model_and_output(
    tmp_path, provider, model, output, input_tokens
):
    path = configuration(tmp_path, provider=provider, model=model)
    execution, result = resolve(
        path, "--max-input-tokens", "max", "--max-output-tokens", output
    )
    assert result.maximum_input_tokens == input_tokens
    expected_output = (
        32000 if output == "32000" else (64000 if "haiku" in model else 128000)
    )
    assert result.maximum_output_tokens == expected_output
    assert result.operational_context_tokens == input_tokens + expected_output
    assert result.for_execution(execution).as_dict() == result.as_dict()
    assert (
        limits.resolve_analysis_limits(execution=execution)
        .for_execution(execution)
        .as_dict()
        == result.as_dict()
    )
    assert result.provenance_dict()["maximum_input_tokens"]["kind"] == "cli"


def test_published_maximum_can_override_saved_deployment_caps(tmp_path):
    path = configuration(
        tmp_path, model_context_tokens=200000, model_max_output_tokens=32000
    )
    _, bounded = resolve(
        path, "--max-input-tokens", "max", "--max-output-tokens", "max"
    )
    assert bounded.maximum_input_tokens == 168000
    _, published = resolve(
        path,
        "--model-context-tokens",
        "max",
        "--model-max-output-tokens",
        "max",
        "--max-input-tokens",
        "max",
        "--max-output-tokens",
        "max",
    )
    assert published.maximum_input_tokens == 872000
    assert published.maximum_output_tokens == 128000


@pytest.mark.parametrize(
    "model,context,output",
    [
        ("haiku", 200000, 64000),
        ("sonnet", 1000000, 128000),
        ("opus", 1000000, 128000),
        ("fable", 1000000, 128000),
    ],
)
def test_alias_run_override_bounds_stale_saved_caps_without_mutation(
    tmp_path, model, context, output
):
    path = configuration(
        tmp_path, model_context_tokens=2000000, model_max_output_tokens=999990
    )
    execution, result = resolve(
        path,
        "--model",
        model,
        "--max-input-tokens",
        "max",
        "--max-output-tokens",
        "max",
    )
    assert execution.route.model == model
    assert result.model_context_tokens == context
    assert result.maximum_output_tokens == output
    assert result.maximum_input_tokens == context - output


@pytest.mark.parametrize("environment_input", ["110000", "2000000", "invalid"])
def test_cli_overrides_environment_for_downstream_resolution(
    tmp_path, monkeypatch, environment_input
):
    path = configuration(tmp_path)
    monkeypatch.setenv("AI_SKILLS_MAX_INPUT_TOKENS", environment_input)
    monkeypatch.setenv("AI_SKILLS_MAX_OUTPUT_TOKENS", "8000")
    monkeypatch.setenv("AI_SKILLS_CONTEXT_WINDOW_TOKENS", "200000")
    execution, result = resolve(
        path, "--max-input-tokens", "max", "--max-output-tokens", "max"
    )
    assert result.maximum_input_tokens == 872000
    assert result.maximum_output_tokens == 128000
    assert (
        limits.resolve_analysis_limits(execution=execution).as_dict()
        == result.as_dict()
    )


def test_route_overrides_are_run_only(tmp_path):
    path = configuration(tmp_path)
    execution, result = resolve(
        path,
        "--execution-profile",
        "work",
        "--model",
        "claude-haiku-4-5-20251001",
        "--reasoning-effort",
        "medium",
        "--max-input-tokens",
        "max",
    )
    assert execution.route.execution_profile == "work"
    assert execution.route.model == "claude-haiku-4-5-20251001"
    assert execution.route.reasoning_effort == ""
    assert execution.route.field_sources["reasoning_effort"].kind == "model_capability"
    assert result.maximum_input_tokens == 168000


@pytest.mark.parametrize("value", ["10", "99999", "872001"])
def test_input_range_rejects_out_of_bounds(tmp_path, value):
    path = configuration(tmp_path)
    with pytest.raises(ValueError, match="between 100000 and 872000"):
        resolve(path, "--max-input-tokens", value, "--max-output-tokens", "max")


def test_small_deployment_cannot_lower_minimums(tmp_path):
    path = configuration(
        tmp_path, model_context_tokens=64000, model_max_output_tokens=8000
    )
    with pytest.raises(ValueError, match="at least 100000 input and 32000 output"):
        resolve(path, "--max-input-tokens", "32000", "--max-output-tokens", "max")


@pytest.mark.parametrize(
    "provider,model",
    [
        ("anthropic", "haiku"),
        ("openai", "gpt-6-sol"),
        ("azure_openai", "gpt-6-sol"),
    ],
)
@pytest.mark.parametrize(
    "field,value", [("max-input-tokens", "99999"), ("max-output-tokens", "31999")]
)
def test_run_only_minimums_are_enforced(tmp_path, provider, model, field, value):
    path = configuration(
        tmp_path,
        provider=provider,
        model=model,
        **(
            {"base_url": "https://azure.test/openai/v1/"}
            if provider == "azure_openai"
            else {}
        ),
    )
    before = path.read_bytes()
    with pytest.raises(ValueError, match="must be between"):
        resolve(path, "--" + field, value)
    assert path.read_bytes() == before


def test_unknown_model_requires_declared_limits_for_max(tmp_path):
    path = configuration(tmp_path, model="private-model")
    with pytest.raises(ValueError, match="recognized model"):
        resolve(path, "--max-input-tokens", "max")
    _, result = resolve(
        path,
        "--model-context-tokens",
        "200000",
        "--model-max-output-tokens",
        "32000",
        "--max-input-tokens",
        "max",
        "--max-output-tokens",
        "max",
    )
    assert result.maximum_input_tokens == 168000


def test_host_hunt_and_autoruns_accept_same_options(tmp_path):
    path = configuration(tmp_path)
    flags = [
        "--ai-config-file",
        str(path),
        "--model",
        "claude-sonnet-5",
        "--max-input-tokens",
        "max",
    ]
    host_args = command.build_parser().parse_args(["--client-id", "C.test", *flags])
    hunt_args = hunt.parse_args(
        ["analyze", "--id", "test", "--hunt-id", "H.test", *flags]
    )
    assert host_args.max_input_tokens == hunt_args.max_input_tokens == "max"
    assert model_options.OPTIONS <= hunt.AUTORUNS_ALLOWED_OPTIONS
    assert (
        "AI model and token overrides (this run only)"
        in command.build_parser().format_help()
    )


def test_host_rejects_small_input_before_api(tmp_path):
    path = configuration(tmp_path)
    with mock.patch.object(
        command, "VeloApiClient", side_effect=AssertionError("API must not open")
    ):
        with pytest.raises(ValueError, match="between 100000"):
            asyncio.run(
                command.async_main(
                    [
                        "--ai-config-file",
                        str(path),
                        "--max-input-tokens",
                        "99999",
                        "--plan-only",
                        "--client-id",
                        "C.test",
                    ]
                )
            )


def test_hunt_rejects_small_input_before_api(tmp_path):
    path = configuration(tmp_path)
    args = hunt.parse_args(
        [
            "analyze",
            "--id",
            "test",
            "--hunt-id",
            "H.test",
            "--ai-config-file",
            str(path),
            "--max-input-tokens",
            "99999",
            "--skip-ai",
        ]
    )
    with mock.patch.object(
        hunt, "VeloApiClient", side_effect=AssertionError("API must not open")
    ):
        with pytest.raises(ValueError, match="between 100000"):
            hunt.command_analyze(args)


def test_canonical_help_lists_budget_options(capsys):
    assert cli.analyze(["--help"]) == 0
    display = capsys.readouterr().out
    assert "--max-input-tokens TOKENS|max" in display
    assert "AI model and token overrides (this run only)" in display


def test_snapshot_planning_receives_overrides(tmp_path):
    path = configuration(tmp_path)
    args = hunt.parse_args(
        [
            "analyze",
            "--snapshot",
            str(tmp_path / "snapshot.json"),
            "--ai-config-file",
            str(path),
            "--max-input-tokens",
            "max",
            "--max-output-tokens",
            "max",
        ]
    )
    with mock.patch.object(
        hunt, "command_analyze_snapshot", return_value={}
    ) as planner:
        hunt.command_analyze(args)
    assert planner.call_args.kwargs["resolved_limits"].maximum_input_tokens == 872000


def test_host_planning_receives_overrides(tmp_path):
    path = configuration(tmp_path)
    args = command.build_parser().parse_args(
        [
            "--client-id",
            "C.test",
            "--plan-only",
            "--ai-config-file",
            str(path),
            "--max-input-tokens",
            "max",
            "--max-output-tokens",
            "max",
        ]
    )

    class ReachedPlanner(Exception):
        pass

    def planner(*args, **kwargs):
        assert kwargs["limits"].maximum_input_tokens == 872000
        raise ReachedPlanner

    with (
        mock.patch.object(
            command, "resolve_collection", return_value=("test", {}, "reused")
        ),
        mock.patch.object(command, "build_workload", side_effect=planner),
        pytest.raises(ReachedPlanner),
    ):
        asyncio.run(
            command.run_analysis_async(
                mock.Mock(), args, policy=mock.Mock(), limits=limits.AnalysisLimits()
            )
        )


def test_runtime_admission_keeps_resolved_maximum(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only")
    path = configuration(tmp_path)
    execution, resolved = resolve(
        path, "--max-input-tokens", "max", "--max-output-tokens", "max"
    )
    with mock.patch.object(factory, "adapter_for", return_value=mock.Mock()):
        runner = factory.create_agent_runner(execution, persist_runtime_files=False)
    assert runner.limits.maximum_input_tokens == resolved.maximum_input_tokens == 872000
    assert (
        runner.limits.maximum_output_tokens == resolved.maximum_output_tokens == 128000
    )
