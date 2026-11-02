"""Run-only model overrides exercise real settings and limit resolvers offline."""

import argparse
import asyncio
import json
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
        # Haiku 5.5 (the haiku alias) caps max at its 100000 standard-price tier.
        ("anthropic", "claude-haiku-5-5", "max", 100000),
        ("anthropic", "haiku", "max", 100000),
        ("anthropic", "claude-sonnet-5-5", "max", 872000),
        ("anthropic", "sonnet", "max", 872000),
        ("anthropic", "opus", "max", 872000),
        ("anthropic", "fable", "max", 872000),
        ("openai", "gpt-6-sol", "max", 272000),
        ("openai", "gpt-6.1-sol", "max", 272000),
        ("openai", "gpt-6.1-terra", "max", 272000),
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
        32000 if output == "32000" else (64000 if "haiku-4-5" in model else 128000)
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
    "model,context,output,input_tokens",
    [
        ("haiku", 1000000, 128000, 100000),
        ("claude-haiku-4-5", 200000, 64000, 136000),
        ("sonnet", 1000000, 128000, 872000),
        ("opus", 1000000, 128000, 872000),
        ("fable", 1000000, 128000, 872000),
    ],
)
def test_alias_run_override_bounds_stale_saved_caps_without_mutation(
    tmp_path, model, context, output, input_tokens
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
    assert result.maximum_input_tokens == input_tokens


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


def test_haiku_alias_run_override_keeps_effort(tmp_path):
    path = configuration(tmp_path)
    execution, result = resolve(
        path, "--model", "haiku", "--reasoning-effort", "low", "--max-input-tokens", "max"
    )
    assert execution.route.model == "haiku"
    assert execution.route.reasoning_effort == "low"
    assert result.maximum_input_tokens == 100000


@pytest.mark.parametrize(
    "model,effort,levels",
    [
        ("claude-opus-4-6", "xhigh", "low, medium, high, max"),
        ("claude-opus-4-5", "max", "low, medium, high"),
    ],
)
def test_run_override_rejects_effort_outside_model_ladder(tmp_path, model, effort, levels):
    path = configuration(tmp_path)
    with pytest.raises(RuntimeError, match=f"supports reasoning effort {levels}$"):
        resolve(path, "--model", model, "--reasoning-effort", effort)


@pytest.mark.parametrize(
    "model,saved,expected",
    [
        ("claude-opus-4-6", "xhigh", "high"),
        ("claude-opus-4-6", "max", "max"),
        ("claude-opus-4-5", "max", "high"),
        ("claude-opus-5-5", "xhigh", "xhigh"),
    ],
)
def test_model_switch_lowers_inherited_effort_to_ladder(tmp_path, model, saved, expected):
    path = configuration(tmp_path, reasoning_effort=saved)
    execution, _ = resolve(path, "--model", model)
    assert execution.route.reasoning_effort == expected
    source = execution.route.field_sources["reasoning_effort"]
    assert (source.kind == "model_capability") == (saved != expected)


def test_claude_code_transport_keeps_effort_it_lowers_itself(tmp_path):
    path = configuration(
        tmp_path, transport="claude_agent_sdk", reasoning_effort="xhigh"
    )
    execution, _ = resolve(path, "--model", "claude-opus-4-6")
    assert execution.route.protocol == "claude_agent_sdk"
    assert execution.route.reasoning_effort == "xhigh"


@pytest.mark.parametrize(
    "transport,maximum", [("claude_agent_sdk", 168000), ("api", 968000)]
)
def test_claude_code_route_bounds_4_6_input_to_200k(tmp_path, transport, maximum):
    path = configuration(tmp_path, model="claude-opus-4-6", transport=transport)
    _, result = resolve(path, "--max-input-tokens", "max")
    assert result.maximum_input_tokens == maximum


@pytest.mark.parametrize("transport", ["claude_agent_sdk", "api"])
def test_disabled_1m_context_bounds_saved_claude_code_profile(tmp_path, transport):
    path = configuration(
        tmp_path,
        model="claude-opus-5-5",
        transport=transport,
        model_context_tokens=1000000,
        model_max_output_tokens=128000,
        max_input_tokens=872000,
        max_output_tokens=128000,
    )
    with mock.patch.dict("os.environ", {"CLAUDE_CODE_DISABLE_1M_CONTEXT": "true"}):
        execution = resolve_agent_execution(
            repo_root=path.parent,
            cli_values={"config_file": str(path)},
            allow_missing_credentials=True,
        )
        bounded = limits.resolve_analysis_limits(
            {}, execution=execution
        ).for_execution(execution)
        _, result = resolve(path, "--model-context-tokens", "max")
    sdk = transport == "claude_agent_sdk"
    route = execution.route
    assert route.claude_code_1m_context is not sdk
    assert route.model_context_tokens == (200000 if sdk else 1000000)
    if sdk:
        source = route.field_sources["model_context_tokens"]
        assert source.name == "CLAUDE_CODE_DISABLE_1M_CONTEXT"
        assert result.maximum_input_tokens + result.maximum_output_tokens <= 200000
        # Saved 1M budgets are refitted to the 200K reference defaults.
        assert (bounded.maximum_input_tokens, bounded.maximum_output_tokens) == (
            120000,
            64000,
        )
        assert bounded.field_sources["maximum_input_tokens"].name == source.name
    else:
        assert result.maximum_input_tokens == 872000


DISABLE_1M = {"CLAUDE_CODE_DISABLE_1M_CONTEXT": "1"}


def claude_code_document(tmp_path, drop=(), **profile):
    path = tmp_path / "analyst-agents.toml"
    work = {
        "provider": "anthropic",
        "model": "claude-opus-5-5",
        "transport": "claude_agent_sdk",
        "model_context_tokens": 1000000,
        "model_max_output_tokens": 128000,
        **profile,
    }
    for name in drop:
        work.pop(name)
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "profiles": {"work": work},
            }
        )
    )
    return path


def default_path_limits(path):
    # Host and hunt analysis resolve limits without an execution first.
    with mock.patch.dict(
        "os.environ", {"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path)}
    ):
        execution = resolve_agent_execution(
            repo_root=path.parent, allow_missing_credentials=True
        )
        unbound = limits.resolve_analysis_limits()
    return execution, unbound.for_execution(execution)


@pytest.mark.parametrize(
    "profile,expected",
    [
        ({"max_input_tokens": 872000, "max_output_tokens": 128000}, (120000, 64000)),
        # Only one saved field; the other keeps the application default.
        ({"max_input_tokens": 872000}, (120000, 64000)),
        # "max" fills the room the refitted partner leaves.
        ({"max_input_tokens": 872000, "max_output_tokens": "max"}, (120000, 80000)),
        ({"max_input_tokens": "max", "max_output_tokens": 128000}, (136000, 64000)),
        ({"max_input_tokens": 150000, "max_output_tokens": 40000}, (150000, 40000)),
    ],
)
@pytest.mark.parametrize("path_kind", ["default", "execution"])
def test_disabled_1m_context_refits_saved_budgets_on_every_path(
    tmp_path, profile, expected, path_kind
):
    path = claude_code_document(tmp_path, **profile)
    with mock.patch.dict("os.environ", DISABLE_1M):
        if path_kind == "default":
            execution, bounded = default_path_limits(path)
        else:
            execution = resolve_agent_execution(
                repo_root=path.parent,
                cli_values={"config_file": str(path)},
                allow_missing_credentials=True,
            )
            bounded = limits.resolve_analysis_limits(
                {}, execution=execution
            ).for_execution(execution)
    assert execution.route.model_context_tokens == 200000
    assert execution.route.model_max_output_tokens == 100000
    assert (bounded.maximum_input_tokens, bounded.maximum_output_tokens) == expected
    # Idempotent: the runner bounds the planned limits again.
    again = bounded.for_execution(execution)
    assert (again.maximum_input_tokens, again.maximum_output_tokens) == expected


def test_disabled_1m_context_keeps_usable_output_without_saved_budgets(tmp_path):
    path = claude_code_document(tmp_path)
    with mock.patch.dict("os.environ", DISABLE_1M):
        execution, bounded = default_path_limits(path)
    assert not execution.route.analysis_profile
    assert bounded.model_context_tokens == 200000
    assert bounded.maximum_output_tokens > 32000
    assert bounded.maximum_input_tokens + bounded.maximum_output_tokens <= 200000


def test_disabled_1m_context_refits_saved_partner_of_cli_budget(tmp_path):
    path = claude_code_document(tmp_path, max_input_tokens=872000, max_output_tokens=128000)
    with mock.patch.dict("os.environ", DISABLE_1M):
        _, result = resolve(path, "--max-input-tokens", "120000")
    assert (result.maximum_input_tokens, result.maximum_output_tokens) == (120000, 64000)


def test_disabled_1m_context_bounds_environment_budgets_as_any_model(tmp_path):
    path = claude_code_document(tmp_path, max_input_tokens=120000, max_output_tokens=64000)
    environment = {**DISABLE_1M, "AI_SKILLS_MAX_INPUT_TOKENS": "872000"}
    with mock.patch.dict("os.environ", environment):
        _, bounded = default_path_limits(path)
    # Not refitted as a saved budget: the shared model-envelope bound narrows it.
    source = bounded.field_sources["maximum_input_tokens"]
    assert (source.kind, source.name) == ("model_envelope", "maximum_input_tokens")
    assert bounded.maximum_input_tokens + bounded.maximum_output_tokens <= 200000


def test_disabled_1m_context_bounds_unlisted_model_overrides(tmp_path):
    path = claude_code_document(tmp_path, model="custom-claude")
    with mock.patch.dict("os.environ", DISABLE_1M):
        with pytest.raises(ValueError, match="exceeds model maximum 200000"):
            resolve(path, "--model-context-tokens", "1000000")
        _, result = resolve(path, "--model-context-tokens", "max")
    assert result.model_context_tokens == 200000


@pytest.mark.parametrize(
    "managed,process,enabled",
    [("1", None, False), ("0", "1", True), (None, "1", False), (None, None, True)],
)
def test_claude_managed_settings_override_the_environment(
    tmp_path, monkeypatch, managed, process, enabled
):
    from vraptor.agent import sources

    directory = tmp_path / "managed"
    monkeypatch.setattr(sources, "DEFAULT_CLAUDE_MANAGED_SETTINGS_DIR", directory)
    if managed is not None:
        directory.mkdir()
        (directory / "managed-settings.json").write_text(
            json.dumps({"env": {"CLAUDE_CODE_DISABLE_1M_CONTEXT": managed}})
        )
    path = claude_code_document(tmp_path)
    environment = {"CLAUDE_CODE_DISABLE_1M_CONTEXT": process} if process else {}
    with mock.patch.dict("os.environ", environment):
        route = resolve_agent_execution(
            repo_root=path.parent,
            cli_values={"config_file": str(path)},
            allow_missing_credentials=True,
        ).route
    assert route.claude_code_1m_context is enabled
    source = route.field_sources["claude_code_1m_context"]
    assert source.kind == (
        "claude_managed_settings" if managed is not None else source.kind
    )
    assert route.model_context_tokens == (1000000 if enabled else 200000)


def test_claude_managed_settings_ignore_hidden_drop_ins(tmp_path, monkeypatch):
    from vraptor.agent import sources

    directory = tmp_path / "managed"
    (directory / "managed-settings.d").mkdir(parents=True)
    for name, value in (
        ("managed-settings.json", "1"),
        ("managed-settings.d/.99-hidden.json", "0"),
    ):
        (directory / name).write_text(
            json.dumps({"env": {"CLAUDE_CODE_DISABLE_1M_CONTEXT": value}})
        )
    monkeypatch.setattr(sources, "DEFAULT_CLAUDE_MANAGED_SETTINGS_DIR", directory)
    value, location = sources.claude_managed_env("CLAUDE_CODE_DISABLE_1M_CONTEXT")
    assert (value, location) == ("1", str(directory / "managed-settings.json"))


def test_disabled_1m_context_refits_saved_budgets_for_planning(tmp_path):
    # Plan-only, skip-ai and snapshot preparation never call for_execution.
    path = claude_code_document(tmp_path, max_input_tokens=872000, max_output_tokens=128000)
    environment = {**DISABLE_1M, "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path)}
    with mock.patch.dict("os.environ", environment):
        planned = limits.resolve_analysis_limits()
    assert (planned.maximum_input_tokens, planned.maximum_output_tokens) == (120000, 64000)
    assert planned.operational_context_tokens == 184000
    with mock.patch.dict("os.environ", {"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path)}):
        planned = limits.resolve_analysis_limits()
    assert (planned.maximum_input_tokens, planned.maximum_output_tokens) == (872000, 128000)


def test_disabled_1m_context_narrows_environment_reserves_of_refitted_pair(tmp_path):
    path = claude_code_document(tmp_path, max_input_tokens=872000, max_output_tokens=128000)
    with mock.patch.dict("os.environ", DISABLE_1M):
        execution = resolve_agent_execution(
            repo_root=path.parent,
            cli_values={"config_file": str(path)},
            allow_missing_credentials=True,
        )
    resolved = limits.resolve_analysis_limits(
        {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "200000"}, execution=execution
    )
    assert resolved.maximum_input_tokens == 120000
    assert resolved.maximum_evidence_tokens_per_item < 120000
    source = resolved.field_sources["maximum_evidence_tokens_per_item"]
    assert (source.kind, source.name) == ("model_envelope", "CLAUDE_CODE_DISABLE_1M_CONTEXT")


def test_disabled_1m_context_keeps_explicit_small_context_without_output_cap(tmp_path):
    path = claude_code_document(
        tmp_path,
        drop=("model_max_output_tokens",),
        model="claude-haiku-4-5",
        model_context_tokens=96000,
        max_input_tokens=64000,
        max_output_tokens=16000,
    )
    with mock.patch.dict("os.environ", DISABLE_1M):
        execution, bounded = default_path_limits(path)
    assert (execution.route.model_context_tokens, execution.route.model_max_output_tokens) == (96000, 0)
    assert (bounded.maximum_input_tokens, bounded.maximum_output_tokens) == (64000, 16000)


def test_max_output_reserves_minimum_input_while_1m_context_is_enabled(tmp_path):
    # The saved input is not reserved: an override model narrows it instead.
    path = claude_code_document(
        tmp_path, transport="api", max_input_tokens=872000, max_output_tokens="max"
    )
    _, result = resolve(path, "--model", "claude-haiku-4-5")
    assert (result.maximum_input_tokens, result.maximum_output_tokens) == (136000, 64000)


def test_haiku_5_5_input_cannot_exceed_standard_price_tier(tmp_path):
    path = configuration(tmp_path, model="claude-haiku-5-5")
    with pytest.raises(ValueError, match="between 100000 and 100000"):
        resolve(path, "--max-input-tokens", "100001", "--max-output-tokens", "max")


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
