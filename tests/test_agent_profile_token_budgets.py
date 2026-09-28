"""Profile budget resolution and setup integration, with no external services."""

import asyncio
import json
from unittest import mock

import pytest
from vraptor.agent import command, factory, manage, sources
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.runtime import AgentRequest, ProviderCapabilities, ProviderResponse
from vraptor.analyze import limits
from vraptor.paths import repository_environment


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(limits, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(manage.os, "isatty", lambda _: False)
    with mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True):
        yield


def setup(path, provider="openai", *flags):
    azure = (
        ["--base-url", "https://azure.test/openai/v1/"]
        if provider == "azure_openai"
        else []
    )
    return manage.setup(
        manage.parser_for("setup").parse_args(
            [
                "--config-file",
                str(path),
                "--provider",
                provider,
                *azure,
                *flags,
            ]
        )
    )


def resolve(path, **cli):
    return resolve_agent_execution(
        repo_root=path.parent,
        cli_values={"config_file": str(path), **cli},
        process_environment={"HOME": str(path.parent), "OPENAI_API_KEY": "test-only"},
        allow_missing_credentials=True,
    )


def document(path, profile=None, defaults=None):
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "analysis_defaults": defaults or {},
                "profiles": {
                    "work": {"provider": "openai", "model": "test", **(profile or {})}
                },
            }
        )
    )
    return path


@pytest.mark.parametrize("provider", ["openai", "azure_openai"])
@pytest.mark.parametrize("context", [None, 400000])
def test_new_defaults_reach_resolver_and_setup_report(tmp_path, provider, context):
    path = tmp_path / "agents.toml"
    flags = ["--model-context-tokens", str(context)] if context else []
    report = setup(path, provider, *flags)
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits({}, execution=selected).for_execution(
        selected
    )
    assert resolved.maximum_input_tokens == 272000
    assert resolved.maximum_output_tokens == 128000
    assert resolved.operational_context_tokens == 400000
    assert resolved.maximum_evidence_tokens_per_item == 200000
    assert report["analysis_limits"]["effective"] == resolved.as_dict()
    assert report["analysis_limits"]["sources"]["maximum_input_tokens"][
        "location"
    ] == str(path)
    assert (
        resolved.provenance_dict()["maximum_output_tokens"]["kind"]
        == "execution_profile"
    )
    assert (
        resolved.provenance_dict()["operational_context_tokens"]["kind"]
        == "derived_profile_budget"
    )


def test_interactive_pair_is_saved_and_reused(tmp_path, capsys):
    path = tmp_path / "agents.toml"

    def answer(prompt):
        if prompt.startswith("Maximum input tokens"):
            return "100000"
        if prompt.startswith("Maximum output tokens"):
            return "32000"
        return ""

    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", side_effect=answer),
    ):
        report = setup(path)
    assert "\nAnalysis token budgets\n" in capsys.readouterr().err
    effective = report["analysis_limits"]["effective"]
    assert effective["operational_context_tokens"] == 132000
    assert effective["maximum_evidence_tokens_per_item"] == 70000
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompt,
    ):
        again = setup(path, "openai", "--no-auto-token-budgets")
    assert again["analysis_limits"]["effective"] == effective
    assert "Maximum input tokens [100000] (Enter to keep): " in [
        c.args[0] for c in prompt.call_args_list
    ]
    assert "Maximum output tokens [32000] (Enter to keep): " in [
        c.args[0] for c in prompt.call_args_list
    ]
    output = capsys.readouterr().err
    assert (
        "Maximum input tokens: keeping 100000; model reference default is 272000."
        in output
    )
    assert (
        "Maximum output tokens: keeping 32000; model reference default is 128000."
        in output
    )
    assert "Standard-price input ceiling: 272,000" in output
    assert "Maximum model output: 128,000" in output


@pytest.mark.parametrize(
    "provider,model,input_tokens,output_tokens",
    [
        ("openai", "gpt-6-astra", 272000, 128000),
        ("openai", "gpt-6-sol", 272000, 128000),
        ("openai", "gpt-6-luna", 272000, 128000),
        ("openai", "gpt-5.6-sol", 272000, 128000),
        ("openai", "gpt-5.6-terra", 272000, 128000),
        ("openai", "gpt-5.6-luna", 272000, 128000),
        ("azure_openai", "gpt-6-sol", 272000, 128000),
        ("anthropic", "claude-sonnet-5", 872000, 128000),
        ("anthropic", "claude-opus-5-5", 872000, 128000),
        ("anthropic", "claude-fable-5-1", 872000, 128000),
        ("anthropic", "claude-haiku-4-5-20251001", 120000, 64000),
    ],
)
def test_selected_model_defaults_reach_real_resolver(
    tmp_path, capsys, provider, model, input_tokens, output_tokens
):
    path = tmp_path / "agents.toml"
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompt,
    ):
        report = setup(path, provider, "--model", model)
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_input_tokens"] == input_tokens
    assert effective["maximum_output_tokens"] == output_tokens
    assert effective["operational_context_tokens"] == input_tokens + output_tokens
    assert f"Maximum input tokens [{input_tokens}] (Enter to keep): " in [
        c.args[0] for c in prompt.call_args_list
    ]
    assert f"Maximum output tokens [{output_tokens}] (Enter to keep): " in [
        c.args[0] for c in prompt.call_args_list
    ]
    assert report["model_token_reference"]["model"] == model
    assert report["model_token_reference"]["known"] is True
    assert "Reference defaults:" in capsys.readouterr().err
    # Re-running does not inflate the budget, change its model cap, or lose it.
    assert setup(path, provider)["analysis_limits"]["effective"] == effective


@pytest.mark.parametrize(
    "provider,model",
    [
        ("azure_openai", "my-gpt-6-sol-deployment"),
        ("openai", "gpt-6-sol-future"),
        ("anthropic", "custom-claude"),
    ],
)
def test_unknown_models_do_not_claim_verified_limits(tmp_path, capsys, provider, model):
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value=""),
    ):
        report = setup(tmp_path / "agents.toml", provider, "--model", model)
    assert report["model_token_reference"] == {"model": model, "known": False}
    assert "Model limits/pricing unverified" in capsys.readouterr().err


@pytest.mark.parametrize("model", ["haiku", "sonnet", "opus", "fable"])
@pytest.mark.parametrize("saved", [False, True])
def test_claude_alias_wizard_uses_bounded_reference(tmp_path, capsys, model, saved):
    native = tmp_path / "claude.json"
    native.write_text(json.dumps({"model": model, "effortLevel": "medium"}))
    path = tmp_path / "agents.toml"
    if saved:
        path.write_text(
            manage._toml(
                {
                    "schema_version": 2,
                    "selection": {"default_profile": "claude_code"},
                    "profiles": {
                        "claude_code": {
                            "source": {"kind": "claude_code", "path": str(native)},
                            "model": model,
                            "model_context_tokens": 1000000,
                            "model_max_output_tokens": 999990,
                            "max_input_tokens": 872000,
                            "max_output_tokens": 128000,
                            "reasoning_effort": "medium",
                        }
                    },
                }
            )
        )
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value=""),
    ):
        report = manage.setup(
            manage.parser_for("setup").parse_args(
                [
                    "--config-file",
                    str(path),
                    "--from-harness",
                    "claude_code",
                    "--harness-config",
                    str(native),
                    "--execution-profile",
                    "claude_code",
                ]
            )
        )
    haiku = model == "haiku"
    effective = report["analysis_limits"]["effective"]
    assert effective["model_context_tokens"] == (200000 if haiku else 1000000)
    assert effective["maximum_input_tokens"] == (120000 if haiku else 872000)
    assert effective["maximum_output_tokens"] == (64000 if haiku else 128000)
    profile = sources.read_config(path)["profiles"]["claude_code"]
    assert profile["model_max_output_tokens"] == (64000 if haiku else 128000)
    if haiku:
        assert "reasoning_effort" not in profile
        assert resolve(path).route.reasoning_effort == ""
    assert report["model_token_reference"]["model"] == model
    assert report["model_token_reference"]["alias_reference_model"].startswith(
        "claude-"
    )
    display = capsys.readouterr().err
    assert "Default alias budget reference:" in display
    assert "Model limits/pricing unverified" not in display
    assert "999,990" not in display


@pytest.mark.parametrize("model", ["haiku", "sonnet", "opus", "fable"])
def test_claude_alias_interactive_max_respects_output_cap(tmp_path, model):
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=lambda prompt: (
                "max" if prompt.startswith("Maximum output tokens") else ""
            ),
        ),
    ):
        report = setup(tmp_path / "agents.toml", "anthropic", "--model", model)
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_output_tokens"] == (64000 if model == "haiku" else 128000)
    assert effective["maximum_input_tokens"] == (120000 if model == "haiku" else 872000)


@pytest.mark.parametrize("model", ["haiku", "sonnet", "opus", "fable"])
def test_claude_alias_keeps_smaller_explicit_budgets(tmp_path, model):
    path = tmp_path / "agents.toml"
    setup(
        path,
        "anthropic",
        "--model",
        model,
        "--model-context-tokens",
        "160000",
        "--model-max-output-tokens",
        "32000",
        "--max-input-tokens",
        "120000",
        "--max-output-tokens",
        "32000",
    )
    report = setup(path, "anthropic", "--no-auto-token-budgets")
    effective = report["analysis_limits"]["effective"]
    assert effective["model_context_tokens"] == 160000
    assert effective["maximum_input_tokens"] == 120000
    assert effective["maximum_output_tokens"] == 32000
    assert report["token_budget_maxima"]["max_output_tokens"] == 32000


@pytest.mark.parametrize(
    "model,maximum",
    [
        ("haiku", 64000),
        ("sonnet", 128000),
        ("opus", 128000),
        ("fable", 128000),
    ],
)
def test_claude_alias_rejects_excessive_explicit_output_without_writing(
    tmp_path, model, maximum
):
    path = tmp_path / "agents.toml"
    setup(path, "anthropic", "--model", model)
    original = path.read_bytes()
    with pytest.raises(RuntimeError, match="Maximum output tokens must be between"):
        setup(path, "anthropic", "--max-output-tokens", str(maximum + 1))
    assert path.read_bytes() == original


def test_haiku_setup_rejects_explicit_effort_before_writing(tmp_path):
    path = tmp_path / "agents.toml"
    with pytest.raises(RuntimeError, match="Haiku does not support"):
        setup(path, "anthropic", "--model", "haiku", "--reasoning-effort", "medium")
    assert not path.exists()


@pytest.mark.parametrize(
    "provider,model",
    [
        ("anthropic", "haiku"),
        ("anthropic", "sonnet"),
        ("anthropic", "opus"),
        ("anthropic", "fable"),
        ("openai", "gpt-6-sol"),
        ("azure_openai", "gpt-6-sol"),
    ],
)
@pytest.mark.parametrize(
    "field,value", [("max-input-tokens", "99999"), ("max-output-tokens", "31999")]
)
def test_setup_rejects_below_minimum_without_changing_profile(
    tmp_path, provider, model, field, value
):
    path = tmp_path / "agents.toml"
    setup(path, provider, "--model", model)
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="must be between"):
        setup(path, provider, "--" + field, value)
    assert path.read_bytes() == before


@pytest.mark.parametrize("provider", ["anthropic", "openai", "azure_openai"])
def test_setup_minimum_pair_is_valid(tmp_path, provider):
    report = setup(
        tmp_path / "agents.toml",
        provider,
        "--model",
        "custom-model",
        "--model-context-tokens",
        "132000",
        "--max-input-tokens",
        "100000",
        "--max-output-tokens",
        "32000",
    )
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_input_tokens"] == 100000
    assert effective["maximum_output_tokens"] == 32000


def test_interactive_output_minimum_reprompts_and_haiku_input_max_is_available(
    tmp_path, capsys
):
    outputs = iter(["31999", "64000"])

    def answer(prompt):
        if prompt.startswith("Maximum output tokens"):
            return next(outputs)
        if prompt.startswith("Maximum input tokens"):
            return "max"
        return ""

    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", side_effect=answer),
    ):
        report = setup(tmp_path / "agents.toml", "anthropic", "--model", "haiku")
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_input_tokens"] == 136000
    assert effective["maximum_output_tokens"] == 64000
    assert "Enter at least 32000 tokens" in capsys.readouterr().err


@pytest.mark.parametrize("model", ["sonnet", "opus", "fable"])
def test_switching_claude_alias_to_haiku_clears_stale_limits_and_effort(
    tmp_path, model
):
    path = tmp_path / "agents.toml"
    setup(path, "anthropic", "--model", model)
    report = setup(path, "anthropic", "--model", "haiku")
    effective = report["analysis_limits"]["effective"]
    assert effective["model_context_tokens"] == 200000
    assert effective["maximum_output_tokens"] == 64000
    assert effective["maximum_input_tokens"] == 120000
    profile = sources.read_config(path)["profiles"]["anthropic"]
    assert profile["model"] == "haiku"
    assert "reasoning_effort" not in profile


def test_haiku_recommendation_is_separate_from_model_maximum(tmp_path, capsys):
    path = tmp_path / "agents.toml"
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value=""),
    ):
        report = setup(path, "anthropic", "--model", "claude-haiku-4-5-20251001")
    display = capsys.readouterr().err
    assert "Maximum model output: 64,000 tokens" in display
    assert "Reference defaults: 120,000 input / 64,000 output" in display
    assert report["model_token_reference"]["max_output_tokens"] == 64000
    assert report["model_token_reference"]["default_output_tokens"] == 64000
    # The configured default leaves headroom; an explicit input may use all
    # remaining context when output is at its model maximum.
    report = setup(
        path,
        "anthropic",
        "--max-output-tokens",
        "64000",
        "--max-input-tokens",
        "136000",
    )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 136000
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 64000


def test_haiku_preserves_smaller_saved_output_budget(tmp_path):
    path = tmp_path / "agents.toml"
    setup(
        path,
        "anthropic",
        "--model",
        "claude-haiku-4-5-20251001",
        "--max-output-tokens",
        "32000",
    )
    report = setup(path, "anthropic", "--no-auto-token-budgets")
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 32000


@pytest.mark.parametrize(
    "harness,model",
    [
        ("codex", "gpt-6-sol"),
        ("claude_code", "claude-sonnet-5"),
    ],
)
def test_inherited_harness_model_drives_budget_without_pinning(
    tmp_path, harness, model
):
    native = tmp_path / ("native.json" if harness == "claude_code" else "native.toml")
    native.write_text(
        json.dumps({"model": model})
        if harness == "claude_code"
        else f'model = "{model}"\n'
    )
    path = tmp_path / "agents.toml"
    report = manage.setup(
        manage.parser_for("setup").parse_args(
            [
                "--config-file",
                str(path),
                "--from-harness",
                harness,
                "--harness-config",
                str(native),
            ]
        )
    )
    assert report["model_token_reference"]["model"] == model
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 128000
    assert "model" not in sources.read_config(path)["profiles"][harness]


def test_saved_shared_budgets_win_over_model_defaults_for_new_profile(tmp_path):
    path = document(
        tmp_path / "agents.toml",
        defaults={"max_input_tokens": 100000, "max_output_tokens": 32000},
    )
    report = setup(
        path,
        "anthropic",
        "--no-auto-token-budgets",
        "--profile-name",
        "claude",
        "--model",
        "claude-sonnet-5",
    )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 100000
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 32000
    assert report["model_token_reference"]["max_input_tokens"] == 872000


def test_explicit_budgets_and_smaller_model_caps_win(tmp_path):
    path = tmp_path / "agents.toml"
    report = setup(
        path,
        "anthropic",
        "--model",
        "claude-sonnet-5",
        "--model-context-tokens",
        "200000",
        "--model-max-output-tokens",
        "64000",
        "--max-input-tokens",
        "100000",
        "--max-output-tokens",
        "32000",
    )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 100000
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 32000
    assert (
        sources.read_config(path)["profiles"]["anthropic"]["model_context_tokens"]
        == 200000
    )


def test_smaller_context_reserves_model_maximum_output_first(tmp_path):
    report = setup(
        tmp_path / "agents.toml",
        "anthropic",
        "--model",
        "claude-sonnet-5",
        "--model-context-tokens",
        "200000",
    )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 100000
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 100000


def test_setup_cli_reports_reference_and_retains_explicit_budget(tmp_path, capsys):
    path = tmp_path / "agents.toml"
    assert (
        manage.main(
            "setup",
            [
                "--config-file",
                str(path),
                "--provider",
                "openai",
                "--model",
                "gpt-6-sol",
                "--max-input-tokens",
                "100000",
                "--max-output-tokens",
                "32000",
            ],
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["model_token_reference"]["max_input_tokens"] == 272000
    assert report["model_token_reference"]["max_output_tokens"] == 128000
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 100000
    assert resolve(path).route.analysis_profile["max_output_tokens"] == 32000


def test_legacy_profile_inherits_saved_shared_values_until_edited(tmp_path):
    path = document(tmp_path / "agents.toml", defaults={"max_output_tokens": 48000})
    before = limits.resolve_analysis_limits({}, execution=resolve(path))
    assert before.maximum_output_tokens == 48000
    assert before.operational_context_tokens == 360000
    report = setup(path)
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 48000
    assert sources.read_config(path)["analysis_defaults"]["max_output_tokens"] == 48000


def test_named_profiles_and_environment_precedence(tmp_path):
    path = tmp_path / "agents.toml"
    setup(path)
    setup(
        path,
        "azure_openai",
        "--profile-name",
        "small",
        "--max-input-tokens",
        "100000",
        "--max-output-tokens",
        "32000",
    )
    assert resolve(path).route.execution_profile == "openai"
    small = resolve(path, execution_profile="small")
    baseline = limits.resolve_analysis_limits({}, execution=small)
    assert baseline.maximum_output_tokens == 32000
    overridden = limits.resolve_analysis_limits(
        {
            "AI_SKILLS_MAX_INPUT_TOKENS": "60000",
            "AI_SKILLS_MAX_OUTPUT_TOKENS": "4000",
        },
        execution=small,
    )
    assert overridden.maximum_input_tokens == 60000
    assert overridden.maximum_output_tokens == 4000
    assert overridden.operational_context_tokens == 64000
    assert (
        overridden.provenance_dict()["maximum_output_tokens"]["kind"] == "environment"
    )
    layers = repository_environment(
        tmp_path,
        process_environment={
            "HOME": str(tmp_path),
            "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path),
            "AI_SKILLS_ANALYST_AGENT_PROFILE": "small",
        },
    )
    assert (
        limits.resolve_analysis_limits(environment_layers=layers).as_dict()
        == baseline.as_dict()
    )


def test_explicit_environment_context_and_evidence_are_preserved(tmp_path):
    path = document(
        tmp_path / "agents.toml", {"max_input_tokens": 64000, "max_output_tokens": 8000}
    )
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits(
        {
            "AI_SKILLS_CONTEXT_WINDOW_TOKENS": "80000",
            "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "20000",
        },
        execution=selected,
    )
    assert resolved.operational_context_tokens == 80000
    assert resolved.maximum_evidence_tokens_per_item == 20000
    with pytest.raises(limits.AnalysisLimitsError, match="exceed operational"):
        limits.resolve_analysis_limits(
            {"AI_SKILLS_CONTEXT_WINDOW_TOKENS": "70000"}, execution=selected
        )


def test_snapshot_is_immutable_and_budget_changes_route_identity(tmp_path):
    path = tmp_path / "agents.toml"
    setup(path)
    first = resolve(path)
    setup(path, "openai", "--max-output-tokens", "64000")
    second = resolve(path)
    assert first.route.identity() != second.route.identity()
    path.unlink()
    with mock.patch.object(
        sources, "read_config", side_effect=AssertionError("unexpected reread")
    ):
        assert (
            limits.resolve_analysis_limits({}, execution=first).maximum_output_tokens
            == 128000
        )
    with pytest.raises(TypeError):
        first.route.analysis_profile["max_output_tokens"] = 1


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_model_caps_apply_and_reapplication_is_stable(tmp_path, provider):
    path = document(
        tmp_path / "agents.toml",
        {
            "provider": provider,
            "model_context_tokens": 100000,
            "model_max_output_tokens": 4000,
            "max_input_tokens": 80000,
            "max_output_tokens": 8000,
        },
    )
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits({}, execution=selected).for_execution(
        selected
    )
    assert resolved.maximum_output_tokens == 4000
    assert resolved.maximum_input_tokens == 80000
    assert resolved.for_execution(selected).as_dict() == resolved.as_dict()


def test_smaller_deployment_context_tightens_saved_pair(tmp_path):
    path = document(
        tmp_path / "agents.toml",
        {
            "model_context_tokens": 256000,
            "model_max_output_tokens": 32000,
            "max_input_tokens": 272000,
            "max_output_tokens": 128000,
        },
    )
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits({}, execution=selected).for_execution(
        selected
    )
    assert resolved.model_context_tokens == 256000
    assert resolved.operational_context_tokens == 256000
    assert resolved.maximum_input_tokens == 224000
    assert resolved.maximum_output_tokens == 32000
    assert resolved.maximum_evidence_tokens_per_item == 169600
    assert (
        resolved.provenance_dict()["maximum_output_tokens"]["kind"] == "model_envelope"
    )


def test_dotenv_overrides_profile_without_importing_harness(tmp_path):
    path = document(
        tmp_path / "agents.toml",
        {"max_input_tokens": 272000, "max_output_tokens": 128000},
    )
    (tmp_path / ".env").write_text(
        "AI_SKILLS_MAX_INPUT_TOKENS=260000\nAI_SKILLS_MAX_OUTPUT_TOKENS=64000\n"
    )
    layers = repository_environment(
        tmp_path,
        process_environment={
            "HOME": str(tmp_path),
            "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE": str(path),
        },
    )
    resolved = limits.resolve_analysis_limits(environment_layers=layers)
    assert resolved.operational_context_tokens == 324000
    assert resolved.maximum_output_tokens == 64000
    assert (
        resolved.provenance_dict()["maximum_input_tokens"]["kind"]
        == "repository_dotenv"
    )


def test_small_model_without_output_ceiling_preserves_input_space(tmp_path):
    path = document(
        tmp_path / "agents.toml",
        {
            "model_context_tokens": 100000,
            "max_input_tokens": 272000,
            "max_output_tokens": 128000,
        },
    )
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits({}, execution=selected).for_execution(
        selected
    )
    assert resolved.maximum_output_tokens == 32000
    assert resolved.maximum_input_tokens == 68000
    assert resolved.for_execution(selected).as_dict() == resolved.as_dict()


@pytest.mark.parametrize("key", ["max_input_tokens", "max_output_tokens"])
@pytest.mark.parametrize("value", [0, -1, True, "128000"])
def test_profile_schema_rejects_invalid_budgets(key, value):
    with pytest.raises(RuntimeError):
        sources.normalize_document(
            {"schema_version": 2, "profiles": {"work": {key: value}}}
        )


def test_invalid_pair_does_not_replace_config_or_backup(tmp_path):
    path = tmp_path / "agents.toml"
    setup(path)
    original = path.read_bytes()
    backup = path.with_suffix(".toml.bak")
    backup.write_text("preserve backup")
    with pytest.raises(RuntimeError, match="Maximum output tokens.*128000"):
        setup(path, "openai", "--max-output-tokens", "200000")
    assert path.read_bytes() == original
    assert backup.read_text() == "preserve backup"


@pytest.mark.parametrize("interactive", [True, False])
@pytest.mark.parametrize(
    "model,context,output_cap,expected_input,expected_output",
    [
        ("gpt-6-sol", 1050000, 256000, 272000, 128000),
        ("gpt-6-sol", 256000, 32000, 224000, 32000),
        ("custom-deployment", 256000, 32000, 224000, 32000),
    ],
)
def test_oversized_saved_budgets_use_ceiling(
    tmp_path,
    capsys,
    interactive,
    model,
    context,
    output_cap,
    expected_input,
    expected_output,
):
    path = document(
        tmp_path / "agents.toml",
        {
            "model": model,
            "model_context_tokens": context,
            "model_max_output_tokens": output_cap,
            "max_input_tokens": 400000,
            "max_output_tokens": 200000,
        },
    )
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch("builtins.input", return_value="") as prompts,
    ):
        report = setup(path, "openai", "--no-auto-token-budgets")
    saved = sources.read_config(path)["profiles"]["work"]
    assert saved["max_input_tokens"] == expected_input
    assert saved["max_output_tokens"] == expected_output
    assert (
        report["analysis_limits"]["effective"]["maximum_input_tokens"] == expected_input
    )
    assert (
        report["analysis_limits"]["effective"]["maximum_output_tokens"]
        == expected_output
    )
    assert report["token_budget_adjustments"]["max_input_tokens"]["previous"] == 400000
    if interactive:
        assert f"Maximum input tokens [{expected_input}] (Enter to keep): " in [
            c.args[0] for c in prompts.call_args_list
        ]
        assert f"Maximum output tokens [{expected_output}] (Enter to keep): " in [
            c.args[0] for c in prompts.call_args_list
        ]
        assert (
            "saved value 400000 is outside the allowed range" in capsys.readouterr().err
        )


@pytest.mark.parametrize(
    "field,value", [("max_input_tokens", 272001), ("max_output_tokens", 128001)]
)
@pytest.mark.parametrize("interactive", [True, False])
def test_budget_above_maximum_is_rejected_before_write(
    tmp_path, field, value, interactive
):
    path = tmp_path / "agents.toml"
    setup(path)
    original = path.read_bytes()
    flags = [] if interactive else ["--" + field.replace("_", "-"), str(value)]
    label = (
        "Maximum input tokens"
        if field == "max_input_tokens"
        else "Maximum output tokens"
    )
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch(
            "builtins.input",
            side_effect=lambda prompt: str(value) if prompt.startswith(label) else "",
        ),
    ):
        if interactive:
            report = setup(path, "openai", *flags)
            assert sources.read_config(path)["profiles"]["openai"][field] == value - 1
            assert report["token_budget_adjustments"][field] == {
                "entered": value,
                "selected": value - 1,
            }
        else:
            with pytest.raises(RuntimeError, match=label):
                setup(path, "openai", *flags)
            assert path.read_bytes() == original
            assert not path.with_suffix(".toml.bak").exists()


def test_switching_to_smaller_model_caps_both_saved_values(tmp_path):
    path = tmp_path / "agents.toml"
    setup(path, "anthropic", "--model", "claude-sonnet-5")
    report = setup(path, "anthropic", "--model", "claude-haiku-4-5-20251001")
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_input_tokens"] == 120000
    assert effective["maximum_output_tokens"] == 64000


def test_output_entry_determines_remaining_input_context(tmp_path):
    path = tmp_path / "agents.toml"
    setup(
        path,
        "openai",
        "--model-context-tokens",
        "300000",
        "--max-input-tokens",
        "200000",
        "--max-output-tokens",
        "64000",
    )
    original = path.read_bytes()

    def answer(prompt):
        if prompt.startswith("Maximum input tokens"):
            return "230000"
        if prompt.startswith("Maximum output tokens"):
            return "100000"
        return ""

    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", side_effect=answer),
    ):
        report = setup(path)
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 100000
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 200000
    assert path.with_suffix(".toml.bak").read_bytes() == original


def test_config_cli_reports_profile_and_derived_sources(tmp_path, monkeypatch, capsys):
    path = tmp_path / "agents.toml"
    setup(path)
    monkeypatch.setattr(
        command,
        "resolve_agent_execution",
        lambda **kw: resolve_agent_execution(repo_root=tmp_path, **kw),
    )
    assert command.main(["--config-file", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)["analysis_limits"]
    assert report["effective"]["maximum_output_tokens"] == 128000
    assert (
        report["sources"]["maximum_output_tokens"]["name"]
        == "profiles.openai.max_output_tokens"
    )
    assert (
        report["sources"]["operational_context_tokens"]["kind"]
        == "derived_profile_budget"
    )


@pytest.mark.parametrize("entry", ["1000000", "max", "auto"])
@pytest.mark.parametrize("output", [32000, 64000, 128000])
def test_existing_sonnet_uses_full_model_context_in_wizard(
    tmp_path, capsys, entry, output
):
    path = document(
        tmp_path / "agents.toml",
        {
            "provider": "anthropic",
            "model": "claude-sonnet-5",
            "max_input_tokens": 128000,
            "max_output_tokens": output,
        },
    )

    def answer(prompt):
        if prompt.startswith("Maximum input tokens"):
            # The displayed maximum must match validation, including saved output.
            assert f"{1000000 - output:,}" in capsys.readouterr().err
            return entry
        return ""

    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", side_effect=answer),
    ):
        report = setup(path, "anthropic", "--no-auto-token-budgets")
    effective = report["analysis_limits"]["effective"]
    assert effective["maximum_input_tokens"] == 1000000 - output
    assert effective["maximum_output_tokens"] == output
    assert effective["operational_context_tokens"] == 1000000
    selected = resolve(path)
    resolved = limits.resolve_analysis_limits({}, execution=selected).for_execution(
        selected
    )
    assert resolved.maximum_input_tokens == 1000000 - output
    assert resolved.for_execution(selected).as_dict() == resolved.as_dict()


@pytest.mark.parametrize(
    "provider,model,input_tokens,output_tokens",
    [
        ("anthropic", "claude-sonnet-5", 872000, 128000),
        ("anthropic", "claude-haiku-4-5-20251001", 120000, 64000),
        ("openai", "gpt-6-sol", 272000, 128000),
    ],
)
def test_automatic_default_replaces_saved_budgets_with_model_recommendations(
    tmp_path, provider, model, input_tokens, output_tokens
):
    path = document(
        tmp_path / "agents.toml",
        {
            "provider": provider,
            "model": model,
            "max_input_tokens": 32000,
            "max_output_tokens": 8000,
        },
    )
    report = setup(path, provider)
    assert (
        report["analysis_limits"]["effective"]["maximum_input_tokens"] == input_tokens
    )
    assert (
        report["analysis_limits"]["effective"]["maximum_output_tokens"] == output_tokens
    )


def test_auto_flag_respects_explicit_output_and_deployment_context(tmp_path):
    path = tmp_path / "agents.toml"
    report = setup(
        path,
        "anthropic",
        "--model",
        "claude-sonnet-5",
        "--auto-token-budgets",
        "--model-context-tokens",
        "200000",
        "--max-output-tokens",
        "32000",
    )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 168000
    assert report["analysis_limits"]["effective"]["maximum_output_tokens"] == 32000


def test_invalid_interactive_token_entry_can_be_corrected(tmp_path, capsys):
    answers = iter(["not-a-number", "-1", "99999", "max"])
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=lambda p: (
                next(answers) if p.startswith("Maximum input tokens") else ""
            ),
        ),
    ):
        report = setup(
            tmp_path / "agents.toml", "anthropic", "--model", "claude-sonnet-5"
        )
    assert report["analysis_limits"]["effective"]["maximum_input_tokens"] == 872000
    display = capsys.readouterr().err
    assert "Enter a positive integer" in display
    assert "Enter at least 100000 tokens" in display
    assert "Maximum input tokens: allowed 100,000–872,000" in display


@pytest.mark.parametrize("provider", ["anthropic", "openai", "azure_openai"])
@pytest.mark.parametrize("interactive", [False, True])
def test_small_model_cannot_lower_minimums(tmp_path, provider, interactive):
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch("builtins.input", return_value=""),
    ):
        path = tmp_path / "agents.toml"
        with pytest.raises(RuntimeError, match="at least.*32000"):
            setup(
                path,
                provider,
                "--model",
                "custom-small-model",
                "--model-context-tokens",
                "64000",
                "--model-max-output-tokens",
                "8000",
            )
        assert not path.exists()


def test_noninteractive_small_explicit_input_fails_without_writing(tmp_path):
    path = tmp_path / "agents.toml"
    with pytest.raises(RuntimeError, match="between 100000"):
        setup(
            path,
            "anthropic",
            "--model",
            "claude-sonnet-5",
            "--max-input-tokens",
            "99999",
        )
    assert not path.exists()


@pytest.mark.parametrize("provider", ["openai", "azure_openai"])
def test_runtime_passes_128k_to_supported_adapter(tmp_path, provider):
    path = tmp_path / "agents.toml"
    setup(path, provider)
    execution = resolve(path)
    adapter = mock.Mock(configuration=execution)
    adapter.capabilities.return_value = ProviderCapabilities(
        request_output_token_limit=True, reasoning_configuration=True
    )
    adapter.execute = mock.AsyncMock(
        return_value=ProviderResponse("ok", "test-request")
    )
    with mock.patch.object(factory, "adapter_for", return_value=adapter):
        runner = factory.create_agent_runner(execution, persist_runtime_files=False)
    result = asyncio.run(
        runner.run(
            AgentRequest(
                task_id="test", prompt="test", output_name="test.txt", metadata={}
            ),
            workdir=tmp_path,
            output_dir=tmp_path / "out",
        )
    )
    assert result.status == "succeeded"
    assert adapter.execute.call_args.args[0].max_output_tokens == 128000
