"""Setup reuses operator settings before suggesting new-profile defaults."""

import json
from pathlib import Path
from unittest import mock

import pytest
from vraptor.agent import manage, sources
from vraptor.agent.config import resolve_agent_execution


@pytest.fixture(autouse=True)
def isolated_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(manage.os, "isatty", lambda _: False)
    with mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True):
        yield


def arguments(path, *flags):
    return manage.parser_for("setup").parse_args(["--config-file", str(path), *flags])


@pytest.mark.parametrize(
    ("answers", "selected"),
    [
        (["yes"], "anthropic"),
        ([" Y "], "anthropic"),
        (["no"], "openai"),
        (["n"], "openai"),
        ([""], "openai"),
        (["invalid", "yes"], "anthropic"),
    ],
)
@pytest.mark.parametrize("existing", [False, True])
def test_interactive_setup_selects_default_at_end(
    tmp_path, answers, selected, existing
):
    path = tmp_path / "agents.toml"
    manage.setup(arguments(path, "--provider", "openai"))
    flags = [
        "--provider",
        "anthropic",
        "--profile-name",
        "anthropic",
        "--reasoning-effort",
        "low",
        "--model",
        "local-model",
        "--model-context-tokens",
        "200000",
    ]
    if existing:
        manage.setup(arguments(path, *flags))
    before = path.read_bytes()
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input", side_effect=["", "", "", "", "", *answers]
        ) as prompt,
    ):
        report = manage.setup(arguments(path, *flags))
    assert prompt.call_args_list[0].args[0].startswith("Configure advanced API")
    assert prompt.call_args_list[1].args[0].startswith("Timeout seconds")
    assert prompt.call_args_list[2].args[0].startswith("Maximum concurrency")
    assert all(
        call.args[0]
        == "Make 'anthropic' the default profile? Current: 'openai' [y/N]: "
        for call in prompt.call_args_list[5:]
    )
    assert sources.read_config(path)["selection"]["default_profile"] == selected
    assert report["default_profile"] == selected
    assert Path(report["backup"]).read_bytes() == before


@pytest.mark.parametrize("interactive", [False, True])
@pytest.mark.parametrize("set_default", [False, True])
def test_default_selection_flag_and_noninteractive_setup(
    tmp_path, interactive, set_default
):
    path = tmp_path / "agents.toml"
    manage.setup(arguments(path, "--provider", "openai"))
    flags = [
        "--provider",
        "anthropic",
        "--profile-name",
        "anthropic",
        "--model",
        "local-model",
        "--model-context-tokens",
        "200000",
        "--timeout-seconds",
        "600",
        "--max-concurrency",
        "1",
        "--max-input-tokens",
        "120000",
        "--max-output-tokens",
        "32000",
        "--reasoning-effort",
        "low",
    ]
    if set_default:
        flags.append("--set-default")
    elif interactive:
        # Already selected profiles need no default-selection prompt.
        manage.setup(arguments(path, *flags, "--set-default"))
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch(
            "builtins.input",
            side_effect=[""] if interactive else AssertionError("unexpected prompt"),
        ),
    ):
        report = manage.setup(arguments(path, *flags))
    selected = "anthropic" if set_default or interactive else "openai"
    assert report["default_profile"] == selected
    assert sources.read_config(path)["selection"]["default_profile"] == selected


@pytest.mark.parametrize("provider", ["openai", "azure_openai"])
def test_new_api_setup_writes_requested_execution_defaults(tmp_path, provider):
    path = tmp_path / "agents.toml"
    flags = ["--base-url", "https://azure.test"] if provider == "azure_openai" else []
    manage.setup(arguments(path, "--provider", provider, *flags))
    name = "azure" if provider == "azure_openai" else provider
    profile = sources.read_config(path)["profiles"][name]
    assert profile["model"] == "gpt-5.6-luna"
    assert profile["reasoning_effort"] == "high"
    assert profile["timeout_seconds"] == 600
    assert profile["max_concurrency"] == 20
    if provider == "azure_openai":
        assert (
            'model = "gpt-5.6-luna"  # Must match your Azure deployment name'
            in path.read_text()
        )
    execution = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert execution.model == profile["model"]
    assert execution.reasoning_effort == "high"
    assert execution.max_concurrency == 20


def test_new_azure_interactive_defaults_can_be_accepted(tmp_path):
    path = tmp_path / "agents.toml"
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompt,
    ):
        manage.setup(
            arguments(
                path, "--provider", "azure_openai", "--base-url", "https://azure.test"
            )
        )
    assert [call.args[0] for call in prompt.call_args_list] == [
        "Profile name [azure] (Enter to keep): ",
        "Configure advanced API endpoint and authentication [y/N]: ",
        "Model ID / deployment name [gpt-5.6-luna] (Enter to keep): ",
        "Reasoning effort [high] (Enter to keep): ",
        "Timeout seconds [600] (Enter to keep): ",
        "Maximum concurrency [20] (Enter to keep): ",
        "Maximum output tokens [128000] (Enter to keep): ",
        "Maximum input tokens [272000] (Enter to keep): ",
    ]


@pytest.mark.parametrize("managed_login", [False, True])
def test_new_claude_setup_uses_shared_token_defaults(tmp_path, managed_login):
    from vraptor.analyze.limits import default_analysis_settings

    path = tmp_path / "agents.toml"
    if managed_login:
        source = tmp_path / ".claude/settings.json"
        source.parent.mkdir()
        source.write_text('{"model":"claude-test"}')
        flags = ["--from-harness", "claude_code"]
        name = "claude_code"
    else:
        flags = ["--provider", "anthropic", "--model", "claude-test"]
        name = "anthropic"
    manage.setup(arguments(path, *flags))
    saved = sources.read_config(path)
    assert saved["analysis_defaults"] == default_analysis_settings()
    assert "model_context_tokens" not in saved["profiles"][name]
    assert "model_max_output_tokens" not in saved["profiles"][name]


@pytest.mark.parametrize("method", ["prompt", "flags"])
def test_execution_settings_can_be_customized(tmp_path, method):
    path = tmp_path / "agents.toml"
    flags = [
        "--provider",
        "azure_openai",
        "--base-url",
        "https://azure.test",
        "--profile-name",
        "azure",
    ]
    if method == "flags":
        flags += [
            "--model",
            "team-deployment",
            "--reasoning-effort",
            "low",
            "--timeout-seconds",
            "900",
            "--max-concurrency",
            "7",
            "--max-input-tokens",
            "272000",
            "--max-output-tokens",
            "128000",
        ]
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=["", "team-deployment", "low", "900", "7", "", ""]
            if method == "prompt"
            else [""],
        ),
    ):
        manage.setup(arguments(path, *flags))
    profile = sources.read_config(path)["profiles"]["azure"]
    for key, value in {
        "model": "team-deployment",
        "reasoning_effort": "low",
        "timeout_seconds": 900,
        "max_concurrency": 7,
    }.items():
        assert profile[key] == value


@pytest.mark.parametrize("kind", ["codex", "claude_code"])
@pytest.mark.parametrize("path_style", ["absolute", "relative", "tilde"])
def test_rerun_prompts_use_saved_harness_path_and_values(tmp_path, kind, path_style):
    path = tmp_path / "agents.toml"
    source = tmp_path / (
        ".codex/azure.config.toml" if kind == "codex" else ".claude/work.json"
    )
    source.parent.mkdir()
    source.write_text(
        'model = "native-model"\n[profiles.team]\nmodel = "team-model"\n'
        if kind == "codex"
        else json.dumps({"model": "native-model"})
    )
    original_source = source.read_bytes()
    saved_path = {
        "absolute": str(source),
        "relative": str(source.relative_to(tmp_path)),
        "tilde": "~/" + str(source.relative_to(tmp_path)),
    }[path_style]
    profile = {
        "source": {
            "kind": kind,
            "path": saved_path,
            **({"profile": "team"} if kind == "codex" else {}),
        },
        "model": "saved-model",
        "reasoning_effort": "low",
        "timeout_seconds": 900,
        "max_concurrency": 7,
        "max_retries": 4,
        "read_timeout_seconds": 120,
        "model_context_tokens": 200000,
        "model_max_output_tokens": 32000,
        "enabled": False,
        "transport": "auto" if kind == "codex" else "claude_agent_sdk",
    }
    other = {"provider": "openai", "model": "other"}
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "profiles": {"work": profile, "other": other},
            }
        )
    )
    before = path.read_bytes()
    # Relative saved paths must resolve from the config directory, not cwd or the candidate directory.
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompt,
        mock.patch.object(manage, "read_config", wraps=manage.read_config) as read,
        mock.patch.object(
            sources, "read_config", wraps=sources.read_config
        ) as read_source,
    ):
        result = manage.setup(arguments(path))
    read.assert_called_once_with(path)
    assert sum(call.args[0] == source for call in read_source.call_args_list) == 1
    prompts = [call.args[0] for call in prompt.call_args_list]
    assert f"[{kind}]" in prompts[0]
    assert "Profile name [work]" in prompts[1]
    assert f"[{source}]" in prompts[2]
    assert "[saved-model]" in prompts[3]
    assert "[low]" in prompts[4]
    assert "[900]" in prompts[5]
    assert "[7]" in prompts[6]
    updated = sources.read_config(path)
    assert updated["profiles"]["work"] == {
        **profile,
        "max_input_tokens": 168000,
        "max_output_tokens": 32000,
        "source": {**profile["source"], "path": str(source)},
    }
    assert updated["profiles"]["other"] == other
    assert updated["selection"]["default_profile"] == "work"
    assert result["profile_action"] == "updated"
    assert Path(result["backup"]).read_bytes() == before
    assert source.read_bytes() == original_source


def test_noninteractive_rerun_preserves_native_inheritance_and_path(tmp_path):
    source = tmp_path / "azure.config.toml"
    source.write_text(
        'model = "deployment"\nmodel_reasoning_effort = "medium"\nmodel_provider = "azure"\n[model_providers.azure]\nbase_url = "https://azure.test"\n'
    )
    path = tmp_path / "agents.toml"
    manage.setup(
        arguments(path, "--from-harness", "codex", "--harness-config", str(source))
    )
    first = sources.read_config(path)["profiles"]["codex"]
    with mock.patch("builtins.input", side_effect=AssertionError("unexpected prompt")):
        manage.setup(arguments(path))
    assert sources.read_config(path)["profiles"]["codex"] == first
    assert "model" not in first and "reasoning_effort" not in first
    execution = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert execution.model == "deployment"
    assert execution.reasoning_effort == "medium"


def test_shared_connection_and_execution_defaults_survive_rerun(tmp_path):
    path = tmp_path / "agents.toml"
    connection = {
        "provider": "azure_openai",
        "base_url": "https://custom.test",
        "api_key_env": "TEAM_KEY",
    }
    defaults = {
        "timeout_seconds": 900,
        "max_concurrency": 8,
        "reasoning_effort": "low",
        "max_retries": 4,
    }
    profiles = {
        "work": {"connection": "team", "model": "saved-deployment", "enabled": False},
        "other": {"connection": "team", "model": "other"},
    }
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "execution_defaults": defaults,
                "connections": {"team": connection},
                "selection": {"default_profile": "work"},
                "profiles": profiles,
            }
        )
    )
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompt,
    ):
        manage.setup(arguments(path))
    document = sources.read_config(path)
    selected = document["profiles"]["work"]
    assert selected["base_url"] == connection["base_url"]
    assert selected["api_key_env"] == "TEAM_KEY"
    assert selected["model"] == "saved-deployment" and selected["enabled"] is False
    assert selected["reasoning_effort"] == "low"
    assert selected["timeout_seconds"] == 900 and selected["max_concurrency"] == 8
    assert "[https://custom.test]" in prompt.call_args_list[2].args[0]
    assert document["execution_defaults"] == defaults
    assert document["connections"]["team"] == connection
    assert document["profiles"]["other"] == profiles["other"]


@pytest.mark.parametrize("native_profile", ["root", "embedded", "sibling"])
@pytest.mark.parametrize("override", ["none", "profile", "environment"])
def test_codex_reasoning_import_preserves_override_precedence(
    tmp_path, native_profile, override
):
    source = tmp_path / "codex.toml"
    source.write_text('model = "native-model"\nmodel_reasoning_effort = "low"\n')
    selected_source = {"kind": "codex", "path": str(source)}
    effort_path = source
    if native_profile != "root":
        selected_source["profile"] = "team"
        selected = 'model_reasoning_effort = "medium"\n'
        if native_profile == "embedded":
            source.write_text(source.read_text() + "[profiles.team]\n" + selected)
        else:
            effort_path = tmp_path / "team.config.toml"
            effort_path.write_text(selected)
    profile = {"source": selected_source}
    if override != "none":
        profile["reasoning_effort"] = "high"
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "profiles": {"work": profile},
            }
        )
    )
    environment = {"HOME": str(tmp_path)}
    if override == "environment":
        environment["AI_SKILLS_ANALYST_AGENT_REASONING_EFFORT"] = "minimal"
    execution = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment=environment,
        allow_missing_credentials=True,
    )
    assert execution.reasoning_effort == (
        "minimal"
        if override == "environment"
        else "high"
        if override == "profile"
        else "low"
        if native_profile == "root"
        else "medium"
    )
    provenance = execution.route.field_sources["reasoning_effort"]
    assert (
        provenance.kind
        == {
            "environment": "process_environment",
            "profile": "execution_profile",
            "none": "codex_route",
        }[override]
    )
    if override == "none":
        assert provenance.location == str(effort_path)


def test_missing_saved_harness_path_does_not_fall_back(tmp_path):
    default = tmp_path / ".codex/config.toml"
    default.parent.mkdir()
    default.write_text('model = "wrong-model"\n')
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "work"},
                "profiles": {
                    "work": {
                        "source": {
                            "kind": "codex",
                            "path": str(tmp_path / "missing.toml"),
                        }
                    }
                },
            }
        )
    )
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="harness configuration file does not exist"):
        manage.setup(arguments(path))
    assert path.read_bytes() == before
    assert not path.with_suffix(".toml.bak").exists()


@pytest.mark.parametrize("field", ["timeout_seconds", "max_concurrency"])
@pytest.mark.parametrize("bad", ["0", "-1", "abc"])
def test_invalid_interactive_limits_do_not_replace_config(tmp_path, field, bad):
    path = tmp_path / "agents.toml"
    manage.setup(arguments(path, "--provider", "openai"))
    before = path.read_bytes()
    label = "Timeout seconds" if field == "timeout_seconds" else "Maximum concurrency"
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=lambda prompt: bad if prompt.startswith(label) else "",
        ),
        pytest.raises(RuntimeError, match="must be a positive integer"),
    ):
        manage.setup(arguments(path))
    assert path.read_bytes() == before
    assert not path.with_suffix(".toml.bak").exists()
