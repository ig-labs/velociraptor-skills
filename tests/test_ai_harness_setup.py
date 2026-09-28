"""Native settings discovery and AI setup integration without external services."""

import asyncio
import json
import os
import subprocess
import sys
from unittest import mock

import pytest
from vraptor.agent import manage, sources
from vraptor.agent.config import resolve_agent_execution

DESKTOP = "Library/Application Support/Claude/settings.json"
BACKUP = ".claude/settings.json"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(manage.os, "isatty", lambda _: False)
    with mock.patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=True):
        yield


def settings(home, relative, model):
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"model": model, "effortLevel": "high"}))
    return path


def resolve(home, profile=None, **environment):
    cli = {}
    if profile is not None:
        path = home / "analyst.toml"
        path.write_text(
            manage._toml(
                {
                    "schema_version": 2,
                    "selection": {"default_profile": "claude"},
                    "profiles": {"claude": profile},
                }
            )
        )
        cli["config_file"] = str(path)
    return resolve_agent_execution(
        cli_values=cli,
        repo_root=home,
        process_environment={"HOME": str(home), "CLAUDECODE": "1", **environment},
        allow_missing_credentials=True,
    )


@pytest.mark.parametrize("named", [False, True])
@pytest.mark.parametrize(
    "locations,expected",
    [
        ([DESKTOP], DESKTOP),
        ([BACKUP], BACKUP),
        ([DESKTOP, BACKUP], DESKTOP),
    ],
)
def test_real_resolver_discovers_claude_settings(tmp_path, named, locations, expected):
    for relative in locations:
        settings(
            tmp_path,
            relative,
            "desktop-model" if relative == DESKTOP else "backup-model",
        )
    selected = resolve(tmp_path, {"source": {"kind": "claude_code"}} if named else None)
    assert selected.model == (
        "desktop-model" if expected == DESKTOP else "backup-model"
    )
    assert selected.route.harness_config_path == str(tmp_path / expected)
    assert selected.route.field_sources["model"].kind == "harness_config"
    assert selected.auth_mode == "claude_managed"


def test_explicit_and_environment_paths_override_discovery(tmp_path):
    settings(tmp_path, DESKTOP, "desktop-model")
    settings(tmp_path, BACKUP, "backup-model")
    custom = settings(tmp_path, "custom.json", "custom-model")
    override = settings(tmp_path, "env.json", "env-model")
    profile = {"source": {"kind": "claude_code", "path": "custom.json"}}
    assert resolve(tmp_path, profile).route.harness_config_path == str(custom)
    selected = resolve(
        tmp_path, profile, AI_SKILLS_ANALYST_AGENT_CLAUDE_CONFIG=str(override)
    )
    assert selected.model == "env-model"
    # A profile model wins over the native file, and an application env override wins over it.
    profile["model"] = "saved-model"
    assert resolve(tmp_path, profile).model == "saved-model"
    assert (
        resolve(tmp_path, profile, AI_SKILLS_ANALYST_AGENT_MODEL="override").model
        == "override"
    )


@pytest.mark.parametrize(
    "variables",
    [
        ("ANTHROPIC_API_KEY",),
        ("ANTHROPIC_AUTH_TOKEN",),
        ("CLAUDE_CODE_OAUTH_TOKEN",),
        ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"),
    ],
)
def test_claude_managed_ignores_inherited_credentials(tmp_path, variables):
    settings(tmp_path, BACKUP, "haiku")
    environment = dict.fromkeys(variables, "unused-test-credential")
    selected = resolve(tmp_path, {"source": {"kind": "claude_code"}}, **environment)
    assert selected.protocol == "claude_agent_sdk"
    assert selected.auth_mode == "claude_managed"
    assert selected.inputs.api_key == ""
    assert not selected.inputs.default_headers
    assert not selected.inputs.credential_present
    assert environment == dict.fromkeys(variables, "unused-test-credential")


@pytest.mark.parametrize("failure", ["missing", "invalid", "directory"])
def test_explicit_bad_source_does_not_fall_back(tmp_path, failure):
    settings(tmp_path, BACKUP, "backup-model")
    path = tmp_path / "custom.json"
    if failure == "invalid":
        path.write_text("not-json")
    elif failure == "directory":
        path.mkdir()
    with pytest.raises(RuntimeError):
        resolve(
            tmp_path,
            {"source": {"kind": "claude_code", "path": str(path)}, "model": "override"},
        )


@pytest.mark.parametrize("directory", [False, True])
def test_invalid_primary_is_reported_instead_of_using_backup(tmp_path, directory):
    settings(tmp_path, BACKUP, "backup-model")
    path = tmp_path / DESKTOP
    path.parent.mkdir(parents=True)
    path.mkdir() if directory else path.write_text("not-json")
    with pytest.raises(RuntimeError):
        resolve(tmp_path)


def setup_args(home, *flags):
    return manage.parser_for("setup").parse_args(
        ["--config-file", str(home / "analyst.toml"), *flags]
    )


def test_no_settings_file_requires_model_but_never_reads_desktop_tokens(tmp_path):
    token_cache = tmp_path / "Library/Application Support/Claude/config.json"
    token_cache.parent.mkdir(parents=True)
    token_cache.write_text('{"oauth:tokenCache":"DO-NOT-IMPORT"}')
    with pytest.raises(RuntimeError, match="model is unavailable"):
        manage.setup(setup_args(tmp_path, "--from-harness", "claude_code"))
    assert not (tmp_path / "analyst.toml").exists()
    report = manage.setup(
        setup_args(
            tmp_path, "--from-harness", "claude_code", "--model", "explicit-model"
        )
    )
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"]["claude_code"]
    assert profile["source"] == {"kind": "claude_code"}
    assert resolve(tmp_path, profile).model == "explicit-model"
    assert "DO-NOT-IMPORT" not in json.dumps(report)
    assert not (tmp_path / DESKTOP).exists()
    assert not (tmp_path / BACKUP).exists()


@pytest.mark.parametrize("native", [False, True])
def test_interactive_claude_prompts_and_optional_login(
    tmp_path, monkeypatch, capsys, native
):
    if native:
        settings(tmp_path, DESKTOP, "native-model")
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        if prompt.startswith("Model ID"):
            assert ("[native-model]" if native else "[required]") in prompt
            return "" if native else "entered-model"
        return ""

    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with (
        mock.patch("builtins.input", side_effect=answer),
        mock.patch.object(manage, "claude_auth_status") as auth,
    ):
        report = manage.setup(setup_args(tmp_path, "--from-harness", "claude_code"))
    auth.assert_not_called()
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"]["claude_code"]
    assert resolve(tmp_path, profile).model == (
        "native-model" if native else "entered-model"
    )
    assert ("model" not in profile) if native else (profile["model"] == "entered-model")
    assert report["authentication"] == "not_checked"
    assert prompts[-1] == "Check Claude Code login and sign in if needed [y/N]: "
    stderr = capsys.readouterr().err
    assert "\nModel and execution\n" in stderr and "\nClaude login\n" in stderr


def test_anthropic_advanced_api_setup_preserves_profiles(tmp_path, monkeypatch):
    manage.setup(setup_args(tmp_path, "--provider", "openai"))
    original = sources.read_config(tmp_path / "analyst.toml")
    answers = {
        "Configure advanced": "y",
        "API endpoint": "https://anthropic.example.test",
        "API key environment": "TEAM_ANTHROPIC_KEY",
        "Model ID": "team-model",
        "Maximum input": "100000",
        "Maximum output": "32000",
    }
    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with mock.patch(
        "builtins.input",
        side_effect=lambda prompt: next(
            (value for key, value in answers.items() if prompt.startswith(key)), ""
        ),
    ):
        manage.setup(setup_args(tmp_path, "--provider", "anthropic"))
    saved = sources.read_config(tmp_path / "analyst.toml")
    assert saved["profiles"]["openai"] == original["profiles"]["openai"]
    assert saved["selection"] == original["selection"]
    profile = saved["profiles"]["anthropic"]
    selected = resolve(tmp_path, profile, TEAM_ANTHROPIC_KEY="SECRET")
    assert selected.auth_mode == "api_key"
    assert selected.inputs.credential_present
    assert selected.route.credential_variable == "TEAM_ANTHROPIC_KEY"
    assert (
        profile["max_input_tokens"] == 100000 and profile["max_output_tokens"] == 32000
    )
    assert "SECRET" not in (tmp_path / "analyst.toml").read_text()
    assert "SECRET" not in json.dumps(selected.public_dict())


@pytest.mark.parametrize(
    "choice", ["openai", "anthropic", "codex", "claude_code", "azure_openai"]
)
@pytest.mark.parametrize("entered", ["", "custom-unlisted-model"])
def test_model_helpers_precede_prompt_without_restricting_models(
    tmp_path, monkeypatch, capsys, choice, entered
):
    if choice in {"codex", "claude_code"}:
        flags = ["--from-harness", choice]
        if choice == "codex":
            native = tmp_path / ".codex/config.toml"
            native.parent.mkdir()
            native.write_text('model = "native-model"\n')
    else:
        flags = ["--provider", choice]
        if choice == "azure_openai":
            flags += ["--base-url", "https://azure.example.test"]
    first = manage.setup(setup_args(tmp_path, *flags, "--model", "saved-model"))
    capsys.readouterr()
    seen = []

    def answer(prompt):
        if prompt.startswith("Model ID"):
            assert "[saved-model]" in prompt
            hints = capsys.readouterr().err
            if choice in {"anthropic", "claude_code"}:
                assert "claude-sonnet-5" in hints and "claude-opus-5-5" in hints
                assert "gpt-6-astra" not in hints
                assert ("aliases: sonnet, opus, haiku, fable" in hints) == (
                    choice == "claude_code"
                )
            elif choice == "azure_openai":
                assert "enter your deployment name" in hints
                assert "gpt-6-astra" not in hints
            else:
                assert "gpt-6-astra" in hints and "gpt-5.6-luna" in hints
                assert "claude-sonnet-5" not in hints
            seen.append(prompt)
            return entered
        return ""

    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with (
        mock.patch("builtins.input", side_effect=answer),
        mock.patch.object(
            manage,
            "claude_auth_status",
            side_effect=AssertionError("unexpected auth check"),
        ),
    ):
        report = manage.setup(setup_args(tmp_path, *flags))
    assert len(seen) == 1
    assert report["default_profile"] == first["default_profile"]
    saved = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert saved["model"] == (entered or "saved-model")


def test_explicit_model_skips_suggestions_and_preserves_json_output(tmp_path, capsys):
    assert (
        manage.main(
            "setup",
            [
                "--config-file",
                str(tmp_path / "analyst.toml"),
                "--provider",
                "openai",
                "--model",
                "custom-unlisted-model",
            ],
        )
        == 0
    )
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "configured"
    assert not output.err
    with (
        mock.patch.object(manage.os, "isatty", return_value=True),
        mock.patch("builtins.input", return_value=""),
    ):
        manage.setup(
            setup_args(tmp_path, "--provider", "openai", "--model", "another-model")
        )
    assert "OpenAI model examples:" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "choice,model,expected,absent",
    [
        ("openai", "gpt-6-astra", "  xhigh", "  none"),
        ("openai", "gpt-6-sol", "  none", "Haiku"),
        ("openai", "gpt-5.6-luna", "  none", "Haiku"),
        ("openai", "gpt-5", "  minimal", "  none"),
        ("anthropic", "claude-sonnet-5", "  xhigh", "  none"),
        ("claude_code", "claude-opus-5-5", "  xhigh", "  none"),
        ("anthropic", "claude-opus-4-6", "  max", "  xhigh"),
        ("anthropic", "claude-haiku-4-5-20251001", "does not support", "  xhigh"),
        (
            "azure_openai",
            "custom-deployment",
            "Azure deployments",
            "Claude / Anthropic",
        ),
    ],
)
def test_effort_options_precede_prompt_and_preserve_saved_values(
    tmp_path, monkeypatch, capsys, choice, model, expected, absent
):
    flags = (
        ["--from-harness", choice]
        if choice == "claude_code"
        else ["--provider", choice]
    )
    flags += ["--model", model]
    if choice == "azure_openai":
        flags += ["--base-url", "https://azure.example.test"]
    saved_effort = [] if "haiku" in model else ["--reasoning-effort", "low"]
    manage.setup(setup_args(tmp_path, *flags, *saved_effort))
    capsys.readouterr()
    seen = []

    def answer(prompt):
        if prompt.startswith("Reasoning effort"):
            output = capsys.readouterr().err
            assert expected in output
            assert absent not in output
            assert ("[low]" if saved_effort else "[inherit]") in prompt
            seen.append(prompt)
        return ""

    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with mock.patch("builtins.input", side_effect=answer):
        report = manage.setup(setup_args(tmp_path, *flags))
    assert len(seen) == 1
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert profile.get("reasoning_effort") == ("low" if saved_effort else None)


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("interactive", [False, True])
@pytest.mark.parametrize(
    "model,expected",
    [
        ("claude-sonnet-5", "medium"),
        ("claude-opus-5-5", "medium"),
        ("claude-fable-5-1", "medium"),
        ("claude-opus-4-5-20251101", "medium"),
        ("claude-sonnet-4-6", "medium"),
        ("claude-opus-4-6", "medium"),
        ("claude-haiku-4-5-20251001", None),
        ("haiku", None),
        ("claude-sonnet-4-5", None),
        ("custom-model", None),
    ],
)
def test_claude_default_effort_matches_model_support(
    tmp_path, managed, interactive, model, expected
):
    flags = (
        ["--from-harness", "claude_code"] if managed else ["--provider", "anthropic"]
    )
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch("builtins.input", return_value="") as prompts,
    ):
        report = manage.setup(setup_args(tmp_path, *flags, "--model", model))
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert profile.get("reasoning_effort") == expected
    assert resolve(tmp_path, profile).reasoning_effort == (expected or "")
    if interactive:
        assert f"Reasoning effort [{expected or 'inherit'}] (Enter to keep): " in [
            c.args[0] for c in prompts.call_args_list
        ]


@pytest.mark.parametrize("interactive", [False, True])
@pytest.mark.parametrize("native_effort", [None, "high"])
def test_claude_inherited_model_gets_medium_only_without_native_effort(
    tmp_path, interactive, native_effort
):
    native = settings(tmp_path, DESKTOP, "claude-sonnet-5")
    native.write_text(
        json.dumps(
            {
                "model": "claude-sonnet-5",
                **({"effortLevel": native_effort} if native_effort else {}),
            }
        )
    )
    with (
        mock.patch("os.isatty", return_value=interactive),
        mock.patch("builtins.input", return_value=""),
    ):
        report = manage.setup(setup_args(tmp_path, "--from-harness", "claude_code"))
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert "model" not in profile
    assert profile.get("reasoning_effort") == (None if native_effort else "medium")
    assert resolve(tmp_path, profile).reasoning_effort == (native_effort or "medium")


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_claude_efforts_can_be_entered_and_resolved(
    tmp_path, monkeypatch, managed, effort
):
    flags = (
        ["--from-harness", "claude_code"] if managed else ["--provider", "anthropic"]
    )
    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with mock.patch(
        "builtins.input",
        side_effect=lambda prompt: (
            effort if prompt.startswith("Reasoning effort") else ""
        ),
    ):
        report = manage.setup(
            setup_args(tmp_path, *flags, "--model", "claude-sonnet-5")
        )
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert resolve(tmp_path, profile).reasoning_effort == effort


@pytest.mark.parametrize(
    "effort", ["none", "minimal", "low", "medium", "high", "xhigh", "max"]
)
def test_openai_keeps_model_specific_effort_values(tmp_path, effort):
    # This checks forwarding, not availability of every level on every model.
    report = manage.setup(
        setup_args(tmp_path, "--provider", "openai", "--reasoning-effort", effort)
    )
    profile = sources.read_config(tmp_path / "analyst.toml")["profiles"][
        report["execution_profile"]
    ]
    assert resolve(tmp_path, profile).reasoning_effort == effort


def test_explicit_effort_skips_helper_and_unsupported_claude_effort_still_fails(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    with mock.patch("builtins.input", return_value=""):
        manage.setup(
            setup_args(tmp_path, "--provider", "openai", "--reasoning-effort", "low")
        )
    assert "reasoning efforts" not in capsys.readouterr().err
    before = (tmp_path / "analyst.toml").read_bytes()
    with (
        mock.patch("builtins.input", return_value=""),
        pytest.raises(RuntimeError, match="Anthropic reasoning_effort"),
    ):
        manage.setup(
            setup_args(
                tmp_path,
                "--provider",
                "anthropic",
                "--model",
                "claude-sonnet-5",
                "--reasoning-effort",
                "none",
            )
        )
    assert (tmp_path / "analyst.toml").read_bytes() == before


@pytest.mark.parametrize("logged_in", [False, True])
def test_interactive_login_only_runs_when_requested_and_needed(
    tmp_path, monkeypatch, logged_in
):
    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    states = (
        [{"authentication": "verified"}]
        if logged_in
        else [
            {"authentication": "login_required"},
            {"authentication": "verified"},
        ]
    )
    with (
        mock.patch(
            "builtins.input",
            side_effect=lambda prompt: (
                "yes" if prompt.startswith("Check Claude") else ""
            ),
        ),
        mock.patch.object(manage, "claude_auth_status", side_effect=states),
        mock.patch.object(manage, "main", return_value=0) as login,
    ):
        report = manage.setup(
            setup_args(
                tmp_path, "--from-harness", "claude_code", "--model", "test-model"
            )
        )
    assert report["authentication"] == "verified"
    assert report["inference"] == "not_tested"
    if logged_in:
        login.assert_not_called()
    else:
        login.assert_called_once_with("login", ["--harness", "claude_code"])


def test_missing_cli_or_malformed_auth_output_is_not_verified():
    with (
        mock.patch.object(manage.shutil, "which", return_value=None),
        mock.patch.object(manage.subprocess, "run") as run,
    ):
        assert manage.claude_auth_status()["authentication"] == "not_checked"
    run.assert_not_called()
    with (
        mock.patch.object(manage.shutil, "which", return_value="/fake/claude"),
        mock.patch.object(
            manage.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, "SECRET", "SECRET"),
        ),
    ):
        report = manage.claude_auth_status()
    assert report["authentication"] == "not_checked" and "SECRET" not in json.dumps(
        report
    )


def test_failed_native_setup_preserves_saved_profile_and_creates_no_backup(tmp_path):
    manage.setup(setup_args(tmp_path, "--provider", "openai"))
    path = tmp_path / "analyst.toml"
    before = path.read_bytes()
    settings(tmp_path, DESKTOP, "discovered")
    with pytest.raises(RuntimeError, match="configuration file does not exist"):
        manage.setup(
            setup_args(
                tmp_path,
                "--from-harness",
                "claude_code",
                "--harness-config",
                str(tmp_path / "missing.json"),
                "--model",
                "override",
            )
        )
    assert path.read_bytes() == before
    assert not path.with_name(path.name + ".bak").exists()


def test_setup_explicit_path_does_not_inspect_invalid_automatic_location(tmp_path):
    (tmp_path / DESKTOP).mkdir(parents=True)
    custom = settings(tmp_path, "custom.json", "chosen-model")
    report = manage.setup(
        setup_args(
            tmp_path, "--from-harness", "claude_code", "--harness-config", str(custom)
        )
    )
    assert report["status"] == "configured"
    saved = sources.read_config(tmp_path / "analyst.toml")["profiles"]["claude_code"]
    assert saved["source"]["path"] == str(custom)


@pytest.mark.parametrize(
    "payload,code,expected",
    [
        (
            {"loggedIn": True, "authMethod": "claude.ai", "email": "PRIVATE"},
            0,
            "verified",
        ),
        ({"loggedIn": False}, 1, "login_required"),
        ({"loggedIn": True, "authMethod": "api_key"}, 0, "login_required"),
        ({"error": "SECRET"}, 2, "not_checked"),
        ([], 0, "not_checked"),
    ],
)
def test_native_auth_status_is_bounded_and_redacted(payload, code, expected):
    with (
        mock.patch.object(manage.shutil, "which", return_value="/fake/claude"),
        mock.patch.object(
            manage.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], code, json.dumps(payload), "SECRET"
            ),
        ) as run,
    ):
        report = manage.claude_auth_status()
    assert report["authentication"] == expected
    assert "PRIVATE" not in json.dumps(report) and "SECRET" not in json.dumps(report)
    assert run.call_args.args[0] == ["/fake/claude", "auth", "status", "--json"]
    assert run.call_args.kwargs["timeout"] == 10


@pytest.mark.parametrize(
    "failure", [OSError("SECRET"), subprocess.TimeoutExpired("SECRET", 10)]
)
def test_native_auth_failures_are_not_verified(failure):
    with (
        mock.patch.object(manage.shutil, "which", return_value="/fake/claude"),
        mock.patch.object(manage.subprocess, "run", side_effect=failure),
    ):
        report = manage.claude_auth_status()
    assert report["authentication"] == "not_checked"
    assert "SECRET" not in json.dumps(report)


@pytest.mark.parametrize(
    "state,status", [("verified", 0), ("login_required", 1), ("not_checked", 1)]
)
def test_claude_doctor_uses_native_status_only_for_live_checks(tmp_path, state, status):
    selected = resolve(
        tmp_path, {"source": {"kind": "claude_code"}, "model": "test-model"}
    )
    for live in (False, True):
        with (
            mock.patch.object(manage, "resolve_agent_execution", return_value=selected),
            mock.patch.object(manage, "version", return_value="0.2.152"),
            mock.patch.object(
                manage, "claude_auth_status", return_value={"authentication": state}
            ) as auth,
        ):
            report, code = asyncio.run(
                manage.inspect_or_test(
                    "doctor",
                    manage.parser_for("doctor").parse_args(["--live"] if live else []),
                )
            )
        assert code == (status if live else 0)
        assert report["authentication"] == (state if live else "not_checked")
        assert auth.call_count == int(live)
        assert report["inference"] == "not_tested"


def cli(home, *args):
    return subprocess.run(
        [sys.executable, "-m", "vraptor.cli", "ai", *args],
        cwd=home,
        env={"HOME": str(home), "AI_SKILLS_REPO_ROOT": str(home), "PATH": os.defpath},
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    )


@pytest.mark.parametrize(
    "kind,location",
    [
        ("codex", ".codex/config.toml"),
        ("claude_code", DESKTOP),
        ("claude_code", BACKUP),
        ("claude_code", ""),
    ],
)
def test_cli_setup_and_config_use_identical_native_values(tmp_path, kind, location):
    if kind == "codex":
        path = tmp_path / location
        path.parent.mkdir()
        path.write_text('model = "native-model"\n')
    elif location:
        settings(tmp_path, location, "native-model")
    flags = [] if location else ["--model", "native-model"]
    report = json.loads(cli(tmp_path, "setup", "--from-harness", kind, *flags).stdout)
    config = json.loads(cli(tmp_path, "config").stdout)
    assert report["execution_profile"] == kind
    assert config["execution"]["effective"]["model"] == "native-model"
    assert report["authentication"] == "not_checked"


@pytest.mark.parametrize(
    "command", [[], ["setup"], ["config"], ["doctor"], ["models"], ["test"], ["login"]]
)
def test_ai_help_is_accessible_without_config(tmp_path, command):
    output = cli(tmp_path, *command, "--help").stdout
    assert "vraptor ai" in output
    if not command or command == ["setup"]:
        assert "vraptor ai setup --from-harness codex" in output
        assert "vraptor ai setup --from-harness claude_code" in output
        assert "vraptor ai setup --provider anthropic" in output
    if command == ["setup"]:
        assert (
            "OpenAI model examples:" in output
            and "Claude / Anthropic model examples:" in output
        )
        assert "gpt-6-astra" in output and "claude-sonnet-5" in output
        assert (
            "OpenAI reasoning efforts" in output
            and "Claude / Anthropic reasoning efforts" in output
        )
        assert "none, low, medium, high, xhigh, max" in output
        for title in (
            "Profile selection:",
            "Connection and authentication:",
            "Model and execution:",
            "Analysis token budgets:",
        ):
            assert "\n\n" + title in output
    if command == ["config"]:
        assert "Diagnostic route overrides (not saved):" in output
