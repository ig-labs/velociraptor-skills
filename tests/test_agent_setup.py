"""Profile routing and operator commands are tested without external inference."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from unittest import mock

import pytest
from vraptor.agent import manage
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.sources import detect_harness, normalize_document, read_config
from vraptor.analyze.limits import AnalysisLimits


def execution(tmp_path, content="", **env):
    if content:
        (tmp_path / "agents.toml").write_text(content)
        env["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] = str(tmp_path / "agents.toml")
    return resolve_agent_execution(
        repo_root=tmp_path,
        process_environment={"HOME": str(tmp_path), **env},
        allow_missing_credentials=True,
    )


PROFILE = """schema_version = 2
[selection]
default_profile = "local"
[connections.local]
provider = "anthropic"
base_url = "https://api.anthropic.com"
[profiles.local]
connection = "local"
model = "test-model"
model_context_tokens = 32768
model_max_output_tokens = 4096
max_concurrency = 1
"""


def test_profile_and_model_envelope(tmp_path):
    from vraptor.agent.factory import create_agent_runner

    result = execution(tmp_path, PROFILE)
    assert result.provider == "anthropic"
    assert result.auth_mode == "api_key"
    assert result.route.execution_profile == "local"
    limits = AnalysisLimits().for_execution(result)
    assert limits.model_context_tokens == 32768
    assert limits.maximum_input_tokens + limits.maximum_output_tokens <= 32768
    assert (
        limits.maximum_safe_evidence_tokens >= limits.maximum_evidence_tokens_per_item
    )
    assert AnalysisLimits().model_context_tokens == 400000
    assert (
        result.route.identity()
        != replace(result.route, model_context_tokens=16384).identity()
    )
    assert limits.for_execution(result) == limits
    runner = create_agent_runner(
        result, limits=AnalysisLimits().runtime_limits(), client=object()
    )
    assert runner.limits == limits.runtime_limits()
    from vraptor.analyze.runtime import limits_from_plan

    assert (
        limits_from_plan({"analysis_limits": limits.as_dict()})
        == limits.runtime_limits()
    )


def test_environment_precedence_and_credential_isolation(tmp_path):
    result = execution(
        tmp_path,
        PROFILE,
        AI_SKILLS_ANALYST_AGENT_MODEL="override",
        OPENAI_API_KEY="unrelated-secret",
    )
    assert result.model == "override"
    assert result.inputs.api_key == ""
    assert "unrelated-secret" not in json.dumps(result.public_dict())
    assert result.route.field_sources["model"].kind == "process_environment"
    with pytest.raises(RuntimeError, match="conflicts"):
        execution(tmp_path, PROFILE, AI_SKILLS_ANALYST_AGENT_PROVIDER="openai")


@pytest.mark.parametrize(
    "provider,endpoint,auth,key",
    [
        ("openai", "https://api.openai.com/v1/", "api_key", "TEAM_KEY"),
        ("azure_openai", "https://example.openai.azure.com", "api_key", "TEAM_KEY"),
        ("anthropic", "https://api.anthropic.com", "api_key", "TEAM_KEY"),
    ],
)
def test_all_connections_use_explicit_credential_reference(
    tmp_path, provider, endpoint, auth, key
):
    content = PROFILE.replace(
        'provider = "anthropic"',
        f'provider = "{provider}"\nauth_mode = "{auth}"\napi_key_env = "{key}"',
    ).replace("https://api.anthropic.com", endpoint)
    result = execution(
        tmp_path, content, TEAM_KEY="selected-secret", OPENAI_API_KEY="wrong-secret"
    )
    assert result.inputs.api_key == "selected-secret"
    assert "selected-secret" not in repr(result)
    assert "wrong-secret" not in json.dumps(result.public_dict())


@pytest.mark.parametrize(
    "edit",
    [
        lambda x: x.replace("schema_version = 2", "schema_version = 1"),
        lambda x: x + '\napi_key = "secret"\n',
        lambda x: x.replace('connection = "local"', 'connection = "missing"'),
        lambda x: x.replace(
            'connection = "local"', 'connection = "local"\nsource = { kind = "codex" }'
        ),
        lambda x: x.replace("max_concurrency = 1", 'max_concurrency = "1"'),
        lambda x: x.replace(
            "https://api.anthropic.com", "https://user:secret@example.com/v1"
        ),
    ],
)
def test_bad_profiles_fail_without_exposing_values(tmp_path, edit):
    with pytest.raises(RuntimeError) as error:
        execution(tmp_path, edit(PROFILE))
    assert "secret" not in str(error.value)


def test_active_claude_detection_and_application_override(tmp_path):
    settings = tmp_path / ".claude/settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps({"model": "claude-test", "hooks": {"never": "execute"}})
    )
    selected = execution(tmp_path, CLAUDECODE="1")
    assert selected.provider == "anthropic"
    assert selected.protocol == "claude_agent_sdk"
    assert selected.route.detected_harness == "claude_code"
    assert AnalysisLimits().for_execution(selected) == AnalysisLimits()
    default = execution(
        tmp_path, CLAUDECODE="1", AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE="application"
    )
    assert default.provider == "openai"


def test_harness_ambiguity_is_not_guessed():
    with pytest.raises(RuntimeError, match="Ambiguous"):
        detect_harness({"CLAUDECODE": "1", "CODEX_THREAD_ID": "task"})
    assert (
        detect_harness(
            {
                "CLAUDECODE": "1",
                "CODEX_THREAD_ID": "task",
                "AI_SKILLS_ANALYST_AGENT_HARNESS": "codex",
            }
        )
        == "codex"
    )


def test_codex_auto_transport_respects_azure(tmp_path):
    config = tmp_path / ".codex/config.toml"
    config.parent.mkdir()
    config.write_text('model = "test"\n')
    assert execution(tmp_path, CODEX_THREAD_ID="task").protocol == "codex_app_server"
    config.write_text(
        'model = "deployment"\nmodel_provider = "azure"\n[model_providers.azure]\nname = "Azure OpenAI"\nbase_url = "https://example.openai.azure.com/openai/v1"\nenv_key = "AZURE_KEY"\n'
    )
    selected = execution(tmp_path, CODEX_THREAD_ID="task")
    assert selected.provider == "azure_openai"
    assert selected.protocol == "responses"


def test_codex_named_config_file_imports_its_provider_table(tmp_path):
    folder = tmp_path / ".codex"
    folder.mkdir()
    (folder / "config.toml").write_text('model = "base"\n')
    selected = folder / "internal.config.toml"
    selected.write_text(
        'model = "deployment"\nmodel_provider = "azure"\n[model_providers.azure]\nname = "Azure OpenAI"\nbase_url = "https://azure.test/openai/v1"\nenv_key = "CUSTOM_AZURE_KEY"\n'
    )
    result = execution(
        tmp_path,
        AI_SKILLS_ANALYST_AGENT_CODEX_PROFILE="internal",
        CUSTOM_AZURE_KEY="selected-key",
    )
    assert result.model == "deployment" and result.provider == "azure_openai"
    assert result.base_url == "https://azure.test/openai/v1/"
    assert result.inputs.api_key == "selected-key"
    assert result.route.harness_config_path == str(selected)


def test_codex_rejects_removed_ollama_provider(tmp_path):
    config = tmp_path / ".codex/config.toml"
    config.parent.mkdir()
    config.write_text(
        'model = "local-test"\nmodel_provider = "ollama"\n[model_providers.ollama]\nname = "Ollama"\nbase_url = "http://local.test:11434/v1/"\nwire_api = "responses"\n'
    )
    with pytest.raises(
        RuntimeError, match="Unsupported analyst agent provider: ollama"
    ):
        execution(tmp_path, CODEX_THREAD_ID="task", OPENAI_API_KEY="must-not-use")


def test_setup_roundtrip_updates_same_type_with_one_backup(tmp_path):
    path = tmp_path / "configuration.toml"
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "test-model",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
        ]
    )
    with mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True):
        first = manage.setup(args)
        assert first["authentication"] == "not_checked"
        assert first["execution_profile"] == "anthropic"
        assert first["profile_action"] == "added"
        assert first["backup"] == ""
        assert list(tmp_path.iterdir()) == [path]
        document = read_config(path)
        assert normalize_document(document) == document
        assert document["schema_version"] == 2
        assert document["profiles"]["anthropic"]["provider"] == "anthropic"
        assert "connections" not in document and "config_sources" not in document
        assert "execution_profiles" not in document
        before = path.read_bytes()
        args.model = "new-model"
        second = manage.setup(args)
        assert second["profile_action"] == "updated"
        backup = path.with_name(path.name + ".bak")
        assert second["backup"] == str(backup)
        assert backup.read_bytes() == before
        previous = path.read_bytes()
        args.model = "latest-model"
        third = manage.setup(args)
        assert third["backup"] == str(backup)
        assert backup.read_bytes() == previous
        assert read_config(path)["profiles"]["anthropic"]["model"] == "latest-model"
        assert set(tmp_path.iterdir()) == {path, backup}
        assert backup.stat().st_mode & 0o077 == 0
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("failure_target", ["backup", "config"])
def test_setup_write_failure_preserves_current_config_and_cleans_temporary_files(
    tmp_path, monkeypatch, failure_target
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    backup = tmp_path / "agents.toml.bak"
    path.write_text(PROFILE.replace("32768", "200000").replace("4096", "32000"))
    backup.write_text("previous backup")
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "replacement",
            "--model-context-tokens",
            "200000",
            "--execution-profile",
            "local",
            "--config-file",
            str(path),
        ]
    )
    real_replace = manage.os.replace

    def fail_selected_write(source, destination):
        if Path(destination) == (backup if failure_target == "backup" else path):
            raise OSError("simulated write failure")
        return real_replace(source, destination)

    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.replace", side_effect=fail_selected_write),
        pytest.raises(OSError, match="simulated write failure"),
    ):
        manage.setup(args)
    assert path.read_bytes() == before
    assert backup.read_bytes() == (
        b"previous backup" if failure_target == "backup" else before
    )
    assert set(tmp_path.iterdir()) == {path, backup}


def test_setup_codex_source_automatically_preserves_azure_routing(tmp_path):
    source = tmp_path / "codex.toml"
    source.write_text(
        'model = "deployment"\nmodel_provider = "azure"\n[model_providers.azure]\nbase_url = "https://azure.test/openai/v1/"\n'
    )
    path = tmp_path / "agents.toml"
    args = manage.parser_for("setup").parse_args(
        [
            "--from-harness",
            "codex",
            "--execution-profile",
            "codex",
            "--harness-config",
            str(source),
            "--config-file",
            str(path),
        ]
    )
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="") as prompts,
    ):
        manage.setup(args)
    assert prompts.call_count == 6  # Execution settings plus input/output budgets.
    document = read_config(path)
    assert document["profiles"]["codex"]["source"]["kind"] == "codex"
    assert "source = {" in path.read_text()
    result = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert result.provider == "azure_openai" and result.protocol == "responses"


@pytest.mark.parametrize(
    "kind,entry",
    [
        ("codex", "default"),
        ("codex", "absolute"),
        ("codex", "tilde"),
        ("codex", "home_variable"),
        ("codex", "relative"),
        ("claude_code", "default"),
        ("claude_code", "absolute"),
    ],
)
def test_interactive_setup_selects_and_preserves_harness_file(
    tmp_path, monkeypatch, kind, entry
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    default = tmp_path / (
        ".codex/config.toml" if kind == "codex" else ".claude/settings.json"
    )
    custom = default.with_name("custom config" + default.suffix)
    default.parent.mkdir()
    originals = {}
    for source, model in ((default, "default-model"), (custom, "custom-model")):
        content = (
            f'model = "{model}"\n' if kind == "codex" else json.dumps({"model": model})
        )
        source.write_text(content)
        originals[source] = source.read_bytes()
    selected_path = default if entry == "default" else custom
    answer = {
        "default": "",
        "absolute": str(custom),
        "tilde": "~/" + str(custom.relative_to(tmp_path)),
        "home_variable": "${HOME}/" + str(custom.relative_to(tmp_path)),
        "relative": str(custom.relative_to(tmp_path)),
    }[entry]
    path = tmp_path / "agents.toml"
    args = manage.parser_for("setup").parse_args(
        ["--config-file", str(path), "--model-context-tokens", "200000"]
    )
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=[kind, "", answer, "", "", "", "", "", ""]
            + ([""] if kind == "claude_code" else []),
        ) as prompts,
    ):
        manage.setup(args)
    assert prompts.call_count == (10 if kind == "claude_code" else 9)
    assert f"Profile name [{kind}]" in prompts.call_args_list[1].args[0]
    assert f"[{default}]" in prompts.call_args_list[2].args[0]
    assert "Enter for default" in prompts.call_args_list[2].args[0]
    document = read_config(path)
    assert document["profiles"][kind]["source"] == {
        "kind": kind,
        "path": str(selected_path),
    }
    result = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert result.model == ("default-model" if entry == "default" else "custom-model")
    assert result.route.harness_config_path == str(selected_path)
    for source, content in originals.items():
        assert source.read_bytes() == content


def test_non_interactive_codex_setup_uses_default_without_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    source = tmp_path / ".codex/config.toml"
    source.parent.mkdir()
    source.write_text('model = "default-model"\n')
    path = tmp_path / "agents.toml"
    args = manage.parser_for("setup").parse_args(
        ["--from-harness", "codex", "--config-file", str(path)]
    )
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=False),
        mock.patch("builtins.input", side_effect=AssertionError("unexpected prompt")),
    ):
        manage.setup(args)
    assert read_config(path)["profiles"]["codex"]["source"]["path"] == str(source)


def test_missing_custom_harness_file_does_not_replace_existing_profile(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        'schema_version = 2\n[profiles.local]\nsource = { kind = "codex", path = "old.toml" }\n'
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--from-harness",
            "codex",
            "--config-file",
            str(path),
            "--execution-profile",
            "local",
        ]
    )
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=[str(tmp_path / "missing.toml"), "", "", "", "", "", ""],
        ),
        pytest.raises(RuntimeError, match="harness configuration file does not exist"),
    ):
        manage.setup(args)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_doctor_offline_never_constructs_client(tmp_path):
    config = tmp_path / "agents.toml"
    config.write_text(PROFILE)
    args = manage.parser_for("doctor").parse_args(["--config-file", str(config)])
    with (
        mock.patch.dict("os.environ", {"HOME": str(tmp_path)}, clear=True),
        mock.patch(
            "vraptor.agent.manage.resolve_agent_execution",
            return_value=execution(tmp_path, PROFILE, ANTHROPIC_API_KEY="test-only"),
        ),
        mock.patch(
            "vraptor.agent.providers.adapter_for",
            side_effect=AssertionError("provider accessed"),
        ),
    ):
        report, code = asyncio.run(manage.inspect_or_test("doctor", args))
    assert code == 0
    assert report["authentication"] == "not_checked"
    assert report["inference"] == "not_tested"


def test_setup_does_not_mutate_a_connection_shared_by_other_profiles(tmp_path):
    path = tmp_path / "agents.toml"
    path.write_text(
        PROFILE.replace("32768", "200000").replace("4096", "32000")
        + '\n[profiles.second]\nconnection = "local"\nmodel = "other"\n'
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--execution-profile",
            "local",
            "--model",
            "replacement-model",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
        ]
    )
    report = manage.setup(args)
    assert Path(report["backup"]).read_bytes() == before
    document = read_config(path)
    assert document["profiles"]["local"]["model"] == "replacement-model"
    assert document["profiles"]["local"]["provider"] == "anthropic"
    assert document["profiles"]["second"] == {"connection": "local", "model": "other"}
    assert document["connections"]["local"]["base_url"] == "https://api.anthropic.com"


def test_selected_source_is_read_once_and_ignores_authentication_fields(tmp_path):
    source = tmp_path / "codex.toml"
    source.write_text('model = "selected-model"\napi_key = "never-import-this"\n')
    document = f"""schema_version = 2
[selection]
default_profile = "desktop"
[profiles.desktop]
source = {{ kind = "codex", path = {json.dumps(str(source))} }}
"""
    with mock.patch("vraptor.agent.sources.read_config", wraps=read_config) as reads:
        result = execution(tmp_path, document)
    assert result.model == "selected-model"
    assert [call.args[0] for call in reads.call_args_list].count(source) == 1
    assert "never-import-this" not in json.dumps(result.public_dict())


def test_bad_parser_diagnostics_do_not_expose_source_values(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("api_key = secret-value-that-must-not-be-printed")
    with pytest.raises(RuntimeError) as error:
        read_config(path)
    assert "secret-value" not in str(error.value)


@pytest.mark.parametrize("json_format", [False, True])
@pytest.mark.parametrize("oversized", [False, True])
def test_config_reader_enforces_size_boundary(tmp_path, json_format, oversized):
    from vraptor.agent.sources import MAX_CONFIG_BYTES

    path = tmp_path / "config"
    content = b'{"value": 1}' if json_format else b"value = 1\n"
    path.write_bytes(content.ljust(MAX_CONFIG_BYTES + int(oversized), b" "))
    if oversized:
        with pytest.raises(RuntimeError, match="1 MiB size limit"):
            read_config(path, json_format=json_format)
    else:
        assert read_config(path, json_format=json_format) == {"value": 1}


def test_legacy_endpoint_environment_override_beats_profile(tmp_path):
    content = PROFILE.replace('provider = "anthropic"', 'provider = "openai"')
    result = execution(tmp_path, content, OPENAI_BASE_URL="http://selected.test/v1")
    assert result.base_url == "http://selected.test/v1"
    assert result.route.field_sources["base_url"].kind == "process_environment"


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_output_only_model_limit_preserves_shared_context(tmp_path, provider):
    selected = execution(
        tmp_path,
        AI_SKILLS_ANALYST_AGENT_PROVIDER=provider,
        AI_SKILLS_ANALYST_AGENT_MODEL="test-model",
        AI_SKILLS_ANALYST_AGENT_MODEL_MAX_OUTPUT_TOKENS="512",
    )
    bounded = AnalysisLimits().for_execution(selected)
    assert bounded.maximum_output_tokens == 512
    assert bounded.operational_context_tokens == 360000
    assert bounded.maximum_input_tokens == 272000


def test_environment_rejects_removed_ollama_provider(tmp_path):
    with pytest.raises(
        RuntimeError, match="Unsupported analyst agent provider: ollama"
    ):
        execution(
            tmp_path,
            AI_SKILLS_ANALYST_AGENT_PROVIDER="ollama",
            AI_SKILLS_ANALYST_AGENT_MODEL="local-model",
        )


@pytest.mark.parametrize("provider", ["openai", "azure_openai", "anthropic"])
@pytest.mark.parametrize("narrow", [False, True])
def test_factory_preserves_valid_caller_budgets(tmp_path, provider, narrow):
    from vraptor.agent.factory import create_agent_runner
    from vraptor.agent.runtime import AgentRuntimeLimits

    selected = execution(
        tmp_path,
        AI_SKILLS_ANALYST_AGENT_PROVIDER=provider,
        AI_SKILLS_ANALYST_AGENT_MODEL="test-model",
        AI_SKILLS_ANALYST_AGENT_BASE_URL="https://model.test/v1/",
        AI_SKILLS_ANALYST_AGENT_MODEL_CONTEXT_TOKENS="800000",
        AI_SKILLS_ANALYST_AGENT_MODEL_MAX_OUTPUT_TOKENS="100000",
    )
    requested = (
        AgentRuntimeLimits(16384, 16000, 12000, 4000, "cl100k_base")
        if narrow
        else AgentRuntimeLimits(800000, 390000, 300000, 90000, "o200k_base")
    )
    runner = create_agent_runner(selected, limits=requested, client=object())
    assert runner.limits == requested


def test_synthetic_check_uses_bounded_request_and_no_persistent_files(tmp_path):
    from types import SimpleNamespace

    selected = execution(tmp_path, PROFILE, ANTHROPIC_API_KEY="test-only")
    args = manage.parser_for("test").parse_args([])
    fake = mock.Mock()
    fake.run = mock.AsyncMock(
        return_value=SimpleNamespace(
            status="succeeded", output="READY", usage={}, error_classification=""
        )
    )
    fake.close = mock.AsyncMock()
    with (
        mock.patch(
            "vraptor.agent.manage.resolve_agent_execution", return_value=selected
        ),
        mock.patch(
            "vraptor.agent.factory.create_agent_runner", return_value=fake
        ) as factory,
    ):
        report, code = asyncio.run(manage.inspect_or_test("test", args))
    assert code == 0 and report["inference"] == "passed"
    assert factory.call_args.args[0].max_concurrency == 1
    assert factory.call_args.args[0].max_retries == 0
    assert factory.call_args.kwargs["persist_runtime_files"] is False
    assert fake.run.call_args.args[0].max_output_tokens == 256
    assert not fake.run.call_args.kwargs["output_dir"].exists()
    fake.close.assert_awaited_once()
