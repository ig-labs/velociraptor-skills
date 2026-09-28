"""Operational credential sources reach analysts without mutating process state."""
import json
import os
import shlex
from unittest import mock

import pytest

from vraptor import cli, paths, settings
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.providers import AzureOpenAIResponsesAdapter
from vraptor.agent.runtime import TimeoutPolicy
from vraptor.analyze.limits import resolve_analysis_limits


@pytest.fixture
def configured(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setattr(os, "environ", {"HOME": str(home), "PATH": os.defpath})
    monkeypatch.setattr("vraptor.resources.repository_root", lambda: repo)
    shared = home / ".codex/.env"
    shared.parent.mkdir()
    shared.write_text("TEST_ANALYST_KEY=shared-secret\nAI_SKILLS_ANALYST_AGENT_MODEL=shared-model\n")
    (repo / ".env").write_text("TEST_ANALYST_KEY=repository-secret\nAI_SKILLS_ANALYST_AGENT_MODEL=repository-model\n")
    analyst = home / "analyst.toml"
    analyst.write_text('''schema_version = 2
[selection]
default_profile = "first"
[profiles.first]
provider = "openai"
transport = "api"
model = "first-model"
api_key_env = "TEST_ANALYST_KEY"
[profiles.second]
provider = "openai"
transport = "api"
model = "second-model"
api_key_env = "TEST_ANALYST_KEY"
''')
    selected = home / "credentials.env"
    selected.write_text(
        f"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE={analyst}\n"
        "AI_SKILLS_ANALYST_AGENT_PROFILE=second\n"
        "AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE=application\n"
        "AI_SKILLS_ANALYST_AGENT_MODEL=selected-model\n"
        "AI_SKILLS_MAX_OUTPUT_TOKENS=41000\n"
        "TEST_ANALYST_KEY=selected-secret\n"
    )
    config = home / "operational.toml"
    config.write_text('schema_version = 1\n[credentials]\nenv_file="credentials.env"\n')
    return repo, config, selected


def test_selected_environment_reaches_profile_credentials_and_limits(configured):
    repo, config, selected = configured
    before = dict(os.environ)
    snapshot = settings.resolve(config_file=config, repo_root=repo)
    with settings.activate(snapshot):
        execution = resolve_agent_execution(repo_root=repo)
        limits = resolve_analysis_limits(execution=execution)
    assert execution.inputs.api_key == "selected-secret"
    assert execution.model == "selected-model"
    assert execution.route.execution_profile == "second"
    assert execution.route.field_sources["credential"].kind == "selected_dotenv"
    assert execution.route.field_sources["credential"].location == str(selected)
    assert limits.maximum_output_tokens == 41000
    assert limits.provenance_dict()["maximum_output_tokens"]["kind"] == "selected_dotenv"
    assert dict(os.environ) == before
    assert "selected-secret" not in repr(snapshot)
    assert "selected-secret" not in json.dumps(snapshot.public_dict())


@pytest.mark.parametrize("process_key,expected,kind", [
    ("process-secret", "process-secret", "process_environment"),
    ("", "selected-secret", "selected_dotenv"),
])
def test_nonempty_process_values_win_and_empty_values_fall_back(configured, monkeypatch, process_key, expected, kind):
    repo, config, _ = configured
    monkeypatch.setenv("TEST_ANALYST_KEY", process_key)
    monkeypatch.setenv("AI_SKILLS_ANALYST_AGENT_MODEL", "process-model")
    monkeypatch.setenv("AI_SKILLS_MAX_OUTPUT_TOKENS", "")
    with settings.activate(settings.resolve(config_file=config, repo_root=repo)):
        execution = resolve_agent_execution(repo_root=repo)
        assert execution.model == "process-model"
        assert execution.inputs.api_key == expected
        assert execution.route.field_sources["credential"].kind == kind
        assert resolve_analysis_limits(execution=execution).maximum_output_tokens == 41000
        explicit = resolve_agent_execution(repo_root=repo, cli_values={"model": "cli-model"})
        assert explicit.model == "cli-model"


def test_empty_selected_secret_falls_back_to_repository(configured):
    repo, config, selected = configured
    selected.write_text(selected.read_text().replace("TEST_ANALYST_KEY=selected-secret", "TEST_ANALYST_KEY="))
    with settings.activate(settings.resolve(config_file=config, repo_root=repo)):
        execution = resolve_agent_execution(repo_root=repo)
    assert execution.inputs.api_key == "repository-secret"
    assert execution.route.field_sources["credential"].kind == "repository_dotenv"


def test_snapshot_preserves_environment_layers_after_files_change(configured, monkeypatch):
    repo, config, selected = configured
    snapshot = settings.resolve(config_file=config, repo_root=repo)
    selected.unlink()
    (repo / ".env").unlink()
    monkeypatch.setattr(paths, "read_dotenv_file", lambda _: pytest.fail("Must reuse frozen environment layers"))
    with settings.activate(snapshot.select("transient-server")):
        assert resolve_agent_execution(repo_root=repo).inputs.api_key == "selected-secret"
        assert resolve_analysis_limits().maximum_output_tokens == 41000


def test_launcher_derived_environment_is_not_reclassified_as_process(configured, monkeypatch):
    repo, config, _ = configured
    monkeypatch.setenv(paths.ORIGINAL_PROCESS_ENV_KEYS, "HOME\nPATH")
    monkeypatch.setenv("TEST_ANALYST_KEY", "launcher-repository-value")
    monkeypatch.setenv("AI_SKILLS_ANALYST_AGENT_MODEL", "launcher-repository-model")
    with settings.activate(settings.resolve(config_file=config, repo_root=repo)):
        execution = resolve_agent_execution(repo_root=repo)
    assert execution.inputs.api_key == "selected-secret"
    assert execution.model == "selected-model"
    assert execution.route.field_sources["credential"].kind == "selected_dotenv"


def test_agent_config_cli_honors_operational_env_file_without_secret_output(configured, capsys):
    _, config, _ = configured
    assert cli.main(["agent", "config", "--settings-file", str(config)]) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["execution"]["effective"]["execution_profile"] == "second"
    assert payload["credentials"][0]["present"]
    assert payload["credentials"][0]["source"]["kind"] == "selected_dotenv"
    assert "selected-secret" not in output


def test_defaults_cli_remains_independent_of_operational_configuration(capsys):
    with mock.patch.object(settings, "resolve", side_effect=AssertionError("Defaults must not load settings")):
        assert cli.main(["agent", "config", "--view", "defaults"]) == 0
    assert json.loads(capsys.readouterr().out)["view"] == "defaults"


@pytest.mark.parametrize("override", [None, "dotenv", "process", "cli"])
def test_operational_analyst_reference_and_inspection_command(configured, monkeypatch, capsys, override):
    repo, config, selected = configured
    # Keep credentials and profile selection in the existing credential source.
    selected.write_text("\n".join(line for line in selected.read_text().splitlines()
                                  if not line.startswith("AI_SKILLS_ANALYST_AGENT_CONFIG_FILE=")) + "\n")
    original = config.parent / "analyst.toml"
    reference = config.parent / "referenced analyst.toml"
    reference.write_text(original.read_text())
    config.write_text(config.read_text() + '\n[analyst]\nconfig_file="referenced analyst.toml"\n')
    expected = reference
    if override in {"dotenv", "process"}:
        selected.write_text(selected.read_text() + f"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE={original}\n")
        expected = original
    if override == "process":
        expected = config.parent / "process.toml"
        expected.write_text(original.read_text())
        monkeypatch.setenv("AI_SKILLS_ANALYST_AGENT_CONFIG_FILE", str(expected))
    before = dict(os.environ)
    snapshot = settings.resolve(config_file=config, repo_root=repo)
    assert snapshot.environment["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] == str(expected)
    with settings.activate(snapshot):
        execution = resolve_agent_execution(repo_root=repo, cli_values={"config_file": str(original)} if override == "cli" else None)
    assert execution.route.config_file == str(original if override == "cli" else expected)
    assert execution.inputs.api_key == "selected-secret"

    assert cli.main(["setup", "show", "--settings-file", str(config)]) == 0
    output = capsys.readouterr().out
    reference_info = json.loads(output)["analyst_agent"]
    assert reference_info["config_file"] == str(expected)
    assert "selected-secret" not in output
    assert cli.main(shlex.split(reference_info["inspect_command"])[1:]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["execution"]["effective"]["config_file"] == str(expected)
    assert inspected["credentials"][0]["present"]
    assert dict(os.environ) == before


def test_missing_operational_analyst_reference_is_reported_without_blocking_setup(configured, capsys):
    repo, config, selected = configured
    selected.write_text("")
    config.write_text('schema_version=1\n[analyst]\nconfig_file="missing.toml"\n')
    snapshot = settings.resolve(config_file=config, repo_root=repo)
    assert snapshot.public_dict()["analyst_agent"]["exists"] is False
    with settings.activate(snapshot), pytest.raises(RuntimeError, match="Selected analyst configuration file does not exist"):
        resolve_agent_execution(repo_root=repo)


def azure_profile(config):
    (config.parent / "analyst.toml").write_text('''schema_version = 2
[selection]
default_profile = "second"
[profiles.second]
provider = "azure_openai"
transport = "api"
model = "deployment"
base_url = "https://example.openai.azure.com/openai/v1/"
auth_mode = "entra"
''')


@pytest.mark.parametrize("source", ["selected", "repository"])
def test_entra_service_principal_uses_frozen_dotenv_credentials(configured, source):
    repo, config, selected = configured
    azure_profile(config)
    credentials = selected if source == "selected" else repo / ".env"
    credentials.write_text(credentials.read_text() +
        "AZURE_TENANT_ID=tenant-id\nAZURE_CLIENT_ID=client-id\nAZURE_CLIENT_SECRET=entra-secret\n")
    before = dict(os.environ)
    with settings.activate(settings.resolve(config_file=config, repo_root=repo)):
        execution = resolve_agent_execution(repo_root=repo)
    credentials.unlink()
    with mock.patch("azure.identity.aio.ClientSecretCredential") as principal, \
         mock.patch("azure.identity.aio.DefaultAzureCredential") as ambient, \
         mock.patch("azure.identity.aio.get_bearer_token_provider", return_value="token-provider") as token, \
         mock.patch("openai.AsyncOpenAI") as sdk:
        AzureOpenAIResponsesAdapter(execution, TimeoutPolicy(1, 2, 3, 2))._build_client()
    principal.assert_called_once_with(tenant_id="tenant-id", client_id="client-id", client_secret="entra-secret")
    ambient.assert_not_called()
    token.assert_called_once_with(principal.return_value, "https://cognitiveservices.azure.com/.default")
    assert sdk.call_args.kwargs["api_key"] == "token-provider"
    assert execution.route.credential_binding.mode == "azure_client_secret"
    assert execution.route.field_sources["credential"].kind == source + "_dotenv"
    assert "entra-secret" not in repr(execution)
    assert "entra-secret" not in json.dumps(execution.public_dict())
    assert dict(os.environ) == before
    with pytest.raises(TypeError):
        execution.inputs.azure_client_secret["client_secret"] = "changed"


def test_partial_service_principal_fails_without_identity_fallback(configured):
    repo, config, selected = configured
    azure_profile(config)
    selected.write_text(selected.read_text() + "AZURE_CLIENT_SECRET=entra-secret\n")
    with settings.activate(settings.resolve(config_file=config, repo_root=repo)), \
         pytest.raises(RuntimeError, match="AZURE_TENANT_ID") as error:
        resolve_agent_execution(repo_root=repo)
    assert "entra-secret" not in str(error.value)
