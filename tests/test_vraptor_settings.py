import argparse
import json
import os
from pathlib import Path
import shlex
import stat

import pytest

from vraptor import paths, settings


@pytest.fixture
def workstation(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setattr(os, "environ", {"HOME": str(home), "PATH": os.defpath})
    monkeypatch.setattr("vraptor.resources.repository_root", lambda: repo)
    paths.load_repo_env.cache_clear()
    yield home, repo
    paths.load_repo_env.cache_clear()


def config(home, text):
    path = home / ".config/vraptor/config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("schema_version = 1\n" + text)
    return path


def test_default_xdg_paths_and_environment_unchanged(workstation):
    home, repo = workstation
    original = dict(os.environ)
    snapshot = settings.resolve(repo_root=repo)
    assert snapshot.values["case_root"] == str(home / "cases")
    assert snapshot.values["velociraptor_bin"] == str(home / "velociraptor/velociraptor")
    assert "runtime_root" not in snapshot.values
    assert snapshot.config_file == home / ".config/vraptor/config.toml"
    assert dict(os.environ) == original
    with pytest.raises(TypeError):
        snapshot.values["case_root"] = "changed"
    snapshot = settings.resolve(repo_root=repo, process_environment={"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"), "XDG_STATE_HOME": str(home / "state")})
    assert snapshot.config_file == home / "config/vraptor/config.toml"
    assert "runtime_root" not in snapshot.values


def test_precedence_and_credentials_are_hidden(workstation):
    home, repo = workstation
    (home / ".codex").mkdir()
    (home / ".codex/.env").write_text("CASE_ROOT=~/shared\nAPI_SECRET=shared-secret\n")
    (repo / ".env").write_text("CASE_ROOT=~/repository\nAPI_SECRET=repo-secret\n")
    (home / "credentials.env").write_text("CASE_ROOT=~/selected\nAPI_SECRET=selected-secret\n")
    path = config(home, '[workstation]\ncase_root="~/configured"\n[credentials]\nenv_file="~/credentials.env"\n')
    snapshot = settings.resolve(repo_root=repo, config_file=path)
    assert snapshot.values["case_root"] == str(home / "selected")
    assert snapshot.environment["API_SECRET"] == "selected-secret"
    assert "selected-secret" not in repr(snapshot)
    assert "API_SECRET" not in json.dumps(snapshot.public_dict())
    snapshot = settings.resolve(repo_root=repo, process_environment={"HOME": str(home), "CASE_ROOT": "~/process", "API_SECRET": "process-secret"})
    assert snapshot.values["case_root"] == str(home / "process")
    assert snapshot.environment["API_SECRET"] == "process-secret"
    snapshot = settings.resolve(repo_root=repo, overrides={"case_root": str(home / "explicit")})
    assert snapshot.values["case_root"] == str(home / "explicit")
    assert snapshot.sources["case_root"] == "command_line"


def test_snapshot_reused_without_rereading_or_mutation(workstation, monkeypatch):
    home, repo = workstation
    path = config(home, '[workstation]\ncase_root="~/configured"\n[connections.lab]\napi_client="../lab.yaml"\nclient_config="../client.yaml"\n')
    snapshot = settings.resolve(repo_root=repo)
    path.unlink()
    before = dict(os.environ)
    monkeypatch.setattr(paths, "read_dotenv_file", lambda _: pytest.fail("Snapshot must not reread dotenv"))
    with settings.activate(snapshot):
        assert paths.default_case_root(repo) == home / "configured"
        assert paths.resolve_velociraptor_api_client_path(None, repo, server_profile="lab") == home / ".config/lab.yaml"
        assert paths.resolve_velociraptor_client_config_path(None, repo, server_profile="lab") == home / ".config/client.yaml"
        assert paths.load_repo_env(repo)["CASE_ROOT"] == str(home / "configured")
        assert paths.resolve_case_root(str(home / "explicit"), repo) == home / "explicit"
    assert settings.current() is None
    assert dict(os.environ) == before


def test_snapshot_active_context_is_nested(workstation):
    home, repo = workstation
    first = settings.resolve(repo_root=repo, overrides={"case_root": str(home / "first")})
    second = settings.resolve(repo_root=repo, overrides={"case_root": str(home / "second")})
    with settings.activate(first):
        with settings.activate(second):
            assert paths.default_case_root(repo) == home / "second"
        assert paths.default_case_root(repo) == home / "first"


def test_named_connection_preserves_legacy_filename_selection(workstation):
    home, repo = workstation
    (repo / ".env").write_text("VELO_LOCAL_API_CLIENT=~/local.yaml\n")
    with settings.activate(settings.resolve("lab", repo_root=repo)):
        assert paths.resolve_velociraptor_api_client_path(None, repo, server_profile="lab") == home / ".config/velociraptor/lab_api_client.yaml"
    config(home, '[connections.lab]\napi_client="~/saved.yaml"\n')
    with settings.activate(settings.resolve("lab", repo_root=repo)):
        assert paths.resolve_velociraptor_api_client_path(None, repo, server_profile="lab") == home / "local.yaml"


def test_connection_defaults_do_not_leak_across_profiles(workstation):
    home, repo = workstation
    config(home, '[connections.one]\napi_client="~/one.yaml"\n[connections.two]\napi_client="~/two.yaml"\n')
    snapshot = settings.resolve("one", repo_root=repo)
    assert snapshot.value("api_client", "two") == str(home / "two.yaml")
    assert snapshot.value("api_client", "unknown") is None


def test_command_override_does_not_contaminate_other_cached_connections(workstation):
    home, repo = workstation
    config(home, '[connections.one]\napi_client="~/one.yaml"\n[connections.two]\napi_client="~/two.yaml"\n')
    snapshot = settings.resolve("one", repo_root=repo,
                                overrides={"api_client": str(home / "explicit.yaml"), "api_user": "selected-user"})
    assert snapshot.values["api_client"] == str(home / "explicit.yaml")
    assert snapshot.value("api_client", "two") == str(home / "two.yaml")
    other = snapshot.select("two")
    assert other.values["api_client"] == str(home / "two.yaml")
    assert other.values["api_user"] == "vraptor"
    assert "api_client" not in snapshot.select("unknown").values
    assert other.environment["VELO_REMOTE_API_USER"] == "vraptor"


def test_unselected_command_override_applies_only_when_explicitly_passed_to_selected_profile(workstation):
    home, repo = workstation
    config(home, '[connections.lab]\napi_client="~/lab.yaml"\n')
    snapshot = settings.resolve(repo_root=repo, overrides={"api_client": str(home / "explicit.yaml")})
    assert snapshot.values["api_client"] == str(home / "explicit.yaml")
    assert snapshot.select("lab").values["api_client"] == str(home / "lab.yaml")
    assert snapshot.select("lab", {"api_client": str(home / "explicit.yaml")}).values["api_client"] == str(home / "explicit.yaml")


def test_valid_cli_overrides_invalid_lower_priority_environment(workstation):
    home, repo = workstation
    environment = {"HOME": str(home), "VELO_REMOTE_API_ROLE_PROFILE": "invalid-role",
                   "VELO_MAPPED_CLIENT_POLL_SECONDS": "invalid-number"}
    snapshot = settings.resolve("lab", repo_root=repo, process_environment=environment,
                                overrides={"api_role_profile": "investigation", "poll_seconds": 15})
    assert snapshot.values["api_role_profile"] == "investigation"
    assert snapshot.values["poll_seconds"] == 15
    with pytest.raises(ValueError, match="api_role_profile"):
        snapshot.select("another")


def test_select_saved_profile_uses_one_snapshot_and_discards_previous_connection_environment(workstation):
    home, repo = workstation
    path = config(home, '[connections.one]\napi_client="~/one.yaml"\nssh_user="one-user"\n[connections.two]\napi_client="~/two.yaml"\n')
    snapshot = settings.resolve("one", repo_root=repo)
    path.unlink()
    selected = snapshot.select("two")
    assert selected.values["api_client"] == str(home / "two.yaml")
    assert "ssh_user" not in selected.values
    assert "VELO_REMOTE_SSH_USER" not in selected.environment
    assert snapshot.environment["VELO_REMOTE_SSH_USER"] == "one-user"
    override = selected.select("unknown", {"api_client": str(home / "saved.yaml")})
    assert override.environment["VELO_LOCAL_API_CLIENT"] == str(home / "saved.yaml")
    assert "api_client" not in selected.select("unknown").values


def test_select_unknown_profile_avoids_generic_local_api_override(workstation):
    home, repo = workstation
    (repo / ".env").write_text("VELO_LOCAL_API_CLIENT=~/local.yaml\nVELO_REMOTE_API_USER=operator\n")
    selected = settings.resolve(repo_root=repo).select("new")
    assert "api_client" not in selected.values
    assert selected.values["api_user"] == "operator"


@pytest.mark.parametrize("text", [
    'mystery = "bad"', '[workstation]\nbinary = false',
    '[workstation]\nsecret = "must-not-print"', '[mapping]\npoll_seconds = 0',
    '[connections.lab]\napi_role_profile="wrong"', '[local_server]\napi_port=65536',
    '[connections."../bad"]\napi_client="api.yaml"', '[credentials]\nenv_file=""',
])
def test_invalid_schema_fails_without_echoing_values(workstation, text):
    home, repo = workstation
    config(home, text)
    with pytest.raises(ValueError) as error:
        settings.resolve(repo_root=repo)
    assert "must-not-print" not in str(error.value)


def test_explicit_missing_config_and_credentials_fail(workstation):
    home, repo = workstation
    with pytest.raises(FileNotFoundError):
        settings.resolve(config_file=home / "missing.toml", repo_root=repo)
    config(home, '[credentials]\nenv_file="missing.env"\n')
    with pytest.raises(ValueError, match="credential env file does not exist"):
        settings.resolve(repo_root=repo)


def test_offline_resolution_tolerates_missing_credentials_but_preserves_available_layers(workstation):
    home, repo = workstation
    path = config(home, '[credentials]\nenv_file="~/credentials.env"\n')
    (repo / ".env").write_text("CASE_ROOT=~/repository\n")
    snapshot = settings.resolve(repo_root=repo, require_credentials=False)
    assert snapshot.values["case_root"] == str(home / "repository")
    assert snapshot.environment_layers.selected is None
    (home / "credentials.env").write_text("CASE_ROOT=~/selected\n")
    snapshot = settings.resolve(repo_root=repo, require_credentials=False)
    assert snapshot.values["case_root"] == str(home / "selected")
    assert snapshot.environment_layers.selected is not None
    path.write_text("malformed TOML = [")
    with pytest.raises(ValueError, match="Invalid TOML"):
        settings.resolve(repo_root=repo, require_credentials=False)


def test_dotenv_does_not_execute_or_import_dangerous_keys(workstation):
    home, repo = workstation
    (home / "creds.env").write_text('API_SECRET="$(touch SENTINEL)"\nPYTHONPATH=evil\nPATH=evil\n')
    config(home, '[credentials]\nenv_file="~/creds.env"\n')
    snapshot = settings.resolve(repo_root=repo)
    assert snapshot.environment["API_SECRET"] == "$(touch SENTINEL)"
    assert "PYTHONPATH" not in snapshot.environment
    assert snapshot.environment["PATH"] == os.defpath


def test_apply_keeps_explicit_and_sets_supported_unset_fields(workstation):
    home, repo = workstation
    snapshot = settings.resolve(repo_root=repo)
    args = argparse.Namespace(case_root="/explicit", velociraptor_bin=None)
    snapshot.apply(args)
    assert args.case_root == "/explicit"
    assert args.velociraptor_bin == str(home / "velociraptor/velociraptor")
    assert not hasattr(args, "runtime_root")


def test_migration_preview_and_write_preserve_secrets_and_existing_values(workstation, capsys):
    home, repo = workstation
    path = config(home, '[workstation]\ncase_root="~/old"\n[connections.other]\napi_client="~/other.yaml"\n')
    before = path.read_text()
    (repo / ".env").write_text("CASE_ROOT=~/new\nVELO_REMOTE_SSH_USER=operator\nAPI_SECRET=do-not-persist\n")
    assert settings.main(["migrate", "--server-profile", "lab"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["written"] is False
    assert preview["conflicts_preserved"] == ["workstation.case_root"]
    assert path.read_text() == before
    settings.main(["migrate", "--server-profile", "lab", "--write"])
    output = capsys.readouterr().out
    assert "do-not-persist" not in output + path.read_text()
    assert settings.read(path)["connections"]["other"]["api_client"] == "~/other.yaml"
    assert settings.read(path)["connections"]["lab"]["ssh_user"] == "operator"
    assert path.with_name(path.name + ".bak").read_text() == before
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_configure_materializes_relative_template_paths_and_rotates_one_backup(workstation, capsys):
    home, repo = workstation
    template = repo / "example.toml"
    template.write_text('schema_version=1\n[connections.lab]\napi_client="./api.yaml"\n[credentials]\nenv_file="./secret.env"\n')
    (repo / "secret.env").touch()
    target = home / "custom/settings.toml"
    settings.main(["configure", "--settings-file", str(target), "--template", str(template)])
    capsys.readouterr()
    configured = settings.read(target)
    assert configured["connections"]["lab"]["api_client"] == str(repo / "api.yaml")
    assert configured["credentials"]["env_file"] == str(repo / "secret.env")
    for suffix in ("first", "second"):
        settings.main(["configure", "--settings-file", str(target), "--case-root", str(home / suffix)])
        capsys.readouterr()
    assert list(target.parent.glob("*.bak")) == [target.with_name(target.name + ".bak")]
    assert settings.read(target)["workstation"]["case_root"] == str(home / "second")


def test_configure_preview_does_not_write(workstation, capsys):
    home, _ = workstation
    settings.main(["configure", "--case-root", str(home / "new"), "--preview"])
    assert json.loads(capsys.readouterr().out)["written"] is False
    assert not settings.default_path().exists()


def test_configure_normalizes_relative_cli_paths_before_saving(workstation, monkeypatch, capsys):
    home, repo = workstation
    monkeypatch.chdir(repo)
    (repo / "credentials.env").touch()
    settings.main(["configure", "--case-root", "cases", "--velociraptor-bin", "./bin/velociraptor",
                   "--server-profile", "lab", "--api-client", "./lab.yaml",
                   "--client-config", "./endpoint.yaml", "--ssh-key", "./key",
                   "--env-file", "./credentials.env"])
    capsys.readouterr()
    monkeypatch.chdir(home)
    result = settings.resolve("lab", repo_root=repo)
    for name, suffix in (("case_root", "cases"), ("velociraptor_bin", "bin/velociraptor"),
                         ("api_client", "lab.yaml"), ("client_config", "endpoint.yaml"),
                         ("ssh_key", "key"), ("env_file", "credentials.env")):
        assert result.values[name] == str(repo / suffix)


def test_configure_normalizes_prompted_paths(workstation, monkeypatch, capsys):
    home, repo = workstation
    monkeypatch.chdir(repo)
    (repo / "credentials.env").touch()
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    answers = {"Investigation parent": "./cases", "Preferred local Velociraptor binary path": "./velociraptor",
               "Optional saved server name": "lab", "Existing local API-client YAML path": "./lab.yaml",
               "Optional credential .env path": "./credentials.env"}
    monkeypatch.setattr("builtins.input", lambda prompt: next((answer for label, answer in answers.items() if prompt.startswith(label)), ""))
    settings.main(["configure"])
    capsys.readouterr()
    monkeypatch.chdir(home)
    result = settings.resolve("lab", repo_root=repo)
    assert result.values["case_root"] == str(repo / "cases")
    assert result.values["api_client"] == str(repo / "lab.yaml")
    assert result.values["env_file"] == str(repo / "credentials.env")


@pytest.mark.parametrize("profile", [None, "lab"])
def test_interactive_remote_settings_are_saved_in_selected_scope(workstation, monkeypatch, capsys, profile):
    from vraptor import cli
    home, repo = workstation
    monkeypatch.chdir(repo)
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    answers = {
        "Remote API username": "vraptor_operator",
        "Remote API role profile": "investigation",
        "Configure remote SSH": "yes",
        "Remote SSH login username": "operator",
        "Local SSH private-key path": "./ssh-key",
        "Velociraptor server YAML path": "/srv/velo/server.yaml",
        "Endpoint-client YAML path on": "/srv/velo/client.yaml",
        "Velociraptor binary path on": "/usr/bin/velociraptor",
        "Remote account used": "velociraptor",
        "Remote server address": "192.0.2.10",
        "Velociraptor organization ID": "O.lab",
        "Existing local API-client": "./api.yaml",
        "API credential YAML path": "/srv/velo/api.yaml",
    }
    prompts = []
    def answer(prompt):
        prompts.append(prompt)
        return next((value for label, value in answers.items() if prompt.startswith(label)), "")
    monkeypatch.setattr("builtins.input", answer)
    assert cli.main(["setup", "configure", *(["--server-profile", profile] if profile else [])]) == 0
    output = capsys.readouterr()
    document = json.loads(output.out)["configuration"]
    connection = document["connections"][profile] if profile else document["connection_defaults"]
    assert connection["api_user"] == "vraptor_operator"
    assert connection["api_role_profile"] == "investigation"
    assert connection["ssh_key"] == str(repo / "ssh-key")
    assert connection["ssh_user"] == "operator"
    assert connection["server_config"] == "/srv/velo/server.yaml"
    assert connection["remote_client_config"] == "/srv/velo/client.yaml"
    assert connection["remote_bin"] == "/usr/bin/velociraptor"
    assert connection["run_as"] == "velociraptor"
    if profile:
        assert not any(p.startswith("Optional saved server name") for p in prompts)
        assert connection["server_ip"] == "192.0.2.10"
        assert connection["org_id"] == "O.lab"
        assert connection["api_client"] == str(repo / "api.yaml")
        assert connection["remote_api_config"] == "/srv/velo/api.yaml"
    else:
        assert "connections" not in document
    for title in ("Workstation", "Remote connection", "Remote SSH access", "Local server", "Mapped evidence", "Advanced paths and API transport", "Credentials"):
        assert f"\n{title}\n" in output.err
    assert "To configure AI, run: vraptor ai setup" in output.err


def test_interactive_local_and_mapped_settings_validate_and_preview(workstation, monkeypatch, capsys):
    from vraptor import cli
    home, repo = workstation
    path = config(home, '[connections.lab]\napi_user="vraptor_operator"\n')
    original = path.read_bytes()
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    ports = iter(["invalid", "70000", "9000"])
    answers = {
        "Configure local server": "yes", "Configure mapped-evidence": "yes",
        "Configure advanced local": "yes", "Local server API username": "local-user",
        "Local server API port": "9001", "Local server GUI port": "9002",
        "Existing local endpoint-client": "~/endpoint.yaml",
        "Mapped-client startup timeout": "300", "Mapped-client readiness timeout": "60",
        "Mapped-client health polling": "20", "Mapped-client stale threshold": "700",
        "Mapped-client consecutive": "4", "Mapped-client maximum restarts": "6",
        "Mapped-client restart window": "800", "Local Velociraptor configuration": "~/configs",
        "Optional runtime directory": "~/runtime", "API maximum gRPC": "1048576",
    }
    def answer(prompt):
        if prompt.startswith("Local server frontend port"):
            return next(ports)
        return next((value for label, value in answers.items() if prompt.startswith(label)), "")
    monkeypatch.setattr("builtins.input", answer)
    assert cli.main(["setup", "configure", "--server-profile", "lab", "--preview"]) == 0
    output = capsys.readouterr()
    payload = json.loads(output.out)
    doc = payload["configuration"]
    assert doc["local_server"] == {"api_user": "local-user", "frontend_port": 9000, "api_port": 9001, "gui_port": 9002}
    assert doc["mapping"] == {"startup_timeout_seconds": 300, "ready_timeout_seconds": 60,
        "poll_seconds": 20, "stale_seconds": 700, "failure_threshold": 4, "max_restarts": 6, "restart_window_seconds": 800}
    assert doc["connections"]["lab"]["client_config"] == str(home / "endpoint.yaml")
    assert doc["connections"]["lab"]["api_user"] == "vraptor_operator"
    assert doc["workstation"]["config_root"] == str(home / "configs")
    assert doc["workstation"]["runtime_root"] == str(home / "runtime")
    assert doc["api"]["grpc_max_message_bytes"] == 1048576
    assert "requires an integer" in output.err and "at most 65535" in output.err
    assert payload["written"] is False
    assert path.read_bytes() == original


def test_interactive_blank_remote_fields_preserve_saved_paths_and_other_profiles(workstation, monkeypatch, capsys):
    from vraptor import cli
    home, repo = workstation
    path = config(home, '[connection_defaults]\nssh_user="operator"\n[connections.lab]\napi_user="vraptor_operator"\napi_client="~/api.yaml"\nserver_config="/srv/server.yaml"\n[connections.other]\nserver_ip="192.0.2.20"\n')
    original = settings.read(path)
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes" if prompt.startswith("Configure remote SSH") else "")
    assert cli.main(["setup", "configure", "--server-profile", "lab"]) == 0
    capsys.readouterr()
    saved = settings.read(path)
    assert saved["connections"] == original["connections"]
    assert saved["connection_defaults"]["ssh_user"] == "operator"


def test_templates_share_valid_generic_schema():
    root = Path(__file__).resolve().parents[1]
    for name in ("vraptor.example.toml",):
        settings.read(root / "config" / name, required=True)


@pytest.mark.parametrize("section", ["connection_defaults", "connections.lab"])
@pytest.mark.parametrize("interactive", [False, True])
def test_configure_preserves_saved_api_user(workstation, monkeypatch, capsys, section, interactive):
    from vraptor import cli

    home, repo = workstation
    path = config(home, f'[{section}]\napi_user="vraptor_operator"\napi_role_profile="investigation"\n')
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: interactive)
    prompts = []
    def answer(prompt):
        prompts.append(prompt)
        return "lab" if prompt.startswith("Optional saved server name") else ""
    monkeypatch.setattr("builtins.input", answer)
    flags = [] if interactive else ["--server-profile", "lab"]
    assert cli.main(["setup", "configure", *flags]) == 0
    capsys.readouterr()
    if interactive:
        assert "Remote API username [vraptor_operator]: " in prompts
    resolved = settings.resolve("lab", repo_root=repo)
    assert resolved.values["api_user"] == "vraptor_operator"
    assert resolved.values["api_role_profile"] == "investigation"
    assert settings.read(path)[section.split('.')[0]]


@pytest.mark.parametrize("interactive", [False, True])
def test_configure_writes_default_remote_identity(workstation, monkeypatch, capsys, interactive):
    from vraptor import cli

    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: interactive)
    prompts = []
    def answer(prompt):
        prompts.append(prompt)
        return ""
    monkeypatch.setattr("builtins.input", answer)
    assert cli.main(["setup", "configure"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["configuration"]["connection_defaults"] == {
        "api_user": "vraptor", "api_role_profile": "provisioning-admin"}
    assert ("Remote API username [vraptor]: " in prompts) == interactive


def test_configure_explicit_identity_targets_defaults_or_named_profile(workstation, capsys):
    settings.main(["configure", "--api-user", "vraptor_operator", "--api-role-profile", "investigation"])
    capsys.readouterr()
    settings.main(["configure", "--server-profile", "lab", "--api-user", "named"])
    capsys.readouterr()
    document = settings.read(settings.default_path())
    assert document["connection_defaults"] == {"api_user": "vraptor_operator", "api_role_profile": "investigation"}
    assert document["connections"]["lab"] == {"api_user": "named"}


@pytest.mark.parametrize("level", ["default", "connection_defaults", "named", "shared", "repository", "selected", "process", "cli"])
def test_connection_identity_precedence_and_sources(workstation, level):
    home, repo = workstation
    levels = ["default", "connection_defaults", "named", "shared", "repository", "selected", "process", "cli"]
    rank = levels.index(level)
    text = ''
    expected_user, expected_role, source = "vraptor", "provisioning-admin", "default"
    path = settings.default_path()
    if rank >= 1:
        text += '[connection_defaults]\napi_user="vraptor_operator"\napi_role_profile="investigation"\n'
        expected_user, expected_role, source = "vraptor_operator", "investigation", f"{path}:connection_defaults"
    if rank >= 2:
        text += '[connections.lab]\napi_user="named"\napi_role_profile="provisioning-admin"\n'
        expected_user, expected_role, source = "named", "provisioning-admin", f"{path}:connections.lab"
    for index, label, dotenv in ((3, "shared", home / ".codex/.env"),
                                (4, "repository", repo / ".env"),
                                (5, "selected", home / "credentials.env")):
        if rank >= index:
            dotenv.parent.mkdir(parents=True, exist_ok=True)
            dotenv.write_text(f"VELO_REMOTE_API_USER={label}\nVELO_REMOTE_API_ROLE_PROFILE=investigation\n")
            expected_user, expected_role, source = label, "investigation", f"environment:{dotenv}"
    if rank >= 5:
        text += '[credentials]\nenv_file="~/credentials.env"\n'
    environment = dict(os.environ)
    if rank >= 6:
        environment.update(VELO_REMOTE_API_USER="process", VELO_REMOTE_API_ROLE_PROFILE="provisioning-admin")
        expected_user, expected_role, source = "process", "provisioning-admin", "environment:process"
    overrides = None
    if rank == 7:
        overrides = {"api_user": "cli", "api_role_profile": "investigation"}
        expected_user, expected_role, source = "cli", "investigation", "command_line"
    config(home, text)
    result = settings.resolve("lab", repo_root=repo, process_environment=environment, overrides=overrides)
    for key, expected in (("api_user", expected_user), ("api_role_profile", expected_role)):
        assert result.values[key] == expected
        suffix = (":" + settings.SCHEMA["connections"][key][1]) if source.startswith("environment:") else "." + key
        assert result.sources[key] == (source if source in {"default", "command_line"} else source + suffix)


def test_cli_show_new_profile_inherits_defaults_with_sources(workstation, capsys):
    from vraptor import cli

    home, repo = workstation
    path = config(home, '[connection_defaults]\napi_user="vraptor_operator"\napi_role_profile="provisioning-admin"\n'
                        '[connections.default]\napi_user="not-inherited"\n')
    assert cli.main(["setup", "show", "--server-profile", "new-profile"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["values"]["api_user"] == "vraptor_operator"
    assert shown["values"]["api_role_profile"] == "provisioning-admin"
    for key in ("api_user", "api_role_profile"):
        assert shown["sources"][key] == f"{path}:connection_defaults.{key}"
    snapshot = settings.resolve("default", repo_root=repo)
    assert snapshot.value("api_user", "another-new-profile") == "vraptor_operator"


@pytest.mark.parametrize("entries", [{"server_ip": "192.0.2.1"}, {"api_user": ""}, {"api_role_profile": "administrator"}])
def test_connection_defaults_validation(entries):
    with pytest.raises(ValueError):
        settings.validate({"schema_version": 1, "connection_defaults": entries})


def test_configure_analyst_reference_and_compact_show(workstation, monkeypatch, capsys):
    home, repo = workstation
    monkeypatch.chdir(repo)
    analyst = repo / "analyst settings.toml"
    analyst.write_text("not TOML; do-not-print-this")
    assert settings.main(["configure", "--analyst-config-file", "analyst settings.toml"]) == 0
    configured = json.loads(capsys.readouterr().out)
    assert configured["configuration"]["analyst"] == {"config_file": str(analyst)}
    assert settings.main(["show"]) == 0
    output = capsys.readouterr().out
    shown = json.loads(output)["analyst_agent"]
    assert set(shown) == {"config_file", "exists", "inspect_command"}
    assert shown["config_file"] == str(analyst)
    assert shown["exists"] is True
    assert shlex.split(shown["inspect_command"]) == [
        "vraptor", "ai", "config", "--settings-file", configured["config_file"],
        "--config-file", str(analyst),
    ]
    assert "do-not-print-this" not in output
    assert settings.resolve(repo_root=repo).environment["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] == str(analyst)


def test_show_missing_default_analyst_config_keeps_inspection_optional(workstation):
    home, repo = workstation
    snapshot = settings.resolve(repo_root=repo, process_environment={
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")})
    assert snapshot.public_dict()["analyst_agent"] == {
        "config_file": str(home / "config/vraptor/analyst-agents.toml"),
        "exists": False, "inspect_command": "vraptor ai config",
    }


@pytest.mark.parametrize("source", ["default", "toml", "environment"])
def test_prep_and_runtime_use_the_same_binary(workstation, monkeypatch, source):
    from types import SimpleNamespace
    from vraptor import cli

    home, repo = workstation
    expected = home / "velociraptor/velociraptor"
    if source != "default":
        config(home, '[workstation]\nbinary="~/custom tools/velo"\n')
        expected = home / "custom tools/velo"
    if source == "environment":
        monkeypatch.setenv("VELO_BIN", "~/override/velociraptor")
        expected = home / "override/velociraptor"

    def run(command, *, env, check):
        assert command[-2:] == ["-t", "velociraptor"]
        assert env["VELO_BIN"] == str(expected)
        assert paths.resolve_velociraptor_binary(None, repo) == str(expected)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli.main(["tools", "prep", "-t", "velociraptor"]) == 0
