"""Offline integration checks for shared live/mapped connection options."""
import argparse
import json
import os
from pathlib import Path
import shlex
import tomllib
from unittest.mock import Mock

import pytest
import yaml

from vraptor import api, cli, paths, query, readiness, readiness_state, settings, setup_config


@pytest.fixture
def workstation(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "environ", {"HOME": str(tmp_path), "PATH": os.defpath})
    monkeypatch.setattr("vraptor.resources.repository_root", lambda: tmp_path)
    paths.load_repo_env.cache_clear()
    yield tmp_path
    paths.load_repo_env.cache_clear()


def write_settings(root, document):
    path = root / ".config/vraptor/config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(settings.render({"schema_version": 1, **document}))
    return path


def test_example_env_preserves_saved_settings(workstation):
    root = workstation
    example = Path(__file__).resolve().parents[1] / "config" / "example.env"
    (root / ".env").write_text(example.read_text())
    write_settings(root, {
        "workstation": {"case_root": "~/custom-cases"},
        "connection_defaults": {"api_user": "vraptor_operator", "api_role_profile": "investigation",
                                "ssh_user": "operator", "ssh_key": "~/private-key"},
        "connections": {"lab": {"org_id": "O.lab"}},
        "mapping": {"poll_seconds": 37, "startup_timeout_seconds": 300, "ready_timeout_seconds": 90},
        "api": {"grpc_max_message_bytes": 1048576},
    })
    snapshot = settings.resolve("lab", repo_root=root)
    assert snapshot.values["api_user"] == "vraptor_operator"
    assert snapshot.values["api_role_profile"] == "investigation"
    assert snapshot.values["ssh_user"] == "operator"
    assert snapshot.values["case_root"] == str(root / "custom-cases")
    assert snapshot.values["poll_seconds"] == 37
    assert snapshot.values["org_id"] == "O.lab"
    assert snapshot.values["grpc_max_message_bytes"] == 1048576


@pytest.mark.parametrize("level", ["defaults", "named", "dotenv", "environment", "cli"])
def test_shared_ssh_settings_precedence_and_paths(workstation, monkeypatch, level):
    root = workstation
    shared = {"ssh_user": "shared", "ssh_key": "../shared.key", "server_config": "/etc/shared.yaml",
              "remote_client_config": "/etc/client.yaml", "remote_bin": "/opt/velociraptor", "run_as": "service"}
    document = {"connection_defaults": shared}
    rank = ["defaults", "named", "dotenv", "environment", "cli"].index(level)
    expected, source = "shared", "connection_defaults.ssh_user"
    if rank >= 1:
        document["connections"] = {"lab": {"ssh_user": "named"}}
        expected, source = "named", "connections.lab.ssh_user"
    if rank >= 2:
        (root / ".env").write_text("VELO_REMOTE_SSH_USER=dotenv\n")
        expected, source = "dotenv", ".env:VELO_REMOTE_SSH_USER"
    if rank >= 3:
        monkeypatch.setenv("VELO_REMOTE_SSH_USER", "environment")
        expected, source = "environment", "environment:process:VELO_REMOTE_SSH_USER"
    flags = {"ssh_user": "cli"} if rank == 4 else None
    if flags:
        expected, source = "cli", "command_line"
    write_settings(root, document)
    snapshot = settings.resolve("lab", repo_root=root, overrides=flags)
    assert snapshot.values["ssh_user"] == expected
    assert snapshot.sources["ssh_user"].endswith(source)
    assert snapshot.values["ssh_key"] == str(root / ".config/shared.key")
    for key in ("server_config", "remote_client_config", "remote_bin", "run_as"):
        assert snapshot.values[key] == shared[key]


def test_new_options_transfer_and_reset(workstation):
    root = workstation
    path = write_settings(root, {
        "connection_defaults": {"ssh_key": "~/key", "ssh_user": "shared", "run_as": "service"},
        "connections": {"lab": {"org_id": "O.lab", "ssh_user": "named"}},
        "api": {"grpc_max_message_bytes": 1048576},
        "mapping": {"startup_timeout_seconds": 300, "ready_timeout_seconds": 90},
    })
    exported = setup_config.export_document(settings.resolve("lab", repo_root=root))
    assert exported["connection_defaults"]["ssh_key"] == "~/key"
    assert exported["connections"]["lab"] == {"org_id": "O.lab", "ssh_user": "named"}
    source = root / "export.toml"
    source.write_text(settings.render(exported))
    target = root / "new.toml"
    _, content, changes = setup_config.deploy_document(source, target)
    target.write_text(content)
    resolved = settings.resolve("lab", config_file=target, repo_root=root)
    assert resolved.values["grpc_max_message_bytes"] == 1048576
    assert resolved.values["startup_timeout_seconds"] == 300
    assert resolved.values["ready_timeout_seconds"] == 90
    assert resolved.values["org_id"] == "O.lab"
    assert resolved.select("new-profile").values["ssh_user"] == "shared"
    assert changes
    planned = setup_config.plan(path, root, [])
    assert planned[0].after is None


@pytest.mark.parametrize("section,key", [("api", "grpc_max_message_bytes"),
                                         ("mapping", "startup_timeout_seconds"),
                                         ("mapping", "ready_timeout_seconds")])
@pytest.mark.parametrize("invalid", [0, -1, True, "bad", 1.5])
def test_new_numeric_options_reject_invalid_values(section, key, invalid):
    with pytest.raises(ValueError):
        settings.validate({"schema_version": 1, section: {key: invalid}})


def test_grpc_limit_rejects_integer_overflow():
    with pytest.raises(ValueError):
        settings.validate({"schema_version": 1, "api": {"grpc_max_message_bytes": 2**31}})


@pytest.mark.parametrize("level", ["toml", "dotenv", "environment", "cli"])
def test_query_cli_uses_selected_org_and_grpc_limit(workstation, monkeypatch, capsys, level):
    root = workstation
    api_path = root / "api.yaml"
    api_path.touch()
    config = write_settings(root, {"connections": {"lab": {"org_id": "O.toml"}},
                                   "api": {"grpc_max_message_bytes": 1048576}})
    rank = ["toml", "dotenv", "environment", "cli"].index(level)
    expected_org, expected_limit = "O.toml", 1048576
    if rank >= 1:
        (root / ".env").write_text("VELO_LOCAL_ORG_ID=O.dotenv\nVELO_GRPC_MAX_MESSAGE_BYTES=2097152\n")
        expected_org, expected_limit = "O.dotenv", 2097152
    if rank >= 2:
        monkeypatch.setenv("VELO_LOCAL_ORG_ID", "O.environment")
        monkeypatch.setenv("VELO_GRPC_MAX_MESSAGE_BYTES", "3145728")
        expected_org, expected_limit = "O.environment", 3145728
    flags = []
    if rank == 3:
        flags = ["--org-id", "O.cli", "--grpc-max-message-bytes", "4194304"]
        expected_org, expected_limit = "O.cli", 4194304
    seen = []
    class FakeApi:
        def __init__(self, path, org_id):
            seen.append((org_id, api.grpc_max_message_bytes()))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def query_batches(self, *_, **__):
            yield [{"ok": True}]
    monkeypatch.setattr(query, "VeloApiClient", FakeApi)
    assert cli.main(["query", "--server-profile", "lab", "--settings-file", str(config),
                     "--api-client", str(api_path), "--vql", "SELECT 1 AS ok FROM scope()", *flags]) == 0
    json.loads(capsys.readouterr().out)
    assert seen == [(expected_org, expected_limit)]


def test_api_transport_and_metadata_share_settings(workstation, monkeypatch):
    root = workstation
    api_path = root / "api.yaml"
    api_path.write_text(yaml.safe_dump({"name": "operator", "org_id": "root", "ca_certificate": "ca",
                                       "client_cert": "cert", "client_private_key": "key",
                                       "api_connection_string": "server.invalid:8001"}))
    write_settings(root, {"connections": {"lab": {"org_id": "O.lab"}},
                         "api": {"grpc_max_message_bytes": 1048576}})
    channel = Mock()
    monkeypatch.setattr(api.grpc, "ssl_channel_credentials", Mock())
    secure_channel = Mock(return_value=channel)
    monkeypatch.setattr(api.grpc, "secure_channel", secure_channel)
    monkeypatch.setattr(api.api_pb2_grpc, "APIStub", Mock())
    snapshot = settings.resolve("lab", repo_root=root)
    with settings.activate(snapshot):
        with api.VeloApiClient(api_path) as client:
            assert client.org_id == "O.lab"
        assert readiness_state.api_metadata(api_path)["org_id"] == "O.lab"
        assert api.VeloApiClient(api_path, org_id="root").org_id == "root"
    options = dict(secure_channel.call_args.args[2])
    assert options["grpc.max_receive_message_length"] == 1048576
    assert options["grpc.max_send_message_length"] == 1048576


def test_ready_timeout_uses_snapshot_and_explicit_override(workstation, monkeypatch):
    write_settings(workstation, {"mapping": {"ready_timeout_seconds": 3}})
    monkeypatch.setattr(readiness, "mapped_client_status", lambda *_: {"state": "starting"})
    monkeypatch.setattr(readiness.time, "sleep", lambda _: None)
    for explicit, expected in ((None, 3), (1, 1)):
        ticks = iter([0, expected])
        monkeypatch.setattr(readiness.time, "monotonic", lambda: next(ticks))
        with settings.activate(settings.resolve(repo_root=workstation)):
            with pytest.raises(RuntimeError, match=f"within {expected} seconds"):
                readiness.wait_for_mapped_client_ready(workstation, "host", timeout_seconds=explicit)


@pytest.mark.parametrize("custom", [False, True])
def test_configure_prints_actionable_ai_setup_note(workstation, monkeypatch, capsys, custom):
    from vraptor.agent import manage
    run = Mock(side_effect=AssertionError("Setup must not run the AI wizard implicitly"))
    monkeypatch.setattr(manage, "main", run)
    flags = ["--settings-file", str(workstation / "custom settings.toml")] if custom else []
    assert cli.main(["setup", "configure", "--case-root", str(workstation / "cases"), *flags]) == 0
    output = capsys.readouterr()
    json.loads(output.out)
    command = shlex.split(output.err.strip().removeprefix("To configure AI, run: "))
    assert command == ["vraptor", "ai", "setup", *flags]
    run.assert_not_called()


@pytest.mark.parametrize("answer,preview,status", [("", False, 0), ("no", False, 0), ("yes", True, 0), ("y", False, 0), ("yes", False, 1)])
def test_interactive_configure_optionally_runs_ai_setup_after_save(workstation, monkeypatch, capsys, answer, preview, status):
    from vraptor.agent import manage
    path = workstation / "custom settings.toml"
    path.write_text(settings.render({"schema_version": 1, "analyst": {"config_file": "chosen-ai.toml"}}))
    original = path.read_bytes()
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    prompts = []
    def respond(prompt):
        prompts.append(prompt)
        if prompt.startswith("Configure AI analyst settings"):
            return answer
        if prompt.startswith("Investigation parent"):
            return str(workstation / "new-cases")
        return ""
    monkeypatch.setattr("builtins.input", respond)
    def launch(command, argv):
        assert command == "setup" and argv == []
        assert settings.read(path)["workstation"]["case_root"] == str(workstation / "new-cases")
        assert settings.current().config_file == path
        assert settings.active_value("analyst_config_file") == str(workstation / "chosen-ai.toml")
        print('{"ai_setup": "result"}')
        return status
    wizard = Mock(side_effect=launch)
    monkeypatch.setattr(manage, "main", wizard)
    result = cli.main(["setup", "configure", "--settings-file", str(path), *(["--preview"] if preview else [])])
    output = capsys.readouterr()
    assert "Configure AI analyst settings [y/N]: " in prompts
    assert "\nAI analyst configuration\n" in output.err
    json.loads(output.out)  # AI wizard output must not append a second JSON document.
    selected = answer in {"y", "yes"} and not preview
    assert wizard.call_count == int(selected)
    assert result == (status if selected else 0)
    if preview:
        assert path.read_bytes() == original
        assert "AI setup was not started" in output.err
    if selected:
        assert '"ai_setup": "result"' in output.err
    if selected and status:
        assert "Operational settings remain saved" in output.err


def test_interactive_configure_runs_real_ai_wizard_with_saved_path(workstation, monkeypatch, capsys):
    from vraptor.agent import manage
    analyst_path = workstation / "profiles" / "analyst.toml"
    path = write_settings(workstation, {"analyst": {"config_file": str(analyst_path)}})
    monkeypatch.setattr(settings.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(manage.os, "isatty", lambda _: True)
    monkeypatch.setattr(manage, "REPO_ROOT", workstation)
    def answer(prompt):
        if prompt.startswith("Configure AI analyst settings"):
            return "yes"
        if prompt.startswith("Connection ("):
            return "openai"
        if prompt.startswith("Model ID"):
            return "test-model"
        return ""
    monkeypatch.setattr("builtins.input", answer)
    assert cli.main(["setup", "configure", "--settings-file", str(path)]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["config_file"] == str(path)
    document = tomllib.loads(analyst_path.read_text())
    profile = document["profiles"][document["selection"]["default_profile"]]
    assert profile["provider"] == "openai"
    assert profile["model"] == "test-model"
    assert str(analyst_path) in output.err
    assert not (workstation / ".config/vraptor/analyst-agents.toml").exists()


@pytest.mark.parametrize("namespace", ["ai", "agent"])
def test_ai_and_aliases_dispatch_existing_setup(workstation, monkeypatch, namespace):
    from vraptor.agent import manage
    wizard = Mock(return_value=0)
    monkeypatch.setattr(manage, "main", wizard)
    assert cli.main([namespace, "setup"]) == 0
    wizard.assert_called_once_with("setup", [])


@pytest.mark.parametrize("namespace", ["ai", "agent"])
def test_ai_defaults_and_help_use_canonical_name(workstation, capsys, namespace):
    # Defaults inspection must work even when operational TOML is invalid.
    path = workstation / ".config/vraptor/config.toml"
    path.parent.mkdir(parents=True)
    path.write_text("invalid TOML")
    assert cli.main([namespace, "config", "--view", "defaults"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), dict)
    assert cli.main([namespace, "--help"]) == 0
    assert "Usage: vraptor ai " in capsys.readouterr().out


def test_native_readiness_uses_selected_organization(workstation, monkeypatch):
    write_settings(workstation, {"connections": {"lab": {"org_id": "O.lab"}}})
    monkeypatch.setattr(readiness, "local_binary", lambda: "velociraptor")
    run = Mock(return_value=argparse.Namespace(returncode=0, stdout='[{"ok": true}]'))
    monkeypatch.setattr(readiness, "run_command", run)
    with settings.activate(settings.resolve("lab", repo_root=workstation)):
        assert readiness.local_query(workstation / "api.yaml", "SELECT 1 AS ok FROM scope()") == [{"ok": True}]
    assert run.call_args.args[0][:3] == ["velociraptor", "--org", "O.lab"]


@pytest.mark.parametrize("view", [[], ["--view", "effective"]])
@pytest.mark.parametrize("file_flag", ["--settings-file", "--config-file"])
def test_operational_config_matches_setup_show(workstation, capsys, view, file_flag):
    path = write_settings(workstation, {
        "connection_defaults": {"api_user": "saved-user"},
        "connections": {"lab": {"api_user": "profile-user", "org_id": "O.lab"}},
    })
    original = path.read_bytes()
    flags = ["--server", "lab", "--api-user", "explicit-user"]
    assert cli.main(["config", *view, file_flag, str(path), *flags]) == 0
    effective = json.loads(capsys.readouterr().out)
    assert effective.pop("view") == "effective"
    assert cli.main(["setup", "show", "--settings-file", str(path), *flags]) == 0
    assert effective == json.loads(capsys.readouterr().out)
    assert effective["values"]["api_user"] == "explicit-user"
    assert effective["sources"]["api_user"] == "command_line"
    assert effective["values"]["org_id"] == "O.lab"
    assert path.read_bytes() == original


@pytest.mark.parametrize("view", [["--view", "defaults"], ["--view=defaults"]])
def test_operational_defaults_ignore_files_environment_and_resolver(workstation, monkeypatch, capsys, view):
    path = write_settings(workstation, {})
    path.write_text("invalid TOML")
    (workstation / ".env").write_text("VELO_REMOTE_API_USER=dotenv-user\n")
    monkeypatch.setenv("VELO_REMOTE_API_USER", "environment-user")
    monkeypatch.setattr(settings, "resolve", Mock(side_effect=AssertionError("Defaults must not resolve local state")))
    assert cli.main(["config", *view]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["view"] == "defaults"
    assert payload["values"]["api_user"] == "vraptor"
    assert payload["values"]["velociraptor_bin"] == "~/velociraptor/velociraptor"
    assert set(payload["sources"].values()) == {"default"}
    assert str(workstation) not in json.dumps(payload)
    assert path.read_text() == "invalid TOML"


@pytest.mark.parametrize("flags", [["--api-user", "override"], ["--settings-file", "missing.toml"], ["--server", "lab"]])
def test_operational_defaults_reject_overrides(workstation, capsys, flags):
    with pytest.raises(SystemExit) as exc:
        cli.main(["config", "--view", "defaults", *flags])
    assert exc.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err


@pytest.mark.parametrize("command,script", [("fetch-api", "fetch_live_api_client.sh"), ("fetch-client", "fetch_live_client_config.sh")])
def test_operational_config_preserves_explicit_fetch_routes(workstation, monkeypatch, command, script):
    from vraptor import legacy_cli
    bootstrap = Mock(return_value=0)
    monkeypatch.setattr(legacy_cli, "run_bootstrap", bootstrap)
    assert cli.main(["config", command, "--server-profile", "lab"]) == 0
    bootstrap.assert_called_once_with(script, ["--server-profile", "lab"])
