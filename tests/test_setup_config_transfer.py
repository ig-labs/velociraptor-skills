"""Settings transfer round trips without moving credentials or wiping other state."""
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from vraptor import cli, paths, settings, setup_config


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


def test_export_reset_deploy_round_trip(workstation, capsys):
    home, repo = workstation
    target = settings.default_path()
    target.parent.mkdir(parents=True)
    target.write_text('schema_version=1\n[workstation]\nbinary="~/custom/velo"\n'
                      '[connection_defaults]\napi_user="vraptor_operator"\napi_role_profile="provisioning-admin"\n'
                      '[credentials]\nenv_file="../secrets.env"\n'
                      '[connections.lab]\napi_user="named"\napi_role_profile="investigation"\nssh_user="operator"\nssh_key="~/key"\n'
                      'server_ip="server.example"\nremote_api_config="/root/api.yaml"\n'
                      '[connections.second]\napi_client="../second.yaml"\n')
    credentials = home / ".config/secrets.env"
    credentials.write_text('CASE_ROOT=~/custom-cases\nAPI_SECRET=never-export-this\n')
    snapshot = home / "snapshots/current.toml"
    command = ["--repo-root", str(repo)]
    assert cli.main(["setup", "export", *command, "--output", str(snapshot)]) == 0
    exported = settings.read(snapshot)
    assert exported["workstation"]["binary"] == "~/custom/velo"
    assert exported["workstation"]["case_root"] == "~/custom-cases"
    assert exported["connections"]["second"]["api_client"] == "~/.config/second.yaml"
    assert exported["connections"]["lab"]["remote_api_config"] == "/root/api.yaml"
    assert exported["connection_defaults"] == {"api_user": "vraptor_operator", "api_role_profile": "provisioning-admin"}
    assert exported["connections"]["lab"]["api_user"] == "named"
    assert "api_user" not in exported["connections"]["second"]
    assert "never-export-this" not in snapshot.read_text()
    assert snapshot.stat().st_mode & 0o777 == 0o600
    before = target.read_bytes()
    assert cli.main(["setup", "reset", *command]) == 0
    assert target.read_bytes() == before
    assert cli.main(["setup", "reset", *command, "--apply"]) == 0
    assert credentials.read_text() == "API_SECRET=never-export-this\n"
    assert "connections" not in settings.read(target)
    assert "connection_defaults" not in settings.read(target)
    reset_content = target.read_bytes()
    assert cli.main(["setup", "deploy", *command, "--from", str(snapshot)]) == 0
    assert target.read_bytes() == reset_content
    assert cli.main(["setup", "deploy", *command, "--from", str(snapshot), "--apply"]) == 0
    deployed = settings.resolve("lab", repo_root=repo)
    assert deployed.values["case_root"] == str(home / "custom-cases")
    assert deployed.values["velociraptor_bin"] == str(home / "custom/velo")
    assert deployed.values["remote_api_config"] == "/root/api.yaml"
    assert deployed.values["api_user"] == "named"
    assert deployed.values["api_role_profile"] == "investigation"
    assert deployed.select("new-profile").values["api_user"] == "vraptor_operator"
    assert deployed.environment["API_SECRET"] == "never-export-this"
    assert "never-export-this" not in capsys.readouterr().out
    assert cli.main(["setup", "deploy", *command, "--from", str(snapshot), "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["written"] is False


def test_deploy_preserves_other_settings_and_rebases_paths(workstation, capsys):
    home, repo = workstation
    source = home / "export/current.toml"
    source.parent.mkdir()
    source.write_text('schema_version=1\n[connections.lab]\napi_client="api.yaml"\n')
    target = settings.default_path()
    target.parent.mkdir(parents=True)
    original = 'schema_version=1\n[analyst]\nconfig_file="../analyst.toml"\n[connections.other]\nssh_user="keep"\n'
    target.write_text(original)
    assert cli.main(["setup", "deploy", "--repo-root", str(repo), "--from", str(source), "--apply"]) == 0
    result = json.loads(capsys.readouterr().out)
    deployed = settings.read(target)
    assert deployed["connections"]["lab"]["api_client"] == str(source.parent / "api.yaml")
    assert deployed["connections"]["other"]["ssh_user"] == "keep"
    assert deployed["analyst"]["config_file"] == "../analyst.toml"
    backup = Path(result["backup_directory"])
    assert (backup / "00-config.toml").read_text() == original


def test_export_is_exclusive_and_environment_connection_requires_name(workstation):
    home, repo = workstation
    snapshot = home / "snapshot.toml"
    os.environ["VELO_LOCAL_ORG_ID"] = "O.lab"
    assert cli.main(["setup", "export", "--repo-root", str(repo), "--output", str(snapshot)]) == 1
    assert not snapshot.exists()
    assert cli.main(["setup", "export", "--repo-root", str(repo), "--server-profile", "lab", "--output", str(snapshot)]) == 0
    original = snapshot.read_bytes()
    assert cli.main(["setup", "export", "--repo-root", str(repo), "--output", str(snapshot), "--server-profile", "lab"]) == 1
    assert snapshot.read_bytes() == original


@pytest.mark.parametrize("source", ['schema_version=1\n[credentials]\napi_key="secret"', 'schema_version="malformed-secret'])
def test_invalid_snapshot_preserves_active_settings(workstation, source, capsys):
    home, repo = workstation
    snapshot = home / "snapshot.toml"
    snapshot.write_text(source)
    target = settings.default_path()
    target.parent.mkdir(parents=True)
    target.write_text('schema_version=1\n')
    assert cli.main(["setup", "deploy", "--repo-root", str(repo), "--from", str(snapshot), "--apply"]) == 1
    assert target.read_text() == 'schema_version=1\n'
    assert "malformed-secret" not in capsys.readouterr().err


def test_export_reads_settings_once_and_default_binary_is_explicit(workstation, monkeypatch):
    home, repo = workstation
    read = Mock(wraps=settings.read)
    monkeypatch.setattr(settings, "read", read)
    assert cli.main(["setup", "export", "--repo-root", str(repo), "--output", str(home / "snapshot.toml")]) == 0
    assert read.call_count == 1
    assert paths.resolve_velociraptor_binary(None, repo) == str(home / "velociraptor/velociraptor")
