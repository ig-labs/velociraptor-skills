import json
import os
from pathlib import Path

import pytest

from vraptor import setup_config as reset

@pytest.fixture
def workspace(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    settings = home / "config/vraptor/config.toml"
    settings.parent.mkdir(parents=True)
    settings.write_text('schema_version = 1\n[credentials]\nenv_file = "../secrets.env"\n')
    selected = home / "config/secrets.env"
    selected.write_text('VELO_REMOTE_API_USER=old-user\nAZURE_OPENAI_API_KEY=secret-selected\n')
    shared = home / ".codex/.env"
    shared.parent.mkdir()
    shared.write_text('VELO_REMOTE_SSH_KEY=/old/key\nSLACK_USER_TOKEN=secret-shared\n')
    dotenv = repo / ".env"
    dotenv.write_bytes(b'# keep\r\nexport VELO_BIN = old\r\nVELO_BIN=duplicate\r\n'
                       b'AI_SKILLS_ANALYST_AGENT_MODEL=chosen\r\nVELO_LOCAL_API_PASSWORD=secret-password\r\n'
                       b'VELO_AUTORUNS_GOLDEN_DB=/keep/db\r\nKEEP=$(never-execute)\r\n')
    return home, repo, settings, selected, shared, dotenv


def test_preview_apply_and_repeat_preserve_secrets_and_exact_backups(workspace, monkeypatch, capsys):
    home, repo, settings, selected, shared, dotenv = workspace
    monkeypatch.setenv("VELO_BIN", "secret-process-value")
    originals = {path: path.read_bytes() for path in (settings, selected, shared, dotenv)}
    untouched = [home / "cases/case01/engagement.json", home / "cases/case01/runtime/writeback.yaml",
                 home / "config/velociraptor/api_client.yaml", home / "config/vraptor/analyst-agents.toml"]
    for path in untouched:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("unchanged")
    args = ["--repo-root", str(repo)]
    assert reset.reset_main(args) == 0
    result = capsys.readouterr()
    preview = json.loads(result.out)
    assert preview["mode"] == "preview"
    assert "VELO_BIN" in preview["shell_unset"]
    assert "secret-" not in result.out + result.err
    assert {path: path.read_bytes() for path in originals} == originals
    assert not (home / "config/vraptor/backups").exists()
    assert not (home / "state").exists()

    assert reset.reset_main([*args, "--apply"]) == 0
    result = capsys.readouterr()
    applied = json.loads(result.out)
    backup = Path(applied["backup_directory"])
    assert backup.parent == home / "config/vraptor/backups"
    assert not (home / "state").exists()
    assert backup.stat().st_mode & 0o777 == 0o700
    for item in json.loads((backup / "manifest.json").read_text())["files"]:
        copied = backup / item["backup"]
        assert copied.read_bytes() == originals[Path(item["original"])]
        assert copied.stat().st_mode & 0o777 == 0o600
    assert settings.read_text() == 'schema_version = 1\n\n[credentials]\nenv_file = "../secrets.env"\n'
    assert dotenv.read_bytes() == (b'# keep\r\nAI_SKILLS_ANALYST_AGENT_MODEL=chosen\r\n'
                                  b'VELO_LOCAL_API_PASSWORD=secret-password\r\n'
                                  b'VELO_AUTORUNS_GOLDEN_DB=/keep/db\r\nKEEP=$(never-execute)\r\n')
    assert shared.read_text() == 'SLACK_USER_TOKEN=secret-shared\n'
    assert selected.read_text() == 'AZURE_OPENAI_API_KEY=secret-selected\n'
    from vraptor.settings import resolve
    active = resolve(config_file=settings, repo_root=repo,
                     process_environment={"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config")})
    assert active.environment["AZURE_OPENAI_API_KEY"] == "secret-selected"
    assert active.environment["AI_SKILLS_ANALYST_AGENT_MODEL"] == "chosen"
    assert active.values["velociraptor_bin"] == str(home / "velociraptor/velociraptor")
    assert active.values["api_user"] == "vraptor"
    assert active.sources["api_user"] == "default"
    assert all(path.read_text() == "unchanged" for path in untouched)
    assert os.environ["VELO_BIN"] == "secret-process-value"
    assert "secret-" not in result.out + result.err
    assert reset.reset_main([*args, "--apply"]) == 0
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["changes"] == [] and repeated["backup_directory"] is None


@pytest.mark.parametrize("config_home", [None, ""])
def test_settings_without_credential_reference_are_removed(workspace, monkeypatch, capsys, config_home):
    home, repo, settings, _, _, _ = workspace
    if config_home is None:
        monkeypatch.delenv("XDG_CONFIG_HOME")
    else:
        monkeypatch.setenv("XDG_CONFIG_HOME", config_home)
    settings.write_text('schema_version = 1\n[workstation]\nbinary = "/old/bin"\n')
    assert reset.reset_main(["--repo-root", str(repo), "--settings-file", str(settings), "--apply"]) == 0
    assert not settings.exists()
    result = json.loads(capsys.readouterr().out)
    assert result["changes"][0]["action"] == "remove"
    assert Path(result["backup_directory"]).parent == home / ".config/vraptor/backups"


def test_setup_reset_preserves_analyst_reference_and_environment(workspace, capsys):
    home, repo, settings, selected, _, _ = workspace
    settings.write_text(settings.read_text() + '\n[analyst]\nconfig_file="../analyst.toml"\n[workstation]\nbinary="/old/bin"\n')
    selected.write_text(selected.read_text() + "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE=~/override.toml\n")
    assert reset.reset_main(["--repo-root", str(repo), "--apply"]) == 0
    result = json.loads(capsys.readouterr().out)
    from vraptor.settings import read
    assert read(settings) == {"schema_version": 1, "credentials": {"env_file": "../secrets.env"},
                              "analyst": {"config_file": "../analyst.toml"}}
    assert "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE=~/override.toml" in selected.read_text()
    assert "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE" not in (result["shell_unset"] or "")


def test_explicit_paths_and_duplicate_dotenv_are_handled_once(workspace, capsys):
    _, repo, settings, selected, _, _ = workspace
    alternative = settings.with_name("alternate.toml")
    settings.rename(alternative)
    assert reset.reset_main(["--repo-root", str(repo), "--settings-file", str(alternative),
                       "--env-file", str(selected), "--env-file", str(selected)]) == 0
    result = json.loads(capsys.readouterr().out)
    paths = [item["path"] for item in result["changes"]]
    assert paths.count(str(selected)) == 1
    assert str(alternative) in paths


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "invalid_toml"])
def test_preflight_refuses_unsafe_inputs_without_changing_other_files(workspace, kind, capsys):
    home, repo, settings, _, shared, dotenv = workspace
    before = settings.read_bytes()
    if kind == "invalid_toml":
        settings.write_text('schema_version = "secret-malformed')
    else:
        dotenv.unlink()
        if kind == "symlink":
            dotenv.symlink_to(shared)
        elif kind == "hardlink":
            dotenv.hardlink_to(shared)
        else:
            dotenv.mkdir()
    assert reset.reset_main(["--repo-root", str(repo), "--apply"]) == 1
    result = capsys.readouterr()
    assert "secret-" not in result.out + result.err
    assert not (home / "config/vraptor/backups").exists()
    assert not (home / "state").exists()
    assert settings.exists()
    if kind != "invalid_toml":
        assert settings.read_bytes() == before
    assert "VELO_REMOTE_SSH_KEY" in shared.read_text()


def test_backup_failure_leaves_all_originals_intact(workspace, monkeypatch):
    _, repo, settings, _, _, _ = workspace
    changes = reset.plan(settings, repo, [])
    def fail(*args, **kwargs):
        raise OSError("synthetic backup failure")
    monkeypatch.setattr(reset, "write_text_atomic", fail)
    with pytest.raises(OSError, match="synthetic backup failure"):
        reset.apply(changes, repo)
    assert all(item.path.read_bytes().decode() == item.before for item in changes)


def test_concurrent_edit_is_preserved(workspace):
    home, repo, settings, _, _, dotenv = workspace
    changes = reset.plan(settings, repo, [])
    dotenv.write_text("OTHER=new edit\n")
    with pytest.raises(ValueError, match="changed during reset"):
        reset.apply(changes, repo)
    assert dotenv.read_text() == "OTHER=new edit\n"
    assert settings.exists()
    assert not (home / "config/vraptor/backups").exists()
    assert not (home / "state").exists()


def test_edit_during_backup_aborts_before_any_reset(workspace, monkeypatch):
    home, repo, settings, _, _, dotenv = workspace
    changes = reset.plan(settings, repo, [])
    write_manifest = reset.write_json_atomic
    def edit_after_backup(*args, **kwargs):
        write_manifest(*args, **kwargs)
        dotenv.write_text("OTHER=concurrent edit\n")
    monkeypatch.setattr(reset, "write_json_atomic", edit_after_backup)
    with pytest.raises(ValueError, match="changed during reset"):
        reset.apply(changes, repo)
    assert settings.read_text() == changes[0].before
    assert dotenv.read_text() == "OTHER=concurrent edit\n"
    assert len(list((home / "config/vraptor/backups").glob("*/manifest.json"))) == 1


def test_refuses_backups_inside_checkout(workspace, monkeypatch):
    _, repo, settings, _, _, _ = workspace
    monkeypatch.setenv("XDG_CONFIG_HOME", str(repo / "config"))
    with pytest.raises(ValueError, match="outside the repository"):
        reset.apply(reset.plan(settings, repo, []), repo)
    assert settings.exists()
    assert not (repo / "config").exists()
