"""Version-2 analyst profiles and operator file updates."""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from vraptor.agent import manage, sources
from vraptor.agent.config import resolve_agent_execution


@pytest.mark.parametrize("xdg", [False, True])
@pytest.mark.parametrize("collision", ["absent", "file", "symlink", "directory"])
def test_default_analyst_path_migration_preserves_bytes_and_permissions(
    tmp_path, xdg, collision
):
    from vraptor.paths import repository_environment

    environment = {"HOME": str(tmp_path)}
    root = tmp_path / ".config"
    if xdg:
        root = tmp_path / "custom-config"
        environment["XDG_CONFIG_HOME"] = str(root)
    legacy = root / "ai_skills/analyst-agents.toml"
    target = root / "vraptor/analyst-agents.toml"
    legacy.parent.mkdir(parents=True)
    content = b"# preserve CRLF and comments\r\nschema_version = 2\r\n"
    legacy.write_bytes(content)
    legacy.chmod(0o640)
    if collision != "absent":
        target.parent.mkdir(parents=True)
        if collision == "file":
            target.write_bytes(b"existing destination")
            target.chmod(0o600)
        elif collision == "symlink":
            target.symlink_to(tmp_path / "missing.toml")
        else:
            target.mkdir()
    layers = repository_environment(tmp_path, process_environment=environment)
    for _ in range(2):
        path, explicit = sources.resolve_config_path(layers, {})
        assert path == target.resolve()
        assert not explicit
    if collision == "absent":
        assert target.read_bytes() == content
        assert target.stat().st_mode & 0o777 == 0o640
        assert not legacy.exists()
    else:
        assert legacy.read_bytes() == content
        assert legacy.stat().st_mode & 0o777 == 0o640
        if collision == "file":
            assert target.read_bytes() == b"existing destination"
            assert target.stat().st_mode & 0o777 == 0o600
        elif collision == "symlink":
            assert target.is_symlink()
            assert not target.exists()
        else:
            assert target.is_dir()


@pytest.mark.parametrize("selection", ["cli", "environment", "dotenv", "operational"])
def test_explicit_legacy_analyst_path_bypasses_migration(tmp_path, selection):
    from vraptor import settings

    legacy = tmp_path / ".config/ai_skills/analyst-agents.toml"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"explicit unchanged")
    environment = {"HOME": str(tmp_path)}
    cli = {}
    if selection == "cli":
        cli["config_file"] = str(legacy)
    elif selection == "environment":
        environment["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] = str(legacy)
    elif selection == "dotenv":
        (tmp_path / ".env").write_text(
            f"AI_SKILLS_ANALYST_AGENT_CONFIG_FILE={legacy}\n"
        )
    else:
        path = tmp_path / ".config/vraptor/config.toml"
        path.parent.mkdir(parents=True)
        path.write_text(
            'schema_version=1\n[analyst]\nconfig_file="~/.config/ai_skills/analyst-agents.toml"\n'
        )
    snapshot = settings.resolve(repo_root=tmp_path, process_environment=environment)
    with settings.activate(snapshot):
        path, explicit = sources.resolve_config_path(snapshot.environment_layers, cli)
    assert explicit and path == legacy
    assert legacy.read_bytes() == b"explicit unchanged"
    assert not (tmp_path / ".config/vraptor/analyst-agents.toml").exists()


def test_migration_never_replaces_concurrently_created_destination(
    tmp_path, monkeypatch
):
    target = tmp_path / "vraptor/analyst-agents.toml"
    legacy = tmp_path / "ai_skills/analyst-agents.toml"
    legacy.parent.mkdir()
    legacy.write_bytes(b"legacy")
    link = os.link

    def race(source, destination):
        destination.write_bytes(b"concurrent")
        return link(source, destination)

    monkeypatch.setattr(sources.os, "link", race)
    sources.migrate_default_config(target)
    assert target.read_bytes() == b"concurrent"
    assert legacy.read_bytes() == b"legacy"


@pytest.mark.parametrize("collision", [False, True])
def test_cli_show_migrates_default_analyst_path_without_overwrite(tmp_path, collision):
    legacy = tmp_path / ".config/ai_skills/analyst-agents.toml"
    target = tmp_path / ".config/vraptor/analyst-agents.toml"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"# original\r\nschema_version=2\r\n")
    legacy.chmod(0o640)
    if collision:
        target.parent.mkdir(parents=True)
        target.write_bytes(b"existing")
    env = {
        "HOME": str(tmp_path),
        "AI_SKILLS_REPO_ROOT": str(tmp_path),
        "PATH": os.defpath,
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vraptor.cli",
            "setup",
            "show",
            "--server-profile",
            "new-profile",
        ],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    shown = json.loads(result.stdout)
    assert shown["analyst_agent"]["config_file"] == str(target)
    assert shown["analyst_agent"]["exists"]
    assert shown["values"]["api_user"] == "vraptor"
    assert shown["sources"]["api_user"] == "default"
    if collision:
        assert target.read_bytes() == b"existing"
        assert legacy.exists()
    else:
        assert target.read_bytes() == b"# original\r\nschema_version=2\r\n"
        assert target.stat().st_mode & 0o777 == 0o640
        assert not legacy.exists()


def resolve(tmp_path, document, profile="local", **environment):
    path = tmp_path / "agents.toml"
    path.write_text(manage._toml(document), encoding="utf-8")
    return resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path), "execution_profile": profile},
        process_environment={"HOME": str(tmp_path), **environment},
        allow_missing_credentials=True,
    )


@pytest.mark.parametrize("provider", ["openai", "azure_openai", "anthropic"])
def test_inline_profiles_preserve_precedence_and_credential_isolation(
    tmp_path, provider
):
    document = {
        "schema_version": 2,
        "execution_defaults": {"max_concurrency": 3},
        "profiles": {
            "local": {
                "provider": provider,
                "base_url": "https://provider.test/v1/",
                "model": "profile-model",
                "auth_mode": "api_key",
                "api_key_env": "SELECTED_KEY",
                "max_concurrency": 2,
                "model_context_tokens": 32768,
            }
        },
    }
    selected = resolve(
        tmp_path,
        document,
        SELECTED_KEY="selected-secret",
        OPENAI_API_KEY="unrelated-secret",
    )
    assert selected.provider == provider and selected.model == "profile-model"
    assert selected.max_concurrency == 2
    assert selected.inputs.api_key == "selected-secret"
    assert "selected-secret" not in json.dumps(selected.public_dict())
    assert selected.route.field_sources["model"].kind == "execution_profile"
    overridden = resolve(
        tmp_path, document, AI_SKILLS_ANALYST_AGENT_MODEL="environment-model"
    )
    assert overridden.model == "environment-model"
    assert overridden.route.field_sources["model"].kind == "process_environment"


def test_named_connection_reuse_has_independent_profile_limits(tmp_path):
    document = {
        "schema_version": 2,
        "execution_defaults": {"max_concurrency": 3},
        "connections": {
            "azure": {"provider": "azure_openai", "base_url": "https://azure.test/"}
        },
        "profiles": {
            "fast": {"connection": "azure", "model": "fast-deployment"},
            "thorough": {
                "connection": "azure",
                "model": "thorough-deployment",
                "max_concurrency": 1,
            },
        },
    }
    fast = resolve(tmp_path, document, "fast")
    thorough = resolve(tmp_path, document, "thorough")
    assert fast.base_url == thorough.base_url == "https://azure.test/openai/v1/"
    assert fast.model == "fast-deployment" and thorough.model == "thorough-deployment"
    assert fast.max_concurrency == 3 and thorough.max_concurrency == 1


@pytest.mark.parametrize(
    "kind,protocol",
    [("codex", "codex_app_server"), ("claude_code", "claude_agent_sdk")],
)
def test_inline_source_resolves_relative_paths_once_without_importing_secrets(
    tmp_path, kind, protocol
):
    source = tmp_path / ("native.toml" if kind == "codex" else "native.json")
    source.write_text(
        'model = "native-model"\napi_key = "ignored-secret"'
        if kind == "codex"
        else json.dumps(
            {
                "model": "native-model",
                "env": {"ANTHROPIC_API_KEY": "ignored-secret"},
                "hooks": {"ignore": "never execute"},
            }
        )
    )
    document = {
        "schema_version": 2,
        "profiles": {
            "local": {
                "source": {"kind": kind, "path": source.name},
                "transport": "auto",
                "model_context_tokens": 32768,
            },
            "unselected": {"source": {"kind": "codex", "path": "does-not-exist.toml"}},
        },
    }
    with (
        mock.patch.object(sources, "read_config", wraps=sources.read_config) as reads,
        mock.patch.object(
            sources, "normalize_document", wraps=sources.normalize_document
        ) as normalize,
    ):
        selected = resolve(tmp_path, document)
    normalize.assert_called_once()
    assert [call.args[0] for call in reads.call_args_list] == [
        tmp_path / "agents.toml",
        source,
    ]
    assert selected.model == "native-model" and selected.protocol == protocol
    assert selected.route.harness_config_path == str(source)
    assert "ignored-secret" not in json.dumps(selected.public_dict())
    assert not selected.inputs.api_key


@pytest.mark.parametrize(
    "profile",
    [
        {},
        [],
        {"model": "missing-provider"},
        {"provider": "unknown"},
        {"provider": "openai", "source": {"kind": "codex"}},
        {"connection": "shared", "source": {"kind": "codex"}},
        {"connection": "shared", "provider": "openai"},
        {"connection": "shared", "base_url": "https://other.test"},
        {"source": {"kind": "codex"}, "api_key_env": "SECRET_KEY"},
        {"source": "codex"},
        {"source": {}},
        {"source": {"kind": "claude_code", "profile": "unsupported"}},
        {"source": {"kind": "codex", "api_key": "secret-value"}},
        {"provider": "openai", "api_key": "secret-value"},
        {"provider": "openai", "api_key_env": "not a variable"},
        {"provider": "openai", "base_url": "https://user:secret-value@provider.test"},
        {"provider": "anthropic", "max_concurrency": True},
        {"connection": "missing"},
        {"config_source": "old-format"},
    ],
)
def test_invalid_profiles_fail_before_accessing_any_source(profile):
    document = {
        "schema_version": 2,
        "connections": {"shared": {"provider": "openai"}},
        "profiles": {"bad": profile},
    }
    with (
        mock.patch.object(
            sources, "read_config", side_effect=AssertionError("unexpected file read")
        ),
        pytest.raises(RuntimeError) as error,
    ):
        sources.normalize_document(document)
    assert "secret-value" not in str(error.value)


@pytest.mark.parametrize("version", [True, 1, 2.0, "2", 3, None])
def test_schema_version_is_an_explicit_supported_integer(version):
    with pytest.raises(RuntimeError, match="schema_version"):
        sources.normalize_document({"schema_version": version})


def test_normalization_returns_an_independent_document():
    original = {
        "schema_version": 2,
        "selection": {"default_profile": "local"},
        "execution_defaults": {"timeout_seconds": 900},
        "analysis_defaults": {"max_analysis_item_tokens": 150000},
        "connections": {"local": {"provider": "anthropic"}},
        "profiles": {
            "local": {
                "connection": "local",
                "model": "old-model",
                "model_context_tokens": 32768,
            },
            "desktop": {
                "source": {"kind": "codex", "path": "native.toml"},
                "transport": "auto",
            },
        },
    }
    before = copy.deepcopy(original)
    normalized = sources.normalize_document(original)
    assert normalized == original
    normalized["selection"]["default_profile"] = "desktop"
    normalized["execution_defaults"]["timeout_seconds"] = 600
    normalized["analysis_defaults"]["max_analysis_item_tokens"] = 1
    normalized["connections"]["local"]["provider"] = "openai"
    normalized["profiles"]["local"]["model"] = "changed-model"
    normalized["profiles"]["desktop"]["source"]["path"] = "changed.toml"
    assert original == before


def test_version_one_is_rejected_without_reading_sources_or_rewriting_file(tmp_path):
    path = tmp_path / "agents.toml"
    before = """schema_version = 1
[selection]
default_profile = "desktop"
[config_sources.desktop]
kind = "codex"
path = "does-not-exist.toml"
[execution_profiles.desktop]
config_source = "desktop"
transport = "auto"
"""
    path.write_text(before)
    with (
        mock.patch.object(sources, "read_config", wraps=sources.read_config) as reads,
        pytest.raises(RuntimeError, match="requires schema_version = 2"),
    ):
        resolve_agent_execution(
            repo_root=tmp_path,
            cli_values={"config_file": str(path)},
            process_environment={"HOME": str(tmp_path)},
            allow_missing_credentials=True,
        )
    reads.assert_called_once_with(path)
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "new-model",
            "--model-context-tokens",
            "200000",
            "--execution-profile",
            "desktop",
            "--config-file",
            str(path),
        ]
    )
    with pytest.raises(RuntimeError, match="requires schema_version = 2"):
        manage.setup(args)
    assert path.read_text() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("section", ["execution_profiles", "config_sources"])
def test_removed_sections_are_rejected_even_with_version_two(section):
    with pytest.raises(RuntimeError, match="Unknown analyst configuration section"):
        sources.normalize_document({"schema_version": 2, section: {}})


@pytest.mark.parametrize(
    "destination", ["home", "xdg", "shared", "repository", "process", "cli"]
)
def test_setup_and_loading_share_destination_precedence(
    tmp_path, monkeypatch, destination
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    rank = ["home", "xdg", "shared", "repository", "process", "cli"].index(destination)
    variable = "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"
    env = {"HOME": str(tmp_path), variable: ""}
    expected = tmp_path / ".config/vraptor/analyst-agents.toml"
    if rank >= 1:
        env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
        expected = tmp_path / "xdg/vraptor/analyst-agents.toml"
    if rank >= 2:
        (tmp_path / ".codex").mkdir()
        (tmp_path / ".codex/.env").write_text(f"{variable}=$HOME/shared.toml\n")
        expected = tmp_path / "shared.toml"
    if rank >= 3:
        (tmp_path / ".env").write_text(f"{variable}=${{HOME}}/repository.toml\n")
        expected = tmp_path / "repository.toml"
    if rank >= 4:
        env[variable] = "~/process.toml"
        expected = tmp_path / "process.toml"
    flags = []
    if rank >= 5:
        flags = ["--config-file", "cli.toml"]
        expected = tmp_path / "cli.toml"
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "local-model",
            "--model-context-tokens",
            "200000",
            *flags,
        ]
    )
    with mock.patch.dict(os.environ, env, clear=True):
        report = manage.setup(args)
    assert report["config_file"] == str(expected)
    assert expected.is_file() and expected.stat().st_mode & 0o077 == 0
    selected = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": args.config_file},
        process_environment=env,
        allow_missing_credentials=True,
    )
    assert selected.route.config_file == report["config_file"]
    assert selected.model == "local-model"
    assert list(tmp_path.rglob("*.toml")) == [expected]


def test_failed_setup_validation_leaves_existing_document_untouched(tmp_path):
    path = tmp_path / "agents.toml"
    backup = tmp_path / "agents.toml.bak"
    backup.write_text("previous backup")
    before = 'schema_version = 2\n[profiles.azure]\nprovider = "azure_openai"\nbase_url = "https://azure.test"\nmodel = "existing"\n'
    path.write_text(before)
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "test",
            "--model-context-tokens",
            "512",
            "--config-file",
            str(path),
        ]
    )
    with pytest.raises(RuntimeError, match="at least 100000 input and 32000 output"):
        manage.setup(args)
    assert path.read_text() == before
    assert backup.read_text() == "previous backup"
    assert set(tmp_path.iterdir()) == {path, backup}


def test_setup_adds_and_updates_all_types_in_one_document(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(manage.os, "isatty", lambda _: False)
    folder = tmp_path / "configuration"
    folder.mkdir()
    path = folder / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "execution_defaults": {"read_timeout_seconds": 900},
                "connections": {
                    "shared": {
                        "provider": "azure_openai",
                        "base_url": "https://azure.test",
                    }
                },
            }
        )
    )
    native = {}
    for kind, filename, content in (
        ("codex", "codex.toml", 'model = "native-model"'),
        ("claude_code", "claude.json", '{"model": "native-model"}'),
    ):
        source = tmp_path / filename
        source.write_text(content)
        native[kind] = source
    types = ["openai", "azure_openai", "anthropic", "codex", "claude_code"]
    for phase in ("added", "updated"):
        for kind in types:
            before_bytes = path.read_bytes()
            before = sources.read_config(path)
            flags = (
                ["--from-harness", kind, "--harness-config", str(native[kind])]
                if kind in native
                else ["--provider", kind]
            )
            if kind == "azure_openai":
                flags += ["--base-url", "https://azure.test"]
            args = manage.parser_for("setup").parse_args(
                [
                    *flags,
                    "--config-file",
                    str(path),
                    "--model",
                    f"{kind}-{phase}",
                    "--model-context-tokens",
                    "200000",
                ]
            )
            with mock.patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=True):
                report = manage.setup(args)
            name = "azure" if kind == "azure_openai" else kind
            after = sources.read_config(path)
            assert report["execution_profile"] == name
            assert report["profile_action"] == phase
            assert report["default_profile"] == "openai"
            assert after["selection"] == {"default_profile": "openai"}
            assert after["profiles"][name]["model"] == f"{kind}-{phase}"
            assert after["connections"] == before["connections"]
            assert after["execution_defaults"] == before["execution_defaults"]
            for other, profile in before.get("profiles", {}).items():
                if other != name:
                    assert after["profiles"][other] == profile
            assert Path(report["backup"]).read_bytes() == before_bytes
    assert len(after["profiles"]) == 5
    assert set(folder.iterdir()) == {path, path.with_name("agents.toml.bak")}


def test_setup_reuses_unique_type_under_existing_custom_name(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "desktop"},
                "connections": {
                    "azure": {
                        "provider": "azure_openai",
                        "base_url": "https://azure.test",
                    }
                },
                "profiles": {
                    "team_azure": {"connection": "azure", "model": "existing"},
                    "desktop": {"source": {"kind": "codex", "path": "unselected.toml"}},
                },
            }
        )
    )
    before = sources.read_config(path)
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "azure_openai",
            "--base-url",
            "https://updated.test",
            "--model",
            "replacement",
            "--config-file",
            str(path),
        ]
    )
    report = manage.setup(args)
    after = sources.read_config(path)
    assert report["execution_profile"] == "team_azure"
    assert report["profile_action"] == "updated"
    assert after["profiles"]["team_azure"]["model"] == "replacement"
    assert set(after["profiles"]) == {"team_azure", "desktop"}
    assert after["profiles"]["desktop"] == before["profiles"]["desktop"]
    assert after["connections"] == before["connections"]
    assert after["selection"] == before["selection"]


@pytest.mark.parametrize("explicit", [False, True])
def test_setup_rejects_profile_name_belonging_to_other_type(
    tmp_path, monkeypatch, explicit
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    name = "custom" if explicit else "codex"
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "profiles": {name: {"provider": "anthropic", "model": "existing"}},
            }
        )
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--from-harness",
            "codex",
            "--config-file",
            str(path),
            *(["--execution-profile", name] if explicit else []),
        ]
    )
    with pytest.raises(RuntimeError, match="different config type"):
        manage.setup(args)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("selected", ["default", "other"])
@pytest.mark.parametrize(
    "old_profile,name",
    [
        ({"provider": "openai", "model": "api-model"}, "openai"),
        ({"connection": "shared", "model": "deployment"}, "azure"),
        ({"source": {"kind": "codex", "path": "unselected.toml"}}, "codex"),
    ],
)
def test_setup_names_generic_profile_and_repairs_only_its_selection(
    tmp_path, monkeypatch, selected, old_profile, name
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    document = {
        "schema_version": 2,
        "selection": {"default_profile": selected},
        "connections": {
            "shared": {"provider": "azure_openai", "base_url": "https://azure.test"}
        },
        "profiles": {
            "default": old_profile,
            "other": {"provider": "openai", "model": "existing"},
        },
    }
    path.write_text(manage._toml(document))
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "claude-model",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
        ]
    )
    report = manage.setup(args)
    after = sources.read_config(path)
    assert "default" not in after["profiles"]
    assert after["profiles"][name] == old_profile
    assert after["profiles"]["other"] == document["profiles"]["other"]
    assert after["connections"] == document["connections"]
    assert after["selection"]["default_profile"] == (
        name if selected == "default" else "other"
    )
    assert report["default_profile"] in after["profiles"]
    assert report["renamed_profiles"] == {"default": name}
    assert Path(report["backup"]).read_bytes() == before


def test_setup_updates_generic_codex_profile_under_its_real_name(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    native = tmp_path / "native.toml"
    native.write_text('model = "native-model"\n')
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "default"},
                "profiles": {
                    "default": {"source": {"kind": "codex", "path": str(native)}}
                },
            }
        )
    )
    args = manage.parser_for("setup").parse_args(
        [
            "--from-harness",
            "codex",
            "--harness-config",
            str(native),
            "--config-file",
            str(path),
        ]
    )
    report = manage.setup(args)
    document = sources.read_config(path)
    assert set(document["profiles"]) == {"codex"}
    assert document["selection"] == {"default_profile": "codex"}
    assert report["profile_action"] == "updated"
    assert report["execution_profile"] == "codex"
    assert report["renamed_profiles"] == {"default": "codex"}
    selected = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert (
        selected.route.execution_profile == "codex" and selected.model == "native-model"
    )


def test_generic_profile_rename_preserves_existing_named_profiles(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    profiles = {
        "default": {"source": {"kind": "codex", "path": "unselected.toml"}},
        "codex": {"provider": "anthropic", "model": "existing-1"},
        "codex_2": {"provider": "anthropic", "model": "existing-2"},
    }
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "default"},
                "profiles": profiles,
            }
        )
    )
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "openai",
            "--model",
            "api-model",
            "--config-file",
            str(path),
        ]
    )
    report = manage.setup(args)
    after = sources.read_config(path)
    assert after["profiles"]["codex"] == profiles["codex"]
    assert after["profiles"]["codex_2"] == profiles["codex_2"]
    assert after["profiles"]["codex_3"] == profiles["default"]
    assert after["selection"] == {"default_profile": "codex_3"}
    assert report["renamed_profiles"] == {"default": "codex_3"}


def test_failed_setup_does_not_persist_profile_rename(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "default"},
                "profiles": {"default": {"provider": "openai", "model": "existing"}},
            }
        )
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "local-model",
            "--model-context-tokens",
            "512",
            "--config-file",
            str(path),
        ]
    )
    with pytest.raises(RuntimeError, match="at least 100000 input and 32000 output"):
        manage.setup(args)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_setup_rejects_generic_default_as_an_explicit_profile_name(tmp_path):
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "openai",
            "--model",
            "api-model",
            "--execution-profile",
            "default",
            "--config-file",
            str(tmp_path / "agents.toml"),
        ]
    )
    with pytest.raises(RuntimeError, match="default is reserved"):
        manage.setup(args)
    assert not list(tmp_path.iterdir())


def test_interactive_setup_creates_custom_named_codex_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    source = tmp_path / "native.toml"
    source.write_text('model = "native-model"\n')
    path = tmp_path / "agents.toml"
    args = manage.parser_for("setup").parse_args(
        [
            "--from-harness",
            "codex",
            "--harness-config",
            str(source),
            "--config-file",
            str(path),
        ]
    )
    with (
        mock.patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input", side_effect=[" codex.work ", "", "", "", "", "", ""]
        ) as prompt,
    ):
        report = manage.setup(args)
    assert prompt.call_args_list[0].args[0] == "Profile name [codex] (Enter to keep): "
    assert prompt.call_count == 7
    after = sources.read_config(path)
    assert set(after["profiles"]) == {"codex.work"}
    assert after["selection"] == {"default_profile": "codex.work"}
    assert after["profiles"]["codex.work"]["source"]["path"] == str(source)
    assert report["profile_action"] == "added" and report["renamed_profiles"] == {}
    selected = resolve_agent_execution(
        repo_root=tmp_path,
        cli_values={"config_file": str(path)},
        process_environment={"HOME": str(tmp_path)},
        allow_missing_credentials=True,
    )
    assert (
        selected.route.execution_profile == "codex.work"
        and selected.model == "native-model"
    )


@pytest.mark.parametrize("method", ["prompt", "flag"])
@pytest.mark.parametrize("selected", ["anthropic", "other"])
def test_setup_custom_rename_updates_only_matching_selection(
    tmp_path, monkeypatch, method, selected
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    document = {
        "schema_version": 2,
        "selection": {"default_profile": selected},
        "profiles": {
            "anthropic": {"provider": "anthropic", "model": "original"},
            "other": {"provider": "openai", "model": "preserve"},
        },
    }
    path.write_text(manage._toml(document))
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "local-model",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
            *(
                ["--profile-name", "local_work", "--execution-profile", "anthropic"]
                if method == "flag"
                else []
            ),
        ]
    )
    with (
        mock.patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=True),
        mock.patch(
            "builtins.input",
            side_effect=(["local_work"] if method == "prompt" else [])
            + ["", "", "", "", "", ""]
            + ([""] if selected == "other" else []),
        ) as prompt,
    ):
        report = manage.setup(args)
    assert prompt.call_count == (7 if method == "prompt" else 6) + (selected == "other")
    after = sources.read_config(path)
    assert set(after["profiles"]) == {"local_work", "other"}
    assert after["profiles"]["other"] == document["profiles"]["other"]
    assert after["selection"]["default_profile"] == (
        "local_work" if selected == "anthropic" else "other"
    )
    assert report["profile_action"] == "updated"
    assert report["renamed_profiles"] == {"anthropic": "local_work"}
    assert Path(report["backup"]).read_bytes() == before
    assert set(tmp_path.iterdir()) == {path, Path(report["backup"])}


@pytest.mark.parametrize(
    "custom_name", ["default", "bad name", "bad/name", "a" * 101, "other"]
)
def test_custom_profile_name_errors_leave_document_untouched(
    tmp_path, monkeypatch, custom_name
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "profiles": {
                    "anthropic": {"provider": "anthropic", "model": "original"},
                    "other": {"provider": "openai", "model": "preserve"},
                },
            }
        )
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "local-model",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
        ]
    )
    with (
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value=custom_name),
        pytest.raises(RuntimeError),
    ):
        manage.setup(args)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("context", [200000, 512])
def test_generic_and_custom_rename_are_saved_together_after_validation(
    tmp_path, monkeypatch, context
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "default"},
                "profiles": {"default": {"provider": "anthropic", "model": "original"}},
            }
        )
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "local-model",
            "--model-context-tokens",
            str(context),
            "--profile-name",
            "local_work",
            "--config-file",
            str(path),
        ]
    )
    if context == 512:
        with pytest.raises(
            RuntimeError, match="at least 100000 input and 32000 output"
        ):
            manage.setup(args)
        assert path.read_bytes() == before
        assert list(tmp_path.iterdir()) == [path]
    else:
        report = manage.setup(args)
        after = sources.read_config(path)
        assert set(after["profiles"]) == {"local_work"}
        assert after["selection"] == {"default_profile": "local_work"}
        assert report["renamed_profiles"] == {"default": "local_work"}


def test_setup_requires_a_name_for_ambiguous_type_and_can_add_another(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    path.write_text(
        manage._toml(
            {
                "schema_version": 2,
                "selection": {"default_profile": "anthropic"},
                "profiles": {
                    "anthropic": {"provider": "anthropic", "model": "first"},
                    "work": {"provider": "anthropic", "model": "second"},
                },
            }
        )
    )
    before = path.read_bytes()
    args = manage.parser_for("setup").parse_args(
        [
            "--provider",
            "anthropic",
            "--model",
            "replacement",
            "--model-context-tokens",
            "200000",
            "--config-file",
            str(path),
        ]
    )
    with pytest.raises(RuntimeError, match="Multiple profiles match"):
        manage.setup(args)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
    args.execution_profile = "work"
    report = manage.setup(args)
    assert report["profile_action"] == "updated"
    assert report["default_profile"] == "anthropic"
    assert sources.read_config(path)["profiles"]["anthropic"]["model"] == "first"
    args.execution_profile = "extra"
    args.set_default = True
    report = manage.setup(args)
    assert report["profile_action"] == "added"
    assert report["default_profile"] == "extra"
    assert set(sources.read_config(path)["profiles"]) == {"anthropic", "work", "extra"}


@pytest.mark.parametrize("name", ["desktop", "desktop.v2"])
def test_inline_source_serializer_roundtrip_including_unicode_paths(name):
    document = {
        "schema_version": 2,
        "profiles": {
            name: {"source": {"kind": "codex", "path": '~/config/🔎 "native".toml'}}
        },
    }
    import tomllib

    assert tomllib.loads(manage._toml(document)) == document


def test_published_examples_resolve_all_profiles_offline(tmp_path):
    document = sources.read_config(
        Path(__file__).resolve().parents[1] / "config/analyst-agents.example.toml"
    )
    assert document["selection"]["default_profile"] == "azure"
    assert "azure" in document["profiles"] and "internal" not in document["profiles"]
    for relative, content in (
        (".codex/config.toml", 'model = "native-model"'),
        (".claude/settings.json", '{"model": "native-model"}'),
    ):
        path = tmp_path / relative
        path.parent.mkdir()
        path.write_text(content)
    for name in document["profiles"]:
        assert resolve(tmp_path, document, name).model


@pytest.mark.parametrize("destination", ["cli", "environment", "default"])
def test_cli_setup_config_and_doctor_share_the_new_schema(tmp_path, destination):
    path = tmp_path / "agents.toml"
    env = {
        "HOME": str(tmp_path),
        "AI_SKILLS_REPO_ROOT": str(tmp_path),
        "PATH": os.defpath,
        "ANTHROPIC_API_KEY": "test-only",
    }
    flags = ["--config-file", str(path)] if destination == "cli" else []
    if destination == "environment":
        env["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] = str(path)
    elif destination == "default":
        path = tmp_path / ".config/vraptor/analyst-agents.toml"
    base = [sys.executable, "-m", "vraptor.cli", "ai"]

    def command(*args):
        result = subprocess.run(
            [*base, *args, *flags],
            env=env,
            cwd=tmp_path,
            check=True,
            text=True,
            capture_output=True,
        )
        return json.loads(result.stdout)

    report = command(
        "setup",
        "--provider",
        "anthropic",
        "--model",
        "local-model",
        "--model-context-tokens",
        "200000",
        "--execution-profile",
        "local",
    )
    assert report["config_file"] == str(path)
    assert sources.read_config(path)["profiles"]["local"]["model"] == "local-model"
    assert "[profiles.local]" in path.read_text()
    before = path.read_bytes()
    assert command("config")
    doctor = command("doctor")
    assert doctor["status"] == "ready" and doctor["inference"] == "not_tested"
    assert path.read_bytes() == before
    added = command("setup", "--provider", "openai", "--model", "api-model")
    assert added["execution_profile"] == "openai"
    assert added["profile_action"] == "added" and added["default_profile"] == "local"
    updated = command(
        "setup",
        "--provider",
        "openai",
        "--model",
        "new-api-model",
        "--set-default",
        "--profile-name",
        "team_openai",
    )
    assert (
        updated["profile_action"] == "updated"
        and updated["default_profile"] == "team_openai"
    )
    assert updated["renamed_profiles"] == {"openai": "team_openai"}
    after = sources.read_config(path)
    assert set(after["profiles"]) == {"local", "team_openai"}
    assert after["profiles"]["local"]["model"] == "local-model"
    assert after["profiles"]["team_openai"]["model"] == "new-api-model"
