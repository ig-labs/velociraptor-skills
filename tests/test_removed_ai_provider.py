"""Removed providers fail offline before setup writes or client construction."""

import os
import subprocess
import sys
from unittest import mock

import pytest
from vraptor.agent import manage, sources
from vraptor.agent.config import ResolvedAgentExecution, ResolvedAgentRoute
from vraptor.agent.factory import create_agent_runner
from vraptor.agent.providers import adapter_for
from vraptor.agent.runtime import TimeoutPolicy


@pytest.mark.parametrize("command", ["setup", "config"])
def test_cli_rejects_ollama_before_writing(tmp_path, command):
    path = tmp_path / "agents.toml"
    before = b'schema_version = 2\n[profiles.work]\nprovider = "openai"\n'
    path.write_bytes(before)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vraptor.cli",
            "ai",
            command,
            "--config-file",
            str(path),
            "--provider",
            "ollama",
        ],
        env={
            "HOME": str(tmp_path),
            "AI_SKILLS_REPO_ROOT": str(tmp_path),
            "PATH": os.defpath,
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "invalid choice: 'ollama'" in result.stderr
    assert path.read_bytes() == before
    assert set(tmp_path.iterdir()) == {path}


@pytest.mark.parametrize("command", ["setup", "config"])
def test_cli_help_lists_only_supported_providers(tmp_path, command):
    result = subprocess.run(
        [sys.executable, "-m", "vraptor.cli", "ai", command, "--help"],
        env={
            "HOME": str(tmp_path),
            "AI_SKILLS_REPO_ROOT": str(tmp_path),
            "PATH": os.defpath,
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "ollama" not in result.stdout.lower()
    assert "{anthropic,azure_openai,openai}" in result.stdout


def test_interactive_setup_does_not_offer_or_accept_ollama(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    args = manage.parser_for("setup").parse_args(["--config-file", str(path)])
    with (
        mock.patch.dict(os.environ, {"HOME": str(tmp_path)}, clear=True),
        mock.patch("os.isatty", return_value=True),
        mock.patch("builtins.input", return_value="ollama") as prompt,
        pytest.raises(RuntimeError, match="Unknown connection selection"),
    ):
        manage.setup(args)
    assert "ollama" not in prompt.call_args.args[0]
    assert not path.exists()


@pytest.mark.parametrize("shared", [False, True])
def test_old_ollama_config_is_rejected_without_rewriting(tmp_path, monkeypatch, shared):
    monkeypatch.setattr(manage, "REPO_ROOT", tmp_path)
    path = tmp_path / "agents.toml"
    document = {
        "schema_version": 2,
        "selection": {"default_profile": "work"},
        "profiles": {
            "work": {"provider": "openai", "model": "test"},
            "local": {"connection": "local"} if shared else {"provider": "ollama"},
        },
    }
    if shared:
        document["connections"] = {"local": {"provider": "ollama"}}
    path.write_text(manage._toml(document))
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="supported provider"):
        sources.normalize_document(sources.read_config(path))
    args = manage.parser_for("setup").parse_args(
        ["--config-file", str(path), "--provider", "openai"]
    )
    with pytest.raises(RuntimeError, match="supported provider"):
        manage.setup(args)
    assert path.read_bytes() == before
    assert set(tmp_path.iterdir()) == {path}


@pytest.mark.parametrize("protocol", ["responses", "codex_app_server"])
def test_factory_rejects_removed_provider_before_adapter_construction(protocol):
    execution = ResolvedAgentExecution(
        route=ResolvedAgentRoute(provider="ollama", model="test", protocol=protocol)
    )
    with (
        mock.patch("vraptor.agent.factory.adapter_for") as factory,
        pytest.raises(RuntimeError, match="Unsupported analyst provider: ollama"),
    ):
        create_agent_runner(execution)
    factory.assert_not_called()


def test_removed_adapter_has_no_api_dispatch():
    execution = ResolvedAgentExecution(
        route=ResolvedAgentRoute(provider="ollama", model="test", protocol="responses")
    )
    with pytest.raises(RuntimeError, match="No adapter registered for provider ollama"):
        adapter_for(execution, timeout_policy=TimeoutPolicy(), client=object())


def test_setup_no_longer_accepts_unauthenticated_api_mode():
    with pytest.raises(SystemExit) as exc:
        manage.parser_for("setup").parse_args(["--auth-mode", "none"])
    assert exc.value.code == 2
