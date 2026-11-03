"""Keep tests out of the developer's real home, case root and state logs."""
import os
from pathlib import Path

import pytest

# Resolved before HOME moves, so tests reuse one tokenizer download and the
# default native binary still runs the offline VQL tests.
TIKTOKEN_CACHE_DIR = os.environ.get("TIKTOKEN_CACHE_DIR") or str(
    Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vraptor" / "tiktoken"
)
DEFAULT_VELO_BIN = Path.home() / "velociraptor/velociraptor"
if "VELO_BIN" not in os.environ and DEFAULT_VELO_BIN.is_file():
    os.environ["VELO_BIN"] = str(DEFAULT_VELO_BIN)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local/state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    # Set rather than unset, so a repo .env CASE_ROOT cannot win.
    monkeypatch.setenv("CASE_ROOT", str(home / "cases"))
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", TIKTOKEN_CACHE_DIR)
    # Claude Code's 1M switch and machine managed settings change Claude budgets.
    monkeypatch.delenv("CLAUDE_CODE_DISABLE_1M_CONTEXT", raising=False)
    from vraptor.agent import sources

    monkeypatch.setattr(sources, "CLAUDE_MANAGED_SETTINGS_DIRS", {})
    monkeypatch.setattr(
        sources, "DEFAULT_CLAUDE_MANAGED_SETTINGS_DIR", home / "claude-managed"
    )
    return home
