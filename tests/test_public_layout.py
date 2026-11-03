from __future__ import annotations

import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_profiles_are_loadable() -> None:
    from vraptor.agent.profiles import load_agent_profile_config

    config = load_agent_profile_config()
    assert config.profiles["host_forensics"].default_depth in config.response_depths
    assert config.profiles["targeted_hunt"].default_depth in config.response_depths


def test_public_entrypoints_are_executable() -> None:
    paths = [
        ROOT / "dfir",
        ROOT / "vraptor",
        ROOT / "utils" / "install.sh",
        ROOT / "utils" / "sync-repos.py",
        ROOT / "utils" / "validate-public-export.py",
    ]
    for path in paths:
        assert path.is_file()
        assert path.stat().st_mode & stat.S_IXUSR
