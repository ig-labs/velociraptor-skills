from __future__ import annotations

import sqlite3
import stat
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_expected_skill_set() -> None:
    expected = {
        "prep-dfir-tools",
        "velociraptor-artifact-selection",
        "velociraptor-collection",
        "velociraptor-engagement-setup",
        "velociraptor-host-analysis",
        "velociraptor-hunting",
        "velociraptor-live-api-client",
        "velociraptor-mapped-client",
    }
    actual = {path.parent.name for path in (ROOT / "skills").glob("*/SKILL.md")}
    assert actual == expected


def test_public_package_metadata() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert metadata["project"]["name"] == "vraptor"
    assert metadata["project"]["requires-python"] == ">=3.11"


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
        ROOT / "utils" / "sync-repos.sh",
        ROOT / "utils" / "sync-repos.py",
        ROOT / "utils" / "validate-public-export.sh",
        ROOT / "utils" / "validate-public-export.py",
    ]
    for path in paths:
        assert path.is_file()
        assert path.stat().st_mode & stat.S_IXUSR


def test_autoruns_database_is_valid() -> None:
    path = ROOT / "src" / "vraptor" / "resources" / "golden" / "autoruns-golden.sqlite"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_unlicensed_guidebook_is_not_exported() -> None:
    assert not list(ROOT.rglob("IR-Guidebook-Final.pdf"))
