from __future__ import annotations

from pathlib import Path


def safe_component(value: str, *, label: str) -> str:
    component = str(value or "").strip()
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        or "\x00" in component
    ):
        raise ValueError(f"Invalid {label}: {value!r}")
    return component


def engagement_dir(case_root: Path, investigation_id: str) -> Path:
    return Path(case_root) / safe_component(investigation_id, label="investigation id")


def engagement_state_path(case_root: Path, investigation_id: str) -> Path:
    return engagement_dir(case_root, investigation_id) / "engagement.json"


def hunts_dir(case_root: Path, investigation_id: str) -> Path:
    return engagement_dir(case_root, investigation_id) / "hunts"


def hunt_dir(case_root: Path, investigation_id: str, hunt_id: str) -> Path:
    return hunts_dir(case_root, investigation_id) / safe_component(hunt_id, label="hunt id")


def systems_dir(case_root: Path, investigation_id: str) -> Path:
    return engagement_dir(case_root, investigation_id) / "systems"


def system_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return systems_dir(case_root, investigation_id) / safe_component(hostname, label="hostname")
