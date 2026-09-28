from __future__ import annotations

from pathlib import Path

from vraptor import case_layout


LAYOUT_VERSION = 3


def engagement_dir(case_root: Path, investigation_id: str) -> Path:
    return case_layout.engagement_dir(case_root, investigation_id)


def engagement_state_path(case_root: Path, investigation_id: str) -> Path:
    return case_layout.engagement_state_path(case_root, investigation_id)


def systems_dir(case_root: Path, investigation_id: str) -> Path:
    return case_layout.systems_dir(case_root, investigation_id)


def system_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return case_layout.system_dir(case_root, investigation_id, hostname)


def system_identity_path(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return system_dir(case_root, investigation_id, hostname) / "system.json"


def collection_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return system_dir(case_root, investigation_id, hostname) / "collection"


def requests_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return collection_dir(case_root, investigation_id, hostname) / "requests"


def request_dir(
    case_root: Path,
    investigation_id: str,
    hostname: str,
    request_id: str,
) -> Path:
    return requests_dir(case_root, investigation_id, hostname) / case_layout.safe_component(
        request_id,
        label="request id",
    )


def current_state_path(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return collection_dir(case_root, investigation_id, hostname) / "current.json"


def request_state_path(
    case_root: Path,
    investigation_id: str,
    hostname: str,
    request_id: str,
) -> Path:
    return request_dir(case_root, investigation_id, hostname, request_id) / "state.json"


def coverage_path(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return collection_dir(case_root, investigation_id, hostname) / "coverage.json"


def request_coverage_path(
    case_root: Path,
    investigation_id: str,
    hostname: str,
    request_id: str,
) -> Path:
    return request_dir(case_root, investigation_id, hostname, request_id) / "coverage.json"


def analysis_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return system_dir(case_root, investigation_id, hostname) / "analysis"


def exports_dir(case_root: Path, investigation_id: str, hostname: str) -> Path:
    return system_dir(case_root, investigation_id, hostname) / "exports"


def hostnames_with_collection_state(investigation_dir: Path) -> list[str]:
    systems_root = investigation_dir / "systems"
    if not systems_root.is_dir():
        return []
    return sorted(
        host_dir.name
        for host_dir in systems_root.iterdir()
        if host_dir.is_dir() and (host_dir / "collection" / "requests").is_dir()
    )


def state_paths_for_host(investigation_dir: Path, hostname: str) -> list[Path]:
    hostname = case_layout.safe_component(hostname, label="hostname")
    root = (
        investigation_dir
        / "systems"
        / hostname
        / "collection"
        / "requests"
    )
    if not root.is_dir():
        return []
    return sorted(path for path in root.glob("*/state.json") if path.is_file())
