"""Shared schema-v5 engagement and Velociraptor connection resolution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vraptor import case_layout
from vraptor.paths import resolve_case_root
from vraptor.paths import resolve_velociraptor_api_client_path
from vraptor import readiness_state as engagement_state


@dataclass(frozen=True)
class EngagementContext:
    engagement_id: str
    engagement_id_source: str
    server_profile: str
    case_root: Path
    engagement_dir: Path
    state_path: Path
    api_client: Path
    state: dict[str, Any]


def clean_identifier(value: str | None, *, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return case_layout.safe_component(text, label=label)


def effective_engagement_id(
    engagement_id: str | None,
    server_profile: str | None,
) -> tuple[str, str]:
    explicit = clean_identifier(engagement_id, label="engagement id")
    if explicit:
        return explicit, "explicit"
    fallback = clean_identifier(server_profile, label="server profile")
    if fallback:
        return fallback, "server_profile_fallback"
    raise RuntimeError(
        "Provide --engagement-id or --server-profile; an engagement folder "
        "cannot be derived from an API filename."
    )


def server_profile_from_state(payload: dict[str, Any]) -> str:
    connection = dict(payload.get("connection") or {})
    return clean_identifier(
        str(connection.get("server_profile") or ""),
        label="server profile",
    )


@dataclass(frozen=True)
class CasePaths:
    engagement_id: str
    engagement_id_source: str
    case_root: Path
    engagement_dir: Path
    state_path: Path


@dataclass(frozen=True)
class ConnectionContext:
    server_profile: str
    api_client: Path
    state: dict[str, Any]


def resolve_case_paths(*, repo_root: Path, engagement_id: str | None,
                       server_profile: str | None, case_root: str | None,
                       readiness_manifest: str | Path | None = None) -> CasePaths:
    selected_engagement_id, source = effective_engagement_id(engagement_id, server_profile)
    root = resolve_case_root(case_root, repo_root)
    directory = case_layout.engagement_dir(root, selected_engagement_id)
    state_path = (Path(readiness_manifest).expanduser().resolve() if readiness_manifest
                  else engagement_state.state_path(root, selected_engagement_id))
    return CasePaths(selected_engagement_id, source, root, directory, state_path)


def resolve_connection(*, repo_root: Path, paths: CasePaths,
                       server_profile: str | None, api_client: str | None,
                       expected_org_id: str | None = None,
                       requested_client_id: str = "", requested_hostname: str = "") -> ConnectionContext:
    state_path = paths.state_path
    selected_engagement_id = paths.engagement_id
    if api_client and not Path(api_client).expanduser().resolve().is_file():
        raise RuntimeError(f"API client config not found at {Path(api_client).expanduser().resolve()}")
    payload = engagement_state.load(state_path)
    recorded_profile = server_profile_from_state(payload)
    explicit_profile = clean_identifier(server_profile, label="server profile")
    if explicit_profile and explicit_profile != recorded_profile:
        raise RuntimeError(
            "Velociraptor readiness failed closed: requested server profile "
            f"{explicit_profile!r} does not match engagement profile "
            f"{recorded_profile!r}"
        )
    selected_profile = recorded_profile or explicit_profile
    if not selected_profile:
        raise RuntimeError(
            "Velociraptor schema-v5 readiness does not declare a server profile. "
            "Rerun engagement setup."
        )
    selected_api = resolve_velociraptor_api_client_path(
        api_client or dict(payload.get("setup") or {}).get("api_client"),
        repo_root,
        server_profile=selected_profile,
    )
    if not selected_api.is_file():
        raise RuntimeError(f"API client config not found at {selected_api}")
    validated = engagement_state.validate(
        path=state_path,
        engagement_id=selected_engagement_id,
        server_profile=selected_profile,
        api_client=selected_api,
        expected_org_id=expected_org_id,
        requested_client_id=requested_client_id,
        requested_hostname=requested_hostname,
    )
    return ConnectionContext(selected_profile, selected_api, validated if payload.get("mappings") else payload)


def resolve(
    *,
    repo_root: Path,
    engagement_id: str | None,
    server_profile: str | None,
    api_client: str | None,
    case_root: str | None,
    readiness_manifest: str | Path | None = None,
    expected_org_id: str | None = None,
    requested_client_id: str = "",
    requested_hostname: str = "",
) -> EngagementContext:
    paths = resolve_case_paths(repo_root=repo_root, engagement_id=engagement_id,
                               server_profile=server_profile, case_root=case_root,
                               readiness_manifest=readiness_manifest)
    connection = resolve_connection(repo_root=repo_root, paths=paths,
                                    server_profile=server_profile, api_client=api_client,
                                    expected_org_id=expected_org_id,
                                    requested_client_id=requested_client_id,
                                    requested_hostname=requested_hostname)
    return EngagementContext(paths.engagement_id, paths.engagement_id_source,
                             connection.server_profile, paths.case_root,
                             paths.engagement_dir, paths.state_path,
                             connection.api_client, connection.state)
