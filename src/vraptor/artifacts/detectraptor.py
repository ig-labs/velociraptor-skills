"""Shared DetectRaptor priority and artifact-profile validation."""

from __future__ import annotations

from vraptor.resources import resource_root

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from vraptor.artifacts import profiles as artifact_profiles


SCHEMA_VERSION = 1
CONTRACT_PATH = (
    resource_root() / "contracts"
    / "detectraptor-analysis-contract.json"
)
DISPOSITIONS = {
    "suspicious",
    "notable",
    "expected",
    "false_positive",
    "unresolved",
}


def load_contract(path: Path | str = CONTRACT_PATH) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(
            f"DetectRaptor analysis contract {source} could not be read: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"DetectRaptor analysis contract {source} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"DetectRaptor analysis contract {source} must be an object.")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"DetectRaptor analysis contract {source} schema_version must be "
            f"{SCHEMA_VERSION}."
        )
    priority = payload.get("priority")
    if not isinstance(priority, list) or not priority:
        raise RuntimeError(
            f"DetectRaptor analysis contract {source} requires priority entries."
        )
    artifacts: list[str] = []
    ranks: list[int] = []
    for index, entry in enumerate(priority, start=1):
        if not isinstance(entry, dict):
            raise RuntimeError(
                f"DetectRaptor priority entry {index} must be an object."
            )
        artifact = str(entry.get("artifact") or "").strip()
        rank = entry.get("rank")
        stacks = entry.get("review_stacks")
        if not artifact:
            raise RuntimeError(
                f"DetectRaptor priority entry {index} requires artifact."
            )
        if not isinstance(rank, int):
            raise RuntimeError(
                f"DetectRaptor priority entry {artifact!r} requires integer rank."
            )
        if not isinstance(stacks, list) or not stacks or any(
            not isinstance(stack, str) or not stack.strip()
            for stack in stacks
        ) or len(stacks) != len(set(stacks)):
            raise RuntimeError(
                f"DetectRaptor priority entry {artifact!r} requires unique "
                "review_stacks."
            )
        artifacts.append(artifact)
        ranks.append(rank)
        named_sources = entry.get("named_sources", [])
        if not isinstance(named_sources, list):
            raise RuntimeError(
                f"DetectRaptor priority entry {artifact!r} named_sources must be a list."
            )
        for source_index, named_source in enumerate(named_sources, start=1):
            if not isinstance(named_source, dict):
                raise RuntimeError(
                    f"DetectRaptor priority entry {artifact!r} named source "
                    f"{source_index} must be an object."
                )
            source_artifact = str(named_source.get("artifact") or "").strip()
            source_stacks = named_source.get("review_stacks")
            if not source_artifact:
                raise RuntimeError(
                    f"DetectRaptor priority entry {artifact!r} named source "
                    f"{source_index} requires artifact."
                )
            if not isinstance(source_stacks, list) or not source_stacks or any(
                not isinstance(stack, str) or not stack.strip()
                for stack in source_stacks
            ) or len(source_stacks) != len(set(source_stacks)):
                raise RuntimeError(
                    f"DetectRaptor named source {source_artifact!r} requires "
                    "unique review_stacks."
                )
            artifacts.append(source_artifact)
    if len(artifacts) != len(set(artifacts)):
        raise RuntimeError("DetectRaptor priority artifacts must be unique.")
    if ranks != list(range(1, len(priority) + 1)):
        raise RuntimeError("DetectRaptor priority ranks must be contiguous and ordered.")
    if set(payload.get("dispositions") or []) != DISPOSITIONS:
        raise RuntimeError(
            "DetectRaptor dispositions do not match the canonical disposition set."
        )
    boundaries = payload.get("evidence_boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != {"fleet", "host"}:
        raise RuntimeError(
            "DetectRaptor analysis contract requires fleet and host evidence boundaries."
        )
    expected_boundaries = {
        "fleet": ("velociraptor-hunting", True),
        "host": ("velociraptor-host-analysis", False),
    }
    for boundary, (canonical_skill, allows_prevalence) in expected_boundaries.items():
        value = boundaries.get(boundary)
        if not isinstance(value, dict):
            raise RuntimeError(
                f"DetectRaptor {boundary} evidence boundary must be an object."
            )
        if value.get("canonical_skill") != canonical_skill:
            raise RuntimeError(
                f"DetectRaptor {boundary} evidence boundary canonical_skill must "
                f"be {canonical_skill!r}."
            )
        if value.get("allows_prevalence") is not allows_prevalence:
            raise RuntimeError(
                f"DetectRaptor {boundary} evidence boundary allows_prevalence "
                f"must be {allows_prevalence}."
            )
    return deepcopy(payload)


def validate_stack_binding(
    *,
    owner: str,
    artifact: str,
    stack_ids: list[str],
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    profile = artifact_profiles.resolve_profile(artifact, profiles)
    if profile is None:
        raise RuntimeError(
            f"{owner} references stacks for unprofiled artifact {artifact!r}."
        )
    available = set(profile.get("review", {}).get("stacks", {}))
    missing = sorted(set(stack_ids) - available)
    if missing:
        raise RuntimeError(
            f"{owner} artifact {artifact!r} references unknown stacks: "
            + ", ".join(missing)
        )
    return {
        "artifact": artifact,
        "stack_ids": list(stack_ids),
        "profile_hash": str(profile.get("_profile_hash") or ""),
    }


def validate_contract_profiles(
    profiles: dict[str, dict[str, Any]],
    *,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = contract or load_contract()
    bindings: list[dict[str, Any]] = []
    named_source_count = 0
    for entry in resolved["priority"]:
        bindings.append(
            validate_stack_binding(
                owner="DetectRaptor analysis contract",
                artifact=str(entry["artifact"]),
                stack_ids=list(entry["review_stacks"]),
                profiles=profiles,
            )
        )
        for named_source in entry.get("named_sources", []):
            named_source_count += 1
            bindings.append(
                validate_stack_binding(
                    owner="DetectRaptor analysis contract named source",
                    artifact=str(named_source["artifact"]),
                    stack_ids=list(named_source["review_stacks"]),
                    profiles=profiles,
                )
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "priority_artifact_count": len(resolved["priority"]),
        "named_source_count": named_source_count,
        "validated_artifact_binding_count": len(bindings),
        "validated_stack_count": sum(
            len(binding["stack_ids"]) for binding in bindings
        ),
        "bindings": bindings,
    }
