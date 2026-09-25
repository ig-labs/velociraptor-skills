"""Operation-scoped immutable artifact and detection-scenario policy."""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from vraptor.artifacts import profiles as artifact_profiles
from vraptor.artifacts import scenarios as detection_scenarios
from vraptor.artifacts import sources as policy_sources


POLICY_SNAPSHOT_SCHEMA_VERSION = 1
PORTABLE_DOCUMENT_KEYS = {"artifact_policy", "profiles", "scenarios"}
PORTABLE_METADATA_KEYS = {
    "schema_version",
    "sha256",
    "profile_sha256",
    "scenario_sha256",
    "profile_count",
    "scenario_count",
    "sources",
}
PORTABLE_SOURCE_KEYS = {
    "category",
    "role",
    "order",
    "content_sha256",
}


class ArtifactPolicyError(RuntimeError):
    """Raised when artifact policy cannot be loaded or validated safely."""


class FrozenList(list):
    """List-compatible immutable value used inside a policy snapshot."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("Artifact policy snapshots are immutable.")

    __setitem__ = _immutable
    __delitem__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        return [deepcopy(value, memo) for value in self]


class FrozenDict(dict):
    """Dict-compatible immutable value used inside a policy snapshot."""

    def _immutable(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("Artifact policy snapshots are immutable.")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        return {
            str(key): deepcopy(value, memo)
            for key, value in self.items()
        }


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return FrozenDict(
            {
                str(key): freeze(child)
                for key, child in value.items()
            }
        )
    if isinstance(value, (list, tuple)):
        return FrozenList(freeze(child) for child in value)
    return value


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): thaw(child)
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [thaw(child) for child in value]
    return deepcopy(value)


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        thaw(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_sha256(value: Any, *, label: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 64:
        raise ArtifactPolicyError(
            f"{label} must be a 64-character SHA-256 value."
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ArtifactPolicyError(f"{label} must be hexadecimal.") from exc
    return normalized


def _identity_catalog(values: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        str(name): {
            str(key): thaw(value)
            for key, value in record.items()
            if not str(key).startswith("_")
        }
        for name, record in values.items()
    }


@dataclass(frozen=True, slots=True)
class PolicySource:
    category: str
    role: str
    order: int
    path: str
    content_sha256: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "role": self.role,
            "order": self.order,
            "path": self.path,
            "content_sha256": self.content_sha256,
        }

    def identity_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "role": self.role,
            "order": self.order,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class ArtifactPolicySnapshot:
    """One validated policy version shared by every phase of an operation."""

    profiles: FrozenDict
    scenarios: FrozenDict
    sources: tuple[PolicySource, ...]
    policy_sha256: str
    profile_sha256: str
    scenario_sha256: str
    schema_version: int = POLICY_SNAPSHOT_SCHEMA_VERSION

    @property
    def profile_sources(self) -> tuple[Path, ...]:
        return tuple(
            Path(source.path)
            for source in self.sources
            if source.category == "artifact_profiles"
        )

    @property
    def scenario_sources(self) -> tuple[Path, ...]:
        return tuple(
            Path(source.path)
            for source in self.sources
            if source.category == "detection_scenarios"
        )

    def metadata(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sha256": self.policy_sha256,
            "profile_sha256": self.profile_sha256,
            "scenario_sha256": self.scenario_sha256,
            "profile_count": len(self.profiles),
            "scenario_count": len(self.scenarios),
            "sources": [source.public_dict() for source in self.sources],
        }

    def portable_identity(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sha256": self.policy_sha256,
            "profile_sha256": self.profile_sha256,
            "scenario_sha256": self.scenario_sha256,
            "profile_count": len(self.profiles),
            "scenario_count": len(self.scenarios),
            "sources": [source.identity_dict() for source in self.sources],
        }

    def resolved_document(
        self,
        *,
        include_local_provenance: bool = False,
    ) -> dict[str, Any]:
        """Return a portable export unless local source paths are requested."""
        if include_local_provenance:
            return {
                "artifact_policy": self.metadata(),
                "profiles": thaw(self.profiles),
                "scenarios": thaw(self.scenarios),
            }
        return {
            "artifact_policy": self.portable_identity(),
            "profiles": _identity_catalog(self.profiles),
            "scenarios": _identity_catalog(self.scenarios),
        }


def _source_paths(
    *,
    artifact_references: Iterable[str | Path] | None,
    scenario_references: Iterable[str | Path] | None,
    environ: Mapping[str, str],
    builtin_profile_path: Path | str,
    builtin_scenario_path: Path | str,
) -> tuple[list[Path], list[Path]]:
    profile_paths = [
        Path(builtin_profile_path).expanduser().resolve(),
        *policy_sources.configured_overlay_paths(
            artifact_references,
            environ=environ,
            environment_variable=artifact_profiles.REFERENCE_ENV_VAR,
            description="Artifact reference",
        ),
    ]
    scenario_paths = [
        Path(builtin_scenario_path).expanduser().resolve(),
        *policy_sources.configured_overlay_paths(
            scenario_references,
            environ=environ,
            environment_variable=detection_scenarios.SCENARIO_REFERENCE_ENV_VAR,
            description="Detection scenario reference",
        ),
    ]
    return profile_paths, scenario_paths


def _load_profiles(
    paths: list[Path],
) -> tuple[dict[str, dict[str, Any]], list[PolicySource]]:
    documents = policy_sources.load_documents(
        paths,
        description="Artifact reference",
    )
    profiles = artifact_profiles.merge_reference_documents(
        (document.path, document.payload) for document in documents
    )
    sources: list[PolicySource] = []
    for document in documents:
        sources.append(
            PolicySource(
                category="artifact_profiles",
                role=document.role,
                order=document.order,
                path=str(document.path),
                content_sha256=document.content_sha256,
            )
        )
    return profiles, sources


def _load_scenarios(
    paths: list[Path],
    *,
    profiles: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[PolicySource]]:
    documents = policy_sources.load_documents(
        paths,
        description="Detection scenario reference",
    )
    scenarios = detection_scenarios.merge_reference_documents(
        ((document.path, document.payload) for document in documents),
        profiles=profiles,
    )
    sources: list[PolicySource] = []
    for document in documents:
        sources.append(
            PolicySource(
                category="detection_scenarios",
                role=document.role,
                order=document.order,
                path=str(document.path),
                content_sha256=document.content_sha256,
            )
        )
    return scenarios, sources


def build_artifact_policy(
    *,
    profiles: Mapping[str, Mapping[str, Any]],
    scenarios: Mapping[str, Mapping[str, Any]] | None = None,
    sources: Iterable[PolicySource] = (),
) -> ArtifactPolicySnapshot:
    """Build an injected immutable snapshot from already validated documents."""

    profile_values = thaw(profiles)
    scenario_values = thaw(scenarios or {})
    ordered_sources = tuple(sources)
    profile_source_identity = [
        source.identity_dict()
        for source in ordered_sources
        if source.category == "artifact_profiles"
    ]
    scenario_source_identity = [
        source.identity_dict()
        for source in ordered_sources
        if source.category == "detection_scenarios"
    ]
    profile_sha256 = canonical_sha256(
        {
            "profiles": _identity_catalog(profile_values),
            "sources": profile_source_identity,
        }
    )
    scenario_sha256 = canonical_sha256(
        {
            "scenarios": _identity_catalog(scenario_values),
            "sources": scenario_source_identity,
        }
    )
    identity_payload = {
        "schema_version": POLICY_SNAPSHOT_SCHEMA_VERSION,
        "profiles": _identity_catalog(profile_values),
        "scenarios": _identity_catalog(scenario_values),
        "sources": [source.identity_dict() for source in ordered_sources],
    }
    return ArtifactPolicySnapshot(
        profiles=freeze(profile_values),
        scenarios=freeze(scenario_values),
        sources=ordered_sources,
        policy_sha256=canonical_sha256(identity_payload),
        profile_sha256=profile_sha256,
        scenario_sha256=scenario_sha256,
    )


def _validate_portable_envelope(
    payload: Any,
    *,
    source_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ArtifactPolicyError(
            f"Policy export {source_path} must be a JSON object."
        )
    unknown_document_keys = sorted(set(payload) - PORTABLE_DOCUMENT_KEYS)
    missing_document_keys = sorted(PORTABLE_DOCUMENT_KEYS - set(payload))
    if unknown_document_keys or missing_document_keys:
        raise ArtifactPolicyError(
            f"Policy export {source_path} keys are invalid; missing="
            f"{missing_document_keys}, unknown={unknown_document_keys}."
        )
    metadata = payload.get("artifact_policy")
    profiles_payload = payload.get("profiles")
    scenarios_payload = payload.get("scenarios")
    if not isinstance(metadata, dict):
        raise ArtifactPolicyError(
            f"Policy export {source_path} artifact_policy must be an object."
        )
    if not isinstance(profiles_payload, dict):
        raise ArtifactPolicyError(
            f"Policy export {source_path} profiles must be an object."
        )
    if not isinstance(scenarios_payload, dict):
        raise ArtifactPolicyError(
            f"Policy export {source_path} scenarios must be an object."
        )
    unknown_metadata_keys = sorted(set(metadata) - PORTABLE_METADATA_KEYS)
    missing_metadata_keys = sorted(PORTABLE_METADATA_KEYS - set(metadata))
    if unknown_metadata_keys or missing_metadata_keys:
        raise ArtifactPolicyError(
            f"Policy export {source_path} metadata keys are invalid; missing="
            f"{missing_metadata_keys}, unknown={unknown_metadata_keys}."
        )
    if metadata.get("schema_version") != POLICY_SNAPSHOT_SCHEMA_VERSION:
        raise ArtifactPolicyError(
            f"Policy export {source_path} requires schema_version "
            f"{POLICY_SNAPSHOT_SCHEMA_VERSION}; got {metadata.get('schema_version')!r}."
        )
    if metadata.get("profile_count") != len(profiles_payload):
        raise ArtifactPolicyError(
            f"Policy export {source_path} profile_count is inconsistent."
        )
    if metadata.get("scenario_count") != len(scenarios_payload):
        raise ArtifactPolicyError(
            f"Policy export {source_path} scenario_count is inconsistent."
        )
    return metadata, profiles_payload, scenarios_payload


def _validate_portable_sources(
    metadata: Mapping[str, Any],
    *,
    source_path: Path,
) -> list[PolicySource]:

    portable_sources = metadata.get("sources")
    if not isinstance(portable_sources, list):
        raise ArtifactPolicyError(
            f"Policy export {source_path} sources must be an array."
        )
    sources: list[PolicySource] = []
    category_orders: dict[str, list[int]] = {}
    for index, value in enumerate(portable_sources):
        label = f"Policy export {source_path} sources[{index}]"
        if not isinstance(value, dict) or set(value) != PORTABLE_SOURCE_KEYS:
            raise ArtifactPolicyError(
                f"{label} must contain exactly {sorted(PORTABLE_SOURCE_KEYS)}."
            )
        category = str(value.get("category") or "")
        role = str(value.get("role") or "")
        order = value.get("order")
        if category not in {"artifact_profiles", "detection_scenarios"}:
            raise ArtifactPolicyError(f"{label}.category is invalid.")
        if role not in {"builtin", "overlay"}:
            raise ArtifactPolicyError(f"{label}.role is invalid.")
        if isinstance(order, bool) or not isinstance(order, int) or order < 0:
            raise ArtifactPolicyError(
                f"{label}.order must be a non-negative integer."
            )
        expected_role = "builtin" if order == 0 else "overlay"
        if role != expected_role:
            raise ArtifactPolicyError(
                f"{label}.role does not match its order."
            )
        category_orders.setdefault(category, []).append(order)
        sources.append(
            PolicySource(
                category=category,
                role=role,
                order=order,
                path="",
                content_sha256=_require_sha256(
                    value.get("content_sha256"),
                    label=f"{label}.content_sha256",
                ),
            )
        )
    expected_categories = ("artifact_profiles", "detection_scenarios")
    for category in expected_categories:
        orders = category_orders.get(category, [])
        if not orders:
            raise ArtifactPolicyError(
                f"Policy export {source_path} has no {category} source provenance."
            )
        if orders != list(range(len(orders))):
            raise ArtifactPolicyError(
                f"Policy export {source_path} {category} source order is not contiguous."
            )
    expected_source_categories = [
        category
        for category in expected_categories
        for _order in category_orders[category]
    ]
    if [source.category for source in sources] != expected_source_categories:
        raise ArtifactPolicyError(
            f"Policy export {source_path} source categories are not canonically ordered."
        )
    return sources


def _validate_portable_catalogs(
    profiles_payload: Mapping[str, Any],
    scenarios_payload: Mapping[str, Any],
    *,
    source_path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:

    validated_profiles = {
        str(name): artifact_profiles.validate_profile(
            str(name),
            value,
            source=source_path,
            apply_defaults=True,
        )
        for name, value in profiles_payload.items()
    }
    validated_scenarios = {
        str(name): detection_scenarios.validate_scenario(
            str(name),
            value,
            source=source_path,
            apply_defaults=True,
            profiles=validated_profiles,
        )
        for name, value in scenarios_payload.items()
    }
    return validated_profiles, validated_scenarios


def _verify_portable_identity(
    metadata: Mapping[str, Any],
    snapshot: ArtifactPolicySnapshot,
    *,
    source_path: Path,
) -> None:
    declared = {
        "sha256": _require_sha256(metadata.get("sha256"), label="artifact_policy.sha256"),
        "profile_sha256": _require_sha256(
            metadata.get("profile_sha256"),
            label="artifact_policy.profile_sha256",
        ),
        "scenario_sha256": _require_sha256(
            metadata.get("scenario_sha256"),
            label="artifact_policy.scenario_sha256",
        ),
    }
    recomputed = {
        "sha256": snapshot.policy_sha256,
        "profile_sha256": snapshot.profile_sha256,
        "scenario_sha256": snapshot.scenario_sha256,
    }
    mismatches = [key for key in declared if declared[key] != recomputed[key]]
    if mismatches:
        raise ArtifactPolicyError(
            f"Policy export {source_path} identity is inconsistent: "
            + ", ".join(mismatches)
            + "."
        )


def validate_portable_document(
    payload: Any,
    *,
    source: Path | str,
) -> ArtifactPolicySnapshot:
    """Validate a portable export and recompute its complete declared identity."""
    source_path = Path(source)
    metadata, profiles_payload, scenarios_payload = _validate_portable_envelope(
        payload,
        source_path=source_path,
    )
    sources = _validate_portable_sources(metadata, source_path=source_path)
    validated_profiles, validated_scenarios = _validate_portable_catalogs(
        profiles_payload,
        scenarios_payload,
        source_path=source_path,
    )
    snapshot = build_artifact_policy(
        profiles=validated_profiles,
        scenarios=validated_scenarios,
        sources=sources,
    )
    _verify_portable_identity(metadata, snapshot, source_path=source_path)
    return snapshot


def load_artifact_policy(
    artifact_references: Iterable[str | Path] | None = None,
    scenario_references: Iterable[str | Path] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    builtin_profile_path: Path | str = artifact_profiles.BUILTIN_REFERENCE_PATH,
    builtin_scenario_path: Path | str = detection_scenarios.BUILTIN_SCENARIO_PATH,
) -> ArtifactPolicySnapshot:
    """Load, validate, hash, and freeze all policy once for one operation."""

    selected_environment = os.environ if environ is None else environ
    profile_paths, scenario_paths = _source_paths(
        artifact_references=artifact_references,
        scenario_references=scenario_references,
        environ=selected_environment,
        builtin_profile_path=builtin_profile_path,
        builtin_scenario_path=builtin_scenario_path,
    )
    profiles, profile_sources = _load_profiles(profile_paths)
    scenarios, scenario_sources = _load_scenarios(
        scenario_paths,
        profiles=profiles,
    )
    return build_artifact_policy(
        profiles=profiles,
        scenarios=scenarios,
        sources=(*profile_sources, *scenario_sources),
    )


def resolve_operation_policy(
    *,
    artifact_references: Iterable[str | Path] | None = None,
    scenario_references: Iterable[str | Path] | None = None,
    policy_snapshot: ArtifactPolicySnapshot | None = None,
) -> ArtifactPolicySnapshot:
    """Resolve one operation boundary without accepting ambiguous inputs."""

    artifact_values = tuple(artifact_references or ())
    scenario_values = tuple(scenario_references or ())
    if policy_snapshot is not None:
        if artifact_values or scenario_values:
            raise ValueError(
                "Policy references cannot be combined with a resolved policy snapshot."
            )
        return policy_snapshot
    return load_artifact_policy(
        artifact_values,
        scenario_values,
    )
