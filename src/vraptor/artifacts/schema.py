"""Offline validation for Velociraptor artifact output schemas."""

from __future__ import annotations
from vraptor.resources import resource_root

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


BUILTIN_CONTRACT_PATH = (
    resource_root()
    / "artifact-schema-compatibility.json"
)


class ArtifactSchemaCompatibilityError(RuntimeError):
    """Raised when a compatibility contract or snapshot is invalid."""


def _load_json_object(path: Path, *, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ArtifactSchemaCompatibilityError(
            f"Could not read {label} {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ArtifactSchemaCompatibilityError(
            f"Invalid JSON in {label} {path}: {exc}"
        ) from exc


def _string_list(value: Any, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ArtifactSchemaCompatibilityError(f"{label} must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ArtifactSchemaCompatibilityError(
                f"{label} must contain non-empty strings"
            )
        normalized = item.strip()
        if normalized not in result:
            result.append(normalized)
    return result


def validate_contract(contract: Any) -> dict[str, Any]:
    if not isinstance(contract, dict) or contract.get("schema_version") != 1:
        raise ArtifactSchemaCompatibilityError(
            "Artifact schema compatibility contract must be a schema-version-1 object"
        )
    artifacts = contract.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ArtifactSchemaCompatibilityError(
            "Artifact schema compatibility contract must define artifacts"
        )
    normalized_artifacts: dict[str, dict[str, Any]] = {}
    for artifact_name, raw_artifact in artifacts.items():
        if not isinstance(artifact_name, str) or not artifact_name.strip():
            raise ArtifactSchemaCompatibilityError(
                "Artifact schema compatibility names must be non-empty strings"
            )
        if not isinstance(raw_artifact, dict):
            raise ArtifactSchemaCompatibilityError(
                f"Artifact contract {artifact_name!r} must be an object"
            )
        raw_groups = raw_artifact.get("semantic_alias_groups")
        if not isinstance(raw_groups, list) or not raw_groups:
            raise ArtifactSchemaCompatibilityError(
                f"Artifact contract {artifact_name!r} must define semantic_alias_groups"
            )
        groups: list[dict[str, Any]] = []
        seen_semantics: set[str] = set()
        for index, raw_group in enumerate(raw_groups):
            label = (
                f"Artifact contract {artifact_name!r} semantic_alias_groups[{index}]"
            )
            if not isinstance(raw_group, dict):
                raise ArtifactSchemaCompatibilityError(
                    f"{label} must be an object"
                )
            semantic = str(raw_group.get("semantic") or "").strip()
            if not semantic:
                raise ArtifactSchemaCompatibilityError(
                    f"{label} must define semantic"
                )
            if semantic in seen_semantics:
                raise ArtifactSchemaCompatibilityError(
                    f"Artifact contract {artifact_name!r} repeats semantic {semantic!r}"
                )
            seen_semantics.add(semantic)
            aliases = _string_list(
                raw_group.get("aliases"),
                label=f"{label} aliases",
            )
            if not aliases:
                raise ArtifactSchemaCompatibilityError(
                    f"{label} aliases must not be empty"
                )
            groups.append(
                {
                    "semantic": semantic,
                    "aliases": aliases,
                    "description": str(
                        raw_group.get("description") or ""
                    ).strip(),
                }
            )
        normalized_artifacts[artifact_name.strip()] = {
            "description": str(raw_artifact.get("description") or "").strip(),
            "semantic_alias_groups": groups,
        }
    return {
        "schema_version": 1,
        "contract_name": str(contract.get("contract_name") or "").strip(),
        "description": str(contract.get("description") or "").strip(),
        "artifacts": normalized_artifacts,
    }


def load_contract(path: Path | str | None = None) -> dict[str, Any]:
    contract_path = (
        Path(path).expanduser().resolve()
        if path is not None
        else BUILTIN_CONTRACT_PATH.resolve()
    )
    return validate_contract(
        _load_json_object(contract_path, label="compatibility contract")
    )


def load_snapshot(path: Path | str) -> Any:
    snapshot_path = Path(path).expanduser().resolve()
    return _load_json_object(snapshot_path, label="schema snapshot")


def _field_names(value: Any) -> set[str]:
    """Extract field names from common schema snapshot representations."""
    fields: set[str] = set()
    if value is None:
        return fields
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            fields.add(normalized)
        return fields
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                fields.update(_field_names(item))
            elif isinstance(item, dict):
                candidate = (
                    item.get("name")
                    or item.get("field")
                    or item.get("column")
                )
                if candidate:
                    fields.update(_field_names(candidate))
        return fields
    if isinstance(value, dict):
        for collection_key in ("fields", "columns", "column_names"):
            if collection_key in value:
                fields.update(_field_names(value[collection_key]))
        properties = value.get("properties")
        if isinstance(properties, dict):
            fields.update(
                str(name).strip()
                for name in properties
                if str(name).strip()
            )
        if not fields and value:
            # A compact schema may map field names directly to type metadata.
            fields.update(
                str(name).strip()
                for name in value
                if str(name).strip()
            )
    return fields


def _artifact_name(item: dict[str, Any]) -> str:
    return str(
        item.get("name")
        or item.get("artifact")
        or item.get("artifact_name")
        or ""
    ).strip()


def _artifact_fields(item: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for key in (
        "fields",
        "columns",
        "column_names",
        "output_fields",
        "schema",
    ):
        if key in item:
            fields.update(_field_names(item[key]))
    sources = item.get("sources")
    source_items: Iterable[Any]
    if isinstance(sources, dict):
        source_items = sources.values()
    elif isinstance(sources, list):
        source_items = sources
    else:
        source_items = ()
    for source in source_items:
        if isinstance(source, dict):
            fields.update(_artifact_fields(source))
        else:
            fields.update(_field_names(source))
    return fields


def snapshot_artifacts(snapshot: Any) -> dict[str, set[str]]:
    """Normalize list- or mapping-shaped connected-server schema snapshots."""
    if isinstance(snapshot, list):
        raw_artifacts: Any = snapshot
    elif isinstance(snapshot, dict):
        raw_artifacts = next(
            (
                snapshot[key]
                for key in ("artifacts", "artifact_schemas", "rows")
                if key in snapshot
            ),
            snapshot,
        )
    else:
        raise ArtifactSchemaCompatibilityError(
            "Schema snapshot must be a JSON object or list"
        )

    artifacts: dict[str, set[str]] = {}
    if isinstance(raw_artifacts, list):
        for index, item in enumerate(raw_artifacts):
            if not isinstance(item, dict):
                raise ArtifactSchemaCompatibilityError(
                    f"Schema snapshot artifact row {index} must be an object"
                )
            name = _artifact_name(item)
            if not name:
                raise ArtifactSchemaCompatibilityError(
                    f"Schema snapshot artifact row {index} has no artifact name"
                )
            artifacts.setdefault(name, set()).update(_artifact_fields(item))
    elif isinstance(raw_artifacts, dict):
        for raw_name, raw_item in raw_artifacts.items():
            name = str(raw_name).strip()
            if name in {
                "schema_version",
                "generated_at",
                "metadata",
                "server",
            }:
                continue
            if not name:
                raise ArtifactSchemaCompatibilityError(
                    "Schema snapshot artifact names must be non-empty"
                )
            if isinstance(raw_item, list):
                fields = _field_names(raw_item)
            elif isinstance(raw_item, dict):
                item = dict(raw_item)
                item.setdefault("name", name)
                fields = _artifact_fields(item)
            else:
                raise ArtifactSchemaCompatibilityError(
                    f"Schema snapshot artifact {name!r} must be an object or field list"
                )
            artifacts.setdefault(name, set()).update(fields)
    else:
        raise ArtifactSchemaCompatibilityError(
            "Schema snapshot artifacts must be a list or object"
        )
    return artifacts


def validate_snapshot(
    snapshot: Any,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validated_contract = (
        validate_contract(contract) if contract is not None else load_contract()
    )
    available_artifacts = snapshot_artifacts(snapshot)
    missing_artifacts: list[str] = []
    missing_groups: list[dict[str, Any]] = []
    artifact_results: list[dict[str, Any]] = []

    for artifact_name, artifact_contract in validated_contract[
        "artifacts"
    ].items():
        present = artifact_name in available_artifacts
        available_fields = available_artifacts.get(artifact_name, set())
        if not present:
            missing_artifacts.append(artifact_name)
        group_results: list[dict[str, Any]] = []
        for group in artifact_contract["semantic_alias_groups"]:
            matched_aliases = [
                alias
                for alias in group["aliases"]
                if alias in available_fields
            ]
            compatible = bool(matched_aliases)
            group_result = {
                "semantic": group["semantic"],
                "accepted_aliases": list(group["aliases"]),
                "matched_aliases": matched_aliases,
                "compatible": compatible,
            }
            group_results.append(group_result)
            if present and not compatible:
                missing_groups.append(
                    {
                        "artifact": artifact_name,
                        "semantic": group["semantic"],
                        "accepted_aliases": list(group["aliases"]),
                        "available_fields": sorted(available_fields),
                    }
                )
        artifact_results.append(
            {
                "artifact": artifact_name,
                "present": present,
                "compatible": present
                and all(item["compatible"] for item in group_results),
                "available_fields": sorted(available_fields),
                "semantic_alias_groups": group_results,
            }
        )

    compatible = not missing_artifacts and not missing_groups
    return {
        "schema_version": 1,
        "contract_name": validated_contract["contract_name"],
        "compatible": compatible,
        "summary": {
            "snapshot_artifact_count": len(available_artifacts),
            "required_artifact_count": len(validated_contract["artifacts"]),
            "missing_artifact_count": len(missing_artifacts),
            "missing_semantic_alias_group_count": len(missing_groups),
        },
        "missing_artifacts": missing_artifacts,
        "missing_semantic_alias_groups": missing_groups,
        "artifacts": artifact_results,
    }


def validate_snapshot_file(
    snapshot_path: Path | str,
    *,
    contract_path: Path | str | None = None,
) -> dict[str, Any]:
    return validate_snapshot(
        load_snapshot(snapshot_path),
        load_contract(contract_path),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a connected-server Velociraptor artifact schema snapshot "
            "without contacting the server."
        )
    )
    parser.add_argument("snapshot_path", nargs="?")
    parser.add_argument("--snapshot", dest="snapshot_option")
    parser.add_argument("--contract")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when required artifacts or semantic aliases are missing.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    snapshot_value = args.snapshot_option or args.snapshot_path
    if not snapshot_value:
        print("error: a schema snapshot path is required", file=sys.stderr)
        return 2
    if (
        args.snapshot_option
        and args.snapshot_path
        and Path(args.snapshot_option).expanduser()
        != Path(args.snapshot_path).expanduser()
    ):
        print(
            "error: provide the schema snapshot as either a positional path "
            "or --snapshot, not both",
            file=sys.stderr,
        )
        return 2
    try:
        result = validate_snapshot_file(
            snapshot_value,
            contract_path=args.contract,
        )
    except ArtifactSchemaCompatibilityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=False))
    return 1 if args.strict and not result["compatible"] else 0
