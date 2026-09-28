#!/usr/bin/env python3
from __future__ import annotations
from vraptor.resources import resource_root

import csv
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from vraptor.artifacts import profiles as artifact_profiles
from vraptor.artifacts import detectraptor as detectraptor_contract


SCHEMA_VERSION = 1
BUILTIN_SCENARIO_PATH = (
    resource_root() / "detection-scenarios.json"
)
SCENARIO_REFERENCE_ENV_VAR = "VELO_DETECTION_SCENARIO_PATHS"
SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ARTIFACT_ROLE_CHOICES = {"primary", "supporting", "context"}
QUESTION_SHAPE_CHOICES = {
    "cross-host",
    "single-host",
    "bounded-time-window",
    "artifact-inventory",
}

SCENARIO_KEYS = {
    "title",
    "objective",
    "selection_guidance",
    "tactics",
    "tags",
    "question_shapes",
    "artifacts",
    "expected_signals",
    "benign_explanations",
    "caveats",
    "follow_up_artifacts",
    "scope_expansion_triggers",
    "enabled",
}
ARTIFACT_BINDING_KEYS = {
    "artifact",
    "role",
    "required_fields",
    "optional_fields",
    "stack_ids",
    "recommended_filters",
    "collection_parameters",
    "notes",
}
SCENARIO_LIST_KEYS = {
    "tactics",
    "tags",
    "question_shapes",
    "expected_signals",
    "benign_explanations",
    "caveats",
    "follow_up_artifacts",
    "scope_expansion_triggers",
}
ARTIFACT_LIST_KEYS = {
    "required_fields",
    "optional_fields",
    "stack_ids",
    "recommended_filters",
}


def _reject_unknown_keys(
    value: dict[str, Any],
    allowed: set[str],
    label: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimeError(f"{label} contains unsupported keys: {', '.join(unknown)}")


def _string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError(f"{label} must be a list of strings.")
    return artifact_profiles.unique_ordered(value)


def artifact_base_name(value: str) -> str:
    return str(value).split("[", 1)[0].strip()


def validate_artifact_binding(
    scenario_id: str,
    value: Any,
    *,
    index: int,
) -> dict[str, Any]:
    label = f"Scenario {scenario_id!r} artifact binding {index}"
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object.")
    binding = deepcopy(value)
    _reject_unknown_keys(binding, ARTIFACT_BINDING_KEYS, label)

    artifact = str(binding.get("artifact") or "").strip()
    if not artifact:
        raise RuntimeError(f"{label} requires artifact.")
    if artifact == "Windows.Registry.Hunter[all]":
        raise RuntimeError(
            f"{label} must not use Windows.Registry.Hunter[all]. "
            "Use a category-scoped Registry Hunter preset only for an explicit "
            "registry use case."
        )
    binding["artifact"] = artifact

    role = str(binding.get("role") or "supporting").strip()
    if role not in ARTIFACT_ROLE_CHOICES:
        raise RuntimeError(
            f"{label} role must be one of: {', '.join(sorted(ARTIFACT_ROLE_CHOICES))}."
        )
    binding["role"] = role

    for key in ARTIFACT_LIST_KEYS:
        binding[key] = _string_list(binding.get(key), f"{label}.{key}")

    overlap = sorted(
        set(binding["required_fields"]) & set(binding["optional_fields"])
    )
    if overlap:
        raise RuntimeError(
            f"{label} fields cannot be both required and optional: {', '.join(overlap)}"
        )

    collection_parameters = binding.get("collection_parameters", {})
    if not isinstance(collection_parameters, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in collection_parameters.items()
    ):
        raise RuntimeError(f"{label}.collection_parameters must map strings to strings.")
    binding["collection_parameters"] = collection_parameters

    notes = binding.get("notes", "")
    if not isinstance(notes, str):
        raise RuntimeError(f"{label}.notes must be a string.")
    binding["notes"] = notes.strip()
    return binding


def validate_scenario(
    scenario_id: str,
    value: Any,
    *,
    source: Path,
    apply_defaults: bool = True,
    profiles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not SCENARIO_ID_RE.fullmatch(scenario_id):
        raise RuntimeError(
            f"Scenario id {scenario_id!r} in {source} must use lowercase letters, "
            "numbers, and hyphens."
        )
    if not isinstance(value, dict):
        raise RuntimeError(f"Scenario {scenario_id!r} in {source} must be an object.")
    scenario = deepcopy(value)
    _reject_unknown_keys(scenario, SCENARIO_KEYS, f"Scenario {scenario_id!r}")

    for key in ("title", "objective", "selection_guidance"):
        if key in scenario and not isinstance(scenario[key], str):
            raise RuntimeError(f"Scenario {scenario_id!r}.{key} must be a string.")
        if key in scenario:
            scenario[key] = scenario[key].strip()

    if apply_defaults:
        for key in ("title", "objective"):
            if not str(scenario.get(key) or "").strip():
                raise RuntimeError(f"Scenario {scenario_id!r} requires {key}.")
        scenario.setdefault("selection_guidance", "")

    for key in SCENARIO_LIST_KEYS:
        if key in scenario or apply_defaults:
            scenario[key] = _string_list(
                scenario.get(key),
                f"Scenario {scenario_id!r}.{key}",
            )

    if "question_shapes" in scenario:
        unsupported = sorted(
            set(scenario["question_shapes"]) - QUESTION_SHAPE_CHOICES
        )
        if unsupported:
            raise RuntimeError(
                f"Scenario {scenario_id!r}.question_shapes contains unsupported "
                f"values: {', '.join(unsupported)}"
            )

    artifacts = scenario.get("artifacts")
    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise RuntimeError(f"Scenario {scenario_id!r}.artifacts must be a list.")
        normalized_artifacts = [
            validate_artifact_binding(scenario_id, item, index=index)
            for index, item in enumerate(artifacts)
        ]
        names = [artifact_base_name(item["artifact"]) for item in normalized_artifacts]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise RuntimeError(
                f"Scenario {scenario_id!r} repeats artifact bindings: "
                f"{', '.join(duplicates)}"
            )
        scenario["artifacts"] = normalized_artifacts

    if apply_defaults:
        artifacts = list(scenario.get("artifacts") or [])
        if not artifacts:
            raise RuntimeError(f"Scenario {scenario_id!r} requires at least one artifact.")
        if not any(item["role"] == "primary" for item in artifacts):
            raise RuntimeError(
                f"Scenario {scenario_id!r} requires at least one primary artifact."
            )
        scenario["artifacts"] = artifacts

    if "enabled" in scenario and not isinstance(scenario["enabled"], bool):
        raise RuntimeError(f"Scenario {scenario_id!r}.enabled must be a boolean.")
    if apply_defaults:
        scenario.setdefault("enabled", True)

    if apply_defaults and profiles is not None:
        for binding in scenario["artifacts"]:
            stack_ids = list(binding.get("stack_ids") or [])
            if not stack_ids:
                continue
            detectraptor_contract.validate_stack_binding(
                owner=f"Scenario {scenario_id!r}",
                artifact=binding["artifact"],
                stack_ids=stack_ids,
                profiles=profiles,
            )
    return scenario


def validate_reference_document(
    payload: Any,
    *,
    source: Path,
    profiles: dict[str, dict[str, Any]] | None = None,
    apply_defaults: bool = False,
) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"Detection scenario reference {source} must be an object.")
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"Detection scenario reference {source} schema_version must be "
            f"{SCHEMA_VERSION}; got {schema_version!r}."
        )
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, dict):
        raise RuntimeError(
            f"Detection scenario reference {source} scenarios must be an object "
            "keyed by scenario id."
        )
    return {
        str(scenario_id): validate_scenario(
            str(scenario_id),
            scenario,
            source=source,
            apply_defaults=apply_defaults,
            profiles=profiles,
        )
        for scenario_id, scenario in scenarios.items()
    }


def merge_reference_documents(
    documents: Iterable[tuple[Path, Any]],
    *,
    profiles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {}
    provenance: dict[str, list[str]] = {}
    for source, payload in documents:
        source_scenarios = validate_reference_document(payload, source=source)
        for scenario_id, scenario in source_scenarios.items():
            scenarios[scenario_id] = artifact_profiles.deep_merge(
                scenarios.get(scenario_id, {}),
                scenario,
            )
            scenarios[scenario_id] = validate_scenario(
                scenario_id,
                scenarios[scenario_id],
                source=source,
                apply_defaults=True,
                profiles=profiles,
            )
            provenance.setdefault(scenario_id, []).append(str(source))
    for scenario_id, scenario in scenarios.items():
        scenario["_provenance"] = provenance.get(scenario_id, [])
        scenario["_scenario_hash"] = artifact_profiles.sha256_value(
            {key: value for key, value in scenario.items() if not key.startswith("_")}
        )
    return scenarios


def public_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(scenario)


def resolve_scenario(
    scenario_id: str,
    scenarios: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    scenario = scenarios.get(str(scenario_id).strip())
    if not scenario or scenario.get("enabled", True) is False:
        return None
    return public_scenario(scenario)


def scenarios_for_artifact(
    artifact_name: str,
    scenarios: dict[str, dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    requested = artifact_base_name(artifact_name)
    output: list[tuple[str, dict[str, Any]]] = []
    for scenario_id, scenario in scenarios.items():
        if scenario.get("enabled", True) is False:
            continue
        if any(
            artifact_base_name(binding.get("artifact", "")) == requested
            for binding in scenario.get("artifacts", [])
        ):
            output.append((scenario_id, public_scenario(scenario)))
    return sorted(output, key=lambda item: item[0])


def scenario_index_rows(
    scenarios: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for scenario_id in sorted(scenarios):
        scenario = scenarios[scenario_id]
        bindings = list(scenario.get("artifacts") or [])
        rows.append(
            {
                "scenario_id": scenario_id,
                "title": scenario.get("title", ""),
                "objective": scenario.get("objective", ""),
                "tactics": "|".join(scenario.get("tactics", [])),
                "tags": "|".join(scenario.get("tags", [])),
                "question_shapes": "|".join(
                    scenario.get("question_shapes", [])
                ),
                "primary_artifacts": "|".join(
                    item["artifact"]
                    for item in bindings
                    if item.get("role") == "primary"
                ),
                "supporting_artifacts": "|".join(
                    item["artifact"]
                    for item in bindings
                    if item.get("role") == "supporting"
                ),
                "context_artifacts": "|".join(
                    item["artifact"]
                    for item in bindings
                    if item.get("role") == "context"
                ),
                "follow_up_artifacts": "|".join(
                    scenario.get("follow_up_artifacts", [])
                ),
                "enabled": bool(scenario.get("enabled", True)),
                "scenario_hash": scenario.get("_scenario_hash", ""),
                "scenario_sources": "|".join(scenario.get("_provenance", [])),
            }
        )
    return rows


def write_scenario_exports(
    output_dir: Path | str,
    scenarios: dict[str, dict[str, Any]],
    source_paths: Iterable[Path],
) -> dict[str, str]:
    root = Path(output_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "detection_scenarios_resolved.json"
    csv_path = root / "detection_scenarios_resolved.csv"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "source_files": [str(path) for path in source_paths],
        "scenarios": {
            scenario_id: public_scenario(scenario)
            for scenario_id, scenario in sorted(scenarios.items())
        },
    }
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    rows = scenario_index_rows(scenarios)
    fieldnames = list(rows[0]) if rows else ["scenario_id"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return {
        "detection_scenarios_json": str(json_path),
        "detection_scenarios_csv": str(csv_path),
    }
