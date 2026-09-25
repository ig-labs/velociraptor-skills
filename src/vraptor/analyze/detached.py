#!/usr/bin/env python3
"""Shared manifest contract for generic detached-evidence workflows."""

from __future__ import annotations

from vraptor.resources import resource_root

import hashlib
import json
from pathlib import Path
from typing import Any

from vraptor.common.hashing import sha256_file


CONTRACT_PATH = (
    resource_root() / "contracts"
    / "detached-evidence-manifest.json"
)


class DetachedEvidenceError(RuntimeError):
    pass


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_contract(path: Path | str = CONTRACT_PATH) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DetachedEvidenceError(
            f"Detached-evidence contract {source} could not be read: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise DetachedEvidenceError(
            f"Detached-evidence contract {source} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise DetachedEvidenceError(
            "Detached-evidence contract must be a schema-version-1 object."
        )
    return payload


def source_record(
    *,
    path: str,
    sha256: str,
    size_bytes: int,
    input_format: str,
    system: str,
    acquisition_context: str,
    stdin: bool = False,
) -> dict[str, Any]:
    return {
        "authority": "stdin" if stdin else "detached-file",
        "path": path,
        "sha256": sha256,
        "size_bytes": int(size_bytes),
        "format": input_format,
        "system": system.strip() or "unspecified",
        "acquisition_context": (
            acquisition_context.strip() or "not supplied"
        ),
    }


def output_record(
    path: Path,
    *,
    role: str,
    record_count: int,
) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    return {
        "role": role,
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "size_bytes": resolved.stat().st_size,
        "record_count": int(record_count),
    }


def manifest_identity(payload: dict[str, Any]) -> str:
    identity = {
        key: value
        for key, value in payload.items()
        if key != "handoff_id"
    }
    return sha256_bytes(stable_json(identity).encode("utf-8"))


def build_manifest(
    *,
    workflow: str,
    question: str,
    source: dict[str, Any],
    scope: dict[str, Any],
    reduction: dict[str, Any],
    coverage: dict[str, Any],
    outputs: list[dict[str, Any]],
    source_references: dict[str, Any],
    unresolved: list[str] | None = None,
    next_pivot: str = "",
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "kind": "detached-evidence-handoff",
        "workflow": workflow,
        "question": question.strip(),
        "source": source,
        "scope": scope,
        "reduction": reduction,
        "coverage": coverage,
        "outputs": outputs,
        "handoff": {
            "source_references": source_references,
            "unresolved": list(unresolved or []),
            "next_pivot": next_pivot.strip(),
        },
        "policy": {
            "rarity_is_malicious": False,
            "reduced_output_is_raw_evidence_copy": False,
        },
        "warnings": list(warnings or []),
    }
    payload["handoff_id"] = manifest_identity(payload)
    validate_manifest(payload)
    return payload


def _required_keys(
    payload: dict[str, Any],
    keys: list[str],
    label: str,
) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise DetachedEvidenceError(
            f"{label} is missing required keys: {', '.join(missing)}"
        )


def validate_manifest(
    payload: dict[str, Any],
    *,
    contract: dict[str, Any] | None = None,
) -> None:
    active = contract or load_contract()
    if not isinstance(payload, dict):
        raise DetachedEvidenceError("Detached-evidence manifest must be an object.")
    _required_keys(
        payload,
        list(active["required_top_level_keys"]),
        "Detached-evidence manifest",
    )
    if payload["schema_version"] != active["schema_version"]:
        raise DetachedEvidenceError("Unsupported detached-evidence schema version.")
    if payload["kind"] != active["kind"]:
        raise DetachedEvidenceError("Unexpected detached-evidence manifest kind.")
    if payload["workflow"] not in active["workflows"]:
        raise DetachedEvidenceError("Unsupported detached-evidence workflow.")
    if not str(payload["question"]).strip():
        raise DetachedEvidenceError("Detached-evidence question must not be empty.")
    if not isinstance(payload["scope"], dict):
        raise DetachedEvidenceError("Detached-evidence scope must be an object.")
    if not isinstance(payload["reduction"], dict):
        raise DetachedEvidenceError("Detached-evidence reduction must be an object.")

    source = payload["source"]
    if not isinstance(source, dict):
        raise DetachedEvidenceError("Detached-evidence source must be an object.")
    _required_keys(source, list(active["required_source_keys"]), "Source")
    if source["authority"] not in active["source_authorities"]:
        raise DetachedEvidenceError("Unsupported detached-evidence source authority.")
    if not _is_sha256(source["sha256"]):
        raise DetachedEvidenceError("Source sha256 must contain 64 hex characters.")
    if int(source["size_bytes"]) < 0:
        raise DetachedEvidenceError("Source size_bytes must be non-negative.")
    if not str(source["path"]).strip():
        raise DetachedEvidenceError("Source path must not be empty.")

    coverage = payload["coverage"]
    if not isinstance(coverage, dict):
        raise DetachedEvidenceError("Coverage must be an object.")
    _required_keys(
        coverage,
        list(active["required_coverage_keys"]),
        "Coverage",
    )
    if coverage["state"] not in active["coverage_states"]:
        raise DetachedEvidenceError("Unsupported detached-evidence coverage state.")
    for key in (
        "source_record_count",
        "processed_record_count",
        "omitted_record_count",
        "duplicate_reference_count",
    ):
        if int(coverage[key]) < 0:
            raise DetachedEvidenceError(f"Coverage {key} must be non-negative.")
    if int(coverage["source_record_count"]) != (
        int(coverage["processed_record_count"])
        + int(coverage["omitted_record_count"])
    ):
        raise DetachedEvidenceError(
            "Coverage source_record_count must equal processed plus omitted."
        )
    if (
        coverage["closure_eligible"]
        and coverage["state"] not in {"exhaustive", "filtered"}
    ):
        raise DetachedEvidenceError(
            "Only exhaustive or filtered coverage may be closure eligible."
        )
    if coverage["closure_eligible"] and int(coverage["omitted_record_count"]):
        raise DetachedEvidenceError(
            "Coverage with omitted records is not closure eligible."
        )
    if coverage["closure_eligible"] and list(coverage["limitations"]):
        raise DetachedEvidenceError(
            "Coverage with recorded limitations is not closure eligible."
        )

    outputs = payload["outputs"]
    if not isinstance(outputs, list) or not outputs:
        raise DetachedEvidenceError("Detached-evidence outputs must not be empty.")
    for index, output in enumerate(outputs):
        if not isinstance(output, dict):
            raise DetachedEvidenceError(f"Output {index} must be an object.")
        _required_keys(
            output,
            list(active["required_output_keys"]),
            f"Output {index}",
        )
        if not _is_sha256(output["sha256"]):
            raise DetachedEvidenceError(
                f"Output {index} sha256 must contain 64 hex characters."
            )
        if int(output["size_bytes"]) < 0 or int(output["record_count"]) < 0:
            raise DetachedEvidenceError(
                f"Output {index} sizes and counts must be non-negative."
            )

    handoff = payload["handoff"]
    if not isinstance(handoff, dict):
        raise DetachedEvidenceError("Detached-evidence handoff must be an object.")
    _required_keys(
        handoff,
        list(active["required_handoff_keys"]),
        "Handoff",
    )
    if not isinstance(handoff["source_references"], dict):
        raise DetachedEvidenceError("Handoff source_references must be an object.")
    if not isinstance(handoff["unresolved"], list):
        raise DetachedEvidenceError("Handoff unresolved must be a list.")

    expected_policy = dict(active["required_policy"])
    if payload["policy"] != expected_policy:
        raise DetachedEvidenceError(
            "Detached-evidence policy must preserve rarity and raw-copy guards."
        )
    if payload["handoff_id"] != manifest_identity(payload):
        raise DetachedEvidenceError("Detached-evidence handoff_id is invalid.")


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def write_manifest(path: Path, payload: dict[str, Any]) -> None:
    validate_manifest(payload)
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(resolved)
