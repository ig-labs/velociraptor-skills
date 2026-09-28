"""Canonical Velociraptor run identity and prior-run reuse policy."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


RUN_IDENTITY_SCHEMA_VERSION = 1
TERMINAL_SUCCESS = "terminal_success"
IN_FLIGHT = "in_flight"
FAILED_OR_CANCELLED = "failed_or_cancelled"
UNKNOWN = "unknown"
REUSABLE_CLASSIFICATIONS = frozenset({TERMINAL_SUCCESS, IN_FLIGHT})
CLASSIFICATION_RANK = {
    TERMINAL_SUCCESS: 30,
    IN_FLIGHT: 20,
    FAILED_OR_CANCELLED: 10,
    UNKNOWN: 0,
}


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def sha256_value(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def canonical_spec(spec: Any) -> dict[str, Any]:
    if isinstance(spec, dict):
        artifact = str(spec.get("artifact") or "")
        env_value = spec.get("env")
        if not isinstance(env_value, dict):
            parameters = spec.get("parameters")
            env_value = {}
            if isinstance(parameters, dict):
                for item in parameters.get("env") or []:
                    if isinstance(item, dict) and str(item.get("key") or ""):
                        env_value[str(item["key"])] = str(item.get("value") or "")
        timeout = spec.get("timeout_seconds")
        if timeout is None:
            timeout = spec.get("timeout")
    else:
        artifact = str(getattr(spec, "artifact", "") or "")
        env_value = getattr(spec, "env", {})
        timeout = getattr(spec, "timeout_seconds", None)

    env = {
        str(key): str(value)
        for key, value in dict(env_value or {}).items()
    }
    normalized_timeout = int(timeout or 0) or None
    return {
        "artifact": artifact,
        "env": dict(sorted(env.items())),
        "timeout_seconds": normalized_timeout,
    }


def canonical_specs(specs: Iterable[Any]) -> list[dict[str, Any]]:
    normalized = [canonical_spec(spec) for spec in specs]
    return sorted(
        normalized,
        key=lambda item: (
            item["artifact"],
            stable_json(item["env"]),
            int(item["timeout_seconds"] or 0),
        ),
    )


def build_run_identity(
    *,
    source_mode: str,
    target: dict[str, Any],
    specs: Iterable[Any],
    source_versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    identity = {
        "schema_version": RUN_IDENTITY_SCHEMA_VERSION,
        "source_mode": str(source_mode),
        "target": json.loads(stable_json(target)),
        "specs": canonical_specs(specs),
        "source_versions": dict(sorted((source_versions or {}).items())),
    }
    return {
        "identity": identity,
        "sha256": sha256_value(identity),
    }


def identity_mismatches(
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> list[str]:
    mismatches: list[str] = []

    def compare(path: str, left: Any, right: Any) -> None:
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                child = f"{path}.{key}" if path else key
                if key not in left:
                    mismatches.append(f"{child}: unexpected {right[key]!r}")
                elif key not in right:
                    mismatches.append(f"{child}: missing; expected {left[key]!r}")
                else:
                    compare(child, left[key], right[key])
            return
        if isinstance(left, list) and isinstance(right, list):
            if left != right:
                mismatches.append(f"{path}: expected {left!r}, actual {right!r}")
            return
        if left != right:
            mismatches.append(f"{path}: expected {left!r}, actual {right!r}")

    compare("", expected, actual)
    return mismatches


def identities_match(
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> bool:
    return not identity_mismatches(expected, actual)


def classify_state(
    state: Any,
    *,
    terminal_success_states: Iterable[str],
    in_flight_states: Iterable[str],
    failure_tokens: Iterable[str] = (
        "FAIL",
        "ERROR",
        "CANCEL",
        "TIMEOUT",
        "STOP",
        "ABORT",
    ),
) -> str:
    normalized = str(state or "").strip().upper()
    if normalized in {str(item).upper() for item in terminal_success_states}:
        return TERMINAL_SUCCESS
    if normalized in {str(item).upper() for item in in_flight_states}:
        return IN_FLIGHT
    if normalized and any(str(token).upper() in normalized for token in failure_tokens):
        return FAILED_OR_CANCELLED
    if normalized:
        return FAILED_OR_CANCELLED
    return UNKNOWN


def classification_rank(classification: str) -> int:
    return CLASSIFICATION_RANK.get(str(classification), 0)


def reuse_allowed(classification: str) -> bool:
    return str(classification) in REUSABLE_CLASSIFICATIONS
