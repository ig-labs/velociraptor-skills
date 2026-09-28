#!/usr/bin/env python3
from __future__ import annotations
from vraptor.resources import resource_root

import csv
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from vraptor.analyze import limits as analysis_limits
SCHEMA_VERSION = 4
SUPPORTED_SCHEMA_VERSIONS = {SCHEMA_VERSION}
TIME_FIELD_EXPRESSION_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
BUILTIN_REFERENCE_PATH = (
    resource_root() / "preferred-artifacts.json"
)
REFERENCE_ENV_VAR = "VELO_ARTIFACT_REFERENCE_PATHS"
DOCUMENT_KEYS = {"schema_version", "profiles"}

TOP_LEVEL_PROFILE_KEYS = {
    "signal_type",
    "row_volume_risk",
    "time_bound_support",
    "selection",
    "review",
    "analysis_routes",
    "enabled",
}
SELECTION_KEYS = {
    "bias",
    "interpretation_caveat",
    "preferred_use_case",
    "question_shapes",
    "windows_skills",
    "fallback_artifacts",
}
REVIEW_KEYS = {
    "strategy",
    "default_stack",
    "stacks",
    "normalizers",
    "vql_select",
    "live_vql_select",
    "filter_fields",
    "filter_scope_fields",
    "known_bad",
    "analysis_fields",
    "sample_fields",
    "context_fields",
    "avoid_stack_fields",
    "recommended_filters",
    "host_fields",
    "timestamp_fields",
    "time_filter",
    "evtx_stack",
    "saved_hunt_projection",
}
STACK_KEYS = {
    "purpose",
    "analysis_role",
    "dimensions",
    "server_dimensions",
    "server_scope_aliases",
    "metrics",
    "max_groups",
    "priority",
    "analysis_route",
    "collection_parameters",
    "enabled",
    "live_only",
}
STACK_ANALYSIS_ROLES = {"scope", "signature", "family_signature", "strata"}
NORMALIZER_KEYS = {"output", "kind", "source_fields", "mode"}
KNOWN_BAD_KEYS = {"id", "field", "operator", "pattern", "reason", "enabled"}
EVTX_STACK_KEYS = {
    "minimum_rows",
    "minimum_estimated_chunks",
    "minimum_reduction_rows",
    "minimum_reduction_percent",
}
SAVED_HUNT_PROJECTION_KEYS = {"summary_fields", "max_source_fields"}
RETIRED_SAVED_HUNT_PROFILE_KEYS = {
    "profile_name",
    "artifact_patterns",
    "field_candidates",
    "summary_fields",
    "timestamp_fields",
    "host_fields",
    "max_source_fields",
    "always_include",
}
SELECTION_LIST_KEYS = {"question_shapes", "windows_skills", "fallback_artifacts"}
REVIEW_LIST_KEYS = {
    "vql_select",
    "live_vql_select",
    "analysis_fields",
    "sample_fields",
    "context_fields",
    "avoid_stack_fields",
    "recommended_filters",
    "host_fields",
    "timestamp_fields",
}
STACK_LIST_KEYS = {
    "dimensions",
    "server_dimensions",
    "server_scope_aliases",
    "metrics",
}
STACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SAFE_VQL_EXPRESSION_PROHIBITED_RE = re.compile(
    r"\b(?:FROM|WHERE|LIMIT|GROUP\s+BY|ORDER\s+BY|LET)\b",
    re.I,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def unique_ordered(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _require_string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuntimeError(f"{label} must be a list of strings.")
    return unique_ordered(value)


def _reject_unknown_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RuntimeError(f"{label} contains unsupported keys: {', '.join(unknown)}")


def validate_safe_vql_expression(value: Any, label: str) -> str:
    expression = str(value or "").strip()
    if (
        not expression
        or ";" in expression
        or "--" in expression
        or "/*" in expression
        or "*/" in expression
        or SAFE_VQL_EXPRESSION_PROHIBITED_RE.search(expression)
    ):
        raise RuntimeError(f"{label} contains an unsafe VQL expression: {value!r}")
    return expression


def _require_vql_expression_map(value: Any, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object mapping aliases to VQL expressions.")
    output: dict[str, str] = {}
    for raw_alias, raw_expression in value.items():
        alias = str(raw_alias or "").strip()
        if not alias or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", alias):
            raise RuntimeError(f"{label} contains an invalid field alias: {raw_alias!r}")
        output[alias] = validate_safe_vql_expression(
            raw_expression,
            f"{label}.{alias}",
        )
    return output


def _validate_time_filter(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be an object.")
    _reject_unknown_keys(value, {"default_roles", "roles"}, label)
    roles_value = value.get("roles") or {}
    if not isinstance(roles_value, dict):
        raise RuntimeError(f"{label}.roles must be an object.")
    roles: dict[str, dict[str, Any]] = {}
    for raw_role, raw_contract in roles_value.items():
        role = str(raw_role or "").strip()
        if not STACK_ID_RE.fullmatch(role):
            raise RuntimeError(f"{label}.roles contains invalid role {raw_role!r}.")
        if not isinstance(raw_contract, dict):
            raise RuntimeError(f"{label}.roles.{role} must be an object.")
        _reject_unknown_keys(
            raw_contract,
            {"semantics", "expressions"},
            f"{label}.roles.{role}",
        )
        semantics = str(raw_contract.get("semantics") or "").strip()
        if not semantics:
            raise RuntimeError(f"{label}.roles.{role}.semantics is required.")
        expressions = _require_string_list(
            raw_contract.get("expressions"),
            f"{label}.roles.{role}.expressions",
        )
        if not expressions:
            raise RuntimeError(
                f"{label}.roles.{role}.expressions requires at least one expression."
            )
        invalid_expressions = [
            expression
            for expression in expressions
            if not TIME_FIELD_EXPRESSION_RE.fullmatch(expression)
        ]
        if invalid_expressions:
            raise RuntimeError(
                f"{label}.roles.{role}.expressions must contain only dotted "
                f"field paths; got {invalid_expressions[0]!r}."
            )
        roles[role] = {
            "semantics": semantics,
            "expressions": [
                validate_safe_vql_expression(
                    expression,
                    f"{label}.roles.{role}.expressions[{index}]",
                )
                for index, expression in enumerate(expressions)
            ],
        }
    defaults = _require_string_list(value.get("default_roles"), f"{label}.default_roles")
    missing = [role for role in defaults if role not in roles]
    if missing:
        raise RuntimeError(
            f"{label}.default_roles references unknown roles: {', '.join(missing)}"
        )
    if roles and not defaults:
        raise RuntimeError(f"{label}.default_roles requires at least one role.")
    return {"default_roles": defaults, "roles": roles}


def validate_profile(
    artifact_name: str,
    profile: Any,
    *,
    source: Path,
    apply_defaults: bool = True,
) -> dict[str, Any]:
    if not artifact_name.strip():
        raise RuntimeError(f"Artifact reference {source} contains an empty artifact name.")
    if not isinstance(profile, dict):
        raise RuntimeError(f"Artifact profile {artifact_name!r} in {source} must be an object.")
    normalized = deepcopy(profile)
    legacy_keys = sorted(set(normalized) & RETIRED_SAVED_HUNT_PROFILE_KEYS)
    if legacy_keys:
        raise RuntimeError(
            f"Profile {artifact_name!r} in {source} uses retired standalone saved-hunt "
            f"fields ({', '.join(legacy_keys)}). Reuse review.sample_fields, "
            "review.timestamp_fields, and review.host_fields, with only summary_fields "
            "or max_source_fields under review.saved_hunt_projection."
        )
    _reject_unknown_keys(normalized, TOP_LEVEL_PROFILE_KEYS, f"Profile {artifact_name!r}")

    for key in ("signal_type", "row_volume_risk", "time_bound_support"):
        if key in normalized and not isinstance(normalized[key], str):
            raise RuntimeError(f"Profile {artifact_name!r} field {key} must be a string.")
    if "enabled" in normalized and not isinstance(normalized["enabled"], bool):
        raise RuntimeError(f"Profile {artifact_name!r} field enabled must be a boolean.")

    selection = normalized.get("selection", {})
    if not isinstance(selection, dict):
        raise RuntimeError(f"Profile {artifact_name!r} selection must be an object.")
    if "selection" in normalized or apply_defaults:
        normalized["selection"] = selection
    _reject_unknown_keys(selection, SELECTION_KEYS, f"Profile {artifact_name!r} selection")
    for key in ("bias", "interpretation_caveat", "preferred_use_case"):
        if key in selection and not isinstance(selection[key], str):
            raise RuntimeError(f"Profile {artifact_name!r} selection.{key} must be a string.")
    for key in SELECTION_LIST_KEYS:
        if key in selection or apply_defaults:
            selection[key] = _require_string_list(
                selection.get(key),
                f"Profile {artifact_name!r} selection.{key}",
            )

    review = normalized.get("review", {})
    if not isinstance(review, dict):
        raise RuntimeError(f"Profile {artifact_name!r} review must be an object.")
    if "review" in normalized or apply_defaults:
        normalized["review"] = review
    _reject_unknown_keys(review, REVIEW_KEYS, f"Profile {artifact_name!r} review")
    if "strategy" in review and not isinstance(review["strategy"], str):
        raise RuntimeError(f"Profile {artifact_name!r} review.strategy must be a string.")
    for key in REVIEW_LIST_KEYS:
        if key in review or apply_defaults:
            review[key] = _require_string_list(
                review.get(key),
                f"Profile {artifact_name!r} review.{key}",
            )
    for projection_key in ("vql_select", "live_vql_select"):
        for index, expression in enumerate(review.get(projection_key, [])):
            review[projection_key][index] = validate_safe_vql_expression(
                expression,
                (
                    f"Profile {artifact_name!r} "
                    f"review.{projection_key}[{index}]"
                ),
            )
    for key in ("filter_fields", "filter_scope_fields"):
        if key in review or apply_defaults:
            review[key] = _require_vql_expression_map(
                review.get(key),
                f"Profile {artifact_name!r} review.{key}",
            )
    if "time_filter" in review:
        review["time_filter"] = _validate_time_filter(
            review.get("time_filter"),
            f"Profile {artifact_name!r} review.time_filter",
        )

    saved_hunt_projection = review.get("saved_hunt_projection")
    if saved_hunt_projection is not None:
        if not isinstance(saved_hunt_projection, dict):
            raise RuntimeError(
                f"Profile {artifact_name!r} review.saved_hunt_projection must be an object."
            )
        _reject_unknown_keys(
            saved_hunt_projection,
            SAVED_HUNT_PROJECTION_KEYS,
            f"Profile {artifact_name!r} review.saved_hunt_projection",
        )
        normalized_projection: dict[str, Any] = {}
        if "summary_fields" in saved_hunt_projection:
            normalized_projection["summary_fields"] = _require_string_list(
                saved_hunt_projection.get("summary_fields"),
                f"Profile {artifact_name!r} review.saved_hunt_projection.summary_fields",
            )
        if "max_source_fields" in saved_hunt_projection:
            maximum = saved_hunt_projection["max_source_fields"]
            if (
                isinstance(maximum, bool)
                or not isinstance(maximum, int)
                or not 1 <= maximum <= 12
            ):
                raise RuntimeError(
                    f"Profile {artifact_name!r} review.saved_hunt_projection.max_source_fields "
                    "must be an integer from 1 through 12."
                )
            normalized_projection["max_source_fields"] = maximum
        if not normalized_projection:
            raise RuntimeError(
                f"Profile {artifact_name!r} review.saved_hunt_projection must configure "
                "summary_fields or max_source_fields."
            )
        review["saved_hunt_projection"] = normalized_projection

    evtx_stack = review.get("evtx_stack")
    if evtx_stack is not None:
        if not isinstance(evtx_stack, dict):
            raise RuntimeError(
                f"Profile {artifact_name!r} review.evtx_stack must be an object."
            )
        _reject_unknown_keys(
            evtx_stack,
            EVTX_STACK_KEYS,
            f"Profile {artifact_name!r} review.evtx_stack",
        )
        integer_fields = {
            "minimum_rows": (1, 10_000_000),
            "minimum_estimated_chunks": (1, 100_000),
            "minimum_reduction_rows": (1, 10_000_000),
        }
        for key, (minimum, maximum) in integer_fields.items():
            if key not in evtx_stack:
                continue
            value = evtx_stack[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise RuntimeError(
                    f"Profile {artifact_name!r} review.evtx_stack.{key} "
                    f"must be an integer from {minimum} through {maximum}."
                )
        if "minimum_reduction_percent" in evtx_stack:
            value = evtx_stack["minimum_reduction_percent"]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 < float(value) <= 100
            ):
                raise RuntimeError(
                    f"Profile {artifact_name!r} "
                    "review.evtx_stack.minimum_reduction_percent must be "
                    "greater than 0 and no more than 100."
                )

    known_bad = review.get("known_bad", [])
    if not isinstance(known_bad, list):
        raise RuntimeError(
            f"Profile {artifact_name!r} review.known_bad must be a list."
        )
    normalized_known_bad: list[dict[str, Any]] = []
    filter_fields = review.get("filter_fields", {})
    for index, raw_rule in enumerate(known_bad):
        if not isinstance(raw_rule, dict):
            raise RuntimeError(
                f"Profile {artifact_name!r} review.known_bad[{index}] must be an object."
            )
        rule = deepcopy(raw_rule)
        _reject_unknown_keys(
            rule,
            KNOWN_BAD_KEYS,
            f"Profile {artifact_name!r} review.known_bad[{index}]",
        )
        rule_id = str(rule.get("id") or "").strip()
        field = str(rule.get("field") or "").strip()
        operator = str(rule.get("operator") or "regex").strip()
        pattern = str(rule.get("pattern") or "")
        reason = str(rule.get("reason") or "").strip()
        if not rule_id or not STACK_ID_RE.fullmatch(rule_id):
            raise RuntimeError(
                f"Profile {artifact_name!r} known-bad rule {index} requires a lowercase id."
            )
        if field not in filter_fields:
            raise RuntimeError(
                f"Profile {artifact_name!r} known-bad rule {rule_id!r} uses "
                f"unknown filter field {field!r}."
            )
        if operator not in {"eq", "regex"}:
            raise RuntimeError(
                f"Profile {artifact_name!r} known-bad rule {rule_id!r} "
                "operator must be eq or regex."
            )
        if not pattern or len(pattern) > 4096:
            raise RuntimeError(
                f"Profile {artifact_name!r} known-bad rule {rule_id!r} "
                "requires a pattern of at most 4096 characters."
            )
        if not reason:
            raise RuntimeError(
                f"Profile {artifact_name!r} known-bad rule {rule_id!r} requires a reason."
            )
        normalized_known_bad.append(
            {
                "id": rule_id,
                "field": field,
                "operator": operator,
                "pattern": pattern,
                "reason": reason,
                "enabled": bool(rule.get("enabled", True)),
            }
        )
    if "known_bad" in review or apply_defaults:
        review["known_bad"] = normalized_known_bad

    stacks = review.get("stacks", {})
    if not isinstance(stacks, dict):
        raise RuntimeError(f"Profile {artifact_name!r} review.stacks must be an object keyed by stack id.")
    normalized_stacks: dict[str, dict[str, Any]] = {}
    for raw_stack_id, raw_stack in stacks.items():
        stack_id = str(raw_stack_id).strip()
        if not STACK_ID_RE.fullmatch(stack_id):
            raise RuntimeError(
                f"Profile {artifact_name!r} stack id {stack_id!r} must use lowercase letters, numbers, underscores, or hyphens."
            )
        if not isinstance(raw_stack, dict):
            raise RuntimeError(f"Profile {artifact_name!r} stack {stack_id!r} must be an object.")
        stack = deepcopy(raw_stack)
        _reject_unknown_keys(stack, STACK_KEYS, f"Profile {artifact_name!r} stack {stack_id!r}")
        for key in ("purpose", "analysis_route", "analysis_role"):
            if key in stack and not isinstance(stack[key], str):
                raise RuntimeError(f"Profile {artifact_name!r} stack {stack_id!r} {key} must be a string.")
        if "analysis_route" in stack:
            try:
                stack["analysis_route"] = analysis_limits.analysis_route(
                    stack["analysis_route"]
                )
            except analysis_limits.AnalysisLimitsError as exc:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} {exc}"
                ) from exc
        analysis_role = str(stack.get("analysis_role") or "").strip()
        if analysis_role and analysis_role not in STACK_ANALYSIS_ROLES:
            raise RuntimeError(
                f"Profile {artifact_name!r} stack {stack_id!r} analysis_role "
                f"must be one of: {', '.join(sorted(STACK_ANALYSIS_ROLES))}."
            )
        if "analysis_role" in stack:
            stack["analysis_role"] = analysis_role
        if apply_defaults and not str(stack.get("purpose") or "").strip():
            raise RuntimeError(
                f"Profile {artifact_name!r} stack {stack_id!r} requires one analytical purpose."
            )
        for boolean_key in ("enabled", "live_only"):
            if boolean_key in stack and not isinstance(
                stack[boolean_key],
                bool,
            ):
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} "
                    f"{boolean_key} must be a boolean."
                )
        collection_parameters = stack.get("collection_parameters", {})
        if not isinstance(collection_parameters, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in collection_parameters.items()
        ):
            raise RuntimeError(
                f"Profile {artifact_name!r} stack {stack_id!r} collection_parameters must map strings to strings."
            )
        if "collection_parameters" in stack or apply_defaults:
            stack["collection_parameters"] = collection_parameters
        if apply_defaults:
            stack.setdefault("enabled", True)
        for key in STACK_LIST_KEYS:
            if key in stack or apply_defaults:
                stack[key] = _require_string_list(
                    stack.get(key),
                    f"Profile {artifact_name!r} stack {stack_id!r} {key}",
                )
        if "server_dimensions" in stack or apply_defaults:
            stack["server_dimensions"] = [
                validate_safe_vql_expression(
                    expression,
                    f"Profile {artifact_name!r} stack {stack_id!r} server_dimensions[{index}]",
                )
                for index, expression in enumerate(
                    stack.get("server_dimensions", [])
                )
            ]
        server_scope_aliases = stack.get("server_scope_aliases", [])
        if server_scope_aliases:
            if len(server_scope_aliases) != len(stack.get("server_dimensions", [])):
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} must define "
                    "one server_scope_aliases entry per server dimension."
                )
            unknown_scope_aliases = sorted(
                set(server_scope_aliases) - set(review.get("filter_scope_fields", {}))
            )
            if unknown_scope_aliases:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} uses unknown "
                    "server scope aliases: "
                    + ", ".join(unknown_scope_aliases)
                )
        if "max_groups" in stack or apply_defaults:
            max_groups = stack.get("max_groups", 10000)
            if not isinstance(max_groups, int) or isinstance(max_groups, bool) or max_groups < 1:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} max_groups must be a positive integer."
                )
            stack["max_groups"] = max_groups
        if "priority" in stack or apply_defaults:
            priority = stack.get("priority", 100)
            if not isinstance(priority, int) or isinstance(priority, bool) or priority < 0:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} priority must be a non-negative integer."
                )
            stack["priority"] = priority
        normalized_stacks[stack_id] = stack
    if "stacks" in review or apply_defaults:
        review["stacks"] = normalized_stacks

    default_stack = review.get("default_stack", "")
    if not isinstance(default_stack, str):
        raise RuntimeError(f"Profile {artifact_name!r} review.default_stack must be a string.")
    default_stack = default_stack.strip()
    if apply_defaults:
        enabled_ids = [
            stack_id
            for stack_id, stack in sorted(
                normalized_stacks.items(),
                key=lambda item: (int(item[1].get("priority", 100)), item[0]),
            )
            if stack.get("enabled", True)
        ]
        if not default_stack and enabled_ids:
            default_stack = enabled_ids[0]
        if default_stack and (
            default_stack not in normalized_stacks
            or not normalized_stacks[default_stack].get("enabled", True)
        ):
            raise RuntimeError(
                f"Profile {artifact_name!r} review.default_stack {default_stack!r} does not reference an enabled stack."
            )
        review["default_stack"] = default_stack
    elif "default_stack" in review:
        review["default_stack"] = default_stack

    normalizers = review.get("normalizers", [])
    if not isinstance(normalizers, list):
        raise RuntimeError(f"Profile {artifact_name!r} review.normalizers must be a list.")
    normalized_normalizers: list[dict[str, Any]] = []
    normalizer_outputs: set[str] = set()
    for index, item in enumerate(normalizers):
        if not isinstance(item, dict):
            raise RuntimeError(f"Profile {artifact_name!r} normalizer {index} must be an object.")
        entry = deepcopy(item)
        _reject_unknown_keys(entry, NORMALIZER_KEYS, f"Profile {artifact_name!r} normalizer {index}")
        output = str(entry.get("output") or "").strip()
        kind = str(entry.get("kind") or "").strip()
        if not output or not kind:
            raise RuntimeError(f"Profile {artifact_name!r} normalizer {index} requires output and kind.")
        if output in normalizer_outputs:
            raise RuntimeError(f"Profile {artifact_name!r} defines normalizer output {output!r} more than once.")
        normalizer_outputs.add(output)
        entry["output"] = output
        entry["kind"] = kind
        entry["source_fields"] = _require_string_list(
            entry.get("source_fields"),
            f"Profile {artifact_name!r} normalizer {output!r} source_fields",
        )
        mode = str(entry.get("mode") or "first_non_empty").strip()
        if mode not in {"first_non_empty", "join_non_empty"}:
            raise RuntimeError(
                f"Profile {artifact_name!r} normalizer {output!r} mode must be first_non_empty or join_non_empty."
            )
        entry["mode"] = mode
        normalized_normalizers.append(entry)
    if "normalizers" in review or apply_defaults:
        review["normalizers"] = normalized_normalizers

    if apply_defaults:
        avoided = set(review.get("avoid_stack_fields", []))
        for stack_id, stack in normalized_stacks.items():
            dimensions = set(stack.get("dimensions", []))
            conflict = sorted(dimensions & avoided)
            if conflict:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} uses fields it also avoids: {', '.join(conflict)}"
                )
            unresolved_virtual = sorted(
                value
                for value in dimensions
                if value.startswith("Normalized") and value not in normalizer_outputs
            )
            if unresolved_virtual:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} has dimensions without normalizers: "
                    f"{', '.join(unresolved_virtual)}"
                )
            unsafe_virtual = sorted(set(stack.get("server_dimensions", [])) & normalizer_outputs)
            if unsafe_virtual:
                raise RuntimeError(
                    f"Profile {artifact_name!r} stack {stack_id!r} uses local normalized fields as server dimensions: "
                    f"{', '.join(unsafe_virtual)}"
                )

    analysis_routes = normalized.get("analysis_routes", {})
    if not isinstance(analysis_routes, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in analysis_routes.items()
    ):
        raise RuntimeError(f"Profile {artifact_name!r} analysis_routes must map strings to strings.")
    normalized_analysis_routes: dict[str, str] = {}
    for key, value in analysis_routes.items():
        try:
            normalized_analysis_routes[str(key)] = analysis_limits.analysis_route(value)
        except analysis_limits.AnalysisLimitsError as exc:
            raise RuntimeError(f"Profile {artifact_name!r} {exc}") from exc
    if "analysis_routes" in normalized or apply_defaults:
        normalized["analysis_routes"] = normalized_analysis_routes
    return normalized


def validate_reference_document(payload: Any, *, source: Path) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"Artifact reference {source} must be a JSON object.")
    legacy_keys = sorted(set(payload) & RETIRED_SAVED_HUNT_PROFILE_KEYS)
    if legacy_keys:
        raise RuntimeError(
            f"Artifact reference {source} uses the retired standalone saved-hunt review "
            f"profile structure ({', '.join(legacy_keys)}). Move artifact policy under "
            "schema_version 4 profiles.<artifact>.review; no compatibility loader is available."
        )
    _reject_unknown_keys(payload, DOCUMENT_KEYS, f"Artifact reference {source}")
    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise RuntimeError(
            f"Artifact reference {source} requires schema_version {SCHEMA_VERSION}; got "
            f"{schema_version!r}. Older overlays are not compatible and are not dual-read."
        )
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        raise RuntimeError(f"Artifact reference {source} profiles must be an object keyed by artifact name.")
    return {
        str(artifact_name): validate_profile(
            str(artifact_name),
            profile,
            source=source,
            apply_defaults=False,
        )
        for artifact_name, profile in profiles.items()
    }


def merge_reference_documents(
    documents: Iterable[tuple[Path, Any]],
) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    provenance: dict[str, list[str]] = {}
    for source, payload in documents:
        source_profiles = validate_reference_document(payload, source=source)
        for artifact_name, profile in source_profiles.items():
            profiles[artifact_name] = deep_merge(
                profiles.get(artifact_name, {}),
                profile,
            )
            profiles[artifact_name] = validate_profile(
                artifact_name,
                profiles[artifact_name],
                source=source,
            )
            provenance.setdefault(artifact_name, []).append(str(source))
    for artifact_name, profile in profiles.items():
        profile["_provenance"] = provenance.get(artifact_name, [])
        profile["_profile_hash"] = sha256_value(
            {key: value for key, value in profile.items() if not key.startswith("_")}
        )
    return profiles


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def public_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(profile)


def resolve_profile(
    artifact_name: str,
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    _, profile, _ = resolve_profile_match(artifact_name, profiles)
    return profile


def resolve_profile_match(
    artifact_name: str,
    profiles: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any] | None, str]:
    normalized = str(artifact_name).split("[", 1)[0].strip()
    candidates = [(normalized, "exact")]
    parent = normalized.partition("/")[0]
    if parent and parent != normalized:
        candidates.append((parent, "parent"))
    for key, resolution in candidates:
        if key not in profiles:
            continue
        profile = profiles[key]
        if not profile or profile.get("enabled", True) is False:
            return key, None, f"disabled-{resolution}"
        return key, public_profile(profile), resolution
    return "", None, "generic-default"


def analysis_fields(profile: dict[str, Any] | None) -> list[str]:
    """Return ordered model-facing fields with sample_fields compatibility."""
    if not profile:
        return []
    review = dict(profile.get("review") or {})
    return unique_ordered(
        review.get("analysis_fields")
        or review.get("sample_fields")
        or []
    )


def ordered_stack_views(
    profile: dict[str, Any],
    *,
    require_server: bool = False,
) -> list[tuple[str, dict[str, Any]]]:
    stacks = profile.get("review", {}).get("stacks", {})
    if not isinstance(stacks, dict):
        return []
    views = [
        (str(stack_id), stack)
        for stack_id, stack in stacks.items()
        if isinstance(stack, dict)
        and stack.get("enabled", True)
        and (require_server or not stack.get("live_only", False))
        and (not require_server or bool(stack.get("server_dimensions")))
    ]
    return sorted(views, key=lambda item: (int(item[1].get("priority", 100)), item[0]))


def select_stack_view(
    profile: dict[str, Any],
    stack_id: str | None = None,
    *,
    require_server: bool = False,
) -> tuple[str, dict[str, Any]] | None:
    views = dict(ordered_stack_views(profile, require_server=require_server))
    requested = str(stack_id or "").strip()
    if requested:
        stack = profile.get("review", {}).get("stacks", {}).get(requested)
        if not isinstance(stack, dict) or not stack.get("enabled", True):
            return None
        if require_server and not stack.get("server_dimensions"):
            return None
        return requested, stack
    default_stack = str(profile.get("review", {}).get("default_stack") or "").strip()
    if default_stack in views:
        return default_stack, views[default_stack]
    ordered = ordered_stack_views(profile, require_server=require_server)
    return ordered[0] if ordered else None


def profile_to_inventory_hints(profile: dict[str, Any]) -> dict[str, Any]:
    selection = profile.get("selection", {})
    review = profile.get("review", {})
    selected = select_stack_view(profile)
    default_stack_id, default_stack = selected if selected else ("", {})
    server_selected = select_stack_view(profile, require_server=True)
    server_stack_id, server_stack = server_selected if server_selected else ("", {})
    stack_views = ordered_stack_views(profile)
    lists = {
        "preferred_stack_fields": default_stack.get("dimensions", []),
        "server_stack_fields": server_stack.get("server_dimensions", []),
        "stack_metrics": default_stack.get("metrics", []),
        "stack_view_ids": [stack_id for stack_id, _ in stack_views],
        "server_stack_view_ids": [
            stack_id for stack_id, stack in stack_views if stack.get("server_dimensions")
        ],
        "stack_view_dimensions": [
            f"{stack_id}={' + '.join(stack.get('dimensions', []))}"
            for stack_id, stack in stack_views
        ],
        "preferred_sample_fields": review.get("sample_fields", []),
        "avoid_stack_fields": review.get("avoid_stack_fields", []),
        "recommended_filters": review.get("recommended_filters", []),
        "recommended_question_shapes": selection.get("question_shapes", []),
        "recommended_windows_skills": selection.get("windows_skills", []),
        "fallback_artifacts": selection.get("fallback_artifacts", []),
        "context_fields": review.get("context_fields", []),
    }
    output: dict[str, Any] = {
        "signal_type": profile.get("signal_type", ""),
        "row_volume_risk": profile.get("row_volume_risk", ""),
        "time_bound_support": profile.get("time_bound_support", ""),
        "selection_bias": selection.get("bias", ""),
        "interpretation_caveat": selection.get("interpretation_caveat", ""),
        "preferred_use_case": selection.get("preferred_use_case", ""),
        "review_strategy": review.get("strategy", ""),
        "default_stack": default_stack_id,
        "default_server_stack": server_stack_id,
        "normalizer_names": [item.get("kind", "") for item in review.get("normalizers", [])],
        "profile_hash": profile.get("_profile_hash", ""),
        "profile_sources": profile.get("_provenance", []),
        "artifact_profile": public_profile(profile),
    }
    for key, values in lists.items():
        output[key] = unique_ordered(values)
    return output


def inventory_hint_rows(profiles: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        artifact_name: profile_to_inventory_hints(profile)
        for artifact_name, profile in profiles.items()
        if profile.get("enabled", True) is not False
    }


def profile_index_rows(profiles: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for artifact_name in sorted(profiles, key=str.lower):
        bias = profile_to_inventory_hints(profiles[artifact_name])
        rows.append(
            {
                "artifact_name": artifact_name,
                "signal_type": bias["signal_type"],
                "row_volume_risk": bias["row_volume_risk"],
                "time_bound_support": bias["time_bound_support"],
                "review_strategy": bias["review_strategy"],
                "default_stack": bias["default_stack"],
                "default_server_stack": bias["default_server_stack"],
                "stack_view_ids": "|".join(bias["stack_view_ids"]),
                "server_stack_view_ids": "|".join(bias["server_stack_view_ids"]),
                "stack_view_dimensions": "|".join(bias["stack_view_dimensions"]),
                "preferred_stack_fields": "|".join(bias["preferred_stack_fields"]),
                "server_stack_fields": "|".join(bias["server_stack_fields"]),
                "stack_metrics": "|".join(bias["stack_metrics"]),
                "preferred_sample_fields": "|".join(bias["preferred_sample_fields"]),
                "avoid_stack_fields": "|".join(bias["avoid_stack_fields"]),
                "recommended_filters": "|".join(bias["recommended_filters"]),
                "normalizers": "|".join(bias["normalizer_names"]),
                "recommended_windows_skills": "|".join(bias["recommended_windows_skills"]),
                "recommended_question_shapes": "|".join(bias["recommended_question_shapes"]),
                "profile_hash": bias["profile_hash"],
                "profile_sources": "|".join(bias["profile_sources"]),
            }
        )
    return rows


def write_profile_exports(
    output_dir: Path | str,
    profiles: dict[str, dict[str, Any]],
    source_paths: Iterable[Path],
) -> dict[str, str]:
    root = Path(output_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "artifact_profiles_resolved.json"
    csv_path = root / "artifact_profiles_resolved.csv"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "source_files": [str(path) for path in source_paths],
        "profiles": {name: public_profile(profile) for name, profile in sorted(profiles.items())},
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    rows = profile_index_rows(profiles)
    fieldnames = list(rows[0]) if rows else ["artifact_name"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return {"artifact_profiles_json": str(json_path), "artifact_profiles_csv": str(csv_path)}
