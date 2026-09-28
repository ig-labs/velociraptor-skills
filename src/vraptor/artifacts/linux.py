#!/usr/bin/env python3
"""Inventory-validated Linux host-analysis planning."""

from __future__ import annotations

from vraptor.resources import resource_root

import argparse
import hashlib
import json
import re
import shlex
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CONTRACT_PATH = (
    resource_root() / "contracts"
    / "velociraptor-linux-host-profile.json"
)
INPUT_NAMES = {
    "date_after",
    "date_before",
    "document_root",
    "estimated_log_bytes",
    "application_context",
    "log_format",
    "path_glob",
    "log_glob",
    "log_timezone",
    "max_log_bytes",
    "search_regex",
    "server_role",
    "web_root",
    "yara_rule",
}
SELECTION_MODES = {"first_available", "first_applicable", "all_available"}
DISTROS = {"debian", "rhel", "suse"}


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise RuntimeError(f"{label} must be a list of non-empty strings.")
    output: list[str] = []
    for item in value:
        if item not in output:
            output.append(item)
    return output


def load_contract(path: Path | str = CONTRACT_PATH) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Linux host profile {source} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Linux host profile {source} is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Linux host profile {source} must be an object.")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"Linux host profile {source} schema_version must be {SCHEMA_VERSION}."
        )
    if payload.get("canonical_skill") != "velociraptor-host-analysis":
        raise RuntimeError(
            "Linux host profile canonical_skill must be 'velociraptor-host-analysis'."
        )
    modes = payload.get("modes")
    focuses = payload.get("focuses")
    capabilities = payload.get("capabilities")
    if not isinstance(modes, dict) or set(modes) != {
        "triage",
        "standard",
        "deep",
        "timeline",
    }:
        raise RuntimeError(
            "Linux host profile requires triage, standard, deep, and timeline modes."
        )
    if not isinstance(focuses, dict) or not focuses:
        raise RuntimeError("Linux host profile requires deep-analysis focuses.")
    if not isinstance(capabilities, dict) or not capabilities:
        raise RuntimeError("Linux host profile requires capabilities.")

    referenced: set[str] = set()
    for mode_id, mode in modes.items():
        if not isinstance(mode, dict):
            raise RuntimeError(f"Linux mode {mode_id!r} must be an object.")
        for key in ("required_capabilities", "optional_capabilities"):
            items = _string_list(mode.get(key), f"Linux mode {mode_id!r}.{key}")
            if key == "required_capabilities" and not items:
                raise RuntimeError(f"Linux mode {mode_id!r} requires capabilities.")
            mode[key] = items
            referenced.update(items)
        for key in ("requires_time_bounds", "requires_focus"):
            if not isinstance(mode.get(key), bool):
                raise RuntimeError(f"Linux mode {mode_id!r}.{key} must be boolean.")

    for focus_id, focus in focuses.items():
        if not isinstance(focus, dict):
            raise RuntimeError(f"Linux focus {focus_id!r} must be an object.")
        for key in ("required_capabilities", "optional_capabilities"):
            items = _string_list(focus.get(key), f"Linux focus {focus_id!r}.{key}")
            focus[key] = items
            referenced.update(items)
        required_inputs = focus.get("required_inputs", [])
        if not isinstance(required_inputs, list):
            raise RuntimeError(
                f"Linux focus {focus_id!r}.required_inputs must be a list."
            )
        required_inputs = (
            _string_list(
                required_inputs,
                f"Linux focus {focus_id!r}.required_inputs",
            )
            if required_inputs
            else []
        )
        unknown_inputs = sorted(set(required_inputs) - INPUT_NAMES)
        if unknown_inputs:
            raise RuntimeError(
                f"Linux focus {focus_id!r} uses unknown inputs: "
                + ", ".join(unknown_inputs)
            )
        focus["required_inputs"] = required_inputs

    for capability_id, capability in capabilities.items():
        if not isinstance(capability, dict):
            raise RuntimeError(f"Linux capability {capability_id!r} must be an object.")
        for key in ("purpose", "volatility", "limitations"):
            if not str(capability.get(key) or "").strip():
                raise RuntimeError(
                    f"Linux capability {capability_id!r} requires {key}."
                )
        selection = str(capability.get("selection") or "")
        if selection not in SELECTION_MODES:
            raise RuntimeError(
                f"Linux capability {capability_id!r} has unsupported selection "
                f"{selection!r}."
            )
        required_inputs = capability.get("required_inputs", [])
        if not isinstance(required_inputs, list):
            raise RuntimeError(
                f"Linux capability {capability_id!r}.required_inputs must be a list."
            )
        required_inputs = _string_list(
            required_inputs,
            f"Linux capability {capability_id!r}.required_inputs",
        ) if required_inputs else []
        unknown_inputs = sorted(set(required_inputs) - INPUT_NAMES)
        if unknown_inputs:
            raise RuntimeError(
                f"Linux capability {capability_id!r} uses unknown inputs: "
                + ", ".join(unknown_inputs)
            )
        capability["required_inputs"] = required_inputs
        candidates = capability.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise RuntimeError(
                f"Linux capability {capability_id!r} requires candidates."
            )
        candidate_names: list[str] = []
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                raise RuntimeError(
                    f"Linux capability {capability_id!r} candidate {index} "
                    "must be an object."
                )
            artifact = str(candidate.get("artifact") or "").strip()
            if not artifact:
                raise RuntimeError(
                    f"Linux capability {capability_id!r} candidate {index} "
                    "requires artifact."
                )
            candidate_names.append(artifact)
            applicability = candidate.get("applicability")
            if applicability is not None and applicability not in DISTROS:
                raise RuntimeError(
                    f"Linux candidate {artifact!r} has unsupported applicability "
                    f"{applicability!r}."
                )
            for key in ("parameter_map", "fixed_env"):
                mapping = candidate.get(key, {})
                if not isinstance(mapping, dict) or any(
                    not isinstance(map_key, str)
                    or not map_key.strip()
                    or not isinstance(map_value, str)
                    or not map_value.strip()
                    for map_key, map_value in mapping.items()
                ):
                    raise RuntimeError(
                        f"Linux candidate {artifact!r}.{key} must map strings to strings."
                    )
                if key == "parameter_map":
                    unknown = sorted(set(mapping) - INPUT_NAMES)
                    if unknown:
                        raise RuntimeError(
                            f"Linux candidate {artifact!r} maps unknown inputs: "
                            + ", ".join(unknown)
                        )
        if len(candidate_names) != len(set(candidate_names)):
            raise RuntimeError(
                f"Linux capability {capability_id!r} candidate artifacts must be unique."
            )
    missing = sorted(referenced - set(capabilities))
    if missing:
        raise RuntimeError(
            "Linux modes or focuses reference unknown capabilities: "
            + ", ".join(missing)
        )
    return deepcopy(payload)


def inventory_parameters(row: dict[str, Any]) -> set[str]:
    values = row.get("parameter_names")
    if isinstance(values, list):
        return {str(item) for item in values if str(item).strip()}
    csv_value = str(row.get("parameter_names_csv") or "")
    if csv_value:
        return {item.strip() for item in csv_value.split(",") if item.strip()}
    parameters = row.get("parameters")
    if isinstance(parameters, list):
        return {
            str(item.get("name"))
            for item in parameters
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        }
    return set()


def load_inventory(path: Path | str) -> tuple[list[dict[str, Any]], str]:
    source = Path(path).expanduser().resolve()
    try:
        raw = source.read_bytes()
        payload = json.loads(raw)
    except OSError as exc:
        raise RuntimeError(f"Artifact inventory {source} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Artifact inventory {source} is invalid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise RuntimeError(
            "Artifact inventory must be artifact_definitions_inventory.json list output."
        )
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict) or not str(item.get("name") or "").strip():
            raise RuntimeError(f"Artifact inventory row {index} requires name.")
        rows.append(dict(item))
    return rows, hashlib.sha256(raw).hexdigest()


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def bounded_path(value: str) -> bool:
    normalized = value.strip()
    return bool(
        normalized
        and normalized.startswith("/")
        and "\x00" not in normalized
        and "\n" not in normalized
        and "\r" not in normalized
        and normalized not in {"/", "/**", "/**/*", "*", "**", "**/*"}
        and len(normalized) >= 4
    )


def parse_bounded_time(value: str, label: str) -> datetime:
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"Linux input {label!r} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(
            f"Linux input {label!r} must include an explicit timezone."
        )
    return parsed


def low_selectivity_search(value: str) -> bool:
    normalized = re.sub(r"^\(\?[a-zA-Z-]+\)", "", value.strip()).casefold()
    tokens = re.findall(r"[a-z0-9._=-]{3,}", normalized)
    generic = {
        "get",
        "post",
        "head",
        "put",
        "delete",
        "options",
        "patch",
        "http",
        "https",
        "request",
        "response",
        "200",
        "201",
        "204",
        "301",
        "302",
        "400",
        "401",
        "403",
        "404",
        "500",
        "502",
        "503",
    }
    selective = [
        token
        for token in tokens
        if token not in generic and len(token.strip(".-_=")) >= 3
    ]
    return not selective


def validate_server_context(values: dict[str, str]) -> None:
    for name in ("server_role", "application_context", "log_format"):
        value = values.get(name, "")
        if value and len(value) < 3:
            raise RuntimeError(
                f"Linux web input {name!r} must be descriptive, not a placeholder."
            )
    timezone = values.get("log_timezone", "")
    if timezone and not re.fullmatch(
        r"(?:UTC|Z|[+-]\d{2}:\d{2}|[A-Za-z]+/[A-Za-z0-9_+-]+)",
        timezone,
    ):
        raise RuntimeError(
            "Linux web input 'log_timezone' must be UTC, Z, an explicit "
            "offset, or an IANA-style timezone."
        )


def validate_log_preflight(values: dict[str, str]) -> None:
    parsed: dict[str, int] = {}
    for name in ("estimated_log_bytes", "max_log_bytes"):
        value = values.get(name, "")
        if not value:
            continue
        try:
            parsed[name] = int(value)
        except ValueError as exc:
            raise RuntimeError(f"Linux input {name!r} must be an integer.") from exc
        if parsed[name] < 0 or (name == "max_log_bytes" and parsed[name] == 0):
            raise RuntimeError(f"Linux input {name!r} must be positive.")
    if (
        "estimated_log_bytes" in parsed
        and "max_log_bytes" in parsed
        and parsed["estimated_log_bytes"] > parsed["max_log_bytes"]
    ):
        raise RuntimeError(
            "Estimated Linux log bytes exceed the operator's maximum; "
            "narrow the log glob before LogHunter collection."
        )


def contract_sha256(contract: dict[str, Any]) -> str:
    canonical = json.dumps(
        contract,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def selected_capability_ids(
    contract: dict[str, Any],
    mode: str,
    focuses: list[str],
) -> tuple[list[str], list[str]]:
    mode_contract = contract["modes"][mode]
    required = list(mode_contract["required_capabilities"])
    optional = list(mode_contract["optional_capabilities"])
    for focus in focuses:
        focus_contract = contract["focuses"][focus]
        required.extend(focus_contract["required_capabilities"])
        optional.extend(focus_contract["optional_capabilities"])
    required = dedupe(required)
    optional = [item for item in dedupe(optional) if item not in required]
    return required, optional


def candidate_env(candidate: dict[str, Any], inputs: dict[str, str]) -> dict[str, str]:
    env = {
        str(key): str(value)
        for key, value in dict(candidate.get("fixed_env") or {}).items()
    }
    for input_name, parameter_name in dict(candidate.get("parameter_map") or {}).items():
        value = str(inputs.get(input_name) or "").strip()
        if value:
            env[str(parameter_name)] = value
    return dict(sorted(env.items()))


def command_for(
    action: str,
    *,
    investigation_id: str,
    client_id: str,
    artifact: str,
    env: dict[str, str],
    analysis_inputs: dict[str, str],
) -> str:
    parts = [
        "dfir",
        "collect",
        action,
        "--investigation-id",
        investigation_id,
        "--client-id",
        client_id,
        "--artifact",
        artifact,
    ]
    for key, value in env.items():
        parts.extend(["--env", f"{key}={value}"])
    for key, value in analysis_inputs.items():
        parts.extend(["--analysis-input", f"{key}={value}"])
    return shlex.join(parts)


def build_plan(
    *,
    inventory_rows: list[dict[str, Any]],
    inventory_sha256: str,
    mode: str,
    focuses: list[str] | None = None,
    include_optional: list[str] | None = None,
    distro: str | None = None,
    inputs: dict[str, str] | None = None,
    investigation_id: str = "INVESTIGATION_ID",
    client_id: str = "CLIENT_ID",
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    active = contract or load_contract()
    if mode not in active["modes"]:
        raise RuntimeError(f"Unsupported Linux mode {mode!r}.")
    focus_values = dedupe(list(focuses or []))
    unknown_focuses = sorted(set(focus_values) - set(active["focuses"]))
    if unknown_focuses:
        raise RuntimeError("Unknown Linux focuses: " + ", ".join(unknown_focuses))
    mode_contract = active["modes"][mode]
    if mode_contract["requires_focus"] and not focus_values:
        raise RuntimeError("Linux deep mode requires at least one --focus.")
    if mode != "deep" and focus_values:
        raise RuntimeError("--focus is supported only with --mode deep.")
    if distro is not None and distro not in DISTROS:
        raise RuntimeError(f"Unsupported Linux distro {distro!r}.")

    values = {key: str(value or "").strip() for key, value in (inputs or {}).items()}
    if mode_contract["requires_time_bounds"] and (
        not values.get("date_after") or not values.get("date_before")
    ):
        raise RuntimeError("Linux timeline mode requires --date-after and --date-before.")
    parsed_after = (
        parse_bounded_time(values["date_after"], "date_after")
        if values.get("date_after")
        else None
    )
    parsed_before = (
        parse_bounded_time(values["date_before"], "date_before")
        if values.get("date_before")
        else None
    )
    if parsed_after and parsed_before and parsed_after >= parsed_before:
        raise RuntimeError("Linux date_after must be earlier than date_before.")
    for path_input in ("path_glob", "log_glob", "web_root"):
        if values.get(path_input) and not bounded_path(values[path_input]):
            raise RuntimeError(
                f"Linux input {path_input!r} must be a bounded path or glob."
            )
    if values.get("document_root") and not bounded_path(values["document_root"]):
        raise RuntimeError(
            "Linux input 'document_root' must be a bounded absolute path."
        )
    validate_server_context(values)
    validate_log_preflight(values)
    if values.get("search_regex") in {".", ".*", "^.*$", "(?s).*"}:
        raise RuntimeError("Linux web-log search regex is unbounded.")
    if values.get("search_regex") and low_selectivity_search(values["search_regex"]):
        raise RuntimeError(
            "Linux web-log search regex is an obvious low-selectivity term."
        )

    inventory = {
        str(row["name"]): {
            "row": row,
            "parameters": inventory_parameters(row),
        }
        for row in inventory_rows
    }
    required_ids, optional_ids = selected_capability_ids(
        active,
        mode,
        focus_values,
    )
    optional_requests = dedupe(list(include_optional or []))
    if "all" in optional_requests:
        included_optional_ids = list(optional_ids)
    else:
        unknown_optional = sorted(set(optional_requests) - set(optional_ids))
        if unknown_optional:
            raise RuntimeError(
                "Requested optional capabilities are not available for this "
                "mode/focus: " + ", ".join(unknown_optional)
            )
        included_optional_ids = optional_requests
    active_capability_ids = [*required_ids, *included_optional_ids]
    consumed_inputs: set[str] = set()
    for focus_id in focus_values:
        consumed_inputs.update(
            active["focuses"][focus_id].get("required_inputs", [])
        )
    for capability_id in active_capability_ids:
        capability = active["capabilities"][capability_id]
        consumed_inputs.update(capability.get("required_inputs", []))
        for candidate in capability["candidates"]:
            consumed_inputs.update((candidate.get("parameter_map") or {}).keys())
    unused_inputs = sorted(
        name for name, value in values.items() if value and name not in consumed_inputs
    )
    if unused_inputs:
        raise RuntimeError(
            "Linux inputs are not used by the selected capabilities: "
            + ", ".join(unused_inputs)
            + ". Add the relevant --include-optional capability or remove them."
        )
    required_set = set(required_ids)
    enforced_set = required_set | set(included_optional_ids)
    blockers: list[str] = []
    for focus_id in focus_values:
        missing_focus_inputs = [
            name
            for name in active["focuses"][focus_id].get("required_inputs", [])
            if not values.get(name)
        ]
        if missing_focus_inputs:
            blockers.append(
                f"{focus_id}: missing context inputs "
                + ", ".join(missing_focus_inputs)
            )
    gaps: list[str] = []
    selections: list[dict[str, Any]] = []

    for capability_id in active_capability_ids:
        capability = active["capabilities"][capability_id]
        required_inputs = list(capability.get("required_inputs") or [])
        missing_inputs = [name for name in required_inputs if not values.get(name)]
        if missing_inputs:
            message = (
                f"{capability_id}: missing inputs " + ", ".join(missing_inputs)
            )
            (blockers if capability_id in enforced_set else gaps).append(message)
            continue

        candidates: list[dict[str, Any]] = []
        for candidate in capability["candidates"]:
            artifact = str(candidate["artifact"])
            inventory_item = inventory.get(artifact)
            if inventory_item is None:
                continue
            applicability = candidate.get("applicability")
            if applicability and applicability != distro:
                continue
            env = candidate_env(candidate, values)
            supported_parameters = set(inventory_item["parameters"])
            unsupported = sorted(set(env) - supported_parameters)
            if unsupported:
                (blockers if capability_id in enforced_set else gaps).append(
                    f"{capability_id}: {artifact} inventory lacks parameters "
                    + ", ".join(unsupported)
                )
                continue
            candidates.append(
                {
                    "artifact": artifact,
                    "env": env,
                    "applicability": applicability,
                }
            )

        if capability["selection"] == "first_applicable" and not distro:
            message = f"{capability_id}: select --distro before package collection"
            (blockers if capability_id in enforced_set else gaps).append(message)
            continue
        selected = (
            candidates
            if capability["selection"] == "all_available"
            else candidates[:1]
        )
        if not selected:
            message = f"{capability_id}: no validated candidate is available"
            (blockers if capability_id in enforced_set else gaps).append(message)
            continue
        for item in selected:
            artifact = item["artifact"]
            env = item["env"]
            mapped_inputs = set(
                dict(
                    next(
                        candidate
                        for candidate in capability["candidates"]
                        if candidate["artifact"] == artifact
                    ).get("parameter_map")
                    or {}
                )
            )
            analysis_inputs = {
                name: values[name]
                for name in capability.get("required_inputs", [])
                if values.get(name) and name not in mapped_inputs
            }
            selections.append(
                {
                    "capability": capability_id,
                    "required": capability_id in enforced_set,
                    "purpose": capability["purpose"],
                    "artifact": artifact,
                    "env": env,
                    "analysis_inputs": analysis_inputs,
                    "volatility": capability["volatility"],
                    "limitations": capability["limitations"],
                    "check_command": command_for(
                        "check",
                        investigation_id=investigation_id,
                        client_id=client_id,
                        artifact=artifact,
                        env=env,
                        analysis_inputs=analysis_inputs,
                    ),
                    "ensure_command": command_for(
                        "ensure",
                        investigation_id=investigation_id,
                        client_id=client_id,
                        artifact=artifact,
                        env=env,
                        analysis_inputs=analysis_inputs,
                    ),
                }
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ready" if not blockers else "incomplete",
        "mode": mode,
        "focuses": focus_values,
        "distro": distro or "",
        "server_context": {
            "server_role": values.get("server_role", ""),
            "application_context": values.get("application_context", ""),
            "document_root": values.get("document_root", ""),
            "log_timezone": values.get("log_timezone", ""),
            "log_format": values.get("log_format", ""),
        },
        "profile_sha256": contract_sha256(active),
        "source_inventory_sha256": inventory_sha256,
        "source_inventory_artifact_count": len(inventory_rows),
        "required_capabilities": required_ids,
        "available_optional_capabilities": optional_ids,
        "included_optional_capabilities": included_optional_ids,
        "selected_artifact_count": len(selections),
        "selected": selections,
        "blockers": blockers,
        "optional_gaps": gaps,
        "guardrails": [
            "Run check before ensure and reuse exact terminal or in-flight flows.",
            "Optional capabilities are excluded unless selected with --include-optional.",
            "Add --force-run only when a fresh exact collection is intentional.",
            "Analyze completed flows in place before considering export.",
            "Do not combine parameterized artifacts into one request; keep each reusable slice independent.",
            "Live process, network, service, mount, ARP, and Docker data are collection-time snapshots.",
            "Export only for explicit immutable evidence, offline review, or interoperability.",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve an inventory-validated Linux host-analysis plan without "
            "starting collections."
        )
    )
    parser.add_argument(
        "--inventory",
        required=True,
        help="artifact_definitions_inventory.json from artifacts inventory",
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=("triage", "standard", "deep", "timeline"),
    )
    parser.add_argument(
        "--focus",
        action="append",
        default=[],
        choices=(
            "persistence",
            "execution",
            "authentication",
            "web-server",
            "container",
            "filesystem",
        ),
    )
    parser.add_argument(
        "--include-optional",
        action="append",
        default=[],
        metavar="CAPABILITY",
        help=(
            "Include one mode/focus optional capability; repeat as needed or "
            "use 'all'. Optional live artifacts are excluded by default."
        ),
    )
    parser.add_argument("--distro", choices=tuple(sorted(DISTROS)))
    parser.add_argument("--investigation-id", default="INVESTIGATION_ID")
    parser.add_argument("--client-id", default="CLIENT_ID")
    parser.add_argument("--date-after")
    parser.add_argument("--date-before")
    parser.add_argument("--path-glob")
    parser.add_argument("--log-glob")
    parser.add_argument("--search-regex")
    parser.add_argument("--server-role")
    parser.add_argument("--application-context")
    parser.add_argument("--document-root")
    parser.add_argument("--log-timezone")
    parser.add_argument("--log-format")
    parser.add_argument("--estimated-log-bytes")
    parser.add_argument("--max-log-bytes")
    parser.add_argument("--web-root")
    parser.add_argument("--yara-rule")
    parser.add_argument("--profile", default=str(CONTRACT_PATH))
    parser.add_argument(
        "--output",
        help=(
            "Plan JSON path. Defaults beside the inventory using the plan "
            "content hash."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        inventory, digest = load_inventory(args.inventory)
        plan = build_plan(
            inventory_rows=inventory,
            inventory_sha256=digest,
            mode=args.mode,
            focuses=args.focus,
            include_optional=args.include_optional,
            distro=args.distro,
            inputs={
                "date_after": args.date_after,
                "date_before": args.date_before,
                "path_glob": args.path_glob,
                "log_glob": args.log_glob,
                "search_regex": args.search_regex,
                "server_role": args.server_role,
                "application_context": args.application_context,
                "document_root": args.document_root,
                "log_timezone": args.log_timezone,
                "log_format": args.log_format,
                "estimated_log_bytes": args.estimated_log_bytes,
                "max_log_bytes": args.max_log_bytes,
                "web_root": args.web_root,
                "yara_rule": args.yara_rule,
            },
            investigation_id=args.investigation_id,
            client_id=args.client_id,
            contract=load_contract(args.profile),
        )
        plan_digest = hashlib.sha256(
            json.dumps(
                plan,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        inventory_path = Path(args.inventory).expanduser().resolve()
        output_path = (
            Path(args.output).expanduser().resolve()
            if args.output
            else inventory_path.parent
            / f"linux-host-plan-{args.mode}-{plan_digest[:12]}.json"
        )
        plan["plan_sha256"] = plan_digest
        plan["plan_file"] = str(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_name(f".{output_path.name}.tmp")
        temporary.write_text(
            json.dumps(plan, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output_path)
        print(json.dumps(plan, indent=2, sort_keys=False))
        return 0 if plan["status"] == "ready" else 2
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
