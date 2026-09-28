"""Stable artifact groups shared by collection planning and artifact selection."""

from __future__ import annotations
from vraptor.resources import resource_root

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


COLLECTION_POLICY_PATH = (
    Path(os.environ["VRAPTOR_COLLECTION_POLICY"]).expanduser().resolve()
    if os.environ.get("VRAPTOR_COLLECTION_POLICY") else
    resource_root() / "collection-groups.json"
)
COLLECTION_POLICY_SCHEMA_VERSION = 1

COLLECTION_TYPE_CHOICES = (
    "all",
    "triage",
    "detectraptor",
    "evtx",
    "mft",
    "network",
    "execution",
    "persistence",
    "persistence-expanded",
    "lateral-movement",
    "exfiltration",
    "timeline",
    "registry",
)

BASELINE_COLLECTION_TYPES = (
    "triage",
    "network",
    "execution",
    "persistence-expanded",
    "lateral-movement",
)

EVTX_ARTIFACTS = (
    "DetectRaptor.Windows.Detection.Evtx",
    "Windows.Detection.PublicIP",
)

MFT_ARTIFACTS = (
    "DetectRaptor.Windows.Detection.MFT",
)

DETECTRAPTOR_ARTIFACTS = (
    "DetectRaptor.Windows.Detection.Evtx",
    "DetectRaptor.Windows.Detection.MFT",
    "DetectRaptor.Windows.Detection.Powershell.PSReadline",
    "DetectRaptor.Windows.Detection.Applications",
    "DetectRaptor.Windows.Detection.LolRMM",
    "DetectRaptor.Windows.Detection.Amcache",
    "DetectRaptor.Windows.Detection.BinaryRename",
    "DetectRaptor.Windows.Detection.Webhistory",
    "DetectRaptor.Windows.Detection.YaraProcessWin",
    "DetectRaptor.Generic.Detection.YaraWebshell",
    "DetectRaptor.Generic.Detection.BrowserExtensions",
    "DetectRaptor.Windows.Detection.ZoneIdentifier",
)

TRIAGE_ARTIFACTS = EVTX_ARTIFACTS + tuple(
    artifact
    for artifact in DETECTRAPTOR_ARTIFACTS[1:]
    if artifact != "DetectRaptor.Generic.Detection.YaraWebshell"
)

ARTIFACT_GROUPS = {
    "triage": TRIAGE_ARTIFACTS,
    "detectraptor": DETECTRAPTOR_ARTIFACTS,
    "evtx": EVTX_ARTIFACTS,
    "mft": MFT_ARTIFACTS,
    "network": (
        "Windows.Network.NetstatEnriched",
        "Windows.System.DNSCache",
    ),
    "execution": (
        "Windows.Detection.Amcache",
        "Windows.Forensics.Bam",
        "Windows.Forensics.RecentFileCache",
        "Windows.Forensics.Timeline",
        "Windows.Forensics.SRUM",
        "Windows.System.AppCompatPCA",
        "Windows.Forensics.Prefetch",
    ),
    "persistence": (
        "Windows.Sysinternals.Autoruns",
    ),
    "persistence-expanded": (
        "Windows.Sys.StartupItems",
        "Windows.System.Services",
        "Windows.System.TaskScheduler",
        "Windows.Registry.TaskCache.HiddenTasks",
        "Windows.Persistence.PermanentWMIEvents",
        "Windows.Sysinternals.Autoruns",
    ),
    "lateral-movement": (
        "Windows.EventLogs.RDPAuth",
        "Windows.EventLogs.ExplicitLogon",
        "Windows.Registry.MountPoints2",
        "Windows.EventLogs.ServiceCreationComspec",
    ),
    "exfiltration": (
        "Windows.EventLogs.EvtxHunter",
        "Windows.NTFS.MFT",
        "Windows.Forensics.SRUM",
        "Windows.Forensics.Prefetch",
    ),
    "timeline": (
        "Windows.NTFS.MFT",
        "Windows.EventLogs.EvtxHunter",
    ),
    "registry": (
        "Windows.Registry.Hunter[all]",
    ),
}

SUPPORTED_COLLECTION_TYPES = tuple(ARTIFACT_GROUPS)


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _ordered_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _require_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Collection policy {field_name} must be a non-empty list.")
    result = [str(item).strip() for item in value]
    if any(not item for item in result):
        raise RuntimeError(f"Collection policy {field_name} contains an empty value.")
    if len(result) != len(set(result)):
        raise RuntimeError(f"Collection policy {field_name} contains duplicate values.")
    return result


def validate_collection_policy(policy: dict[str, Any]) -> None:
    if int(policy.get("schema_version") or 0) != COLLECTION_POLICY_SCHEMA_VERSION:
        raise RuntimeError(
            "Unsupported collection policy schema_version "
            f"{policy.get('schema_version')!r}; expected {COLLECTION_POLICY_SCHEMA_VERSION}."
        )
    target_modes = set(
        _require_string_list(policy.get("target_modes"), "target_modes")
    )
    requirements = set(
        _require_string_list(policy.get("requirements"), "requirements")
    )
    cost_classes = set(
        _require_string_list(policy.get("cost_classes"), "cost_classes")
    )
    scope_gates = set(
        _require_string_list(policy.get("scope_gates"), "scope_gates")
    )
    groups = policy.get("groups")
    if not isinstance(groups, dict) or not groups:
        raise RuntimeError("Collection policy groups must be a non-empty object.")

    for group_name, group in groups.items():
        if not str(group_name).strip() or not isinstance(group, dict):
            raise RuntimeError("Collection policy contains an invalid group entry.")
        artifacts = group.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise RuntimeError(
                f"Collection policy group {group_name!r} needs artifact entries."
            )
        if not any(
            isinstance(item, dict) and item.get("requirement") == "core"
            for item in artifacts
        ):
            raise RuntimeError(
                f"Collection policy group {group_name!r} needs at least one core source."
            )
        logical_ids: set[str] = set()
        for index, item in enumerate(artifacts):
            field_prefix = f"groups.{group_name}.artifacts[{index}]"
            if not isinstance(item, dict):
                raise RuntimeError(f"Collection policy {field_prefix} must be an object.")
            logical_id = str(item.get("id") or "").strip()
            if not logical_id or logical_id in logical_ids:
                raise RuntimeError(
                    f"Collection policy {field_prefix}.id must be unique and non-empty."
                )
            logical_ids.add(logical_id)
            alternatives = _require_string_list(
                item.get("alternatives"), f"{field_prefix}.alternatives"
            )
            if "Windows.Registry.Hunter[all]" in alternatives:
                raise RuntimeError(
                    "Windows.Registry.Hunter[all] must remain a standalone opt-in "
                    "collection and cannot appear in IR collection groups."
                )
            requirement = str(item.get("requirement") or "")
            if requirement not in requirements:
                raise RuntimeError(
                    f"Collection policy {field_prefix}.requirement is not supported."
                )
            applicability = set(
                _require_string_list(
                    item.get("applicability"), f"{field_prefix}.applicability"
                )
            )
            if not applicability <= target_modes:
                raise RuntimeError(
                    f"Collection policy {field_prefix}.applicability contains an "
                    "unsupported target mode."
                )
            if str(item.get("cost") or "") not in cost_classes:
                raise RuntimeError(
                    f"Collection policy {field_prefix}.cost is not supported."
                )
            if str(item.get("scope_gate") or "none") not in scope_gates:
                raise RuntimeError(
                    f"Collection policy {field_prefix}.scope_gate is not supported."
                )
            default_parameters = item.get("default_parameters") or {}
            if not isinstance(default_parameters, dict) or any(
                not str(key).strip() or not isinstance(value, str)
                for key, value in default_parameters.items()
            ):
                raise RuntimeError(
                    f"Collection policy {field_prefix}.default_parameters must "
                    "map non-empty names to string values."
                )

    bundles = policy.get("bundles")
    if not isinstance(bundles, dict) or not bundles:
        raise RuntimeError("Collection policy bundles must be a non-empty object.")
    prohibited = set(str(item) for item in policy.get("prohibited_baseline_artifacts") or [])
    for bundle_name, bundle in bundles.items():
        if not str(bundle_name).strip() or not isinstance(bundle, dict):
            raise RuntimeError("Collection policy contains an invalid bundle entry.")
        if str(bundle.get("target_mode") or "") not in target_modes:
            raise RuntimeError(
                f"Collection policy bundle {bundle_name!r} has an invalid target_mode."
            )
        bundle_groups = _require_string_list(
            bundle.get("groups"), f"bundles.{bundle_name}.groups"
        )
        unknown_groups = sorted(set(bundle_groups) - set(groups))
        if unknown_groups:
            raise RuntimeError(
                f"Collection policy bundle {bundle_name!r} references unknown group(s): "
                + ", ".join(unknown_groups)
            )
        selected_names = {
            alternative
            for group_name in bundle_groups
            for item in groups[group_name]["artifacts"]
            for alternative in item["alternatives"]
        }
        disallowed = sorted(selected_names & prohibited)
        if disallowed:
            raise RuntimeError(
                f"Collection policy bundle {bundle_name!r} contains prohibited "
                "baseline artifact(s): "
                + ", ".join(disallowed)
            )

    followups = policy.get("followups")
    if not isinstance(followups, dict) or not followups:
        raise RuntimeError("Collection policy followups must be a non-empty object.")
    for followup_name, followup in followups.items():
        if not str(followup_name).strip() or not isinstance(followup, dict):
            raise RuntimeError("Collection policy contains an invalid follow-up entry.")
        if not str(followup.get("route") or "").strip():
            raise RuntimeError(
                f"Collection policy follow-up {followup_name!r} needs a route."
            )
        if str(followup.get("cost") or "") not in cost_classes:
            raise RuntimeError(
                f"Collection policy follow-up {followup_name!r} has an invalid cost."
            )
        if str(followup.get("scope_gate") or "") not in scope_gates:
            raise RuntimeError(
                f"Collection policy follow-up {followup_name!r} has an invalid scope gate."
            )
        _require_string_list(
            followup.get("required_inputs"),
            f"followups.{followup_name}.required_inputs",
        )
        if not str(followup.get("reason") or "").strip():
            raise RuntimeError(
                f"Collection policy follow-up {followup_name!r} needs a reason."
            )


@lru_cache(maxsize=1)
def load_collection_policy() -> dict[str, Any]:
    try:
        policy = json.loads(COLLECTION_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Unable to load collection policy {COLLECTION_POLICY_PATH}: {exc}"
        ) from exc
    if not isinstance(policy, dict):
        raise RuntimeError("Collection policy root must be a JSON object.")
    validate_collection_policy(policy)
    return policy


def collection_policy_metadata() -> dict[str, Any]:
    policy = load_collection_policy()
    return {
        "policy_id": str(policy.get("policy_id") or ""),
        "schema_version": int(policy["schema_version"]),
        "sha256": hashlib.sha256(_stable_json(policy).encode("utf-8")).hexdigest(),
    }


def collection_policy_followups() -> dict[str, Any]:
    return json.loads(_stable_json(load_collection_policy().get("followups") or {}))


def resolve_collection_policy(
    *,
    bundle: str | None = None,
    groups: Iterable[str] = (),
    target_mode: str | None = None,
    available_artifacts: Iterable[str] | None = None,
) -> dict[str, Any]:
    policy = load_collection_policy()
    policy_groups = dict(policy["groups"])
    policy_bundles = dict(policy["bundles"])
    requested_groups = _ordered_unique(str(item).strip() for item in groups if str(item).strip())

    bundle_name = str(bundle or "").strip()
    if bundle_name:
        if bundle_name not in policy_bundles:
            raise RuntimeError(f"Unknown IR collection bundle {bundle_name!r}.")
        if requested_groups:
            raise RuntimeError("--bundle cannot be combined with --collection-group.")
        bundle_definition = policy_bundles[bundle_name]
        requested_groups = list(bundle_definition["groups"])
        inferred_mode = str(bundle_definition["target_mode"])
        if target_mode and str(target_mode) != inferred_mode:
            raise RuntimeError(
                f"Bundle {bundle_name!r} requires target mode {inferred_mode!r}."
            )
        resolved_target_mode = inferred_mode
    else:
        if not requested_groups:
            raise RuntimeError("At least one IR collection group is required.")
        resolved_target_mode = str(target_mode or "").strip()
        if not resolved_target_mode:
            raise RuntimeError(
                "Custom IR collection groups require --target-mode live or mapped-disk."
            )

    if resolved_target_mode not in set(policy["target_modes"]):
        raise RuntimeError(f"Unsupported target mode {resolved_target_mode!r}.")
    unknown_groups = sorted(set(requested_groups) - set(policy_groups))
    if unknown_groups:
        raise RuntimeError(
            "Unknown IR collection group(s): " + ", ".join(unknown_groups)
        )

    availability_checked = available_artifacts is not None
    available = set(str(item).strip() for item in available_artifacts or [] if str(item).strip())
    logical_sources: list[dict[str, Any]] = []
    candidate_artifacts: list[str] = []
    selected_artifacts: list[str] = []
    missing_core: list[str] = []
    unavailable_recommended: list[str] = []
    unavailable_optional: list[str] = []
    not_applicable: list[str] = []

    for group_name in requested_groups:
        for item in policy_groups[group_name]["artifacts"]:
            logical_id = str(item["id"])
            source_key = f"{group_name}:{logical_id}"
            alternatives = [str(value) for value in item["alternatives"]]
            applicable = resolved_target_mode in set(item["applicability"])
            selected = ""
            if applicable:
                candidate_artifacts.extend(alternatives)
                if availability_checked:
                    selected = next(
                        (artifact for artifact in alternatives if artifact in available),
                        "",
                    )
                else:
                    selected = alternatives[0]

            if not applicable:
                status = "not_applicable"
                not_applicable.append(source_key)
            elif selected:
                status = "selected" if availability_checked else "availability_unchecked"
                selected_artifacts.append(selected)
            elif item["requirement"] == "core":
                status = "missing_core"
                missing_core.append(source_key)
            elif item["requirement"] == "recommended":
                status = "unavailable_recommended"
                unavailable_recommended.append(source_key)
            else:
                status = "unavailable_optional"
                unavailable_optional.append(source_key)
            logical_sources.append(
                {
                    "source_key": source_key,
                    "group": group_name,
                    "logical_id": logical_id,
                    "requirement": str(item["requirement"]),
                    "cost": str(item["cost"]),
                    "scope_gate": str(item.get("scope_gate") or "none"),
                    "default_parameters": dict(item.get("default_parameters") or {}),
                    "applicability": list(item["applicability"]),
                    "alternatives": alternatives,
                    "selected_artifact": selected,
                    "status": status,
                }
            )

    selected_artifacts = _ordered_unique(selected_artifacts)
    candidate_artifacts = _ordered_unique(candidate_artifacts)
    physical_sources: list[dict[str, Any]] = []
    for artifact in selected_artifacts:
        matching = [
            item for item in logical_sources if item["selected_artifact"] == artifact
        ]
        default_parameters: dict[str, str] = {}
        for item in matching:
            for name, value in item["default_parameters"].items():
                if name in default_parameters and default_parameters[name] != value:
                    raise RuntimeError(
                        f"Collection policy has conflicting default parameter {name!r} "
                        f"for selected artifact {artifact!r}."
                    )
                default_parameters[name] = value
        physical_sources.append(
            {
                "artifact": artifact,
                "groups": _ordered_unique(item["group"] for item in matching),
                "logical_sources": [item["source_key"] for item in matching],
                "requirements": _ordered_unique(
                    item["requirement"] for item in matching
                ),
                "default_parameters": default_parameters,
            }
        )

    group_statuses: list[dict[str, Any]] = []
    for group_name in requested_groups:
        sources = [item for item in logical_sources if item["group"] == group_name]
        statuses = {str(item["status"]) for item in sources}
        if "missing_core" in statuses:
            group_status = "core_missing"
        elif statuses == {"not_applicable"}:
            group_status = "not_applicable"
        elif statuses & {"unavailable_recommended", "unavailable_optional"}:
            group_status = "degraded"
        elif "availability_unchecked" in statuses:
            group_status = "availability_unchecked"
        else:
            group_status = "ready"
        group_statuses.append(
            {
                "group": group_name,
                "status": group_status,
                "analysis_profile": str(
                    policy_groups[group_name].get("analysis_profile") or "generic"
                ),
            }
        )

    if missing_core and not bundle_name:
        status = "blocked"
    elif missing_core or unavailable_recommended or unavailable_optional:
        status = "degraded"
    elif availability_checked:
        status = "ready"
    else:
        status = "availability_unchecked"

    return {
        "status": status,
        "bundle": bundle_name,
        "target_mode": resolved_target_mode,
        "requested_groups": requested_groups,
        "candidate_artifacts": candidate_artifacts,
        "available_artifacts": sorted(available & set(candidate_artifacts)) if availability_checked else [],
        "selected_artifacts": selected_artifacts,
        "logical_sources": logical_sources,
        "physical_sources": physical_sources,
        "group_statuses": group_statuses,
        "missing_core": missing_core,
        "unavailable_recommended": unavailable_recommended,
        "unavailable_optional": unavailable_optional,
        "not_applicable": not_applicable,
        "followup_ids": list((policy.get("followups") or {}).keys()),
        "policy": collection_policy_metadata(),
    }


_IR_POLICY = load_collection_policy()
IR_COLLECTION_GROUPS = tuple(_IR_POLICY["groups"])
IR_COLLECTION_BUNDLES = tuple(_IR_POLICY["bundles"])
IR_TARGET_MODES = tuple(_IR_POLICY["target_modes"])
