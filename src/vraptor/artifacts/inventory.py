#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
from vraptor.paths import resolve_velociraptor_api_client_path
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.api import VeloApiClient
from vraptor.api import resolve_org_id
from vraptor.collect.catalog import ARTIFACT_GROUPS
from vraptor.collect.catalog import COLLECTION_TYPE_CHOICES
from vraptor.collect.catalog import load_collection_policy
from vraptor.common.sequences import unique_ordered

REFERENCE_JSON_PATH = artifact_profiles.BUILTIN_REFERENCE_PATH
QUESTION_SHAPE_CHOICES = ("cross-host", "single-host", "bounded-time-window", "artifact-inventory")
WINDOWS_SKILL_CHOICES = (
    "velociraptor-hunting",
    "velociraptor-host-analysis",
    "velociraptor-collection",
)
WORKFLOW_CHOICES = ("hunt", "collection", "analysis")
WORKFLOW_BY_WINDOWS_SKILL = {
    "velociraptor-hunting": ("hunt",),
    "velociraptor-host-analysis": ("collection", "analysis"),
    "velociraptor-collection": ("collection",),
}


NARROWING_PARAMETER_NAMES = {
    "DateAfter",
    "DateBefore",
    "ModifiedAfter",
    "ModifiedBefore",
    "Glob",
    "PathRegex",
    "FileRegex",
    "Regex",
    "IocRegex",
    "ChannelRegex",
    "ProviderRegex",
    "IdRegex",
    "FilenameRegex",
    "SearchRegex",
    "MFTDrive",
    "EvtxGlob",
}
TIME_BOUND_PARAMETER_NAMES = {
    "DateAfter",
    "DateBefore",
    "ModifiedAfter",
    "ModifiedBefore",
}
HUNT_PROFILE_ARTIFACTS = {
    "detectraptor": {
        "DetectRaptor.Windows.Detection.Evtx",
        "DetectRaptor.Windows.Detection.Applications",
        "DetectRaptor.Windows.Detection.Powershell.PSReadline",
        "DetectRaptor.Windows.Detection.MFT",
        "DetectRaptor.Windows.Detection.LolRMM",
        "DetectRaptor.Windows.Detection.Amcache",
        "DetectRaptor.Windows.Detection.BinaryRename",
        "DetectRaptor.Windows.Detection.Webhistory",
        "DetectRaptor.Windows.Detection.YaraProcessWin",
        "DetectRaptor.Generic.Detection.YaraWebshell",
        "DetectRaptor.Generic.Detection.BrowserExtensions",
        "DetectRaptor.Windows.Detection.ZoneIdentifier",
    },
    "lateral-movement": {
        "Windows.EventLogs.ServiceCreationComspec",
    },
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export Velociraptor artifact_definitions() inventory to CSV/JSON, "
            "join curated bias notes, and materialize recommendation-oriented "
            "shortlists for hunt, collection, or analysis planning."
        )
    )
    parser.add_argument("--api-client", help="Path to Velociraptor API client config.")
    parser.add_argument(
        "--server-profile",
        help="Velociraptor server/config profile used for API-client resolution.",
    )
    parser.add_argument(
        "--org-id",
        default=None,
        help="Velociraptor org id. Defaults to root, with orgs/<id> as a compatibility fallback.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Disposable cache directory to refresh or replace with inventory outputs.",
    )
    parser.add_argument("--name-regex", help="Optional regex filter against artifact name.")
    parser.add_argument("--description-regex", help="Optional regex filter against artifact description.")
    parser.add_argument("--type-regex", help="Optional regex filter against artifact type.")
    parser.add_argument("--parameter-regex", help="Optional regex filter against parameter names or serialized parameter JSON.")
    parser.add_argument(
        "--workflow",
        choices=WORKFLOW_CHOICES,
        help="Optional recommendation filter for high-level workflow owner: hunt, collection, or analysis.",
    )
    parser.add_argument(
        "--question-shape",
        choices=QUESTION_SHAPE_CHOICES,
        help="Optional recommendation filter for question shape such as cross-host or bounded-time-window.",
    )
    parser.add_argument(
        "--windows-skill",
        choices=WINDOWS_SKILL_CHOICES,
        help="Optional recommendation filter for the intended Windows skill owner.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Maximum number of rows to include in the recommendation shortlist when recommendation filters are used.",
    )
    parser.add_argument(
        "--force-run",
        action="store_true",
        help="Force a fresh artifact_definitions() export even when a matching prior export already exists.",
    )
    parser.add_argument(
        "--artifact-reference",
        action="append",
        default=[],
        help=(
            "Site or case artifact-reference JSON file or directory. Repeat to apply ordered overlays. "
            "Explicit values replace VELO_ARTIFACT_REFERENCE_PATHS."
        ),
    )
    return parser.parse_args(argv)


def compile_optional_regex(value: str | None) -> re.Pattern[str] | None:
    if not value:
        return None
    return re.compile(value, re.IGNORECASE)


def split_multi_value_field(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        return unique_ordered([str(item) for item in value])
    tokens = [item.strip() for item in re.split(r"[|,]", value) if item.strip()]
    return unique_ordered(tokens)


def join_multi_value_field(values: list[str]) -> str:
    return "|".join(unique_ordered([value.strip() for value in values if value.strip()]))


def resolved_org_id(args: argparse.Namespace) -> str:
    return resolve_org_id(
        args.org_id
    )


def resolved_api_client_path(args: argparse.Namespace) -> Path:
    return resolve_velociraptor_api_client_path(
        args.api_client,
        REPO_ROOT,
        server_profile=getattr(args, "server_profile", None),
    )


def file_fingerprint(path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        data = resolved.read_bytes()
    except OSError:
        return f"missing:{resolved}"
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def expected_cache_identity(
    args: argparse.Namespace,
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> dict[str, Any]:
    api_client_path = resolved_api_client_path(args)
    return {
        "schema_version": 2,
        "org_id": resolved_org_id(args),
        "api_client_path": str(api_client_path),
        "api_client_fingerprint": file_fingerprint(api_client_path),
        "artifact_policy": policy.portable_identity(),
    }


def artifact_base_name(name: str) -> str:
    return str(name).split("[", 1)[0].strip()


def artifact_name_matches(candidate: str, expected: str) -> bool:
    candidate_name = artifact_base_name(candidate)
    expected_name = artifact_base_name(expected)
    return bool(candidate_name and expected_name and candidate_name == expected_name)


def parameter_is_required(parameter: dict[str, Any]) -> bool:
    required_value = parameter.get("required")
    if isinstance(required_value, bool):
        return required_value
    mandatory_value = parameter.get("mandatory")
    if isinstance(mandatory_value, bool):
        return mandatory_value
    optional_value = parameter.get("optional")
    if isinstance(optional_value, bool):
        return not optional_value
    return False


def extract_parameter_details(parameters: list[dict[str, Any]]) -> dict[str, list[str]]:
    names = unique_ordered(
        [str(item.get("name") or "").strip() for item in parameters if isinstance(item, dict) and str(item.get("name") or "").strip()]
    )
    required = unique_ordered(
        [
            str(item.get("name") or "").strip()
            for item in parameters
            if isinstance(item, dict) and str(item.get("name") or "").strip() and parameter_is_required(item)
        ]
    )
    optional = [name for name in names if name not in set(required)]
    narrowing = [name for name in names if name in NARROWING_PARAMETER_NAMES]
    time_bound = [name for name in names if name in TIME_BOUND_PARAMETER_NAMES]
    return {
        "names": names,
        "required": required,
        "optional": optional,
        "narrowing": narrowing,
        "time_bound": time_bound,
    }


def derived_collection_types(artifact_name: str) -> list[str]:
    collection_types: list[str] = []
    for collection_type in COLLECTION_TYPE_CHOICES:
        if collection_type == "all":
            continue
        group_items = ARTIFACT_GROUPS.get(collection_type, ())
        if any(artifact_name_matches(item, artifact_name) for item in group_items):
            collection_types.append(str(collection_type))
    return unique_ordered(collection_types)


def derived_ir_collection_groups(artifact_name: str) -> list[str]:
    collection_groups: list[str] = []
    policy = load_collection_policy()
    for group_name, group in policy["groups"].items():
        alternatives = [
            alternative
            for item in group["artifacts"]
            for alternative in item["alternatives"]
        ]
        if any(artifact_name_matches(item, artifact_name) for item in alternatives):
            collection_groups.append(str(group_name))
    return unique_ordered(collection_groups)


def derived_hunt_profiles(artifact_name: str, windows_skills: list[str]) -> list[str]:
    profiles = [
        profile
        for profile, artifacts in HUNT_PROFILE_ARTIFACTS.items()
        if any(artifact_name_matches(item, artifact_name) for item in artifacts)
    ]
    if "velociraptor-hunting" in windows_skills and not profiles:
        profiles.append("targeted")
    return unique_ordered(profiles)


def derived_workflows(windows_skills: list[str]) -> list[str]:
    workflows = [
        workflow
        for skill in windows_skills
        for workflow in WORKFLOW_BY_WINDOWS_SKILL.get(skill, ())
    ]
    return unique_ordered(workflows)


def risk_rank(value: str) -> int:
    order = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "very-high": 3,
    }
    return order.get(str(value or "").strip().lower(), 99)


def load_bias_rows(
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> dict[str, dict[str, Any]]:
    return artifact_profiles.inventory_hint_rows(policy.profiles)


def filter_row(
    row: dict[str, Any],
    name_pattern: re.Pattern[str] | None,
    description_pattern: re.Pattern[str] | None,
    type_pattern: re.Pattern[str] | None,
    parameter_pattern: re.Pattern[str] | None,
) -> bool:
    name = str(row.get("name") or "")
    description = str(row.get("description") or "")
    artifact_type = str(row.get("type") or "")
    parameters_json = str(row.get("parameters_json") or "")
    parameter_names = ",".join(row.get("parameter_names") or [])

    if name_pattern and not name_pattern.search(name):
        return False
    if description_pattern and not description_pattern.search(description):
        return False
    if type_pattern and not type_pattern.search(artifact_type):
        return False
    if parameter_pattern and not (
        parameter_pattern.search(parameters_json) or parameter_pattern.search(parameter_names)
    ):
        return False
    return True


def serialize_metadata(item: Any) -> str:
    return json.dumps(item, separators=(",", ":"), ensure_ascii=True, sort_keys=True)


def normalize_rows(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in raw_rows:
        parameters = row.get("parameters")
        if not isinstance(parameters, list):
            parameters = []
        parameter_details = extract_parameter_details(parameters)
        parameter_names = parameter_details["names"]
        normalized.append(
            {
                "name": str(row.get("name") or ""),
                "description": str(row.get("description") or ""),
                "type": str(row.get("type") or ""),
                "built_in": bool(row.get("built_in")),
                "compiled_in": bool(row.get("compiled_in")),
                "is_alias": bool(row.get("is_alias")),
                "is_inherited": bool(row.get("is_inherited")),
                "parameter_count": len(parameter_names),
                "parameter_names": parameter_names,
                "parameter_names_csv": ",".join(name for name in parameter_names if name),
                "required_parameter_names": parameter_details["required"],
                "required_parameter_names_csv": ",".join(parameter_details["required"]),
                "optional_parameter_names": parameter_details["optional"],
                "optional_parameter_names_csv": ",".join(parameter_details["optional"]),
                "narrowing_parameter_names": parameter_details["narrowing"],
                "narrowing_parameter_names_csv": ",".join(parameter_details["narrowing"]),
                "time_bound_parameter_names": parameter_details["time_bound"],
                "time_bound_parameter_names_csv": ",".join(parameter_details["time_bound"]),
                "parameters_json": serialize_metadata(parameters),
                "metadata_json": serialize_metadata(row.get("metadata") or {}),
            }
        )
    normalized.sort(key=lambda item: item["name"].lower())
    return normalized


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def build_enriched_rows(rows: list[dict[str, Any]], bias_rows: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for row in rows:
        bias = bias_rows.get(row["name"], {})
        windows_skills = split_multi_value_field(bias.get("recommended_windows_skills", ""))
        question_shapes = split_multi_value_field(bias.get("recommended_question_shapes", ""))
        fallback_artifacts = split_multi_value_field(bias.get("fallback_artifacts", ""))
        stack_view_ids = split_multi_value_field(bias.get("stack_view_ids", ""))
        server_stack_view_ids = split_multi_value_field(bias.get("server_stack_view_ids", ""))
        stack_view_dimensions = split_multi_value_field(bias.get("stack_view_dimensions", ""))
        preferred_stack_fields = split_multi_value_field(bias.get("preferred_stack_fields", ""))
        server_stack_fields = split_multi_value_field(bias.get("server_stack_fields", ""))
        stack_metrics = split_multi_value_field(bias.get("stack_metrics", ""))
        preferred_sample_fields = split_multi_value_field(bias.get("preferred_sample_fields", ""))
        avoid_stack_fields = split_multi_value_field(bias.get("avoid_stack_fields", ""))
        recommended_filters = split_multi_value_field(bias.get("recommended_filters", ""))
        collection_types = derived_collection_types(row["name"])
        collection_groups = derived_ir_collection_groups(row["name"])
        hunt_profiles = derived_hunt_profiles(row["name"], windows_skills)
        workflows = derived_workflows(windows_skills)
        item = dict(row)
        item["signal_type"] = bias.get("signal_type", "")
        item["row_volume_risk"] = bias.get("row_volume_risk", "")
        item["time_bound_support"] = bias.get("time_bound_support", "")
        item["selection_bias"] = bias.get("selection_bias", "")
        item["interpretation_caveat"] = bias.get("interpretation_caveat", "")
        item["preferred_use_case"] = bias.get("preferred_use_case", "")
        item["review_strategy"] = bias.get("review_strategy", "")
        item["default_stack"] = bias.get("default_stack", "")
        item["default_server_stack"] = bias.get("default_server_stack", "")
        item["stack_view_ids"] = stack_view_ids
        item["stack_view_ids_csv"] = join_multi_value_field(stack_view_ids)
        item["server_stack_view_ids"] = server_stack_view_ids
        item["server_stack_view_ids_csv"] = join_multi_value_field(server_stack_view_ids)
        item["stack_view_dimensions"] = stack_view_dimensions
        item["stack_view_dimensions_csv"] = join_multi_value_field(stack_view_dimensions)
        item["preferred_stack_fields"] = preferred_stack_fields
        item["preferred_stack_fields_csv"] = join_multi_value_field(preferred_stack_fields)
        item["server_stack_fields"] = server_stack_fields
        item["server_stack_fields_csv"] = join_multi_value_field(item["server_stack_fields"])
        item["stack_metrics"] = stack_metrics
        item["stack_metrics_csv"] = join_multi_value_field(stack_metrics)
        item["preferred_sample_fields"] = preferred_sample_fields
        item["preferred_sample_fields_csv"] = join_multi_value_field(preferred_sample_fields)
        item["avoid_stack_fields"] = avoid_stack_fields
        item["avoid_stack_fields_csv"] = join_multi_value_field(avoid_stack_fields)
        item["recommended_filters"] = recommended_filters
        item["recommended_filters_csv"] = join_multi_value_field(recommended_filters)
        item["recommended_question_shapes"] = question_shapes
        item["recommended_question_shapes_csv"] = join_multi_value_field(question_shapes)
        item["recommended_windows_skills"] = windows_skills
        item["recommended_windows_skills_csv"] = join_multi_value_field(windows_skills)
        item["recommended_workflows"] = workflows
        item["recommended_workflows_csv"] = join_multi_value_field(workflows)
        item["recommended_hunt_profiles"] = hunt_profiles
        item["recommended_hunt_profiles_csv"] = join_multi_value_field(hunt_profiles)
        item["recommended_collection_types"] = collection_types
        item["recommended_collection_types_csv"] = join_multi_value_field(collection_types)
        item["recommended_ir_collection_groups"] = collection_groups
        item["recommended_ir_collection_groups_csv"] = join_multi_value_field(
            collection_groups
        )
        item["fallback_artifacts"] = fallback_artifacts
        item["fallback_artifacts_csv"] = join_multi_value_field(fallback_artifacts)
        item["normalizer_names"] = split_multi_value_field(bias.get("normalizer_names", ""))
        item["normalizer_names_csv"] = join_multi_value_field(item["normalizer_names"])
        item["profile_hash"] = str(bias.get("profile_hash") or "")
        item["profile_sources"] = split_multi_value_field(bias.get("profile_sources", ""))
        item["profile_sources_csv"] = join_multi_value_field(item["profile_sources"])
        item["artifact_profile"] = bias.get("artifact_profile") if isinstance(bias.get("artifact_profile"), dict) else {}
        enriched.append(item)
    return enriched


def recommendation_filters_requested(args: argparse.Namespace) -> bool:
    return bool(args.workflow or args.question_shape or args.windows_skill)


def recommendation_matches(row: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.workflow and args.workflow not in row.get("recommended_workflows", []):
        return False
    if args.question_shape and args.question_shape not in row.get("recommended_question_shapes", []):
        return False
    if args.windows_skill and args.windows_skill not in row.get("recommended_windows_skills", []):
        return False
    return True


def recommendation_score(row: dict[str, Any], args: argparse.Namespace) -> int:
    score = 0
    if args.workflow and args.workflow in row.get("recommended_workflows", []):
        score += 4
    if args.question_shape and args.question_shape in row.get("recommended_question_shapes", []):
        score += 3
    if args.windows_skill and args.windows_skill in row.get("recommended_windows_skills", []):
        score += 5
    if row.get("preferred_use_case"):
        score += 1
    if row.get("narrowing_parameter_names"):
        score += 1
    return score


def recommendation_reason(row: dict[str, Any]) -> str:
    parts: list[str] = []
    workflows = row.get("recommended_workflows", [])
    windows_skills = row.get("recommended_windows_skills", [])
    collection_types = row.get("recommended_collection_types", [])
    hunt_profiles = row.get("recommended_hunt_profiles", [])
    preferred_use_case = str(row.get("preferred_use_case") or "").strip()
    if workflows:
        parts.append(f"Best fit for {', '.join(workflows)} workflow planning")
    if windows_skills:
        parts.append(f"Normal Windows owner: {', '.join(windows_skills)}")
    if hunt_profiles:
        parts.append(f"Hunt profile hint: {', '.join(hunt_profiles)}")
    if collection_types:
        parts.append(f"Collection bundle hint: {', '.join(collection_types)}")
    if preferred_use_case:
        parts.append(preferred_use_case)
    return "; ".join(parts)


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts if str(part))


def review_command_base(row: dict[str, Any]) -> list[str]:
    return [
        "dfir",
        "hunt",
        "native",
        "review-results",
        "--investigation-id",
        "$INVESTIGATION_ID",
        "--hunt-id",
        "$HUNT_ID",
        "--artifact",
        str(row.get("name") or ""),
    ]


def review_where_args(row: dict[str, Any]) -> list[str]:
    review_strategy = str(row.get("review_strategy") or "").strip()
    recommended_filters = row.get("recommended_filters") or []
    if review_strategy in {"detection_or_keyword", "command_or_keyword", "auth_pivot"} or recommended_filters:
        return ["--where", "$REVIEW_WHERE"]
    return []


def review_sample_command(row: dict[str, Any]) -> str:
    fields = list(row.get("preferred_sample_fields") or [])
    args = [
        *review_command_base(row),
        "--review-operation",
        "sample",
        "--review-depth",
        "explore",
    ]
    for field in fields:
        args.extend(["--field", field])
    args.extend(review_where_args(row))
    return shell_join(args)


def review_stack_command(row: dict[str, Any]) -> str:
    fields = list(row.get("server_stack_fields") or row.get("preferred_stack_fields") or [])
    if not fields:
        return ""
    args = [
        *review_command_base(row),
        "--review-operation",
        "stack",
        "--review-depth",
        "explore",
    ]
    for field in fields:
        args.extend(["--group-by", field])
    args.extend(review_where_args(row))
    return shell_join(args)


def review_inventory_command(row: dict[str, Any]) -> str:
    fields = list(row.get("server_stack_fields") or row.get("preferred_stack_fields") or [])
    args = [
        *review_command_base(row),
        "--review-operation",
        "inventory",
        "--inventory-mode",
        "quick",
        "--review-depth",
        "explore",
    ]
    for field in fields:
        args.extend(["--inventory-group-by", field])
    args.extend(review_where_args(row))
    return shell_join(args)


def review_filter_hint(row: dict[str, Any]) -> str:
    filters = list(row.get("recommended_filters") or [])
    if not filters:
        return ""
    return (
        "Set $REVIEW_WHERE to a bounded server-side VQL expression before running "
        "the command, and prefer hunt-time filters when available: "
        + ", ".join(filters)
    )


def build_recommendation_rows(rows: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    shortlisted = [row for row in rows if recommendation_matches(row, args)] if recommendation_filters_requested(args) else list(rows)
    shortlisted.sort(
        key=lambda row: (
            -recommendation_score(row, args),
            risk_rank(str(row.get("row_volume_risk") or "")),
            str(row.get("name") or "").lower(),
        )
    )
    if recommendation_filters_requested(args):
        shortlisted = shortlisted[: max(args.top, 0)]

    recommendations: list[dict[str, Any]] = []
    for row in shortlisted:
        recommendations.append(
            {
                "artifact": row["name"],
                "description": row["description"],
                "recommended_workflows": row.get("recommended_workflows", []),
                "recommended_workflows_csv": row.get("recommended_workflows_csv", ""),
                "recommended_question_shapes": row.get("recommended_question_shapes", []),
                "recommended_question_shapes_csv": row.get("recommended_question_shapes_csv", ""),
                "recommended_windows_skills": row.get("recommended_windows_skills", []),
                "recommended_windows_skills_csv": row.get("recommended_windows_skills_csv", ""),
                "recommended_hunt_profiles": row.get("recommended_hunt_profiles", []),
                "recommended_hunt_profiles_csv": row.get("recommended_hunt_profiles_csv", ""),
                "recommended_collection_types": row.get("recommended_collection_types", []),
                "recommended_collection_types_csv": row.get("recommended_collection_types_csv", ""),
                "recommended_ir_collection_groups": row.get(
                    "recommended_ir_collection_groups", []
                ),
                "recommended_ir_collection_groups_csv": row.get(
                    "recommended_ir_collection_groups_csv", ""
                ),
                "required_parameter_names": row.get("required_parameter_names", []),
                "required_parameter_names_csv": row.get("required_parameter_names_csv", ""),
                "optional_parameter_names": row.get("optional_parameter_names", []),
                "optional_parameter_names_csv": row.get("optional_parameter_names_csv", ""),
                "narrowing_parameter_names": row.get("narrowing_parameter_names", []),
                "narrowing_parameter_names_csv": row.get("narrowing_parameter_names_csv", ""),
                "time_bound_parameter_names": row.get("time_bound_parameter_names", []),
                "time_bound_parameter_names_csv": row.get("time_bound_parameter_names_csv", ""),
                "signal_type": row.get("signal_type", ""),
                "row_volume_risk": row.get("row_volume_risk", ""),
                "time_bound_support": row.get("time_bound_support", ""),
                "preferred_use_case": row.get("preferred_use_case", ""),
                "review_strategy": row.get("review_strategy", ""),
                "default_stack": row.get("default_stack", ""),
                "default_server_stack": row.get("default_server_stack", ""),
                "stack_view_ids": row.get("stack_view_ids", []),
                "stack_view_ids_csv": row.get("stack_view_ids_csv", ""),
                "server_stack_view_ids": row.get("server_stack_view_ids", []),
                "server_stack_view_ids_csv": row.get("server_stack_view_ids_csv", ""),
                "stack_view_dimensions": row.get("stack_view_dimensions", []),
                "stack_view_dimensions_csv": row.get("stack_view_dimensions_csv", ""),
                "preferred_stack_fields": row.get("preferred_stack_fields", []),
                "preferred_stack_fields_csv": row.get("preferred_stack_fields_csv", ""),
                "server_stack_fields": row.get("server_stack_fields", []),
                "server_stack_fields_csv": row.get("server_stack_fields_csv", ""),
                "stack_metrics": row.get("stack_metrics", []),
                "stack_metrics_csv": row.get("stack_metrics_csv", ""),
                "preferred_sample_fields": row.get("preferred_sample_fields", []),
                "preferred_sample_fields_csv": row.get("preferred_sample_fields_csv", ""),
                "avoid_stack_fields": row.get("avoid_stack_fields", []),
                "avoid_stack_fields_csv": row.get("avoid_stack_fields_csv", ""),
                "recommended_filters": row.get("recommended_filters", []),
                "recommended_filters_csv": row.get("recommended_filters_csv", ""),
                "selection_bias": row.get("selection_bias", ""),
                "interpretation_caveat": row.get("interpretation_caveat", ""),
                "fallback_artifacts": row.get("fallback_artifacts", []),
                "fallback_artifacts_csv": row.get("fallback_artifacts_csv", ""),
                "normalizer_names": row.get("normalizer_names", []),
                "normalizer_names_csv": row.get("normalizer_names_csv", ""),
                "profile_hash": row.get("profile_hash", ""),
                "profile_sources": row.get("profile_sources", []),
                "profile_sources_csv": row.get("profile_sources_csv", ""),
                "artifact_profile": row.get("artifact_profile", {}),
                "recommendation_reason": recommendation_reason(row),
                "recommendation_score": recommendation_score(row, args),
                "review_sample_command": review_sample_command(row),
                "review_stack_command": review_stack_command(row),
                "review_inventory_command": review_inventory_command(row),
                "review_filter_hint": review_filter_hint(row),
            }
        )
    return recommendations


def expected_filters(args: argparse.Namespace) -> dict[str, str]:
    return {
        "name_regex": args.name_regex or "",
        "description_regex": args.description_regex or "",
        "type_regex": args.type_regex or "",
        "parameter_regex": args.parameter_regex or "",
        "workflow": args.workflow or "",
        "question_shape": args.question_shape or "",
        "windows_skill": args.windows_skill or "",
        "top": str(args.top) if recommendation_filters_requested(args) else "",
    }


def existing_export_matches(
    summary_path: Path,
    args: argparse.Namespace,
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> tuple[bool, dict[str, Any] | None]:
    if not summary_path.exists():
        return False, None
    try:
        payload = read_json(summary_path)
    except (json.JSONDecodeError, OSError):
        return False, None
    if not isinstance(payload, dict):
        return False, None

    if payload.get("cache_identity") != expected_cache_identity(args, policy):
        return False, payload
    if payload.get("filters") != expected_filters(args):
        return False, payload

    output_files = payload.get("output_files")
    if not isinstance(output_files, dict):
        return False, payload

    required_keys = (
        "json",
        "csv",
        "enriched_csv",
        "recommendations_json",
        "recommendations_csv",
        "artifact_profiles_json",
        "artifact_profiles_csv",
    )
    for key in required_keys:
        value = output_files.get(key)
        if not value or not Path(str(value)).exists():
            return False, payload
    return True, payload


def print_output_paths(output_files: dict[str, Any]) -> None:
    ordered_keys = (
        "csv",
        "enriched_csv",
        "recommendations_csv",
        "recommendations_json",
        "summary",
    )
    for key in ordered_keys:
        value = output_files.get(key)
        if value:
            print(str(value))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    name_pattern = compile_optional_regex(args.name_regex)
    description_pattern = compile_optional_regex(args.description_regex)
    type_pattern = compile_optional_regex(args.type_regex)
    parameter_pattern = compile_optional_regex(args.parameter_regex)
    policy = artifact_policy.load_artifact_policy(
        getattr(args, "artifact_reference", [])
    )
    profiles = policy.profiles
    reference_paths = policy.profile_sources
    bias_rows = load_bias_rows(policy)
    summary_path = output_dir / "artifact_definitions_inventory_summary.json"

    if not args.force_run:
        matched, summary_payload = existing_export_matches(
            summary_path,
            args,
            policy,
        )
        if matched and isinstance(summary_payload, dict):
            print_output_paths(summary_payload["output_files"])
            return 0

    org_id = resolved_org_id(args)
    with VeloApiClient(resolved_api_client_path(args), org_id=org_id) as api:
        raw_rows = api.query(
            "SELECT name, description, type, built_in, compiled_in, is_alias, is_inherited, parameters, metadata FROM artifact_definitions()"
        )

    rows = normalize_rows(raw_rows)
    filtered_rows = [
        row
        for row in rows
        if filter_row(row, name_pattern, description_pattern, type_pattern, parameter_pattern)
    ]
    enriched_rows = build_enriched_rows(filtered_rows, bias_rows)
    recommendation_rows = build_recommendation_rows(enriched_rows, args)

    json_path = output_dir / "artifact_definitions_inventory.json"
    csv_path = output_dir / "artifact_definitions_inventory.csv"
    enriched_csv_path = output_dir / "artifact_definitions_inventory_enriched.csv"
    recommendations_json_path = output_dir / "artifact_definitions_inventory_recommendations.json"
    recommendations_csv_path = output_dir / "artifact_definitions_inventory_recommendations.csv"
    profile_outputs = artifact_profiles.write_profile_exports(output_dir, profiles, reference_paths)

    write_json(json_path, filtered_rows)
    write_csv(
        csv_path,
        filtered_rows,
        [
            "name",
            "description",
            "type",
            "built_in",
            "compiled_in",
            "is_alias",
            "is_inherited",
            "parameter_count",
            "parameter_names_csv",
            "required_parameter_names_csv",
            "optional_parameter_names_csv",
            "narrowing_parameter_names_csv",
            "time_bound_parameter_names_csv",
            "parameters_json",
            "metadata_json",
        ],
    )
    write_csv(
        enriched_csv_path,
        enriched_rows,
        [
            "name",
            "description",
            "type",
            "parameter_count",
            "parameter_names_csv",
            "signal_type",
            "row_volume_risk",
            "time_bound_support",
            "selection_bias",
            "interpretation_caveat",
            "preferred_use_case",
            "review_strategy",
            "default_stack",
            "default_server_stack",
            "stack_view_ids_csv",
            "server_stack_view_ids_csv",
            "stack_view_dimensions_csv",
            "preferred_stack_fields_csv",
            "server_stack_fields_csv",
            "stack_metrics_csv",
            "preferred_sample_fields_csv",
            "avoid_stack_fields_csv",
            "recommended_filters_csv",
            "recommended_workflows_csv",
            "recommended_question_shapes_csv",
            "recommended_windows_skills_csv",
            "recommended_hunt_profiles_csv",
            "recommended_collection_types_csv",
            "recommended_ir_collection_groups_csv",
            "fallback_artifacts_csv",
            "normalizer_names_csv",
            "profile_hash",
            "profile_sources_csv",
            "required_parameter_names_csv",
            "optional_parameter_names_csv",
            "narrowing_parameter_names_csv",
            "time_bound_parameter_names_csv",
            "parameters_json",
        ],
    )
    write_json(
        recommendations_json_path,
        {
            "org_id": org_id,
            "filters": expected_filters(args),
            "artifact_policy": policy.metadata(),
            "artifact_count_total": len(rows),
            "artifact_count_exported": len(filtered_rows),
            "recommendation_count": len(recommendation_rows),
            "recommendations": recommendation_rows,
        },
    )
    write_csv(
        recommendations_csv_path,
        recommendation_rows,
        [
            "artifact",
            "description",
            "recommended_workflows_csv",
            "recommended_question_shapes_csv",
            "recommended_windows_skills_csv",
            "recommended_hunt_profiles_csv",
            "recommended_collection_types_csv",
            "recommended_ir_collection_groups_csv",
            "signal_type",
            "row_volume_risk",
            "time_bound_support",
            "review_strategy",
            "default_stack",
            "default_server_stack",
            "stack_view_ids_csv",
            "server_stack_view_ids_csv",
            "stack_view_dimensions_csv",
            "preferred_stack_fields_csv",
            "server_stack_fields_csv",
            "stack_metrics_csv",
            "preferred_sample_fields_csv",
            "avoid_stack_fields_csv",
            "recommended_filters_csv",
            "required_parameter_names_csv",
            "optional_parameter_names_csv",
            "narrowing_parameter_names_csv",
            "time_bound_parameter_names_csv",
            "fallback_artifacts_csv",
            "normalizer_names_csv",
            "profile_hash",
            "profile_sources_csv",
            "preferred_use_case",
            "selection_bias",
            "interpretation_caveat",
            "recommendation_reason",
            "recommendation_score",
            "review_sample_command",
            "review_stack_command",
            "review_inventory_command",
            "review_filter_hint",
        ],
    )
    write_json(
        summary_path,
        {
            "storage_class": "disposable_cache",
            "source_of_truth": "velociraptor",
            "evidence": False,
            "artifact_count_total": len(rows),
            "artifact_count_exported": len(filtered_rows),
            "recommendation_count": len(recommendation_rows),
            "org_id": org_id,
            "cache_identity": expected_cache_identity(args, policy),
            "artifact_policy": policy.metadata(),
            "filters": expected_filters(args),
            "force_run": bool(args.force_run),
            "output_files": {
                "json": str(json_path),
                "csv": str(csv_path),
                "enriched_csv": str(enriched_csv_path),
                "recommendations_json": str(recommendations_json_path),
                "recommendations_csv": str(recommendations_csv_path),
                **profile_outputs,
                "summary": str(summary_path),
            },
        },
    )

    print_output_paths(
        {
            "csv": str(csv_path),
            "enriched_csv": str(enriched_csv_path),
            "recommendations_csv": str(recommendations_csv_path),
            "recommendations_json": str(recommendations_json_path),
            "summary": str(summary_path),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
