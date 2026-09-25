#!/usr/bin/env python3
"""Bounded live hunt analysis without materializing raw evidence."""

from __future__ import annotations
from vraptor.resources import resource_root

import base64
import copy
import csv
import functools
import gzip
import hashlib
import io
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from vraptor.agent import diagnostics as agent_diagnostics
from vraptor.analyze import limits as analysis_limits
from vraptor.common import atomic_io
from vraptor.common import token_budget
from vraptor.common.hashing import sha256_file
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.profiles import PROFILE_NAMES
from vraptor.agent.profiles import RESPONSE_DEPTH_NAMES
from vraptor.agent.profiles import load_agent_profile_config
from vraptor.agent.profiles import normalize_profile_name
from vraptor.agent.profiles import normalize_response_depth
from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import ai_review as autoruns_ai_review
from vraptor.autoruns import golden as autoruns_golden
from vraptor.autoruns import regex as autoruns_regex
from vraptor.autoruns import reporting as autoruns_reporting
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.analyze import flow as flow_analysis
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.analyze import stack_review as generic_stack_review
from vraptor.hunt import operations as hunting
from vraptor.artifacts import persistence as persistence_policy
from vraptor.logging import operations as operation_log
from vraptor.analyze import source as review_source
from vraptor.api import InventoryNotFoundError
from vraptor.api import build_vql_request
from vraptor.api import org_id_candidates


ANALYSIS_VERSION = 3
FILTER_SCHEMA_VERSION = 2
AUTORUNS_RESIDUAL_WORKFLOW_VERSION = 3
AUTORUNS_STREAMING_WORKFLOW_VERSION = 2
GENERIC_STACK_STREAMING_WORKFLOW_VERSION = 2
AUTORUNS_REVIEW_QUEUE_SCHEMA_VERSION = 2
REPORT_MAX_CONTEXT_GROUPS = 10
CANONICAL_CONTEXT_SUMMARY_LIMIT = 20
CANONICAL_CONTEXT_TEXT_CHARS = 192
REPORT_MAX_ENDPOINTS_PER_GROUP = 10
REPORT_MAX_FINDINGS = 20
REPORT_MAX_TEXT_CHARS = 320
REPORT_MAX_NARRATIVE_ITEMS = 50
REPORT_MAX_RESPONSE_REVIEW_ITEMS = 100
REPORT_MAX_RESPONSE_EXAMPLE_ROWS = 3
REPORT_MAX_RESPONSE_ROW_FIELDS = 20
REPORT_MAX_CHAT_CHARS = 32_000
REVIEW_ITEMS_MANIFEST_FILENAME = "review-items.json"
REVIEW_SCOPE_AD_HOC = "ad_hoc_review"
AUTORUNS_POTENTIAL_GOLDEN_FILENAME = "autoruns_potential_golden.csv"
AUTORUNS_REVIEW_QUEUE_FIELDS = (
    "ReviewId",
    "Artifact",
    "UseCase",
    "Kind",
    "Category",
    "EntryLocation",
    "Entry",
    "ImagePath",
    "LaunchString",
    "Signer",
    "ScopeRowCount",
    "ExactVariantCountLowerBound",
    "ClosureEligible",
    "EvidenceHash",
    "PriorityReviewReasons",
    "AiDisposition",
    "AiSeverity",
    "AiConfidence",
    "AiDrilldownRecommended",
    "AiReason",
    "AiModel",
    "Complete",
    "Disposition",
    "Reason",
    "DrilldownReason",
    "HijackRiskReviewed",
    "VariantRiskReviewed",
    "LolbinBehaviorReviewed",
    "UnverifiedSignerReviewed",
    "PromoteToGolden",
    "FindingsJson",
    "FiltersJson",
    "NormalizationCandidatesJson",
    "PendingReviewJson",
)
AUTORUNS_REVIEW_QUEUE_AI_FIELDS = (
    "AiDisposition",
    "AiSeverity",
    "AiConfidence",
    "AiDrilldownRecommended",
    "AiReason",
    "AiModel",
)
AUTORUNS_POTENTIAL_GOLDEN_FIELDS = (
    "ImagePath",
    "LaunchString",
    "Signer",
    "Total",
    "Reason",
)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_DIRECT_ROW_LIMIT = 1_000
DEFAULT_SAMPLE_ROWS = 100
DEFAULT_STACK_DISCOVERY_ROWS = generic_stack_review.DEFAULT_DISCOVERY_ROWS
MIN_STACK_DISCOVERY_ROWS = generic_stack_review.MIN_DISCOVERY_ROWS
MAX_STACK_DISCOVERY_ROWS = generic_stack_review.MAX_DISCOVERY_ROWS
DEFAULT_MAX_BRANCHES = 20
DEFAULT_MAX_REVIEW_ROWS = 1_000
DEFAULT_MAX_STACK_GROUPS = 2_500
DEFAULT_QUERY_BATCH_ROWS = 100
DEFAULT_AUTORUNS_DRILLDOWN_REQUEST_BYTES = 1024 * 1024
DEFAULT_DRILLDOWN_WORKERS = 8
SIGNATURE_GROUP_LIMIT = 20
DOMINANT_SIGNATURE_LIMIT = 5
REPETITIVE_COVERAGE = 0.80
MIXED_COVERAGE = 0.30
REPETITIVE_PATTERN_ROWS = 3
MIXED_PATTERN_ROWS = 5
FILTER_REFERENCE_ENV_VAR = "VELO_HUNT_FILTER_PATHS"
AUTORUNS_GOLDEN_TOOL_ENV_VAR = "VELO_AUTORUNS_GOLDEN_TOOL"
AUTORUNS_GOLDEN_VERSION_ENV_VAR = "VELO_AUTORUNS_GOLDEN_VERSION"
LOLBIN_REFERENCE_PATH = (
    resource_root() / "windows-lolbins.json"
)
AUTORUNS_ARTIFACTS = {
    "IG.Windows.Sysinternals.Autoruns",
    "Windows.Sysinternals.Autoruns",
}
AUTORUNS_USE_CASES = {
    "autoruns-lolbin",
    "autoruns-rmm",
    "autoruns-unverified",
}
AUTORUNS_AUTOMATED_USE_CASES = {
    "autoruns-lolbin",
    "autoruns-unverified",
}
COLLECTION_STACK_SIGNAL_TYPES = {
    "auth",
    "browser-activity",
    "command-history",
    "event-log",
    "usage",
}
SUSPICIOUS_OUTPUT_NAMES = {
    "suspicious_lolbins.json",
    "suspicious_rmm.json",
    "suspicious_unverified.json",
}
ACTIVE_FILTER_STATUSES = {"case-approved", "promoted", "detection-applied"}
FILTER_STATUSES = {
    "candidate",
    "case-approved",
    "promoted",
    "detection-applied",
    "retired",
}
FILTER_OPERATORS = {"eq", "regex"}
TERMINAL_HUNT_STATES = {"FINISHED", "STOPPED"}


def source_review_strategy(
    *,
    source: review_source.ReviewSource | None,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Select row review for snapshots and stacking for comparative records."""
    if source is None or source.source_type != "flow":
        return {
            "mode": "fleet-stack",
            "source_type": "hunt",
            "stacking": True,
            "reason": "Hunts compare repeated values and prevalence across hosts.",
        }
    signal_type = str(profile.get("signal_type") or "").strip().lower()
    stacking = signal_type in COLLECTION_STACK_SIGNAL_TYPES
    return {
        "mode": (
            "collection-event-stack"
            if stacking
            else "collection-direct-context"
        ),
        "source_type": "flow",
        "signal_type": signal_type,
        "stacking": stacking,
        "reason": (
            "Event-like records benefit from frequency and pattern comparison."
            if stacking
            else "Single-host state is reviewed as contextual rows without "
            "fleet-style prevalence counts."
        ),
    }
QUERY_OUTCOME_COMPLETE = "complete"
QUERY_OUTCOME_ROW_LIMIT = "row_limit_reached"
QUERY_OUTCOME_TOKEN_LIMIT = "token_limit_reached"
QUERY_OUTCOME_FIRST_ROW_OVERSIZED = "first_row_oversized"
QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED = "shared_budget_exhausted"
ACCOUNTING_DISPOSITIONS = {"benign", "expected", "notable", "suspicious"}
VERIFIED_SIGNER_RE = re.compile(
    r"(?i)^\s*\(?verified\)?(?:\s|$)"
)
NORMALIZATION_KINDS = {
    "autoruns_user_path",
    "casefold",
    "command_line",
    "guid",
    "timestamp",
    "version",
    "whitespace",
    "windows_path",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def accounting_id_for(
    *,
    artifact: str,
    scope: dict[str, Any],
    stack_id: str,
    values: list[Any],
) -> str:
    return "accounting-" + sha256_value(
        {
            "artifact": artifact,
            "scope": scope,
            "stack_id": stack_id,
            "values": values,
        }
    )[:16]


def unique_dicts(values: Iterable[dict[str, Any]], *, key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for value in values:
        identity = str(value.get(key) or "")
        if not identity or identity in seen:
            continue
        seen.add(identity)
        output.append(value)
    return output


def analysis_paths(
    hunt_root: Path,
    *,
    memory_filename: str = "analysis-hunt.md",
) -> dict[str, Path]:
    root = hunt_root / "analysis"
    return {
        "root": root,
        "state": root / flow_analysis_coordinator.STATE_FILENAME,
        "filters": root / "filters.json",
        "analysis_memory": hunt_root / memory_filename,
        "review_items_manifest": root / REVIEW_ITEMS_MANIFEST_FILENAME,
        "summary": hunt_root / memory_filename,
        "autoruns_potential_golden": (
            root / AUTORUNS_POTENTIAL_GOLDEN_FILENAME
        ),
        "autoruns_review": root / "autoruns_review.csv",
        "autoruns_ai_review": root / "autoruns_ai_review",
    }


def analysis_output_paths(
    paths: dict[str, Path],
    *,
    use_case: str,
) -> dict[str, Path]:
    selected = str(use_case or "").strip()
    if not selected:
        return {"filters": paths["filters"]}
    if selected not in AUTORUNS_USE_CASES:
        raise RuntimeError(
            f"Unknown analysis output use case {selected!r}."
        )
    suffix = selected.removeprefix("autoruns-").replace("_", "-")
    return {"filters": paths["root"] / f"filters-{suffix}.json"}


def load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected a JSON object in {path}.")
    return payload


@functools.lru_cache(maxsize=8)
def lolbin_image_path_regex(path: Path = LOLBIN_REFERENCE_PATH) -> str:
    payload = load_json_object(path)
    names = payload.get("executables")
    if not isinstance(names, list):
        raise RuntimeError(f"LOLBIN reference {path} must contain executables.")
    normalized = sorted(
        {
            str(name).strip().lower()
            for name in names
            if str(name).strip().lower().endswith(".exe")
        }
    )
    if not normalized:
        raise RuntimeError(f"LOLBIN reference {path} contains no executables.")
    return r"(?i)(?:^|[\\/])(?:" + "|".join(
        re.escape(name) for name in normalized
    ) + r")$"


def autoruns_use_case(
    artifact: str,
    requested: str,
    *,
    env: dict[str, str],
    rmm_classifier: autoruns_golden.RmmClassifier | None = None,
) -> dict[str, Any] | None:
    use_case = str(requested or "").strip()
    if not use_case:
        return None
    if artifact not in AUTORUNS_ARTIFACTS:
        raise RuntimeError(
            f"Use case {use_case!r} is only supported for Sysinternals "
            "Autoruns artifacts."
        )
    if use_case not in AUTORUNS_USE_CASES:
        raise RuntimeError(
            f"Unknown Autoruns use case {use_case!r}. Expected one of: "
            + ", ".join(sorted(AUTORUNS_USE_CASES))
            + "."
        )
    if use_case == "autoruns-lolbin":
        variable = bind_value(
            env,
            "UseCaseLolbinRegex",
            lolbin_image_path_regex(),
        )
        return {
            "id": use_case,
            "output_name": "suspicious_lolbins.json",
            "purpose": (
                "Stack LOLBAS executable candidates by image path, launch "
                "string, and signer; drill suspicious tuples to all matching "
                "hosts and original Autoruns context."
            ),
            "where": f"(lowcase(string=`Image Path`) =~ {variable})",
            "family_stack": {
                "purpose": "LOLBIN image-path and launch-string triage.",
                "analysis_role": "family_signature",
                "dimensions": [
                    "EntryLocation",
                    "Entry",
                    "ImagePath",
                    "LaunchString",
                    "Signer",
                ],
                "server_dimensions": [
                    "lowcase(string=`Entry Location`)",
                    autoruns.ascii_lower_vql("Entry"),
                    autoruns.user_path_vql("`Image Path`"),
                    autoruns.user_path_vql("`Launch String`"),
                    autoruns.ascii_lower_vql("Signer"),
                ],
            },
            "reference": str(LOLBIN_REFERENCE_PATH),
            "reference_hash": sha256_value(
                load_json_object(LOLBIN_REFERENCE_PATH)
            ),
        }
    if use_case == "autoruns-rmm":
        classifier = rmm_classifier or autoruns_golden.RmmClassifier()
        variable = bind_value(
            env,
            "UseCaseRmmRegex",
            classifier.regex(),
        )
        return {
            "id": use_case,
            "output_name": "suspicious_rmm.json",
            "purpose": (
                "Stack RMM, remote-access, dual-use administration, and "
                "greyware candidates by path, launch string, and signer; "
                "drill suspicious or unauthorized tuples to all matching "
                "hosts and original Autoruns context."
            ),
            "where": (
                f"(string=`Image Path` =~ {variable} OR "
                f"string=`Launch String` =~ {variable})"
            ),
            "family_stack": {
                "purpose": "RMM and greyware path and launch-string triage.",
                "analysis_role": "family_signature",
                "dimensions": [
                    "EntryLocation",
                    "Entry",
                    "ImagePath",
                    "LaunchString",
                    "Signer",
                ],
                "server_dimensions": [
                    "lowcase(string=`Entry Location`)",
                    autoruns.ascii_lower_vql("Entry"),
                    autoruns.user_path_vql("`Image Path`"),
                    autoruns.user_path_vql("`Launch String`"),
                    autoruns.ascii_lower_vql("Signer"),
                ],
            },
            "reference": str(classifier.path),
            "reference_hash": classifier.reference_hash,
        }
    verified = bind_value(env, "UseCaseVerifiedRegex", r"(?i)verified")
    return {
        "id": use_case,
        "output_name": "suspicious_unverified.json",
        "purpose": (
            "Stack unverified Autoruns entries that have an Image Path or "
            "Launch String; drill suspicious tuples to all matching hosts and "
            "original Autoruns context."
        ),
        "where": (
            f"(NOT (string=Signer =~ {verified}) AND "
            "(`Image Path` OR `Launch String`))"
        ),
        "family_stack": {
            "purpose": "Unverified populated Autoruns entry triage.",
            "analysis_role": "family_signature",
            "dimensions": [
                "EntryLocation",
                "Entry",
                "ImagePath",
                "LaunchString",
                "Signer",
            ],
            "server_dimensions": [
                "lowcase(string=`Entry Location`)",
                autoruns.ascii_lower_vql("Entry"),
                autoruns.user_path_vql("`Image Path`"),
                autoruns.user_path_vql("`Launch String`"),
                autoruns.ascii_lower_vql("Signer"),
            ],
        },
    }


def configured_autoruns_golden(
    *,
    tool: str = "",
    version: str = "",
    database: Path | None = None,
    rmm_reference: Path | None = None,
    environ: dict[str, str] | None = None,
    disabled: bool = False,
) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    selected_tool = str(
        ""
        if disabled
        else tool or env.get(AUTORUNS_GOLDEN_TOOL_ENV_VAR) or ""
    ).strip()
    selected_version = str(
        ""
        if disabled
        else version or env.get(AUTORUNS_GOLDEN_VERSION_ENV_VAR) or ""
    ).strip()
    classifier = autoruns_golden.RmmClassifier(rmm_reference)
    result = {
        "enabled": bool(selected_tool),
        "tool": selected_tool,
        "version": selected_version,
        "lolbin_reference_hash": sha256_value(
            load_json_object(LOLBIN_REFERENCE_PATH)
        ),
        "rmm_reference": str(classifier.path),
        "rmm_reference_hash": classifier.reference_hash,
        "rmm_regex": classifier.regex(),
    }
    if result["enabled"] and database is not None:
        resolved_database = database.expanduser().resolve()
        lookup = autoruns_golden.live_lookup_payload(
            resolved_database,
            rmm_reference=rmm_reference,
        )
        result.update(
            {
                "database": str(resolved_database),
                "database_sha256": lookup["sha256"],
                "identity_count": lookup["identity_count"],
                "record_count": lookup["record_count"],
                "lookup_key_count": lookup["lookup_key_count"],
                "lookup_payload_sha256": lookup[
                    "lookup_payload_sha256"
                ],
                "lookup_uncompressed_bytes": lookup[
                    "lookup_uncompressed_bytes"
                ],
                "lookup_compressed_bytes": lookup[
                    "lookup_compressed_bytes"
                ],
                "lookup_base64_bytes": lookup["lookup_base64_bytes"],
                "lookup_gzip_base64": lookup["lookup_gzip_base64"],
                "regex_only": bool(lookup.get("regex_only")),
                "regex_rule_count": lookup.get("regex_rule_count", 0),
                "regex_lookup_gzip_base64": lookup.get("regex_lookup_gzip_base64", ""),
                "lookup_transport": lookup["lookup_transport"],
            }
        )
    return result


def autoruns_golden_general_metadata(
    configuration: dict[str, Any],
) -> dict[str, Any]:
    metadata = {
        key: configuration[key]
        for key in (
            "enabled",
            "tool",
            "version",
            "inventory_hash",
            "database_sha256",
            "identity_count",
            "record_count",
            "lookup_key_count",
            "regex_rule_count",
            "lookup_payload_sha256",
            "lookup_transport",
            "inventory_sync",
        )
        if key in configuration
    }
    if metadata.get("enabled"):
        metadata["residual_workflow_version"] = (
            AUTORUNS_RESIDUAL_WORKFLOW_VERSION
        )
    return metadata


def resolve_autoruns_golden_inventory(
    api: Any,
    configuration: dict[str, Any],
    *,
    sync_missing_or_stale: bool = False,
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    resolved = dict(configuration)
    if not resolved.get("enabled"):
        return resolved
    database_hash = str(resolved.get("database_sha256") or "").strip()
    database_path = str(resolved.get("database") or "").strip()
    if (
        not database_hash
        or not database_path
        or not resolved.get("lookup_gzip_base64")
    ):
        raise RuntimeError(
            "Configured Autoruns GoldenDB requires the shared local SQLite "
            "database so its compact lookup index can be sent to server VQL."
        )
    version = str(resolved.get("version") or "")
    version_hash = re.search(r"-([0-9a-fA-F]{8})$", version)
    if (
        version_hash is not None
        and not database_hash.casefold().startswith(
            version_hash.group(1).casefold()
        )
    ):
        raise RuntimeError(
            "Configured Autoruns GoldenDB version does not match the shared "
            "local SQLite database."
        )
    try:
        rows = api.query(
            """
            SELECT inventory_get(
                tool=ToolName,
                version=ToolVersion,
                probe=TRUE) AS Inventory
            FROM scope()
            """,
            {
                "ToolName": str(resolved["tool"]),
                "ToolVersion": str(resolved.get("version") or ""),
            },
            max_wait=30,
            max_row=5,
        )
    except InventoryNotFoundError:
        # A missing pinned version is expected on first use or after an update.
        # Keep publication and hash verification in the existing sync path.
        rows = []
    inventory = (rows[0] if rows else {}).get("Inventory")
    inventory_hash = ""
    sync_reason = ""
    if not isinstance(inventory, dict):
        sync_reason = "missing"
    else:
        definition = inventory.get("Definition")
        definition = definition if isinstance(definition, dict) else {}
        inventory_hash = str(
            definition.get("hash")
            or definition.get("Hash")
            or inventory.get(
                f"Tool_{resolved['tool']}_HASH",
                "",
            )
            or ""
        ).strip()
        if not inventory_hash:
            sync_reason = "missing_hash"
        elif inventory_hash.casefold() != database_hash.casefold():
            sync_reason = "stale"

    if sync_reason:
        if not sync_missing_or_stale:
            if sync_reason == "missing":
                raise RuntimeError(
                    "Configured Autoruns GoldenDB inventory tool was not "
                    "found. Publish the current database before running live "
                    "analysis."
                )
            if sync_reason == "missing_hash":
                raise RuntimeError(
                    "Configured Autoruns GoldenDB inventory definition lacks "
                    "a hash. Republish the current database before running "
                    "live analysis."
                )
            raise RuntimeError(
                "Published Autoruns GoldenDB inventory hash does not match "
                "the shared local SQLite database. Push the current database "
                "before running live analysis."
            )
        publication = autoruns_golden.publish_database(
            api,
            Path(database_path),
            tool_name=str(resolved["tool"]),
            tool_version=version,
            rmm_reference=rmm_reference,
        )
        inventory_hash = str(
            publication.get("database_sha256") or ""
        ).strip()
        if inventory_hash.casefold() != database_hash.casefold():
            raise RuntimeError(
                "Autoruns GoldenDB publication verification did not match "
                "the shared local SQLite database."
            )
        resolved["inventory_sync"] = {
            "status": "updated",
            "reason": sync_reason,
            "tool": str(resolved["tool"]),
            "version": version,
            "database_sha256": database_hash,
        }
    else:
        resolved["inventory_sync"] = {
            "status": "current",
            "reason": "",
            "tool": str(resolved["tool"]),
            "version": version,
            "database_sha256": database_hash,
        }
    resolved["inventory_hash"] = inventory_hash
    return resolved


def autoruns_golden_where(
    artifact: str,
    *,
    configuration: dict[str, Any],
    env: dict[str, str],
    preserve_priority: bool = False,
) -> str:
    if (
        artifact not in AUTORUNS_ARTIFACTS
        or not configuration.get("enabled")
    ):
        return ""
    lookup_payload = str(
        configuration.get("lookup_gzip_base64") or ""
    )
    if not lookup_payload:
        raise RuntimeError(
            "Autoruns GoldenDB server lookup index was not configured."
        )
    env["AutorunsGoldenLookupGzipBase64"] = lookup_payload
    hash_key = autoruns.trusted_key_vql()
    lookup = f"get(item=AutorunsGoldenKeys, field={hash_key})"
    if configuration.get("regex_only"):
        lookup = "FALSE"
    if configuration.get("regex_rule_count"):
        regex_payload = str(configuration.get("regex_lookup_gzip_base64") or "")
        if not regex_payload:
            raise RuntimeError("Autoruns GoldenDB regex lookup index was not configured.")
        env["AutorunsGoldenRegexGzipBase64"] = regex_payload
        regex_match = (
            "AutorunsGoldenRegexMatch("
            f"GoldenImage={autoruns.user_path_vql('`Image Path`')}, "
            f"GoldenLaunch={autoruns.user_path_vql('`Launch String`')})"
        )
        if configuration.get("regex_only"):
            category = autoruns.ascii_lower_vql('if(condition=Category, then=Category, else="")')
            regex_match = (f"AutorunsGoldenRegexOnlyMatch(GoldenCategory={category}, "
                f"GoldenImage={autoruns.user_path_vql('`Image Path`')}, "
                f"GoldenLaunch={autoruns.user_path_vql('`Launch String`')}, "
                f"GoldenSigner={autoruns.ascii_lower_vql('Signer')})")
        # if() is lazy: exact hits never walk the regex rules.
        lookup = f"if(condition={lookup}, then=TRUE, else={regex_match})"
    if not preserve_priority:
        return f"(NOT ({lookup}))"
    lolbin_regex = bind_value(
        env,
        "AutorunsGoldenLolbinRegex",
        lolbin_image_path_regex(),
    )
    rmm_regex = bind_value(
        env,
        "AutorunsGoldenRmmRegex",
        str(configuration["rmm_regex"]),
    )
    verified_regex = bind_value(
        env,
        "AutorunsGoldenVerifiedRegex",
        r"(?i)verified",
    )
    priority = " OR ".join(
        [
            f"(lowcase(string=`Image Path`) =~ {lolbin_regex})",
            (
                f"(NOT (string=Signer =~ {verified_regex}) AND "
                "(`Image Path` OR `Launch String`))"
            ),
            (
                f"(string=`Image Path` =~ {rmm_regex} OR "
                f"string=`Launch String` =~ {rmm_regex})"
            ),
            "(string=`Image Path` =~ '''(?i)^\\s*file not found:''')",
            "(string=`Launch String` =~ '''(?i)^\\s*file not found:''')",
        ]
    )
    return f"(NOT ({lookup}) OR ({priority}))"


def autoruns_non_promotable_reasons(
    *,
    logical_dimensions: list[str],
    values: list[str],
    classifier: autoruns_golden.RmmClassifier,
) -> list[str]:
    mapped = {
        str(name): str(value)
        for name, value in zip(
            logical_dimensions,
            values,
            strict=False,
        )
    }
    image_path = (
        mapped.get("NormalizedImagePath")
        or mapped.get("ImagePath")
        or ""
    )
    launch_string = (
        mapped.get("NormalizedLaunchString")
        or mapped.get("LaunchString")
        or ""
    )
    reasons = classifier.reasons(
        image_path=image_path,
        launch_string=launch_string,
    )
    if autoruns_golden.is_missing_file(
        image_path=image_path,
        launch_string=launch_string,
    ):
        reasons.append("missing-file")
    return reasons


def autoruns_priority_review_reasons(
    *,
    logical_dimensions: list[str],
    values: list[str],
) -> list[str]:
    mapped = {
        str(name): str(value)
        for name, value in zip(
            logical_dimensions,
            values,
            strict=False,
        )
    }
    image_path = (
        mapped.get("NormalizedImagePath")
        or mapped.get("ImagePath")
        or ""
    )
    launch_string = (
        mapped.get("NormalizedLaunchString")
        or mapped.get("LaunchString")
        or ""
    )
    signer = mapped.get("Signer") or ""
    reasons: list[str] = []
    if image_path and re.search(
        lolbin_image_path_regex(),
        image_path,
    ):
        reasons.append("lolbin-image")
    if (
        (image_path or launch_string)
        and not VERIFIED_SIGNER_RE.search(signer)
    ):
        reasons.append("unverified-signer")
    return reasons


def pending_autoruns_priority_review_reasons(
    pending: dict[str, Any],
) -> list[str]:
    review_match = dict(pending.get("review_match") or {})
    return autoruns_priority_review_reasons(
        logical_dimensions=[
            str(value)
            for value in review_match.get("logical_dimensions") or []
        ],
        values=[
            str(value)
            for value in review_match.get("values") or []
        ],
    )


def configured_filter_paths(
    explicit: Iterable[str | Path] | None,
    *,
    environ: dict[str, str] | None = None,
) -> list[Path]:
    requested = [
        Path(value).expanduser().resolve()
        for value in (explicit or [])
        if str(value).strip()
    ]
    if requested:
        return requested
    env = environ if environ is not None else os.environ
    configured = str(env.get(FILTER_REFERENCE_ENV_VAR) or "").strip()
    if not configured:
        return []
    return [
        Path(value).expanduser().resolve()
        for value in configured.split(os.pathsep)
        if value.strip()
    ]


def filter_identity(record: dict[str, Any]) -> str:
    basis = {
        "artifact": str(record.get("artifact") or ""),
        "use_case": str(record.get("use_case") or ""),
        "scope": dict(record.get("scope") or {}),
        "conditions": filter_conditions(record),
    }
    return f"filter-{sha256_value(basis)[:16]}"


def filter_conditions(record: dict[str, Any]) -> list[dict[str, str]]:
    raw_conditions = record.get("conditions")
    if not isinstance(raw_conditions, list):
        return []
    return [
        {
            "field": str(item.get("field") or ""),
            "operator": str(item.get("operator") or "regex"),
            "pattern": str(item.get("pattern") or item.get("value") or ""),
        }
        for item in raw_conditions
        if isinstance(item, dict)
    ]


def serialized_filter_match(record: dict[str, Any]) -> dict[str, Any]:
    return {"conditions": filter_conditions(record)}


def record_matches_use_case(
    record: dict[str, Any],
    *,
    use_case: str,
) -> bool:
    return str(record.get("use_case") or "") == str(use_case or "")


def validate_filter(
    raw: dict[str, Any],
    *,
    artifact: str,
    profile: dict[str, Any],
    source: str,
    default_status: str,
) -> dict[str, Any]:
    review = profile.get("review", {})
    filter_fields = dict(review.get("filter_fields") or {})
    scope_fields = dict(review.get("filter_scope_fields") or {})
    raw_conditions = raw.get("conditions")
    if not isinstance(raw_conditions, list):
        raise RuntimeError("Filter conditions must be a list.")
    conditions = filter_conditions(raw)
    if not conditions or len(conditions) > 8:
        raise RuntimeError("Filters require 1-8 field conditions.")
    normalized_conditions: list[dict[str, str]] = []
    for condition in conditions:
        field = str(condition.get("field") or "").strip()
        operator = str(condition.get("operator") or "regex").strip()
        pattern = str(condition.get("pattern") or "")
        if field not in filter_fields:
            raise RuntimeError(
                f"Filter field {field!r} is not approved for artifact {artifact}."
            )
        if operator not in FILTER_OPERATORS:
            raise RuntimeError(
                "Filter operator must be one of: "
                f"{', '.join(sorted(FILTER_OPERATORS))}."
            )
        if not pattern or len(pattern) > 4096:
            raise RuntimeError(
                "Filter patterns must contain 1-4096 characters."
            )
        normalized_conditions.append(
            {
                "field": field,
                "operator": operator,
                "pattern": pattern,
            }
        )
    reason = str(raw.get("reason") or "").strip()
    status = str(raw.get("status") or default_status).strip()
    if not reason:
        raise RuntimeError("Every filter requires a reason.")
    if status not in FILTER_STATUSES:
        raise RuntimeError(f"Unknown filter status: {status}.")
    scope = raw.get("scope") or {}
    if not isinstance(scope, dict):
        raise RuntimeError("Filter scope must be an object.")
    normalized_scope: dict[str, str] = {}
    for raw_alias, raw_value in scope.items():
        alias = str(raw_alias or "").strip()
        value = str(raw_value or "")
        if alias not in scope_fields:
            raise RuntimeError(
                f"Filter scope field {alias!r} is not approved for artifact {artifact}."
            )
        if not value or len(value) > 4096:
            raise RuntimeError("Filter scope values must contain 1-4096 characters.")
        normalized_scope[alias] = value
    record = {
        "artifact": artifact,
        "use_case": str(raw.get("use_case") or ""),
        "scope": normalized_scope,
        "conditions": normalized_conditions,
        "reason": reason,
        "status": status,
        "source": source,
        "created_at": str(raw.get("created_at") or now_utc()),
        "owner": str(raw.get("owner") or ""),
        "review_after": str(raw.get("review_after") or ""),
    }
    record["id"] = str(raw.get("id") or filter_identity(record))
    return record


def load_reusable_filters(
    paths: Iterable[Path],
    *,
    profiles: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    resolved_paths: list[str] = []
    for path in paths:
        payload = load_json_object(path)
        if payload.get("schema_version") != FILTER_SCHEMA_VERSION:
            raise RuntimeError(
                f"Filter reference {path} schema_version must be {FILTER_SCHEMA_VERSION}."
            )
        raw_filters = payload.get("filters")
        if not isinstance(raw_filters, list):
            raise RuntimeError(f"Filter reference {path} must contain a filters list.")
        for raw in raw_filters:
            if not isinstance(raw, dict):
                raise RuntimeError(f"Filter reference {path} contains a non-object filter.")
            artifact = str(raw.get("artifact") or "").strip()
            profile = artifact_profiles.resolve_profile(artifact, profiles)
            if profile is None:
                raise RuntimeError(
                    f"Filter reference {path} targets unknown artifact {artifact!r}."
                )
            records.append(
                validate_filter(
                    raw,
                    artifact=artifact,
                    profile=profile,
                    source=str(path),
                    default_status="promoted",
                )
            )
        resolved_paths.append(str(path))
    return unique_dicts(records, key="id"), resolved_paths


def profile_projection(
    profile: dict[str, Any] | None,
    *,
    live: bool = True,
) -> list[str]:
    if profile is None:
        return ["*"]
    review = profile.get("review", {})
    if live:
        # A live flow result is not guaranteed to expose the same schema as
        # an exported collection.  Prefer an explicit live projection; when
        # one is absent, preserve the server row shape instead of falling
        # back to sample_fields, which can contain fields unavailable in the
        # selected flow and cause VQL compilation failures.
        projection = list(review.get("live_vql_select") or [])
        if not projection:
            return ["*"]
    else:
        projection = list(review.get("vql_select") or [])
    if projection:
        return projection
    fields = list(profile.get("review", {}).get("sample_fields") or [])
    safe_fields = [
        field
        for field in fields
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", str(field))
    ]
    return safe_fields or ["*"]


def unprofiled_runtime_profile(artifact: str) -> dict[str, Any]:
    """Return a non-promotable runtime shell for an unprofiled artifact."""
    return {
        "review": {
            "vql_select": ["*"],
            "filter_fields": {},
            "filter_scope_fields": {},
            "known_bad": [],
            "stacks": {},
            "default_stack": "",
        },
        "_profile_hash": sha256_value({"artifact": artifact, "fallback": True}),
    }


def source_vql(source: review_source.ReviewSource | None = None) -> str:
    if source is not None and source.source_type == "flow":
        return "FlowReviewRows"
    if source is not None:
        return source.vql
    return "hunt_results(hunt_id=HuntId, artifact=ArtifactName)"


def source_query_preamble(
    source: review_source.ReviewSource | None = None,
) -> str:
    if source is None or source.source_type != "flow":
        return ""
    return (
        "LET FlowReviewRows = SELECT *,\n"
        "       ClientId AS ClientId,\n"
        "       client_info(client_id=ClientId).os_info.fqdn AS Fqdn\n"
        f"FROM {source.vql}\n"
    )


def query_env(
    hunt_id: str,
    artifact: str,
    source: review_source.ReviewSource | None = None,
) -> dict[str, str]:
    if source is not None:
        return source.query_environment()
    return {"HuntId": hunt_id, "ArtifactName": artifact}


def bind_value(env: dict[str, str], prefix: str, value: str) -> str:
    index = 1
    while f"{prefix}{index}" in env:
        index += 1
    key = f"{prefix}{index}"
    env[key] = value
    return key


def match_expression(
    record: dict[str, Any],
    *,
    profile: dict[str, Any],
    env: dict[str, str],
    prefix: str,
) -> str:
    review = profile.get("review", {})
    filter_fields = dict(review.get("filter_fields") or {})
    scope_fields = dict(review.get("filter_scope_fields") or {})
    terms: list[str] = []
    for alias, value in sorted(dict(record.get("scope") or {}).items()):
        variable = bind_value(env, f"{prefix}Scope", str(value))
        terms.append(f"({scope_fields[alias]} = {variable})")
    for condition in filter_conditions(record):
        variable = bind_value(
            env,
            f"{prefix}Value",
            str(condition["pattern"]),
        )
        expression = str(filter_fields[str(condition["field"])])
        if condition["operator"] == "eq":
            terms.append(f"({expression} = {variable})")
        else:
            terms.append(f"({expression} =~ {variable})")
    return "(" + " AND ".join(terms) + ")"


def known_bad_match_expression(
    record: dict[str, Any],
    *,
    profile: dict[str, Any],
    env: dict[str, str],
    prefix: str,
) -> str:
    normalized = {
        **record,
        "conditions": [
            {
                "field": str(record.get("field") or ""),
                "operator": str(record.get("operator") or "regex"),
                "pattern": str(record.get("pattern") or ""),
            }
        ],
    }
    return match_expression(
        normalized,
        profile=profile,
        env=env,
        prefix=prefix,
    )


def scope_expression(
    scope: dict[str, str],
    *,
    profile: dict[str, Any],
    env: dict[str, str],
    prefix: str,
) -> str:
    scope_fields = dict(profile.get("review", {}).get("filter_scope_fields") or {})
    terms: list[str] = []
    for alias, value in sorted(scope.items()):
        if alias not in scope_fields:
            raise RuntimeError(f"Unknown review scope field {alias!r}.")
        variable = bind_value(env, f"{prefix}Scope", str(value))
        terms.append(f"({scope_fields[alias]} = {variable})")
    return "(" + " AND ".join(terms) + ")" if terms else ""


def remaining_where(
    *,
    profile: dict[str, Any],
    filters: list[dict[str, Any]],
    reviewed_scopes: list[dict[str, str]],
    reviewed_matches: list[dict[str, Any]],
    reviewed_signatures: list[dict[str, Any]],
    known_bad: list[dict[str, Any]],
    env: dict[str, str],
) -> str:
    terms: list[str] = []
    active_filters = [
        item for item in filters if item.get("status") in ACTIVE_FILTER_STATUSES
    ]
    if active_filters:
        filter_match = " OR ".join(
            match_expression(item, profile=profile, env=env, prefix="Filter")
            for item in active_filters
        )
        enabled_known_bad = [item for item in known_bad if item.get("enabled", True)]
        if enabled_known_bad:
            bad_match = " OR ".join(
                known_bad_match_expression(
                    item,
                    profile=profile,
                    env=env,
                    prefix="KnownBad",
                )
                for item in enabled_known_bad
            )
            terms.append(f"NOT (({filter_match}) AND NOT ({bad_match}))")
        else:
            terms.append(f"NOT ({filter_match})")
    for scope in reviewed_scopes:
        rendered = scope_expression(
            scope,
            profile=profile,
            env=env,
            prefix="Reviewed",
        )
        if rendered:
            terms.append(f"NOT {rendered}")
    for item in reviewed_matches:
        terms.append(
            "NOT "
            + match_expression(
                item,
                profile=profile,
                env=env,
                prefix="ReviewedMatch",
            )
        )
    for index, item in enumerate(reviewed_signatures, start=1):
        signature_env = env
        signature_scope_values = dict(item.get("scope") or {})
        signature_scope_dimensions = list(
            item.get("scope_server_dimensions") or []
        )
        signature_scope_aliases = list(item.get("scope_aliases") or [])
        if signature_scope_dimensions:
            signature_scope = dimension_match_expression(
                signature_scope_dimensions,
                [
                    str(signature_scope_values.get(alias) or "")
                    for alias in signature_scope_aliases
                ],
                env=signature_env,
                prefix=f"ReviewedSignatureScope{index}",
            )
        else:
            signature_scope = scope_expression(
                signature_scope_values,
                profile=profile,
                env=signature_env,
                prefix=f"ReviewedSignatureScope{index}",
            )
        signature_match = dimension_match_expression(
            list(item.get("server_dimensions") or []),
            [str(value) for value in item.get("values") or []],
            env=signature_env,
            prefix=f"ReviewedSignature{index}",
        )
        rendered = combine_where(signature_scope, signature_match)
        if rendered:
            terms.append(f"NOT ({rendered})")
    return " AND ".join(terms)


def combine_where(*expressions: str) -> str:
    values = [f"({value})" for value in expressions if str(value).strip()]
    return " AND ".join(values)


def autoruns_golden_query_preamble(where: str) -> str:
    statements: list[str] = []
    if "AutorunsGoldenKeys" in where:
        statements.append(
            "LET AutorunsGoldenKeys <= memoize("
            'key="GoldenKey", period=1000000, query={ '
            "SELECT _value AS GoldenKey "
            "FROM foreach(row=parse_json_array("
            "data=gunzip(string=base64decode("
            "string=AutorunsGoldenLookupGzipBase64)))) "
            "})"
        )
    if "AutorunsGoldenRegexOnlyMatch" in where:
        statements.append(autoruns_regex.vql_regex_only_preamble(source=(
            "parse_json_array(data=gunzip(string=base64decode(string=AutorunsGoldenRegexGzipBase64)))")))
    if "AutorunsGoldenRegexMatch" in where:
        statements.append(autoruns_regex.vql_preamble(source=(
            "SELECT * FROM foreach(row=parse_json_array("
            "data=gunzip(string=base64decode(string=AutorunsGoldenRegexGzipBase64))))"
        )))
    if "AutorunsSelectedHashes" in where:
        statements.append(
            "LET AutorunsSelectedHashes <= memoize("
            'key="HashKey", period=1000000, query={ '
            'SELECT hash(accessor="data", hashselect="SHA1", '
            "path=serialize(item=dict("
            "ImagePath=ImagePath, "
            "LaunchString=LaunchString, "
            "Signer=Signer"
            '), format="json")).SHA1 AS HashKey '
            "FROM foreach(row=parse_json_array("
            "data=gunzip(string=base64decode("
            "string=AutorunsSelectedHashesGzipBase64)))) "
            "})"
        )
    return "\n".join(statements) + ("\n" if statements else "")


def autoruns_selected_hash_where(
    records: Iterable[dict[str, Any]],
    *,
    env: dict[str, str],
) -> tuple[
    str,
    dict[tuple[str, str, str], dict[str, Any]],
]:
    selected: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}
    for record in records:
        # Live stack identities are already canonical. Never re-normalize them.
        payload = {key: str(record.get(key) or "")
                   for key in ("ImagePath", "LaunchString", "Signer")}
        identity = (
            payload["ImagePath"],
            payload["LaunchString"],
            payload["Signer"],
        )
        selected[identity] = dict(record)
    payload = json.dumps(
        [
            {
                "ImagePath": identity[0],
                "LaunchString": identity[1],
                "Signer": identity[2],
            }
            for identity in sorted(selected)
        ],
        separators=(",", ":"),
    ).encode("utf-8")
    env["AutorunsSelectedHashesGzipBase64"] = base64.b64encode(
        gzip.compress(payload, mtime=0)
    ).decode("ascii")
    where = (
        "get(item=AutorunsSelectedHashes, "
        f"field={autoruns.trusted_key_vql()})"
    )
    return where, selected


def autoruns_suspicious_request_batches(
    api: Any,
    *,
    projection: list[str],
    suspicious_rows: list[dict[str, Any]],
    env: dict[str, str],
    source: review_source.ReviewSource | None = None,
    identity_batch_size: int | None = None,
    request_max_bytes: int = DEFAULT_AUTORUNS_DRILLDOWN_REQUEST_BYTES,
) -> list[tuple[str, dict[str, str], dict[tuple[str, str, str], dict[str, Any]], int]]:
    """Preflight and partition canonical identities by serialized request size.

    The bound includes protobuf fields, VQL, and every environment value, using
    the larger organization fallback and the transport's effective timeout.
    Splitting sorted candidate ranges in half avoids quadratic recompression.
    All singleton checks and batch planning finish before any query is issued.
    """
    if identity_batch_size is not None and (
        not isinstance(identity_batch_size, int)
        or isinstance(identity_batch_size, bool) or identity_batch_size <= 0
    ):
        raise RuntimeError("Autoruns identity batch size must be positive.")
    if (not isinstance(request_max_bytes, int)
            or isinstance(request_max_bytes, bool) or request_max_bytes <= 0):
        raise RuntimeError("Autoruns request byte limit must be positive.")
    selected = {autoruns_residual_identity(row): row for row in suspicious_rows}
    records = [selected[identity] for identity in sorted(selected)]
    if not records:
        return []
    org_id = getattr(api, "org_id", "root")
    if not isinstance(org_id, str):
        org_id = "root"
    largest_org_id = max(org_id_candidates(org_id), key=lambda value: len(value.encode("utf-8")))
    timeout = getattr(api, "query_timeout_seconds", 0)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        timeout = 0
    # Selected identities change only the environment, so render VQL once.
    where, _ = autoruns_selected_hash_where([], env={})
    query = select_all_vql(projection, where, source=source)

    def candidate(rows: list[dict[str, Any]]) -> tuple[
        str, dict[str, str], dict[tuple[str, str, str], dict[str, Any]], int,
    ]:
        batch_env = dict(env)
        _, identities = autoruns_selected_hash_where(rows, env=batch_env)
        size = build_vql_request(
            query, batch_env, org_id=largest_org_id, timeout=timeout,
            max_wait=30, max_row=DEFAULT_QUERY_BATCH_ROWS,
        ).ByteSize()
        return query, batch_env, identities, size

    for record in records:
        singleton = candidate([record])
        if singleton[3] > request_max_bytes:
            operation_log.emit(
                "autoruns_drilldown_failed", level="error", stage="autoruns_drilldown",
                error_code="autoruns_identity_request_too_large",
                request_bytes=singleton[3], request_max_bytes=request_max_bytes,
            )
            raise RuntimeError(
                "One Autoruns identity exceeds the serialized request byte limit "
                f"({singleton[3]} > {request_max_bytes}); no drill-down queries issued."
            )

    batches = []

    def partition(rows: list[dict[str, Any]]) -> None:
        batch = candidate(rows)
        if batch[3] <= request_max_bytes:
            batches.append(batch)
            return
        midpoint = len(rows) // 2
        partition(rows[:midpoint])
        partition(rows[midpoint:])

    count_cap = identity_batch_size or len(records)
    for offset in range(0, len(records), count_cap):
        partition(records[offset:offset + count_cap])
    return batches


def count_vql(
    where: str,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    clause = f"\nWHERE {where}" if where else ""
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + "SELECT count() AS RowCount\n"
        f"FROM {source_vql(source)}"
        f"{clause}\n"
        "GROUP BY TRUE"
    )


def autoruns_accounting_vql(
    where: str, *, source: review_source.ReviewSource | None = None,
) -> str:
    """Independent accounting baseline for synthetic parity tests/benchmarks."""
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + "LET AutorunsAccountingRows = SELECT *, "
        + f"if(condition={where or 'TRUE'}, then=1, else=0) AS Residual\n"
        + f"FROM {source_vql(source)}\n"
        + "SELECT count() AS SourceRows, sum(item=Residual) AS ResidualRows, "
        + "sum(item=if(condition=Residual AND (`Image Path` OR `Launch String`), "
        + "then=1, else=0)) AS PopulatedRows\n"
        + "FROM AutorunsAccountingRows GROUP BY TRUE"
    )


def exact_count(
    api: Any, vql: str, env: dict[str, str], *, purpose: str = "count-matching-rows",
) -> int:
    with operation_log.query_context(
        purpose=purpose, hunt_id=env.get("HuntId"), artifact=env.get("ArtifactName"),
    ):
        rows = api.query(vql, env, max_wait=30, max_row=5)
        count = int((rows[0] if rows else {}).get("RowCount") or 0)
        operation_log.emit("analysis_count_completed", matched_rows=count)
        return count


def select_vql(
    projection: list[str],
    where: str,
    limit: int,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    select = "SELECT " + ",\n       ".join(projection)
    if not where:
        return (
            source_query_preamble(source)
            + select
            + f"\nFROM {source_vql(source)}\nLIMIT {limit}"
        )
    # Evaluate predicates before applying configured aliases. VQL SELECT aliases
    # are visible to WHERE, so a projection such as
    # ``Detection.Name AS Detection`` otherwise shadows the source Detection
    # object and makes ``WHERE Detection.Name = ...`` silently return no rows.
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + f"LET ReviewRows = SELECT * FROM {source_vql(source)}\n"
        f"WHERE {where}\n"
        f"{select}\n"
        "FROM ReviewRows\n"
        f"LIMIT {limit}"
    )


def select_all_vql(
    projection: list[str],
    where: str,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    select = "SELECT " + ",\n       ".join(projection)
    if not where:
        return source_query_preamble(source) + select + f"\nFROM {source_vql(source)}"
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + f"LET ReviewRows = SELECT * FROM {source_vql(source)}\n"
        f"WHERE {where}\n"
        f"{select}\n"
        "FROM ReviewRows"
    )


def stack_vql(
    dimensions: list[str],
    where: str,
    limit: int,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    select_parts = [
        f"{expression} AS Pivot{index}"
        for index, expression in enumerate(dimensions, start=1)
    ]
    aliases = [f"Pivot{index}" for index in range(1, len(dimensions) + 1)]
    clause = f"\nWHERE {where}" if where else ""
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + f"SELECT {', '.join(select_parts)}, count() AS Count\n"
        f"FROM {source_vql(source)}"
        f"{clause}\n"
        f"GROUP BY {', '.join(aliases)}\n"
        "ORDER BY Count DESC\n"
        f"LIMIT {limit}"
    )


def streaming_stack_vql(
    dimensions: list[str],
    where: str,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    """Build an aggregate with occurrence and distinct-host prevalence."""
    if not dimensions:
        raise RuntimeError("Streaming stack dimensions cannot be empty.")
    select_parts = [
        f"{expression} AS Pivot{index}"
        for index, expression in enumerate(dimensions, start=1)
    ]
    aliases = [f"Pivot{index}" for index in range(1, len(dimensions) + 1)]
    clause = f"\nWHERE {where}" if where else ""
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + "LET StackHostGroups = SELECT "
        + f"{', '.join(select_parts)}, ClientId, count() AS HostRows\n"
        f"FROM {source_vql(source)}"
        f"{clause}\n"
        f"GROUP BY {', '.join([*aliases, 'ClientId'])}\n"
        f"SELECT {', '.join(aliases)}, count() AS HostCount, "
        "sum(item=HostRows) AS Count\n"
        "FROM StackHostGroups\n"
        f"GROUP BY {', '.join(aliases)}\n"
        "ORDER BY Count"
    )


def impacted_hosts_vql(
    where: str,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    """Return exact endpoint identities and row counts for one stack group."""
    clause = f"\nWHERE {where}" if where else ""
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + "LET ImpactRows = SELECT *\n"
        f"FROM {source_vql(source)}"
        f"{clause}\n"
        "SELECT ClientId, Fqdn, count() AS RowCount\n"
        "FROM ImpactRows\n"
        "GROUP BY ClientId, Fqdn\n"
        "ORDER BY RowCount DESC"
    )


def quote_vql_field_identifier(field: str) -> str:
    """Quote one validated top-level field name; never accept VQL fragments."""
    if not generic_stack_review.safe_field_name(field) or "`" in field:
        raise RuntimeError(f"Unsafe dynamic stack field identifier {field!r}.")
    return f"`{field}`"


def discovery_sample_vql(
    where: str,
    row_count: int,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    """Build a deterministic bounded schema-discovery query."""
    if not MIN_STACK_DISCOVERY_ROWS <= row_count <= MAX_STACK_DISCOVERY_ROWS:
        raise RuntimeError(
            "Dynamic stack discovery rows must be between "
            f"{MIN_STACK_DISCOVERY_ROWS} and {MAX_STACK_DISCOVERY_ROWS}."
        )
    if not where:
        return (
            source_query_preamble(source)
            + "SELECT *\n"
            f"FROM {source_vql(source)}\n"
            "ORDER BY ClientId\n"
            f"LIMIT {row_count}"
        )
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + f"LET DiscoveryRows = SELECT * FROM {source_vql(source)}\n"
        f"WHERE {where}\n"
        "SELECT *\n"
        "FROM DiscoveryRows\n"
        "ORDER BY ClientId\n"
        f"LIMIT {row_count}"
    )


def iter_query_rows(
    api: Any,
    *,
    vql: str,
    env: dict[str, str],
    purpose: str = "stream-review-rows",
    strict_rows: bool = False,
) -> Iterator[dict[str, Any]]:
    """Yield live VQL rows without materializing the complete response."""
    if not hasattr(api, "query_batches"):
        raise RuntimeError(
            "Generic streaming stacks require a batch-streaming API client."
        )
    batches = api.query_batches(
        vql,
        env,
        max_wait=30,
        max_row=DEFAULT_QUERY_BATCH_ROWS,
    )
    iterator = iter(batches)
    while True:
        with operation_log.query_context(
            purpose=purpose, hunt_id=env.get("HuntId"), artifact=env.get("ArtifactName"),
        ):
            try:
                batch = next(iterator)
            except StopIteration:
                return
        if strict_rows and not isinstance(batch, list):
            raise RuntimeError("Streaming query returned a malformed row batch.")
        for row in batch:
            if isinstance(row, dict):
                yield dict(row)
            elif strict_rows:
                raise RuntimeError("Streaming query returned a malformed row.")


def autoruns_residual_stack_vql(
    where: str,
    *,
    source: review_source.ReviewSource | None = None,
) -> str:
    image_path = autoruns.user_path_vql("`Image Path`")
    launch_string = autoruns.user_path_vql("`Launch String`")
    sort_identity = (
        "serialize(item=dict("
        "ImagePath=ImagePath, "
        "LaunchString=LaunchString, "
        "Signer=Signer"
        "), format=\"json\")"
    )
    sort_key = (
        "format(format='%020d|%v', "
        f"args=[Total, {sort_identity}])"
    )
    populated = "(`Image Path` OR `Launch String`)"
    source_where = combine_where(where, populated)
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(source_where)
        + "LET AutorunsResidualRows = SELECT\n"
        f"    {image_path} AS ImagePath,\n"
        f"    {launch_string} AS LaunchString,\n"
        f"    {autoruns.ascii_lower_vql('Signer')} AS Signer,\n"
        "    Category\n"
        f"FROM {source_vql(source)}\n"
        f"WHERE {source_where}\n"
        "LET AutorunsResidualStack = SELECT\n"
        "       ImagePath, LaunchString, Signer,\n"
        "       min(item=Category) AS ExampleCategory,\n"
        "       count() AS Total\n"
        "FROM AutorunsResidualRows\n"
        "GROUP BY ImagePath, LaunchString, Signer\n"
        "SELECT ImagePath, LaunchString, Signer,\n"
        "       ExampleCategory, Total,\n"
        f"       {sort_key} AS SortKey\n"
        "FROM AutorunsResidualStack\n"
        "ORDER BY SortKey DESC"
    )


def autoruns_accounted_stack_vql(
    where: str, *, source: review_source.ReviewSource | None = None,
) -> str:
    """One source pass; retain residual groups and two accounting buckets only.

    Matching stays before grouping: trusted identities never create individual
    bins. The materialized *aggregates* allow the summary to precede the stream
    without retaining source rows or evaluating GoldenDB a second time.
    """
    identity = 'serialize(item=dict(ImagePath=ImagePath, LaunchString=LaunchString, Signer=Signer), format="json")'
    return (
        source_query_preamble(source)
        + autoruns_golden_query_preamble(where)
        + "LET AutorunsScopedRows = SELECT *, "
        + f"if(condition={where or 'TRUE'}, then=TRUE, else=FALSE) AS Residual\n"
        + f"FROM {source_vql(source)}\n"
        + "LET AutorunsBucketRows = SELECT *, if(condition=Residual, "
        + 'then=if(condition=`Image Path` OR `Launch String`, then="group", else="blank"), '
        + 'else="matched") AS Kind FROM AutorunsScopedRows\n'
        + "LET AutorunsReducedRows = SELECT Kind, Category, "
        + f'if(condition=Kind = "group", then={autoruns.user_path_vql("`Image Path`")}, else="") AS ImagePath, '
        + f'if(condition=Kind = "group", then={autoruns.user_path_vql("`Launch String`")}, else="") AS LaunchString, '
        + f'if(condition=Kind = "group", then={autoruns.ascii_lower_vql("Signer")}, else="") AS Signer '
        + "FROM AutorunsBucketRows\n"
        + "LET AutorunsCountedGroups <= SELECT Kind, ImagePath, LaunchString, Signer, "
        + "min(item=Category) AS ExampleCategory, count() AS Total "
        + "FROM AutorunsReducedRows GROUP BY Kind, ImagePath, LaunchString, Signer\n"
        + "LET AutorunsSummary <= SELECT sum(item=Total) AS SourceRows, "
        + 'sum(item=if(condition=Kind = "matched", then=Total, else=0)) AS MatchedRows, '
        + 'sum(item=if(condition=Kind != "matched", then=Total, else=0)) AS ResidualRows, '
        + 'sum(item=if(condition=Kind = "group", then=Total, else=0)) AS PopulatedRows, '
        + 'sum(item=if(condition=Kind = "group", then=1, else=0)) AS GroupCount '
        + "FROM AutorunsCountedGroups GROUP BY TRUE\n"
        + "SELECT * FROM chain(\n"
        + 'a={ SELECT "summary" AS _AutorunsStream, '
        + ", ".join(
            f"if(condition=AutorunsSummary, then=AutorunsSummary[0].{key}, else=0) AS {key}"
            for key in ("SourceRows", "MatchedRows", "ResidualRows", "PopulatedRows", "GroupCount")
        )
        + " FROM scope() },\n"
        + 'b={ SELECT "group" AS _AutorunsStream, ImagePath, LaunchString, Signer, ExampleCategory, Total, '
        + f"format(format='%020d|%v', args=[Total, {identity}]) AS SortKey "
        + 'FROM AutorunsCountedGroups WHERE Kind = "group" ORDER BY SortKey DESC },\n'
        + 'c={ SELECT "complete" AS _AutorunsStream FROM scope() })'
    )


class AutorunsAccountedStack:
    """Consume a summary, then validate every streamed group and terminal marker."""

    def __init__(self, rows: Iterable[dict[str, Any]]):
        self._rows = iter(rows)
        self.complete = False
        summary = next(self._rows, None)
        if not isinstance(summary, dict) or summary.get("_AutorunsStream") != "summary":
            raise RuntimeError("Autoruns accounted stack omitted its summary.")
        self.counts: dict[str, int] = {}
        for key in ("SourceRows", "MatchedRows", "ResidualRows", "PopulatedRows", "GroupCount"):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise RuntimeError(f"Autoruns accounted stack returned invalid {key}.")
            self.counts[key] = value
        c = self.counts
        if (c["MatchedRows"] + c["ResidualRows"] != c["SourceRows"]
                or not c["GroupCount"] <= c["PopulatedRows"] <= c["ResidualRows"]
                or bool(c["GroupCount"]) != bool(c["PopulatedRows"])):
            raise RuntimeError("Autoruns accounted stack returned inconsistent scope counts.")

    def __iter__(self) -> Iterator[dict[str, Any]]:
        represented = groups = 0
        previous_sort = None
        seen: set[tuple[str, str, str]] = set()
        for row in self._rows:
            if not isinstance(row, dict):
                raise RuntimeError("Autoruns accounted stack returned a malformed row.")
            kind = row.get("_AutorunsStream")
            if kind == "complete":
                sentinel = object()
                if next(self._rows, sentinel) is not sentinel:
                    raise RuntimeError("Autoruns accounted stack returned rows after completion.")
                if (represented != self.counts["PopulatedRows"]
                        or groups != self.counts["GroupCount"]):
                    raise RuntimeError("Autoruns accounted stack accounting mismatch.")
                self.complete = True
                return
            if kind != "group":
                raise RuntimeError("Autoruns accounted stack returned an unexpected record.")
            total = row.get("Total")
            if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
                raise RuntimeError("Autoruns accounted stack returned an invalid group total.")
            if any(not isinstance(row.get(key), str)
                   for key in ("ImagePath", "LaunchString", "Signer", "SortKey")):
                raise RuntimeError("Autoruns accounted stack returned an invalid identity or sort key.")
            identity = autoruns_residual_identity(row)
            if identity in seen:
                raise RuntimeError("Autoruns accounted stack returned a duplicate identity.")
            seen.add(identity)
            sort_key = row["SortKey"]
            if previous_sort is not None and sort_key > previous_sort:
                raise RuntimeError("Autoruns accounted stack returned groups out of order.")
            previous_sort = sort_key
            represented += total
            groups += 1
            if represented > self.counts["PopulatedRows"] or groups > self.counts["GroupCount"]:
                raise RuntimeError("Autoruns accounted stack accounting mismatch.")
            yield {key: str(row.get(key) or "") for key in
                   ("ImagePath", "LaunchString", "Signer", "ExampleCategory")} | {"Total": total}
        raise RuntimeError("Autoruns accounted stack omitted its completion marker.")


def autoruns_residual_identity(
    record: dict[str, Any],
) -> tuple[str, str, str]:
    return (
        str(record.get("ImagePath") or ""),
        str(record.get("LaunchString") or ""),
        str(record.get("Signer") or ""),
    )


def render_csv_with_metadata(
    *,
    metadata: dict[str, Any],
    fieldnames: Iterable[str],
    rows: Iterable[dict[str, Any]],
) -> str:
    buffer = io.StringIO()
    for key, value in metadata.items():
        buffer.write(f"# {key}: {value}\n")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(fieldnames),
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def parse_csv_with_metadata(
    path: Path,
) -> tuple[dict[str, str], list[dict[str, str]], list[str]]:
    metadata: dict[str, str] = {}
    body_lines: list[str] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("#"):
            key, separator, value = line[1:].partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
            continue
        if line.strip():
            body_lines.append(line)
    if not body_lines:
        raise RuntimeError(f"CSV file {path} has no header.")
    reader = csv.DictReader(io.StringIO("\n".join(body_lines) + "\n"))
    fieldnames = list(reader.fieldnames or [])
    if not fieldnames:
        raise RuntimeError(f"CSV file {path} has no fields.")
    return metadata, [dict(row) for row in reader], fieldnames


def parse_csv_bool(value: Any, *, field: str) -> bool:
    normalized = str(value or "").strip().casefold()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"", "0", "false", "no", "n"}:
        return False
    raise RuntimeError(
        f"CSV field {field} must be true or false, not {value!r}."
    )


def parse_csv_json_list(value: Any, *, field: str) -> list[Any]:
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"CSV field {field} is not valid JSON: {error}."
        ) from error
    if not isinstance(parsed, list):
        raise RuntimeError(f"CSV field {field} must contain a JSON list.")
    return parsed


def focused_autoruns_pending_review(
    pending: dict[str, Any],
) -> bool:
    return (
        str(pending.get("artifact") or "") in AUTORUNS_ARTIFACTS
        and str(pending.get("kind") or "") == "normalized_stack"
        and str(pending.get("use_case") or "") in AUTORUNS_USE_CASES
    )


def review_queue_set_id(
    pending_reviews: Iterable[dict[str, Any]],
) -> str:
    ordered = sorted(
        (
            dict(item)
            for item in pending_reviews
        ),
        key=lambda item: str(item.get("review_id") or ""),
    )
    return sha256_value(ordered)


def review_queue_dimensions(
    pending: dict[str, Any],
) -> dict[str, str]:
    review_match = dict(pending.get("review_match") or {})
    dimensions = list(review_match.get("logical_dimensions") or [])
    values = list(review_match.get("values") or [])
    return {
        str(dimension): str(value)
        for dimension, value in zip(dimensions, values, strict=False)
    }


def parse_autoruns_review_queue(
    path: Path,
    *,
    expected_hunt_id: str = "",
    expected_artifact: str = "",
    expected_use_case: str = "",
    expected_review_set_id: str = "",
    expected_count: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, str]]:
    metadata, rows, fieldnames = parse_csv_with_metadata(path)
    schema_version = int(metadata.get("SchemaVersion") or 0)
    if schema_version not in {
        1,
        AUTORUNS_REVIEW_QUEUE_SCHEMA_VERSION,
    }:
        raise RuntimeError(
            f"Unsupported Autoruns review CSV schema in {path}."
        )
    required_fields = set(AUTORUNS_REVIEW_QUEUE_FIELDS)
    if schema_version == 1:
        required_fields.difference_update(AUTORUNS_REVIEW_QUEUE_AI_FIELDS)
    missing_fields = sorted(required_fields.difference(fieldnames))
    if missing_fields:
        raise RuntimeError(
            f"Autoruns review CSV {path} is missing fields: "
            + ", ".join(missing_fields)
        )
    for row in rows:
        for field in AUTORUNS_REVIEW_QUEUE_AI_FIELDS:
            row.setdefault(field, "")
    checks = {
        "HuntId": expected_hunt_id,
        "Artifact": expected_artifact,
        "UseCase": expected_use_case,
        "ReviewSetId": expected_review_set_id,
    }
    for key, expected in checks.items():
        if expected and metadata.get(key) != expected:
            raise RuntimeError(
                f"Autoruns review CSV {path} has stale or mismatched {key}."
            )
    pending_reviews: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        review_id = str(row.get("ReviewId") or "").strip()
        raw_pending = str(row.get("PendingReviewJson") or "").strip()
        if not review_id or review_id in seen_ids:
            raise RuntimeError(
                f"Autoruns review CSV {path} row {row_number} has a missing "
                "or duplicate ReviewId."
            )
        seen_ids.add(review_id)
        try:
            pending = json.loads(raw_pending)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Autoruns review CSV {path} row {row_number} has invalid "
                f"PendingReviewJson: {error}."
            ) from error
        if not isinstance(pending, dict):
            raise RuntimeError(
                f"Autoruns review CSV {path} row {row_number} "
                "PendingReviewJson must be an object."
            )
        immutable_checks = {
            "review_id": review_id,
            "artifact": str(row.get("Artifact") or ""),
            "kind": str(row.get("Kind") or ""),
            "use_case": str(row.get("UseCase") or ""),
            "evidence_hash": str(row.get("EvidenceHash") or ""),
        }
        for key, expected in immutable_checks.items():
            if str(pending.get(key) or "") != expected:
                raise RuntimeError(
                    f"Autoruns review CSV {path} row {row_number} modified "
                    f"immutable field {key}."
                )
        if not focused_autoruns_pending_review(pending):
            raise RuntimeError(
                f"Autoruns review CSV {path} row {row_number} is not a "
                "focused Autoruns normalized-stack review."
            )
        dimensions = review_queue_dimensions(pending)
        scope = dict(pending.get("scope") or {})
        display_checks = {
            "Category": str(
                scope.get("Category")
                or dimensions.get("Category")
                or ""
            ),
            "EntryLocation": dimensions.get("EntryLocation", ""),
            "Entry": dimensions.get("Entry", ""),
            "ImagePath": dimensions.get("ImagePath", ""),
            "LaunchString": dimensions.get("LaunchString", ""),
            "Signer": dimensions.get("Signer", ""),
            "ScopeRowCount": str(
                int(pending.get("scope_row_count") or 0)
            ),
            "ExactVariantCountLowerBound": str(
                int(
                    pending.get("exact_variant_count_lower_bound")
                    or 0
                )
            ),
            "ClosureEligible": str(
                bool(pending.get("closure_eligible"))
            ).lower(),
            "PriorityReviewReasons": ";".join(
                str(value)
                for value in pending.get("priority_review_reasons") or []
            ),
        }
        for field, expected in display_checks.items():
            if str(row.get(field) or "") != expected:
                raise RuntimeError(
                    f"Autoruns review CSV {path} row {row_number} modified "
                    f"immutable field {field}."
                )
        pending_reviews.append(pending)
    calculated_set_id = review_queue_set_id(pending_reviews)
    if metadata.get("ReviewSetId") != calculated_set_id:
        raise RuntimeError(
            f"Autoruns review CSV {path} immutable review set has changed."
        )
    declared_count = int(metadata.get("ReviewCount") or -1)
    if declared_count != len(pending_reviews):
        raise RuntimeError(
            f"Autoruns review CSV {path} ReviewCount does not match its rows."
        )
    if expected_count is not None and len(pending_reviews) != expected_count:
        raise RuntimeError(
            f"Autoruns review CSV {path} no longer contains the expected "
            f"{expected_count} review item(s)."
        )
    return pending_reviews, rows, metadata


def decisions_from_autoruns_review_queue(path: Path) -> list[dict[str, Any]]:
    _, rows, _ = parse_autoruns_review_queue(path)
    decisions: list[dict[str, Any]] = []
    for row in rows:
        complete = parse_csv_bool(
            row.get("Complete"),
            field="Complete",
        )
        drilldown_reason = str(row.get("DrilldownReason") or "").strip()
        if not complete and not drilldown_reason:
            continue
        decision = {
            "review_id": str(row.get("ReviewId") or ""),
            "complete": complete,
            "disposition": str(
                row.get("Disposition") or "expected"
            ).strip(),
            "reason": str(row.get("Reason") or "").strip(),
            "hijack_risk_reviewed": parse_csv_bool(
                row.get("HijackRiskReviewed"),
                field="HijackRiskReviewed",
            ),
            "variant_risk_reviewed": parse_csv_bool(
                row.get("VariantRiskReviewed"),
                field="VariantRiskReviewed",
            ),
            "lolbin_behavior_reviewed": parse_csv_bool(
                row.get("LolbinBehaviorReviewed"),
                field="LolbinBehaviorReviewed",
            ),
            "unverified_signer_reviewed": parse_csv_bool(
                row.get("UnverifiedSignerReviewed"),
                field="UnverifiedSignerReviewed",
            ),
            "promote_to_golden": parse_csv_bool(
                row.get("PromoteToGolden"),
                field="PromoteToGolden",
            ),
            "findings": parse_csv_json_list(
                row.get("FindingsJson"),
                field="FindingsJson",
            ),
            "filters": parse_csv_json_list(
                row.get("FiltersJson"),
                field="FiltersJson",
            ),
            "normalization_candidates": parse_csv_json_list(
                row.get("NormalizationCandidatesJson"),
                field="NormalizationCandidatesJson",
            ),
        }
        if drilldown_reason:
            decision["drilldown"] = {"reason": drilldown_reason}
        decisions.append(decision)
    return decisions


def autoruns_context_items_for_state(
    state: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    details: dict[str, list[dict[str, Any]]] = {}
    for artifact, artifact_state in sorted(
        state.get("artifacts", {}).items()
    ):
        workflows: list[dict[str, Any]] = []
        residual = artifact_state.get("autoruns_residual_workflow")
        if isinstance(residual, dict):
            workflows.append(residual)
        focused = artifact_state.get("autoruns_focused_workflows")
        if isinstance(focused, dict):
            workflows.extend(
                item
                for item in focused.values()
                if isinstance(item, dict)
            )
        artifact_details: list[dict[str, Any]] = []
        for workflow in workflows:
            context = workflow.get("suspicious_context")
            if not isinstance(context, dict):
                continue
            artifact_details.extend(
                dict(item)
                for item in context.get("items") or []
                if isinstance(item, dict)
            )
        if artifact_details:
            details[str(artifact)] = artifact_details
    return details


def autoruns_context_exclusion_reason(row: dict[str, Any]) -> str:
    entry_location = (
        str(row.get("EntryLocation") or "")
        .strip()
        .replace("/", "\\")
        .rstrip("\\")
        .casefold()
    )
    entry = str(row.get("Entry") or "").strip().casefold()
    category = str(row.get("Category") or "").strip().casefold()
    image_path = autoruns.normalize_user_path(
        row.get("ImagePath")
    )
    launch_string = autoruns.normalize_user_path(
        row.get("LaunchString")
    )
    signer = str(row.get("Signer") or "").strip().casefold()
    if (
        entry_location
        == (
            r"hklm\system\currentcontrolset\control"
            r"\safeboot\alternateshell"
        )
        and entry == "cmd.exe"
        and category == "logon"
        and image_path == r"c:\windows\system32\cmd.exe"
        and launch_string == "cmd.exe"
        and signer == "(verified) microsoft windows"
    ):
        return "windows-default-safeboot-alternate-shell"
    return ""


def stack_for_role(
    profile: dict[str, Any],
    role: str,
) -> tuple[str, dict[str, Any]] | None:
    for stack_id, stack in artifact_profiles.ordered_stack_views(
        profile,
        require_server=True,
    ):
        configured_role = str(stack.get("analysis_role") or "")
        if configured_role == role:
            return stack_id, stack
        if configured_role:
            continue
        has_scope = bool(stack.get("server_scope_aliases"))
        if role == "scope" and has_scope:
            return stack_id, stack
        if role == "signature" and not has_scope and len(
            stack.get("server_dimensions") or []
        ) == 1:
            return stack_id, stack
    return None


def dimension_match_expression(
    dimensions: list[str],
    values: list[str],
    *,
    env: dict[str, str],
    prefix: str,
) -> str:
    if not dimensions or len(dimensions) != len(values):
        raise RuntimeError("Stack dimensions and values must be non-empty and aligned.")
    terms: list[str] = []
    for index, (expression, value) in enumerate(
        zip(dimensions, values, strict=True),
        start=1,
    ):
        if value == "":
            # Aggregate response values are normalized with ``value or ""``.
            # Apply the same falsey semantics during exact-row follow-up so
            # NULL or missing nested dimensions remain reproducible.
            terms.append(f"(NOT ({expression}))")
            continue
        variable = bind_value(env, f"{prefix}{index}Value", value)
        terms.append(f"({expression} = {variable})")
    return "(" + " AND ".join(terms) + ")"


def reviewed_signature_records_for_scope(
    reviewed_signatures: list[dict[str, Any]],
    *,
    scope: dict[str, str],
    stack_id: str | None = None,
) -> list[dict[str, Any]]:
    scope_key = stable_json(scope)
    return [
        item
        for item in reviewed_signatures
        if stable_json(dict(item.get("scope") or {})) == scope_key
        and (
            stack_id is None
            or str(item.get("stack_id") or "") == stack_id
        )
    ]


def accounted_signature_rows(
    reviewed_signatures: list[dict[str, Any]],
    *,
    excluded_scopes: list[dict[str, str]] | None = None,
) -> int:
    excluded = {
        stable_json(scope)
        for scope in (excluded_scopes or [])
    }
    return sum(
        max(0, int(item.get("row_count") or 0))
        for item in reviewed_signatures
        if stable_json(dict(item.get("scope") or {})) not in excluded
    )


def unreviewed_family_groups(
    groups: list[dict[str, Any]],
    *,
    artifact: str,
    scope: dict[str, str],
    stack_id: str,
    dimension_count: int,
    reviewed_signatures: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    accounted_ids = {
        str(item.get("id") or "")
        for item in reviewed_signature_records_for_scope(
            reviewed_signatures,
            scope=scope,
            stack_id=stack_id,
        )
    }
    return [
        group
        for group in groups
        if accounting_id_for(
            artifact=artifact,
            scope=scope,
            stack_id=stack_id,
            values=[
                str(group.get(f"Pivot{index}") or "")
                for index in range(1, dimension_count + 1)
            ],
        )
        not in accounted_ids
    ]


def signature_reduction(
    groups: list[dict[str, Any]],
    *,
    scope_count: int,
    dimension_count: int = 1,
    allow_empty_dimensions: bool = False,
) -> dict[str, Any]:
    normalized = [
        {
            "signature": sha256_value(
                [
                    str(group.get(f"Pivot{index}") or "")
                    for index in range(1, dimension_count + 1)
                ]
            ),
            "values": [
                str(group.get(f"Pivot{index}") or "")
                for index in range(1, dimension_count + 1)
            ],
            "count": int(group.get("Count") or 0),
        }
        for group in groups
        if (
            True
            if allow_empty_dimensions
            else all(
                str(group.get(f"Pivot{index}") or "")
                for index in range(1, dimension_count + 1)
            )
        )
        and int(group.get("Count") or 0) > 0
    ]
    leading_probe = normalized[:DOMINANT_SIGNATURE_LIMIT]
    probe_rows = sum(item["count"] for item in leading_probe)
    probe_coverage = 0.0 if scope_count <= 0 else probe_rows / scope_count
    if probe_coverage >= REPETITIVE_COVERAGE:
        classification = "repetitive"
        rows_per_pattern = REPETITIVE_PATTERN_ROWS
        leading: list[dict[str, Any]] = []
        leading_rows = 0
        for item in leading_probe:
            leading.append(item)
            leading_rows += item["count"]
            if leading_rows / scope_count >= REPETITIVE_COVERAGE:
                break
    elif probe_coverage >= MIXED_COVERAGE:
        classification = "mixed"
        rows_per_pattern = MIXED_PATTERN_ROWS
        leading = leading_probe
        leading_rows = probe_rows
    else:
        classification = "unique"
        rows_per_pattern = 0
        leading = leading_probe
        leading_rows = probe_rows
    coverage = 0.0 if scope_count <= 0 else leading_rows / scope_count
    return {
        "classification": classification,
        "scope_row_count": scope_count,
        "signature_groups_returned": len(normalized),
        "leading_signature_count": len(leading),
        "leading_rows": leading_rows,
        "leading_coverage_percent": round(coverage * 100, 2),
        "tail_rows": max(0, scope_count - leading_rows),
        "rows_per_pattern": rows_per_pattern,
        "leading_signatures": leading,
    }


def query_rows_bounded(
    api: Any,
    *,
    vql: str,
    env: dict[str, str],
    row_limit: int,
    token_limit: int,
    token_encoding: str,
    max_item_tokens: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    estimated_tokens = 0
    truncated = False
    outcome = QUERY_OUTCOME_COMPLETE
    first_row_tokens = 0
    effective_max_item_tokens = int(max_item_tokens or token_limit)
    if hasattr(api, "query_batches"):
        batches = api.query_batches(
            vql,
            env,
            max_wait=30,
            max_row=max(1, min(DEFAULT_QUERY_BATCH_ROWS, row_limit)),
        )
    else:
        batches = [
            api.query(
                vql,
                env,
                max_wait=30,
                max_row=max(1, min(DEFAULT_QUERY_BATCH_ROWS, row_limit)),
            )
        ]
    for batch in batches:
        for row in batch:
            row_tokens = token_budget.estimate_tokens(
                stable_json(row),
                token_encoding,
            )
            if not rows:
                first_row_tokens = row_tokens
            if row_tokens > effective_max_item_tokens:
                outcome = QUERY_OUTCOME_FIRST_ROW_OVERSIZED
                truncated = True
                break
            if estimated_tokens + row_tokens > token_limit:
                outcome = (
                    QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED
                    if not rows
                    else QUERY_OUTCOME_TOKEN_LIMIT
                )
                truncated = True
                break
            if len(rows) >= row_limit:
                outcome = QUERY_OUTCOME_ROW_LIMIT
                truncated = True
                break
            rows.append(dict(row))
            estimated_tokens += row_tokens
        if truncated:
            break
    if not truncated and len(rows) >= row_limit:
        outcome = QUERY_OUTCOME_ROW_LIMIT
    return rows, {
        "row_count": len(rows),
        "estimated_tokens": estimated_tokens,
        "truncated": truncated,
        "outcome": outcome,
        "oversized_row": outcome == QUERY_OUTCOME_FIRST_ROW_OVERSIZED,
        "shared_budget_exhausted": (
            outcome == QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED
        ),
        "first_row_tokens": first_row_tokens,
        "token_limit": token_limit,
        "max_item_tokens": effective_max_item_tokens,
        "token_encoding": token_encoding,
    }


def query_rows_exhaustive_transient(
    api: Any,
    *,
    vql: str,
    env: dict[str, str],
    expected_count: int,
    maximum_rows: int,
    token_encoding: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read an exact bounded live scope for immediate in-memory chunking."""
    if expected_count < 0:
        raise RuntimeError("Expected transient review row count cannot be negative.")
    if expected_count > maximum_rows:
        raise RuntimeError(
            f"Transient exhaustive review requires {expected_count} rows, exceeding "
            f"maximum_rows={maximum_rows}. Configure stacking, narrower filters, "
            "or a larger explicit transient-review ceiling."
        )
    rows: list[dict[str, Any]] = []
    estimated_tokens = 0
    first_row_tokens = 0
    if hasattr(api, "query_batches"):
        batches = api.query_batches(
            vql,
            env,
            max_wait=30,
            max_row=max(
                1,
                min(DEFAULT_QUERY_BATCH_ROWS, max(1, expected_count)),
            ),
        )
    else:
        batches = [
            api.query(
                vql,
                env,
                max_wait=30,
                max_row=max(1, expected_count),
            )
        ]
    for batch in batches:
        for row in batch:
            if len(rows) >= maximum_rows:
                raise RuntimeError(
                    "Transient exhaustive review exceeded its configured row ceiling."
                )
            materialized = dict(row)
            row_tokens = token_budget.estimate_tokens(
                stable_json(materialized),
                token_encoding,
            )
            if not rows:
                first_row_tokens = row_tokens
            rows.append(materialized)
            estimated_tokens += row_tokens
    if len(rows) != expected_count:
        raise RuntimeError(
            "Transient exhaustive review row-count mismatch: "
            f"expected {expected_count}, received {len(rows)}."
        )
    return rows, {
        "row_count": len(rows),
        "estimated_tokens": estimated_tokens,
        "truncated": False,
        "outcome": QUERY_OUTCOME_COMPLETE,
        "oversized_row": False,
        "shared_budget_exhausted": False,
        "first_row_tokens": first_row_tokens,
        "token_limit": 0,
        "max_item_tokens": 0,
        "token_encoding": token_encoding,
        "transient_exhaustive": True,
    }


def empty_query_meta(token_encoding: str) -> dict[str, Any]:
    return {
        "row_count": 0,
        "estimated_tokens": 0,
        "truncated": False,
        "outcome": QUERY_OUTCOME_COMPLETE,
        "oversized_row": False,
        "shared_budget_exhausted": False,
        "first_row_tokens": 0,
        "token_limit": 0,
        "max_item_tokens": 0,
        "token_encoding": token_encoding,
    }


def bound_materialized_rows(
    rows: list[dict[str, Any]],
    *,
    row_limit: int,
    token_limit: int,
    token_encoding: str,
    max_item_tokens: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    bounded: list[dict[str, Any]] = []
    estimated_tokens = 0
    first_row_tokens = 0
    outcome = QUERY_OUTCOME_COMPLETE
    truncated = False
    for row in rows:
        row_tokens = token_budget.estimate_tokens(
            stable_json(row),
            token_encoding,
        )
        if not bounded:
            first_row_tokens = row_tokens
        if row_tokens > max_item_tokens:
            outcome = QUERY_OUTCOME_FIRST_ROW_OVERSIZED
            truncated = True
            break
        if estimated_tokens + row_tokens > token_limit:
            outcome = (
                QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED
                if not bounded
                else QUERY_OUTCOME_TOKEN_LIMIT
            )
            truncated = True
            break
        if len(bounded) >= row_limit:
            outcome = QUERY_OUTCOME_ROW_LIMIT
            truncated = True
            break
        bounded.append(dict(row))
        estimated_tokens += row_tokens
    if not truncated and len(rows) >= row_limit:
        outcome = QUERY_OUTCOME_ROW_LIMIT
    return bounded, {
        "row_count": len(bounded),
        "estimated_tokens": estimated_tokens,
        "truncated": truncated,
        "outcome": outcome,
        "oversized_row": outcome == QUERY_OUTCOME_FIRST_ROW_OVERSIZED,
        "shared_budget_exhausted": (
            outcome == QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED
        ),
        "first_row_tokens": first_row_tokens,
        "token_limit": token_limit,
        "max_item_tokens": max_item_tokens,
        "token_encoding": token_encoding,
    }


def query_stops_pass(query_meta: dict[str, Any]) -> bool:
    return str(query_meta.get("outcome") or "") in {
        QUERY_OUTCOME_TOKEN_LIMIT,
        QUERY_OUTCOME_FIRST_ROW_OVERSIZED,
        QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED,
    }


def query_emits_review(query_meta: dict[str, Any]) -> bool:
    return not (
        int(query_meta.get("row_count") or 0) == 0
        and query_meta.get("outcome") == QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED
    )


def record_budget_stop(
    artifact_state: dict[str, Any],
    query_meta: dict[str, Any],
    *,
    purpose: str,
) -> None:
    if not query_stops_pass(query_meta):
        return
    artifact_state["budget_stop"] = {
        "at": now_utc(),
        "purpose": purpose,
        "outcome": str(query_meta.get("outcome") or ""),
        "rows_returned": int(query_meta.get("row_count") or 0),
        "tokens_used": int(query_meta.get("estimated_tokens") or 0),
        "first_row_tokens": int(query_meta.get("first_row_tokens") or 0),
        "token_limit": int(query_meta.get("token_limit") or 0),
        "max_item_tokens": int(query_meta.get("max_item_tokens") or 0),
    }


def require_rows_for_positive_count(
    *,
    purpose: str,
    expected_count: int,
    rows: list[dict[str, Any]],
    query_meta: dict[str, Any],
) -> None:
    if (
        expected_count > 0
        and not rows
        and query_meta.get("outcome")
        not in {
            QUERY_OUTCOME_FIRST_ROW_OVERSIZED,
            QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED,
        }
    ):
        raise RuntimeError(
            f"{purpose} reported {expected_count} row(s), but its review query "
            "returned none. Check the stack-to-scope or signature expression."
        )


def evidence_review_id(
    *,
    hunt_id: str,
    artifact: str,
    kind: str,
    scope: dict[str, str],
    vql: str,
    env: dict[str, str],
    rows: list[dict[str, Any]],
) -> tuple[str, str]:
    evidence_hash = sha256_value(rows)
    review_id = "review-" + sha256_value(
        {
            "hunt_id": hunt_id,
            "artifact": artifact,
            "kind": kind,
            "scope": scope,
            "vql": vql,
            "env": env,
            "evidence_hash": evidence_hash,
        }
    )[:16]
    return review_id, evidence_hash


def review_item(
    *,
    hunt_id: str,
    artifact: str,
    kind: str,
    scope: dict[str, str],
    scope_count: int,
    exhaustive: bool,
    vql: str,
    env: dict[str, str],
    rows: list[dict[str, Any]],
    query_meta: dict[str, Any],
    review_match: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    review_id, evidence_hash = evidence_review_id(
        hunt_id=hunt_id,
        artifact=artifact,
        kind=kind,
        scope=scope,
        vql=vql,
        env=env,
        rows=rows,
    )
    public = {
        "review_id": review_id,
        "artifact": artifact,
        "kind": kind,
        "scope": scope,
        "scope_row_count": scope_count,
        "exhaustive": exhaustive,
        "evidence_hash": evidence_hash,
        "query": {
            "query_hash": sha256_value({"vql": vql, "env": env}),
            **query_meta,
        },
        "rows": rows,
        "decision_template": {
            "review_id": review_id,
            "complete": False,
            "findings": [],
            "filters": [],
            "normalization_candidates": [],
        },
    }
    if kind == "filter_validation":
        public["decision_template"]["filter_status"] = "case-approved"
    else:
        public["decision_template"]["disposition"] = "expected"
        public["decision_template"]["reason"] = ""
    if kind in {"signature", "normalized_stack"}:
        public["decision_template"]["drilldown"] = None
    if kind == "normalized_stack":
        public["decision_template"]["hijack_risk_reviewed"] = False
        public["decision_template"]["variant_risk_reviewed"] = False
    pending = {
        key: value
        for key, value in public.items()
        if key not in {"rows", "decision_template"}
    }
    pending["review_match"] = review_match or {}
    return public, pending


def normalize_known_bad(
    profile: dict[str, Any],
    *,
    artifact: str,
    indicators: list[str],
) -> list[dict[str, Any]]:
    review = profile.get("review", {})
    records = [
        {
            **item,
            "artifact": artifact,
            "scope": {},
            "status": "known-bad",
            "source": "artifact-profile",
        }
        for item in review.get("known_bad", [])
        if item.get("enabled", True)
    ]
    filter_fields = dict(review.get("filter_fields") or {})
    primary_field = next(iter(filter_fields), "")
    for index, raw in enumerate(indicators, start=1):
        value = str(raw)
        if "=" in value:
            field, pattern = value.split("=", 1)
            field = field.strip()
        else:
            field, pattern = primary_field, value
        if not field or field not in filter_fields:
            raise RuntimeError(
                f"Known-bad indicator field {field!r} is not approved for {artifact}."
            )
        if not pattern or len(pattern) > 4096:
            raise RuntimeError("Known-bad indicators must contain 1-4096 characters.")
        records.append(
            {
                "id": f"cli-indicator-{index}",
                "artifact": artifact,
                "scope": {},
                "field": field,
                "operator": "regex",
                "pattern": pattern,
                "reason": "Operator-supplied known-bad indicator.",
                "enabled": True,
                "status": "known-bad",
                "source": "command-line",
            }
        )
    return records


def initial_state(
    *,
    investigation_id: str,
    hunt_id: str,
    group: str,
    hunt_state: str,
) -> dict[str, Any]:
    timestamp = now_utc()
    return {
        "analysis_version": ANALYSIS_VERSION,
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "group": group,
        "created_at": timestamp,
        "updated_at": timestamp,
        "hunt_state": hunt_state,
        "status": "new",
        "host_execution": {},
        "artifacts": {},
        "case_filters": [],
        "findings": [],
        "analyst_review_memory": [],
        "normalization_candidates": [],
        "golden_promotions": [],
        "golden_promotion_skips": [],
        "autoruns_mode_coverage": {},
        "analysis_outputs": {},
        "filter_reference_files": [],
        "query_ledger": [],
    }


def load_state(
    path: Path,
    *,
    investigation_id: str,
    hunt_id: str,
    group: str,
    hunt_state: str,
) -> dict[str, Any]:
    """Load only the current canonical specialized state.

    Unsupported or mismatched local state is rebuilt from Velociraptor, which
    remains authoritative for hunt results and flow state.
    """

    if not path.is_file():
        return initial_state(
            investigation_id=investigation_id,
            hunt_id=hunt_id,
            group=group,
            hunt_state=hunt_state,
        )
    container = load_json_object(path)
    if int(container.get("schema_version") or 0) != flow_analysis.SCHEMA_VERSION:
        return initial_state(
            investigation_id=investigation_id,
            hunt_id=hunt_id,
            group=group,
            hunt_state=hunt_state,
        )
    embedded = container.get("specialized_analysis")
    if not isinstance(embedded, dict):
        return initial_state(
            investigation_id=investigation_id,
            hunt_id=hunt_id,
            group=group,
            hunt_state=hunt_state,
        )
    state = copy.deepcopy(embedded)
    if int(state.get("analysis_version") or 0) != ANALYSIS_VERSION:
        return initial_state(
            investigation_id=investigation_id,
            hunt_id=hunt_id,
            group=group,
            hunt_state=hunt_state,
        )
    if str(state.get("hunt_id") or "") != hunt_id:
        raise RuntimeError(f"Live analysis state {path} belongs to another hunt.")
    state.setdefault("artifacts", {})
    state.setdefault("host_execution", {})
    state.setdefault("case_filters", [])
    state.setdefault("findings", [])
    state.setdefault("analyst_review_memory", [])
    state.setdefault("normalization_candidates", [])
    state.setdefault("golden_promotions", [])
    state.setdefault("golden_promotion_skips", [])
    state.setdefault("autoruns_mode_coverage", {})
    state.setdefault("analysis_outputs", {})
    state.setdefault("query_ledger", [])
    review_manifest_path = path.parent / REVIEW_ITEMS_MANIFEST_FILENAME
    if review_manifest_path.is_file():
        manifest_reference = dict(state.get("review_items") or {})
        expected_manifest_sha256 = str(
            manifest_reference.get("sha256") or ""
        )
        actual_manifest_sha256 = sha256_file(review_manifest_path)
        if expected_manifest_sha256 and (
            expected_manifest_sha256 != actual_manifest_sha256
        ):
            raise RuntimeError(
                f"Review item manifest {review_manifest_path} does not match canonical state."
            )
        manifest = load_json_object(review_manifest_path)
        if str(manifest.get("hunt_id") or "") != hunt_id:
            raise RuntimeError(
                f"Review item manifest {review_manifest_path} belongs to another hunt."
            )
        for item in manifest.get("review_items") or []:
            if not isinstance(item, dict):
                continue
            review_state = item.get("review_state")
            if not isinstance(review_state, dict):
                continue
            artifact = str(review_state.get("artifact") or "")
            artifact_state = state["artifacts"].get(artifact)
            if not artifact or not isinstance(artifact_state, dict):
                continue
            artifact_state["pending_reviews"] = unique_dicts(
                [
                    *list(artifact_state.get("pending_reviews") or []),
                    review_state,
                ],
                key="review_id",
            )
    return state


def load_decisions(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    if path.suffix.casefold() == ".csv":
        return decisions_from_autoruns_review_queue(path)
    payload = load_json_object(path)
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        raise RuntimeError(f"Review decisions {path} must contain a reviews list.")
    if any(not isinstance(item, dict) for item in reviews):
        raise RuntimeError(f"Review decisions {path} contains a non-object review.")
    return list(reviews)


def compact_completed_scope_pages(artifact_state: dict[str, Any]) -> None:
    accounted_ids = {
        str(item.get("id") or "")
        for item in artifact_state.get("reviewed_signatures", [])
    }
    compacted_ids: set[str] = set()
    for page in artifact_state.get("scope_stack_pages", []):
        if page.get("status") == "compacted" or not page.get("exhaustive"):
            continue
        required_ids = {
            str(value)
            for value in page.get("accounting_ids") or []
            if str(value)
        }
        if not required_ids or not required_ids.issubset(accounted_ids):
            continue
        scope = dict(page.get("scope") or {})
        if scope:
            artifact_state.setdefault("reviewed_scopes", []).append(scope)
        page["status"] = "compacted"
        page["compacted_at"] = now_utc()
        compacted_ids.update(required_ids)
    seen_scopes: set[str] = set()
    unique_scopes: list[dict[str, Any]] = []
    for scope in artifact_state.get("reviewed_scopes") or []:
        scope_id = sha256_value(scope)
        if scope_id in seen_scopes:
            continue
        seen_scopes.add(scope_id)
        unique_scopes.append(scope)
    artifact_state["reviewed_scopes"] = unique_scopes
    if compacted_ids:
        artifact_state["reviewed_signatures"] = [
            item
            for item in artifact_state.get("reviewed_signatures", [])
            if str(item.get("id") or "") not in compacted_ids
        ]


def autoruns_promotion_record(
    *,
    pending: dict[str, Any],
    decision_context: dict[str, Any] | None = None,
) -> dict[str, str]:
    review_match = dict(pending.get("review_match") or {})
    dimensions = [
        str(value)
        for value in review_match.get("logical_dimensions") or []
    ]
    values = [
        str(value)
        for value in review_match.get("values") or []
    ]
    mapped = {
        name: value
        for name, value in zip(dimensions, values, strict=False)
    }
    image_path = (
        mapped["NormalizedImagePath"]
        if "NormalizedImagePath" in mapped
        else mapped.get("ImagePath")
    )
    launch_string = (
        mapped["NormalizedLaunchString"]
        if "NormalizedLaunchString" in mapped
        else mapped.get("LaunchString")
    )
    if image_path is None or launch_string is None or "Signer" not in mapped:
        raise RuntimeError(
            "Autoruns GoldenDB promotion requires logical ImagePath, "
            "LaunchString, and Signer dimensions."
        )
    return autoruns_golden.normalized_record(
        {
            "Category": dict(review_match.get("scope") or {}).get(
                "Category",
                "",
            ),
            "ImagePath": image_path,
            "LaunchString": launch_string,
            "Signer": mapped["Signer"],
            "EntryLocation": mapped.get("EntryLocation", ""),
            "Entry": mapped.get("Entry", ""),
            "Description": str(
                (decision_context or {}).get("Description")
                or (decision_context or {}).get("description")
                or ""
            ),
            "Company": str(
                (decision_context or {}).get("Company")
                or (decision_context or {}).get("company")
                or ""
            ),
        }
    )


def write_text_atomic(path: Path, text: str) -> None:
    atomic_io.write_text_atomic(path, text, newline="")


def pending_reviews_by_id(
    state: dict[str, Any],
) -> dict[str, tuple[str, dict[str, Any]]]:
    output: dict[str, tuple[str, dict[str, Any]]] = {}
    for artifact, artifact_state in state.get("artifacts", {}).items():
        for pending in artifact_state.get("pending_reviews", []):
            review_id = str(pending.get("review_id") or "")
            if review_id:
                output[review_id] = (str(artifact), pending)
    return output


def apply_decisions(
    state: dict[str, Any],
    decisions: list[dict[str, Any]],
    *,
    profiles: dict[str, dict[str, Any]],
    source: str,
    golden_db_path: Path | None = None,
    promote_reviewed: bool = False,
    rmm_reference: Path | None = None,
    golden_baseline_databases: Iterable[Path] | None = None,
) -> None:
    if promote_reviewed and golden_db_path is None:
        raise RuntimeError(
            "Automatic reviewed promotion requires a local GoldenDB path."
        )
    golden_candidates: list[dict[str, str]] = []
    pending_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
    for artifact, artifact_state in state.get("artifacts", {}).items():
        for pending in artifact_state.get("pending_reviews", []):
            pending_by_id[str(pending.get("review_id") or "")] = (
                artifact,
                pending,
            )
    for decision in decisions:
        review_id = str(decision.get("review_id") or "")
        if review_id not in pending_by_id:
            raise RuntimeError(
                f"Review decision references unknown or stale review_id {review_id!r}."
            )
        artifact, pending = pending_by_id[review_id]
        pending_use_case = str(pending.get("use_case") or "")
        profile = artifact_profiles.resolve_profile(artifact, profiles)
        if profile is None:
            discovery = dict(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("stack_discovery")
                or {}
            )
            review_match = dict(pending.get("review_match") or {})
            if (
                discovery.get("runtime_profile_ephemeral") is True
                and (
                    review_match.get("type") == "streaming_stack_group"
                    or (
                        pending.get("kind") == "direct"
                        and pending.get("exhaustive") is True
                    )
                )
            ):
                profile = unprofiled_runtime_profile(artifact)
            else:
                raise RuntimeError(
                    f"No artifact profile is available for {artifact}."
                )
        artifact_state = state["artifacts"][artifact]
        if pending.get("kind") == "filter_validation" and bool(
            decision.get("complete")
        ):
            if "filter_status" not in decision:
                raise RuntimeError(
                    "Completed filter validation decisions require an explicit "
                    "filter_status."
                )
            filter_status = str(decision.get("filter_status") or "").strip()
            if filter_status not in {"case-approved", "retired"}:
                raise RuntimeError(
                    "Filter validation decisions must set filter_status to "
                    "'case-approved' or 'retired'."
                )
            matched_rows = int(pending.get("scope_row_count") or 0)
            if filter_status == "case-approved" and matched_rows == 0:
                raise RuntimeError(
                    "A zero-match filter cannot be approved; retire it or "
                    "collect a non-zero validation sample."
                )
            query_meta = dict(pending.get("query") or {})
            if filter_status == "case-approved" and (
                int(query_meta.get("row_count") or 0) < 1
                or bool(query_meta.get("oversized_row"))
            ):
                raise RuntimeError(
                    "A filter cannot be approved without at least one "
                    "reviewable validation row; retire it or increase the "
                    "bounded token limit."
                )
            filter_id = str(pending.get("filter_id") or "")
            matched_filter = next(
                (
                    item
                    for item in state.get("case_filters", [])
                    if str(item.get("id") or "") == filter_id
                ),
                None,
            )
            if matched_filter is None:
                raise RuntimeError(
                    f"Filter validation {review_id} references missing filter "
                    f"{filter_id!r}."
                )
            matched_filter["status"] = filter_status
            matched_filter["validated_at"] = now_utc()
            matched_filter["validation_review_id"] = review_id
            matched_filter["matched_rows"] = matched_rows
        findings = decision.get("findings") or []
        if not isinstance(findings, list):
            raise RuntimeError(f"Review decision {review_id} findings must be a list.")
        for raw_finding in findings:
            if isinstance(raw_finding, dict):
                finding = dict(raw_finding)
            else:
                finding = {"summary": str(raw_finding)}
            finding["artifact"] = artifact
            finding["use_case"] = pending_use_case
            finding["review_id"] = review_id
            finding["recorded_at"] = now_utc()
            state["findings"].append(finding)
        raw_normalizations = decision.get("normalization_candidates") or []
        if not isinstance(raw_normalizations, list):
            raise RuntimeError(
                f"Review decision {review_id} normalization_candidates must "
                "be a list."
            )
        for raw_candidate in raw_normalizations:
            if not isinstance(raw_candidate, dict):
                raise RuntimeError(
                    f"Review decision {review_id} contains a non-object "
                    "normalization candidate."
                )
            field = str(raw_candidate.get("field") or "").strip()
            kind = str(raw_candidate.get("kind") or "").strip()
            reason = str(raw_candidate.get("reason") or "").strip()
            if not field or kind not in NORMALIZATION_KINDS or not reason:
                raise RuntimeError(
                    "Normalization candidates require field, a supported "
                    "kind, and a concrete reason."
                )
            candidate = {
                "id": "normalization-" + sha256_value(
                    {
                        "artifact": artifact,
                        "use_case": pending_use_case,
                        "field": field,
                        "kind": kind,
                        "scope": raw_candidate.get("scope") or {},
                    }
                )[:16],
                "artifact": artifact,
                "use_case": pending_use_case,
                "field": field,
                "kind": kind,
                "scope": dict(raw_candidate.get("scope") or {}),
                "reason": reason,
                "status": "proposed",
                "review_id": review_id,
                "proposed_at": now_utc(),
            }
            state["normalization_candidates"].append(candidate)
        state["normalization_candidates"] = unique_dicts(
            state["normalization_candidates"],
            key="id",
        )
        raw_drilldown = decision.get("drilldown")
        if raw_drilldown:
            if not isinstance(raw_drilldown, dict):
                raise RuntimeError(
                    f"Review decision {review_id} drilldown must be an object."
                )
            drilldown_reason = str(raw_drilldown.get("reason") or "").strip()
            review_match = dict(pending.get("review_match") or {})
            if (
                not drilldown_reason
                or not review_match.get("server_dimensions")
                or not review_match.get("values")
            ):
                raise RuntimeError(
                    "Drill-down requests require a concrete reason and a "
                    "deterministic signature-backed review."
                )
            drilldown_id = "drilldown-" + sha256_value(
                {
                    "artifact": artifact,
                    "scope": review_match.get("scope") or {},
                    "stack_id": review_match.get("stack_id") or "",
                    "values": review_match.get("values") or [],
                }
            )[:16]
            artifact_state.setdefault("drilldown_requests", []).append(
                {
                    "id": drilldown_id,
                    "scope": dict(review_match.get("scope") or {}),
                    "stack_id": str(review_match.get("stack_id") or ""),
                    "server_dimensions": list(
                        review_match.get("server_dimensions") or []
                    ),
                    "scope_aliases": list(
                        review_match.get("scope_aliases") or []
                    ),
                    "scope_server_dimensions": list(
                        review_match.get("scope_server_dimensions") or []
                    ),
                    "values": [
                        str(value) for value in review_match.get("values") or []
                    ],
                    "reason": drilldown_reason,
                    "source_disposition": str(
                        decision.get("disposition") or ""
                    ).strip(),
                    "use_case": str(pending.get("use_case") or ""),
                    "output_name": str(pending.get("output_name") or ""),
                    "source_review_id": review_id,
                    "status": "pending",
                    "requested_at": now_utc(),
                }
            )
            artifact_state["drilldown_requests"] = unique_dicts(
                artifact_state["drilldown_requests"],
                key="id",
            )
        raw_filters = decision.get("filters") or []
        if not isinstance(raw_filters, list):
            raise RuntimeError(f"Review decision {review_id} filters must be a list.")
        if (
            bool(decision.get("complete"))
            and pending.get("kind") != "filter_validation"
            and pending.get("kind") != "signature"
            and not pending.get("exhaustive")
            and not raw_filters
            and not raw_drilldown
            and not (
                pending.get("kind") == "normalized_stack"
                and pending.get("closure_eligible")
            )
        ):
            raise RuntimeError(
                f"Review {review_id} is non-exhaustive and cannot be marked "
                "complete without a filter candidate. Submit complete=false, "
                "increase bounded limits, refine the pivot, or explicitly "
                "extract the evidence."
            )
        for raw_filter in raw_filters:
            if not isinstance(raw_filter, dict):
                raise RuntimeError(f"Review decision {review_id} contains a non-object filter.")
            candidate = dict(raw_filter)
            candidate["status"] = "candidate"
            candidate["use_case"] = pending_use_case
            record = validate_filter(
                candidate,
                artifact=artifact,
                profile=profile,
                source=source,
                default_status="candidate",
            )
            state["case_filters"].append(record)
        state["case_filters"] = unique_dicts(state["case_filters"], key="id")
        if bool(decision.get("complete")):
            disposition = str(decision.get("disposition") or "").strip()
            reason = str(decision.get("reason") or "").strip()
            if pending.get("kind") != "filter_validation":
                if disposition not in ACCOUNTING_DISPOSITIONS:
                    raise RuntimeError(
                        f"Review {review_id} requires disposition one of: "
                        f"{', '.join(sorted(ACCOUNTING_DISPOSITIONS))}."
                    )
                if not reason:
                    raise RuntimeError(
                        f"Review {review_id} requires a concrete accounting "
                        "reason."
                    )
            if pending.get("kind") == "signature":
                if raw_drilldown:
                    # A suspicious normalized/exact pivot remains in the
                    # remaining set until its original rows are retrieved and
                    # the drill-down itself is completed exhaustively.
                    pass
                else:
                    review_match = dict(pending.get("review_match") or {})
                    if (
                        not review_match.get("server_dimensions")
                        or not review_match.get("values")
                    ):
                        raise RuntimeError(
                            f"Signature review {review_id} has no deterministic "
                            "server-side match."
                        )
                    accounting_id = accounting_id_for(
                        artifact=artifact,
                        scope=dict(review_match.get("scope") or {}),
                        stack_id=str(review_match.get("stack_id") or ""),
                        values=list(review_match.get("values") or []),
                    )
                    signature_record = {
                        "id": accounting_id,
                        "use_case": pending_use_case,
                        "scope": dict(review_match.get("scope") or {}),
                        "stack_id": str(review_match.get("stack_id") or ""),
                        "server_dimensions": list(
                            review_match.get("server_dimensions") or []
                        ),
                        "scope_aliases": list(
                            review_match.get("scope_aliases") or []
                        ),
                        "scope_server_dimensions": list(
                            review_match.get("scope_server_dimensions") or []
                        ),
                        "values": [
                            str(value)
                            for value in review_match.get("values") or []
                        ],
                        "row_count": int(
                            review_match.get("row_count")
                            or pending.get("scope_row_count")
                            or 0
                        ),
                        "disposition": disposition,
                        "reason": reason,
                        "review_id": review_id,
                        "accounted_at": now_utc(),
                    }
                    artifact_state.setdefault("reviewed_signatures", []).append(
                        signature_record
                    )
                    artifact_state["reviewed_signatures"] = unique_dicts(
                        artifact_state["reviewed_signatures"],
                        key="id",
                    )
                    artifact_state.setdefault("row_accounting", []).append(
                        {
                            **signature_record,
                            "basis": "exact_signature",
                        }
                    )
                    artifact_state["row_accounting"] = unique_dicts(
                        artifact_state["row_accounting"],
                        key="id",
                    )
            elif pending.get("kind") == "normalized_stack":
                if raw_drilldown:
                    pass
                elif not pending.get("closure_eligible"):
                    raise RuntimeError(
                        f"Normalized stack review {review_id} contains "
                        "multiple exact variants and requires drill-down."
                    )
                elif not bool(decision.get("hijack_risk_reviewed")):
                    raise RuntimeError(
                        f"Normalized stack review {review_id} requires "
                        "hijack_risk_reviewed=true before direct closure."
                    )
                elif (
                    int(pending.get("exact_variant_count_lower_bound") or 0) != 1
                    and not bool(decision.get("variant_risk_reviewed"))
                ):
                    raise RuntimeError(
                        f"Normalized stack review {review_id} has multiple or "
                        "unresolved exact variants and requires "
                        "variant_risk_reviewed=true before direct closure."
                    )
                else:
                    review_match = dict(pending.get("review_match") or {})
                    accounting_id = accounting_id_for(
                        artifact=artifact,
                        scope=dict(review_match.get("scope") or {}),
                        stack_id=str(review_match.get("stack_id") or ""),
                        values=list(review_match.get("values") or []),
                    )
                    signature_record = {
                        "id": accounting_id,
                        "use_case": pending_use_case,
                        "scope": dict(review_match.get("scope") or {}),
                        "stack_id": str(review_match.get("stack_id") or ""),
                        "server_dimensions": list(
                            review_match.get("server_dimensions") or []
                        ),
                        "scope_aliases": list(
                            review_match.get("scope_aliases") or []
                        ),
                        "scope_server_dimensions": list(
                            review_match.get("scope_server_dimensions") or []
                        ),
                        "values": [
                            str(value)
                            for value in review_match.get("values") or []
                        ],
                        "row_count": int(
                            review_match.get("row_count")
                            or pending.get("scope_row_count")
                            or 0
                        ),
                        "disposition": disposition,
                        "reason": reason,
                        "review_id": review_id,
                        "accounted_at": now_utc(),
                    }
                    artifact_state.setdefault("reviewed_signatures", []).append(
                        signature_record
                    )
                    artifact_state.setdefault("row_accounting", []).append(
                        {
                            **signature_record,
                            "basis": "normalized_stack_review",
                        }
                    )
            elif pending.get("kind") == "drilldown":
                request_id = str(pending.get("drilldown_id") or "")
                request = next(
                    (
                        item
                        for item in artifact_state.get(
                            "drilldown_requests",
                            [],
                        )
                        if str(item.get("id") or "") == request_id
                    ),
                    None,
                )
                if request is None:
                    raise RuntimeError(
                        f"Drill-down review {review_id} references missing "
                        f"request {request_id!r}."
                    )
                request["status"] = "complete"
                request["completed_at"] = now_utc()
                request["completion_review_id"] = review_id
                accounting_id = accounting_id_for(
                    artifact=artifact,
                    scope=dict(request.get("scope") or {}),
                    stack_id=str(request.get("stack_id") or ""),
                    values=list(request.get("values") or []),
                )
                signature_record = {
                    "id": accounting_id,
                    "use_case": pending_use_case,
                    "scope": dict(request.get("scope") or {}),
                    "stack_id": str(request.get("stack_id") or ""),
                    "server_dimensions": list(
                        request.get("server_dimensions") or []
                    ),
                    "scope_aliases": list(request.get("scope_aliases") or []),
                    "scope_server_dimensions": list(
                        request.get("scope_server_dimensions") or []
                    ),
                    "values": [
                        str(value) for value in request.get("values") or []
                    ],
                    "row_count": int(pending.get("scope_row_count") or 0),
                    "disposition": disposition,
                    "reason": reason,
                    "review_id": review_id,
                    "accounted_at": now_utc(),
                }
                artifact_state.setdefault("reviewed_signatures", []).append(
                    signature_record
                )
                artifact_state["reviewed_signatures"] = unique_dicts(
                    artifact_state["reviewed_signatures"],
                    key="id",
                )
                artifact_state.setdefault("row_accounting", []).append(
                    {
                        **signature_record,
                        "basis": "exhaustive_normalized_drilldown",
                    }
                )
            elif pending.get("kind") == "direct" and pending.get("exhaustive"):
                accounted_rows = int(
                    pending.get("artifact_total") or pending.get("scope_row_count") or 0
                )
                artifact_state["completed_at_total"] = accounted_rows
                accounting_id = "accounting-" + sha256_value(
                    {
                        "artifact": artifact,
                        "review_id": review_id,
                        "basis": "exhaustive_review",
                    }
                )[:16]
                artifact_state.setdefault("row_accounting", []).append(
                    {
                        "id": accounting_id,
                        "use_case": pending_use_case,
                        "scope": {},
                        "basis": "exhaustive_review",
                        "row_count": accounted_rows,
                        "disposition": disposition,
                        "reason": reason,
                        "review_id": review_id,
                        "accounted_at": now_utc(),
                    }
                )
            elif pending.get("kind") == "pivot" and pending.get("exhaustive"):
                scope = dict(pending.get("scope") or {})
                if scope:
                    artifact_state.setdefault("reviewed_scopes", []).append(scope)
                    accounting_id = "accounting-" + sha256_value(
                        {
                            "artifact": artifact,
                            "scope": scope,
                            "basis": "exhaustive_scope_review",
                        }
                    )[:16]
                    artifact_state.setdefault("row_accounting", []).append(
                        {
                            "id": accounting_id,
                            "use_case": pending_use_case,
                            "scope": scope,
                            "basis": "exhaustive_scope_review",
                            "row_count": int(pending.get("scope_row_count") or 0),
                            "disposition": disposition,
                            "reason": reason,
                            "review_id": review_id,
                            "accounted_at": now_utc(),
                        }
                    )
            elif pending.get("kind") == "known_bad" and pending.get("exhaustive"):
                review_match = dict(pending.get("review_match") or {})
                if review_match:
                    artifact_state.setdefault("reviewed_matches", []).append(
                        review_match
                    )
                    accounting_id = "accounting-" + sha256_value(
                        {
                            "artifact": artifact,
                            "review_match": review_match,
                            "basis": "known_bad_review",
                        }
                    )[:16]
                    artifact_state.setdefault("row_accounting", []).append(
                        {
                            "id": accounting_id,
                            "scope": dict(review_match.get("scope") or {}),
                            "basis": "known_bad_review",
                            "row_count": int(pending.get("scope_row_count") or 0),
                            "disposition": disposition,
                            "reason": reason,
                            "review_id": review_id,
                            "accounted_at": now_utc(),
                        }
                    )
            artifact_state["row_accounting"] = unique_dicts(
                artifact_state.get("row_accounting") or [],
                key="id",
            )
            artifact_state["reviewed_signatures"] = unique_dicts(
                artifact_state.get("reviewed_signatures") or [],
                key="id",
            )
            explicit_promotion = bool(
                decision.get("promote_to_golden")
            )
            promotion_requested = (
                explicit_promotion or promote_reviewed
            )
            if promotion_requested and artifact in AUTORUNS_ARTIFACTS:
                if golden_db_path is None:
                    raise RuntimeError(
                        f"Review {review_id} requested GoldenDB promotion "
                        "without --autoruns-golden-db."
                    )
                blocked = sorted(
                    set(pending.get("non_promotable_reasons") or [])
                )
                priority_reasons = sorted(
                    set(
                        pending.get("priority_review_reasons")
                        or pending_autoruns_priority_review_reasons(
                            pending
                        )
                    )
                )
                missing_priority_reviews: list[str] = []
                if (
                    "lolbin-image" in priority_reasons
                    and not bool(
                        decision.get("lolbin_behavior_reviewed")
                    )
                ):
                    missing_priority_reviews.append(
                        "lolbin_behavior_reviewed"
                    )
                if (
                    "unverified-signer" in priority_reasons
                    and not bool(
                        decision.get("unverified_signer_reviewed")
                    )
                ):
                    missing_priority_reviews.append(
                        "unverified_signer_reviewed"
                    )
                promotion_eligible = (
                    pending.get("kind") == "normalized_stack"
                    and not raw_drilldown
                    and disposition in {"benign", "expected"}
                    and not blocked
                    and not missing_priority_reviews
                )
                if not promotion_eligible:
                    reason = (
                        ",".join(blocked)
                        or ",".join(
                            f"requires-{value}"
                            for value in missing_priority_reviews
                        )
                        or "requires-complete-benign-or-expected-"
                        "normalized-stack"
                    )
                    if explicit_promotion:
                        raise RuntimeError(
                            f"Review {review_id} is not eligible for "
                            f"GoldenDB promotion: {reason}."
                        )
                    state.setdefault(
                        "golden_promotion_skips",
                        [],
                    ).append(
                        {
                            "review_id": review_id,
                            "artifact": artifact,
                            "reason": reason,
                            "recorded_at": now_utc(),
                        }
                    )
                else:
                    decision_context = (
                        decision.get("golden_context") or {}
                    )
                    if not isinstance(decision_context, dict):
                        raise RuntimeError(
                            f"Review {review_id} golden_context must be "
                            "an object."
                        )
                    record = autoruns_promotion_record(
                        pending=pending,
                        decision_context=decision_context,
                    )
                    golden_candidates.append(record)
                    state.setdefault("golden_promotions", []).append(
                        {
                            "review_id": review_id,
                            "artifact": artifact,
                            "hash_key": record["hash_key"],
                            "category": record["category"],
                            "database": str(golden_db_path),
                            "recorded_at": now_utc(),
                        }
                    )
        artifact_state.setdefault("completed_review_ids", []).append(review_id)
    if golden_candidates and golden_db_path is not None:
        autoruns_golden.promote_records(
            golden_db_path,
            golden_candidates,
            rmm_reference=rmm_reference,
            baseline_databases=golden_baseline_databases,
        )
    state["golden_promotions"] = unique_dicts(
        state.get("golden_promotions") or [],
        key="review_id",
    )
    state["golden_promotion_skips"] = unique_dicts(
        state.get("golden_promotion_skips") or [],
        key="review_id",
    )
    for artifact_state in state.get("artifacts", {}).values():
        compact_completed_scope_pages(artifact_state)
    decided_ids = {
        str(decision.get("review_id") or "")
        for decision in decisions
    }
    for artifact_state in state.get("artifacts", {}).values():
        artifact_state["pending_reviews"] = [
            pending
            for pending in artifact_state.get("pending_reviews", [])
            if str(pending.get("review_id") or "") not in decided_ids
        ]


def artifact_state_for(
    state: dict[str, Any],
    artifact: str,
    *,
    profile_hash: str,
) -> dict[str, Any]:
    artifact_state = state["artifacts"].setdefault(
        artifact,
        {
            "profile_hash": profile_hash,
            "status": "new",
            "baseline_total": 0,
            "current_total": 0,
            "remaining_total": 0,
            "completed_at_total": None,
            "reviewed_scopes": [],
            "reviewed_matches": [],
            "reviewed_signatures": [],
            "row_accounting": [],
            "drilldown_requests": [],
            "scope_stack_pages": [],
            "pending_reviews": [],
            "completed_review_ids": [],
            "budget_stop": {},
            "autoruns_focused_workflows": {},
        },
    )
    artifact_state.setdefault("budget_stop", {})
    artifact_state.setdefault("reviewed_signatures", [])
    artifact_state.setdefault("row_accounting", [])
    artifact_state.setdefault("drilldown_requests", [])
    artifact_state.setdefault("scope_stack_pages", [])
    artifact_state.setdefault("autoruns_focused_workflows", {})
    if artifact_state.get("profile_hash") != profile_hash:
        artifact_state["profile_hash"] = profile_hash
        artifact_state["completed_at_total"] = None
        artifact_state["reviewed_scopes"] = []
        artifact_state["reviewed_matches"] = []
        artifact_state["reviewed_signatures"] = []
        artifact_state["row_accounting"] = []
        artifact_state["drilldown_requests"] = []
        artifact_state["scope_stack_pages"] = []
        artifact_state["pending_reviews"] = []
        artifact_state["autoruns_focused_workflows"] = {}
        artifact_state["status"] = "profile_changed"
    return artifact_state


def query_with_scope(
    *,
    base_where: str,
    scope: dict[str, str],
    profile: dict[str, Any],
    env: dict[str, str],
) -> str:
    rendered_scope = scope_expression(
        scope,
        profile=profile,
        env=env,
        prefix="Pivot",
    )
    return combine_where(base_where, rendered_scope)


def append_query_ledger(
    state: dict[str, Any],
    *,
    artifact: str,
    purpose: str,
    vql: str,
    env: dict[str, str],
    row_count: int,
) -> str:
    query_hash = sha256_value({"vql": vql, "env": env})
    state["query_ledger"].append(
        {
            "at": now_utc(),
            "artifact": artifact,
            "purpose": purpose,
            "query_hash": query_hash,
            "row_count": row_count,
        }
    )
    state["query_ledger"] = state["query_ledger"][-500:]
    return query_hash


def autoruns_analysis_mode_id(
    *,
    use_case: str,
    golden_enabled: bool,
) -> str:
    selected = str(use_case or "").strip()
    if selected:
        return selected
    return "general-golden-residual" if golden_enabled else "general"


def update_autoruns_mode_coverage(
    state: dict[str, Any],
    *,
    artifact: str,
    artifact_state: dict[str, Any],
    use_case: str,
    golden_enabled: bool,
) -> dict[str, Any]:
    if artifact not in AUTORUNS_ARTIFACTS:
        return {}
    mode_id = autoruns_analysis_mode_id(
        use_case=use_case,
        golden_enabled=golden_enabled,
    )
    source_rows = int(artifact_state.get("current_total") or 0)
    scope_rows = int(
        artifact_state.get("analysis_scope_total")
        if artifact_state.get("analysis_scope_total") is not None
        else source_rows
    )
    remaining_rows = max(
        0,
        int(artifact_state.get("remaining_total") or 0),
    )
    result_review_coverage = (
        "complete"
        if str(artifact_state.get("status") or "") == "complete"
        else "incomplete"
    )
    target_coverage = str(
        state.get("target_execution_coverage") or "unknown"
    )
    source_terminal = (
        str(state.get("hunt_state") or "").upper()
        in TERMINAL_HUNT_STATES
    )
    coverage = (
        "complete"
        if result_review_coverage == "complete"
        and target_execution_satisfies_review(target_coverage)
        and source_terminal
        else "provisional"
        if not source_terminal
        else "provisional"
        if target_coverage == "provisional"
        else "unknown"
        if target_coverage == "unknown"
        else "incomplete"
    )
    golden = dict(artifact_state.get("autoruns_golden") or {})
    record = {
        "mode": mode_id,
        "source_rows": source_rows,
        "scope_rows": scope_rows,
        "accounted_rows": max(0, scope_rows - remaining_rows),
        "remaining_rows": remaining_rows,
        "status": str(artifact_state.get("status") or ""),
        "result_review_coverage": result_review_coverage,
        "target_execution_coverage": target_coverage,
        "coverage": coverage,
        "analysis_input_hash": str(
            artifact_state.get("analysis_input_hash") or ""
        ),
        "updated_at": now_utc(),
    }
    if result_review_coverage == "complete":
        record["completed_at"] = now_utc()
    if golden_enabled and not use_case:
        record["golden_db"] = {
            key: golden.get(key)
            for key in (
                "tool",
                "version",
                "inventory_hash",
                "identity_count",
                "record_count",
                "strict_subtraction",
                "source_rows",
                "matched_rows",
                "residual_rows",
                "warnings",
            )
            if key in golden
        }
    state.setdefault("autoruns_mode_coverage", {}).setdefault(
        artifact,
        {},
    )[mode_id] = record
    return record


def analysis_input_hash(
    *,
    profile_hash: str,
    filters: list[dict[str, Any]],
    known_bad: list[dict[str, Any]],
    use_case: dict[str, Any] | None = None,
    autoruns_golden_configuration: dict[str, Any] | None = None,
    source_review_mode: str = "",
    stack_field_preferences: list[str] | None = None,
    stack_field_guidance: str = "",
    stack_max_total_rows: int | None = None,
) -> str:
    filter_keys = (
        "id",
        "artifact",
        "scope",
        "conditions",
        "status",
    )
    known_bad_keys = (
        "id",
        "artifact",
        "scope",
        "field",
        "operator",
        "pattern",
        "enabled",
    )
    golden_input_keys = (
        "enabled",
        "tool",
        "version",
        "inventory_hash",
        "database_sha256",
        "lookup_payload_sha256",
        "residual_workflow_version",
    )
    golden_input = {
        key: (autoruns_golden_configuration or {}).get(key)
        for key in golden_input_keys
        if key in (autoruns_golden_configuration or {})
    }
    return sha256_value(
        {
            "profile_hash": profile_hash,
            "autoruns_canonicalization_version": autoruns.CANONICALIZATION_VERSION,
            "filters": sorted(
                (
                    {key: item.get(key) for key in filter_keys}
                    for item in filters
                ),
                key=lambda item: stable_json(item),
            ),
            "known_bad": sorted(
                (
                    {key: item.get(key) for key in known_bad_keys}
                    for item in known_bad
                ),
                key=lambda item: stable_json(item),
            ),
            "use_case": use_case or {},
            "autoruns_golden": golden_input,
            "source_review_mode": source_review_mode,
            **({"stack_max_total_rows": stack_max_total_rows}
               if stack_max_total_rows is not None else {}),
            "stack_field_preferences": list(stack_field_preferences or []),
            "stack_field_guidance_sha256": (
                sha256_value(stack_field_guidance)
                if stack_field_guidance
                else ""
            ),
        }
    )


def update_analysis_watermark(
    artifact_state: dict[str, Any],
    *,
    total: int,
    input_hash: str,
) -> list[str]:
    previous_hash = str(artifact_state.get("analysis_input_hash") or "")
    previous_total = int(artifact_state.get("current_total") or 0)
    reasons: list[str] = []
    if previous_hash:
        if previous_total != total:
            reasons.append(f"row_count_changed:{previous_total}->{total}")
        if previous_hash != input_hash:
            reasons.append("analysis_inputs_changed")
    if reasons:
        artifact_state["completed_at_total"] = None
        artifact_state["reviewed_scopes"] = []
        artifact_state["reviewed_matches"] = []
        artifact_state["reviewed_signatures"] = []
        artifact_state["row_accounting"] = []
        artifact_state["drilldown_requests"] = []
        artifact_state["scope_stack_pages"] = []
        artifact_state["pending_reviews"] = []
        artifact_state["budget_stop"] = {}
        artifact_state["watermark_reset_at"] = now_utc()
        artifact_state["watermark_reset_reasons"] = reasons
    artifact_state["current_total"] = total
    artifact_state["analysis_input_hash"] = input_hash
    artifact_state["coverage_watermark_total"] = total
    return reasons


def compact_autoruns_residual_state(
    artifact_state: dict[str, Any],
) -> None:
    for key in (
        "reviewed_scopes",
        "reviewed_matches",
        "reviewed_signatures",
        "row_accounting",
        "drilldown_requests",
        "scope_stack_pages",
        "pending_reviews",
        "scope_reductions",
    ):
        artifact_state[key] = []
    artifact_state["budget_stop"] = {}


def retained_autoruns_candidate_output(
    paths: dict[str, Path],
    artifact_state: dict[str, Any],
) -> dict[str, Any]:
    """Describe a prior candidate set without treating it as current output."""

    output: dict[str, Any] = {
        "status": "pending",
        "action": "none",
        "current_run": False,
        "reason": "awaiting_current_review",
    }
    candidate_path = paths["autoruns_potential_golden"]
    if not candidate_path.is_file():
        return output
    actual_sha256 = sha256_file(candidate_path)
    previous_workflow = artifact_state.get("autoruns_residual_workflow")
    previous_reference: dict[str, Any] = {}
    previous_stage = ""
    if isinstance(previous_workflow, dict):
        previous_stage = str(previous_workflow.get("stage") or "")
        previous_reference = dict(
            dict(previous_workflow.get("classification") or {}).get(
                "potential_golden"
            )
            or {}
        )
    retained_reference = {
        key: copy.deepcopy(previous_reference[key])
        for key in (
            "path",
            "sha256",
            "row_count",
            "reviewed_group_count",
            "published_at",
            "source_stack_sha256",
            "source_query_sha256",
            "golden_db_sha256",
            "golden_db_version",
        )
        if key in previous_reference
    }
    retained_reference.setdefault(
        "path", f"analysis/{candidate_path.name}"
    )
    retained_reference["actual_sha256"] = actual_sha256
    verified = bool(
        previous_stage == "complete"
        and previous_reference.get("path")
        == f"analysis/{candidate_path.name}"
        and previous_reference.get("sha256") == actual_sha256
    )
    retained_reference["verified"] = verified
    output.update(
        {
            "action": (
                "preserved_stale" if verified else "preserved_unverified"
            ),
            "retained_previous": retained_reference,
        }
    )
    return output


def iter_autoruns_stack_rows(
    api: Any,
    *,
    query: str,
    query_environment: dict[str, str],
) -> Iterable[dict[str, Any]]:
    """Yield normalized aggregate rows directly from streamed API batches."""

    for row in iter_query_rows(
        api,
        vql=query,
        env=query_environment,
        purpose="build-autoruns-residual-stack",
    ):
        total = int(row.get("Total") or 0)
        if total <= 0:
            continue
        yield {
            "ImagePath": str(row.get("ImagePath") or ""),
            "LaunchString": str(row.get("LaunchString") or ""),
            "Signer": str(row.get("Signer") or ""),
            "ExampleCategory": str(row.get("ExampleCategory") or ""),
            "Total": total,
        }


def review_autoruns_suspicious_context_streaming(
    api: Any,
    *,
    hunt_id: str,
    artifact: str,
    profile: dict[str, Any],
    suspicious_rows: list[dict[str, Any]],
    state: dict[str, Any],
    source: review_source.ReviewSource | None = None,
    identity_batch_size: int | None = None,
    request_max_bytes: int = DEFAULT_AUTORUNS_DRILLDOWN_REQUEST_BYTES,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate exact suspicious context without persisting or retaining rows."""

    projection = [
        *profile_projection(profile),
        f"{autoruns.trusted_key_vql()} AS HashKey",
        "dict(ImagePath=" + autoruns.user_path_vql("`Image Path`")
        + ", LaunchString=" + autoruns.user_path_vql("`Launch String`")
        + ", Signer=" + autoruns.ascii_lower_vql("Signer") + ") AS _AutorunsIdentity",
    ]
    all_items: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    contextual_exclusions: list[dict[str, Any]] = []
    global_hosts: set[tuple[str, str]] = set()
    context_row_count = 0
    query_count = 0

    batches = autoruns_suspicious_request_batches(
        api, projection=projection, suspicious_rows=suspicious_rows,
        env=query_env(hunt_id, artifact, source), source=source,
        identity_batch_size=identity_batch_size, request_max_bytes=request_max_bytes,
    )
    for batch_number, (query, env, selected_by_identity, request_bytes) in enumerate(batches, 1):
        stats: dict[tuple[str, str, str], dict[str, Any]] = {
            identity: {
                "row_count": 0,
                "hosts": {},
                "categories": set(),
                "persistence": set(),
                "hash_key": "",
                "exclusion_reasons": set(),
            }
            for identity in selected_by_identity
        }
        operation_log.emit(
            "autoruns_drilldown_started", stage="autoruns_drilldown",
            batch=batch_number,
            selected_identities=len(selected_by_identity),
            request_bytes=request_bytes, request_max_bytes=request_max_bytes,
        )
        for row in iter_query_rows(
            api, vql=query, env=env, purpose="autoruns-suspicious-drilldown",
            strict_rows=True,
        ):
            payload = row.get("_AutorunsIdentity")
            if not isinstance(payload, dict) or any(
                not isinstance(payload.get(key), str)
                for key in ("ImagePath", "LaunchString", "Signer")
            ):
                operation_log.emit("autoruns_drilldown_failed", level="error",
                                   stage="autoruns_drilldown",
                                   error_code="autoruns_invalid_server_identity")
                raise RuntimeError("Suspicious Autoruns drill-down omitted its server identity.")
            identity = (
                payload["ImagePath"],
                payload["LaunchString"],
                payload["Signer"],
            )
            if identity not in stats:
                operation_log.emit(
                    "autoruns_drilldown_failed", level="error",
                    stage="autoruns_drilldown", error_code="autoruns_unexpected_identity",
                    batch=batch_number,
                )
                raise RuntimeError(
                    "Suspicious Autoruns drill-down returned an unexpected "
                    "normalized identity."
                )
            hash_key = str(row.get("HashKey") or "").strip().casefold()
            if not SHA1_RE.fullmatch(hash_key):
                operation_log.emit(
                    "autoruns_drilldown_failed", level="error",
                    stage="autoruns_drilldown", error_code="autoruns_invalid_hash",
                    batch=batch_number,
                )
                raise RuntimeError(
                    "Suspicious Autoruns drill-down returned an invalid "
                    "server HashKey."
                )
            item = stats[identity]
            existing_hash = str(item["hash_key"] or "")
            if existing_hash and existing_hash != hash_key:
                operation_log.emit(
                    "autoruns_drilldown_failed", level="error",
                    stage="autoruns_drilldown", error_code="autoruns_inconsistent_hash",
                    batch=batch_number,
                )
                raise RuntimeError(
                    "Suspicious Autoruns drill-down returned inconsistent "
                    "server HashKeys for one normalized identity."
                )
            item["hash_key"] = hash_key
            item["row_count"] += 1
            context_row_count += 1
            host = (
                str(row.get("Fqdn") or ""),
                str(row.get("ClientId") or ""),
            )
            if any(host):
                item["hosts"][host] = int(item["hosts"].get(host) or 0) + 1
            category = str(row.get("Category") or "")
            if category:
                item["categories"].add(category)
            persistence = (
                category,
                str(row.get("EntryLocation") or ""),
                str(row.get("Entry") or ""),
            )
            if any(persistence):
                item["persistence"].add(persistence)
            item["exclusion_reasons"].add(
                autoruns_context_exclusion_reason(dict(row))
            )
        missing = [identity for identity, item in stats.items() if not item["row_count"]]
        operation_log.emit(
            "autoruns_drilldown_validated" if not missing else "autoruns_drilldown_failed",
            level="error" if missing else "info", stage="autoruns_drilldown",
            error_code="autoruns_missing_identity" if missing else "none",
            query_sha256=sha256_value({"vql": query, "env": env}),
            purpose="autoruns-suspicious-drilldown",
            batch=batch_number,
            selected_identities=len(stats), matched_identities=len(stats) - len(missing),
            missing_identities=len(missing), rows=sum(item["row_count"] for item in stats.values()),
        )
        for identity in missing[:10]:
            operation_log.emit(
                "autoruns_missing_identity", level="debug", stage="autoruns_drilldown",
                identity_reference=sha256_value(identity),
                omitted_identities=max(0, len(missing) - 10),
            )
        if missing:
            raise RuntimeError(
                "Suspicious Autoruns drill-down omitted selected identities "
                f"({len(missing)} missing)."
            )
        query_hash = append_query_ledger(
            state,
            artifact=artifact,
            purpose="autoruns-suspicious-drilldown-stream",
            vql=query,
            env=env,
            row_count=sum(int(item["row_count"]) for item in stats.values()),
        )
        query_count += 1
        for identity in sorted(stats):
            item = stats[identity]
            reasons = set(item["exclusion_reasons"])
            if len(reasons) == 1 and "" not in reasons:
                contextual_exclusions.append(
                    {
                        "identity_sha256": sha256_value(identity),
                        "reason": next(iter(reasons)),
                        "row_count": int(item["row_count"]),
                    }
                )
                continue
            suspicious = selected_by_identity[identity]
            accepted.append(suspicious)
            global_hosts.update(item["hosts"])
            if len(all_items) >= REPORT_MAX_FINDINGS:
                continue
            endpoints = [
                {
                    "fqdn": fqdn,
                    "client_id": client_id,
                    "row_count": int(item["hosts"][(fqdn, client_id)]),
                }
                for fqdn, client_id in sorted(item["hosts"])[
                    :REPORT_MAX_ENDPOINTS_PER_GROUP
                ]
            ]
            persistence = [
                {
                    "category": category,
                    "entry_location": entry_location,
                    "entry": entry,
                }
                for category, entry_location, entry in sorted(item["persistence"])[
                    :REPORT_MAX_CONTEXT_GROUPS
                ]
            ]
            all_items.append(
                {
                    "identity_sha256": sha256_value(identity),
                    "ImagePath": suspicious["ImagePath"],
                    "LaunchString": suspicious["LaunchString"],
                    "Signer": suspicious["Signer"],
                    "Severity": suspicious["Severity"],
                    "Reason": suspicious["Reason"],
                    "row_count": int(item["row_count"]),
                    "host_count": len(item["hosts"]),
                    "categories": sorted(item["categories"]),
                    "endpoints": endpoints,
                    "omitted_endpoint_count": max(
                        len(item["hosts"]) - len(endpoints), 0
                    ),
                    "persistence": persistence,
                    "omitted_persistence_count": max(
                        len(item["persistence"]) - len(persistence), 0
                    ),
                    "source": {
                        "hunt_id": hunt_id,
                        "artifact": artifact,
                        "query_sha256": query_hash,
                    },
                }
            )
    return {
        "persisted": False,
        "authoritative_source": "Velociraptor live query",
        "identity_count": len(accepted),
        "row_count": context_row_count
        - sum(int(item["row_count"]) for item in contextual_exclusions),
        "host_count": len(global_hosts),
        "items": all_items,
        "context_group_count": len(accepted),
        "omitted_identity_summary_count": max(
            len(accepted) - len(all_items),
            0,
        ),
        "query_count": query_count,
        "contextual_exclusion_count": len(contextual_exclusions),
        "contextual_exclusions": contextual_exclusions[:REPORT_MAX_FINDINGS],
    }, accepted


def sync_autoruns_finding(
    state: dict[str, Any],
    *,
    artifact: str,
    use_case: str,
    context: dict[str, Any],
) -> None:
    """Replace the deterministic aggregate finding for one Autoruns mode."""

    mode = str(use_case or "general-golden-residual")
    finding_id = "autoruns:" + sha256_value(
        {"artifact": artifact, "mode": mode}
    )[:16]
    state["findings"] = [
        item
        for item in state.get("findings") or []
        if (
            not isinstance(item, dict)
            or str(item.get("finding_id") or "") != finding_id
        )
    ]
    identity_count = int(context.get("identity_count") or 0)
    if identity_count <= 0:
        return
    row_count = int(context.get("row_count") or 0)
    host_count = int(context.get("host_count") or 0)
    representative_items = [
        item
        for item in context.get("items") or []
        if isinstance(item, dict)
    ]
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "review": 0,
    }
    severity = max(
        (
            str(item.get("Severity") or "review").casefold()
            for item in representative_items
        ),
        key=lambda value: severity_order.get(value, 0),
        default="review",
    )
    omitted = int(context.get("omitted_identity_summary_count") or 0)
    omitted_text = (
        f" {omitted} additional identity summary(s) are omitted from bounded "
        "report context."
        if omitted
        else ""
    )
    state["findings"].append(
        {
            "finding_id": finding_id,
            "finding_source": "autoruns-streaming",
            "artifact": artifact,
            "use_case": str(use_case or ""),
            "severity": severity,
            "disposition": "suspicious",
            "title": "Suspicious Autoruns persistence",
            "summary": (
                f"{identity_count} suspicious Autoruns identity/identities "
                f"represent {row_count} exact row(s) across {host_count} host(s)."
                f"{omitted_text}"
            ),
            "row_count": row_count,
            "host_count": host_count,
            "context_group_count": int(
                context.get("context_group_count") or identity_count
            ),
            "provisional": True,
        }
    )


def analyze_autoruns_streaming_workflow(
    api: Any,
    *,
    paths: dict[str, Path],
    hunt_id: str,
    artifact: str,
    use_case: str,
    profile: dict[str, Any],
    artifact_state: dict[str, Any],
    state: dict[str, Any],
    analysis_scope_where: str,
    analysis_scope_env: dict[str, str],
    scope_rows: int,
    rmm_classifier: autoruns_golden.RmmClassifier,
    golden_configuration: dict[str, Any],
    ai_review_enabled: bool,
    max_review_tokens: int,
    token_encoding: str,
    analyst_execution: ResolvedAgentExecution | None = None,
    source: review_source.ReviewSource | None = None,
    populated_rows: int | None = None,
    accounted_stack: AutorunsAccountedStack | None = None,
    initial_source_acquisition_seconds: float = 0.0,
) -> list[dict[str, Any]]:
    """Run live Autoruns stacking and review without sectional data files."""

    candidate_output = retained_autoruns_candidate_output(
        paths,
        artifact_state,
    )
    compact_autoruns_residual_state(artifact_state)
    populated_where = combine_where(
        analysis_scope_where,
        "(`Image Path` OR `Launch String`)",
    )
    if populated_rows is None:
        stack_count_query = count_vql(populated_where, source=source)
        stack_source_rows = exact_count(
            api,
            stack_count_query,
            analysis_scope_env,
            purpose="count-populated-autoruns-rows",
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=f"{use_case or 'autoruns-general'}-stream-source-count",
            vql=stack_count_query,
            env=analysis_scope_env,
            row_count=stack_source_rows,
        )
    else:
        stack_source_rows = populated_rows
    query_builder = autoruns_accounted_stack_vql if accounted_stack is not None else autoruns_residual_stack_vql
    query = query_builder(
        analysis_scope_where,
        source=source,
    )
    query_hash = sha256_value({"vql": query, "env": analysis_scope_env})
    workflow = {
        "version": AUTORUNS_STREAMING_WORKFLOW_VERSION,
        "mode": use_case or "general-golden-residual",
        "stage": "awaiting_ai_classification",
        "stack": {
            "query_hash": query_hash,
            "represented_rows": 0,
            "group_count": 0,
            "blank_path_rows_dropped": max(0, scope_rows - stack_source_rows),
            "persisted": False,
        },
        "classification": {},
        "suspicious_context": {},
    }
    if use_case:
        retained_general_candidate = candidate_output.get(
            "retained_previous"
        )
        candidate_output = {
            "status": "not_applicable",
            "action": "not_applicable",
            "current_run": False,
            "reason": "focused_autoruns_review",
        }
        if retained_general_candidate:
            candidate_output["retained_general_candidate"] = (
                retained_general_candidate
            )
    workflow["candidate_output"] = candidate_output
    if use_case:
        artifact_state.setdefault("autoruns_focused_workflows", {})[
            use_case
        ] = workflow
    else:
        artifact_state["autoruns_residual_workflow"] = workflow
    artifact_state["mode"] = f"{use_case or 'autoruns-general'}-streaming"
    artifact_state["remaining_total"] = scope_rows
    artifact_state["status"] = "awaiting_ai_classification"
    if not ai_review_enabled:
        if accounted_stack is not None:
            for _ in accounted_stack:
                pass
        if not use_case:
            candidate_output["status"] = "not_produced"
            candidate_output["reason"] = "ai_review_disabled"
        return []

    def scripted_exclusion_reason(row: dict[str, str]) -> str:
        if use_case:
            return ""
        reasons = rmm_classifier.reasons(
            image_path=row.get("ImagePath"),
            launch_string=row.get("LaunchString"),
        )
        return (
            "deferred-to-autoruns-rmm:" + ",".join(sorted(set(reasons)))
            if reasons
            else ""
        )

    prompt_builder: Callable[..., str] | None = None
    if use_case:
        prompt_builder = lambda **kwargs: autoruns_ai_review._focused_stack_prompt(
            **kwargs,
            use_case=use_case,
        )
    operation_log.emit("autoruns_review_started", stage="autoruns_ai_review",
                       rows=stack_source_rows)
    try:
        ai_result = autoruns_ai_review.classify_streaming_rows(
            accounted_stack if accounted_stack is not None else iter_autoruns_stack_rows(
                api,
                query=query,
                query_environment=analysis_scope_env,
            ),
            workdir=paths["root"],
            maximum_evidence_tokens=max_review_tokens,
            token_encoding=token_encoding,
            exclusion_reason=scripted_exclusion_reason,
            review_mode=use_case or "general-residual",
            prompt_builder=prompt_builder,
            execution=analyst_execution,
            initial_source_acquisition_seconds=initial_source_acquisition_seconds,
        )
    except Exception as exc:
        operation_log.emit("autoruns_review_failed", level="error",
                           stage="autoruns_ai_review", error_code="autoruns_classification_failed",
                           error_class=type(exc).__name__)
        workflow["stage"] = "ai_classification_failed"
        if not use_case:
            candidate_output["status"] = "failed"
            candidate_output["reason"] = "ai_classification_failed"
        workflow["ai_review"] = {
            "model": analyst_execution.model,
            "error": str(exc),
            "runtime_files_persisted": False,
        }
        artifact_state["status"] = "ai_classification_failed"
        return []
    manifest = dict(ai_result["manifest"])
    represented_rows = int(manifest["represented_row_count"])
    if accounted_stack is not None and (
        not accounted_stack.complete
        or represented_rows != stack_source_rows
        or int(manifest["reviewed_group_count"]) != accounted_stack.counts["GroupCount"]
    ):
        raise RuntimeError("Autoruns streaming stack accounting mismatch or incomplete review.")
    workflow["stack"]["expected_rows"] = stack_source_rows
    workflow["stack"]["additional_rows"] = max(0, represented_rows - stack_source_rows)
    if represented_rows > stack_source_rows:
        warning = (
            f"Autoruns stack represents {represented_rows} row(s), "
            f"{represented_rows - stack_source_rows} above the initial count "
            f"of {stack_source_rows}. Continuing with all reviewed rows; "
            "live hunt results may have grown between queries."
        )
        workflow["stack"]["warnings"] = [warning]
        operation_log.emit(
            "autoruns_accounting_growth", level="warning",
            stage="autoruns_stack_validation",
            error_code="autoruns_stack_count_increased",
            rows=represented_rows, total=stack_source_rows, error_detail=warning,
        )
    if represented_rows < stack_source_rows:
        operation_log.emit("autoruns_accounting_failed", level="error",
                           stage="autoruns_stack_validation", error_code="autoruns_stack_count_mismatch",
                           rows=int(manifest["represented_row_count"]), total=stack_source_rows)
        raise RuntimeError(
            "Autoruns streaming stack accounting mismatch: represented "
            f"{manifest['represented_row_count']} row(s), expected "
            f"{stack_source_rows}."
        )
    suspicious_rows = list(ai_result["suspicious_rows"])
    potential_rows = list(ai_result["potential_golden_rows"])
    if use_case and potential_rows:
        raise RuntimeError(
            "Focused Autoruns review returned potential-GoldenDB rows."
        )
    overlap = {
        autoruns_residual_identity(row) for row in suspicious_rows
    }.intersection(
        autoruns_residual_identity(row) for row in potential_rows
    )
    if overlap:
        raise RuntimeError(
            "Autoruns AI classification placed one identity in both outputs."
        )
    for row in potential_rows:
        reasons = list(
            rmm_classifier.reasons(
                image_path=row.get("ImagePath"),
                launch_string=row.get("LaunchString"),
            )
        )
        if autoruns_golden.is_missing_file(
            image_path=row.get("ImagePath"),
            launch_string=row.get("LaunchString"),
        ):
            reasons.append("missing-file")
        if reasons:
            raise RuntimeError(
                "Autoruns potential-GoldenDB classification contains a "
                "non-promotable identity."
            )
    operation_log.emit("autoruns_review_completed", stage="autoruns_ai_review",
                       group_count=int(manifest["reviewed_group_count"]),
                       selected_identities=len(suspicious_rows),
                       duration_ms=float(manifest.get("duration_seconds") or 0) * 1000)
    context, suspicious_rows = review_autoruns_suspicious_context_streaming(
        api,
        hunt_id=hunt_id,
        artifact=artifact,
        profile=profile,
        suspicious_rows=suspicious_rows,
        state=state,
        source=source,
    )
    operation_log.emit("autoruns_publication_started", stage="autoruns_publication")
    potential_reference: dict[str, Any] = {}
    if not use_case:
        metadata = {
            "SchemaVersion": AUTORUNS_STREAMING_WORKFLOW_VERSION,
            "CanonicalizationVersion": autoruns.CANONICALIZATION_VERSION,
            "EngagementId": str(state.get("investigation_id") or ""),
            "HuntId": hunt_id,
            "Artifact": artifact,
            "SourceStackSHA256": manifest["source_stack_sha256"],
            "SourceQuerySHA256": query_hash,
            "GoldenDBSHA256": str(
                golden_configuration.get("database_sha256") or ""
            ),
            "GoldenDBVersion": str(
                golden_configuration.get("version") or ""
            ),
            "SourceGroupCount": manifest["reviewed_group_count"],
            "ReviewedGroupCount": manifest["reviewed_group_count"],
            "ReviewComplete": "true",
        }
        potential_path = paths["autoruns_potential_golden"]
        write_text_atomic(
            potential_path,
            render_csv_with_metadata(
                metadata=metadata,
                fieldnames=AUTORUNS_POTENTIAL_GOLDEN_FIELDS,
                rows=potential_rows,
            ),
        )
        potential_reference = {
            "path": f"analysis/{potential_path.name}",
            "sha256": sha256_file(potential_path),
            "row_count": len(potential_rows),
            "reviewed_group_count": int(manifest["reviewed_group_count"]),
            "published_at": now_utc(),
            "source_stack_sha256": manifest["source_stack_sha256"],
            "source_query_sha256": query_hash,
            "golden_db_sha256": str(
                golden_configuration.get("database_sha256") or ""
            ),
            "golden_db_version": str(
                golden_configuration.get("version") or ""
            ),
        }
        workflow["candidate_output"] = {
            "status": "complete",
            "action": (
                "published" if potential_rows else "published_empty"
            ),
            "current_run": True,
            "reason": "complete_streamed_review",
            "reference": copy.deepcopy(potential_reference),
        }
    append_query_ledger(
        state,
        artifact=artifact,
        purpose=f"{use_case or 'autoruns-general'}-stream-stack",
        vql=query,
        env=analysis_scope_env,
        row_count=int(manifest["reviewed_group_count"]),
    )
    workflow["stack"].update(
        {
            "sha256": manifest["source_stack_sha256"],
            "group_count": int(manifest["reviewed_group_count"]),
            "represented_rows": int(manifest["represented_row_count"]),
        }
    )
    workflow["classification"] = {
        "suspicious_count": len(suspicious_rows),
        "potential_golden_count": len(potential_rows),
        "reviewed_group_count": int(manifest["reviewed_group_count"]),
        "review_complete": True,
        "potential_golden": potential_reference,
    }
    workflow["ai_review"] = manifest
    workflow["suspicious_context"] = context
    workflow["stage"] = "complete"
    sync_autoruns_finding(
        state,
        artifact=artifact,
        use_case=use_case,
        context=context,
    )
    artifact_state["remaining_total"] = 0
    artifact_state["completed_at_total"] = scope_rows
    artifact_state["status"] = "complete"
    operation_log.emit("autoruns_validation_completed", stage="autoruns_validation",
                       group_count=int(manifest["reviewed_group_count"]))
    return []


def analyze_generic_streaming_stack_workflow(
    api: Any,
    *,
    paths: dict[str, Path],
    hunt_id: str,
    artifact: str,
    question: str,
    profile: dict[str, Any],
    projection: list[str],
    artifact_state: dict[str, Any],
    state: dict[str, Any],
    base_where: str,
    remaining_env: dict[str, str],
    remaining: int,
    reviewed_signatures: list[dict[str, Any]],
    max_flagged_groups: int,
    max_followup_rows: int,
    host_denominator: int,
    max_review_tokens: int,
    discovery_rows: int,
    stack_field_preferences: list[str],
    stack_field_guidance: str,
    token_encoding: str,
    analyst_execution: ResolvedAgentExecution | None = None,
    source: review_source.ReviewSource | None = None,
    stack_max_total_rows: int | None = None,
) -> list[dict[str, Any]] | None:
    """Stream a curated or ephemeral complete aggregate through analyst slots."""
    selected_scope = stack_for_role(profile, "scope")
    selected_signature = (
        stack_for_role(profile, "family_signature")
        or stack_for_role(profile, "signature")
    )
    dynamic = selected_signature is None
    discovery_metadata: dict[str, Any] = {}
    if dynamic:
        discovery_query = discovery_sample_vql(
            base_where,
            discovery_rows,
            source=source,
        )
        discovery_env = dict(remaining_env)
        sample = api.query(
            discovery_query,
            discovery_env,
            max_wait=30,
            max_row=discovery_rows,
        )
        sample = [dict(row) for row in sample if isinstance(row, dict)]
        append_query_ledger(
            state,
            artifact=artifact,
            purpose="dynamic-stack-discovery",
            vql=discovery_query,
            env=discovery_env,
            row_count=len(sample),
        )
        discovery_metadata = {
            "sample_row_count": len(sample),
            "sample_query_hash": sha256_value(
                {"vql": discovery_query, "env": discovery_env}
            ),
            "observed_statistics_hash": "",
            "selected_model": (
                analyst_execution.model if analyst_execution is not None else ""
            ),
            "recommendation_hash": "",
            "validated_scope_field": "",
            "validated_signature_fields": [],
            "rejected_recommendations": [],
            "requested_field_preferences": list(stack_field_preferences),
            "field_guidance_hash": (
                sha256_value(stack_field_guidance)
                if stack_field_guidance
                else ""
            ),
            "operator_question": "",
            "generated_aggregate_query_hash": "",
            "represented_rows": 0,
            "represented_groups": 0,
            "rare_first_ordering": True,
            "fallback_reason": "",
            "runtime_profile_ephemeral": True,
        }
        if not sample:
            discovery_metadata["fallback_reason"] = "discovery_sample_empty"
            artifact_state["stack_discovery"] = discovery_metadata
            return None
        recommendation = generic_stack_review.recommend_runtime_stack_fields(
            sample,
            artifact=artifact,
            question=question,
            workdir=paths["root"],
            preferred_fields=stack_field_preferences,
            field_guidance=stack_field_guidance,
            execution=analyst_execution,
        )
        discovery_metadata.update(
            {
                "observed_statistics_hash": str(
                    recommendation["statistics_sha256"]
                ),
                "selected_model": str(recommendation["selected_model"]),
                "recommendation_hash": str(
                    recommendation["recommendation_sha256"]
                ),
                "validated_scope_field": str(
                    recommendation["scope_field"]
                ),
                "validated_signature_fields": list(
                    recommendation["signature_fields"]
                ),
                "rejected_recommendations": list(
                    recommendation["rejected_recommendations"]
                ),
                "operator_question": str(
                    recommendation.get("operator_question") or ""
                ),
                "fallback_reason": str(recommendation["fallback_reason"]),
            }
        )
        artifact_state["stack_discovery"] = discovery_metadata
        if discovery_metadata["fallback_reason"]:
            if stack_field_preferences or stack_field_guidance:
                artifact_state["mode"] = "stack-field-clarification"
                artifact_state["remaining_total"] = remaining
                artifact_state["status"] = "awaiting_stack_field_input"
                artifact_state["pending_reviews"] = []
                return []
            return None
        scope_aliases = (
            [str(recommendation["scope_field"])]
            if recommendation["scope_field"]
            else []
        )
        scope_dimensions = [
            quote_vql_field_identifier(field) for field in scope_aliases
        ]
        logical_dimensions = list(recommendation["signature_fields"])
        signature_dimensions = [
            quote_vql_field_identifier(field) for field in logical_dimensions
        ]
        runtime_hash = sha256_value(
            {"scope": scope_aliases, "signatures": logical_dimensions}
        )[:12]
        scope_id = "runtime-discovered-scope" if scope_aliases else "global"
        signature_id = f"runtime-discovered-{runtime_hash}"
        signature_stack = {
            "purpose": "Ephemeral runtime stack selected from transient rows.",
            "analysis_role": "signature",
        }
    else:
        signature_id, signature_stack = selected_signature
        signature_dimensions = list(
            signature_stack.get("server_dimensions") or []
        )
        if not signature_dimensions:
            return None
        logical_dimensions = list(signature_stack.get("dimensions") or [])
        if len(logical_dimensions) != len(signature_dimensions):
            logical_dimensions = [
                f"Group{index}"
                for index in range(1, len(signature_dimensions) + 1)
            ]
        if selected_scope is None:
            scope_id = "global"
            scope_dimensions = []
            scope_aliases = []
        else:
            scope_id, scope_stack = selected_scope
            scope_dimensions = list(scope_stack.get("server_dimensions") or [])
            scope_aliases = list(scope_stack.get("server_scope_aliases") or [])
            if not scope_dimensions or len(scope_dimensions) != len(scope_aliases):
                return None

    accounted_ids = {
        str(item.get("id") or "")
        for item in reviewed_signatures
        if str(item.get("stack_id") or "") == signature_id
    }
    stream_stats = {
        "scope_group_count": 0,
        "aggregate_query_count": 0,
        "skipped_reviewed_group_count": 0,
        "skipped_reviewed_row_count": 0,
    }

    def scoped_groups() -> Iterator[dict[str, Any]]:
        scope_query = streaming_stack_vql(
            scope_dimensions,
            base_where,
            source=source,
        )
        scope_env = dict(remaining_env)
        for scope_row in iter_query_rows(
            api,
            vql=scope_query,
            env=scope_env,
            purpose="build-scope-groups",
        ):
            scope = {
                scope_aliases[index - 1]: str(
                    scope_row.get(f"Pivot{index}") or ""
                )
                for index in range(1, len(scope_dimensions) + 1)
            }
            if not all(scope.values()):
                continue
            scope_count = int(scope_row.get("Count") or 0)
            if scope_count <= 0:
                continue
            stream_stats["scope_group_count"] += 1
            branch_env = dict(remaining_env)
            branch_where = query_with_scope(
                base_where=base_where,
                scope=scope,
                profile=profile,
                env=branch_env,
            )
            group_query = streaming_stack_vql(
                signature_dimensions,
                branch_where,
                source=source,
            )
            group_count = 0
            represented_rows = 0
            for group_row in iter_query_rows(
                api,
                vql=group_query,
                env=branch_env,
                purpose="build-signature-groups",
            ):
                values = [
                    str(group_row.get(f"Pivot{index}") or "")
                    for index in range(1, len(signature_dimensions) + 1)
                ]
                count = int(group_row.get("Count") or 0)
                host_count = int(group_row.get("HostCount") or 0)
                if count <= 0:
                    continue
                group_count += 1
                represented_rows += count
                accounting_id = accounting_id_for(
                    artifact=artifact,
                    scope=scope,
                    stack_id=signature_id,
                    values=values,
                )
                if accounting_id in accounted_ids:
                    stream_stats["skipped_reviewed_group_count"] += 1
                    stream_stats["skipped_reviewed_row_count"] += count
                    continue
                group_env = dict(branch_env)
                group_match = dimension_match_expression(
                    signature_dimensions,
                    values,
                    env=group_env,
                    prefix="StreamingStack",
                )
                group_where = combine_where(branch_where, group_match)
                yield {
                    "artifact": artifact,
                    "scope": scope,
                    "scope_count": scope_count,
                    "stack_id": signature_id,
                    "stack_purpose": str(
                        signature_stack.get("purpose") or ""
                    ),
                    "logical_dimensions": logical_dimensions,
                    "server_dimensions": signature_dimensions,
                    "scope_aliases": scope_aliases,
                    "scope_server_dimensions": scope_dimensions,
                    "values": values,
                    "count": count,
                    "host_count": host_count,
                    "host_denominator": host_denominator,
                    "host_prevalence_percent": (
                        round(host_count / host_denominator * 100, 2)
                        if host_denominator
                        else 0.0
                    ),
                    "accounting_id": accounting_id,
                    "query": select_vql(
                        projection,
                        group_where,
                        count,
                        source=source,
                    ),
                    "host_query": impacted_hosts_vql(
                        group_where,
                        source=source,
                    ),
                    "env": group_env,
                }
            stream_stats["aggregate_query_count"] += 1
            append_query_ledger(
                state,
                artifact=artifact,
                purpose=(
                    f"streaming-stack:{signature_id}:"
                    f"{sha256_value(scope)[:8]}"
                ),
                vql=group_query,
                env=branch_env,
                row_count=group_count,
            )
            if represented_rows != scope_count:
                raise RuntimeError(
                    "Generic streaming stack scope accounting mismatch for "
                    f"{scope}: {represented_rows} represented != "
                    f"{scope_count} authoritative row(s)."
                )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=f"streaming-scope:{scope_id}",
            vql=scope_query,
            env=scope_env,
            row_count=int(stream_stats["scope_group_count"]),
        )

    aggregate_dimensions = [*scope_dimensions, *signature_dimensions]
    aggregate_query = streaming_stack_vql(
        aggregate_dimensions,
        base_where,
        source=source,
    )
    aggregate_env = dict(remaining_env)
    if dynamic:
        discovery_metadata["generated_aggregate_query_hash"] = sha256_value(
            {"vql": aggregate_query, "env": aggregate_env}
        )

    def aggregate_groups() -> Iterator[dict[str, Any]]:
        represented_rows = 0
        group_count = 0
        observed_scopes: set[str] = set()
        for group_row in iter_query_rows(
            api,
            vql=aggregate_query,
            env=aggregate_env,
            purpose="build-aggregate-stack",
        ):
            all_values = [
                str(group_row.get(f"Pivot{index}") or "")
                for index in range(1, len(aggregate_dimensions) + 1)
            ]
            count = int(group_row.get("Count") or 0)
            host_count = int(group_row.get("HostCount") or 0)
            if count <= 0:
                continue
            scope_values = all_values[: len(scope_dimensions)]
            values = all_values[len(scope_dimensions) :]
            scope = {
                scope_aliases[index]: value
                for index, value in enumerate(scope_values)
            }
            observed_scopes.add(stable_json(scope))
            group_count += 1
            represented_rows += count
            accounting_id = accounting_id_for(
                artifact=artifact,
                scope=scope,
                stack_id=signature_id,
                values=values,
            )
            if accounting_id in accounted_ids:
                stream_stats["skipped_reviewed_group_count"] += 1
                stream_stats["skipped_reviewed_row_count"] += count
                continue
            group_env = dict(remaining_env)
            group_match = dimension_match_expression(
                aggregate_dimensions,
                all_values,
                env=group_env,
                prefix="DynamicStreamingStack",
            )
            group_where = combine_where(base_where, group_match)
            yield {
                "artifact": artifact,
                "scope": scope,
                "scope_count": remaining,
                "stack_id": signature_id,
                "stack_purpose": str(signature_stack.get("purpose") or ""),
                "logical_dimensions": logical_dimensions,
                "server_dimensions": signature_dimensions,
                "scope_aliases": scope_aliases,
                "scope_server_dimensions": scope_dimensions,
                "values": values,
                "count": count,
                "host_count": host_count,
                "host_denominator": host_denominator,
                "host_prevalence_percent": (
                    round(host_count / host_denominator * 100, 2)
                    if host_denominator
                    else 0.0
                ),
                "accounting_id": accounting_id,
                "query": select_vql(
                    projection,
                    group_where,
                    count,
                    source=source,
                ),
                "host_query": impacted_hosts_vql(
                    group_where,
                    source=source,
                ),
                "env": group_env,
            }
        stream_stats["scope_group_count"] = max(1, len(observed_scopes))
        stream_stats["aggregate_query_count"] = 1
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=f"streaming-stack:{signature_id}",
            vql=aggregate_query,
            env=aggregate_env,
            row_count=group_count,
        )
        if represented_rows != remaining:
            raise RuntimeError(
                "Generic streaming stack accounting mismatch: represented "
                f"{represented_rows} row(s), expected {remaining}."
            )

    result = generic_stack_review.review_streaming_groups(
        (
            scoped_groups()
            if selected_scope is not None and not dynamic
            else aggregate_groups()
        ),
        workdir=paths["root"],
        question=question,
        maximum_evidence_tokens=max_review_tokens,
        token_encoding=token_encoding,
        max_flagged_groups=max_flagged_groups,
        execution=analyst_execution,
        max_total_rows=stack_max_total_rows,
    )
    enriched_groups: list[dict[str, Any]] = []
    followup_rows_remaining = max(0, int(max_followup_rows))
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    flagged_groups = sorted(
        result["flagged_groups"],
        key=lambda item: (
            severity_order.get(
                str(item.get("severity") or "").casefold(),
                5,
            ),
            0
            if str(item.get("disposition") or "").casefold() == "suspicious"
            else 1,
            int(item.get("count") or 0),
            str(item.get("accounting_id") or ""),
        ),
    )
    for flagged in flagged_groups:
        expected_count = int(flagged.get("count") or 0)
        host_rows = list(
            iter_query_rows(
                api,
                vql=str(flagged["host_query"]),
                env=dict(flagged["env"]),
                purpose="find-impacted-hosts",
            )
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=(
                "streaming-stack-impacted-hosts:"
                f"{flagged.get('accounting_id') or ''}"
            ),
            vql=str(flagged["host_query"]),
            env=dict(flagged["env"]),
            row_count=len(host_rows),
        )
        impacted_machines = [
            {
                "fqdn": str(row.get("Fqdn") or ""),
                "client_id": str(row.get("ClientId") or ""),
                "row_count": int(row.get("RowCount") or 0),
            }
            for row in host_rows
            if row.get("Fqdn") or row.get("ClientId")
        ]
        observed_host_count = len(
            {
                (
                    str(item.get("client_id") or ""),
                    str(item.get("fqdn") or ""),
                )
                for item in impacted_machines
            }
        )
        if observed_host_count:
            flagged["host_count"] = observed_host_count
            flagged["host_prevalence_percent"] = (
                round(observed_host_count / host_denominator * 100, 2)
                if host_denominator
                else 0.0
            )
        requested_rows = min(expected_count, followup_rows_remaining)
        source_rows: list[dict[str, Any]] = []
        rows_exhaustive = False
        query_meta = empty_query_meta(token_encoding)
        if requested_rows == expected_count and expected_count > 0:
            source_rows, query_meta = query_rows_exhaustive_transient(
                api,
                vql=str(flagged["query"]),
                env=dict(flagged["env"]),
                expected_count=expected_count,
                maximum_rows=followup_rows_remaining,
                token_encoding=token_encoding,
            )
            rows_exhaustive = True
        elif requested_rows > 0:
            source_rows, query_meta = query_rows_bounded(
                api,
                vql=str(flagged["query"]),
                env=dict(flagged["env"]),
                row_limit=requested_rows,
                token_limit=max_review_tokens,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
        followup_rows_remaining -= len(source_rows)
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=(
                "streaming-stack-original-rows:"
                f"{flagged.get('accounting_id') or ''}"
            ),
            vql=str(flagged["query"]),
            env=dict(flagged["env"]),
            row_count=len(source_rows),
        )
        enriched_groups.append(
            {
                **flagged,
                "group_id": str(flagged.get("accounting_id") or ""),
                "impacted_machines": impacted_machines,
                "source_rows": source_rows,
                "rows_exhaustive": rows_exhaustive,
                "followup_query_meta": query_meta,
            }
        )
    followup_result = generic_stack_review.review_enriched_groups(
        enriched_groups,
        workdir=paths["root"],
        question=question,
        maximum_evidence_tokens=max_review_tokens,
        token_encoding=token_encoding,
        execution=analyst_execution,
    )
    result["flagged_groups"] = followup_result["assessments"]
    manifest = dict(result["manifest"])
    manifest["aggregate_suspicious_group_count"] = int(
        manifest.get("suspicious_group_count") or 0
    )
    manifest["aggregate_notable_group_count"] = int(
        manifest.get("notable_group_count") or 0
    )
    manifest["suspicious_group_count"] = sum(
        str(item.get("disposition") or "").casefold() == "suspicious"
        for item in followup_result["assessments"]
    )
    manifest["notable_group_count"] = sum(
        str(item.get("disposition") or "").casefold() == "notable"
        for item in followup_result["assessments"]
    )
    manifest.update(stream_stats)
    manifest.update(
        {
            "workflow_version": GENERIC_STACK_STREAMING_WORKFLOW_VERSION,
            "scope_stack_id": scope_id,
            "signature_stack_id": signature_id,
            "signature_logical_dimensions": logical_dimensions,
            "signature_server_dimensions": signature_dimensions,
            "expected_row_count": remaining,
            "rare_first_ordering": True,
            "runtime_profile_ephemeral": dynamic,
            "host_denominator": host_denominator,
            "followup": dict(followup_result["manifest"]),
            "followup_source_row_count": sum(
                len(item.get("source_rows") or [])
                for item in followup_result["assessments"]
            ),
            "followup_exhaustive_group_count": sum(
                bool(item.get("rows_exhaustive"))
                for item in followup_result["assessments"]
            ),
        }
    )
    if int(manifest["represented_row_count"]) != remaining:
        raise RuntimeError(
            "Generic streaming stack accounting mismatch: represented "
            f"{manifest['represented_row_count']} row(s), expected {remaining}."
        )
    if dynamic:
        discovery_metadata.update(
            {
                "represented_rows": int(manifest["represented_row_count"]),
                "represented_groups": int(manifest["reviewed_group_count"]) + int(manifest["excluded_group_count"]),
            }
        )
        artifact_state["stack_discovery"] = discovery_metadata
    else:
        artifact_state.pop("stack_discovery", None)

    items: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for flagged in result["flagged_groups"]:
        values = [str(value) for value in flagged.get("values") or []]
        aggregate_row = {
            logical_dimensions[index]: value
            for index, value in enumerate(values)
        }
        aggregate_row.update(
            {
                "Count": int(flagged.get("count") or 0),
                "HostCount": int(flagged.get("host_count") or 0),
                "HostDenominator": int(
                    flagged.get("host_denominator") or 0
                ),
                "HostPrevalencePercent": float(
                    flagged.get("host_prevalence_percent") or 0
                ),
                "AnalystDisposition": str(flagged["disposition"]),
                "AnalystSeverity": str(flagged["severity"]),
                "AnalystSummary": str(flagged["summary"]),
                "AnalystReason": str(flagged["reason"]),
            }
        )
        query_meta = {
            **empty_query_meta(token_encoding),
            "row_count": 1,
            "estimated_tokens": token_budget.estimate_tokens(
                stable_json(aggregate_row),
                token_encoding,
            ),
        }
        review_match = {
            "type": "streaming_stack_group",
            "scope": dict(flagged.get("scope") or {}),
            "stack_id": signature_id,
            "logical_dimensions": logical_dimensions,
            "server_dimensions": signature_dimensions,
            "scope_aliases": list(flagged.get("scope_aliases") or []),
            "scope_server_dimensions": list(
                flagged.get("scope_server_dimensions") or []
            ),
            "values": values,
            "row_count": int(flagged.get("count") or 0),
            "host_count": int(flagged.get("host_count") or 0),
            "host_denominator": int(
                flagged.get("host_denominator") or 0
            ),
            "host_prevalence_percent": float(
                flagged.get("host_prevalence_percent") or 0
            ),
            "impacted_machines": list(
                flagged.get("impacted_machines") or []
            ),
            "rows_reviewed": len(flagged.get("source_rows") or []),
            "rows_exhaustive": bool(flagged.get("rows_exhaustive")),
        }
        public, stored = review_item(
            hunt_id=hunt_id,
            artifact=artifact,
            kind="normalized_stack",
            scope=dict(flagged.get("scope") or {}),
            scope_count=int(flagged.get("count") or 0),
            exhaustive=bool(flagged.get("rows_exhaustive")),
            vql=str(flagged["query"]),
            env=dict(flagged["env"]),
            rows=[aggregate_row],
            query_meta=query_meta,
            review_match=review_match,
        )
        public["reduction"] = {
            "classification": "streamed",
            "signature_stack": signature_id,
            "signature_values": values,
            "signature_row_count": int(flagged.get("count") or 0),
            "representative_rows": 0,
            "accounting_basis": "streaming_stack_requires_drilldown",
            "closure_eligible": False,
        }
        public["ai_review"] = {
            "disposition": str(flagged["disposition"]),
            "severity": str(flagged["severity"]),
            "summary": str(flagged["summary"]),
            "reason": str(flagged["reason"]),
        }
        public["impact"] = {
            key: review_match[key]
            for key in (
                "host_count",
                "host_denominator",
                "host_prevalence_percent",
                "impacted_machines",
                "rows_reviewed",
                "rows_exhaustive",
            )
        }
        public["priority_reason"] = (
            "The follow-up analyst reviewed impacted hosts and "
            f"{len(flagged.get('source_rows') or [])} original row(s), marking "
            f"this group {flagged['disposition']}."
        )
        public["decision_template"]["disposition"] = str(
            flagged["disposition"]
        )
        public["decision_template"]["reason"] = str(flagged["reason"])
        stored["closure_eligible"] = bool(flagged.get("rows_exhaustive"))
        stored["streaming_ai_review"] = dict(public["ai_review"])
        stored["impact"] = copy.deepcopy(public["impact"])
        items.append(public)
        pending.append(stored)
        finding = {
                "finding_id": (
                    "generic-stack:"
                    f"{str(flagged.get('accounting_id') or '')}"
                ),
                "artifact": artifact,
                "severity": str(flagged["severity"]),
                "disposition": str(flagged["disposition"]),
                "title": str(flagged["summary"]),
                "summary": (
                    f"{flagged['summary']} "
                    f"{int(flagged.get('count') or 0)} occurrence(s) across "
                    f"{int(flagged.get('host_count') or 0)}/"
                    f"{int(flagged.get('host_denominator') or 0)} hosts "
                    f"({float(flagged.get('host_prevalence_percent') or 0):.1f}%)."
                ),
                "reason": str(flagged["reason"]),
                "row_count": int(flagged.get("count") or 0),
                "host_count": int(flagged.get("host_count") or 0),
                "host_denominator": int(
                    flagged.get("host_denominator") or 0
                ),
                "host_prevalence_percent": float(
                    flagged.get("host_prevalence_percent") or 0
                ),
                "impacted_machines": list(
                    flagged.get("impacted_machines") or []
                ),
                "rows_reviewed": len(flagged.get("source_rows") or []),
                "rows_exhaustive": bool(flagged.get("rows_exhaustive")),
                "provisional": True,
            }
        state["findings"] = [
            item
            for item in state.get("findings") or []
            if (
                not isinstance(item, dict)
                or str(item.get("finding_id") or "")
                != str(finding["finding_id"])
            )
        ]
        state["findings"].append(finding)

    artifact_state["mode"] = "generic-stack-streaming"
    artifact_state["streaming_stack"] = manifest
    artifact_state["scope_reductions"] = [
        {
            "scope": {},
            "signature_stack": signature_id,
            "signature_level": (
                "normalized"
                if str(signature_stack.get("analysis_role") or "")
                == "family_signature"
                else "exact"
            ),
            "classification": "streamed",
            "scope_row_count": remaining,
            "signature_groups_returned": int(
                manifest["reviewed_group_count"]
            ) + int(manifest["excluded_group_count"]),
            "flagged_group_count": int(manifest["flagged_group_count"]),
        }
    ]
    artifact_state["pending_reviews"] = pending
    if int(manifest.get("excluded_group_count") or 0) > 0:
        artifact_state["remaining_total"] = (
            remaining if int(manifest["omitted_flagged_group_count"]) > 0
            else int(manifest["excluded_row_count"]) + sum(
                int(item.get("scope_row_count") or 0) for item in pending)
        )
        artifact_state["status"] = "incomplete_stack_threshold"
    elif int(manifest["omitted_flagged_group_count"]) > 0:
        artifact_state["remaining_total"] = remaining
        artifact_state["status"] = "incomplete_streaming_flagged_limit"
    elif pending:
        artifact_state["remaining_total"] = sum(
            int(item.get("scope_row_count") or 0) for item in pending
        )
        artifact_state["status"] = "awaiting_review"
    else:
        artifact_state["remaining_total"] = 0
        artifact_state["completed_at_total"] = int(
            artifact_state.get("analysis_scope_total") or remaining
        )
        artifact_state["status"] = "complete"
    return items


def analyze_artifact(
    api: Any,
    *,
    paths: dict[str, Path],
    hunt_id: str,
    artifact: str,
    question: str,
    profile: dict[str, Any],
    artifact_state: dict[str, Any],
    state: dict[str, Any],
    reusable_filters: list[dict[str, Any]],
    indicators: list[str],
    use_case: str,
    autoruns_golden_configuration: dict[str, Any],
    rmm_classifier: autoruns_golden.RmmClassifier,
    direct_row_limit: int,
    sample_rows: int,
    max_branches: int,
    max_review_rows: int,
    max_stack_groups: int,
    max_review_tokens: int,
    stack_discovery_rows: int,
    stack_field_preferences: list[str],
    stack_field_guidance: str,
    token_encoding: str,
    autoruns_ai_review_enabled: bool,
    analyst_execution: ResolvedAgentExecution | None = None,
    source: review_source.ReviewSource | None = None,
    transient_exhaustive_direct: bool = False,
    max_transient_rows: int = 50_000,
    stack_max_total_rows: int | None = None,
) -> list[dict[str, Any]]:
    projection = profile_projection(profile)
    case_filters = [
        item
        for item in state.get("case_filters", [])
        if str(item.get("artifact") or "") == artifact
        and record_matches_use_case(item, use_case=use_case)
    ]
    promoted_filters = [
        item
        for item in reusable_filters
        if str(item.get("artifact") or "") == artifact
        and record_matches_use_case(item, use_case=use_case)
    ]
    all_filters = unique_dicts([*promoted_filters, *case_filters], key="id")
    known_bad = normalize_known_bad(profile, artifact=artifact, indicators=indicators)

    total_env = query_env(hunt_id, artifact, source)
    use_case_hash_env = query_env(hunt_id, artifact, source)
    selected_use_case = autoruns_use_case(
        artifact,
        use_case,
        env=use_case_hash_env,
        rmm_classifier=rmm_classifier,
    )
    golden_scope_where = (
        ""
        if selected_use_case
        else autoruns_golden_where(
            artifact,
            configuration=autoruns_golden_configuration,
            env=use_case_hash_env,
            preserve_priority=False,
        )
    )
    analysis_scope_where = combine_where(
        str((selected_use_case or {}).get("where") or ""),
        golden_scope_where,
    )
    review_strategy = source_review_strategy(source=source, profile=profile)
    if stack_max_total_rows is not None and (
        not review_strategy["stacking"] or artifact in AUTORUNS_ARTIFACTS
    ):
        raise RuntimeError(
            "--stack-max-total-rows requires generic hunt stacking; "
            "use --profile autoruns for the Autoruns workflow."
        )
    accounting = None
    accounted_stack = None
    initial_source_acquisition_seconds = 0.0
    if (artifact in AUTORUNS_ARTIFACTS and not selected_use_case
            and autoruns_golden_configuration.get("enabled") and review_strategy["stacking"]):
        total_query = autoruns_accounted_stack_vql(analysis_scope_where, source=source)
        acquisition_started = time.monotonic()
        accounted_stack = AutorunsAccountedStack(iter_query_rows(
            api, vql=total_query, env=use_case_hash_env,
            purpose="autoruns-accounted-stack", strict_rows=True,
        ))
        initial_source_acquisition_seconds = time.monotonic() - acquisition_started
        accounting = accounted_stack.counts
        total = accounting["SourceRows"]
        operation_log.emit("autoruns_accounting_completed", stage="autoruns_accounting",
                           source_rows=total, matched_rows=accounting["MatchedRows"],
                           residual_rows=accounting["ResidualRows"], populated_rows=accounting["PopulatedRows"],
                           group_count=accounting["GroupCount"],
                           duration_ms=initial_source_acquisition_seconds * 1000)
        append_query_ledger(state, artifact=artifact, purpose="autoruns-accounted-stack",
                            vql=total_query, env=use_case_hash_env, row_count=total)
    else:
        total_query = count_vql("", source=source)
        total = exact_count(api, total_query, total_env, purpose="count-source-rows")
        append_query_ledger(
            state,
            artifact=artifact,
            purpose="exact-total",
            vql=total_query,
            env=total_env,
            row_count=total,
        )
    if not artifact_state.get("baseline_total"):
        artifact_state["baseline_total"] = total
    current_input_hash = analysis_input_hash(
        profile_hash=str(artifact_state.get("profile_hash") or ""),
        filters=all_filters,
        known_bad=known_bad,
        use_case=selected_use_case,
        autoruns_golden_configuration=(
            autoruns_golden_general_metadata(
                autoruns_golden_configuration
            )
            if artifact in AUTORUNS_ARTIFACTS and not selected_use_case
            else {}
        ),
        source_review_mode=(
            str(review_strategy.get("mode") or "")
            if source is not None and source.source_type == "flow"
            else ""
        ),
        stack_field_preferences=stack_field_preferences,
        stack_field_guidance=stack_field_guidance,
        stack_max_total_rows=stack_max_total_rows,
    )
    update_analysis_watermark(
        artifact_state,
        total=total,
        input_hash=current_input_hash,
    )
    artifact_state["projection"] = projection
    artifact_state["filter_count"] = len(all_filters)
    artifact_state["known_bad_rule_count"] = len(known_bad)
    artifact_state["use_case"] = (
        {
            "id": selected_use_case["id"],
            "purpose": selected_use_case["purpose"],
            "output_name": selected_use_case["output_name"],
            **(
                {"reference": selected_use_case["reference"]}
                if selected_use_case.get("reference")
                else {}
            ),
            **(
                {"reference_hash": selected_use_case["reference_hash"]}
                if selected_use_case.get("reference_hash")
                else {}
            ),
        }
        if selected_use_case
        else {}
    )
    artifact_state["autoruns_golden"] = (
        autoruns_golden_general_metadata(
            autoruns_golden_configuration
        )
        if artifact in AUTORUNS_ARTIFACTS and not selected_use_case
        else {}
    )
    artifact_state["source_review_strategy"] = review_strategy
    analysis_total = accounting["ResidualRows"] if accounting is not None else total
    if analysis_scope_where and accounting is None:
        use_case_count_query = count_vql(
            analysis_scope_where,
            source=source,
        )
        analysis_total = exact_count(
            api,
            use_case_count_query,
            use_case_hash_env,
            purpose="count-use-case-rows" if selected_use_case else "count-golden-residual-rows",
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=(
                f"use-case-count:{selected_use_case['id']}"
                if selected_use_case
                else "autoruns-golden-residual-count"
            ),
            vql=use_case_count_query,
            env=use_case_hash_env,
            row_count=analysis_total,
        )
    artifact_state["analysis_scope_total"] = analysis_total
    if (
        artifact in AUTORUNS_ARTIFACTS
        and not selected_use_case
        and autoruns_golden_configuration.get("enabled")
    ):
        matched_rows = max(0, total - analysis_total)
        warnings: list[str] = []
        if (
            int(autoruns_golden_configuration.get("identity_count") or 0) > 0
            and matched_rows == 0
        ):
            warnings.append("non_empty_golden_db_produced_zero_matches")
        artifact_state["autoruns_golden"].update(
            {
                "strict_subtraction": True,
                "source_rows": total,
                "matched_rows": matched_rows,
                "residual_rows": analysis_total,
                "warnings": warnings,
            }
        )

    if (
        artifact in AUTORUNS_ARTIFACTS
        and not selected_use_case
        and autoruns_golden_configuration.get("enabled")
        and not review_strategy["stacking"]
    ):
        golden_residual_rows = analysis_total
        populated_where = combine_where(
            analysis_scope_where,
            "(`Image Path` OR `Launch String`)",
        )
        populated_count_query = count_vql(populated_where, source=source)
        analysis_total = exact_count(
            api,
            populated_count_query,
            use_case_hash_env,
            purpose="count-populated-autoruns-rows",
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose="autoruns-direct-context-count",
            vql=populated_count_query,
            env=use_case_hash_env,
            row_count=analysis_total,
        )
        analysis_scope_where = populated_where
        artifact_state["analysis_scope_total"] = analysis_total
        artifact_state["source_review_strategy"].update(
            {
                "golden_residual_rows": golden_residual_rows,
                "review_rows": analysis_total,
                "blank_path_rows_dropped": max(
                    0,
                    golden_residual_rows - analysis_total,
                ),
            }
        )
        artifact_state.pop("autoruns_residual_workflow", None)

    if (
        artifact in AUTORUNS_ARTIFACTS
        and selected_use_case
        and str(selected_use_case.get("id") or "")
        in AUTORUNS_AUTOMATED_USE_CASES
        and review_strategy["stacking"]
    ):
        return analyze_autoruns_streaming_workflow(
            api,
            paths=paths,
            hunt_id=hunt_id,
            artifact=artifact,
            use_case=str(selected_use_case["id"]),
            profile=profile,
            artifact_state=artifact_state,
            state=state,
            analysis_scope_where=analysis_scope_where,
            analysis_scope_env=use_case_hash_env,
            scope_rows=analysis_total,
            rmm_classifier=rmm_classifier,
            golden_configuration={},
            ai_review_enabled=autoruns_ai_review_enabled,
            max_review_tokens=max_review_tokens,
            token_encoding=token_encoding,
            analyst_execution=analyst_execution,
            source=source,
        )

    if (
        artifact in AUTORUNS_ARTIFACTS
        and not selected_use_case
        and autoruns_golden_configuration.get("enabled")
        and review_strategy["stacking"]
    ):
        return analyze_autoruns_streaming_workflow(
            api,
            paths=paths,
            hunt_id=hunt_id,
            artifact=artifact,
            use_case="",
            profile=profile,
            artifact_state=artifact_state,
            state=state,
            analysis_scope_where=analysis_scope_where,
            analysis_scope_env=use_case_hash_env,
            scope_rows=analysis_total,
            rmm_classifier=rmm_classifier,
            golden_configuration=autoruns_golden_configuration,
            ai_review_enabled=autoruns_ai_review_enabled,
            max_review_tokens=max_review_tokens,
            token_encoding=token_encoding,
            analyst_execution=analyst_execution,
            source=source,
            populated_rows=accounting["PopulatedRows"] if accounting is not None else None,
            accounted_stack=accounted_stack,
            initial_source_acquisition_seconds=initial_source_acquisition_seconds,
        )

    pending_drilldowns = [
        item
        for item in artifact_state.get("drilldown_requests", [])
        if item.get("status") == "pending"
    ]
    if pending_drilldowns:
        items: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        row_budget = max_review_rows
        token_budget_remaining = max_review_tokens

        def prepare_drilldown(
            request: dict[str, Any],
        ) -> dict[str, Any]:
            drilldown_env = query_env(hunt_id, artifact, source)
            request_scope = dict(request.get("scope") or {})
            dynamic_scope_dimensions = list(
                request.get("scope_server_dimensions") or []
            )
            dynamic_scope_aliases = list(request.get("scope_aliases") or [])
            if dynamic_scope_dimensions:
                drilldown_scope = dimension_match_expression(
                    dynamic_scope_dimensions,
                    [str(request_scope.get(alias) or "") for alias in dynamic_scope_aliases],
                    env=drilldown_env,
                    prefix="DrilldownScope",
                )
            else:
                drilldown_scope = scope_expression(
                    request_scope,
                    profile=profile,
                    env=drilldown_env,
                    prefix="Drilldown",
                )
            drilldown_signature = dimension_match_expression(
                list(request.get("server_dimensions") or []),
                [str(value) for value in request.get("values") or []],
                env=drilldown_env,
                prefix="DrilldownSignature",
            )
            drilldown_where = combine_where(
                drilldown_scope,
                drilldown_signature,
            )
            drilldown_count_query = count_vql(
                drilldown_where,
                source=source,
            )
            drilldown_count = exact_count(
                api,
                drilldown_count_query,
                drilldown_env,
            )
            return {
                "request": request,
                "env": drilldown_env,
                "where": drilldown_where,
                "count_query": drilldown_count_query,
                "count": drilldown_count,
            }

        branch_requests = pending_drilldowns[:max_branches]
        worker_count = max(
            1,
            min(DEFAULT_DRILLDOWN_WORKERS, len(branch_requests)),
        )
        if worker_count == 1:
            prepared_drilldowns = [
                prepare_drilldown(request)
                for request in branch_requests
            ]
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                prepared_drilldowns = list(
                    executor.map(prepare_drilldown, branch_requests)
                )
        selected_drilldowns: list[dict[str, Any]] = []
        allocated_rows = row_budget
        for prepared in prepared_drilldowns:
            request = prepared["request"]
            drilldown_count = int(prepared["count"])
            append_query_ledger(
                state,
                artifact=artifact,
                purpose=f"drilldown-count:{request['id']}",
                vql=str(prepared["count_query"]),
                env=dict(prepared["env"]),
                row_count=drilldown_count,
            )
            if drilldown_count <= 0:
                continue
            requested = min(drilldown_count, allocated_rows)
            if requested <= 0:
                break
            drilldown_query = select_vql(
                projection,
                str(prepared["where"]),
                requested,
                source=source,
            )
            selected_drilldowns.append(
                {
                    **prepared,
                    "requested": requested,
                    "query": drilldown_query,
                }
            )
            allocated_rows -= requested
            if requested < drilldown_count or allocated_rows <= 0:
                break

        def fetch_drilldown_rows(
            prepared: dict[str, Any],
        ) -> list[dict[str, Any]]:
            requested = int(prepared["requested"])
            rows, _ = query_rows_bounded(
                api,
                vql=str(prepared["query"]),
                env=dict(prepared["env"]),
                row_limit=requested,
                token_limit=max_review_tokens,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            return rows

        fetch_worker_count = max(
            1,
            min(DEFAULT_DRILLDOWN_WORKERS, len(selected_drilldowns)),
        )
        if fetch_worker_count == 1:
            fetched_drilldowns = [
                fetch_drilldown_rows(prepared)
                for prepared in selected_drilldowns
            ]
        else:
            with ThreadPoolExecutor(
                max_workers=fetch_worker_count,
            ) as executor:
                fetched_drilldowns = list(
                    executor.map(
                        fetch_drilldown_rows,
                        selected_drilldowns,
                    )
                )

        for prepared, raw_rows in zip(
            selected_drilldowns,
            fetched_drilldowns,
            strict=True,
        ):
            if row_budget <= 0 or token_budget_remaining <= 0:
                break
            request = prepared["request"]
            drilldown_count = int(prepared["count"])
            requested = min(int(prepared["requested"]), row_budget)
            rows, meta = bound_materialized_rows(
                raw_rows,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            if (
                len(raw_rows) <= requested
                and meta.get("outcome") == QUERY_OUTCOME_ROW_LIMIT
            ):
                meta["outcome"] = QUERY_OUTCOME_COMPLETE
                meta["truncated"] = False
            append_query_ledger(
                state,
                artifact=artifact,
                purpose=f"drilldown:{request['id']}",
                vql=str(prepared["query"]),
                env=dict(prepared["env"]),
                row_count=len(rows),
            )
            if not rows and drilldown_count > 0:
                require_rows_for_positive_count(
                    purpose=f"Drill-down {request['id']}",
                    expected_count=drilldown_count,
                    rows=rows,
                    query_meta=meta,
                )
            if rows:
                record_budget_stop(
                    artifact_state,
                    meta,
                    purpose=f"drilldown:{request['id']}",
                )
            if not query_emits_review(meta):
                break
            require_rows_for_positive_count(
                purpose=f"Drill-down {request['id']}",
                expected_count=drilldown_count,
                rows=rows,
                query_meta=meta,
            )
            exhaustive = len(rows) == drilldown_count and not meta["truncated"]
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="drilldown",
                scope=dict(request.get("scope") or {}),
                scope_count=drilldown_count,
                exhaustive=exhaustive,
                vql=str(prepared["query"]),
                env=dict(prepared["env"]),
                rows=rows,
                query_meta=meta,
                review_match=request,
            )
            public["drilldown"] = {
                "id": request["id"],
                "stack_id": request.get("stack_id") or "",
                "reason": request.get("reason") or "",
            }
            public["use_case"] = str(request.get("use_case") or "")
            public["output_name"] = str(request.get("output_name") or "")
            public["source_disposition"] = str(
                request.get("source_disposition") or ""
            )
            stored["use_case"] = public["use_case"]
            stored["output_name"] = public["output_name"]
            stored["source_disposition"] = public["source_disposition"]
            public["priority_reason"] = (
                "Targeted requery of the original hunt rows for a suspicious "
                "normalized or exact stack value. Complete only when the "
                "returned rows are exhaustive."
            )
            stored["drilldown_id"] = request["id"]
            items.append(public)
            pending.append(stored)
            row_budget -= len(rows)
            token_budget_remaining -= int(meta["estimated_tokens"])
            if query_stops_pass(meta):
                token_budget_remaining = 0
                break
        artifact_state["remaining_total"] = total
        artifact_state["mode"] = "drilldown"
        artifact_state["status"] = (
            "awaiting_drilldown_review"
            if pending
            else "incomplete_drilldown_budget"
        )
        artifact_state["pending_reviews"] = pending
        return items

    candidate_filters = [
        item for item in case_filters if item.get("status") == "candidate"
    ]
    if candidate_filters:
        validation_env = query_env(hunt_id, artifact, source)
        validation_base = remaining_where(
            profile=profile,
            filters=all_filters,
            reviewed_scopes=[],
            reviewed_matches=[],
            reviewed_signatures=[],
            known_bad=known_bad,
            env=validation_env,
        )
        validation_env.update(
            {
                key: value
                for key, value in use_case_hash_env.items()
                if key not in {"HuntId", "ArtifactName"}
            }
        )
        validation_base = combine_where(
            analysis_scope_where,
            validation_base,
        )
        items: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        row_budget = max_review_rows
        token_budget_remaining = max_review_tokens
        for candidate in candidate_filters[:max_branches]:
            if row_budget <= 0 or token_budget_remaining <= 0:
                break
            candidate_env = dict(validation_env)
            candidate_match = match_expression(
                candidate,
                profile=profile,
                env=candidate_env,
                prefix="Candidate",
            )
            candidate_where = combine_where(validation_base, candidate_match)
            candidate_count_query = count_vql(
                candidate_where,
                source=source,
            )
            candidate_count = exact_count(
                api,
                candidate_count_query,
                candidate_env,
            )
            append_query_ledger(
                state,
                artifact=artifact,
                purpose=f"filter-validation-count:{candidate['id']}",
                vql=candidate_count_query,
                env=candidate_env,
                row_count=candidate_count,
            )
            requested = min(candidate_count, sample_rows, row_budget)
            candidate_query = select_vql(
                projection,
                candidate_where,
                max(1, requested),
                source=source,
            )
            if requested:
                rows, meta = query_rows_bounded(
                    api,
                    vql=candidate_query,
                    env=candidate_env,
                    row_limit=requested,
                    token_limit=token_budget_remaining,
                    token_encoding=token_encoding,
                    max_item_tokens=max_review_tokens,
                )
            else:
                rows = []
                meta = empty_query_meta(token_encoding)
            record_budget_stop(
                artifact_state,
                meta,
                purpose=f"filter-validation:{candidate['id']}",
            )
            if not query_emits_review(meta):
                break
            exhaustive = len(rows) == candidate_count and not meta["truncated"]
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="filter_validation",
                scope=dict(candidate.get("scope") or {}),
                scope_count=candidate_count,
                exhaustive=exhaustive,
                vql=candidate_query,
                env=candidate_env,
                rows=rows,
                query_meta=meta,
                review_match=candidate,
            )
            public["filter"] = candidate
            public["use_case"] = str(candidate.get("use_case") or "")
            public["priority_reason"] = (
                "Validate the proposed suppression against matched rows before "
                "it becomes active."
            )
            stored["filter_id"] = candidate["id"]
            stored["use_case"] = str(candidate.get("use_case") or "")
            items.append(public)
            pending.append(stored)
            row_budget -= len(rows)
            token_budget_remaining -= int(meta["estimated_tokens"])
            if query_stops_pass(meta):
                token_budget_remaining = 0
                break
        artifact_state["remaining_total"] = total
        artifact_state["mode"] = "filter-validation"
        artifact_state["status"] = (
            "awaiting_filter_validation"
            if pending
            else "incomplete_filter_validation_budget"
        )
        artifact_state["pending_reviews"] = pending
        return items

    if artifact_state.get("completed_at_total") == analysis_total:
        artifact_state["remaining_total"] = 0
        artifact_state["status"] = "complete"
        artifact_state["pending_reviews"] = []
        return []

    reviewed_scopes = list(artifact_state.get("reviewed_scopes") or [])
    reviewed_signatures = list(
        artifact_state.get("reviewed_signatures") or []
    )
    prefer_scope_stacking = (
        review_strategy["stacking"]
        and str(profile.get("review", {}).get("strategy") or "")
        == "category_signature_stack"
    )
    remaining_env = query_env(hunt_id, artifact, source)
    remaining_env.update(
        {
            key: value
            for key, value in use_case_hash_env.items()
            if key not in {"HuntId", "ArtifactName"}
        }
    )
    base_where = combine_where(
        analysis_scope_where,
        remaining_where(
            profile=profile,
            filters=all_filters,
            reviewed_scopes=reviewed_scopes,
            reviewed_matches=list(artifact_state.get("reviewed_matches") or []),
            # Category-first normalized stacks continue by fetching a
            # deterministic superset and skipping accounted keys in process
            # memory. Rendering one VQL NOT clause per reviewed key becomes
            # unusable after large pages.
            reviewed_signatures=(
                [] if prefer_scope_stacking else reviewed_signatures
            ),
            known_bad=known_bad,
            env=remaining_env,
        ),
    )
    if base_where:
        remaining_query = count_vql(base_where, source=source)
        gross_remaining = exact_count(
            api, remaining_query, remaining_env, purpose="count-remaining-rows",
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=(
                "remaining-count-before-stack-accounting"
                if prefer_scope_stacking
                else "remaining-count"
            ),
            vql=remaining_query,
            env=remaining_env,
            row_count=gross_remaining,
        )
    else:
        gross_remaining = analysis_total
    if prefer_scope_stacking:
        remaining = max(
            0,
            gross_remaining
            - accounted_signature_rows(
                reviewed_signatures,
                excluded_scopes=reviewed_scopes,
            ),
        )
    else:
        remaining = gross_remaining
    artifact_state["remaining_total"] = remaining
    artifact_state["pending_reviews"] = []
    if remaining == 0:
        artifact_state["completed_at_total"] = analysis_total
        artifact_state["status"] = "complete"
        return []

    items: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    row_budget = max_review_rows
    stack_group_budget = max_stack_groups
    token_budget_remaining = max_review_tokens
    generic_streaming_stack_enabled = (
        review_strategy["stacking"]
        and autoruns_ai_review_enabled
        and artifact not in AUTORUNS_ARTIFACTS
    )

    for rule in known_bad if remaining > direct_row_limit else []:
        if row_budget <= 0 or token_budget_remaining <= 0:
            break
        bad_env = dict(remaining_env)
        bad_match = known_bad_match_expression(
            rule,
            profile=profile,
            env=bad_env,
            prefix="Priority",
        )
        bad_where = combine_where(base_where, bad_match)
        bad_count_query = count_vql(bad_where, source=source)
        bad_count = exact_count(api, bad_count_query, bad_env)
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=f"known-bad-count:{rule['id']}",
            vql=bad_count_query,
            env=bad_env,
            row_count=bad_count,
        )
        if bad_count <= 0:
            continue
        requested = min(bad_count, sample_rows, row_budget)
        bad_query = select_vql(
            projection,
            bad_where,
            requested,
            source=source,
        )
        rows, meta = query_rows_bounded(
            api,
            vql=bad_query,
            env=bad_env,
            row_limit=requested,
            token_limit=token_budget_remaining,
            token_encoding=token_encoding,
            max_item_tokens=max_review_tokens,
        )
        record_budget_stop(
            artifact_state,
            meta,
            purpose=f"known-bad:{rule['id']}",
        )
        if not query_emits_review(meta):
            break
        exhaustive = len(rows) == bad_count and not meta["truncated"]
        public, stored = review_item(
            hunt_id=hunt_id,
            artifact=artifact,
            kind="known_bad",
            scope={},
            scope_count=bad_count,
            exhaustive=exhaustive,
            vql=bad_query,
            env=bad_env,
            rows=rows,
            query_meta=meta,
            review_match=rule,
        )
        public["priority_reason"] = rule["reason"]
        items.append(public)
        pending.append(stored)
        row_budget -= len(rows)
        token_budget_remaining -= int(meta["estimated_tokens"])
        if query_stops_pass(meta):
            token_budget_remaining = 0
            break

    if (
        (
            remaining <= direct_row_limit
            or not review_strategy["stacking"]
        )
        and not generic_streaming_stack_enabled
        and row_budget > 0
        and token_budget_remaining > 0
        and (not selected_use_case or not review_strategy["stacking"])
        and not (prefer_scope_stacking and reviewed_signatures)
    ):
        if transient_exhaustive_direct and not review_strategy["stacking"]:
            requested = remaining
            direct_query = select_all_vql(
                projection,
                base_where,
                source=source,
            )
            rows, meta = query_rows_exhaustive_transient(
                api,
                vql=direct_query,
                env=remaining_env,
                expected_count=remaining,
                maximum_rows=max_transient_rows,
                token_encoding=token_encoding,
            )
        else:
            requested = min(remaining, row_budget)
            direct_query = select_vql(
                projection,
                base_where,
                requested,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=direct_query,
                env=remaining_env,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
        record_budget_stop(artifact_state, meta, purpose="direct")
        if not query_emits_review(meta):
            artifact_state["mode"] = "direct-memory"
            artifact_state["status"] = "incomplete_review_budget"
            artifact_state["pending_reviews"] = pending
            return items
        exhaustive = len(rows) == remaining and not meta["truncated"]
        public, stored = review_item(
            hunt_id=hunt_id,
            artifact=artifact,
            kind="direct",
            scope={},
            scope_count=remaining,
            exhaustive=exhaustive,
            vql=direct_query,
            env=remaining_env,
            rows=rows,
            query_meta=meta,
        )
        stored["artifact_total"] = analysis_total
        items.append(public)
        pending.append(stored)
        artifact_state["mode"] = "direct-memory"
        artifact_state["status"] = "awaiting_review"
        artifact_state["pending_reviews"] = pending
        return items

    if generic_streaming_stack_enabled:
        streamed_items = analyze_generic_streaming_stack_workflow(
            api,
            paths=paths,
            hunt_id=hunt_id,
            artifact=artifact,
            question=question,
            profile=profile,
            projection=projection,
            artifact_state=artifact_state,
            state=state,
            base_where=base_where,
            remaining_env=remaining_env,
            remaining=remaining,
            reviewed_signatures=reviewed_signatures,
            max_flagged_groups=min(
                max_stack_groups,
                REPORT_MAX_RESPONSE_REVIEW_ITEMS,
            ),
            max_followup_rows=max_review_rows,
            host_denominator=(
                int(
                    dict(state.get("host_execution") or {}).get(
                        "target_count"
                    )
                    or 0
                )
                if dict(state.get("host_execution") or {}).get(
                    "denominator_basis"
                )
                == "baseline_targets"
                else int(
                    dict(state.get("host_execution") or {}).get(
                        "responded_count"
                    )
                    or 0
                )
            ),
            max_review_tokens=max_review_tokens,
            discovery_rows=stack_discovery_rows,
            stack_field_preferences=stack_field_preferences,
            stack_field_guidance=stack_field_guidance,
            token_encoding=token_encoding,
            analyst_execution=analyst_execution,
            source=source,
            stack_max_total_rows=stack_max_total_rows,
        )
        if streamed_items is not None:
            if pending:
                artifact_state["pending_reviews"] = unique_dicts(
                    [*pending, *artifact_state["pending_reviews"]],
                    key="review_id",
                )
                streamed_items = [*items, *streamed_items]
                if artifact_state["status"] == "complete":
                    artifact_state["status"] = "awaiting_review"
                    artifact_state.pop("completed_at_total", None)
            return streamed_items
        if stack_max_total_rows is not None:
            raise RuntimeError(
                "--stack-max-total-rows could not be applied: no usable stack "
                "fields were selected. Configure stack fields before retrying."
            )

    if (
        review_strategy["stacking"]
        and artifact not in AUTORUNS_ARTIFACTS
        and not autoruns_ai_review_enabled
        and (
            stack_for_role(profile, "family_signature")
            or stack_for_role(profile, "signature")
        )
        is None
    ):
        artifact_state["stack_discovery"] = {
            "sample_row_count": 0,
            "sample_query_hash": "",
            "observed_statistics_hash": "",
            "selected_model": (
                analyst_execution.model if analyst_execution is not None else ""
            ),
            "recommendation_hash": "",
            "validated_scope_field": "",
            "validated_signature_fields": [],
            "rejected_recommendations": [],
            "requested_field_preferences": list(stack_field_preferences),
            "field_guidance_hash": (
                sha256_value(stack_field_guidance)
                if stack_field_guidance
                else ""
            ),
            "operator_question": (
                "AI field selection is disabled. Enable the analyst agent or "
                "provide a curated artifact profile."
                if stack_field_preferences or stack_field_guidance
                else ""
            ),
            "generated_aggregate_query_hash": "",
            "represented_rows": 0,
            "represented_groups": 0,
            "rare_first_ordering": True,
            "fallback_reason": "ai_disabled",
            "runtime_profile_ephemeral": True,
        }

    selected_stack = stack_for_role(profile, "scope")
    if selected_stack is None:
        if row_budget > 0 and token_budget_remaining > 0:
            direct_fallback = remaining <= direct_row_limit
            requested = min(
                remaining if direct_fallback else sample_rows,
                row_budget,
            )
            sample_query = select_vql(
                projection,
                base_where,
                requested,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=sample_query,
                env=remaining_env,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            record_budget_stop(artifact_state, meta, purpose="sample")
            if not query_emits_review(meta):
                artifact_state["mode"] = "sample-first"
                artifact_state["status"] = "incomplete_review_budget"
                artifact_state["pending_reviews"] = pending
                return items
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="direct" if direct_fallback else "sample",
                scope={},
                scope_count=remaining,
                exhaustive=(
                    direct_fallback
                    and len(rows) == remaining
                    and not meta["truncated"]
                ),
                vql=sample_query,
                env=remaining_env,
                rows=rows,
                query_meta=meta,
            )
            items.append(public)
            pending.append(stored)
        artifact_state["mode"] = (
            "direct-memory"
            if remaining <= direct_row_limit
            else "sample-first"
        )
        artifact_state["status"] = "awaiting_review"
        artifact_state["pending_reviews"] = pending
        return items

    stack_id, stack = selected_stack
    dimensions = list(stack.get("server_dimensions") or [])
    scope_aliases = list(stack.get("server_scope_aliases") or [])
    if not dimensions or len(dimensions) != len(scope_aliases):
        if row_budget > 0 and token_budget_remaining > 0:
            direct_fallback = remaining <= direct_row_limit
            requested = min(
                remaining if direct_fallback else sample_rows,
                row_budget,
            )
            sample_query = select_vql(
                projection,
                base_where,
                requested,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=sample_query,
                env=remaining_env,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            record_budget_stop(
                artifact_state,
                meta,
                purpose="sample-without-scope-mapping",
            )
            if not query_emits_review(meta):
                artifact_state["mode"] = "sample-first"
                artifact_state["status"] = "incomplete_review_budget"
                artifact_state["pending_reviews"] = pending
                return items
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="direct" if direct_fallback else "sample",
                scope={},
                scope_count=remaining,
                exhaustive=(
                    direct_fallback
                    and len(rows) == remaining
                    and not meta["truncated"]
                ),
                vql=sample_query,
                env=remaining_env,
                rows=rows,
                query_meta=meta,
            )
            public["priority_reason"] = (
                "No stack-to-scope mapping is approved; use this bounded "
                "sample to propose evidence filters or findings."
            )
            items.append(public)
            pending.append(stored)
        artifact_state["mode"] = (
            "direct-memory"
            if remaining <= direct_row_limit
            else "sample-first"
        )
        artifact_state["status"] = (
            "awaiting_review" if pending else "incomplete_no_safe_pivot"
        )
        artifact_state["pending_reviews"] = pending
        return items
    pivot_env = dict(remaining_env)
    pivot_query = stack_vql(
        dimensions,
        base_where,
        max_branches,
        source=source,
    )
    with operation_log.query_context(
        purpose="build-scope-pivot", hunt_id=hunt_id, artifact=artifact,
    ):
        groups = api.query(
            pivot_query,
            pivot_env,
            max_wait=30,
            max_row=max(1, min(DEFAULT_QUERY_BATCH_ROWS, max_branches)),
        )
    append_query_ledger(
        state,
        artifact=artifact,
        purpose=f"pivot:{stack_id}",
        vql=pivot_query,
        env=pivot_env,
        row_count=len(groups),
    )
    if remaining > 0 and not groups:
        raise RuntimeError(
            f"Scope stack {stack_id!r} reported no groups for {remaining} "
            f"remaining {artifact} row(s)."
        )
    signature_stack = stack_for_role(profile, "signature")
    family_signature_stack = stack_for_role(profile, "family_signature")
    if selected_use_case:
        family_signature_stack = (
            str(selected_use_case["id"]),
            dict(selected_use_case["family_stack"]),
        )
    artifact_state["scope_reductions"] = []
    for group in groups:
        if token_budget_remaining <= 0:
            break
        if row_budget <= 0 and stack_group_budget <= 0:
            break
        scope = {
            scope_aliases[index - 1]: str(group.get(f"Pivot{index}") or "")
            for index in range(1, len(dimensions) + 1)
        }
        if not all(scope.values()):
            continue
        gross_scope_count = int(group.get("Count") or 0)
        scope_reviewed_signatures = reviewed_signature_records_for_scope(
            reviewed_signatures,
            scope=scope,
        )
        scope_count = (
            max(
                0,
                gross_scope_count
                - accounted_signature_rows(scope_reviewed_signatures),
            )
            if prefer_scope_stacking
            else gross_scope_count
        )
        branch_env = dict(remaining_env)
        branch_where = query_with_scope(
            base_where=base_where,
            scope=scope,
            profile=profile,
            env=branch_env,
        )
        if scope_count <= 0:
            continue
        if scope_count <= direct_row_limit and not prefer_scope_stacking:
            requested = min(scope_count, row_budget)
            branch_query = select_vql(
                projection,
                branch_where,
                requested,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=branch_query,
                env=branch_env,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            record_budget_stop(
                artifact_state,
                meta,
                purpose=f"scope:{sha256_value(scope)[:8]}",
            )
            if not query_emits_review(meta):
                break
            require_rows_for_positive_count(
                purpose=f"Scope {scope}",
                expected_count=scope_count,
                rows=rows,
                query_meta=meta,
            )
            exhaustive = len(rows) == scope_count and not meta["truncated"]
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="pivot",
                scope=scope,
                scope_count=scope_count,
                exhaustive=exhaustive,
                vql=branch_query,
                env=branch_env,
                rows=rows,
                query_meta=meta,
            )
            public["pivot"] = {
                "id": stack_id,
                "purpose": str(stack.get("purpose") or ""),
            }
            items.append(public)
            pending.append(stored)
            row_budget -= len(rows)
            token_budget_remaining -= int(meta["estimated_tokens"])
            if query_stops_pass(meta):
                token_budget_remaining = 0
            continue

        if signature_stack is None:
            requested = min(sample_rows, row_budget)
            branch_query = select_vql(
                projection,
                branch_where,
                requested,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=branch_query,
                env=branch_env,
                row_limit=requested,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            record_budget_stop(
                artifact_state,
                meta,
                purpose=f"scope-sample:{sha256_value(scope)[:8]}",
            )
            if not query_emits_review(meta):
                break
            require_rows_for_positive_count(
                purpose=f"Scope sample {scope}",
                expected_count=scope_count,
                rows=rows,
                query_meta=meta,
            )
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="sample",
                scope=scope,
                scope_count=scope_count,
                exhaustive=False,
                vql=branch_query,
                env=branch_env,
                rows=rows,
                query_meta=meta,
            )
            public["priority_reason"] = (
                "No stable server-side evidence signature is configured; "
                "review a larger bounded sample and propose raw-field filters."
            )
            items.append(public)
            pending.append(stored)
            row_budget -= len(rows)
            token_budget_remaining -= int(meta["estimated_tokens"])
            if query_stops_pass(meta):
                token_budget_remaining = 0
            continue

        signature_id, signature = signature_stack
        signature_dimensions = list(signature.get("server_dimensions") or [])
        if len(signature_dimensions) != 1:
            raise RuntimeError(
                f"Signature stack {signature_id!r} must define one server dimension."
            )
        signature_query = stack_vql(
            signature_dimensions,
            branch_where,
            min(SIGNATURE_GROUP_LIMIT, max_branches),
            source=source,
        )
        signature_groups = api.query(
            signature_query,
            branch_env,
            max_wait=30,
            max_row=max(
                1,
                min(
                    DEFAULT_QUERY_BATCH_ROWS,
                    SIGNATURE_GROUP_LIMIT,
                    max_branches,
                ),
            ),
        )
        append_query_ledger(
            state,
            artifact=artifact,
            purpose=f"signature:{signature_id}:{sha256_value(scope)[:8]}",
            vql=signature_query,
            env=branch_env,
            row_count=len(signature_groups),
        )
        if scope_count > 0 and not signature_groups:
            raise RuntimeError(
                f"Signature stack {signature_id!r} reported no groups for "
                f"positive scope {scope} ({scope_count} row(s))."
            )
        reduction = signature_reduction(
            signature_groups,
            scope_count=(
                gross_scope_count
                if prefer_scope_stacking
                else scope_count
            ),
        )
        reduction_record = {
            "scope": scope,
            "signature_stack": signature_id,
            "signature_level": "exact",
            **reduction,
        }
        artifact_state["scope_reductions"].append(reduction_record)

        # Normalized stacks are token-efficient triage units. They may account
        # for rows directly only when one exact variant covers the whole group;
        # otherwise they require an original-row drill-down.
        if family_signature_stack and (
            reduction["classification"] == "unique"
            or prefer_scope_stacking
        ):
            family_signature_id, family_signature = family_signature_stack
            family_dimensions = list(
                family_signature.get("server_dimensions") or []
            )
            if not family_dimensions:
                raise RuntimeError(
                    f"Family signature stack {family_signature_id!r} must "
                    "define at least one server dimension."
                )
            if stack_group_budget <= 0:
                continue
            family_group_limit = stack_group_budget
            accounted_family_records = (
                reviewed_signature_records_for_scope(
                    reviewed_signatures,
                    scope=scope,
                    stack_id=family_signature_id,
                )
                if prefer_scope_stacking
                else []
            )
            family_query_limit = (
                family_group_limit
                + len(accounted_family_records)
                + 1
            )
            family_query = stack_vql(
                family_dimensions,
                branch_where,
                family_query_limit,
                source=source,
            )
            raw_family_groups = api.query(
                family_query,
                branch_env,
                max_wait=30,
                max_row=family_query_limit,
            )
            unreviewed_raw_family_groups = unreviewed_family_groups(
                raw_family_groups,
                artifact=artifact,
                scope=scope,
                stack_id=family_signature_id,
                dimension_count=len(family_dimensions),
                reviewed_signatures=reviewed_signatures,
            )
            family_groups, family_meta = bound_materialized_rows(
                unreviewed_raw_family_groups,
                row_limit=family_group_limit,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            if len(raw_family_groups) >= family_query_limit:
                family_meta["outcome"] = QUERY_OUTCOME_ROW_LIMIT
                family_meta["truncated"] = True
            elif (
                len(raw_family_groups) < family_query_limit
                and len(unreviewed_raw_family_groups) <= family_group_limit
                and family_meta.get("outcome") == QUERY_OUTCOME_ROW_LIMIT
            ):
                family_meta["outcome"] = QUERY_OUTCOME_COMPLETE
                family_meta["truncated"] = False
            append_query_ledger(
                state,
                artifact=artifact,
                purpose=(
                    f"family-signature:{family_signature_id}:"
                    f"{sha256_value(scope)[:8]}"
                ),
                vql=family_query,
                env=branch_env,
                row_count=len(family_groups),
            )
            if scope_count > 0 and not family_groups:
                require_rows_for_positive_count(
                    purpose=f"Normalized stack {family_signature_id}",
                    expected_count=scope_count,
                    rows=family_groups,
                    query_meta=family_meta,
                )
            family_reduction = signature_reduction(
                family_groups,
                scope_count=scope_count,
                dimension_count=len(family_dimensions),
                allow_empty_dimensions=True,
            )
            artifact_state["scope_reductions"].append(
                {
                    "scope": scope,
                    "signature_stack": family_signature_id,
                    "signature_level": "normalized",
                    **family_reduction,
                }
            )
            variant_pair_limit = min(
                max(1, len(family_groups) * 4),
                max_stack_groups,
            )
            variant_pair_query = ""
            variant_pairs: list[dict[str, Any]] = []
            if not accounted_family_records:
                variant_pair_query = stack_vql(
                    [*family_dimensions, signature_dimensions[0]],
                    branch_where,
                    variant_pair_limit,
                    source=source,
                )
                variant_pairs = api.query(
                    variant_pair_query,
                    branch_env,
                    max_wait=30,
                    max_row=max(
                        1,
                        min(DEFAULT_QUERY_BATCH_ROWS, variant_pair_limit),
                    ),
                )
                append_query_ledger(
                    state,
                    artifact=artifact,
                    purpose=(
                        f"normalized-variants:{family_signature_id}:"
                        f"{sha256_value(scope)[:8]}"
                    ),
                    vql=variant_pair_query,
                    env=branch_env,
                    row_count=len(variant_pairs),
                )
            variants_by_family: dict[tuple[str, ...], list[dict[str, Any]]] = {}
            for pair in variant_pairs:
                family_key = tuple(
                    str(pair.get(f"Pivot{index}") or "")
                    for index in range(1, len(family_dimensions) + 1)
                )
                exact_key = str(
                    pair.get(f"Pivot{len(family_dimensions) + 1}") or ""
                )
                pair_count = int(pair.get("Count") or 0)
                if exact_key and pair_count > 0:
                    variants_by_family.setdefault(family_key, []).append(
                        {
                            "signature": exact_key,
                            "count": pair_count,
                        }
                    )
            logical_dimensions = list(family_signature.get("dimensions") or [])
            if len(logical_dimensions) != len(family_dimensions):
                logical_dimensions = [
                    f"Group{index}"
                    for index in range(1, len(family_dimensions) + 1)
                ]
            page_review_ids: list[str] = []
            page_accounting_ids: list[str] = []
            for family_index, family_group in enumerate(
                family_groups,
                start=1,
            ):
                if stack_group_budget <= 0 or token_budget_remaining <= 0:
                    break
                family_values = [
                    str(family_group.get(f"Pivot{index}") or "")
                    for index in range(1, len(family_dimensions) + 1)
                ]
                family_key = tuple(family_values)
                family_count = int(family_group.get("Count") or 0)
                if family_count <= 0:
                    continue
                family_env = dict(branch_env)
                dimension_match_expression(
                    family_dimensions,
                    family_values,
                    env=family_env,
                    prefix=f"Normalized{family_index}",
                )
                variant_groups = variants_by_family.get(family_key, [])
                exact_variant_count_lower_bound = len(variant_groups)
                single_exact_variant = (
                    exact_variant_count_lower_bound == 1
                    and int(variant_groups[0].get("count") or 0) == family_count
                )
                closure_eligible = True
                aggregate_row = {
                    logical_dimensions[index]: value
                    for index, value in enumerate(family_values)
                }
                aggregate_row.update(
                    {
                        "Count": family_count,
                        "ExactVariantCountLowerBound": (
                            exact_variant_count_lower_bound
                        ),
                        "ClosureEligible": closure_eligible,
                    }
                )
                aggregate_tokens = token_budget.estimate_tokens(
                    stable_json(aggregate_row),
                    token_encoding,
                )
                if aggregate_tokens > token_budget_remaining:
                    record_budget_stop(
                        artifact_state,
                        {
                            **empty_query_meta(token_encoding),
                            "outcome": QUERY_OUTCOME_SHARED_BUDGET_EXHAUSTED,
                            "token_limit": token_budget_remaining,
                            "max_item_tokens": max_review_tokens,
                        },
                        purpose=(
                            f"normalized-stack:{sha256_value(scope)[:8]}:"
                            f"{family_index}"
                        ),
                    )
                    token_budget_remaining = 0
                    break
                meta = {
                    **empty_query_meta(token_encoding),
                    "row_count": 1,
                    "estimated_tokens": aggregate_tokens,
                    "token_limit": token_budget_remaining,
                    "max_item_tokens": max_review_tokens,
                }
                review_match = {
                    "type": "normalized_signature",
                    "scope": scope,
                    "stack_id": family_signature_id,
                    "logical_dimensions": logical_dimensions,
                    "server_dimensions": family_dimensions,
                    "values": family_values,
                    "row_count": family_count,
                }
                public, stored = review_item(
                    hunt_id=hunt_id,
                    artifact=artifact,
                    kind="normalized_stack",
                    scope=scope,
                    scope_count=family_count,
                    exhaustive=False,
                    vql=family_query,
                    env=family_env,
                    rows=[aggregate_row],
                    query_meta=meta,
                    review_match=review_match,
                )
                public["reduction"] = {
                    "classification": family_reduction["classification"],
                    "signature_stack": family_signature_id,
                    "signature_values": family_values,
                    "signature_row_count": family_count,
                    "scope_coverage_percent": round(
                        100 * family_count / scope_count,
                        2,
                    ),
                    "representative_rows": 0,
                    "accounting_basis": "normalized_stack_requires_drilldown",
                    "exact_variant_count_lower_bound": (
                        exact_variant_count_lower_bound
                    ),
                    "closure_eligible": closure_eligible,
                    "single_exact_variant": single_exact_variant,
                }
                if single_exact_variant:
                    public["reduction"]["accounting_basis"] = (
                        "normalized_single_exact_variant"
                    )
                else:
                    public["reduction"]["accounting_basis"] = (
                        "normalized_stack_review"
                    )
                stored["closure_eligible"] = closure_eligible
                stored["exact_variant_count_lower_bound"] = (
                    exact_variant_count_lower_bound
                )
                if selected_use_case:
                    public["use_case"] = str(selected_use_case["id"])
                    public["output_name"] = str(
                        selected_use_case["output_name"]
                    )
                    stored["use_case"] = public["use_case"]
                    stored["output_name"] = public["output_name"]
                if artifact in AUTORUNS_ARTIFACTS:
                    non_promotable_reasons = (
                        autoruns_non_promotable_reasons(
                            logical_dimensions=logical_dimensions,
                            values=family_values,
                            classifier=rmm_classifier,
                        )
                    )
                    if selected_use_case:
                        non_promotable_reasons.append(
                            f"focused-use-case:{selected_use_case['id']}"
                        )
                    non_promotable_reasons = sorted(
                        set(non_promotable_reasons)
                    )
                    priority_review_reasons = sorted(
                        set(
                            autoruns_priority_review_reasons(
                                logical_dimensions=logical_dimensions,
                                values=family_values,
                            )
                        )
                    )
                    public["golden_promotion"] = {
                        "eligible": not non_promotable_reasons,
                        "non_promotable_reasons": (
                            non_promotable_reasons
                        ),
                        "priority_review_reasons": (
                            priority_review_reasons
                        ),
                    }
                    public["decision_template"][
                        "promote_to_golden"
                    ] = False
                    public["decision_template"]["golden_context"] = {
                        "Description": "",
                        "Company": "",
                    }
                    public["decision_template"][
                        "lolbin_behavior_reviewed"
                    ] = False
                    public["decision_template"][
                        "unverified_signer_reviewed"
                    ] = False
                    stored["non_promotable_reasons"] = (
                        non_promotable_reasons
                    )
                    stored["priority_review_reasons"] = (
                        priority_review_reasons
                    )
                public["priority_reason"] = (
                    "Token-efficient normalized stack over selected fields. "
                    + (
                        "The group has one exact variant and may close after "
                        "explicit DLL/.NET hijack-risk review."
                        if single_exact_variant
                        else "Multiple or unresolved exact variants exist. "
                        "Close only after explicit variant and hijack-risk "
                        "review, otherwise request a drill-down."
                    )
                )
                items.append(public)
                pending.append(stored)
                page_review_ids.append(str(public["review_id"]))
                page_accounting_ids.append(
                    accounting_id_for(
                        artifact=artifact,
                        scope=scope,
                        stack_id=family_signature_id,
                        values=family_values,
                    )
                )
                stack_group_budget -= 1
                token_budget_remaining -= aggregate_tokens
            if page_review_ids:
                page_id = "scope-page-" + sha256_value(
                    {
                        "artifact": artifact,
                        "scope": scope,
                        "stack_id": family_signature_id,
                        "review_ids": page_review_ids,
                    }
                )[:16]
                page_record = {
                    "id": page_id,
                    "scope": scope,
                    "stack_id": family_signature_id,
                    "review_ids": page_review_ids,
                    "accounting_ids": page_accounting_ids,
                    "group_count": len(page_review_ids),
                    "exhaustive": (
                        family_meta.get("outcome") == QUERY_OUTCOME_COMPLETE
                    ),
                    "status": "pending",
                    "created_at": now_utc(),
                }
                pages = [
                    page
                    for page in artifact_state.get("scope_stack_pages", [])
                    if str(page.get("id") or "") != page_id
                ]
                artifact_state["scope_stack_pages"] = [*pages, page_record]
            if query_stops_pass(family_meta):
                record_budget_stop(
                    artifact_state,
                    family_meta,
                    purpose=f"normalized-stack:{sha256_value(scope)[:8]}",
                )
                token_budget_remaining = 0
            continue

        # Every large-scope row is processed through an exact signature. One
        # representative row is returned for each signature, while Count is
        # the exact number of rows that the eventual analyst decision will
        # account for. No tail is discarded merely because it was not sampled.
        for signature_index, group_record in enumerate(signature_groups, start=1):
            if row_budget <= 0 or token_budget_remaining <= 0:
                break
            signature_value = str(group_record.get("Pivot1") or "")
            signature_count = int(group_record.get("Count") or 0)
            if not signature_value or signature_count <= 0:
                continue
            signature_env = dict(branch_env)
            signature_match = dimension_match_expression(
                signature_dimensions,
                [signature_value],
                env=signature_env,
                prefix=f"Signature{signature_index}",
            )
            signature_where = combine_where(branch_where, signature_match)
            signature_query = select_vql(
                projection,
                signature_where,
                1,
                source=source,
            )
            rows, meta = query_rows_bounded(
                api,
                vql=signature_query,
                env=signature_env,
                row_limit=1,
                token_limit=token_budget_remaining,
                token_encoding=token_encoding,
                max_item_tokens=max_review_tokens,
            )
            record_budget_stop(
                artifact_state,
                meta,
                purpose=(
                    f"exact-signature:{sha256_value(scope)[:8]}:"
                    f"{signature_index}"
                ),
            )
            if not query_emits_review(meta):
                token_budget_remaining = 0
                break
            require_rows_for_positive_count(
                purpose=f"Exact signature {signature_value}",
                expected_count=signature_count,
                rows=rows,
                query_meta=meta,
            )
            review_match = {
                "type": "exact_signature",
                "scope": scope,
                "stack_id": signature_id,
                "server_dimensions": signature_dimensions,
                "values": [signature_value],
                "row_count": signature_count,
            }
            public, stored = review_item(
                hunt_id=hunt_id,
                artifact=artifact,
                kind="signature",
                scope=scope,
                scope_count=signature_count,
                exhaustive=signature_count == 1,
                vql=signature_query,
                env=signature_env,
                rows=rows,
                query_meta=meta,
                review_match=review_match,
            )
            public["reduction"] = {
                "classification": reduction["classification"],
                "signature_stack": signature_id,
                "signature": signature_value,
                "signature_row_count": signature_count,
                "scope_coverage_percent": round(
                    100 * signature_count / scope_count,
                    2,
                ),
                "representative_rows": len(rows),
                "accounting_basis": "exact_signature",
            }
            public["priority_reason"] = (
                "Review this exact signature representative. A completed "
                "decision must record a disposition and reason; only then "
                "will all rows with this exact signature be removed from the "
                "remaining set."
            )
            items.append(public)
            pending.append(stored)
            row_budget -= len(rows)
            token_budget_remaining -= int(meta["estimated_tokens"])
            if query_stops_pass(meta):
                token_budget_remaining = 0
                break
    artifact_state["mode"] = "iterative-live"
    artifact_state["status"] = "awaiting_review" if pending else "incomplete_no_safe_pivot"
    artifact_state["pending_reviews"] = pending
    return items


def compact_report_text(
    value: Any,
    *,
    fallback: str = "",
    limit: int = REPORT_MAX_TEXT_CHARS,
) -> str:
    rendered = " ".join(str(value or "").split()).strip() or fallback
    if len(rendered) > limit:
        rendered = rendered[: limit - 1].rstrip() + "…"
    return rendered.replace("|", "\\|")


def render_bounded_autoruns_context(
    rows: Iterable[dict[str, Any]],
    *,
    heading_level: int,
    context_group_count: int = 0,
) -> list[str]:
    return autoruns_reporting.render_context(
        rows,
        heading_level=heading_level,
        context_group_count=context_group_count,
        max_groups=REPORT_MAX_CONTEXT_GROUPS,
        max_endpoints_per_group=REPORT_MAX_ENDPOINTS_PER_GROUP,
    )


def compact_autoruns_workflow(workflow: dict[str, Any]) -> dict[str, Any]:
    """Retain bounded context summaries needed to rebuild the canonical report."""
    compact = copy.deepcopy(workflow)
    context = compact.get("suspicious_context")
    if isinstance(context, dict):
        items = [
            item
            for item in context.get("items") or []
            if isinstance(item, dict)
        ]
        if items:
            representative_items: list[dict[str, Any]] = []
            for item in items[:CANONICAL_CONTEXT_SUMMARY_LIMIT]:
                representative = {
                    key: compact_report_text(
                        item.get(key),
                        limit=CANONICAL_CONTEXT_TEXT_CHARS,
                    )
                    for key in (
                        "identity_sha256",
                        "ImagePath",
                        "LaunchString",
                        "Signer",
                        "Severity",
                        "Reason",
                    )
                    if item.get(key) not in (None, "")
                }
                for key in (
                    "row_count",
                    "host_count",
                    "omitted_endpoint_count",
                    "omitted_persistence_count",
                ):
                    if item.get(key) is not None:
                        representative[key] = max(int(item.get(key) or 0), 0)
                endpoints = [
                    endpoint
                    for endpoint in item.get("endpoints") or []
                    if isinstance(endpoint, dict)
                ]
                if endpoints:
                    representative["endpoints"] = [
                        {
                            "fqdn": compact_report_text(
                                endpoint.get("fqdn"),
                                limit=CANONICAL_CONTEXT_TEXT_CHARS,
                            ),
                            "client_id": compact_report_text(
                                endpoint.get("client_id"),
                                limit=CANONICAL_CONTEXT_TEXT_CHARS,
                            ),
                            "row_count": max(
                                int(endpoint.get("row_count") or 0), 0
                            ),
                        }
                        for endpoint in endpoints[
                            :REPORT_MAX_ENDPOINTS_PER_GROUP
                        ]
                    ]
                    representative["omitted_endpoint_count"] = (
                        int(representative.get("omitted_endpoint_count") or 0)
                        + max(
                            len(endpoints) - REPORT_MAX_ENDPOINTS_PER_GROUP,
                            0,
                        )
                    )
                persistence = [
                    variant
                    for variant in item.get("persistence") or []
                    if isinstance(variant, dict)
                ]
                if persistence:
                    representative["persistence"] = [
                        {
                            key: compact_report_text(
                                variant.get(key),
                                limit=CANONICAL_CONTEXT_TEXT_CHARS,
                            )
                            for key in (
                                "category",
                                "entry_location",
                                "entry",
                            )
                            if variant.get(key) not in (None, "")
                        }
                        for variant in persistence[:REPORT_MAX_CONTEXT_GROUPS]
                    ]
                    representative["omitted_persistence_count"] = (
                        int(
                            representative.get("omitted_persistence_count")
                            or 0
                        )
                        + max(
                            len(persistence) - REPORT_MAX_CONTEXT_GROUPS,
                            0,
                        )
                    )
                source = item.get("source")
                if isinstance(source, dict):
                    representative["source"] = {
                        key: compact_report_text(
                            source.get(key),
                            limit=CANONICAL_CONTEXT_TEXT_CHARS,
                        )
                        for key in ("hunt_id", "artifact", "query_sha256")
                        if source.get(key) not in (None, "")
                    }
                representative_items.append(representative)
            context["representative_items"] = representative_items
        item_count = max(
            len(items),
            int(context.get("context_group_count") or 0),
            len(context.get("representative_items") or []),
        )
        context.pop("items", None)
        context["context_group_count"] = item_count
    return compact


def generic_stack_leads(
    state: dict[str, Any],
    *,
    selected_artifacts: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Return bounded provisional leads from completed generic stack review."""
    selected = {
        str(value)
        for value in (selected_artifacts or [])
        if str(value)
    }
    leads: list[dict[str, Any]] = []
    for artifact, artifact_state in sorted(
        state.get("artifacts", {}).items()
    ):
        if selected and str(artifact) not in selected:
            continue
        if not isinstance(artifact_state, dict):
            continue
        for pending in artifact_state.get("pending_reviews") or []:
            if (
                not isinstance(pending, dict)
                or str(pending.get("kind") or "") != "normalized_stack"
            ):
                continue
            ai_review = dict(pending.get("streaming_ai_review") or {})
            review_match = dict(pending.get("review_match") or {})
            impact = dict(pending.get("impact") or {})
            if not ai_review or review_match.get("type") != "streaming_stack_group":
                continue
            dimensions = [
                str(value)
                for value in review_match.get("logical_dimensions") or []
            ]
            values = [
                str(value)
                for value in review_match.get("values") or []
            ]
            leads.append(
                {
                    "artifact": str(artifact),
                    "review_id": str(pending.get("review_id") or ""),
                    "disposition": str(ai_review.get("disposition") or ""),
                    "severity": str(ai_review.get("severity") or ""),
                    "reason": str(ai_review.get("reason") or ""),
                    "row_count": int(
                        review_match.get("row_count")
                        or pending.get("scope_row_count")
                        or 0
                    ),
                    "host_count": int(
                        impact.get("host_count")
                        or review_match.get("host_count")
                        or 0
                    ),
                    "host_denominator": int(
                        impact.get("host_denominator")
                        or review_match.get("host_denominator")
                        or 0
                    ),
                    "host_prevalence_percent": float(
                        impact.get("host_prevalence_percent")
                        or review_match.get("host_prevalence_percent")
                        or 0
                    ),
                    "impacted_machines": list(
                        impact.get("impacted_machines")
                        or review_match.get("impacted_machines")
                        or []
                    ),
                    "rows_reviewed": int(
                        impact.get("rows_reviewed")
                        or review_match.get("rows_reviewed")
                        or 0
                    ),
                    "rows_exhaustive": bool(
                        impact.get("rows_exhaustive")
                        or review_match.get("rows_exhaustive")
                    ),
                    "dimensions": dimensions,
                    "values": values,
                }
            )
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    disposition_order = {"suspicious": 0, "notable": 1}
    return sorted(
        leads,
        key=lambda item: (
            severity_order.get(item["severity"].casefold(), 5),
            disposition_order.get(item["disposition"].casefold(), 2),
            int(item["row_count"]),
            item["artifact"],
            item["review_id"],
        ),
    )


def render_generic_stack_chat_summary(
    state: dict[str, Any],
    *,
    selected_artifacts: Iterable[str] | None = None,
) -> str:
    """Render bounded user-facing results for a completed generic stack pass."""
    selected = {
        str(value)
        for value in (selected_artifacts or [])
        if str(value)
    }
    artifacts = [
        (str(artifact), artifact_state)
        for artifact, artifact_state in sorted(
            state.get("artifacts", {}).items()
        )
        if (
            not selected
            or str(artifact) in selected
        )
        and isinstance(artifact_state, dict)
        and isinstance(artifact_state.get("streaming_stack"), dict)
        and artifact_state.get("streaming_stack")
    ]
    if not artifacts:
        return ""
    lines = ["## Generic stack analysis summary", ""]
    for artifact, artifact_state in artifacts:
        stack = dict(artifact_state.get("streaming_stack") or {})
        discovery = dict(artifact_state.get("stack_discovery") or {})
        source_rows = int(artifact_state.get("current_total") or 0)
        represented_rows = int(stack.get("represented_row_count") or 0)
        groups = int(stack.get("reviewed_group_count") or 0)
        reduction = (
            round(100 * (1 - groups / source_rows), 1)
            if source_rows
            else 0.0
        )
        retained_dimensions = next(
            (
                list(review_match.get("logical_dimensions") or [])
                for review in artifact_state.get("pending_reviews") or []
                if isinstance(review, dict)
                for review_match in [review.get("review_match")]
                if isinstance(review_match, dict)
                and review_match.get("logical_dimensions")
            ),
            [],
        )
        dimensions = list(
            stack.get("signature_logical_dimensions")
            or retained_dimensions
            or discovery.get("validated_signature_fields")
            or []
        )
        pending_reviews = [
            review
            for review in artifact_state.get("pending_reviews") or []
            if isinstance(review, dict)
        ]
        exact_follow_up_complete = bool(pending_reviews) and all(
            isinstance(review.get("query"), dict)
            and str(review["query"].get("outcome") or "")
            == "complete"
            and isinstance(review.get("review_match"), dict)
            and review["review_match"].get("rows_exhaustive")
            is True
            for review in pending_reviews
        )
        closure = (
            "high-count groups excluded from AI review"
            if stack.get("excluded_group_count") else
            "pending operator disposition"
            if exact_follow_up_complete
            else (
                "pending original-row validation"
                if pending_reviews
                else "complete"
            )
        )
        if stack.get("max_total_rows") is not None:
            lines.append(f"Stack threshold > {stack['max_total_rows']}: "
                         f"{stack.get('excluded_group_count', 0):,} groups / "
                         f"{stack.get('excluded_row_count', 0):,} records excluded from AI.")
        lines.extend(
            [
                f"### {artifact}",
                "",
                (
                    "- Aggregate AI pass: "
                    f"`{'complete' if represented_rows == source_rows and source_rows and not stack.get('excluded_group_count') else 'incomplete'}`"
                ),
                (
                    f"- Reduction: {source_rows:,} source rows to "
                    f"{groups:,} AI-reviewed groups ({reduction:.1f}% reduction)"
                ),
                (
                    "- Fields: "
                    + (
                        ", ".join(f"`{value}`" for value in dimensions)
                        if dimensions
                        else "`configured profile`"
                    )
                ),
                (
                    "- Classification: "
                    f"{int(stack.get('suspicious_group_count') or 0)} suspicious; "
                    f"{int(stack.get('notable_group_count') or 0)} notable"
                ),
                (
                    "- Evidentiary closure: "
                    f"`{closure}`"
                ),
                "",
            ]
        )
    leads = generic_stack_leads(
        state,
        selected_artifacts=selected_artifacts,
    )
    if leads:
        lines.extend(
            [
                "### Priority provisional leads",
                "",
                "These are aggregate leads, not confirmed findings.",
                "",
            ]
        )
        for lead in leads[:REPORT_MAX_CONTEXT_GROUPS]:
            pairs = [
                f"{name}={compact_report_text(value, limit=120)}"
                for name, value in zip(
                    lead["dimensions"],
                    lead["values"],
                    strict=False,
                )
            ]
            identity = "; ".join(pairs) or "stack group"
            lines.append(
                f"- **{lead['severity'].upper()} {lead['disposition']}** "
                f"({lead['row_count']} row(s), "
                f"{lead['host_count']}/{lead['host_denominator']} hosts, "
                f"{lead['host_prevalence_percent']:.1f}%): "
                f"{compact_report_text(identity, limit=320)} — "
                f"{compact_report_text(lead['reason'])}"
            )
            machines = [
                str(item.get("fqdn") or item.get("client_id") or "")
                for item in lead.get("impacted_machines") or []
                if item.get("fqdn") or item.get("client_id")
            ]
            if machines:
                lines.append(
                    "  - Impacted machines: "
                    + ", ".join(
                        compact_report_text(value, limit=80)
                        for value in machines[:20]
                    )
                )
            lines.append(
                "  - Source-row follow-up: "
                f"{lead['rows_reviewed']} row(s); "
                f"exhaustive `{lead['rows_exhaustive']}`"
            )
        if len(leads) > REPORT_MAX_CONTEXT_GROUPS:
            lines.append(
                f"- {len(leads) - REPORT_MAX_CONTEXT_GROUPS} additional "
                "provisional lead(s) remain in the structured review queue."
            )
    return "\n".join(lines).rstrip() + "\n"


def render_autoruns_chat_summary(
    state: dict[str, Any],
    *,
    autoruns_context_details: dict[str, list[dict[str, str]]],
    selected_artifacts: Iterable[str] | None = None,
) -> str:
    selected = {
        str(value)
        for value in (selected_artifacts or [])
        if str(value)
    }
    artifacts = [
        (str(artifact), artifact_state)
        for artifact, artifact_state in sorted(
            state.get("artifacts", {}).items()
        )
        if (
            not selected
            or str(artifact) in selected
        )
        and isinstance(
            artifact_state.get("autoruns_residual_workflow"),
            dict,
        )
    ]
    if not artifacts:
        return ""
    lines = ["## Autoruns hunt summary", ""]
    for artifact, artifact_state in artifacts:
        workflow = artifact_state["autoruns_residual_workflow"]
        stack = dict(workflow.get("stack") or {})
        classification = dict(workflow.get("classification") or {})
        ai_review = dict(workflow.get("ai_review") or {})
        golden = dict(artifact_state.get("autoruns_golden") or {})
        context = dict(workflow.get("suspicious_context") or {})
        details = autoruns_context_details.get(artifact, [])
        lines.extend(
            [
                f"### {artifact}",
                "",
                f"- Status: `{artifact_state.get('status', '')}`",
                (
                    "- Rows: "
                    f"{int(golden.get('source_rows') or 0):,} source; "
                    f"{int(golden.get('matched_rows') or 0):,} GoldenDB; "
                    f"{int(golden.get('residual_rows') or 0):,} residual"
                ),
                (
                    "- Stack: "
                    f"{int(stack.get('group_count') or 0):,} groups; "
                    f"{int(stack.get('represented_rows') or 0):,} rows"
                ),
                (
                    "- Review: "
                    f"{int(ai_review.get('script_excluded_group_count') or 0):,} "
                    "script-deferred; "
                    f"{int(ai_review.get('model_reviewed_group_count') or 0):,} "
                    "model-reviewed"
                ),
                (
                    "- Result: "
                    f"{int(classification.get('suspicious_count') or 0):,} "
                    "suspicious identities; "
                    f"{int(classification.get('potential_golden_count') or 0):,} "
                    "potential GoldenDB identities"
                ),
                (
                    "- Exact context: "
                    f"{int(context.get('row_count') or 0):,} rows across "
                    f"{int(context.get('host_count') or 0):,} hosts; "
                    "validated live and not persisted"
                ),
                "",
            ]
        )
        lines.extend(
            render_bounded_autoruns_context(
                details,
                heading_level=4,
                context_group_count=int(
                    context.get("context_group_count")
                    or context.get("identity_count")
                    or len(details)
                ),
            )
        )
    rendered = "\n".join(lines).rstrip() + "\n"
    if len(rendered) <= REPORT_MAX_CHAT_CHARS:
        return rendered
    suffix = (
        "\n\nChat summary reached its 32,000-character guard; consult the linked "
        "specialized report and Velociraptor for remaining groups.\n"
    )
    clipped = rendered[
        : REPORT_MAX_CHAT_CHARS - len(suffix)
    ].rsplit("\n", 1)[0].rstrip()
    return clipped + suffix


def target_execution_coverage(
    hunt_row: dict[str, Any],
    *,
    hunt_state: str,
) -> str:
    if str(hunt_row.get("review_scope") or "") == REVIEW_SCOPE_AD_HOC:
        return "not_assessed"
    if hunt_row.get("baseline_scope_available") is False:
        return "unknown"
    if hunt_row.get("strict_complete") is True:
        return "complete"
    if hunt_row.get("baseline_scope_available") is True:
        return (
            "provisional"
            if hunt_state not in TERMINAL_HUNT_STATES
            else "incomplete"
        )
    readiness = str(
        hunt_row.get("coverage_readiness")
        or hunt_row.get("review_readiness")
        or ""
    )
    if readiness == "baseline_unavailable":
        return "unknown"
    return "unknown"


def target_execution_satisfies_review(value: object) -> bool:
    return str(value or "") in {"complete", "not_assessed"}


def host_execution_statistics(
    hunt_row: dict[str, Any],
) -> dict[str, Any]:
    count_keys = {
        "client_count",
        "responded_client_count",
        "completed_client_count",
        "terminal_client_count",
        "failed_client_count",
        "open_client_count",
        "baseline_target_count",
        "baseline_completed_client_count",
        "baseline_terminal_client_count",
        "baseline_failed_client_count",
        "baseline_open_client_count",
        "baseline_pending_client_count",
        "baseline_responded_client_count",
    }
    if not any(key in hunt_row for key in count_keys):
        return {}

    def count(*keys: str) -> int:
        for key in keys:
            if hunt_row.get(key) is not None:
                try:
                    return max(int(hunt_row[key]), 0)
                except (TypeError, ValueError):
                    continue
        return 0

    baseline_available = hunt_row.get("baseline_scope_available") is True
    if baseline_available:
        target_count = count("baseline_target_count")
        terminal_count = count(
            "baseline_terminal_client_count",
            "terminal_client_count",
        )
        return {
            "denominator_basis": "baseline_targets",
            "target_count": target_count,
            "responded_count": count(
                "baseline_responded_client_count",
                "responded_client_count",
                "client_count",
            ),
            "completed_count": count(
                "baseline_completed_client_count",
                "completed_client_count",
                "success_terminal_client_count",
            ),
            "terminal_count": terminal_count,
            "failed_count": count(
                "baseline_failed_client_count",
                "failed_client_count",
            ),
            "open_count": count(
                "baseline_open_client_count",
                "open_client_count",
            ),
            "pending_count": count(
                "baseline_pending_client_count",
            )
            or max(target_count - terminal_count, 0),
        }

    return {
        "denominator_basis": "responding_hosts",
        "target_count": None,
        "responded_count": count(
            "responded_client_count",
            "client_count",
        ),
        "completed_count": count(
            "completed_client_count",
            "success_terminal_client_count",
        ),
        "terminal_count": count("terminal_client_count"),
        "failed_count": count("failed_client_count"),
        "open_count": count("open_client_count"),
        "pending_count": 0,
    }


def review_rmm_metadata_streaming(
    state: dict[str, Any],
    review_items: list[dict[str, Any]],
    *,
    workdir: Path,
    ai_review_enabled: bool,
    max_review_tokens: int,
    token_encoding: str | None,
    analyst_execution: ResolvedAgentExecution | None = None,
) -> None:
    """Add advisory RMM AI results without creating a review CSV or part files."""

    if not ai_review_enabled:
        return
    public_by_id = {
        str(item.get("review_id") or ""): item
        for item in review_items
        if str(item.get("review_id") or "")
    }
    for _artifact, artifact_state in dict(state.get("artifacts") or {}).items():
        if not isinstance(artifact_state, dict):
            continue
        queue = [
            item
            for item in artifact_state.get("pending_reviews") or []
            if (
                focused_autoruns_pending_review(item)
                and str(item.get("use_case") or "") == "autoruns-rmm"
            )
        ]
        if not queue:
            continue

        def focused_rows() -> Iterator[dict[str, Any]]:
            for pending in queue:
                dimensions = review_queue_dimensions(pending)
                scope = dict(pending.get("scope") or {})
                yield {
                    "ReviewId": str(pending.get("review_id") or ""),
                    "Category": str(
                        scope.get("Category")
                        or dimensions.get("Category")
                        or ""
                    ),
                    "EntryLocation": dimensions.get("EntryLocation", ""),
                    "Entry": dimensions.get("Entry", ""),
                    "ImagePath": dimensions.get("ImagePath", ""),
                    "LaunchString": dimensions.get("LaunchString", ""),
                    "Signer": dimensions.get("Signer", ""),
                    "ScopeRowCount": str(
                        int(pending.get("scope_row_count") or 0)
                    ),
                    "ExactVariantCountLowerBound": str(
                        int(
                            pending.get("exact_variant_count_lower_bound")
                            or 0
                        )
                    ),
                    "ClosureEligible": str(
                        bool(pending.get("closure_eligible"))
                    ).lower(),
                    "PriorityReviewReasons": ";".join(
                        str(value)
                        for value in pending.get("priority_review_reasons") or []
                    ),
                }

        try:
            result = autoruns_ai_review.review_focused_rows_streaming(
                focused_rows(),
                workdir=workdir,
                use_case="autoruns-rmm",
                maximum_evidence_tokens=max_review_tokens,
                token_encoding=(
                    token_encoding or token_budget.token_encoding_name()
                ),
                execution=analyst_execution,
            )
            manifest = dict(result.get("manifest") or {})
            artifact_state["rmm_ai_review"] = manifest
            recommendations = {
                str(item.get("review_id") or ""): item
                for item in result.get("recommendations") or []
            }
            for pending in queue:
                review_id = str(pending.get("review_id") or "")
                recommendation = recommendations.get(review_id)
                if recommendation is None:
                    continue
                advisory = {
                    key: recommendation[key]
                    for key in (
                        "disposition",
                        "severity",
                        "confidence",
                        "drilldown_recommended",
                        "reason",
                    )
                }
                pending["ai_review"] = advisory
                public = public_by_id.get(review_id)
                if public is not None:
                    public["ai_review"] = copy.deepcopy(advisory)
        except Exception as exc:
            artifact_state["rmm_ai_review"] = {
                "enabled": True,
                "model": (
                    analyst_execution.model
                    if analyst_execution is not None
                    else ""
                ),
                "runtime_files_persisted": False,
                "error": compact_report_text(exc),
            }


def output_state_for_use_case(
    state: dict[str, Any],
    *,
    use_case: str,
) -> dict[str, Any]:
    selected = str(use_case or "")
    scoped = copy.deepcopy(state)
    scoped["analysis_output_mode"] = selected or "general"
    scoped["case_filters"] = [
        item
        for item in scoped.get("case_filters", [])
        if record_matches_use_case(item, use_case=selected)
    ]
    scoped["findings"] = [
        item
        for item in scoped.get("findings", [])
        if record_matches_use_case(item, use_case=selected)
    ]
    scoped["normalization_candidates"] = [
        item
        for item in scoped.get("normalization_candidates", [])
        if record_matches_use_case(item, use_case=selected)
    ]
    scoped_mode_coverage: dict[str, dict[str, Any]] = {}
    for artifact, modes in scoped.get(
        "autoruns_mode_coverage",
        {},
    ).items():
        if not isinstance(modes, dict):
            continue
        selected_modes = {
            mode_id: record
            for mode_id, record in modes.items()
            if isinstance(record, dict)
            and (
                mode_id == selected
                if selected
                else mode_id not in AUTORUNS_USE_CASES
            )
        }
        if selected_modes:
            scoped_mode_coverage[str(artifact)] = selected_modes
    scoped["autoruns_mode_coverage"] = scoped_mode_coverage
    for artifact, artifact_state in scoped.get("artifacts", {}).items():
        if not isinstance(artifact_state, dict):
            continue
        coverage_records = scoped_mode_coverage.get(
            str(artifact),
            {},
        )
        coverage_record = next(
            iter(coverage_records.values()),
            {},
        )
        if coverage_record:
            artifact_state["mode"] = (
                f"{selected}-csv"
                if selected
                else str(coverage_record.get("mode") or "general")
            )
            artifact_state["current_total"] = int(
                coverage_record.get("scope_rows") or 0
            )
            artifact_state["remaining_total"] = int(
                coverage_record.get("remaining_rows") or 0
            )
            artifact_state["filter_count"] = sum(
                str(item.get("artifact") or "") == str(artifact)
                for item in scoped.get("case_filters", [])
            )
        artifact_state["pending_reviews"] = [
            item
            for item in artifact_state.get("pending_reviews", [])
            if record_matches_use_case(item, use_case=selected)
        ]
        artifact_state["pending_review_files"] = [
            item
            for item in artifact_state.get("pending_review_files", [])
            if record_matches_use_case(item, use_case=selected)
        ]
        artifact_state["row_accounting"] = [
            item
            for item in artifact_state.get("row_accounting", [])
            if record_matches_use_case(item, use_case=selected)
        ]
        artifact_state["reviewed_signatures"] = [
            item
            for item in artifact_state.get("reviewed_signatures", [])
            if record_matches_use_case(item, use_case=selected)
        ]
        artifact_state["drilldown_requests"] = [
            item
            for item in artifact_state.get("drilldown_requests", [])
            if record_matches_use_case(item, use_case=selected)
        ]
        focused = artifact_state.get("autoruns_focused_workflows")
        if selected:
            artifact_state.pop("autoruns_residual_workflow", None)
            artifact_state["autoruns_golden"] = {}
            artifact_state["autoruns_focused_workflows"] = (
                {
                    selected: focused[selected]
                }
                if isinstance(focused, dict)
                and isinstance(focused.get(selected), dict)
                else {}
            )
            if selected in AUTORUNS_AUTOMATED_USE_CASES:
                artifact_state["scope_reductions"] = []
                artifact_state["budget_stop"] = {}
        else:
            artifact_state["autoruns_focused_workflows"] = {}
            if isinstance(
                artifact_state.get("autoruns_residual_workflow"),
                dict,
            ):
                artifact_state["scope_reductions"] = []
                artifact_state["budget_stop"] = {}
    return scoped


def compact_specialized_state_for_persistence(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Bound persisted specialized state while preserving review metadata."""

    persisted = copy.deepcopy(state)
    persisted["query_ledger"] = list(persisted.get("query_ledger") or [])[-50:]
    persisted["findings"] = list(persisted.get("findings") or [])[
        -REPORT_MAX_NARRATIVE_ITEMS:
    ]
    persisted["analyst_review_memory"] = list(
        persisted.get("analyst_review_memory") or []
    )[-REPORT_MAX_NARRATIVE_ITEMS:]
    report_path = str(
        dict(persisted.get("analysis_memory") or {}).get("path") or ""
    )
    for output in dict(persisted.get("analysis_outputs") or {}).values():
        if not isinstance(output, dict):
            continue
        output.pop("summary", None)
        if report_path:
            output["report"] = report_path
    for artifact, artifact_state in dict(
        persisted.get("artifacts") or {}
    ).items():
        if str(artifact) not in AUTORUNS_ARTIFACTS or not isinstance(
            artifact_state, dict
        ):
            continue
        for key in (
            "reviewed_scopes",
            "reviewed_matches",
            "reviewed_signatures",
            "row_accounting",
            "drilldown_requests",
            "scope_stack_pages",
            "scope_reductions",
        ):
            artifact_state[key] = []
        artifact_state["pending_reviews"] = []
        artifact_state["pending_review_count"] = len(
            list(state.get("artifacts", {}).get(artifact, {}).get("pending_reviews") or [])
        )
        residual = artifact_state.get("autoruns_residual_workflow")
        if isinstance(residual, dict):
            artifact_state["autoruns_residual_workflow"] = (
                compact_autoruns_workflow(residual)
            )
        focused = artifact_state.get("autoruns_focused_workflows")
        if isinstance(focused, dict):
            artifact_state["autoruns_focused_workflows"] = {
                str(mode): compact_autoruns_workflow(workflow)
                for mode, workflow in focused.items()
                if isinstance(workflow, dict)
            }
    return persisted


def write_canonical_specialized_state(
    path: Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Atomically publish specialized state inside the current checkpoint."""

    container: dict[str, Any]
    if path.is_file():
        existing = load_json_object(path)
        if int(existing.get("schema_version") or 0) == flow_analysis.SCHEMA_VERSION:
            container = existing
        else:
            container = flow_analysis.initial_state(
                scope_type="hunt",
                scope_id=str(state.get("hunt_id") or ""),
                analysis_id="",
            )
    else:
        container = flow_analysis.initial_state(
            scope_type="hunt",
            scope_id=str(state.get("hunt_id") or ""),
            analysis_id="",
        )
    existing_scope = str(container.get("scope_id") or "")
    hunt_id = str(state.get("hunt_id") or "")
    if existing_scope and existing_scope != hunt_id:
        raise RuntimeError(
            f"Canonical analysis state belongs to hunt {existing_scope}, not {hunt_id}."
        )
    container["schema_version"] = flow_analysis.SCHEMA_VERSION
    container["scope_type"] = "hunt"
    container["scope_id"] = hunt_id
    container["specialized_analysis"] = compact_specialized_state_for_persistence(
        state
    )
    if not container.get("checkpoint") and not container.get("runs"):
        container["review_scope"] = str(
            state.get("review_scope") or "managed_collection"
        )
        container["analysis_method"] = "specialized"
        container["coverage"] = {
            "result_review": str(
                state.get("result_review_coverage") or "unknown"
            ),
            "target_execution": str(
                state.get("target_execution_coverage") or "unknown"
            ),
            "overall": str(state.get("coverage") or "unknown"),
        }
    container["updated_at"] = now_utc()
    hunting.write_json(path, container)
    return container


def write_outputs(
    paths: dict[str, Path],
    state: dict[str, Any],
    *,
    reusable_filters: list[dict[str, Any]],
    use_case: str = "",
    ai_review_enabled: bool = False,
    max_review_tokens: int = (
        analysis_limits.DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM
    ),
    token_encoding: str | None = None,
) -> list[dict[str, Any]]:
    paths["root"].mkdir(parents=True, exist_ok=True)
    selected_output_paths = analysis_output_paths(
        paths,
        use_case=use_case,
    )
    output_mode = str(use_case or "") or "general"
    state["analysis_memory"] = {
        "path": str(paths["analysis_memory"]),
        "updated_at": str(state.get("updated_at") or now_utc()),
    }
    output_state = output_state_for_use_case(
        state,
        use_case=use_case,
    )
    selected_case_filters = output_state.get("case_filters", [])
    selected_reusable_filters = [
        item
        for item in reusable_filters
        if record_matches_use_case(item, use_case=use_case)
        and item.get("status") in ACTIVE_FILTER_STATUSES
    ]
    filters_required = bool(
        selected_case_filters or selected_reusable_filters
    )
    output_record = {
        "report": str(paths["analysis_memory"]),
        "updated_at": str(state.get("updated_at") or now_utc()),
    }
    if filters_required:
        output_record["filters"] = str(selected_output_paths["filters"])
    state.setdefault("analysis_outputs", {})[output_mode] = output_record
    # Focused review queues use the canonical metadata-only review-items.json
    # manifest; live analysis does not create editable queue CSVs or review dirs.
    persisted_state = copy.deepcopy(state)
    review_files: list[dict[str, Any]] = []
    write_canonical_specialized_state(paths["state"], persisted_state)
    persisted_output_state = output_state_for_use_case(
        persisted_state,
        use_case=use_case,
    )
    selected_case_filters = persisted_output_state.get(
        "case_filters",
        [],
    )
    filter_payload = {
        "schema_version": FILTER_SCHEMA_VERSION,
        "hunt_id": persisted_state["hunt_id"],
        "updated_at": persisted_state["updated_at"],
        "use_case": str(use_case or ""),
        "case_filters": selected_case_filters,
        "filters": [
            item
            for item in selected_case_filters
            if item.get("status") in ACTIVE_FILTER_STATUSES
        ],
        "reusable_filters_applied": [
            {
                "id": item["id"],
                "artifact": item["artifact"],
                "use_case": str(item.get("use_case") or ""),
                "scope": item.get("scope", {}),
                **serialized_filter_match(item),
                "reason": item["reason"],
                "status": item["status"],
                "source": item["source"],
            }
            for item in selected_reusable_filters
        ],
    }
    if filters_required:
        hunting.write_json(
            selected_output_paths["filters"],
            filter_payload,
        )
    else:
        selected_output_paths["filters"].unlink(missing_ok=True)
    return review_files


def write_suspicious_use_case_outputs(
    paths: dict[str, Path],
    *,
    hunt_id: str,
    review_items: list[dict[str, Any]],
) -> list[str]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in review_items:
        if str(item.get("use_case") or "").startswith("autoruns-"):
            continue
        output_name = str(item.get("output_name") or "")
        if (
            item.get("kind") != "drilldown"
            or not item.get("exhaustive")
            or str(item.get("source_disposition") or "") != "suspicious"
            or not output_name
        ):
            continue
        if output_name not in SUSPICIOUS_OUTPUT_NAMES:
            raise RuntimeError(
                f"Unsupported suspicious use-case output {output_name!r}."
            )
        rows = list(item.get("rows") or [])
        hosts = unique_dicts(
            [
                {
                    "id": sha256_value(
                        {
                            "Fqdn": str(row.get("Fqdn") or ""),
                            "ClientId": str(row.get("ClientId") or ""),
                        }
                    ),
                    "Fqdn": str(row.get("Fqdn") or ""),
                    "ClientId": str(row.get("ClientId") or ""),
                }
                for row in rows
                if row.get("Fqdn") or row.get("ClientId")
            ],
            key="id",
        )
        for host in hosts:
            host.pop("id", None)
        grouped.setdefault(output_name, []).append(
            {
                "id": "suspicious-" + sha256_value(
                    {
                        "artifact": item.get("artifact"),
                        "scope": item.get("scope"),
                        "drilldown": item.get("drilldown"),
                        "rows": rows,
                    }
                )[:16],
                "artifact": str(item.get("artifact") or ""),
                "use_case": str(item.get("use_case") or ""),
                "scope": dict(item.get("scope") or {}),
                "row_count": int(item.get("scope_row_count") or len(rows)),
                "reason": str(
                    (item.get("drilldown") or {}).get("reason") or ""
                ),
                "hosts": hosts,
                "context": rows,
                "evidence_hash": str(item.get("evidence_hash") or ""),
                "recorded_at": now_utc(),
            }
        )
    written: list[str] = []
    for output_name, new_items in grouped.items():
        output_path = paths["root"] / output_name
        existing_items: list[dict[str, Any]] = []
        if output_path.exists():
            existing = load_json_object(output_path)
            if isinstance(existing.get("items"), list):
                existing_items = [
                    value
                    for value in existing["items"]
                    if isinstance(value, dict)
                ]
        merged = unique_dicts([*existing_items, *new_items], key="id")
        hunting.write_json(
            output_path,
            {
                "schema_version": 1,
                "hunt_id": hunt_id,
                "updated_at": now_utc(),
                "item_count": len(merged),
                "items": merged,
            },
        )
        written.append(str(output_path))
    return written


def review_item_metadata(item: dict[str, Any]) -> dict[str, Any]:
    """Return decision metadata without transient row payloads."""
    compact = copy.deepcopy(item)
    rows = compact.pop("rows", [])
    compact["returned_row_count"] = len(rows) if isinstance(rows, list) else 0
    compact["row_reference"] = {
        "type": "velociraptor_live_query",
        "review_id": str(item.get("review_id") or ""),
        "query_hash": str(dict(item.get("query") or {}).get("query_hash") or ""),
        "materialized": False,
    }
    return compact


def compact_review_row(row: Any) -> dict[str, str]:
    if not isinstance(row, dict):
        return {"value": compact_report_text(row)}
    return {
        str(key): compact_report_text(value)
        for key, value in list(row.items())[:REPORT_MAX_RESPONSE_ROW_FIELDS]
    }


def review_items_for_response(
    review_items: list[dict[str, Any]],
    *,
    include_review_rows: bool,
) -> list[dict[str, Any]]:
    if include_review_rows:
        return copy.deepcopy(review_items)
    output: list[dict[str, Any]] = []
    for item in review_items[:REPORT_MAX_RESPONSE_REVIEW_ITEMS]:
        compact = review_item_metadata(item)
        rows = item.get("rows") or []
        compact["representative_rows"] = [
            compact_review_row(row)
            for row in list(rows)[:REPORT_MAX_RESPONSE_EXAMPLE_ROWS]
        ]
        compact["rows_omitted_from_response"] = max(
            len(rows) - len(compact["representative_rows"]),
            0,
        )
        output.append(compact)
    return output


def write_review_items_manifest(
    path: Path,
    *,
    hunt_id: str,
    review_items: list[dict[str, Any]],
    state: dict[str, Any],
) -> str:
    if not review_items:
        path.unlink(missing_ok=True)
        return ""
    pending_by_review_id = {
        review_id: pending
        for review_id, (_, pending) in pending_reviews_by_id(state).items()
    }

    def manifest_item(item: dict[str, Any]) -> dict[str, Any]:
        compact = review_item_metadata(item)
        pending = pending_by_review_id.get(
            str(item.get("review_id") or "")
        )
        if (
            isinstance(pending, dict)
            and str(pending.get("artifact") or "") in AUTORUNS_ARTIFACTS
        ):
            compact["review_state"] = {
                key: copy.deepcopy(pending[key])
                for key in (
                    "review_id",
                    "artifact",
                    "kind",
                    "scope",
                    "scope_row_count",
                    "exhaustive",
                    "evidence_hash",
                    "query",
                    "review_match",
                    "closure_eligible",
                    "exact_variant_count_lower_bound",
                    "use_case",
                    "output_name",
                    "non_promotable_reasons",
                    "priority_review_reasons",
                    "ai_review",
                )
                if key in pending
            }
        return compact

    hunting.write_json(
        path,
        {
            "schema_version": 1,
            "hunt_id": hunt_id,
            "updated_at": now_utc(),
            "authoritative_row_source": "Velociraptor live query",
            "raw_rows_persisted": False,
            "review_item_count": len(review_items),
            "default_response_policy": {
                "item_limit": REPORT_MAX_RESPONSE_REVIEW_ITEMS,
                "representative_row_limit": REPORT_MAX_RESPONSE_EXAMPLE_ROWS,
                "row_field_limit": REPORT_MAX_RESPONSE_ROW_FIELDS,
                "omitted_item_count": max(
                    len(review_items) - REPORT_MAX_RESPONSE_REVIEW_ITEMS,
                    0,
                ),
            },
            "review_items": [
                manifest_item(item) for item in review_items
            ],
        },
    )
    return str(path)


def _specialized_debug_session(
    *args: Any, **kwargs: Any
) -> agent_diagnostics.DebugSession | None:
    if not bool(kwargs.get("debug_validation", False)):
        return None
    hunt_row = dict(kwargs.get("hunt_row") or {})
    hunt_id = str(hunt_row.get("hunt_id") or hunt_row.get("HuntId") or "unknown")
    hunt_root = Path(kwargs["hunt_root"])
    use_case = str(kwargs.get("use_case") or "")
    return agent_diagnostics.DebugSession(
        hunt_root / "analysis" / flow_analysis_coordinator.VALIDATION_DEBUG_FILENAME,
        scope_type="hunt",
        scope_id=hunt_id,
        lane=use_case or "specialized_stack",
    )


@agent_diagnostics.auto_debug_scope(_specialized_debug_session)
def analyze_live_hunt(
    api: Any,
    *,
    investigation_id: str,
    hunt_row: dict[str, Any],
    request: Any,
    hunt_root: Path,
    question: str = "What activity is malicious, security-relevant, or useful cross-host context?",
    task_mode: str = "targeted_hunt",
    response_depth: str = "",
    artifact_references: Iterable[str | Path] | None = None,
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot | None = None,
    filter_references: Iterable[str | Path] | None = None,
    decisions_path: Path | None = None,
    indicators: list[str] | None = None,
    use_case: str = "",
    autoruns_golden_tool: str = "",
    autoruns_golden_version: str = "",
    autoruns_golden_disabled: bool = False,
    autoruns_golden_sync: bool = True,
    autoruns_golden_db: Path | None = None,
    autoruns_golden_promote_reviewed: bool = False,
    autoruns_rmm_reference: Path | None = None,
    direct_row_limit: int = DEFAULT_DIRECT_ROW_LIMIT,
    sample_rows: int = DEFAULT_SAMPLE_ROWS,
    stack_discovery_rows: int = DEFAULT_STACK_DISCOVERY_ROWS,
    stack_field_preferences: Iterable[str] | None = None,
    stack_field_guidance: str = "",
    max_branches: int = DEFAULT_MAX_BRANCHES,
    max_review_rows: int = DEFAULT_MAX_REVIEW_ROWS,
    max_stack_groups: int = DEFAULT_MAX_STACK_GROUPS,
    max_review_tokens: int = (
        analysis_limits.DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM
    ),
    maximum_review_tokens: int = (
        analysis_limits.DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM
    ),
    token_encoding: str | None = None,
    autoruns_ai_review_enabled: bool = False,
    skip_ai: bool = False,
    finding_consolidation_spec: ResolvedAgentExecution | None = None,
    synthesis_mode: str = "full",
    debug_validation: bool = False,
    include_review_rows: bool = False,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    stack_max_total_rows: int | None = None,
) -> dict[str, Any]:
    hunt_id = str(hunt_row.get("hunt_id") or hunt_row.get("HuntId") or "")
    if not hunt_id:
        raise RuntimeError("Live hunt analysis requires a hunt id.")
    normalized_task_mode = normalize_profile_name(task_mode or "targeted_hunt")
    if normalized_task_mode not in PROFILE_NAMES:
        raise RuntimeError(f"Unknown task mode: {normalized_task_mode}")
    normalized_response_depth = normalize_response_depth(response_depth)
    if not normalized_response_depth:
        normalized_response_depth = load_agent_profile_config().profiles[
            normalized_task_mode
        ].default_depth
    if normalized_response_depth not in RESPONSE_DEPTH_NAMES:
        raise RuntimeError(f"Unknown response depth: {normalized_response_depth}")
    if skip_ai:
        autoruns_ai_review_enabled = False
        finding_consolidation_spec = None
    analyst_execution = (
        finding_consolidation_spec
        if isinstance(finding_consolidation_spec, ResolvedAgentExecution)
        else None
    )
    if autoruns_ai_review_enabled and analyst_execution is None:
        analyst_execution = resolve_agent_execution(
            allow_missing_credentials=True
        )

    def publish_progress(
        phase: str,
        *,
        status: str = "running",
        force: bool = False,
        **counts: Any,
    ) -> None:
        if progress_callback is not None:
            progress_callback(
                {
                    "phase": phase,
                    "status": status,
                    "hunt_id": hunt_id,
                    "force": force,
                    **counts,
                }
            )

    publish_progress("inventory", force=True)
    if not question.strip():
        raise RuntimeError("Live hunt analysis question cannot be empty.")
    if min(
        direct_row_limit,
        sample_rows,
        max_branches,
        max_review_rows,
        max_stack_groups,
        max_review_tokens,
        maximum_review_tokens,
    ) <= 0:
        raise RuntimeError("Live analysis limits must be positive.")
    if not MIN_STACK_DISCOVERY_ROWS <= stack_discovery_rows <= MAX_STACK_DISCOVERY_ROWS:
        raise RuntimeError(
            "stack_discovery_rows must be between "
            f"{MIN_STACK_DISCOVERY_ROWS} and {MAX_STACK_DISCOVERY_ROWS}."
        )
    if max_review_tokens > maximum_review_tokens:
        raise RuntimeError(
            "Live analysis max_review_tokens may not exceed "
            f"{maximum_review_tokens}."
        )
    normalized_stack_field_preferences = (
        generic_stack_review.normalize_field_preferences(
            stack_field_preferences
        )
    )
    normalized_stack_field_guidance = (
        generic_stack_review.normalize_field_guidance(
            stack_field_guidance
        )
    )
    group = ""
    description = str(hunt_row.get("hunt_description") or "")
    marker = re.search(r"(?:^|\s)dfir-group=([^\s]+)", description)
    if marker:
        group = marker.group(1)
    hunt_state = hunting.normalize_hunt_state(hunt_row.get("state"))
    resolved_policy = artifact_policy.resolve_operation_policy(
        artifact_references=artifact_references,
        policy_snapshot=policy_snapshot,
    )
    profiles = resolved_policy.profiles
    rmm_classifier = autoruns_golden.RmmClassifier(
        autoruns_rmm_reference
    )
    autoruns_golden_configuration = configured_autoruns_golden(
        tool=autoruns_golden_tool,
        version=autoruns_golden_version,
        database=autoruns_golden_db,
        rmm_reference=autoruns_rmm_reference,
        disabled=autoruns_golden_disabled,
    )
    if (
        autoruns_golden_configuration.get("enabled")
        and not str(use_case or "").strip()
        and any(
            str(spec.artifact) in AUTORUNS_ARTIFACTS
            for spec in request.expected_specs
        )
    ):
        publish_progress("golden_db", force=True)
        autoruns_golden_configuration = (
            resolve_autoruns_golden_inventory(
                api,
                autoruns_golden_configuration,
                sync_missing_or_stale=autoruns_golden_sync,
                rmm_reference=autoruns_rmm_reference,
            )
        )
    reusable_filters, filter_paths = load_reusable_filters(
        configured_filter_paths(filter_references),
        profiles=profiles,
    )
    paths = analysis_paths(hunt_root)
    state = load_state(
        paths["state"],
        investigation_id=investigation_id,
        hunt_id=hunt_id,
        group=group,
        hunt_state=hunt_state,
    )
    state["task_mode"] = normalized_task_mode
    state["response_depth"] = normalized_response_depth
    decisions = load_decisions(decisions_path)
    if decisions:
        apply_decisions(
            state,
            decisions,
            profiles=profiles,
            source=str(decisions_path),
            golden_db_path=autoruns_golden_db,
            promote_reviewed=autoruns_golden_promote_reviewed,
            rmm_reference=autoruns_rmm_reference,
        )
    state["hunt_state"] = hunt_state
    state["host_execution"] = host_execution_statistics(hunt_row)
    state["artifact_policy"] = resolved_policy.metadata()
    state["filter_reference_files"] = filter_paths

    review_items: list[dict[str, Any]] = []
    expected_specs = list(request.expected_specs)
    publish_progress(
        "stack_analysis",
        force=True,
        submitted=len(expected_specs),
    )
    for artifact_index, spec in enumerate(expected_specs, start=1):
        artifact = str(spec.artifact)
        profile = artifact_profiles.resolve_profile(artifact, profiles)
        if profile is None:
            profile = unprofiled_runtime_profile(artifact)
        artifact_state = artifact_state_for(
            state,
            artifact,
            profile_hash=str(profile.get("_profile_hash") or ""),
        )
        selected_use_case_id = str(use_case or "").strip()
        retained_focused_reviews = [
            item
            for item in artifact_state.get("pending_reviews") or []
            if (
                focused_autoruns_pending_review(item)
                and str(item.get("use_case") or "") == "autoruns-rmm"
                and str(item.get("use_case") or "")
                != selected_use_case_id
            )
        ]
        artifact_items = analyze_artifact(
            api,
            paths=paths,
            hunt_id=hunt_id,
            artifact=artifact,
            question=question,
            profile=profile,
            artifact_state=artifact_state,
            state=state,
            reusable_filters=reusable_filters,
            indicators=list(indicators or []),
            use_case=use_case,
            autoruns_golden_configuration=(
                autoruns_golden_configuration
            ),
            rmm_classifier=rmm_classifier,
            direct_row_limit=direct_row_limit,
            sample_rows=sample_rows,
            stack_discovery_rows=stack_discovery_rows,
            stack_field_preferences=normalized_stack_field_preferences,
            stack_field_guidance=normalized_stack_field_guidance,
            max_branches=max_branches,
            max_review_rows=max_review_rows,
            max_stack_groups=max_stack_groups,
            max_review_tokens=max_review_tokens,
            token_encoding=token_encoding or token_budget.token_encoding_name(),
            autoruns_ai_review_enabled=autoruns_ai_review_enabled,
            analyst_execution=analyst_execution,
            stack_max_total_rows=stack_max_total_rows,
        )
        if retained_focused_reviews:
            artifact_state["pending_reviews"] = unique_dicts(
                [
                    *retained_focused_reviews,
                    *list(artifact_state.get("pending_reviews") or []),
                ],
                key="review_id",
            )
        configured_normalizers = list(
            profile.get("review", {}).get("normalizers") or []
        )
        for item in artifact_items:
            item["configured_normalizers"] = configured_normalizers
        review_items.extend(artifact_items)
        publish_progress(
            "stack_analysis",
            completed=artifact_index,
            groups=len(review_items),
            artifact=artifact,
        )

    artifact_statuses = {
        str(item.get("status") or "")
        for item in state.get("artifacts", {}).values()
    }
    awaiting_autoruns_classification = bool(
        artifact_statuses.intersection(
            {
                "awaiting_ai_classification",
                "incomplete_ai_classification",
            }
        )
    )
    state_has_pending_reviews = any(
        item.get("pending_reviews")
        for item in state.get("artifacts", {}).values()
    )
    all_complete = (
        bool(artifact_statuses)
        and artifact_statuses == {"complete"}
        and not state_has_pending_reviews
    )
    state["result_review_coverage"] = (
        "complete" if all_complete else "incomplete"
    )
    state["target_execution_coverage"] = target_execution_coverage(
        hunt_row,
        hunt_state=hunt_state,
    )
    state["review_scope"] = str(
        hunt_row.get("review_scope") or "managed_collection"
    )
    source_terminal = hunt_state in TERMINAL_HUNT_STATES
    state["coverage"] = (
        "complete"
        if state["result_review_coverage"] == "complete"
        and target_execution_satisfies_review(
            state["target_execution_coverage"]
        )
        and source_terminal
        else "provisional"
        if not source_terminal
        else "provisional"
        if state["target_execution_coverage"] == "provisional"
        else "unknown"
        if state["target_execution_coverage"] == "unknown"
        else "incomplete"
    )
    state["status"] = (
        "complete"
        if all_complete
        and target_execution_satisfies_review(
            state["target_execution_coverage"]
        )
        and source_terminal
        else "review_complete_source_non_terminal"
        if all_complete and not source_terminal
        else "review_complete_coverage_unknown"
        if all_complete and state["target_execution_coverage"] == "unknown"
        else "review_complete_target_incomplete"
        if all_complete
        else "awaiting_ai_classification"
        if awaiting_autoruns_classification
        else "awaiting_review"
        if review_items or state_has_pending_reviews
        else "incomplete"
    )
    selected_artifacts = [
        str(spec.artifact)
        for spec in request.expected_specs
    ]
    selected_autoruns_mode_coverage: dict[str, dict[str, Any]] = {}
    for artifact in selected_artifacts:
        artifact_state = state.get("artifacts", {}).get(artifact)
        if not isinstance(artifact_state, dict):
            continue
        coverage_record = update_autoruns_mode_coverage(
            state,
            artifact=artifact,
            artifact_state=artifact_state,
            use_case=use_case,
            golden_enabled=bool(
                autoruns_golden_configuration.get("enabled")
                and not str(use_case or "").strip()
            ),
        )
        if coverage_record:
            selected_autoruns_mode_coverage[artifact] = coverage_record
    selected_statuses = {
        str(
            state.get("artifacts", {})
            .get(artifact, {})
            .get("status")
            or ""
        )
        for artifact in selected_artifacts
    }
    selected_all_complete = (
        bool(selected_statuses)
        and selected_statuses == {"complete"}
    )
    selected_awaiting_autoruns_classification = bool(
        selected_statuses.intersection(
            {
                "awaiting_ai_classification",
                "incomplete_ai_classification",
            }
        )
    )
    selected_result_review_coverage = (
        "complete" if selected_all_complete else "incomplete"
    )
    selected_coverage = (
        "complete"
        if selected_all_complete
        and target_execution_satisfies_review(
            state["target_execution_coverage"]
        )
        and source_terminal
        else "provisional"
        if not source_terminal
        else "provisional"
        if state["target_execution_coverage"] == "provisional"
        else "unknown"
        if state["target_execution_coverage"] == "unknown"
        else "incomplete"
    )
    selected_status = (
        "complete"
        if selected_all_complete
        and target_execution_satisfies_review(
            state["target_execution_coverage"]
        )
        and source_terminal
        else "review_complete_source_non_terminal"
        if selected_all_complete and not source_terminal
        else "review_complete_coverage_unknown"
        if selected_all_complete
        and state["target_execution_coverage"] == "unknown"
        else "review_complete_target_incomplete"
        if selected_all_complete
        else "awaiting_ai_classification"
        if selected_awaiting_autoruns_classification
        else "awaiting_review"
        if review_items
        else "incomplete"
    )
    publish_progress("analyst_review", force=True, groups=len(review_items))
    review_rmm_metadata_streaming(
        state,
        review_items,
        workdir=paths["root"],
        ai_review_enabled=autoruns_ai_review_enabled,
        max_review_tokens=max_review_tokens,
        token_encoding=token_encoding,
        analyst_execution=analyst_execution,
    )
    if not skip_ai and synthesis_mode == "full":
        publish_progress("finding_consolidation", force=True)
        flow_analysis_coordinator.consolidate_specialized_findings(
            state,
            question=question,
            spec=finding_consolidation_spec,
            workdir=hunt_root,
            runtime_dir=paths["root"] / ".runtime-finding-consolidation",
        )
    if skip_ai:
        selected_status = "prepared"
        selected_result_review_coverage = "not_reviewed"
        selected_coverage = "incomplete"
        state.update(ai_review_status="skipped", review_complete=False,
                     status="prepared", result_review_coverage="not_reviewed", coverage="incomplete")
    else:
        state.pop("ai_review_status", None)
        state.pop("review_complete", None)
    if not skip_ai and synthesis_mode == "none":
        state.update(review_status="not_requested", synthesis_mode="none", result_role="preliminary_candidates")
        state.pop("specialized_finding_summary", None)
    elif not skip_ai:
        state.update(synthesis_mode="full")
        state.pop("review_status", None)
        state.pop("result_role", None)
    state["updated_at"] = now_utc()
    publish_progress("publishing", force=True)
    review_files = write_outputs(
        paths,
        state,
        reusable_filters=reusable_filters,
        use_case=use_case,
        ai_review_enabled=autoruns_ai_review_enabled,
        max_review_tokens=max_review_tokens,
        token_encoding=token_encoding,
    )
    suspicious_outputs = write_suspicious_use_case_outputs(
        paths,
        hunt_id=hunt_id,
        review_items=review_items,
    )
    review_items_manifest = write_review_items_manifest(
        paths["review_items_manifest"],
        hunt_id=hunt_id,
        review_items=review_items,
        state=state,
    )
    flow_analysis_coordinator.refresh_canonical_hunt_report(
        hunt_root,
        question=question,
        specialized_state=state,
    )
    validation_debug_path = (
        paths["root"]
        / flow_analysis_coordinator.VALIDATION_DEBUG_FILENAME
    )
    validation_debug_reference: dict[str, Any] = {}
    if debug_validation:
        debug_base = {
            "schema_version": flow_analysis_coordinator.VALIDATION_DEBUG_SCHEMA_VERSION,
            "operation_id": operation_log.current_operation_id(),
            "scope_type": "hunt",
            "scope_id": hunt_id,
            "lane": use_case or "specialized_stack",
            "artifact_diagnostics": [
                {
                    "artifact_sha256": sha256_value(str(artifact)),
                    "status": artifact_state.get("status"),
                    "current_total": int(artifact_state.get("current_total") or 0),
                    "remaining_total": int(artifact_state.get("remaining_total") or 0),
                    "mode": artifact_state.get("mode"),
                }
                for artifact, artifact_state in sorted(
                    state.get("artifacts", {}).items()
                )
                if isinstance(artifact_state, dict)
            ][:512],
            "candidate_output": {
                str(artifact): copy.deepcopy(
                    dict(artifact_state.get("autoruns_residual_workflow") or {}).get(
                        "candidate_output"
                    )
                    or {}
                )
                for artifact, artifact_state in sorted(
                    state.get("artifacts", {}).items()
                )
                if isinstance(artifact_state, dict)
                and dict(artifact_state.get("autoruns_residual_workflow") or {}).get(
                    "candidate_output"
                )
            },
        }
        flow_analysis_coordinator.write_validation_debug(
            validation_debug_path,
            debug_base,
            (),
            status=str(state.get("status") or "complete"),
            completed_at=str(state.get("updated_at") or now_utc()),
        )
        validation_debug_reference = {
            "path": str(validation_debug_path),
            "sha256": sha256_file(validation_debug_path),
            "run_id": str(
                json.loads(validation_debug_path.read_text(encoding="utf-8")).get(
                    "run_id"
                )
                or ""
            ),
            "current_run": True,
        }
    elif validation_debug_path.is_file():
        previous_debug = json.loads(
            validation_debug_path.read_text(encoding="utf-8")
        )
        validation_debug_reference = {
            "path": str(validation_debug_path),
            "sha256": sha256_file(validation_debug_path),
            "run_id": str(previous_debug.get("run_id") or ""),
            "current_run": False,
        }
    persistence_manifest = persistence_policy.audit_analysis_tree(
        paths["root"],
        state,
        extra_files=[paths["analysis_memory"]],
    )
    persisted_state = copy.deepcopy(state)
    persisted_state["source_identifiers"] = list(
        state["source_identifiers"]
    )
    persisted_state["coverage_state"] = dict(state["coverage_state"])
    persisted_state["persistence_manifest"] = persistence_manifest
    if review_items_manifest:
        persisted_state["review_items"] = {
            "path": f"analysis/{paths['review_items_manifest'].name}",
            "sha256": sha256_file(paths["review_items_manifest"]),
            "count": len(review_items),
        }
    else:
        persisted_state.pop("review_items", None)
    if validation_debug_reference:
        persisted_state["last_validation_debug"] = validation_debug_reference
    else:
        persisted_state.pop("last_validation_debug", None)
    write_canonical_specialized_state(paths["state"], persisted_state)
    selected_autoruns_context_details = {
        artifact: rows
        for artifact, rows in autoruns_context_items_for_state(
            state
        ).items()
        if artifact in selected_artifacts
    }
    selected_output_paths = analysis_output_paths(
        paths,
        use_case=use_case,
    )
    autoruns_chat_summary = render_autoruns_chat_summary(
        state,
        autoruns_context_details=selected_autoruns_context_details,
        selected_artifacts=selected_artifacts,
    )
    analysis_chat_summary = render_generic_stack_chat_summary(
        state,
        selected_artifacts=selected_artifacts,
    )
    chat_summary = "\n\n".join(
        value.strip()
        for value in (autoruns_chat_summary, analysis_chat_summary)
        if value.strip()
    )
    if not chat_summary:
        target_summary = (
            ""
            if autoruns_reporting.hide_unassessed_target_execution(
                {**state, "selected_artifacts": selected_artifacts}
            )
            else f"- Target execution: `{state['target_execution_coverage']}`\n"
        )
        chat_summary = (
            "## Hunt analysis summary\n\n"
            f"- Hunt: `{hunt_id}`\n"
            f"- Status: `{selected_status}`\n"
            f"- Result review: `{selected_result_review_coverage}`\n"
            f"{target_summary}\n"
            "No specialized findings summary was returned. Consult the canonical "
            "analysis report for coverage and next actions.\n"
        )
    if skip_ai:
        chat_summary = f"Hunt {hunt_id}: deterministic stack preparation finished; AI review skipped."
    elif synthesis_mode == "none":
        chat_summary = "Preliminary candidates; final synthesis not requested. Caller review required.\n\n" + chat_summary
    publish_progress("analysis_complete", status=selected_status, force=True)
    return {
        "action": "live_hunt_analysis",
        "synthesis_mode": synthesis_mode,
        **({"review_status": "not_requested"} if synthesis_mode == "none" else {}),
        **({"ai_review_status": "skipped", "review_complete": False} if skip_ai else {}),
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "group": group,
        "hunt_state": hunt_state,
        "task_mode": normalized_task_mode,
        "response_depth": normalized_response_depth,
        "selected_artifacts": selected_artifacts,
        "status": selected_status,
        "coverage": selected_coverage,
        "result_review_coverage": selected_result_review_coverage,
        "target_execution_coverage": state["target_execution_coverage"],
        "review_scope": state["review_scope"],
        "coverage_state": dict(state["coverage_state"]),
        "persistence_manifest": persistence_manifest,
        "host_execution": dict(state.get("host_execution") or {}),
        "artifact_policy": resolved_policy.metadata(),
        "autoruns_mode_coverage": selected_autoruns_mode_coverage,
        "direct_row_limit": direct_row_limit,
        "use_case": use_case,
        "autoruns_golden": {
            **autoruns_golden_general_metadata(
                autoruns_golden_configuration
            )
        },
        "autoruns_golden_db": (
            str(autoruns_golden_db)
            if autoruns_golden_db
            else ""
        ),
        "golden_promotion_count": len(
            state.get("golden_promotions") or []
        ),
        "autoruns_residual_workflow": {
            artifact: compact_autoruns_workflow(
                dict(
                    state.get("artifacts", {})
                    .get(artifact, {})
                    .get("autoruns_residual_workflow")
                    or {}
                )
            )
            for artifact in selected_artifacts
            if isinstance(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("autoruns_residual_workflow"),
                dict,
            )
        },
        "streaming_stacks": {
            artifact: dict(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("streaming_stack")
                or {}
            )
            for artifact in selected_artifacts
            if isinstance(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("streaming_stack"),
                dict,
            )
        },
        "stack_discovery": {
            artifact: dict(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("stack_discovery")
                or {}
            )
            for artifact in selected_artifacts
            if isinstance(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("stack_discovery"),
                dict,
            )
        },
        "autoruns_focused_workflows": {
            artifact: {
                str(mode): compact_autoruns_workflow(dict(workflow))
                for mode, workflow in dict(
                    state.get("artifacts", {})
                    .get(artifact, {})
                    .get("autoruns_focused_workflows")
                    or {}
                ).items()
                if isinstance(workflow, dict)
            }
            for artifact in selected_artifacts
            if isinstance(
                state.get("artifacts", {})
                .get(artifact, {})
                .get("autoruns_focused_workflows"),
                dict,
            )
        },
        "chat_summary": chat_summary,
        "autoruns_chat_summary": autoruns_chat_summary,
        "analysis_chat_summary": analysis_chat_summary,
        "stack_analysis_complete": bool(
            selected_artifacts
            and all(
                int(
                    dict(
                        state.get("artifacts", {})
                        .get(artifact, {})
                        .get("streaming_stack")
                        or {}
                    ).get("represented_row_count")
                    or 0
                )
                == int(
                    state.get("artifacts", {})
                    .get(artifact, {})
                    .get("current_total")
                    or 0
                )
                and int(
                    state.get("artifacts", {})
                    .get(artifact, {})
                    .get("current_total")
                    or 0
                )
                > 0
                and not dict(
                    state.get("artifacts", {}).get(artifact, {}).get("streaming_stack") or {}
                ).get("excluded_group_count")
                for artifact in selected_artifacts
            )
        ),
        "operator_review_required": bool(review_items),
        "finding_consolidation": {
            key: value
            for key, value in dict(
                state.get("specialized_finding_summary") or {}
            ).items()
            if key
            in {
                "mode",
                "status",
                "source_group_count",
                "covered_source_group_count",
                "limitations",
                "manager",
            }
        },
        "review_item_count": len(review_items),
        "review_items_returned": (
            len(review_items)
            if include_review_rows
            else min(len(review_items), REPORT_MAX_RESPONSE_REVIEW_ITEMS)
        ),
        "review_items_omitted_from_response": (
            0
            if include_review_rows
            else max(
                len(review_items) - REPORT_MAX_RESPONSE_REVIEW_ITEMS,
                0,
            )
        ),
        "review_rows_included": include_review_rows,
        "review_items": review_items_for_response(
            review_items,
            include_review_rows=include_review_rows,
        ),
        "review_items_file": review_items_manifest,
        "review_files": review_files,
        "state_file": str(paths["state"]),
        "filters_file": (
            str(selected_output_paths["filters"])
            if selected_output_paths["filters"].is_file()
            else ""
        ),
        "analysis_file": str(paths["analysis_memory"]),
        "suspicious_output_files": suspicious_outputs,
        "raw_evidence_persisted": any(
            bool(record.get("raw_rows"))
            for record in persistence_manifest["files"]
        ),
        "raw_result_exported": bool(
            persistence_manifest["raw_result_export_count"]
        ),
        "snapshot_created": False,
    }
