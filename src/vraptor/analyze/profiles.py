"""Validated collection-level analysis profile and artifact strategy routing."""

from __future__ import annotations
from vraptor.resources import resource_root

import json
from pathlib import Path
from typing import Any, Iterable

from vraptor.agent.profiles import PROFILE_NAMES
from vraptor.agent.profiles import RESPONSE_DEPTH_NAMES
from vraptor.agent.profiles import load_agent_profile_config
from vraptor.agent.profiles import normalize_profile_name
from vraptor.agent.profiles import normalize_response_depth as normalize_agent_response_depth
from vraptor.collect.catalog import IR_COLLECTION_BUNDLES
from vraptor.collect.catalog import IR_COLLECTION_GROUPS
from vraptor.collect.catalog import SUPPORTED_COLLECTION_TYPES


SCHEMA_VERSION = 1
RESOURCE_PATH = (
    resource_root()
    / "collection-analysis-profiles.json"
)
PROFILE_IDS = {
    "generic",
    "detectraptor-host",
    "timeline",
    "ir-standard-host",
    "volatile-state",
    "execution-history",
    "identity-state",
    "persistence-state",
    "authentication-lateral",
    "script-execution",
    "defense-evasion",
}
STRATEGY_IDS = {"autoruns-goldendb"}
TASK_MODES = frozenset(PROFILE_NAMES)
RESPONSE_DEPTHS = frozenset(RESPONSE_DEPTH_NAMES)


def normalize_task_mode(value: str | None) -> str:
    return normalize_profile_name(value)


def normalize_response_depth(value: str | None) -> str:
    return normalize_agent_response_depth(value)


def response_depth_policy(
    response_depth: str | None,
    *,
    task_mode: str | None = None,
) -> dict[str, str]:
    mode = normalize_task_mode(task_mode)
    if mode and mode not in TASK_MODES:
        raise ValueError(
            f"Unknown task mode {task_mode!r}; expected incident-response, targeted-hunt, "
            "host-forensics, or compromise-assessment."
        )
    default_depth = (
        load_agent_profile_config().profiles[mode].default_depth
        if mode
        else "standard"
    )
    depth = normalize_response_depth(response_depth) or default_depth
    if depth not in RESPONSE_DEPTHS:
        raise ValueError(
            f"Unknown response depth {response_depth!r}; expected rapid, standard, or deep."
        )
    contract = load_agent_profile_config().response_depths[depth]
    return {
        "depth": depth,
        "description": contract.description,
        "output": contract.output_contract,
    }


def question_relevance_policy(
    question: str,
    *,
    task_mode: str | None = None,
) -> dict[str, str]:
    """Return deterministic inclusion rules for the exact investigation question."""
    normalized = " ".join(str(question).casefold().split())
    mode = normalize_task_mode(task_mode)
    if mode and mode not in TASK_MODES:
        raise ValueError(
            f"Unknown task mode {task_mode!r}; expected incident-response, targeted-hunt, "
            "host-forensics, or compromise-assessment."
        )
    if mode == "compromise_assessment":
        return {
            "mode": mode,
            "include": (
                "Describe the assessed environment and coverage, retain prevalence and baseline context, "
                "and return rare or anomalous activity as candidate leads for exact validation."
            ),
            "context": (
                "Retain useful host, user, management-tool, software, authentication, and network context "
                "even when it is not independently suspicious."
            ),
            "exclude": (
                "Omit unsupported compromise conclusions and do not equate rarity, administrative capability, "
                "or remote-management software with maliciousness."
            ),
        }
    if mode == "host_forensics":
        return {
            "mode": mode,
            "include": (
                "Return material host activity in UTC chronological order and findings that answer the exact host question."
            ),
            "context": (
                "For each finding retain available username/account/SID, logon/session, parent-child process, "
                "path/hash/signer, network tuple, timestamp, and exact source reference."
            ),
            "exclude": "Omit routine inventory that does not establish chronology, interpretation, or a bounded follow-up.",
        }
    if mode == "targeted_hunt":
        return {
            "mode": mode,
            "include": "Return exact matches, non-hits, affected hosts and users, prevalence, and supporting references for the declared seed or hypothesis.",
            "context": "Retain context only when it validates identity, scope, confidence, or the next exact pivot.",
            "exclude": "Do not broaden into generic environment discovery or unrelated anomaly review.",
        }
    if mode == "incident_response":
        return {
            "mode": mode,
            "include": "Return evidence that advances the bounded incident hypothesis, impact assessment, scope, or chronology.",
            "context": "Attach available identity and causal context to the finding it explains and retain exact provenance.",
            "exclude": "Do not broaden host, artifact, user, IOC, or time scope without an explicit case task.",
        }
    landscape_terms = (
        "host landscape",
        "rmm",
        "remote management",
        "remote access software",
        "greyware",
        "software inventory",
        "administrative capability",
        "administration context",
    )
    persistence_terms = (
        "persistence",
        "autorun",
        "auto-start",
        "autostart",
        "scheduled task",
        "startup item",
    )
    maliciousness_terms = ("malicious", "suspicious", "compromise", "threat")
    if any(term in normalized for term in landscape_terms):
        return {
            "mode": "landscape",
            "include": (
                "Return host landscape, RMM, remote-access, greyware, security tooling, "
                "and administrative context that answers the question."
            ),
            "context": "Retain useful management context even when it is not suspicious.",
            "exclude": "Omit unrelated artifact detail and routine rows that do not describe the requested landscape.",
        }
    if any(term in normalized for term in persistence_terms):
        return {
            "mode": "persistence",
            "include": (
                "Return only persistence mechanisms, suspicious persistence candidates, "
                "directly explanatory context, limitations, and bounded validation steps."
            ),
            "context": "Keep benign context only when it explains a persistence-looking signal.",
            "exclude": "Omit unrelated execution, network, inventory, and ordinary system-component rows.",
        }
    if not normalized or any(term in normalized for term in maliciousness_terms):
        return {
            "mode": "maliciousness",
            "include": (
                "Return only malicious, suspicious, or materially unresolved findings; "
                "their required evidence components; confidence limitations; and bounded follow-up."
            ),
            "context": (
                "Return benign explanations only when they directly explain a suspicious-looking signal. "
                "Return landscape, RMM, greyware, or administration context only when it materially changes a finding."
            ),
            "exclude": (
                "Omit ordinary system components, routine software inventory, expected services or tasks, "
                "generic host landscape, and unrelated benign activity."
            ),
        }
    return {
        "mode": "targeted",
        "include": "Return only evidence and conclusions that directly answer the exact targeted question.",
        "context": "Retain context only when it changes confidence, priority, or a specific follow-up.",
        "exclude": "Omit all artifact content outside the target and all generic host-landscape commentary.",
    }


def load_registry(path: Path | None = None) -> dict[str, Any]:
    source = path or RESOURCE_PATH
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid collection analysis profile registry: {source}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(f"Unsupported collection analysis profile registry: {source}")
    default_profile = str(payload.get("default_profile") or "")
    profiles = payload.get("profiles")
    collection_profiles = payload.get("collection_profiles")
    artifact_strategies = payload.get("artifact_strategies")
    if default_profile not in PROFILE_IDS or not isinstance(profiles, dict):
        raise RuntimeError("Collection analysis registry has an invalid default profile")
    if set(profiles) != PROFILE_IDS:
        raise RuntimeError("Collection analysis registry profile ids are incomplete")
    for profile_id, profile in profiles.items():
        objectives = profile.get("objectives") if isinstance(profile, dict) else None
        if not isinstance(objectives, list) or not objectives or any(
            not isinstance(value, str) or not value.strip() for value in objectives
        ):
            raise RuntimeError(
                f"Collection analysis profile {profile_id} has invalid objectives"
            )
    if not isinstance(collection_profiles, dict):
        raise RuntimeError("collection_profiles must be an object")
    required_collection_profiles = {
        *SUPPORTED_COLLECTION_TYPES,
        *IR_COLLECTION_GROUPS,
        *IR_COLLECTION_BUNDLES,
    }
    if set(collection_profiles) != required_collection_profiles:
        raise RuntimeError(
            "collection_profiles must cover every supported collection type, "
            "IR group, and IR bundle"
        )
    if any(str(value) not in PROFILE_IDS for value in collection_profiles.values()):
        raise RuntimeError("collection_profiles contains an unknown profile id")
    if not isinstance(artifact_strategies, dict):
        raise RuntimeError("artifact_strategies must be an object")
    if any(str(value) not in STRATEGY_IDS for value in artifact_strategies.values()):
        raise RuntimeError("artifact_strategies contains an unknown strategy id")
    return payload


def resolve_analysis_profile(
    collection_type: str,
    *,
    registry: dict[str, Any] | None = None,
) -> str:
    selected = registry or load_registry()
    return str(
        selected["collection_profiles"].get(
            collection_type,
            selected["default_profile"],
        )
    )


def resolve_artifact_strategies(
    artifacts: Iterable[str],
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, str]:
    selected = registry or load_registry()
    configured = dict(selected["artifact_strategies"])
    return {
        str(artifact): str(configured[str(artifact)])
        for artifact in artifacts
        if str(artifact) in configured
    }


def profile_contract(
    collection_type: str,
    artifacts: Iterable[str],
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected = registry or load_registry()
    profile_id = resolve_analysis_profile(collection_type, registry=selected)
    profile = dict(selected["profiles"][profile_id])
    return {
        "analysis_profile": profile_id,
        "analysis_profile_reference": str(profile.get("reference") or ""),
        "analysis_profile_purpose": str(profile.get("purpose") or ""),
        "analysis_objectives": [
            str(value).strip() for value in profile.get("objectives") or []
        ],
        "artifact_strategies": resolve_artifact_strategies(
            artifacts,
            registry=selected,
        ),
    }
