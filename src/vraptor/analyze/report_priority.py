"""Explicit report priority, independent of evidence confidence.

Priority controls presentation only. Ranking never removes findings or changes
their evidence, confidence, dispositions, or collection/review coverage.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

SCHEMA_VERSION = 1
PRIORITIES = ("critical", "high", "medium", "low")
# Retain saved classifications. Missing assessment stays above explicitly low items.
RETAINED_PRIORITIES = ("critical", "high", "medium", "unranked", "low", "informational")
_RANK = {value: index for index, value in enumerate(RETAINED_PRIORITIES)}


def priority_metadata(finding: Mapping[str, Any]) -> dict[str, str]:
    """Read explicit priority or a recognized legacy severity; never confidence."""
    raw = finding.get("report_priority")
    rationale = str(finding.get("priority_rationale") or "").strip()
    if raw is None:
        review = finding.get("ai_review")
        review = review if isinstance(review, Mapping) else {}
        raw = finding.get("severity", finding.get("Severity", review.get("severity")))
        severity = str(raw or "").strip().casefold()
        if severity == "info":
            severity = "informational"
        if severity in _RANK and severity != "unranked":
            return {
                "report_priority": severity,
                "priority_rationale": rationale or f"Existing explicit severity: {severity}.",
            }
    value = str(raw or "").strip().casefold()
    return {
        "report_priority": value if value in _RANK else "unranked",
        "priority_rationale": rationale,
    }


def _canonical_value(value: Any) -> Any:
    """Normalize unordered containers found in specialized report groups."""
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(
            (_canonical_value(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False, default=str),
        )
    return value


def display_priority(finding: Mapping[str, Any]) -> str:
    """Render the internal missing-priority sentinel without changing saved data."""
    level = priority_metadata(finding)["report_priority"]
    return "Not assessed" if level == "unranked" else level


def priority_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    """Stable ordering within priority, without arrival order or confidence ranking."""
    metadata = priority_metadata(finding)
    # Canonical content only breaks otherwise identical identities. It never
    # upgrades priority because a confidence label or raw row count is higher.
    canonical = json.dumps(
        _canonical_value({key: value for key, value in finding.items() if key != "confidence"}),
        sort_keys=True, ensure_ascii=False, default=str,
    )
    identifier = str(finding.get("id") or finding.get("finding_id") or "")
    natural_id = tuple(
        (1, int(part)) if part.isdecimal() else (0, part.casefold())
        for part in re.split(r"([0-9]+)", identifier)
    )
    return (
        _RANK[metadata["report_priority"]],
        natural_id,
        identifier,
        str(finding.get("artifact") or ""),
        canonical,
    )


def rank_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return every finding with normalized metadata in deterministic order."""
    return sorted(
        ({**finding, **priority_metadata(finding)} for finding in findings),
        key=priority_key,
    )


def validated_priority(
    level: str, rationale: str, *, allow_legacy: bool = False,
) -> dict[str, str]:
    """Validate new output strictly; allow retained labels only during recovery."""
    level = level.strip().casefold()
    allowed = RETAINED_PRIORITIES if allow_legacy else PRIORITIES
    if level not in allowed or not rationale.strip():
        raise ValueError("PRIORITY requires " + ", ".join(allowed) + " and a nonempty rationale")
    return {"report_priority": level, "priority_rationale": rationale.strip()}


def prompt_instruction() -> str:
    return (
        "For each FINDING emit PRIORITY\t<finding ID>\t"
        "<critical|high|medium|low>\t<concise rationale> "
        "after its FINDING record. Reporting priority is incident urgency/impact and "
        "relevance to the question, not evidence confidence or detection severity alone. "
        "Use critical for evidence-supported immediate severe impact or urgent containment; "
        "high for material incident impact requiring prompt action; medium for material "
        "investigation work; low for limited-impact follow-up. Do not emit informational "
        "or unranked as new priorities. Put new informational observations in relevant "
        "CONTEXT when permitted by the context/reference contract; do not invent a "
        "finding or change evidence roles just to attach context. Legacy classifications "
        "in accepted inputs remain retained in their source records. Explain the "
        "priority using cited evidence and uncertainty. Do not invent business impact, "
        "treat file presence as execution, or equate high confidence with high priority. "
        "Priority changes presentation only and must not remove supported findings.\n"
    )
