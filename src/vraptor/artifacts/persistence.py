"""Executable persistence and closure policy for live Velociraptor analysis."""

from __future__ import annotations

from vraptor.resources import resource_root

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from vraptor.common.hashing import sha256_file as _file_sha256


POLICY_VERSION = 5
POLICY_PATH = (
    resource_root() / "contracts"
    / "velociraptor-persistence-policy.json"
)
TERMINAL_HUNT_STATES = {"FINISHED", "STOPPED"}
TERMINAL_FLOW_STATES = {"FINISHED"}
RAW_RESULT_SUFFIXES = {".csv", ".jsonl"}
DEFAULT_COMPACT_MARKDOWN_MAX_BYTES = 512 * 1024
PREVIOUS_ANALYSIS_DIRECTORY = "previous-analysis"
PREVIOUS_ANALYSIS_RUN_PATTERN = re.compile(
    r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$"
)
AGENT_EVENT_FIELDS = {
    "type",
    "task_id",
    "provider",
    "model",
    "protocol",
    "timestamp",
    "attempt",
    "request_id",
    "metadata",
}
AGENT_EVENT_TYPES = {
    "output_progress",
    "request_accepted",
    "request_cancelled",
    "request_completed",
    "request_failed",
    "request_started",
    "request_timed_out",
    "retry_scheduled",
    "usage_updated",
}
AGENT_EVENT_METADATA_FIELDS = {
    "cached_input_tokens",
    "characters",
    "delay_seconds",
    "error_classification",
    "input_tokens",
    "finish_reason",
    "local_output_tokens",
    "max_output_tokens_requested",
    "max_output_tokens_sent",
    "output_tokens",
    "provider_error_code",
    "provider_error_param",
    "provider_status",
    "retry_after_seconds",
    "retryable",
    "total_tokens",
}


class PersistencePolicyError(RuntimeError):
    """Raised when analysis attempts unsupported persistence or closure."""


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if int(payload.get("version") or 0) != POLICY_VERSION:
        raise PersistencePolicyError(
            f"Unsupported Velociraptor persistence policy in {path}."
        )
    return payload


def authorize_persistence(
    classification: str,
    *,
    source_ids: Iterable[str],
    raw_rows: bool = False,
    explicit_export: bool = False,
    complete_accounting: bool = False,
    bounded: bool = False,
    exact: bool = False,
    finding_ids: Iterable[str] = (),
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one requested persistence operation against the policy."""
    active_policy = policy or load_policy()
    classes = dict(active_policy.get("persistence_classes") or {})
    rule = dict(classes.get(classification) or {})
    if not rule:
        raise PersistencePolicyError(
            f"Unknown persistence classification {classification!r}."
        )
    normalized_sources = sorted(
        {str(value).strip() for value in source_ids if str(value).strip()}
    )
    normalized_findings = sorted(
        {str(value).strip() for value in finding_ids if str(value).strip()}
    )
    if rule.get("denied_in_live_analysis"):
        raise PersistencePolicyError(
            "Raw Velociraptor result persistence is denied during live analysis."
        )
    if bool(raw_rows) != bool(rule.get("raw_rows")):
        raise PersistencePolicyError(
            f"Persistence class {classification!r} does not match raw_rows="
            f"{bool(raw_rows)}."
        )
    requirements = (
        ("requires_source_ids", bool(normalized_sources), "source identifiers"),
        (
            "requires_explicit_export",
            bool(explicit_export),
            "an explicit export request",
        ),
        (
            "requires_complete_accounting",
            bool(complete_accounting),
            "complete aggregate accounting",
        ),
        ("requires_bounded", bool(bounded), "a bounded review set"),
        ("requires_exact", bool(exact), "exact source context"),
        ("requires_finding_ids", bool(normalized_findings), "finding identifiers"),
    )
    for key, satisfied, label in requirements:
        if rule.get(key) and not satisfied:
            raise PersistencePolicyError(
                f"Persistence class {classification!r} requires {label}."
            )
    return {
        "policy_version": int(active_policy["version"]),
        "classification": classification,
        "raw_rows": bool(raw_rows),
        "source_ids": normalized_sources,
        "finding_ids": normalized_findings,
        "explicit_export": bool(explicit_export),
        "complete_accounting": bool(complete_accounting),
        "bounded": bool(bounded),
        "exact": bool(exact),
    }


def _walk_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)


def _walk_mappings(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def source_identifiers(state: dict[str, Any]) -> list[str]:
    source_type = str(state.get("source_type") or "hunt")
    if source_type == "collection":
        identifiers: list[str] = []
        client_id = str(state.get("client_id") or "").strip()
        for artifact, source in sorted(
            (state.get("collection_sources") or {}).items()
        ):
            if not isinstance(source, dict):
                continue
            flow_id = str(source.get("flow_id") or "").strip()
            component = str(
                source.get("result_component")
                or source.get("artifact_name")
                or artifact
            ).strip()
            if client_id and flow_id:
                identifiers.append(f"flow:{client_id}:{flow_id}:{component}")
        return identifiers
    hunt_id = str(state.get("hunt_id") or "").strip()
    if not hunt_id:
        return []
    artifacts = sorted(
        str(artifact)
        for artifact in (state.get("artifacts") or {})
        if str(artifact)
    )
    return [f"hunt:{hunt_id}:{artifact}" for artifact in artifacts] or [
        f"hunt:{hunt_id}"
    ]


def coverage_record(state: dict[str, Any]) -> dict[str, Any]:
    """Build normalized coverage and fail-closed closure metadata."""
    source_type = str(state.get("source_type") or "hunt")
    blockers: list[str] = []
    if source_type == "collection":
        sources = [
            source
            for source in (state.get("collection_sources") or {}).values()
            if isinstance(source, dict)
        ]
        terminal = bool(sources) and all(
            str(source.get("flow_state") or "").upper()
            in TERMINAL_FLOW_STATES
            for source in sources
        )
        execution_coverage = str(
            state.get("flow_execution_coverage") or "unknown"
        )
    else:
        terminal = (
            str(state.get("hunt_state") or "").upper()
            in TERMINAL_HUNT_STATES
        )
        execution_coverage = str(
            state.get("target_execution_coverage") or "unknown"
        )
    if not terminal:
        blockers.append("source_non_terminal")
    execution_satisfies_scope = execution_coverage == "complete" or (
        source_type == "hunt"
        and str(state.get("review_scope") or "") == "ad_hoc_review"
        and execution_coverage == "not_assessed"
    )
    if not execution_satisfies_scope:
        blockers.append("target_scope_incomplete")
    result_review = str(state.get("result_review_coverage") or "unknown")
    if result_review != "complete":
        blockers.append("result_review_incomplete")

    sampled = False
    truncated = False
    token_limited = False
    group_truncated = False
    for record in _walk_mappings(state.get("artifacts") or {}):
        if str(record.get("kind") or "").casefold() == "sample":
            sampled = True
        query = record.get("query")
        if isinstance(query, dict) and query.get("truncated") is True:
            truncated = True
    for key, value in _walk_values(state.get("artifacts") or {}):
        normalized = key.casefold().replace("-", "_")
        if normalized == "sampled" and value is True:
            sampled = True
        if normalized == "truncated" and value is True:
            truncated = True
        if normalized == "group_truncated" and value is True:
            group_truncated = True
        if normalized == "budget_stop" and isinstance(value, dict) and value:
            token_limited = True
        if normalized == "outcome" and str(value) in {
            "token_limit_reached",
            "first_row_oversized",
            "shared_budget_exhausted",
        }:
            token_limited = True
    for enabled, blocker in (
        (sampled, "sampled"),
        (truncated, "truncated"),
        (token_limited, "token_limited"),
        (group_truncated, "group_truncated"),
    ):
        if enabled:
            blockers.append(blocker)
    blockers = list(dict.fromkeys(blockers))
    complete_claim_allowed = not blockers
    overall = str(state.get("coverage") or "unknown")
    if overall not in {"complete", "partial", "unknown", "failed", "not_applicable"}:
        overall = "partial" if overall in {"incomplete", "provisional"} else "unknown"
    return {
        "policy_version": POLICY_VERSION,
        "source_type": source_type,
        "source_ids": source_identifiers(state),
        "source_terminal": terminal,
        "execution_coverage": execution_coverage,
        "result_review_coverage": result_review,
        "overall": overall,
        "sampled": sampled,
        "truncated": truncated,
        "token_limited": token_limited,
        "group_truncated": group_truncated,
        "closure_blockers": blockers,
        "complete_claim_allowed": complete_claim_allowed,
    }


def enforce_closure(state: dict[str, Any]) -> dict[str, Any]:
    coverage = coverage_record(state)
    state["source_identifiers"] = coverage["source_ids"]
    state["coverage_state"] = coverage
    claims_complete = (
        str(state.get("coverage") or "") == "complete"
        or str(state.get("status") or "") == "complete"
    )
    if claims_complete and not coverage["complete_claim_allowed"]:
        raise PersistencePolicyError(
            "Analysis cannot claim complete coverage: "
            + ", ".join(coverage["closure_blockers"])
        )
    return coverage


def _csv_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.startswith("#"):
                break
            key, separator, value = line[1:].partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
    except (OSError, UnicodeError):
        return {}
    return metadata


def _finding_ids_for_path(path: Path, metadata: dict[str, str]) -> list[str]:
    identities = (
        metadata.get("SuspiciousIdentityCount")
        or metadata.get("ContextRowCount")
        or metadata.get("ScopeRowCount")
        or ""
    )
    if identities:
        return [f"finding-set:{path.stem}:{identities}"]
    if path.suffix.casefold() == ".md":
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        return sorted(
            {
                value.strip()
                for matched in re.findall(r"^- Supports:\s*(.+)$", text, flags=re.M)
                for value in matched.split(",")
                if value.strip()
            }
        )
    if path.suffix.casefold() == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [
            str(item.get("id") or "")
            for item in payload.get("items") or []
            if isinstance(item, dict) and str(item.get("id") or "")
        ]
    return []


def _markdown_content_profile(
    path: Path,
    *,
    finding_ids: Iterable[str],
    max_compact_bytes: int,
) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PersistencePolicyError(
            f"Unable to inspect Markdown persistence content: {path.name}."
        ) from exc
    exact_markers = bool(list(finding_ids)) and bool(
        re.search(r"^- Supports:\s*\S", text, flags=re.M)
    )
    if exact_markers:
        return "manager_selected_exact_context"
    raw_row_markers = (
        "#### Suspicious host and persistence context" in text
        or (
            text.count("- Launch:") >= 2
            and text.count("- Endpoint:") >= 2
        )
        or (
            "## Selected full evidence" in text
            and "````json" in text
        )
        or bool(re.search(r"^### Evidence \d+\s*$", text, flags=re.M))
    )
    if raw_row_markers:
        raise PersistencePolicyError(
            f"Markdown {path.name} contains exact row-shaped evidence without "
            "manager-selected finding identifiers."
        )
    size = path.stat().st_size
    if size > max_compact_bytes:
        raise PersistencePolicyError(
            f"Compact Markdown {path.name} exceeds the {max_compact_bytes}-byte "
            "content guard."
        )
    return "compact_human_summary"


def _json_contains_row_payload(value: Any) -> bool:
    if isinstance(value, list):
        return any(_json_contains_row_payload(item) for item in value)
    if not isinstance(value, dict):
        return False
    for key, child in value.items():
        normalized = re.sub(r"[^a-z]", "", str(key).casefold())
        if normalized in {"rows", "rawrows", "resultrows"} and isinstance(
            child,
            list,
        ) and any(isinstance(item, dict) for item in child):
            return True
        if _json_contains_row_payload(child):
            return True
    return False


def _json_content_profile(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PersistencePolicyError(
            f"Unable to inspect JSON persistence content: {path.name}."
        ) from exc
    if _json_contains_row_payload(payload):
        raise PersistencePolicyError(
            f"JSON {path.name} contains inline row payloads but is classified as "
            "compact state."
        )
    return "compact_structured_state"


def _validate_previous_analysis_path(relative: str) -> None:
    parts = Path(relative).parts
    if not parts or parts[0] != PREVIOUS_ANALYSIS_DIRECTORY:
        return
    if (
        len(parts) != 3
        or PREVIOUS_ANALYSIS_RUN_PATTERN.fullmatch(parts[1]) is None
    ):
        raise PersistencePolicyError(
            "Previous analysis files must use "
            "previous-analysis/<UTC timestamp>-<random id>/<bundle file>: "
            f"{relative}"
        )


def _agent_event_log_content_profile(
    path: Path,
    *,
    maximum_bytes: int,
    maximum_events: int,
) -> str:
    if path.stat().st_size > maximum_bytes:
        raise PersistencePolicyError(
            f"Agent event log {path.name} exceeds the {maximum_bytes}-byte "
            "content guard."
        )
    event_count = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                event_count += 1
                if event_count > maximum_events:
                    raise PersistencePolicyError(
                        f"Agent event log {path.name} exceeds the "
                        f"{maximum_events}-event content guard."
                    )
                event = json.loads(line)
                if not isinstance(event, dict) or set(event) != AGENT_EVENT_FIELDS:
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} does not use "
                        "the normalized event schema."
                    )
                if event.get("type") not in AGENT_EVENT_TYPES:
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} contains an "
                        "unsupported event type."
                    )
                metadata = event.get("metadata")
                if not isinstance(metadata, dict) or not set(metadata).issubset(
                    AGENT_EVENT_METADATA_FIELDS
                ):
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} contains "
                        "unsupported metadata fields."
                    )
                string_fields = (
                    "type",
                    "task_id",
                    "provider",
                    "model",
                    "protocol",
                    "timestamp",
                    "request_id",
                )
                if any(
                    not isinstance(event.get(field), str)
                    or len(str(event.get(field))) > 512
                    for field in string_fields
                ):
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} contains "
                        "invalid or oversized identifiers."
                    )
                if not isinstance(event.get("attempt"), int) or int(
                    event["attempt"]
                ) <= 0:
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} contains an "
                        "invalid attempt number."
                    )
                if any(
                    isinstance(value, (dict, list, tuple, set))
                    or (isinstance(value, str) and len(value) > 512)
                    for value in metadata.values()
                ):
                    raise PersistencePolicyError(
                        f"Agent event log {path.name}:{line_number} contains "
                        "unbounded metadata values."
                    )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PersistencePolicyError(
            f"Unable to inspect agent event log content: {path.name}."
        ) from exc
    if event_count == 0:
        raise PersistencePolicyError(f"Agent event log {path.name} is empty.")
    return "bounded_agent_runtime_events"


def classify_analysis_file(
    path: Path,
    *,
    analysis_root: Path,
    source_ids: Iterable[str],
) -> dict[str, Any]:
    relative = path.relative_to(analysis_root).as_posix()
    name = path.name.casefold()
    policy = load_policy()
    _validate_previous_analysis_path(relative)
    metadata = _csv_metadata(path) if path.suffix.casefold() == ".csv" else {}
    if relative == "state.json" or relative.startswith("autoruns_ai_review/"):
        raise PersistencePolicyError(
            f"Legacy Autoruns live-analysis output is not permitted: {relative}"
        )
    if name in {
        "suspicious_lolbins.json",
        "suspicious_rmm.json",
        "suspicious_unverified.json",
    }:
        raise PersistencePolicyError(
            f"Legacy Autoruns live-analysis output is not permitted: {relative}"
        )
    self_referential = relative == "hunt-analysis-state.json"
    common = {
        "path": relative,
        "sha256": "" if self_referential else _file_sha256(path),
        "size": None if self_referential else path.stat().st_size,
    }
    if self_referential:
        common["self_referential"] = True
    if name.endswith(".events.jsonl"):
        event_policy = dict(
            policy["persistence_classes"]["bounded_agent_runtime_events"]
        )
        return {
            **common,
            "content_profile": _agent_event_log_content_profile(
                path,
                maximum_bytes=int(event_policy["maximum_bytes"]),
                maximum_events=int(event_policy["maximum_events"]),
            ),
            **authorize_persistence(
                "bounded_agent_runtime_events",
                source_ids=source_ids,
                bounded=True,
                policy=policy,
            ),
        }
    if name in {
        "hunt-analysis-validation-debug.json",
        "host-analysis-validation-debug.json",
    }:
        return {
            **common,
            "content_profile": _json_content_profile(path),
            **authorize_persistence(
                "bounded_validation_debug",
                source_ids=source_ids,
                bounded=True,
            ),
        }
    if path.suffix.casefold() in {".md", ".json"}:
        finding_ids = _finding_ids_for_path(path, metadata)
        if name.startswith("suspicious_") or (
            finding_ids
            and (
                name == "finding-evidence.md"
                or "artifact-analysis/" in relative.casefold()
            )
        ):
            return {
                **common,
                "content_profile": (
                    _markdown_content_profile(
                        path,
                        finding_ids=finding_ids,
                        max_compact_bytes=int(
                            policy.get("compact_markdown_max_bytes")
                            or DEFAULT_COMPACT_MARKDOWN_MAX_BYTES
                        ),
                    )
                    if path.suffix.casefold() == ".md"
                    else "exact_structured_context"
                ),
                **authorize_persistence(
                    "exact_suspicious_context",
                    source_ids=source_ids,
                    raw_rows=True,
                    exact=True,
                    finding_ids=finding_ids,
                ),
            }
        content_profile = (
            _markdown_content_profile(
                path,
                finding_ids=finding_ids,
                max_compact_bytes=int(
                    policy.get("compact_markdown_max_bytes")
                    or DEFAULT_COMPACT_MARKDOWN_MAX_BYTES
                ),
            )
            if path.suffix.casefold() == ".md"
            else _json_content_profile(path)
        )
        return {
            **common,
            "content_profile": content_profile,
            **authorize_persistence(
                "compact_state",
                source_ids=source_ids,
            ),
        }
    if path.suffix.casefold() == ".csv":
        if (
            not name.startswith("autoruns_")
            and
            ("context" in name or "scope" in name)
            and (
                "suspicious" in name
                or "SuspiciousIdentityCount" in metadata
            )
        ):
            return {
                **common,
                **authorize_persistence(
                    "exact_suspicious_context",
                    source_ids=source_ids,
                    raw_rows=True,
                    exact=True,
                    finding_ids=_finding_ids_for_path(path, metadata),
                ),
            }
        if name == "autoruns_review.csv":
            source_ids = list(source_ids)
            try:
                if metadata.get("AutorunsReview"):
                    # Retain validation of historical exports with inline provenance.
                    provenance = json.loads(metadata["AutorunsReview"])
                    expected_schema = "autoruns-review-v1"
                    payload = path.read_bytes().split(b"\n", 1)[1]
                else:
                    state_path = analysis_root / "hunt-analysis-state.json"
                    state = json.loads(state_path.read_text()) if state_path.is_file() else {}
                    provenance = state.get("specialized_analysis", {}).get("autoruns_review")
                    payload = path.read_bytes()
                    if provenance:
                        expected_schema = ("autoruns-review-v4" if provenance.get("schema") == "autoruns-review-v4"
                                           else "autoruns-review-v3")
                    else:
                        sidecar = path.with_suffix(".metadata.json")
                        if sidecar.stat().st_size > 65536:
                            raise ValueError("oversized provenance")
                        provenance = json.loads(sidecar.read_text(encoding="utf-8"))
                        expected_schema = "autoruns-review-v2"
                counts = provenance["counts"]
                fields = ("SourceRows", "EligibleRows", "MatchedRows", "ResidualRows", "ExcludedRows", "GroupCount")
                if any(type(counts[field]) is not int or counts[field] < 0 for field in fields):
                    raise ValueError("invalid counts")
                high_count_rows = 0
                if expected_schema == "autoruns-review-v4":
                    from vraptor.autoruns import review as autoruns_review
                    try:
                        autoruns_review.validate_cutoff_counts(counts, provenance["max_total_rows"],
                            golden_first=provenance["source_contract"] == autoruns_review.GOLDEN_FIRST_SOURCE_CONTRACT)
                    except RuntimeError as exc:
                        raise ValueError("invalid cutoff counts") from exc
                    selection = provenance["source_selection"]
                    if (provenance["source_contract"] not in {autoruns_review.SOURCE_CONTRACT, autoruns_review.GOLDEN_FIRST_SOURCE_CONTRACT}
                            or selection != dict(stage=("after_golden" if provenance["source_contract"] == autoruns_review.GOLDEN_FIRST_SOURCE_CONTRACT else "before_golden"), max_total_rows=provenance["max_total_rows"],
                                excluded_group_count=counts["HighCountExcludedGroups"],
                                excluded_row_count=counts["HighCountExcludedRows"])):
                        raise ValueError("invalid cutoff provenance")
                    high_count_rows = counts["HighCountExcludedRows"]
                valid = (
                    provenance["schema"] == expected_schema
                    and provenance["source_complete"] is True
                    and provenance["content"] == ("count_filtered_residual_stacks" if expected_schema == "autoruns-review-v4" else "complete_residual_stacks")
                    and (expected_schema in {"autoruns-review-v3", "autoruns-review-v4"} or provenance["source_stats"])
                    and provenance["artifact"] in {"IG.Windows.Sysinternals.Autoruns", "Windows.Sysinternals.Autoruns"}
                    and f"hunt:{provenance['hunt_id']}" in source_ids
                    and counts["SourceRows"] == counts["EligibleRows"] + counts["ExcludedRows"]
                    and counts["EligibleRows"] == high_count_rows + counts["MatchedRows"] + counts["ResidualRows"]
                    and counts["GroupCount"] <= counts["ResidualRows"]
                    and all(re.fullmatch(r"[0-9a-f]{64}", provenance[key]) for key in
                        ("database_sha256", "query_environment_sha256", "review_csv_sha256"))
                    and hashlib.sha256(payload).hexdigest() == provenance["review_csv_sha256"]
                    and payload.startswith((
                        b"Category,ImagePath,LaunchString,Signer,TotalRows,ExampleHosts\r\n",
                        b"Category,ImagePath,LaunchString,Signer,TotalRows,ExampleHosts\n"))
                )
                if not valid:
                    raise ValueError("incomplete or changed aggregate")
            except (KeyError, ValueError, TypeError, IndexError, OSError) as exc:
                raise PersistencePolicyError(f"Invalid Autoruns review aggregate: {relative}") from exc
            return {
                **common,
                **authorize_persistence(
                    "complete_required_aggregate", source_ids=source_ids,
                    complete_accounting=True,
                ),
            }
        if name == "autoruns_potential_golden.csv":
            state_path = analysis_root / "hunt-analysis-state.json"
            if state_path.is_file():
                state = json.loads(state_path.read_text())
                record = state.get("specialized_analysis", {}).get("autoruns_review", {})
                if record:
                    if (f"hunt:{record.get('hunt_id')}" not in source_ids
                            or _file_sha256(path) != record.get("candidate_csv_sha256")):
                        raise PersistencePolicyError("Candidate CSV differs from canonical Autoruns state.")
                    return {**common, **authorize_persistence(
                        "complete_required_aggregate", source_ids=source_ids,
                        complete_accounting=bool(record.get("source_complete")))}
            complete_accounting = bool(
                metadata.get("ReviewComplete", "").casefold() == "true"
                and metadata.get("SourceStackSHA256")
                and metadata.get("ReviewedGroupCount") is not None
            )
            return {
                **common,
                **authorize_persistence(
                    "complete_required_aggregate",
                    source_ids=source_ids,
                    complete_accounting=complete_accounting,
                ),
            }
        if (
            "review" in name
            or "candidate" in name
            or "excluded" in name
            or "autoruns_ai_review/" in relative
        ):
            if name.startswith("autoruns_") and "golden" not in name:
                raise PersistencePolicyError(
                    f"Legacy Autoruns live-analysis output is not permitted: {relative}"
                )
            return {
                **common,
                **authorize_persistence(
                    "bounded_review_queue",
                    source_ids=source_ids,
                    bounded=True,
                ),
            }
    raise PersistencePolicyError(
        f"Unclassified raw-result-like live-analysis output: {relative}"
    )


def preflight_analysis_tree(
    analysis_root: Path,
    source_ids: Iterable[str],
    *,
    extra_files: Iterable[Path] = (),
) -> None:
    """Reject incompatible existing outputs without requiring completed analysis."""
    _classify_analysis_tree(
        analysis_root, list(source_ids), extra_files=extra_files,
        phase="output_preflight",
    )


def _classify_analysis_tree(
    analysis_root: Path,
    source_ids: list[str],
    *,
    extra_files: Iterable[Path] = (),
    remove_unauthorized: bool = False,
    phase: str = "publishing",
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    violations: list[str] = []
    candidate_paths = {
        path
        for path in analysis_root.rglob("*")
        if path.is_file()
    }
    candidate_paths.update(
        Path(path)
        for path in extra_files
        if Path(path).is_file()
    )
    for path in sorted(candidate_paths):
        if path.name == ".DS_Store":
            continue  # Finder metadata is neither evidence nor an analysis output.
        if not path.is_file():
            continue
        classification_root = (
            analysis_root
            if path.is_relative_to(analysis_root)
            else analysis_root.parent
        )
        try:
            records.append(
                classify_analysis_file(
                    path,
                    analysis_root=classification_root,
                    source_ids=source_ids,
                )
            )
        except PersistencePolicyError as exc:
            violations.append(f"{path.absolute()}: {exc}")
            if remove_unauthorized and path.suffix.casefold() in RAW_RESULT_SUFFIXES:
                path.unlink(missing_ok=True)
    if violations:
        from vraptor.logging import operations as operation_log

        action = (
            "Rejected CSV/JSONL files were removed by explicit request."
            if remove_unauthorized else "No files were removed."
        )
        remedy = (
            "Move unrelated historical files outside the analysis directory "
            "(for example, into the case reviews directory), or correct the "
            "output format/classification, then rerun the same command."
        )
        for violation in violations:
            operation_log.emit(
                "stage_failed", level="error", stage=phase, status="failed",
                error_class="PersistencePolicyError", error_detail=violation,
            )
        operation_log.emit(
            "stage_failed", level="error", stage=phase, status="failed",
            error_detail=f"{action} {remedy}",
        )
        raise PersistencePolicyError(
            f"Analysis output check failed during {phase}: "
            f"{len(violations)} incompatible file(s).\n"
            + "\n".join(f"- {item}" for item in violations)
            + f"\n{action} {remedy}"
        )
    return records


def audit_analysis_tree(
    analysis_root: Path,
    state: dict[str, Any],
    *,
    remove_unauthorized: bool = False,
    extra_files: Iterable[Path] = (),
) -> dict[str, Any]:
    """Validate closure and outputs; preserve rejected files by default."""
    coverage = enforce_closure(state)
    source_ids = list(coverage["source_ids"])
    if not source_ids:
        raise PersistencePolicyError(
            "Analysis persistence requires authoritative source identifiers."
        )
    records = _classify_analysis_tree(
        analysis_root, source_ids, extra_files=extra_files,
        remove_unauthorized=remove_unauthorized,
    )
    manifest = {
        "policy_version": POLICY_VERSION,
        "default_raw_result_action": "deny",
        "source_ids": source_ids,
        "file_count": len(records),
        "raw_result_export_count": sum(
            record["classification"]
            in {"immutable_evidence_export", "interoperability_export"}
            for record in records
        ),
        "files": records,
    }
    state["persistence_manifest"] = manifest
    return manifest
