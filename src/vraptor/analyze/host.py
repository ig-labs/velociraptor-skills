"""Deterministic in-memory preparation for native collection-analysis agents."""

from __future__ import annotations

import csv
import base64
import copy
import gzip
import hashlib
import io
import json
import re
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from vraptor.analyze import limits as analysis_limits
from vraptor.common import token_budget
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.analyze import line_protocol as analyst_line_protocol
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.autoruns import golden as autoruns_golden
from vraptor.autoruns import regex as autoruns_regex
from vraptor.collect import requests as collection
from vraptor.analyze import profiles as collection_analysis_profiles
from vraptor.analyze import references as evidence_references
from vraptor.analyze import planning as review_planning


ANALYSIS_PLAN_SCHEMA_VERSION = 6
CONTEXT_WORKER_PROTOCOL = "reference-line-v3"
UPLIFT_SCOPES = {"global", "site"}
CONTEXT_TYPES = {
    "identity",
    "session",
    "process",
    "file",
    "network",
    "timeline",
    "environment",
    "general",
}
_WORKER_TRAILING_TEXT_FIELDS = {
    "FINDING": 4,
    "CONTEXT": 4,
    "LIMITATION": 1,
    "FOLLOW_UP": 1,
    "UPLIFT": 3,
}
_SYNTHESIS_TRAILING_TEXT_FIELDS = {
    "FINDING": 4,
    "CONTEXT": 4,
}
SOURCE_ROW_NUMBER_FIELD = "_AnalysisSourceRowNumber"
CONFIDENCE_VALUES = {"low", "medium", "high"}
ATTACK_TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Stealth",
    "Defense Impairment",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
COVERAGE_DOMAINS = {
    "execution",
    "persistence",
    "authentication",
    "lateral_movement",
    "network",
}
_ATTACK_TACTIC_LOOKUP = {
    re.sub(r"[\s_-]+", " ", value).casefold(): value
    for value in ATTACK_TACTICS
}
class WorkerResultError(ValueError):
    """Raised when native analyst output is invalid."""

    def __init__(
        self,
        message: str,
        *,
        diagnostics: list[dict[str, Any]] | None = None,
    ):
        super().__init__(message)
        self.diagnostics = [dict(item) for item in diagnostics or []]


def format_validation_diagnostics(
    message: str,
    diagnostics: list[dict[str, Any]],
) -> str:
    """Render deterministic, value-free diagnostics for one bounded retry."""
    rendered: list[str] = []
    for diagnostic in diagnostics:
        details = [
            f"{key}={json.dumps(value, ensure_ascii=False, sort_keys=True)}"
            for key, value in sorted(diagnostic.items())
        ]
        rendered.append("{" + ", ".join(details) + "}")
    return message + (": " + "; ".join(rendered) if rendered else "")


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        import json

        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return value


def preferred_fields_for_rows(
    rows: list[dict[str, Any]],
    preferred_fields: Iterable[str],
    *,
    field_sources: dict[str, list[str]] | None = None,
) -> list[str]:
    """Choose configured semantics that exist, including source-field aliases."""
    present = {str(key) for row in rows for key in row}
    sources = field_sources or {}
    selected = [
        str(field)
        for field in preferred_fields
        if any(
            candidate in present
            for candidate in dict.fromkeys(
                [str(field), *sources.get(str(field), [])]
            )
        )
    ]
    if selected:
        return selected
    return sorted(present)


def _simple_projection_field(expression: Any) -> tuple[str, str] | None:
    """Return a simple source-field and model-facing alias from a VQL projection."""
    match = re.fullmatch(
        r"\s*(?:`([^`]+)`|([A-Za-z_][A-Za-z0-9_.]*))"
        r"(?:\s+AS\s+([A-Za-z_][A-Za-z0-9_]*))?\s*",
        str(expression or ""),
        flags=re.I,
    )
    if not match:
        return None
    source = str(match.group(1) or match.group(2) or "").strip()
    alias = str(match.group(3) or source).strip()
    return source, alias


HUNT_ONLY_HOST_FIELDS = {"fqdn", "hostname"}


def host_live_projection(expressions: Iterable[Any]) -> list[str]:
    """Remove hunt-only host identity from an exact-client projection.

    Host analysis is already bound to one resolved client and hostname.  Hunt
    analysis still consumes the profile's unmodified ``live_vql_select`` so it
    retains per-row endpoint attribution.
    """
    selected: list[str] = []
    for raw in expressions:
        expression = str(raw or "").strip()
        if not expression:
            continue
        resolved = _simple_projection_field(expression)
        if resolved is not None:
            source, alias = resolved
            if {
                source.casefold(),
                alias.casefold(),
            } & HUNT_ONLY_HOST_FIELDS:
                continue
        if expression not in selected:
            selected.append(expression)
    return selected


def profile_field_sources(
    profile: dict[str, Any] | None,
) -> dict[str, list[str]]:
    """Map canonical analysis fields to raw flow-result field aliases."""
    if not profile:
        return {}
    review = dict(profile.get("review") or {})
    sources: dict[str, list[str]] = {}
    for projection_name in ("live_vql_select", "vql_select"):
        for expression in review.get(projection_name) or []:
            resolved = _simple_projection_field(expression)
            if resolved is None:
                continue
            source, alias = resolved
            sources.setdefault(alias, [])
            if source not in sources[alias]:
                sources[alias].append(source)
    for alias, expression in dict(review.get("filter_fields") or {}).items():
        resolved = _simple_projection_field(expression)
        if resolved is None:
            continue
        source, _ = resolved
        canonical = str(alias)
        sources.setdefault(canonical, [])
        if source not in sources[canonical]:
            sources[canonical].append(source)
    return sources


def _projected_value(
    row: dict[str, Any],
    field: str,
    field_sources: dict[str, list[str]],
) -> Any:
    for candidate in dict.fromkeys([field, *field_sources.get(field, [])]):
        if candidate in row:
            return row.get(candidate)
    return None


def project_rows(
    rows: list[dict[str, Any]],
    *,
    source_alias: str,
    artifact: str,
    component: str,
    flow_id: str,
    preferred_fields: Iterable[str],
    field_sources: dict[str, list[str]] | None = None,
    row_offset: int = 0,
) -> tuple[list[dict[str, Any]], list[str]]:
    sources = field_sources or {}
    fields = preferred_fields_for_rows(
        rows,
        preferred_fields,
        field_sources=sources,
    )
    projected: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        row_number = int(row.get(SOURCE_ROW_NUMBER_FIELD) or row_offset + index)
        projected.append(
            {
                "_Artifact": artifact,
                "_Component": component,
                "_FlowId": flow_id,
                "_RowNumber": row_number,
                "_SourceRef": evidence_references.format_source_reference(
                    source_alias,
                    row_number,
                ),
                **{
                    field: csv_value(_projected_value(row, field, sources))
                    for field in fields
                },
            }
        )
    return projected, fields


def csv_text(rows: list[dict[str, Any]]) -> str:
    """Serialize rows deterministically without writing an evidence file."""
    if not rows:
        return ""
    headers: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                headers.append(key)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=headers,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def estimate_csv_tokens(
    rows: list[dict[str, Any]],
    *,
    encoding_name: str | None = None,
) -> int:
    return token_budget.estimate_tokens(csv_text(rows), encoding_name)


def plan_row_chunks(
    rows: list[dict[str, Any]],
    *,
    maximum_tokens: int,
    encoding_name: str | None = None,
) -> list[dict[str, int]]:
    """Plan contiguous row ranges whose complete CSV fits the token ceiling."""
    if maximum_tokens <= 0:
        raise ValueError("maximum_tokens must be greater than zero")
    if not rows:
        return []

    headers: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                headers.append(key)
    header_buffer = io.StringIO(newline="")
    csv.DictWriter(
        header_buffer,
        fieldnames=headers,
        extrasaction="ignore",
        lineterminator="\n",
    ).writeheader()
    header_tokens = token_budget.estimate_tokens(
        header_buffer.getvalue(), encoding_name
    )
    row_token_estimates: list[int] = []
    for row in rows:
        row_buffer = io.StringIO(newline="")
        csv.DictWriter(
            row_buffer,
            fieldnames=headers,
            extrasaction="ignore",
            lineterminator="\n",
        ).writerow(row)
        row_token_estimates.append(
            token_budget.estimate_tokens(row_buffer.getvalue(), encoding_name)
        )

    chunks: list[dict[str, int]] = []
    start = 0
    conservative_tokens = header_tokens
    for index, row_tokens in enumerate(row_token_estimates):
        if index > start and conservative_tokens + row_tokens > maximum_tokens:
            chunk_rows = rows[start:index]
            actual_tokens = estimate_csv_tokens(
                chunk_rows, encoding_name=encoding_name
            )
            chunks.append(
                {
                    "row_start": start,
                    "row_end": index,
                    "row_count": len(chunk_rows),
                    "input_tokens": actual_tokens,
                }
            )
            start = index
            conservative_tokens = header_tokens
        conservative_tokens += row_tokens
        if index == start and estimate_csv_tokens(
            rows[index : index + 1], encoding_name=encoding_name
        ) > maximum_tokens:
            raise ValueError(
                f"row {index} exceeds the context-safe CSV token budget"
            )
    chunk_rows = rows[start:]
    actual_tokens = estimate_csv_tokens(chunk_rows, encoding_name=encoding_name)
    if actual_tokens > maximum_tokens:
        # Per-fragment estimates are conservative for supported tokenizers. Keep
        # this explicit guard so a future tokenizer cannot create an overflow.
        raise RuntimeError("incremental CSV token accounting exceeded its ceiling")
    chunks.append(
        {
            "row_start": start,
            "row_end": len(rows),
            "row_count": len(chunk_rows),
            "input_tokens": actual_tokens,
        }
    )
    return chunks


def artifact_state(item: dict[str, Any], *, timed_out: bool = False) -> str:
    if not item.get("matching_flow_found"):
        return "missing"
    if not item.get("is_finished"):
        return "timed_out" if timed_out else "running"
    flow_state = str(item.get("flow_state") or "").upper()
    rows = int(item.get("total_rows") or 0)
    components = list(item.get("available_result_components") or [])
    if flow_state in {"FINISHED", "COMPLETED"}:
        return "success" if rows > 0 or components else "empty"
    return "partial" if rows > 0 or components else "failed"


def _profile_projection(
    artifact: str,
    profiles: dict[str, dict[str, Any]],
    *,
    strategy: str = "",
) -> tuple[list[str], dict[str, list[str]]]:
    profile = artifact_profiles.resolve_profile(artifact, profiles)
    preferred = artifact_profiles.analysis_fields(profile)
    if strategy == "autoruns-goldendb":
        preferred = list(
            dict.fromkeys(
                [
                    *preferred,
                    autoruns_golden.FILTER_HASH_FIELD,
                    autoruns_golden.FILTER_STATUS_FIELD,
                ]
            )
        )
    return preferred, profile_field_sources(profile)


def _autoruns_golden_keys(
    database: Path,
) -> tuple[set[str], dict[str, Any], autoruns_regex.RegexIndex]:
    lookup = autoruns_golden.live_lookup_payload(database)
    serialized = gzip.decompress(
        base64.b64decode(str(lookup["lookup_gzip_base64"]))
    )
    keys = {str(value) for value in json.loads(serialized)}
    connection = autoruns_golden.connect_database(database, readonly=True)
    try:
        regex_index = autoruns_regex.RegexIndex(autoruns_golden.regex_records(connection))
    finally:
        connection.close()
    return keys, {
        "strategy": "autoruns-goldendb",
        "database": str(database),
        "database_mode": "read_only",
        "database_sha256": str(lookup.get("sha256") or ""),
        "lookup_key_count": len(keys),
        "regex_rule_count": lookup.get("regex_rule_count", 0),
    }, regex_index


def reduce_autoruns_with_golden_db(
    rows: list[dict[str, Any]],
    *,
    database: Path,
    keys: set[str] | None = None,
    base_metadata: dict[str, Any] | None = None,
    regex_index: autoruns_regex.RegexIndex | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Subtract hash OR paired path/launch regex matches in one pass without writing evidence."""
    if keys is None or base_metadata is None:
        keys, base_metadata, regex_index = _autoruns_golden_keys(database)
    if regex_index is None and base_metadata.get("regex_rule_count"):
        raise RuntimeError("GoldenDB regex rules were not loaded with the hash index.")
    residual: list[dict[str, Any]] = []
    matched = 0
    blank = 0
    for source in rows:
        row = dict(source)
        normalized = autoruns_golden.normalized_record(row)
        if not normalized["image_path"] and not normalized["launch_string"]:
            blank += 1
            continue
        identity = normalized["hash_key"]
        if identity in keys or (
            regex_index is not None and regex_index.matches(normalized)
        ):
            matched += 1
            continue
        row[autoruns_golden.FILTER_HASH_FIELD] = identity
        row[autoruns_golden.FILTER_STATUS_FIELD] = "not_known_good"
        residual.append(row)
    return residual, {
        **base_metadata,
        "input_rows": len(rows),
        "known_good_filtered_rows": matched,
        "empty_identity_dropped_rows": blank,
        "residual_rows": len(residual),
    }


def collection_source_descriptors(
    payload: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Describe every result component as a distinct collection evidence source."""
    client_id = str(payload.get("client_id") or "")
    scope_id = str(payload.get("request_id") or "")
    org_id = str(payload.get("org_id") or "")
    descriptors: list[dict[str, Any]] = []
    for item in payload.get("artifact_flows") or []:
        artifact = str(item.get("artifact") or "").strip()
        flow_id = str(item.get("flow_id") or "").strip()
        components = list(item.get("available_result_components") or []) or [
            str(item.get("artifact_name") or artifact).strip() or artifact
        ]
        for component in components:
            component_name = str(component)
            source_id = evidence_references.evidence_source_id(
                scope_type="collection",
                scope_id=scope_id,
                org_id=org_id,
                client_id=client_id,
                flow_id=flow_id,
                artifact=artifact,
                source=component_name,
            )
            descriptors.append(
                {
                    "source_id": source_id,
                    "scope_type": "collection",
                    "scope_id": scope_id,
                    "org_id": org_id,
                    "client_id": client_id,
                    "flow_id": flow_id,
                    "artifact": artifact,
                    "source": component_name,
                }
            )
    return descriptors


def ensure_collection_source_aliases(
    payload: Mapping[str, Any],
    *,
    existing: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Allocate request-wide aliases without renumbering previously seen sources."""
    return evidence_references.ensure_source_aliases(
        existing,
        collection_source_descriptors(payload),
    )


def query_preferred_evidence(
    api: Any,
    payload: dict[str, Any],
    *,
    profiles: dict[str, dict[str, Any]],
    source_aliases: Mapping[str, Mapping[str, Any]] | None = None,
    artifact_strategies: dict[str, str] | None = None,
    autoruns_golden_db: Path | None = None,
    time_scopes: Mapping[str, analysis_time_scope.ResolvedTimeScope] | None = None,
    query_rows: Callable[..., list[dict[str, Any]]] = (
        collection.query_artifact_source
    ),
) -> list[dict[str, Any]]:
    """Query successful exact flows and retain only preferred analysis fields."""
    client_id = str(payload.get("client_id") or "")
    scope_id = str(payload.get("request_id") or "")
    org_id = str(payload.get("org_id") or "")
    strategies = dict(artifact_strategies or {})
    golden_cache: tuple[set[str], dict[str, Any], autoruns_regex.RegexIndex] | None = None
    resolved_source_aliases = ensure_collection_source_aliases(
        payload,
        existing=source_aliases,
    )
    evidence: list[dict[str, Any]] = []
    for item in payload.get("artifact_flows") or []:
        artifact = str(item.get("artifact") or "").strip()
        artifact_time_scope = dict(time_scopes or {}).get(artifact)
        time_predicate = (
            artifact_time_scope.predicate()
            if artifact_time_scope is not None
            else ""
        )
        state = artifact_state(item)
        record: dict[str, Any] = {
            "artifact": artifact,
            "flow_id": str(item.get("flow_id") or "").strip(),
            "flow_state": str(item.get("flow_state") or ""),
            "artifact_state": state,
            "reported_row_count": int(item.get("total_rows") or 0),
            "row_count": 0,
            "preferred_fields": [],
            "analysis_strategy": str(strategies.get(artifact) or ""),
            "strategy_metadata": {},
            "components": [],
            "rows": [],
            "query_error": "",
            "time_scope": (
                artifact_time_scope.canonical()
                if artifact_time_scope is not None
                else {"mode": "all"}
            ),
            "time_filter_application": (
                "server_source_where" if time_predicate else "not_applied"
            ),
            "time_filter_validation": (
                "pending" if time_predicate else "not_required"
            ),
        }
        if state == "empty":
            evidence.append(record)
            continue
        if state not in {"success", "partial"}:
            record["query_error"] = "flow did not finish successfully"
            evidence.append(record)
            continue

        components = list(item.get("available_result_components") or [])
        if not components:
            components = [
                str(item.get("artifact_name") or artifact).strip() or artifact
            ]
        preferred, field_sources = _profile_projection(
            artifact,
            profiles,
            strategy=str(strategies.get(artifact) or ""),
        )
        artifact_profile = artifact_profiles.resolve_profile(artifact, profiles)
        review_contract = dict((artifact_profile or {}).get("review") or {})
        live_projection = host_live_projection(
            review_contract.get("live_vql_select") or []
        )
        if artifact_time_scope is not None and live_projection:
            for role in artifact_time_scope.roles:
                for expression in artifact_time_scope.expressions[role]:
                    root = str(expression).split(".", 1)[0]
                    if root and root not in live_projection:
                        live_projection.append(root)
        selected_fields: list[str] = []
        projected_rows: list[dict[str, Any]] = []
        component_errors: list[str] = []
        for component in components:
            component_name = str(component)
            component_row_offset = len(projected_rows)
            source_id = evidence_references.evidence_source_id(
                scope_type="collection",
                scope_id=scope_id,
                org_id=org_id,
                client_id=client_id,
                flow_id=record["flow_id"],
                artifact=artifact,
                source=component_name,
            )
            source_alias = str(resolved_source_aliases[source_id]["alias"])
            try:
                if query_rows is collection.query_artifact_source:
                    source_rows = query_rows(
                        api,
                        client_id,
                        record["flow_id"],
                        component_name,
                        projection=live_projection,
                        time_predicate=time_predicate,
                        time_environment=(
                            artifact_time_scope.scope.environment()
                            if time_predicate and artifact_time_scope is not None
                            else None
                        ),
                    )
                else:
                    source_rows = query_rows(
                        api,
                        client_id,
                        record["flow_id"],
                        component_name,
                    )
                resolved_time_scope = artifact_time_scope
                if time_predicate and query_rows is collection.query_artifact_source:
                    numbered_rows: list[dict[str, Any]] = []
                    prior_row_number = 0
                    invalid_scope_rows = 0
                    for raw_row in source_rows:
                        row = dict(raw_row)
                        row_number = row.get(SOURCE_ROW_NUMBER_FIELD)
                        if (
                            isinstance(row_number, bool)
                            or not isinstance(row_number, int)
                            or row_number <= prior_row_number
                        ):
                            raise RuntimeError(
                                "server-side time filtering returned a missing, "
                                "invalid, or non-monotonic source row ordinal"
                            )
                        prior_row_number = row_number
                        if (
                            resolved_time_scope is None
                            or not resolved_time_scope.includes(row)
                        ):
                            invalid_scope_rows += 1
                        numbered_rows.append(row)
                    if invalid_scope_rows:
                        raise RuntimeError(
                            "server-side time filter validation failed: "
                            f"{invalid_scope_rows} returned row(s) were outside "
                            "the requested analysis window"
                        )
                    source_rows = numbered_rows
                    record["time_filter_validation"] = "passed"
                else:
                    source_rows = [
                        {**dict(row), SOURCE_ROW_NUMBER_FIELD: row_number}
                        for row_number, row in enumerate(source_rows, start=1)
                    ]
                if (
                    resolved_time_scope is not None
                    and not (
                        time_predicate
                        and query_rows is collection.query_artifact_source
                    )
                ):
                    source_rows = resolved_time_scope.filter_rows(source_rows)
                strategy_metadata: dict[str, Any] = {}
                if strategies.get(artifact) == "autoruns-goldendb":
                    if autoruns_golden_db is None:
                        raise RuntimeError(
                            "Autoruns GoldenDB strategy requires a read-only database"
                        )
                    if golden_cache is None:
                        golden_cache = _autoruns_golden_keys(autoruns_golden_db)
                    source_rows, strategy_metadata = reduce_autoruns_with_golden_db(
                        source_rows,
                        database=autoruns_golden_db,
                        keys=golden_cache[0],
                        base_metadata=golden_cache[1],
                        regex_index=golden_cache[2],
                    )
                projected, fields = project_rows(
                    source_rows,
                    source_alias=source_alias,
                    artifact=artifact,
                    component=component_name,
                    flow_id=record["flow_id"],
                    preferred_fields=preferred,
                    field_sources=field_sources,
                    row_offset=0,
                )
                for field in fields:
                    if field not in selected_fields:
                        selected_fields.append(field)
                projected_rows.extend(projected)
                record["components"].append(
                    {
                        "component": component_name,
                        "source_id": source_id,
                        "source_alias": source_alias,
                        "state": "success" if projected else "empty",
                        "query_error": "",
                        "row_offset": component_row_offset,
                        "row_count": len(projected),
                        "time_filter_application": (
                            "server_source_where" if time_predicate else "not_applied"
                        ),
                        "time_filter_validation": (
                            "passed" if time_predicate else "not_required"
                        ),
                        "rows": projected,
                    }
                )
                if strategy_metadata:
                    record["strategy_metadata"] = strategy_metadata
            except Exception as exc:  # API implementations expose several error types.
                if time_predicate:
                    record["time_filter_validation"] = "failed"
                error = f"{component_name}: result query failed: {exc}"
                component_errors.append(error)
                record["components"].append(
                    {
                        "component": component_name,
                        "source_id": source_id,
                        "source_alias": source_alias,
                        "state": "failed",
                        "query_error": str(exc),
                        "row_offset": component_row_offset,
                        "row_count": 0,
                        "time_filter_application": (
                            "server_source_where" if time_predicate else "not_applied"
                        ),
                        "time_filter_validation": (
                            "failed" if time_predicate else "not_required"
                        ),
                        "rows": [],
                    }
                )
        if time_predicate:
            record["time_filter_validation"] = (
                "partial"
                if component_errors and projected_rows
                else "failed"
                if component_errors
                else "passed"
            )
        record["preferred_fields"] = selected_fields
        record["rows"] = projected_rows
        record["row_count"] = len(projected_rows)
        record["query_error"] = "; ".join(component_errors)
        record["artifact_state"] = (
            "partial"
            if component_errors and projected_rows
            else "failed"
            if component_errors
            else "partial"
            if state == "partial"
            else "success"
            if projected_rows
            else "empty"
        )
        evidence.append(record)
    return evidence


def _plan_from_evidence(
    evidence: list[dict[str, Any]],
    payload: dict[str, Any],
    *,
    collection_type: str,
    limits: analysis_limits.AnalysisLimits,
    profile_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    limits.validate()
    effective_profile_contract = copy.deepcopy(dict(profile_contract or {}))
    usable_tokens = review_planning.resolve_maximum_evidence_tokens_per_item(limits)
    encoding = limits.token_encoding
    total_rows = sum(int(item.get("row_count") or 0) for item in evidence)
    failures = [
        {
            "artifact": item["artifact"],
            "flow_id": item["flow_id"],
            "state": item["artifact_state"],
            "error": item["query_error"],
        }
        for item in evidence
        if item["artifact_state"] not in {"success", "empty"}
    ]
    chunks: list[dict[str, Any]] = []
    mode = "empty"
    artifact_rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    artifact_chunk_counts: dict[tuple[str, str], int] = {}
    if total_rows:
        for item in evidence:
            rows = list(item.get("rows") or [])
            if not rows:
                continue
            key = (str(item["artifact"]), str(item["flow_id"]))
            artifact_rows[key] = rows
            planned = plan_row_chunks(
                rows,
                maximum_tokens=usable_tokens,
                encoding_name=encoding,
            )
            artifact_chunk_counts[key] = len(planned)
            components = [
                str(component.get("component") or "")
                for component in item.get("components") or []
                if str(component.get("component") or "")
            ]
            component_label = components[0] if len(components) == 1 else "mixed"
            for task_chunk_index, chunk in enumerate(planned):
                chunks.append(
                    {
                        "chunk_index": len(chunks),
                        "artifact": item["artifact"],
                        "flow_id": item["flow_id"],
                        "component": component_label,
                        "components": components,
                        "task_chunk_index": task_chunk_index,
                        "task_chunk_count": len(planned),
                        **chunk,
                    }
                )
        mode = (
            "direct"
            if len(chunks) == 1
            else "chunked"
            if any(value > 1 for value in artifact_chunk_counts.values())
            else "parallel_direct"
        )

    public_artifacts: list[dict[str, Any]] = []
    for item in evidence:
        public_item = {
            key: value
            for key, value in item.items()
            if key not in {"rows", "components"}
        }
        public_item["components"] = [
            {key: value for key, value in component.items() if key != "rows"}
            for component in item.get("components") or []
        ]
        public_artifacts.append(public_item)

    time_filter = dict(effective_profile_contract.get("time_filter") or {})
    if time_filter:
        time_filter["application_stage"] = (
            "server_source_where"
            if time_filter.get("filtered_artifacts")
            else "not_applied"
        )
        artifact_validation = {
            str(item.get("artifact") or ""): {
                "application": str(
                    item.get("time_filter_application") or "not_applied"
                ),
                "validation": str(
                    item.get("time_filter_validation") or "not_required"
                ),
            }
            for item in public_artifacts
            if str(item.get("artifact") or "")
        }
        time_filter["artifact_validation"] = artifact_validation
        validation_states = {
            str(item.get("validation") or "")
            for item in artifact_validation.values()
        }
        if "partial" in validation_states:
            time_filter["coverage"] = "partial"
        elif "failed" in validation_states:
            time_filter["coverage"] = (
                "partial" if "passed" in validation_states else "failed"
            )
        effective_profile_contract["time_filter"] = time_filter

    source_aliases = {
        str(component["source_id"]): {
            "alias": str(component["source_alias"]),
            "scope_type": "collection",
            "scope_id": str(payload.get("request_id") or ""),
            "org_id": str(payload.get("org_id") or ""),
            "client_id": str(payload.get("client_id") or ""),
            "flow_id": str(item.get("flow_id") or ""),
            "artifact": str(item.get("artifact") or ""),
            "source": str(component.get("component") or ""),
            "source_id": str(component["source_id"]),
        }
        for item in evidence
        for component in item.get("components") or []
        if str(component.get("source_id") or "")
    }

    source_identity = [
        {
            "artifact": str(item.get("artifact") or ""),
            "flow_id": str(item.get("flow_id") or ""),
            "artifact_state": str(item.get("artifact_state") or ""),
            "components": [
                {
                    "component": str(component.get("component") or ""),
                    "source_id": str(component.get("source_id") or ""),
                    "source_alias": str(component.get("source_alias") or ""),
                    "state": str(component.get("state") or ""),
                    "query_error": str(component.get("query_error") or ""),
                    "row_count": int(component.get("row_count") or 0),
                    "rows_sha256": hashlib.sha256(
                        csv_text(list(component.get("rows") or [])).encode("utf-8")
                    ).hexdigest(),
                }
                for component in item.get("components") or []
            ],
        }
        for item in evidence
    ]
    source_fingerprint = hashlib.sha256(
        json.dumps(source_identity, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    artifact_tasks: list[dict[str, Any]] = []
    chunks_by_task: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for chunk in chunks:
        key = (
            str(chunk["artifact"]),
            str(chunk["flow_id"]),
        )
        chunks_by_task.setdefault(key, []).append(chunk)
    for key, task_chunks in chunks_by_task.items():
        artifact, flow_id = key
        task_id = "artifact-task-" + hashlib.sha256(
            json.dumps(
                {
                    "source_fingerprint": source_fingerprint,
                    "artifact": artifact,
                    "flow_id": flow_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]
        for chunk in task_chunks:
            chunk["task_id"] = task_id
        artifact_tasks.append(
            {
                "task_id": task_id,
                "role": "artifact-analyst",
                "artifact": artifact,
                "flow_id": flow_id,
                "analysis_mode": "direct" if len(task_chunks) == 1 else "chunked",
                "analysis_route": "high-volume",
                "analysis_task": analysis_limits.analysis_task("high-volume"),
                "components": list(task_chunks[0].get("components") or []),
                "chunk_indices": [int(item["chunk_index"]) for item in task_chunks],
                "chunk_count": len(task_chunks),
                "row_count": sum(int(item["row_count"]) for item in task_chunks),
                "input_tokens": sum(int(item["input_tokens"]) for item in task_chunks),
            }
        )
    expected_chunk_headers = [
        {
            "artifact": str(chunk.get("artifact") or "all"),
            "source_artifact": str(chunk.get("artifact") or "all"),
            "component": str(chunk.get("component") or ""),
            "flow_id": str(chunk.get("flow_id") or ""),
            "chunk_index": int(chunk["chunk_index"]),
            "chunk_count": len(chunks),
            "row_start": int(chunk["row_start"]),
            "row_end": int(chunk["row_end"]),
            "row_count": int(chunk["row_count"]),
            "input_tokens": int(chunk["input_tokens"]),
            "task_id": str(chunk["task_id"]),
            "task_chunk_index": int(chunk["task_chunk_index"]),
            "task_chunk_count": int(chunk["task_chunk_count"]),
        }
        for chunk in chunks
    ]
    limits_identity = limits.identity()
    plan_identity = {
        "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
        "source_fingerprint": source_fingerprint,
        "collection_type": collection_type,
        "analysis_limits_identity": limits_identity,
        "token_encoding": encoding,
        "expected_chunks": expected_chunk_headers,
        "profile": effective_profile_contract,
    }
    plan_fingerprint = hashlib.sha256(
        json.dumps(plan_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    plan = {
        "schema_version": ANALYSIS_PLAN_SCHEMA_VERSION,
        "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
        "source_aliases": source_aliases,
        "investigation_id": str(payload.get("investigation_id") or ""),
        "hostname": str(payload.get("hostname") or ""),
        "client_id": str(payload.get("client_id") or ""),
        "collection_type": collection_type,
        "request_id": str(payload.get("request_id") or ""),
        "supersedes_request_id": str(
            payload.get("supersedes_request_id") or ""
        ),
        "unavailable_artifacts": sorted(
            {
                str(value)
                for value in payload.get("unavailable_artifacts") or []
                if str(value).strip()
            }
        ),
        "analysis_mode": mode,
        "analysis_limits": limits.as_dict(),
        "analysis_limits_identity": limits_identity,
        "token_estimator": token_budget.token_estimator_name(encoding),
        "direct_input_tokens": max(
            (int(item["input_tokens"]) for item in chunks),
            default=0,
        ),
        "total_evidence_tokens": sum(
            estimate_csv_tokens(rows, encoding_name=encoding)
            for rows in artifact_rows.values()
        ),
        "total_rows": total_rows,
        "chunk_count": len(chunks),
        "chunks": chunks,
        "artifact_tasks": artifact_tasks,
        "artifact_task_count": len(artifact_tasks),
        "expected_chunk_headers": expected_chunk_headers,
        "source_fingerprint": source_fingerprint,
        "plan_fingerprint": plan_fingerprint,
        "artifacts": public_artifacts,
        "collection_failures": failures,
        "evidence_persisted": False,
        **effective_profile_contract,
    }
    return plan


def build_analysis_workload(
    api: Any,
    payload: dict[str, Any],
    *,
    collection_type: str,
    source_aliases: Mapping[str, Mapping[str, Any]] | None = None,
    limits: analysis_limits.AnalysisLimits,
    analysis_profile_contract: dict[str, Any] | None = None,
    artifact_strategies: dict[str, str] | None = None,
    autoruns_golden_db: Path | None = None,
    profiles: dict[str, dict[str, Any]] | None = None,
    time_scopes: Mapping[str, analysis_time_scope.ResolvedTimeScope] | None = None,
    query_rows: Callable[[Any, str, str, str], list[dict[str, Any]]] = (
        collection.query_artifact_source
    ),
) -> tuple[dict[str, Any], dict[int, str]]:
    """Build a public plan and ephemeral chunk payloads from one evidence query."""
    contract = analysis_profile_contract or collection_analysis_profiles.profile_contract(
        collection_type,
        list(payload.get("requested_artifacts") or []),
    )
    evidence = query_preferred_evidence(
        api,
        payload,
        source_aliases=source_aliases,
        profiles=profiles,
        artifact_strategies=artifact_strategies,
        autoruns_golden_db=autoruns_golden_db,
        time_scopes=time_scopes,
        query_rows=query_rows,
    )
    plan = _plan_from_evidence(
        evidence,
        payload,
        collection_type=collection_type,
        limits=limits,
        profile_contract=contract,
    )
    rows_by_artifact = {
        (str(item.get("artifact") or ""), str(item.get("flow_id") or "")): list(
            item.get("rows") or []
        )
        for item in evidence
    }
    chunks = {
        int(chunk["chunk_index"]): csv_text(
            rows_by_artifact[(str(chunk["artifact"]), str(chunk["flow_id"]))][
                int(chunk["row_start"]):int(chunk["row_end"])
            ]
        )
        for chunk in plan["chunks"]
    }
    return plan, chunks


def build_analysis_plan(
    api: Any,
    payload: dict[str, Any],
    *,
    collection_type: str,
    source_aliases: Mapping[str, Mapping[str, Any]] | None = None,
    limits: analysis_limits.AnalysisLimits,
    analysis_profile_contract: dict[str, Any] | None = None,
    artifact_strategies: dict[str, str] | None = None,
    autoruns_golden_db: Path | None = None,
    profiles: dict[str, dict[str, Any]] | None = None,
    query_rows: Callable[[Any, str, str, str], list[dict[str, Any]]] = (
        collection.query_artifact_source
    ),
) -> dict[str, Any]:
    """Build a no-evidence plan from server rows held only in process memory."""
    plan, _chunks = build_analysis_workload(
        api,
        payload,
        collection_type=collection_type,
        source_aliases=source_aliases,
        limits=limits,
        analysis_profile_contract=analysis_profile_contract,
        artifact_strategies=artifact_strategies,
        autoruns_golden_db=autoruns_golden_db,
        profiles=profiles,
        query_rows=query_rows,
    )
    return plan


def validate_context_worker_result(
    result: Any,
    *,
    artifact: str,
    chunk_index: int,
    chunk_count: int,
    row_start: int,
    row_end: int,
    expected_row_count: int,
    source_rows: dict[str, dict[str, Any]],
    allow_uplift_candidates: bool = False,
) -> dict[str, Any]:
    """Validate one reference-only worker response and hydrate cited rows."""
    if isinstance(result, str):
        result, _repairs = evidence_references.normalize_response_references(result, source_rows)

    def fail(
        code: str,
        message: str,
        *,
        line: int = 0,
        record: str = "",
        ref: str = "",
        value: str = "",
    ) -> None:
        diagnostic: dict[str, Any] = {"code": code}
        if line:
            diagnostic["line"] = line
        if record:
            diagnostic["record"] = record
        if ref:
            diagnostic["ref"] = ref
        if value:
            diagnostic["value"] = value
        raise WorkerResultError(message, diagnostics=[diagnostic])

    try:
        lines = analyst_line_protocol.strict_lines(
            result,
            output_name="worker result",
        )
    except analyst_line_protocol.LineProtocolError as exc:
        diagnostic = exc.diagnostic
        fail(
            str(diagnostic.get("code") or "invalid_output"),
            str(exc),
            line=int(diagnostic.get("line") or 0),
            record=str(diagnostic.get("record") or ""),
            value=str(diagnostic.get("value") or ""),
        )

    expected_artifact = str(artifact).strip()
    if not expected_artifact:
        raise ValueError("expected artifact is required")
    if chunk_count <= 0 or chunk_index < 0 or chunk_index >= chunk_count:
        raise ValueError("expected chunk identity is invalid")
    if row_start < 0 or row_end <= row_start:
        raise ValueError("expected row range is invalid")
    if expected_row_count != row_end - row_start:
        raise ValueError("expected row count does not match the row range")
    if len(source_rows) != expected_row_count:
        raise ValueError("source rows do not match the assigned row count")
    try:
        for ref in source_rows:
            evidence_references.parse_source_reference(ref)
    except ValueError as exc:
        raise ValueError("source rows use an invalid reference protocol") from exc

    if len(lines) < 2:
        fail("truncated_output", "worker result is obviously truncated")
    result_fields = lines[0].split("\t")
    if len(result_fields) != 2 or result_fields[0] != "RESULT":
        fail("invalid_result_header", "line 1 must be RESULT<TAB>value", line=1)
    result_kind = result_fields[1]
    if result_kind not in {"findings", "no_reportable_findings"}:
        fail("unsupported_result", "RESULT is unsupported", line=1, record="RESULT")

    def canonical_tactics(value: str, *, line_number: int) -> list[str]:
        submitted = [item.strip() for item in value.split(",") if item.strip()]
        if not submitted:
            fail(
                "missing_tactic",
                f"line {line_number} FINDING requires at least one ATT&CK tactic",
                line=line_number,
                record="FINDING",
            )
        tactics: list[str] = []
        for item in submitted:
            key = re.sub(r"[\s_-]+", " ", item).casefold()
            canonical = _ATTACK_TACTIC_LOOKUP.get(key)
            if canonical is None:
                fail(
                    "unsupported_tactic",
                    f"line {line_number} FINDING uses unsupported ATT&CK tactic",
                    line=line_number,
                    record="FINDING",
                    value=item,
                )
            tactics.append(canonical)
        if len(tactics) != len(set(tactics)):
            fail(
                "duplicate_tactic",
                f"line {line_number} FINDING tactics must be unique",
                line=line_number,
                record="FINDING",
            )
        return tactics

    def hydrated_row(ref: str) -> dict[str, Any]:
        fields = {
            str(name): str(value)
            for name, value in source_rows[ref].items()
            if not str(name).startswith("_")
            and value is not None
            and str(value).strip()
        }
        return {
            "ref": ref,
            "fields": fields,
            "source": evidence_references.source_provenance(
                source_rows[ref],
                reference=ref,
            ),
        }

    findings: dict[str, dict[str, Any]] = {}
    finding_order: list[str] = []
    context: list[dict[str, Any]] = []
    limitations: list[str] = []
    follow_up: list[str] = []
    uplift_candidates: list[dict[str, Any]] = []
    uplift_refs: set[str] = set()
    seen_context: set[tuple[str, str, str, str]] = set()
    body_start = 1

    for line_number, line in enumerate(lines[body_start:-1], start=body_start + 1):
        if not line:
            continue
        record = line.partition("\t")[0]
        fields = analyst_line_protocol.tab_fields(
            line,
            final_text_field=_WORKER_TRAILING_TEXT_FIELDS.get(record),
        )
        if record == "FINDING":
            if len(fields) != 5:
                fail(
                    "invalid_finding_record",
                    f"line {line_number} FINDING requires id, confidence, tactics, and text",
                    line=line_number,
                    record=record,
                )
            finding_id, confidence, tactic_text, summary = fields[1:]
            if not finding_id or finding_id in findings:
                fail(
                    "invalid_finding_id",
                    f"line {line_number} has an invalid finding ID",
                    line=line_number,
                    record=record,
                )
            if confidence not in CONFIDENCE_VALUES:
                fail(
                    "invalid_confidence",
                    f"line {line_number} has invalid confidence",
                    line=line_number,
                    record=record,
                )
            if not summary.strip():
                fail(
                    "empty_finding",
                    f"line {line_number} has an empty finding",
                    line=line_number,
                    record=record,
                )
            findings[finding_id] = {
                "id": finding_id,
                "confidence": confidence,
                "domains": canonical_tactics(tactic_text, line_number=line_number),
                "summary": summary.strip(),
                "rows": [],
            }
            finding_order.append(finding_id)
        elif record == "EVIDENCE":
            if len(fields) != 3:
                fail(
                    "invalid_evidence_record",
                    f"line {line_number} EVIDENCE requires finding ID and source reference",
                    line=line_number,
                    record=record,
                )
            finding_id, ref = fields[1:]
            if finding_id not in findings:
                fail(
                    "unknown_finding",
                    f"line {line_number} EVIDENCE references an unknown finding",
                    line=line_number,
                    record=record,
                )
            if ref not in source_rows:
                fail(
                    "invalid_source_reference",
                    f"line {line_number} EVIDENCE is not assigned to this chunk",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            if any(item["ref"] == ref for item in findings[finding_id]["rows"]):
                fail(
                    "duplicate_source_reference",
                    f"line {line_number} duplicates finding evidence",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            findings[finding_id]["rows"].append(hydrated_row(ref))
        elif record == "CONTEXT":
            raw_fields = line.split("\t")
            if len(raw_fields) == 3 or (
                len(raw_fields) >= 3 and raw_fields[1] in source_rows
            ):
                finding_id = ""
                ref = raw_fields[1]
                summary = "\t".join(raw_fields[2:])
                # Legacy three-field context had no finding identifier. Treat
                # it as environment context rather than silently presenting it
                # as finding-linked causal context.
                context_type = "environment"
            elif len(fields) == 5:
                finding_id, ref, context_type, summary = fields[1:]
                if finding_id.casefold() in {"-", "none"}:
                    finding_id = ""
            else:
                fail(
                    "invalid_context_record",
                    f"line {line_number} CONTEXT requires finding ID, source reference, context type, and text",
                    line=line_number,
                    record=record,
                )
            if finding_id and finding_id not in findings:
                fail(
                    "unknown_finding",
                    f"line {line_number} CONTEXT references an unknown finding",
                    line=line_number,
                    record=record,
                )
            context_type = context_type.strip().casefold().replace("-", "_")
            if context_type not in CONTEXT_TYPES:
                fail(
                    "invalid_context_type",
                    f"line {line_number} CONTEXT type is invalid",
                    line=line_number,
                    record=record,
                    value=context_type,
                )
            if not finding_id and context_type != "environment":
                fail(
                    "unlinked_context_type",
                    f"line {line_number} unlinked CONTEXT must use environment type",
                    line=line_number,
                    record=record,
                    value=context_type,
                )
            if ref not in source_rows:
                fail(
                    "invalid_source_reference",
                    f"line {line_number} CONTEXT is not assigned to this chunk",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            if not summary.strip():
                fail(
                    "empty_context",
                    f"line {line_number} CONTEXT text is empty",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            key = (finding_id, ref, context_type, summary.strip())
            if key not in seen_context:
                row = hydrated_row(ref)
                context.append(
                    {
                        "ref": ref,
                        "finding_id": finding_id,
                        "context_type": context_type,
                        "summary": summary.strip(),
                        "fields": row["fields"],
                        "source": row["source"],
                    }
                )
                seen_context.add(key)
        elif record == "UPLIFT":
            if not allow_uplift_candidates:
                fail(
                    "unsupported_record",
                    f"line {line_number} uses unsupported record {record}",
                    line=line_number,
                    record=record,
                )
            if len(fields) != 4:
                fail(
                    "invalid_uplift_record",
                    f"line {line_number} UPLIFT requires source reference, scope, and reason",
                    line=line_number,
                    record=record,
                )
            ref, scope, reason = fields[1:]
            if ref not in source_rows:
                fail(
                    "invalid_source_reference",
                    f"line {line_number} UPLIFT is not assigned to this chunk",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            if scope not in UPLIFT_SCOPES:
                fail(
                    "invalid_uplift_scope",
                    f"line {line_number} UPLIFT scope must be global or site",
                    line=line_number,
                    record=record,
                    ref=ref,
                    value=scope,
                )
            if not reason.strip():
                fail(
                    "empty_uplift_reason",
                    f"line {line_number} UPLIFT reason is empty",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            if ref in uplift_refs:
                fail(
                    "duplicate_source_reference",
                    f"line {line_number} duplicates an uplift source reference",
                    line=line_number,
                    record=record,
                    ref=ref,
                )
            row = hydrated_row(ref)
            uplift_candidates.append(
                {
                    "ref": ref,
                    "scope": scope,
                    "summary": reason.strip(),
                    "fields": row["fields"],
                    "source": row["source"],
                }
            )
            uplift_refs.add(ref)
        elif record in {"LIMITATION", "FOLLOW_UP"}:
            if len(fields) != 2 or not fields[1].strip():
                fail(
                    "invalid_prose_record",
                    f"line {line_number} {record} requires non-empty text",
                    line=line_number,
                    record=record,
                )
            (limitations if record == "LIMITATION" else follow_up).append(
                fields[1].strip()
            )
        else:
            fail(
                "unsupported_record",
                f"line {line_number} uses unsupported record {record}",
                line=line_number,
                record=record,
            )

    if result_kind == "findings" and not findings:
        fail("missing_finding", "RESULT findings requires at least one FINDING")
    if result_kind == "no_reportable_findings" and findings:
        fail(
            "unexpected_finding",
            "RESULT no_reportable_findings cannot contain FINDING records",
        )
    for finding_id, finding in findings.items():
        if not finding["rows"]:
            fail(
                "missing_evidence",
                f"FINDING {finding_id} requires at least one EVIDENCE record",
                record="FINDING",
            )
    finding_refs = {
        str(row.get("ref") or "")
        for finding in findings.values()
        for row in finding.get("rows") or []
    }
    conflicting_refs = sorted(finding_refs & uplift_refs)
    if conflicting_refs:
        fail(
            "conflicting_source_classification",
            "A source reference cannot be both finding evidence and an uplift candidate",
            record="UPLIFT",
            ref=conflicting_refs[0],
        )

    return {
        "protocol": CONTEXT_WORKER_PROTOCOL,
        "artifact": expected_artifact,
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        "row_start": row_start,
        "row_end": row_end,
        "row_count": expected_row_count,
        "status": "complete",
        "result": result_kind,
        "findings": [findings[item] for item in finding_order],
        "relevant_context": context,
        "uplift_candidates": uplift_candidates,
        "explained": [],
        "limitations": _ordered_unique(limitations),
        "bounded_follow_up": _ordered_unique(follow_up),
    }


def _ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


def merge_context_worker_results(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Merge compact accepted worker records without building an evidence catalogue."""
    if not results:
        raise ValueError("at least one context worker result is required")
    ordered = sorted(results, key=lambda item: int(item["chunk_index"]))
    seen_chunks: set[int] = set()
    expected_chunk_count = int(ordered[0]["chunk_count"])
    reviewed_rows = 0
    findings: list[dict[str, Any]] = []
    context: list[dict[str, Any]] = []
    explained: list[dict[str, Any]] = []
    limitations: list[str] = []
    follow_up: list[str] = []
    uplift_candidates: list[dict[str, Any]] = []

    for result in ordered:
        if result.get("protocol") != CONTEXT_WORKER_PROTOCOL:
            raise ValueError("worker result does not use the line-oriented protocol")
        if int(result.get("chunk_count", -1)) != expected_chunk_count:
            raise ValueError("worker results contain inconsistent chunk counts")
        chunk_index = int(result["chunk_index"])
        if chunk_index in seen_chunks:
            raise ValueError(f"duplicate context worker chunk {chunk_index}")
        seen_chunks.add(chunk_index)
        reviewed_rows += int(result["row_count"])
        origin = {
            "artifact": str(result["artifact"]),
            "chunk_index": chunk_index,
        }
        findings.extend({**origin, **dict(item)} for item in result.get("findings") or [])
        context.extend(
            {**origin, **dict(item)} for item in result.get("relevant_context") or []
        )
        uplift_candidates.extend(
            {**origin, **dict(item)} for item in result.get("uplift_candidates") or []
        )
        explained.extend(
            {**origin, **dict(item)} for item in result.get("explained") or []
        )
        limitations.extend(result.get("limitations") or [])
        follow_up.extend(result.get("bounded_follow_up") or [])

    return {
        "protocol": CONTEXT_WORKER_PROTOCOL,
        "status": "complete",
        "reviewed_rows": reviewed_rows,
        "findings": findings,
        "relevant_context": context,
        "uplift_candidates": uplift_candidates,
        "explained": explained,
        "limitations": _ordered_unique(limitations),
        "bounded_follow_up": _ordered_unique(follow_up),
        "chunk_count": len(seen_chunks),
        "expected_chunk_count": expected_chunk_count,
    }


def validate_analysis_story(
    story: Any,
    *,
    task: str,
    question: str,
    expected_chunks: list[dict[str, Any]],
    accepted_chunks: dict[str, dict[str, Any]],
    failed_chunks: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate a line-oriented synthesis story against accepted worker evidence."""
    if isinstance(story, str):
        refs = [r["ref"] for worker in accepted_chunks.values()
                for r in [*(row for finding in worker.get("findings", []) for row in finding.get("rows", [])),
                          *worker.get("relevant_context", [])]]
        story, _repairs = evidence_references.normalize_response_references(story, refs)
    try:
        lines = analyst_line_protocol.strict_lines(
            story,
            output_name="synthesis story",
        )
    except analyst_line_protocol.LineProtocolError as exc:
        raise ValueError(str(exc)) from exc

    planned_chunks = len(expected_chunks)
    planned_rows = sum(int(item.get("row_count") or 0) for item in expected_chunks)
    accepted_count = len(accepted_chunks)
    accepted_rows = sum(int(item.get("row_count") or 0) for item in accepted_chunks.values())
    status = (
        "complete"
        if accepted_count == planned_chunks and not failed_chunks
        else "complete_with_failures"
        if accepted_count
        else "failed"
    )

    section_names = (
        "ANSWER",
        "FINDINGS",
        "RELEVANT_CONTEXT",
        "LIMITATIONS",
        "FOLLOW_UP",
    )
    sections: dict[str, list[str]] = {name: [] for name in section_names}
    current = ""
    for line in lines[:-1]:
        if not line and not current:
            continue
        if line in section_names:
            current = line
            continue
        if not current:
            if line:
                raise ValueError("synthesis story content appears before ANSWER")
            continue
        if line:
            sections[current].append(line)
    if any(name not in lines for name in section_names):
        raise ValueError("synthesis story is missing a required section")
    answer = "\n".join(sections["ANSWER"]).strip()
    if not answer:
        raise ValueError("synthesis story ANSWER is required")
    if failed_chunks and "supplied evidence" in answer.lower():
        raise ValueError(
            "coverage-limited synthesis must describe accepted evidence, not supplied evidence"
        )

    evidence_sources: dict[str, dict[str, Any]] = {}
    context_sources: dict[str, dict[str, Any]] = {}
    for accepted in accepted_chunks.values():
        artifact = str(accepted.get("artifact") or "")
        chunk_index = int(accepted.get("chunk_index", -1))
        chunk_count = int(accepted.get("chunk_count", planned_chunks))
        for finding in accepted.get("findings") or []:
            for row in finding.get("rows") or []:
                ref = str(row.get("ref") or "")
                evidence_references.parse_source_reference(ref)
                origin = dict(row.get("_origin") or {})
                candidate = {
                    "artifact": str(origin.get("artifact") or artifact),
                    "chunk_index": int(origin.get("chunk_index", chunk_index)),
                    "chunk_count": int(origin.get("chunk_count", chunk_count)),
                    "fields": {
                        str(key): str(value)
                        for key, value in dict(row.get("fields") or {}).items()
                    },
                    "domains": {str(value) for value in finding.get("domains") or []},
                    "full_fields": {
                        str(key): str(value)
                        for key, value in dict(
                            row.get("_full_fields") or row.get("fields") or {}
                        ).items()
                    },
                    "source": dict(row.get("source") or {}),
                }
                existing = evidence_sources.get(ref)
                if existing is not None:
                    if any(
                        existing.get(key) != candidate.get(key)
                        for key in (
                            "artifact",
                            "chunk_index",
                            "chunk_count",
                            "full_fields",
                            "source",
                        )
                    ):
                        raise ValueError(
                            f"accepted evidence reference {ref} resolves ambiguously"
                        )
                    for name, value in candidate["fields"].items():
                        if name in existing["fields"] and existing["fields"][name] != value:
                            raise ValueError(
                                f"accepted evidence reference {ref} resolves ambiguously"
                            )
                        existing["fields"][name] = value
                    existing["domains"].update(candidate["domains"])
                else:
                    evidence_sources[ref] = candidate
        for item in [
            *list(accepted.get("relevant_context") or []),
            *list(accepted.get("explained") or []),
        ]:
            ref = str(item.get("ref") or "")
            if not ref:
                continue
            evidence_references.parse_source_reference(ref)
            fields = {
                str(key): str(value)
                for key, value in dict(item.get("fields") or {}).items()
                if str(key).strip() and str(value).strip()
            }
            if fields:
                origin = dict(item.get("_origin") or {})
                candidate = {
                    "artifact": str(origin.get("artifact") or artifact),
                    "chunk_index": int(origin.get("chunk_index", chunk_index)),
                    "chunk_count": int(origin.get("chunk_count", chunk_count)),
                    "fields": fields,
                    "source": dict(item.get("source") or {}),
                }
                existing = context_sources.get(ref)
                if existing is not None:
                    if any(
                        existing.get(key) != candidate.get(key)
                        for key in (
                            "artifact",
                            "chunk_index",
                            "chunk_count",
                            "source",
                        )
                    ):
                        raise ValueError(
                            f"accepted context reference {ref} resolves ambiguously"
                        )
                    for name, value in candidate["fields"].items():
                        if name in existing["fields"] and existing["fields"][name] != value:
                            raise ValueError(
                                f"accepted context reference {ref} resolves ambiguously"
                            )
                        existing["fields"][name] = value
                else:
                    context_sources[ref] = candidate

    synthesis_diagnostics: list[dict[str, Any]] = []
    for line_number, line in enumerate(sections["FINDINGS"], start=1):
        record = line.partition("\t")[0]
        fields = analyst_line_protocol.tab_fields(
            line,
            final_text_field=_SYNTHESIS_TRAILING_TEXT_FIELDS.get(record),
        )
        if not fields:
            continue
        if fields[0] == "FINDING" and len(fields) == 5:
            for tactic in [
                item.strip() for item in fields[3].split(",") if item.strip()
            ]:
                normalized = re.sub(r"[\s_-]+", " ", tactic).casefold()
                if normalized not in _ATTACK_TACTIC_LOOKUP:
                    synthesis_diagnostics.append(
                        {
                            "allowed": list(ATTACK_TACTICS),
                            "code": "unsupported_tactic",
                            "line": line_number,
                            "record": "FINDING",
                            "value": tactic,
                        }
                    )
            continue
        if fields[0] != "EVIDENCE" or len(fields) != 3:
            continue
        ref = fields[2]
        source = evidence_sources.get(ref)
        if source is None:
            synthesis_diagnostics.append(
                {
                    "code": "unavailable_source",
                    "line": line_number,
                    "record": "EVIDENCE",
                    "ref": ref,
                }
            )
            continue
    if synthesis_diagnostics:
        raise WorkerResultError(
            format_validation_diagnostics(
                "synthesis story failed deterministic validation",
                synthesis_diagnostics,
            ),
            diagnostics=synthesis_diagnostics,
        )

    findings: dict[str, dict[str, Any]] = {}
    finding_order: list[str] = []
    for line_number, line in enumerate(sections["FINDINGS"], start=1):
        if line in {"None.", "- None."}:
            continue
        record = line.partition("\t")[0]
        fields = analyst_line_protocol.tab_fields(
            line,
            final_text_field=_SYNTHESIS_TRAILING_TEXT_FIELDS.get(record),
        )
        if fields[0] == "FINDING":
            if len(fields) != 5:
                raise ValueError(
                    "synthesis FINDING requires id, confidence, domains, and text"
                )
            finding_id, confidence, domain_text, summary = fields[1:]
            if not finding_id or finding_id in findings:
                raise ValueError("synthesis FINDING id is invalid or duplicated")
            if confidence not in CONFIDENCE_VALUES or not summary.strip():
                raise ValueError("synthesis FINDING confidence or text is invalid")
            submitted_tactics = [
                value.strip() for value in domain_text.split(",") if value.strip()
            ]
            domains = [
                _ATTACK_TACTIC_LOOKUP.get(
                    re.sub(r"[\s_-]+", " ", value).casefold(),
                    "",
                )
                for value in submitted_tactics
            ]
            if (
                not domains
                or len(domains) != len(set(domains))
                or any(not value for value in domains)
            ):
                raise ValueError("synthesis FINDING tactics are invalid")
            findings[finding_id] = {
                "id": finding_id,
                "confidence": confidence,
                "domains": domains,
                "summary": summary.strip(),
                "evidence": [],
                "_supported_domains": set(),
            }
            finding_order.append(finding_id)
        elif fields[0] == "EVIDENCE":
            if len(fields) != 3:
                raise ValueError(
                    "synthesis EVIDENCE requires finding and source reference"
                )
            finding_id, ref = fields[1:3]
            if finding_id not in findings:
                raise ValueError("synthesis EVIDENCE references an unknown finding")
            evidence_references.parse_source_reference(ref)
            source = evidence_sources.get(ref)
            if source is None:
                raise ValueError("synthesis EVIDENCE is not present in accepted worker results")
            source_domains = set(source["domains"])
            findings[finding_id]["_supported_domains"].update(source_domains)
            findings[finding_id]["evidence"].append(
                {
                    "artifact": str(source["artifact"]),
                    "chunk_index": int(source["chunk_index"]),
                    "chunk_count": int(source["chunk_count"]),
                    "ref": ref,
                    "fields": dict(source["fields"]),
                    "_full_fields": dict(source["full_fields"]),
                    "source": dict(source["source"]),
                }
            )
        else:
            diagnostics = [
                {
                    "allowed": ["FINDING", "EVIDENCE"],
                    "code": "unsupported_record",
                    "line": line_number,
                    "record": "FINDINGS",
                }
            ]
            raise WorkerResultError(
                format_validation_diagnostics(
                    "synthesis FINDINGS contains an unsupported record",
                    diagnostics,
                ),
                diagnostics=diagnostics,
            )
    for finding_id, finding in findings.items():
        if not finding["evidence"]:
            raise ValueError(f"synthesis FINDING {finding_id} requires EVIDENCE")
        unsupported_domains = sorted(
            set(finding["domains"]) - finding["_supported_domains"]
        )
        if unsupported_domains:
            diagnostics = [
                {
                    "allowed": sorted(finding["_supported_domains"]),
                    "code": "unsupported_evidence_tactic",
                    "finding_id": finding_id,
                    "record": "FINDING",
                    "value": domain,
                }
                for domain in unsupported_domains
            ]
            raise WorkerResultError(
                format_validation_diagnostics(
                    "synthesis FINDING tactics are not supported by cited evidence",
                    diagnostics,
                ),
                diagnostics=diagnostics,
            )
        finding.pop("_supported_domains", None)

    relevant_context: list[dict[str, Any]] = []
    for line_number, line in enumerate(sections["RELEVANT_CONTEXT"], start=1):
        if line in {"None.", "- None."}:
            continue
        raw_fields = line.split("\t")
        fields = analyst_line_protocol.tab_fields(
            line,
            final_text_field=_SYNTHESIS_TRAILING_TEXT_FIELDS["CONTEXT"],
        )
        if (
            (len(raw_fields) == 3 or len(raw_fields) >= 3 and raw_fields[1] in context_sources)
            and raw_fields[0] == "CONTEXT"
        ):
            finding_id = ""
            ref = raw_fields[1]
            summary = "\t".join(raw_fields[2:])
            context_type = "environment"
        elif len(fields) == 5 and fields[0] == "CONTEXT":
            finding_id, ref, context_type, summary = fields[1:5]
            if finding_id.casefold() in {"-", "none"}:
                finding_id = ""
        else:
            raise ValueError(
                "synthesis RELEVANT_CONTEXT requires "
                "CONTEXT, finding ID, source reference, context type, and text"
            )
        if finding_id and finding_id not in findings:
            raise ValueError(
                f"synthesis CONTEXT line {line_number} references an unknown finding"
            )
        context_type = context_type.strip().casefold().replace("-", "_")
        if context_type not in CONTEXT_TYPES:
            raise ValueError(
                f"synthesis CONTEXT line {line_number} has invalid context type"
            )
        if not finding_id and context_type != "environment":
            raise ValueError(
                f"synthesis CONTEXT line {line_number} unlinked context must use environment type"
            )
        evidence_references.parse_source_reference(ref)
        source = context_sources.get(ref)
        if source is None:
            raise ValueError(
                f"synthesis CONTEXT line {line_number} is not present in "
                "accepted worker context"
            )
        if not summary.strip():
            raise ValueError(
                f"synthesis CONTEXT line {line_number} text must be populated"
            )
        relevant_context.append(
            {
                "artifact": str(source["artifact"]),
                "chunk_index": int(source["chunk_index"]),
                "chunk_count": int(source["chunk_count"]),
                "ref": ref,
                "finding_id": finding_id,
                "context_type": context_type,
                "summary": summary.strip(),
                "fields": dict(source["fields"]),
                "source": dict(source["source"]),
            }
        )

    def prose(section: str) -> list[str]:
        values = [
            line.removeprefix("- ").removeprefix("LIMITATION\t").removeprefix("FOLLOW_UP\t").strip()
            for line in sections[section]
            if line not in {"None.", "- None."} and line.removeprefix("- ").strip()
        ]
        return _ordered_unique(values)

    return {
        "format": "analysis-story-v2",
        "task": task.strip(),
        "question": question.strip(),
        "status": status,
        "coverage": {
            "planned_chunks": planned_chunks,
            "accepted_chunks": accepted_count,
            "planned_rows": planned_rows,
            "reviewed_rows": accepted_rows,
        },
        "answer": answer,
        "findings": [findings[item] for item in finding_order],
        "relevant_context": relevant_context,
        "limitations": prose("LIMITATIONS"),
        "bounded_follow_up": prose("FOLLOW_UP"),
    }
