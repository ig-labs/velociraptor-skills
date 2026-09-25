"""Stable source-qualified evidence references for Velociraptor analysis."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any


REFERENCE_PROTOCOL = "source-row-v1"
_ALIAS_RE = re.compile(r"S([0-9]{4,})")
_REFERENCE_RE = re.compile(r"(S[0-9]{4,})-R([1-9][0-9]*)")


def normalize_response_references(text: str, available: Iterable[str]) -> tuple[str, int]:
    """Repair padding only when an existing source-qualified identity is unique."""
    token = re.compile(r"\bS([0-9]{1,20})-R([0-9]{1,20})\b")
    identities: dict[tuple[int, int], set[str]] = {}
    for ref in available:
        match = token.fullmatch(ref)
        if match:
            identities.setdefault((int(match[1]), int(match[2])), set()).add(ref)
    repairs = 0

    def replace(match):
        nonlocal repairs
        values = identities.get((int(match[1]), int(match[2])), set())
        if len(values) == 1 and match[0] not in values:
            repairs += 1
            return next(iter(values))
        return match[0]

    return token.sub(replace, text), repairs


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def evidence_source_id(
    *,
    scope_type: str,
    scope_id: str,
    org_id: str,
    client_id: str,
    flow_id: str,
    artifact: str,
    source: str,
) -> str:
    """Return an immutable identity for one terminal result source."""
    identity = {
        "protocol": REFERENCE_PROTOCOL,
        "scope_type": str(scope_type),
        "scope_id": str(scope_id),
        "org_id": str(org_id),
        "client_id": str(client_id),
        "flow_id": str(flow_id),
        "artifact": str(artifact),
        "source": str(source),
    }
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"evidence-source-v1-{digest[:32]}"


def format_source_alias(number: int) -> str:
    if number <= 0:
        raise ValueError("source alias number must be positive")
    return f"S{number:04d}"


def parse_source_alias(value: str) -> int:
    match = _ALIAS_RE.fullmatch(str(value).strip())
    if match is None:
        raise ValueError("source alias must use Sxxxx with a positive number")
    number = int(match.group(1))
    if number <= 0:
        raise ValueError("source alias number must be positive")
    return number


def format_source_reference(alias: str, row_number: int) -> str:
    parse_source_alias(alias)
    if row_number <= 0:
        raise ValueError("source row number must be positive")
    return f"{alias}-R{row_number}"


def parse_source_reference(value: str) -> tuple[str, int]:
    match = _REFERENCE_RE.fullmatch(str(value).strip())
    if match is None:
        raise ValueError("source reference must use Sxxxx-Rn with positive numbers")
    alias = match.group(1)
    parse_source_alias(alias)
    return alias, int(match.group(2))


def ensure_source_aliases(
    existing: Mapping[str, Mapping[str, Any]] | None,
    sources: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Preserve existing aliases and allocate monotonic aliases for new sources."""
    aliases: dict[str, dict[str, Any]] = {}
    used: dict[str, str] = {}
    highest = 0
    for source_id, raw in dict(existing or {}).items():
        entry = {str(key): value for key, value in dict(raw).items()}
        alias = str(entry.get("alias") or "")
        number = parse_source_alias(alias)
        if alias in used and used[alias] != str(source_id):
            raise ValueError(f"source alias {alias} is assigned more than once")
        used[alias] = str(source_id)
        highest = max(highest, number)
        aliases[str(source_id)] = {**entry, "alias": alias}

    normalized_sources: dict[str, dict[str, Any]] = {}
    for raw in sources:
        source = {str(key): value for key, value in dict(raw).items()}
        source_id = str(source.get("source_id") or "")
        if not source_id:
            raise ValueError("evidence source metadata requires source_id")
        normalized_sources[source_id] = source

    for source_id in sorted(normalized_sources):
        metadata = normalized_sources[source_id]
        if source_id in aliases:
            aliases[source_id] = {**metadata, **aliases[source_id]}
            continue
        highest += 1
        alias = format_source_alias(highest)
        aliases[source_id] = {**metadata, "alias": alias}
        used[alias] = source_id
    return aliases


def source_provenance(
    row: Mapping[str, Any],
    *,
    reference: str | None = None,
) -> dict[str, Any]:
    """Extract coordinator-owned provenance from an ephemeral projected row."""
    alias, reference_row = parse_source_reference(
        str(reference or row.get("_SourceRef") or "")
    )
    return {
        "scope_type": str(row.get("_ScopeType") or ""),
        "scope_id": str(row.get("_ScopeId") or ""),
        "hunt_id": str(row.get("_HuntId") or ""),
        "org_id": str(row.get("_OrgId") or ""),
        "client_id": str(row.get("_ClientId") or ""),
        "hostname": str(row.get("_Hostname") or ""),
        "fqdn": str(row.get("_Fqdn") or ""),
        "flow_id": str(row.get("_FlowId") or ""),
        "artifact": str(row.get("_Artifact") or ""),
        "source": str(row.get("_Component") or ""),
        "source_id": str(row.get("_SourceId") or ""),
        "source_alias": str(row.get("_SourceAlias") or alias),
        "source_row_number": int(
            row.get("_SourceRowNumber")
            or row.get("_FlowRowNumber")
            or row.get("_RowNumber")
            or reference_row
        ),
    }
