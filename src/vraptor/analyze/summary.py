"""Compact human-facing summaries for Velociraptor analysis results."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from vraptor.analyze import references as evidence_references


MAX_PRIMARY_FINDINGS = 20
MAX_EXAMPLES_PER_FINDING = 3
MAX_PREVIEW_CHARS = 320
SUPPLEMENT_VALUE_CHARS = 600
MAX_FULL_CONTEXT_CHARS = 2_000_000
MAX_CHAT_SUMMARY_CHARS = 32_000
MAX_TIMELINE_ROWS = 20


def unique_limitations(values: Iterable[str]) -> list[str]:
    """Remove protocol prefixes and exact normalized duplicates without losing caveats."""
    result = []
    seen = set()
    for value in values:
        text = re.sub(r"^(?:-\s+)?LIMITATION\s*\t\s*", "", str(value).strip())
        key = " ".join(text.casefold().split()).rstrip(".")
        if key and key not in seen:
            result.append(text)
            seen.add(key)
    return result

_TIMESTAMP_FIELDS = (
    "timestamp",
    "eventtime",
    "eventtimestamp",
    "datetime",
    "starttime",
    "endtime",
    "created",
    "creationtime",
    "modified",
    "lastmodified",
    "lastactive",
    "lastruntime",
    "mtime",
    "atime",
    "ctime",
)
_HOST_FIELDS = ("hostname", "fqdn", "computer", "host", "clientid")
_ACTOR_FIELDS = (
    "username",
    "user",
    "accountname",
    "targetusername",
    "subjectusername",
    "sid",
    "usersid",
    "logonid",
    "sessionid",
)
_ACTION_FIELDS = (
    "commandline",
    "processname",
    "process",
    "imagepath",
    "image",
    "executable",
    "action",
    "eventid",
    "description",
    "path",
    "name",
)


def safe_artifact_name(value: str) -> str:
    raw = str(value).strip() or "unknown-artifact"
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-.")
    readable = (token or "unknown-artifact")[:120].rstrip("-.")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{readable}--{digest}"


def artifact_report_path(artifact: str) -> Path:
    return Path("artifact-analysis") / f"{safe_artifact_name(artifact)}.md"


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _visible_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(name): value
        for name, value in fields.items()
        if re.sub(r"[^a-z0-9]", "", str(name).casefold())
        not in {"evidencesha256", "evidencehash", "deduphash"}
    }


def _preview(value: Any, *, limit: int = MAX_PREVIEW_CHARS) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def compress_refs(values: Iterable[Any]) -> str:
    by_alias: dict[str, set[int]] = {}
    for value in values:
        reference = str(value or "").strip()
        if not reference:
            continue
        alias, row_number = evidence_references.parse_source_reference(reference)
        by_alias.setdefault(alias, set()).add(row_number)
    ranges: list[str] = []
    for alias in sorted(by_alias, key=evidence_references.parse_source_alias):
        start: int | None = None
        end: int | None = None
        for row_number in sorted(by_alias[alias]):
            if start is None or end is None:
                start = end = row_number
                continue
            if row_number == end + 1:
                end = row_number
                continue
            ranges.append(
                f"{alias}-R{start}"
                if start == end
                else f"{alias}-R{start}–R{end}"
            )
            start = end = row_number
        if start is not None and end is not None:
            ranges.append(
                f"{alias}-R{start}"
                if start == end
                else f"{alias}-R{start}–R{end}"
            )
    return ", ".join(ranges) or "-"


def _source_group_key(evidence: Mapping[str, Any]) -> tuple[str, ...]:
    source = dict(evidence.get("source") or {})
    has_source_row = bool(source.get("source_row_number"))
    return (
        str(source.get("hostname") or source.get("fqdn") or ""),
        str(source.get("client_id") or ""),
        str(source.get("flow_id") or ""),
        str(source.get("artifact") or evidence.get("artifact") or ""),
        str(source.get("source_alias") or ""),
        str(source.get("source") or ""),
        "" if has_source_row else str(int(evidence.get("chunk_index") or 0) + 1),
        "" if has_source_row else str(int(evidence.get("chunk_count") or 0)),
    )


def grouped_sources(evidence_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    for raw in evidence_rows:
        evidence = dict(raw)
        key = _source_group_key(evidence)
        group = groups.setdefault(
            key,
            {
                "hostname": key[0],
                "client_id": key[1],
                "flow_id": key[2],
                "artifact": key[3],
                "source_alias": key[4],
                "source": key[5],
                "chunk": f"{key[6]}/{key[7]}" if key[7] not in {"", "0"} else "",
                "refs": [],
            },
        )
        group["refs"].append(evidence.get("ref"))
    rendered: list[dict[str, Any]] = []
    for group in groups.values():
        group["refs"] = compress_refs(group["refs"])
        rendered.append(group)
    return rendered


def representative_examples(
    evidence_rows: Iterable[Mapping[str, Any]],
    *,
    limit: int = MAX_EXAMPLES_PER_FINDING,
) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in evidence_rows:
        evidence = dict(raw)
        fields = _visible_fields(dict(evidence.get("fields") or {}))
        if not fields:
            continue
        identity = _canonical(fields)
        if identity in seen:
            continue
        seen.add(identity)
        examples.append(
            {
                "ref": str(evidence.get("ref") or ""),
                "label": (
                    f"{evidence.get('artifact', '')}:{evidence.get('ref', '')}"
                    if evidence.get("artifact")
                    else str(evidence.get("ref") or "")
                ),
                "artifact": str(evidence.get("artifact") or ""),
                "fields": {name: _preview(value) for name, value in fields.items()},
            }
        )
        if len(examples) >= limit:
            break
    return examples


def preview_fields(fields: Mapping[str, Any]) -> dict[str, str]:
    return {
        name: _preview(value)
        for name, value in _visible_fields(fields).items()
    }


def compact_result(
    result: Mapping[str, Any],
    *,
    artifact_reports: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the compact JSON contract returned to chat, GUI, and CLI."""
    payload = copy.deepcopy(dict(result))
    payload["limitations"] = unique_limitations(payload.get("limitations") or [])
    compact_findings: list[dict[str, Any]] = []
    all_findings = list(payload.get("findings") or [])
    declared_finding_count = (
        len(all_findings)
        if payload.get("final_review")
        else max(len(all_findings), int(payload.get("finding_count") or 0))
    )
    for index, finding in enumerate(all_findings):
        evidence = list(finding.get("evidence") or [])
        has_source_evidence = bool(evidence)
        compact_findings.append(
            {
                "id": str(finding.get("id") or ""),
                "confidence": str(finding.get("confidence") or "unknown"),
                "domains": list(finding.get("domains") or []),
                "summary": str(finding.get("summary") or ""),
                "occurrence_count": (
                    len(evidence)
                    if has_source_evidence
                    else int(finding.get("occurrence_count") or 0)
                ),
                "sources": (
                    grouped_sources(evidence)
                    if has_source_evidence
                    else copy.deepcopy(list(finding.get("sources") or []))
                ),
                "examples": (
                    representative_examples(evidence)
                    if has_source_evidence and index < MAX_PRIMARY_FINDINGS
                    else copy.deepcopy(list(finding.get("examples") or []))[
                        :MAX_EXAMPLES_PER_FINDING
                    ]
                    if index < MAX_PRIMARY_FINDINGS
                    else []
                ),
            }
        )
    payload["findings"] = compact_findings
    payload["finding_count"] = declared_finding_count
    payload["primary_finding_count"] = min(
        len(compact_findings), MAX_PRIMARY_FINDINGS
    )
    payload["indexed_finding_count"] = max(
        0, len(compact_findings) - MAX_PRIMARY_FINDINGS
    )
    payload["findings_omitted_from_summary"] = max(
        0, declared_finding_count - len(compact_findings)
    )
    payload["relevant_context"] = [
        {
            "summary": str(item.get("summary") or "Relevant context"),
            "finding_id": str(item.get("finding_id") or ""),
            "context_type": str(item.get("context_type") or "general"),
            "artifact": str(item.get("artifact") or ""),
            "ref": str(item.get("ref") or ""),
            "fields": {
                name: _preview(value)
                for name, value in _visible_fields(
                    dict(item.get("fields") or {})
                ).items()
            },
        }
        if isinstance(item, Mapping)
        else str(item)
        for item in list(payload.get("relevant_context") or [])[:10]
    ]
    if "investigative_leads" in payload:
        leads = list(payload["investigative_leads"] or [])
        payload["investigative_lead_count"] = len({item["candidate_id"] for item in leads})
        payload["investigative_leads"] = [
            {
                **{key: value for key, value in item.items() if key != "_full_fields"},
                "fields": preview_fields(item.get("fields") or {}),
            }
            for item in leads
        ]
    if artifact_reports:
        payload["artifact_reports"] = dict(sorted(artifact_reports.items()))
    payload["evidence_persisted"] = False
    return payload


def source_group_text(group: Mapping[str, Any]) -> str:
    identity = str(group.get("hostname") or group.get("client_id") or "unknown host")
    client_id = str(group.get("client_id") or "")
    if client_id and client_id != identity:
        identity += f" ({client_id})"
    components = [identity]
    if group.get("flow_id"):
        components.append(str(group["flow_id"]))
    if group.get("artifact"):
        components.append(str(group["artifact"]))
    if group.get("source") and group.get("source") != group.get("artifact"):
        components.append(str(group["source"]))
    if group.get("refs"):
        components.append(str(group["refs"]))
    elif group.get("chunk"):
        components.append(f"chunk {group['chunk']} {group.get('refs', '-')}".strip())
    return " / ".join(components)


def render_compact_findings(result: Mapping[str, Any]) -> list[str]:
    raw_findings = list(result.get("findings") or [])
    summary = (
        dict(result)
        if raw_findings
        and all("sources" in finding and "examples" in finding for finding in raw_findings)
        else compact_result(result)
    )
    findings = list(summary.get("findings") or [])
    if not findings:
        if result.get("review_status") == "not_requested":
            return ["No preliminary candidates were returned; final review was not requested. This is not a benign verdict."]
        if dict(result.get("final_review") or {}).get("status") == "failed":
            return ["Supported findings unavailable: final AI review failed."]
        return ["No reportable findings were identified."]
    primary_count = min(
        len(findings),
        max(
            0,
            int(summary.get("primary_finding_count") or MAX_PRIMARY_FINDINGS),
        ),
    )
    lines: list[str] = []
    for finding in findings[:primary_count]:
        finding_id = str(finding.get("id") or "Finding")
        lines.extend(
            [
                f"### {finding_id}: {finding.get('summary', '')}",
                "",
                f"- Confidence: `{finding.get('confidence', 'unknown')}`",
                "- ATT&CK tactics: "
                + (", ".join(finding.get("domains") or []) or "not specified"),
                f"- Selected supporting rows: {int(finding.get('occurrence_count') or 0)}",
            ]
        )
        for source in finding.get("sources") or []:
            lines.append(f"- Source: `{source_group_text(source)}`")
        examples = list(finding.get("examples") or [])
        if examples:
            lines.extend(["", "Representative examples:", ""])
            for example in examples:
                fields = "; ".join(
                    f"{name}={value}"
                    for name, value in dict(example.get("fields") or {}).items()
                )
                lines.append(f"- `{example.get('label') or example.get('ref') or '-'}` {fields}")
        lines.append("")
    indexed_findings = findings[primary_count:]
    if indexed_findings:
        lines.extend(["### Additional findings index", ""])
        for finding in indexed_findings:
            finding_id = str(finding.get("id") or "Finding")
            confidence = str(finding.get("confidence") or "unknown")
            finding_summary = _preview(str(finding.get("summary") or ""))
            occurrence_count = int(finding.get("occurrence_count") or 0)
            lines.append(
                f"- `{finding_id}` [{confidence}] {finding_summary} "
                f"(selected supporting rows: {occurrence_count})"
            )
        lines.append("")
    omitted = int(summary.get("findings_omitted_from_summary") or 0)
    if omitted:
        lines.append(
            f"{omitted} additional finding group(s) were not available in this "
            "compact result; consult linked detailed reports when present."
        )
    lines.append(
        f"Finding representation: {primary_count} detailed, "
        f"{len(indexed_findings)} indexed, {omitted} unavailable."
    )
    return lines


def render_final_review(
    result: Mapping[str, Any], *, compact: bool = False,
) -> list[str]:
    review = dict(result.get("final_review") or {})
    if not review:
        return []
    lines = ["", "### Final AI review", "",
             f"- Status: `{review.get('status')}`; candidates: {review.get('candidate_count', 0)}; "
             f"supported findings: {len(result.get('findings') or [])}."]
    leads = list(result.get("investigative_leads") or [])
    if leads:
        lines.extend(["", "### Unresolved investigative leads", ""])
        for item in leads[:10] if compact else leads:
            text = _preview(item.get("summary")) if compact else item.get("summary")
            lines.append(f"- `{item.get('candidate_id')}` `{item.get('ref')}`: {text}")
        if compact and len(leads) > 10:
            lines.append(f"- {len(leads) - 10} additional source-linked lead entries in the report.")
    if review.get("dispositions"):
        lines.extend(["", "### Candidate dispositions", ""])
        if compact:
            lines.append(f"- All {len(review['dispositions'])} dispositions and source references "
                         "are retained in the report and structured result.")
            return lines
        for item in review["dispositions"]:
            lines.append(f"- `{item['candidate_id']}` → `{item['disposition']}` "
                         f"{('→ `' + item['finding_id'] + '` ') if item.get('finding_id') else ''}"
                         f"({compress_refs(item['refs'])}): {item['rationale']}")
    return lines


def render_relevant_context(result: Mapping[str, Any]) -> list[str]:
    """Render bounded context with its finding and semantic relationship."""
    summary = compact_result(result)
    items = list(summary.get("relevant_context") or [])
    if not items:
        return ["No additional finding-linked context was retained."]
    lines: list[str] = []
    for raw in items[:10]:
        if not isinstance(raw, Mapping):
            lines.append(f"- {raw}")
            continue
        finding_id = str(raw.get("finding_id") or "environment")
        context_type = str(raw.get("context_type") or "general")
        ref = str(raw.get("ref") or "-")
        artifact = str(raw.get("artifact") or "")
        fields = "; ".join(
            f"{name}={value}"
            for name, value in dict(raw.get("fields") or {}).items()
        )
        source = " / ".join(value for value in (artifact, ref) if value) or "unknown source"
        suffix = f" — {fields}" if fields else ""
        lines.append(
            f"- `{finding_id}` `{context_type}` `{source}`: "
            f"{raw.get('summary') or 'Relevant context'}{suffix}"
        )
    return lines


def _normalized_field_map(fields: Mapping[str, Any]) -> dict[str, tuple[str, Any]]:
    return {
        re.sub(r"[^a-z0-9]", "", str(name).casefold()): (str(name), value)
        for name, value in fields.items()
    }


def _utc_timestamp(value: Any) -> str:
    """Return an unambiguous UTC timestamp or an empty value.

    Naive timestamps are deliberately omitted because labelling them UTC would
    strengthen the source evidence beyond what the row establishes.
    """
    raw = str(value or "").strip()
    parsed: datetime | None = None
    if re.fullmatch(r"\d{10}(?:\.\d+)?", raw):
        parsed = datetime.fromtimestamp(float(raw), tz=timezone.utc)
    elif re.fullmatch(r"\d{13}", raw):
        parsed = datetime.fromtimestamp(int(raw) / 1_000, tz=timezone.utc)
    elif re.fullmatch(r"\d{16}", raw):
        parsed = datetime.fromtimestamp(int(raw) / 1_000_000, tz=timezone.utc)
    elif re.fullmatch(r"\d{19}", raw):
        parsed = datetime.fromtimestamp(int(raw) / 1_000_000_000, tz=timezone.utc)
    else:
        candidate = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return ""
        if parsed.tzinfo is None:
            return ""
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds" if parsed.microsecond else "seconds"
    ).replace("+00:00", "Z")


def _timeline_values(
    normalized: Mapping[str, tuple[str, Any]],
    names: Iterable[str],
    *,
    limit: int,
) -> str:
    values: list[str] = []
    for name in names:
        if name not in normalized:
            continue
        original_name, value = normalized[name]
        preview = _preview(value, limit=160)
        if preview:
            values.append(f"{original_name}={preview}")
        if len(values) >= limit:
            break
    return "; ".join(values)


def _timeline_row(
    *,
    fields: Mapping[str, Any],
    default_host: str,
    evidence_source: str,
    interpretation: str,
    confidence: str,
) -> tuple[str, str, str, str, str, str, str] | None:
    normalized = _normalized_field_map(fields)
    timestamp = ""
    for name in _TIMESTAMP_FIELDS:
        if name in normalized:
            timestamp = _utc_timestamp(normalized[name][1])
            if timestamp:
                break
    if not timestamp:
        return None
    host = default_host
    for name in _HOST_FIELDS:
        if name in normalized and str(normalized[name][1]).strip():
            host = _preview(normalized[name][1], limit=120)
            break
    actor = _timeline_values(normalized, _ACTOR_FIELDS, limit=3) or "-"
    action = _timeline_values(normalized, _ACTION_FIELDS, limit=3)
    return (
        timestamp,
        host or "-",
        actor,
        action or _preview(interpretation, limit=240) or "-",
        evidence_source or "-",
        _preview(interpretation, limit=240) or "-",
        confidence or "unknown",
    )


def _timeline_cell(value: Any) -> str:
    return _preview(value, limit=320).replace("|", "\\|") or "-"


def render_utc_timeline(
    result: Mapping[str, Any],
    *,
    default_host: str = "",
    limit: int = MAX_TIMELINE_ROWS,
) -> list[str]:
    """Render a bounded evidence-linked timeline from time-bearing examples.

    Only timezone-aware ISO values or recognizable Unix epochs are accepted, so
    every timestamp displayed in this table can safely be normalized to UTC.
    """
    summary = compact_result(result)
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    confidence_by_finding: dict[str, str] = {}
    for finding in summary.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        finding_id = str(finding.get("id") or "")
        confidence = str(finding.get("confidence") or "unknown")
        confidence_by_finding[finding_id] = confidence
        interpretation = str(finding.get("summary") or "Material host activity")
        for example in finding.get("examples") or []:
            if not isinstance(example, Mapping):
                continue
            source = str(example.get("label") or example.get("ref") or "")
            row = _timeline_row(
                fields=dict(example.get("fields") or {}),
                default_host=default_host,
                evidence_source=source,
                interpretation=interpretation,
                confidence=confidence,
            )
            if row:
                rows.append(row)
    for context in summary.get("relevant_context") or []:
        if not isinstance(context, Mapping):
            continue
        finding_id = str(context.get("finding_id") or "")
        artifact = str(context.get("artifact") or "")
        ref = str(context.get("ref") or "")
        source = " / ".join(value for value in (artifact, ref) if value)
        row = _timeline_row(
            fields=dict(context.get("fields") or {}),
            default_host=default_host,
            evidence_source=source,
            interpretation=str(context.get("summary") or "Relevant context"),
            confidence=confidence_by_finding.get(finding_id, "context"),
        )
        if row:
            rows.append(row)
    unique_rows = sorted(set(rows), key=lambda row: row)
    if not unique_rows:
        return [
            "No unambiguous time-bearing material entries were retained in the "
            "compact result; source-local or timezone-unknown values were not "
            "relabelled as UTC."
        ]
    lines = [
        "| Timestamp (UTC) | Host | User/session | Process/action | Evidence source | Interpretation | Confidence |",
        "|---|---|---|---|---|---|---|",
    ]
    effective_limit = max(1, int(limit))
    lines.extend(
        "| " + " | ".join(_timeline_cell(value) for value in row) + " |"
        for row in unique_rows[:effective_limit]
    )
    if len(unique_rows) > effective_limit:
        lines.append(
            f"\n{len(unique_rows) - effective_limit} additional timeline row(s) omitted."
        )
    return lines


def analysis_stage(result: Mapping[str, Any], status: str = "") -> str:
    """Explain completion without upgrading missing or failed final review."""
    status = str(status or result.get("status") or "unknown")
    review = str(dict(result.get("final_review") or {}).get("status") or "")
    if result.get("review_status") == "not_requested":
        return "preliminary analysis " + status + "; final synthesis not requested"
    if result.get("ai_review_status") == "skipped" or status in {"planned", "prepared"}:
        return "prepared only; AI analysis not run"
    if review == "failed":
        return "blocked: final review failed; assessment remains provisional"
    if status == "failed":
        return "blocked: analysis failed"
    if status in {"running", "pending"}:
        return "analysis " + status + "; final review pending"
    if review == "complete":
        return "final review complete" + ("; coverage limitations remain" if status != "complete" else "")
    return "final review not recorded; completion unverified"


def render_flow_freshness(flows: Iterable[Mapping[str, Any]]) -> list[str]:
    """Render existing flow metadata, never treating acquisition as event coverage."""
    flows = list(flows)
    if not flows:
        return ["- Collection dates and reuse: unavailable in this checkpoint."]
    lines = ["", "| Flow | Created (UTC) | Last active (UTC) | Selection |",
             "|---|---|---|---|"]
    for flow in flows[:20]:
        values = [str(flow.get("flow_id") or "unknown"),
                  _utc_timestamp(flow.get("created")) or "unknown",
                  _utc_timestamp(flow.get("last_active")) or "unknown",
                  str(flow.get("reuse_decision") or "unknown")]
        lines.append("| " + " | ".join(value.replace("|", "\\|").replace("\n", " ") for value in values) + " |")
    if len(flows) > 20:
        lines.append(f"- {len(flows) - 20} additional flow records omitted; see the request checkpoint.")
    lines.append("- Flow dates describe acquisition, not the event period reviewed. "
                 "A newer analysis does not refresh reused evidence or establish current host state.")
    return lines


def render_resume(result: Mapping[str, Any], status: str = "") -> list[str]:
    """Expose saved recovery even when no detailed failed-stage diagnostics exist."""
    effective_status = str(status or result.get("status") or "")
    failed_review = dict(result.get("final_review") or {}).get("status") == "failed"
    command = str(dict(result.get("troubleshooting") or {}).get("resume_command") or "")
    if not command or (effective_status not in {"failed", "complete_with_failures"} and not failed_review):
        return []
    return ["", "Check for an active runner or monitor for this request before resuming.",
            "Resume using the same configuration (collection failures may still require separate recovery):",
            "", "```sh", command, "```"]


def render_chat_summary(
    result: Mapping[str, Any],
    *,
    title: str = "Analysis summary",
    status: str = "",
    coverage: Mapping[str, Any] | None = None,
    flow_metadata: Iterable[Mapping[str, Any]] | None = None,
    analysis_completed_at: str = "",
    collection_complete: bool | None = None,
) -> str:
    """Render the bounded Markdown contract that callers surface to chat."""
    payload = dict(result)
    effective_coverage = dict(coverage or payload.get("coverage") or {})
    effective_status = str(status or payload.get("status") or "unknown")
    lines = [f"## {title}", "", f"- Status: `{effective_status}`"]
    if collection_complete is not None:
        lines.append("- Collection: " + ("complete" if collection_complete else "incomplete or failed"))
    # Hunt summaries have their own review contract; do not require host synthesis there.
    if flow_metadata is not None or payload.get("final_review") or payload.get("review_status"):
        lines.append(f"- Analysis: {analysis_stage(payload, effective_status)}")
    if analysis_completed_at:
        lines.append(f"- Analysis completed: `{analysis_completed_at}`")
    if flow_metadata is not None:
        lines.extend(render_flow_freshness(flow_metadata))
    troubleshooting = dict(payload.get("troubleshooting") or {})
    if troubleshooting.get("failed_stages"):
        lines.append(f"- Troubleshooting: `{troubleshooting.get('diagnostics_file', '')}`")
        for item in troubleshooting["failed_stages"][:10]:
            last = (item.get("attempt_history") or [{}])[-1]
            codes = ", ".join(str(d.get("code") or "") for d in last.get("defects") or [])
            lines.append(f"- Failed `{item.get('stage')}` / `{item.get('task_id')}` after {item.get('attempts', 0)} attempts: {last.get('category', item.get('category', 'analysis_error'))}; {codes or last.get('message', item.get('message', 'See diagnostics.'))}")
    lines.extend(render_resume(payload, effective_status))
    if effective_coverage:
        for label, key in (
            ("Result review", "result_review"),
            ("Target execution", "target_execution"),
            ("Analysis time filter", "time_filter"),
            ("Overall coverage", "overall"),
        ):
            value = str(effective_coverage.get(key) or "").strip()
            if value:
                lines.append(f"- {label}: `{value}`")
    lines.extend(
        [
            "",
            "### Assessment",
            "",
            str(payload.get("answer") or "No assessment text was returned."),
            "",
            "### Preliminary candidates" if payload.get("review_status") == "not_requested" else "### Findings",
            "",
            *render_compact_findings(payload),
            "",
            "### Relevant context",
            "",
            *render_relevant_context(payload),
            *render_final_review(payload, compact=True),
            "",
            "### Limitations",
            "",
        ]
    )
    limitations = [
        str(value).strip()
        for value in payload.get("limitations") or []
        if str(value).strip()
    ]
    lines.extend(f"- {value}" for value in limitations)
    if not limitations:
        lines.append("- None identified.")
    lines.extend(["", "### Next action", ""])
    follow_up = [
        str(value).strip()
        for value in payload.get("bounded_follow_up") or []
        if str(value).strip()
    ]
    lines.extend(f"- {value}" for value in follow_up)
    if not follow_up:
        lines.append("- No bounded follow-up was returned.")
    rendered = "\n".join(lines).rstrip() + "\n"
    if len(rendered) <= MAX_CHAT_SUMMARY_CHARS:
        return rendered
    suffix = (
        "\n\nChat summary reached its 32,000-character guard; consult the "
        "linked analysis report for remaining detail.\n"
    )
    clipped = rendered[
        : MAX_CHAT_SUMMARY_CHARS - len(suffix)
    ].rsplit("\n", 1)[0].rstrip()
    return clipped + suffix


def _full_evidence_groups(
    findings: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        finding_id = str(finding.get("id") or "Finding")
        for raw in finding.get("evidence") or []:
            evidence = dict(raw)
            selected_fields = _visible_fields(dict(evidence.get("fields") or {}))
            full_fields = _visible_fields(
                dict(evidence.get("_full_fields") or selected_fields)
            )
            if not selected_fields or not full_fields:
                continue
            artifact = str(evidence.get("artifact") or "")
            key = (artifact, _canonical(selected_fields))
            group = groups.setdefault(
                key,
                {
                    "artifact": artifact,
                    "fields": full_fields,
                    "finding_ids": [],
                    "evidence": [],
                },
            )
            group["finding_ids"].append(finding_id)
            group["evidence"].append(evidence)
    return list(groups.values())


def _result_full_evidence_groups(
    result: Mapping[str, Any],
) -> list[dict[str, Any]]:
    findings = [
        dict(item)
        for item in result.get("findings") or []
        if isinstance(item, Mapping)
    ]
    context_evidence = []
    for raw in [*(result.get("relevant_context") or []), *(result.get("investigative_leads") or [])]:
        if not isinstance(raw, Mapping) or not raw.get("_full_fields"):
            continue
        context_evidence.append(
            {
                "artifact": raw.get("artifact"),
                "ref": raw.get("ref"),
                "source": raw.get("source"),
                "fields": raw.get("fields"),
                "_full_fields": raw.get("_full_fields"),
            }
        )
    if context_evidence:
        findings.append(
            {
                "id": "Selected review context",
                "evidence": context_evidence,
            }
        )
    return _full_evidence_groups(findings)


def _render_full_groups(groups: Iterable[Mapping[str, Any]]) -> list[str]:
    lines: list[str] = []
    retained = 0
    omitted = 0
    used_chars = 0
    for group in groups:
        field_json = json.dumps(
            group["fields"],
            ensure_ascii=False,
            indent=2,
            default=str,
        )
        if used_chars + len(field_json) > MAX_FULL_CONTEXT_CHARS:
            omitted += 1
            continue
        retained += 1
        used_chars += len(field_json)
        lines.extend(
            [
                f"### Evidence {retained}",
                "",
                "- Supports: " + ", ".join(dict.fromkeys(group["finding_ids"])),
                f"- Repeated selected rows represented: {len(group['evidence'])}",
            ]
        )
        for source in grouped_sources(group["evidence"]):
            lines.append(f"- Source: `{source_group_text(source)}`")
        lines.extend(["", "````json", field_json, "````", ""])
    if omitted:
        lines.extend(
            [
                f"{omitted} additional selected full-row group(s) exceeded the "
                "2,000,000-character report guard and remain authoritative in "
                "Velociraptor.",
                "",
            ]
        )
    return lines


def discard_full_rows(value: Any) -> Any:
    """Remove transient selected-row payloads before durable JSON persistence."""
    if isinstance(value, list):
        return [discard_full_rows(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        str(key): discard_full_rows(item)
        for key, item in value.items()
        if str(key) != "_full_fields"
    }


def render_time_filter_provenance(value: Mapping[str, Any] | None) -> list[str]:
    """Render compact, value-free analysis-time filter provenance."""
    time_filter = dict(value or {})
    if not time_filter:
        return []
    lines = [
        f"- Coverage: `{time_filter.get('coverage', 'not_requested')}`",
        f"- Application: `{time_filter.get('application_stage', 'not_applied')}`",
    ]
    if time_filter.get("time_after"):
        lines.append(f"- After (exclusive): `{time_filter['time_after']}`")
    if time_filter.get("time_before"):
        lines.append(f"- Before (exclusive): `{time_filter['time_before']}`")
    requested_roles = list(time_filter.get("requested_time_fields") or [])
    if requested_roles:
        lines.append("- Requested roles: " + ", ".join(f"`{v}`" for v in requested_roles))
    for artifact, raw_resolution in sorted(
        dict(time_filter.get("resolved_artifacts") or {}).items()
    ):
        resolution = dict(raw_resolution)
        expressions = [
            expression
            for role in resolution.get("roles") or []
            for expression in dict(resolution.get("expressions") or {}).get(role, [])
        ]
        lines.append(
            f"- Filtered `{artifact}` using "
            + ", ".join(f"`{expression}`" for expression in expressions)
        )
    unsupported = list(time_filter.get("unsupported_artifacts") or [])
    if unsupported:
        lines.append(
            "- Unfiltered without a verified role: "
            + ", ".join(f"`{artifact}`" for artifact in unsupported)
        )
    validation = dict(time_filter.get("artifact_validation") or {})
    if validation:
        lines.append(
            "- Server validation: "
            + ", ".join(
                f"`{artifact}={dict(status).get('validation', 'unknown')}`"
                for artifact, status in sorted(validation.items())
            )
        )
    return lines


def render_artifact_report(result: Mapping[str, Any]) -> str:
    artifact = str(result.get("artifact") or "unknown")
    coverage = dict(result.get("coverage") or {})
    lines = [
        f"# Artifact analysis: {artifact}",
        "",
        f"- Review status: `{result.get('status', 'unknown')}`",
        f"- Review coverage: {int(coverage.get('reviewed_rows') or 0)}/{int(coverage.get('planned_rows') or 0)} exposed rows",
        f"- Collection coverage: `{dict(result.get('collection_coverage') or {}).get('status', 'not_assessed')}`; flow `{dict(result.get('collection_coverage') or {}).get('flow_state', 'UNKNOWN')}`",
        "- Velociraptor source of truth: yes",
        "- Rows sharing manager-selected fields use one full projected representative.",
        f"- Analysis time filter: `{coverage.get('time_filter', 'not_requested')}`",
        "",
        "## Analysis time filter",
        "",
        *(
            render_time_filter_provenance(result.get("time_filter"))
            or ["- Not requested."]
        ),
        "",
        "## Analysis",
        "",
        str(result.get("answer") or "No artifact answer was produced."),
        "",
        "## Preliminary candidates — caller review required"
        if result.get("result_role") in {"provisional_candidates", "preliminary_candidates"} else "## Findings",
        "",
        *render_compact_findings(result),
        "",
        "## Relevant context",
        "",
        *render_relevant_context(result),
        *render_final_review(result),
        "",
        "## Selected full evidence",
        "",
    ]
    groups = _result_full_evidence_groups(result)
    if not groups:
        lines.append("No full evidence values were selected by the analysis manager.")
    lines.extend(_render_full_groups(groups))
    for heading, key in (("Limitations", "limitations"), ("Bounded follow-up", "bounded_follow_up")):
        lines.extend([f"## {heading}", ""])
        values = unique_limitations(result.get(key) or []) if key == "limitations" else list(result.get(key) or [])
        lines.extend(f"- {value}" for value in values)
        if not values:
            lines.append("- None.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def needs_finding_supplement(result: Mapping[str, Any]) -> bool:
    for group in _result_full_evidence_groups(result):
        fields = dict(group.get("fields") or {})
        artifact = str(group.get("artifact") or "").casefold()
        if "evtx" in artifact or "powershell" in artifact:
            return True
        if any(len(str(value)) > SUPPLEMENT_VALUE_CHARS for value in fields.values()):
            return True
    return False


def render_finding_supplement(result: Mapping[str, Any], *, title: str) -> str:
    lines = [
        f"# {title}",
        "",
        "This contains only manager-selected full values supporting findings or "
        "selected ambiguous review context. "
        "Rows with identical manager-selected fields are consolidated around one "
        "full projected representative; Velociraptor remains authoritative.",
        "",
    ]
    groups = _result_full_evidence_groups(result)
    lines.extend(_render_full_groups(groups))
    return "\n".join(lines).rstrip() + "\n"


def consolidate_exact_findings(
    findings: Iterable[Mapping[str, Any]], *, id_prefix: str
) -> list[dict[str, Any]]:
    """Merge only deterministic exact repeats; semantic grouping belongs to AI."""
    grouped: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    order: list[tuple[str, str, tuple[str, ...]]] = []
    for raw in findings:
        finding = copy.deepcopy(dict(raw))
        original_evidence = copy.deepcopy(list(finding.get("evidence") or []))
        summary = re.sub(r"\s+", " ", str(finding.get("summary") or "")).strip()
        key = (
            summary.casefold(),
            str(finding.get("confidence") or "unknown"),
            tuple(sorted(str(value) for value in finding.get("domains") or [])),
        )
        if key not in grouped:
            grouped[key] = finding
            grouped[key]["summary"] = summary
            grouped[key]["evidence"] = []
            order.append(key)
        target = grouped[key]
        seen = {
            _canonical(
                {
                    "artifact": item.get("artifact"),
                    "chunk_index": item.get("chunk_index"),
                    "ref": item.get("ref"),
                    "source": item.get("source"),
                    "fields": item.get("fields"),
                }
            )
            for item in target["evidence"]
        }
        for evidence in original_evidence:
            identity = _canonical(
                {
                    "artifact": evidence.get("artifact"),
                    "chunk_index": evidence.get("chunk_index"),
                    "ref": evidence.get("ref"),
                    "source": evidence.get("source"),
                    "fields": evidence.get("fields"),
                }
            )
            if identity not in seen:
                target["evidence"].append(copy.deepcopy(evidence))
                seen.add(identity)
    consolidated = [grouped[key] for key in order]
    for index, finding in enumerate(consolidated, start=1):
        finding["id"] = f"{id_prefix}{index}"
    return consolidated
