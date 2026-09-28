"""Synthesis policy and lossless preliminary handoffs shared by host and hunt review."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

MODES = ("none", "full")
VERSION = 1


def cache_key(
    *, results: Sequence[Mapping], question: str, plan: Mapping, execution: Mapping
) -> str:
    from vraptor.analyze.final_review import VERSION as review_version

    return fingerprint(
        {
            "version": VERSION,
            "review_version": review_version,
            "results": results,
            "question": question,
            "execution": execution,
            "plan": {
                key: plan.get(key)
                for key in (
                    "scope_type",
                    "task_mode",
                    "response_depth",
                    "analysis_limits",
                    "analysis_profile",
                    "analysis_objectives",
                    "artifacts",
                    "time_filter",
                    "collection_failures",
                )
            },
        }
    )


def cached_result(cache: Mapping, key: str) -> dict | None:
    result = cache.get("result")
    if (
        cache.get("input_fingerprint") == key
        and isinstance(result, dict)
        and (
            result.get("status") == "complete"
            or (
                result.get("status") == "complete_with_failures"
                and result.get("review_status") == "complete"
            )
        )
        and cache.get("result_fingerprint") == fingerprint(result)
    ):
        return copy.deepcopy(result)
    return None


def cache_record(result: Mapping, key: str) -> dict:
    return {
        "input_fingerprint": key,
        "result_fingerprint": fingerprint(result),
        "result": copy.deepcopy(dict(result)),
    }


def mode(value: str = "full") -> str:
    if value not in MODES:
        raise ValueError("synthesis must be none or full")
    return value


def fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def preliminary(
    results: Sequence[Mapping[str, Any]],
    *,
    question: str,
    scope: str = "host",
    failures: Sequence[str] = (),
) -> dict[str, Any]:
    """Combine accepted candidates without semantic merging or another model call.

    Candidate namespaces and context links remain local to each input. Exact
    duplicate records within that input are collapsed; host/source provenance is
    part of identity. A caller must perform the final evidential assessment.
    """
    findings, context, limitations, follow_up = [], [], list(failures), []
    coverage = dict.fromkeys(
        ("planned_chunks", "accepted_chunks", "planned_rows", "reviewed_rows"), 0
    )
    statuses = {str(r.get("status") or "failed") for r in results}
    if failures:
        statuses.add("failed")
    status = (
        "complete"
        if not statuses or statuses <= {"complete"}
        else "failed"
        if statuses == {"failed"}
        else "complete_with_failures"
    )
    groups = []
    for index, result in enumerate(results, 1):
        mapping, seen = {}, {}
        artifact = str(result.get("artifact") or "multiple")
        for finding in result.get("findings") or []:
            item = copy.deepcopy(finding)
            old_id = str(item.pop("id", ""))
            item.setdefault("artifact", artifact)
            key = fingerprint(item)
            if key not in seen:
                new_id = f"A{index:04d}:F{len(seen) + 1}"
                seen[key] = new_id
                findings.append({"id": new_id, **item})
            mapping[old_id] = seen[key]
        for record in result.get("relevant_context") or []:
            if isinstance(record, Mapping):
                record = copy.deepcopy(dict(record))
                record["finding_id"] = mapping.get(
                    str(record.get("finding_id") or ""), ""
                )
                record.setdefault("artifact", artifact)
                context.append(record)
        for name in coverage:
            coverage[name] += int(dict(result.get("coverage") or {}).get(name) or 0)
        limitations.extend(result.get("limitations") or [])
        follow_up.extend(result.get("bounded_follow_up") or [])
        groups.append(
            {
                "artifact": artifact,
                "candidate_count": len(seen),
                "status": result.get("status", "failed"),
                "coverage": copy.deepcopy(result.get("coverage") or {}),
            }
        )
    return {
        "format": f"{scope}-analysis-v2",
        "task": f"{scope}-analysis",
        "question": question,
        "status": status,
        "analysis_status": status,
        "synthesis_mode": "none",
        "review_status": "not_requested",
        "result_role": "preliminary_candidates",
        "coverage": coverage,
        "answer": f"{len(findings)} preliminary candidate(s); final synthesis was not requested. "
        "Candidates require evidence review and cross-artifact correlation by the caller.",
        "findings": findings,
        "finding_count": len(findings),
        "relevant_context": context,
        "limitations": list(dict.fromkeys(limitations)),
        "bounded_follow_up": list(dict.fromkeys(follow_up)),
        "groups": groups,
    }


def page(
    result: Mapping[str, Any],
    *,
    offset: int = 0,
    limit: int = 50,
    artifact: str = "",
    host: str = "",
    candidate: str = "",
    reference: str = "",
    evidence_offset: int = 0,
    context_offset: int = 0,
) -> dict:
    """Bounded, deterministic retrieval; filters never imply complete coverage."""
    if min(offset, evidence_offset, context_offset) < 0 or not 1 <= limit <= 200:
        raise ValueError("offset must be nonnegative; limit must be 1..200")

    def row_matches(row):
        return (
            (not artifact or row.get("artifact") == artifact)
            and (
                not host
                or host
                in {
                    str(row.get("source", {}).get(k) or "")
                    for k in ("hostname", "client_id")
                }
            )
            and (not reference or row.get("ref") == reference)
        )

    def bounded(record):
        item = copy.deepcopy(record)
        clipped = []
        for key, value in list(item.items()):
            if key == "fields":
                # Evidence remains source-addressable; retrieval is a preview.
                encoded = json.dumps(value, ensure_ascii=False)
                if len(encoded.encode()) > 4096:
                    item[key] = {"_preview": encoded[:1000]}
                    clipped.append(key)
            elif isinstance(value, str) and len(value) > 2048:
                item[key] = value[:2048]
                clipped.append(key)
        if clipped:
            item["truncated_fields"] = clipped
        return item

    matches = []
    for finding in result.get("findings") or []:
        evidence = finding.get("evidence") or []
        if artifact and not (
            finding.get("artifact") == artifact
            or any(e.get("artifact") == artifact for e in evidence)
        ):
            continue
        if host and not any(
            host
            in {
                str(e.get("source", {}).get(k) or "") for k in ("hostname", "client_id")
            }
            for e in evidence
        ):
            continue
        if candidate and finding.get("id") != candidate:
            continue
        if reference and not any(e.get("ref") == reference for e in evidence):
            continue
        matches.append(finding)
    selected, used_bytes = [], 0
    for finding in matches[offset : offset + limit]:
        item = bounded({k: v for k, v in finding.items() if k != "evidence"})
        rows = finding.get("evidence") or []
        if reference or host:
            rows = [row for row in rows if row_matches(row)]
        item["evidence"] = [
            bounded(row) for row in rows[evidence_offset : evidence_offset + 10]
        ]
        item["evidence_total"] = len(rows)
        item["evidence_next_offset"] = (
            evidence_offset + 10 if evidence_offset + 10 < len(rows) else None
        )
        size = len(json.dumps(item, ensure_ascii=False).encode())
        if selected and used_bytes + size > 96_000:
            break
        selected.append(item)
        used_bytes += size
    contexts = [
        row
        for row in result.get("relevant_context") or []
        if isinstance(row, Mapping)
        and row_matches(row)
        and (not candidate or row.get("finding_id") == candidate)
    ]
    context_page, context_bytes = [], 0
    for row in contexts[context_offset : context_offset + 20]:
        item = bounded(row)
        size = len(json.dumps(item, ensure_ascii=False).encode())
        if context_page and context_bytes + size > 32_000:
            break
        context_page.append(item)
        context_bytes += size
    next_context = context_offset + len(context_page)
    next_candidate = offset + len(selected)
    return {
        "status": result.get("status"),
        "review_status": result.get("review_status", "unknown"),
        "coverage": result.get("coverage", {}),
        "total_candidates": len(result.get("findings") or []),
        "matching_candidates": len(matches),
        "returned_candidates": len(selected),
        "undisplayed_candidates": max(0, len(matches) - len(selected)),
        "next_offset": next_candidate if next_candidate < len(matches) else None,
        "matching_context": len(contexts),
        "returned_context": len(context_page),
        "context_next_offset": next_context if next_context < len(contexts) else None,
        "relevant_context": context_page,
        "findings": selected,
        "preview_only": True,
    }
