"""Flat artifact-scoped execution for Velociraptor collection analysis."""

from __future__ import annotations

import asyncio
import copy
import csv
import io
import inspect
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Callable, Iterable

from vraptor.analyze import limits as analysis_limits
from vraptor.common import token_budget
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import analyst_execution_metadata
from vraptor.agent.factory import create_agent_runner
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentResult
from vraptor.agent.runtime import AgentRuntimeLimits
from vraptor.agent.runtime import is_output_limit_failure
from vraptor.agent.runtime import now_utc
from vraptor.agent.runtime import run_item_pool
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.analyze import summary as analysis_summary
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import references as evidence_references
from vraptor.analyze import final_review as host_final_review
from vraptor.analyze import synthesis as synthesis_policy
from vraptor.analyze import prompt_debug
from vraptor.analyze import recovery


RUN_SCHEMA_VERSION = 8
SYNTHESIS_SUMMARY_MAX_CHARS = 320
SYNTHESIS_EVIDENCE_ROWS_PER_FINDING = 3
SYNTHESIS_CONTEXT_ITEMS_PER_CHUNK = 5
DOMAIN_ARTIFACT_MARKERS = {
    "execution": (
        "evtx",
        "amcache",
        "bam",
        "prefetch",
        "appcompat",
        "timeline",
        "yara",
        "process",
        "mft",
    ),
    "persistence": (
        "service",
        "taskscheduler",
        "permanentwmi",
        "autoruns",
        "startup",
    ),
    "authentication": (
        "rdpauth",
        "explicitlogon",
        "logon",
        "authentication",
    ),
    "lateral_movement": (
        "rdpauth",
        "explicitlogon",
        "netstat",
        "remote",
        "smb",
        "winrm",
        "wmi",
    ),
    "network": (
        "network",
        "netstat",
        "dnscache",
        "rdpauth",
        "explicitlogon",
    ),
}
COVERAGE_TACTICS = {
    "execution": {"Execution"},
    "persistence": {"Persistence"},
    "authentication": {
        "Initial Access",
        "Privilege Escalation",
        "Credential Access",
    },
    "lateral_movement": {"Lateral Movement"},
    "network": {"Command and Control", "Exfiltration"},
}


def source_rows_from_csv(
    csv_evidence: str,
    source_aliases: dict[str, dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Build an ephemeral source-reference map for deterministic evidence hydration."""
    by_alias = {
        str(entry.get("alias") or ""): {**dict(entry), "source_id": source_id}
        for source_id, entry in source_aliases.items()
    }
    rows: dict[str, dict[str, str]] = {}
    for row in csv.DictReader(io.StringIO(csv_evidence)):
        ref = str(row.get("_SourceRef") or "").strip()
        if not ref or ref in rows:
            raise ValueError("ephemeral CSV contains an invalid source reference")
        alias, row_number = evidence_references.parse_source_reference(ref)
        source = by_alias.get(alias)
        if source is None:
            raise ValueError(f"ephemeral CSV uses unknown source alias {alias}")
        normalized = {str(key): str(value or "") for key, value in row.items()}
        normalized.update(
            {
                "_ScopeType": str(source.get("scope_type") or ""),
                "_ScopeId": str(source.get("scope_id") or ""),
                "_HuntId": str(source.get("hunt_id") or ""),
                "_OrgId": str(source.get("org_id") or ""),
                "_ClientId": str(source.get("client_id") or ""),
                "_Hostname": str(source.get("hostname") or ""),
                "_Fqdn": str(source.get("fqdn") or ""),
                "_SourceId": str(source.get("source_id") or ""),
                "_SourceAlias": alias,
                "_SourceRowNumber": str(row_number),
            }
        )
        rows[ref] = normalized
    return rows


def limits_from_plan(plan: dict[str, Any]) -> AgentRuntimeLimits:
    raw = plan.get("analysis_limits")
    if not isinstance(raw, dict):
        raise ValueError("analysis plan is missing analysis_limits")
    limits = analysis_limits.AnalysisLimits(
        model_context_tokens=int(raw["model_context_tokens"]),
        operational_context_tokens=int(raw["operational_context_tokens"]),
        maximum_input_tokens=int(raw["maximum_input_tokens"]),
        maximum_evidence_tokens_per_item=int(
            raw["maximum_evidence_tokens_per_item"]
        ),
        maximum_output_tokens=int(raw["maximum_output_tokens"]),
        maximum_analysis_item_rows=int(raw["maximum_analysis_item_rows"]),
        maximum_analysis_item_bytes=int(raw["maximum_analysis_item_bytes"]),
        token_encoding=str(raw["token_encoding"]),
        instruction_reserve_tokens=int(raw.get("instruction_reserve_tokens", analysis_limits.INSTRUCTION_RESERVE_TOKENS)),
        prior_context_reserve_tokens=int(raw.get("prior_context_reserve_tokens", analysis_limits.PRIOR_CONTEXT_RESERVE_TOKENS)),
        safety_reserve_tokens=int(raw.get("safety_reserve_tokens", analysis_limits.SAFETY_RESERVE_TOKENS)),
    )
    limits.validate()
    return limits.runtime_limits()


def model_visible_csv(csv_evidence: str) -> tuple[str, list[str]]:
    """Hide coordinator metadata while preserving the source-reference protocol."""
    reader = csv.DictReader(io.StringIO(csv_evidence))
    headers = list(reader.fieldnames or [])
    if "_SourceRef" not in headers:
        raise ValueError("CSV evidence is missing the required _SourceRef column")
    selectable = [name for name in headers if name and not name.startswith("_")]
    visible_headers = ["_SourceRef", *selectable]
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=visible_headers,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    for row in reader:
        writer.writerow({name: row.get(name, "") for name in visible_headers})
    return output.getvalue().rstrip("\n"), selectable


def render_chunk_prompt(
    *,
    plan: dict[str, Any],
    chunk: dict[str, Any],
    question: str,
    csv_evidence: str,
) -> str:
    artifact = str(chunk["artifact"])
    chunk_index = int(chunk["task_chunk_index"])
    chunk_count = int(chunk["task_chunk_count"])
    row_start = int(chunk["row_start"])
    row_end = int(chunk["row_end"])
    row_count = int(chunk["row_count"])
    objectives = [
        str(value).strip()
        for value in plan.get("analysis_objectives") or []
        if str(value).strip()
    ] or [
        "Answer the exact investigation question from the assigned rows.",
        "Preserve only evidence components needed for returned claims.",
        "State confidence-affecting limitations and the smallest useful follow-up.",
    ]
    visible_csv, selectable_fields = model_visible_csv(csv_evidence)
    selectable_text = ", ".join(selectable_fields) or "None"
    example_refs = [
        str(row.get("_SourceRef") or "")
        for row in csv.DictReader(io.StringIO(csv_evidence))
        if str(row.get("_SourceRef") or "")
    ][:2]
    example_ref = example_refs[0]
    example_evidence = "".join(
        f"EVIDENCE\tF1\t{ref}\n" for ref in example_refs
    )
    allow_uplift_candidates = bool(plan.get("allow_uplift_candidates"))
    uplift_example = (
        f"UPLIFT\t{example_ref}\tsite\tStable expected activity suitable for later whitelist review.\n"
        if allow_uplift_candidates
        else ""
    )
    uplift_instructions = (
        "You may also return sparse whitelist opportunities as "
        "UPLIFT<TAB>SourceRef<TAB>global|site<TAB>reason. Use global only for "
        "stable reusable Windows or vendor behavior and site for internal or "
        "organization-specific behavior. Return UPLIFT only when the complete "
        "row is clearly expected, stable, and free of conflicting suspicious "
        "behavior. Do not return a benign record for every row. A source "
        "reference cannot be both FINDING evidence and UPLIFT. The coordinator "
        "will copy the referenced payload; never copy evidence values into the "
        "response. UPLIFT records may accompany RESULT<TAB>no_reportable_findings.\n\n"
        if allow_uplift_candidates
        else ""
    )
    prompt = (
        "You are a read-only DFIR artifact analyst. You have no tools and must use only "
        "the CSV evidence in this prompt. Review every assigned row exactly once.\n\n"
        f"Question: {question.strip()}\n"
        f"Collection: {plan['collection_type']}\n"
        f"Request: {plan['request_id']}\n"
        f"Artifact: {artifact}\n"
        f"Components: {', '.join(chunk.get('components') or [])}\n"
        f"Chunk: {chunk_index + 1}/{chunk_count}\n"
        f"Chunk row range: {row_start + 1}-{row_end}\n"
        f"Rows: {row_count}\n"
        f"Profile: {plan.get('analysis_profile', '')}\n\n"
        f"Task mode: {plan.get('task_mode', 'host_forensics')}\n"
        f"Response depth: {plan.get('response_depth', 'standard')}\n\n"
        "Objectives:\n"
        + "\n".join(f"- {value}" for value in objectives)
        + "\n\n"
        "Return only question-relevant findings and context. Do not return JSON, raw "
        "rows, evidence values, an evidence catalogue, or review-accounting prose. "
        "A finding requires at least one EVIDENCE record. Python will hydrate exact "
        "evidence and provenance from the referenced source row.\n\n"
        "The _SourceRef column is coordinator-owned reference metadata. Copy its "
        "Sxxxx-R<number> value into the reference position. Never return _SourceRef "
        "as evidence and never copy any source value into the response. "
        f"Visible source fields for analysis: {selectable_text}.\n\n"
        "Return one complete tab-delimited response matching this example. The "
        "coordinator already owns artifact, chunk, row-range, row-count, and status "
        "metadata; do not repeat them:\n"
        "RESULT\tfindings\n"
        "FINDING\tF1\thigh\tExecution,Credential Access\tConcise question-relevant finding.\n"
        f"{example_evidence}"
        f"CONTEXT\tF1\t{example_ref}\tidentity\tMaterial identity or causal context that changes interpretation.\n"
        f"{uplift_example}"
        "LIMITATION\tConfidence-affecting limitation.\n"
        "FOLLOW_UP\tSmallest bounded next review.\n"
        "END\n\n"
        "Copy every Sxxxx-R<number> reference exactly from _SourceRef; never invent "
        "or modify references. Use CONTEXT<TAB>FindingId<TAB>SourceRef<TAB>identity|session|process|file|network|timeline|environment|general<TAB>Text. "
        "Use '-' as FindingId only for material environment-level context that cannot honestly be attached to a finding. "
        "When FindingId is '-', ContextType must be exactly environment. "
        "Use one EVIDENCE or CONTEXT record per source row and "
        "repeat records when multiple rows apply. Every finding requires at least one "
        "EVIDENCE record. Use only these Enterprise ATT&CK tactic names: "
        f"{', '.join(collection_analysis.ATTACK_TACTICS)}. Harmless case, underscore, "
        "or hyphen variations are normalized; obsolete or unknown tactics are rejected. "
        "Do not return source field names, raw values, JSON, Markdown, or usage metadata. "
        "If there are no findings, use RESULT<TAB>no_reportable_findings and omit "
        "FINDING and EVIDENCE records. Finish with exactly one END line.\n\n"
        f"{uplift_instructions}"
        "--- CSV EVIDENCE START ---\n"
        f"{visible_csv}\n"
        "--- CSV EVIDENCE END ---"
    )
    prompt_debug.capture(prompt, plan=plan, chunk=chunk, csv_evidence=csv_evidence)
    return prompt


def bounded_synthesis_chunks(
    accepted_chunks: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return the exact accepted-result projection visible to synthesis."""
    projected = copy.deepcopy(accepted_chunks)
    for worker in projected.values():
        for finding in worker.get("findings") or []:
            rows = list(finding.get("rows") or [])
            previously_omitted = int(finding.get("_omitted_evidence_rows") or 0)
            finding["rows"] = rows[:SYNTHESIS_EVIDENCE_ROWS_PER_FINDING]
            finding["_omitted_evidence_rows"] = previously_omitted + max(
                0, len(rows) - SYNTHESIS_EVIDENCE_ROWS_PER_FINDING
            )
        for key in ("relevant_context",):
            items = list(worker.get(key) or [])
            previously_omitted = int(worker.get(f"_omitted_{key}") or 0)
            worker[key] = items[:SYNTHESIS_CONTEXT_ITEMS_PER_CHUNK]
            worker[f"_omitted_{key}"] = previously_omitted + max(
                0, len(items) - SYNTHESIS_CONTEXT_ITEMS_PER_CHUNK
            )
    return projected


def _compact_worker_result(result: dict[str, Any]) -> str:
    def clipped(value: Any) -> str:
        text = str(value or "").strip()
        if len(text) <= SYNTHESIS_SUMMARY_MAX_CHARS:
            return text
        return text[: SYNTHESIS_SUMMARY_MAX_CHARS - 1].rstrip() + "…"

    lines = [
        f"ARTIFACT\t{result['artifact']}",
        f"CHUNK\t{int(result['chunk_index']) + 1}/{result['chunk_count']}",
        f"ROW_RANGE\t{int(result['row_start']) + 1}-{result['row_end']}",
        f"ROW_COUNT\t{result['row_count']}",
        "STATUS\tcomplete",
        f"RESULT\t{result['result']}",
    ]
    if str(result.get("answer") or "").strip():
        lines.append(f"ANSWER\t{clipped(result['answer'])}")
    for finding in result.get("findings") or []:
        lines.append(
            f"FINDING\t{finding['id']}\t{finding['confidence']}\t"
            f"{','.join(finding.get('domains') or [])}\t{clipped(finding['summary'])}"
        )
        finding_rows = list(finding.get("rows") or [])
        for row in finding_rows:
            lines.append(f"EVIDENCE\t{finding['id']}\t{row['ref']}")
        omitted = int(finding.get("_omitted_evidence_rows") or 0)
        if omitted > 0:
            lines.append(f"OMITTED_EVIDENCE_ROWS\t{finding['id']}\t{omitted}")
    for record, key in (("CONTEXT", "relevant_context"),):
        items = list(result.get(key) or [])
        for item in items:
            normalized = (
                dict(item)
                if isinstance(item, dict)
                else {"ref": "-", "summary": str(item), "fields": {}}
            )
            line = (
                f"{record}\t{normalized.get('finding_id') or '-'}\t"
                f"{normalized.get('ref') or '-'}\t"
                f"{normalized.get('context_type') or 'general'}\t"
                f"{clipped(normalized.get('summary'))}"
            )
            lines.append(line)
        omitted = int(result.get(f"_omitted_{key}") or 0)
        if omitted > 0:
            lines.append(f"OMITTED_{record}_ITEMS\t{omitted}")
    lines.extend(
        f"LIMITATION\t{clipped(value)}" for value in result.get("limitations") or []
    )
    lines.extend(
        f"FOLLOW_UP\t{clipped(value)}"
        for value in result.get("bounded_follow_up") or []
    )
    lines.append("END")
    return "\n".join(lines)


def _synthesis_prompt_limit_error(
    prompt: str,
    *,
    plan: dict[str, Any],
) -> str:
    limits = plan.get("analysis_limits")
    if not isinstance(limits, dict):
        return ""
    maximum = limits.get("maximum_input_tokens")
    encoding = str(limits.get("token_encoding") or "").strip()
    if maximum is None or not encoding:
        return ""
    maximum_tokens = int(maximum)
    input_tokens = token_budget.estimate_tokens(prompt, encoding)
    if input_tokens <= maximum_tokens:
        return ""
    return (
        "Synthesis prompt exceeds maximum input tokens "
        f"({input_tokens} > {maximum_tokens}); deterministic accepted-result "
        "fallback used."
    )


def _deterministic_task_record(
    *,
    task_id: str,
    stage: str,
    error: str,
) -> dict[str, Any]:
    run = AgentResult(
        task_id=task_id,
        status="failed",
        output="",
        output_file="",
        events_file="",
        manifest_file="",
        elapsed_seconds=0.0,
        error=error,
    )
    return {
        "task_id": task_id,
        "stage": stage,
        "attempts": 0,
        "status": "failed",
        "error": error,
        "diagnostics": [],
        "run": asdict(run),
        "attempt_history": [],
    }


def _artifact_synthesis_limit_fallback(
    *,
    artifact_task: dict[str, Any],
    question: str,
    expected: list[dict[str, Any]],
    accepted: dict[str, dict[str, Any]],
    failures: dict[str, str],
    error: str,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    relevant_context: list[Any] = []
    limitations: list[str] = []
    bounded_follow_up: list[str] = []
    finding_number = 0
    for key in sorted(accepted):
        worker = accepted[key]
        for finding in worker.get("findings") or []:
            finding_number += 1
            findings.append(
                {
                    "id": f"F{finding_number}",
                    "confidence": str(finding["confidence"]),
                    "domains": list(finding.get("domains") or []),
                    "summary": str(finding["summary"]),
                    "evidence": [
                        {
                            "artifact": str(worker["artifact"]),
                            "chunk_index": int(worker["chunk_index"]),
                            "chunk_count": int(worker["chunk_count"]),
                            "ref": str(row["ref"]),
                            "fields": dict(row["fields"]),
                            "source": copy.deepcopy(row.get("source") or {}),
                        }
                        for row in finding.get("rows") or []
                    ],
                }
            )
        for item in [
            *list(worker.get("relevant_context") or []),
            *list(worker.get("explained") or []),
        ]:
            if not isinstance(item, dict) or not item.get("ref") or not item.get("fields"):
                continue
            relevant_context.append(
                {
                    **copy.deepcopy(item),
                    "artifact": str(worker["artifact"]),
                    "chunk_index": int(worker["chunk_index"]),
                    "chunk_count": int(worker["chunk_count"]),
                }
            )
        limitations.extend(str(value) for value in worker.get("limitations") or [])
        bounded_follow_up.extend(
            str(value) for value in worker.get("bounded_follow_up") or []
        )
    limitations.extend(str(value) for value in failures.values())
    limitations.append(error)
    planned_rows = sum(int(item.get("row_count") or 0) for item in expected)
    reviewed_rows = sum(
        int(item.get("row_count") or 0) for item in accepted.values()
    )
    findings = analysis_summary.consolidate_exact_findings(
        findings,
        id_prefix="F",
    )
    return {
        "format": "artifact-analysis-v2",
        "task_id": str(artifact_task["task_id"]),
        "artifact": str(artifact_task["artifact"]),
        "question": question.strip(),
        "status": "complete_with_failures",
        "coverage": {
            "planned_chunks": len(expected),
            "accepted_chunks": len(accepted),
            "planned_rows": planned_rows,
            "reviewed_rows": reviewed_rows,
        },
        "answer": (
            "Automated synthesis could not be accepted. Deterministic fallback "
            "retained all accepted findings, evidence, and context."
        ),
        "findings": findings,
        "relevant_context": relevant_context,
        "limitations": list(dict.fromkeys(limitations)),
        "bounded_follow_up": list(dict.fromkeys(bounded_follow_up)),
    }


def synthesis_output_policy(*, task_mode: str, response_depth: str) -> str:
    """Return the output rule that applies after reference-only reduction."""
    mode = str(task_mode or "").strip().casefold().replace("-", "_")
    depth = str(response_depth or "standard").strip().casefold()
    mode_policy = {
        "host_forensics": (
            "Lead with the direct host assessment and retain material UTC chronology plus "
            "finding-linked user/session/process/file/network context."
        ),
        "targeted_hunt": (
            "Keep the exact hunt seed and filters; report hits, non-hits, affected hosts "
            "and users, prevalence, execution/review coverage, and the next exact pivot."
        ),
        "compromise_assessment": (
            "Lead with environment and coverage, then baseline and prevalence observations, "
            "candidate anomalies, explicit unknowns, and narrowing actions. Do not equate rarity with compromise."
        ),
        "incident_response": (
            "Answer the bounded incident question directly, retain relevant chronology and "
            "finding-linked context, and do not broaden scope."
        ),
    }.get(
        mode,
        "Answer the bounded evidence question directly and retain finding-linked context.",
    )
    if depth == "rapid":
        depth_policy = (
            "Return only the highest-signal conclusions, essential context, material coverage "
            "gaps, and immediate action; label incomplete review provisional."
        )
    elif depth == "deep" and mode == "host_forensics":
        depth_policy = (
            "Render material activity as a compact UTC table with columns timestamp | host | "
            "user/session | process/action | evidence source | interpretation | confidence, "
            "and include supported benign alternatives."
        )
    elif depth == "deep":
        depth_policy = (
            "Include the full bounded chronology, supported alternate explanations, exact "
            "provenance, coverage, limitations, and bounded follow-up."
        )
    else:
        depth_policy = (
            "Return prioritized findings, relevant chronology, exact provenance, coverage, "
            "limitations, and bounded next actions."
        )
    return f"{mode_policy} {depth_policy}"


def render_synthesis_prompt(
    *,
    task: str,
    question: str,
    accepted_chunks: dict[str, dict[str, Any]],
    failures: dict[str, str],
    task_mode: str = "",
    response_depth: str = "",
) -> str:
    visible_chunks = bounded_synthesis_chunks(accepted_chunks)
    accepted_text = "\n\n".join(
        _compact_worker_result(visible_chunks[key]) for key in sorted(visible_chunks)
    ) or "No accepted analysis results."
    failure_text = "\n".join(
        f"- {key}: {value}" for key, value in sorted(failures.items())
    ) or "- None."
    output_policy = synthesis_output_policy(
        task_mode=task_mode,
        response_depth=response_depth,
    )
    return (
        "You are a read-only DFIR synthesis analyst. Use only the compact, validated "
        "analysis results below. Do not infer raw evidence or create an evidence "
        "catalogue. Consolidate semantically equivalent observations into one "
        "finding, including repeated commands or events across rows and chunks. "
        "Choose the smallest representative reference set that supports each finding; "
        "do not repeat equivalent evidence lines. Preserve materially distinct "
        "behavior as separate findings. Python will hydrate exact values and "
        "provenance from accepted references. Input EVIDENCE records contain stable "
        "references, never evidence values. OMITTED_* records are bounded "
        "compaction accounting and are not evidence.\n\n"
        f"Task: {task}\n"
        f"Question: {question.strip()}\n\n"
        f"Task mode: {task_mode or 'unspecified'}\n"
        f"Response depth: {response_depth or 'standard'}\n\n"
        f"Output policy: {output_policy}\n\n"
        "Return plain text in this exact structure. The coordinator already owns "
        "task, question, status, and coverage metadata; do not repeat them:\n"
        "ANSWER\nConcise direct answer.\n\n"
        "FINDINGS\n"
        "FINDING\tM1\thigh\tExecution,Credential Access\tCoherent finding.\n"
        "EVIDENCE\tM1\tSxxxx-R<number>\n\n"
        "RELEVANT_CONTEXT\n"
        "CONTEXT\tM1\tSxxxx-R<number>\tidentity\tQuestion-relevant context\n"
        "or None. Use '-' instead of M1 only for environment-level context. CONTEXT must cite an accepted CONTEXT record and use identity, session, process, file, network, timeline, environment, or general as its type.\n\n"
        "LIMITATIONS\nCoverage or confidence limitations or None.\n\n"
        "FOLLOW_UP\nSmallest bounded follow-up or None.\n"
        "END\n\n"
        "When coverage failed, describe only what accepted evidence established. "
        "Use only these Enterprise ATT&CK tactic names: "
        f"{', '.join(collection_analysis.ATTACK_TACTICS)}. "
        "Inside FINDINGS, emit only FINDING and EVIDENCE records, or exactly "
        "None. Do not add prose, bullets, headings, CONTEXT, LIMITATION, or "
        "FOLLOW_UP records there. For each synthesized FINDING, use only tactics "
        "already assigned to its cited input EVIDENCE records. The synthesized "
        "tactic set must be a subset of the union of those cited records' tactics; "
        "do not infer a new tactic from summary text. "
        "Do not use the phrase 'supplied evidence' and do not imply that a failed "
        "domain was assessed. The final line must be END and no usage footer may "
        "follow.\n\n"
        "Accepted results:\n"
        f"{accepted_text}\n\n"
        "Coverage failures:\n"
        f"{failure_text}"
    )


def render_retry_prompt(
    original_prompt: str,
    *,
    error: str,
    diagnostics: list[dict[str, Any]],
) -> str:
    """Append deterministic correction instructions without evidence values."""
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in diagnostics:
        serialized = json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if serialized not in seen:
            seen.add(serialized)
            unique.append(dict(item))
    if unique:
        defect_text = "\n".join(
            "DEFECT\t"
            + json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for item in unique
        )
    else:
        defect_text = f"DEFECT\t{error}"
    return (
        original_prompt
        + "\n\nRETRY CORRECTION\n"
        "Your previous response failed deterministic validation. Correct every "
        "defect below in one complete response. Use only the allowed ATT&CK tactic "
        "names and exact source references shown by the original input or "
        "diagnostics. Do not guess, substitute, or copy evidence values or field "
        "names. Use exactly one Sxxxx-R<number> per EVIDENCE or CONTEXT record. "
        "Link CONTEXT to a returned finding ID, or use '-' only with ContextType environment. "
        "Copy assigned headers exactly; coordinator-owned metadata is "
        "authoritative.\n"
        + defect_text
        + "\nReturn one complete response in the original required format."
    )


async def _validated_pool_async(
    tasks: Iterable[AgentRequest],
    *,
    max_concurrency: int,
    execute: Callable[[AgentRequest], Any],
    validate: Callable[[AgentRequest, str], dict[str, Any]],
    on_progress: Callable[[dict[str, Any]], None] | None = None,
    retry_prompt_error: Callable[[str], str] | None = None,
    schedule: Callable[[AgentRequest, Callable[[AgentRequest], Any]], Any] | None = None,
    correction_attempts: int = analysis_limits.DEFAULT_VALIDATION_CORRECTION_ATTEMPTS,
    accepted_callback: Callable[[AgentRequest, dict[str, Any]], None] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    correction_attempts = analysis_limits.correction_attempts(correction_attempts)
    accepted: dict[str, dict[str, Any]] = {}
    records: dict[str, dict[str, Any]] = {}

    async def execute_safely(task: AgentRequest) -> AgentResult:
        try:
            value = execute(task)
            return await value if inspect.isawaitable(value) else value
        except Exception as exc:
            return AgentResult(
                task_id=task.task_id,
                status="failed",
                output="",
                output_file="",
                events_file="",
                manifest_file="",
                elapsed_seconds=0.0,
                error=f"{type(exc).__name__}: worker execution failed",
                error_classification="worker_exception",
            )

    async def process(base_task: AgentRequest) -> tuple[
        dict[str, Any] | None, dict[str, Any]
    ]:
        attempt_history: list[dict[str, Any]] = []
        correction_defects: list[dict[str, Any]] = []
        current_task = base_task
        debug_index = prompt_debug.track_task(base_task)
        for attempt in range(1, correction_attempts + 2):
            result = await execute_safely(current_task)
            prompt_debug.response(
                debug_index, attempt=attempt, prompt=current_task.prompt,
                output=result.output if result.output or result.status == "succeeded" else None,
                status=result.status,
            )
            error = result.error
            diagnostics: list[dict[str, Any]] = []
            normalized: dict[str, Any] | None = None
            if result.status == "succeeded":
                try:
                    normalized = validate(current_task, result.output)
                    error = ""
                except (ValueError, collection_analysis.WorkerResultError) as exc:
                    error = str(exc)
                    diagnostics = recovery.validation_defects(exc)
                finally:
                    prompt_debug.validation(
                        debug_index, attempt,
                        "accepted" if normalized is not None else "rejected",
                    )
            retryable = (
                normalized is None
                and attempt <= correction_attempts
                and result.status == "succeeded"
                and not is_output_limit_failure(result)
                and not error.startswith(
                    "Agent prompt exceeds maximum input tokens"
                )
            )
            attempt_history.append(
                {
                    "attempt": attempt,
                    "status": (
                        "accepted"
                        if normalized is not None
                        else "retrying"
                        if retryable
                        else "failed"
                    ),
                    "error": error,
                    "diagnostics": diagnostics,
                    "run": asdict(result),
                }
            )
            record = {
                "task_id": base_task.task_id,
                "stage": base_task.metadata.get("stage"),
                "attempts": attempt,
                "status": "accepted" if normalized is not None else "failed",
                "error": error,
                "diagnostics": diagnostics,
                "run": asdict(result),
                "attempt_history": attempt_history,
                "coverage": {
                    key: value for key, value in dict(base_task.metadata.get("chunk") or {}).items()
                    if key in {"row_start", "row_end", "row_count", "task_chunk_index", "task_chunk_count"}
                },
            }
            if on_progress is not None:
                on_progress(
                    {
                        "phase": str(base_task.metadata.get("stage") or "analysis"),
                        "task_id": base_task.task_id,
                        "attempt": attempt,
                        "status": (
                            "accepted"
                            if normalized is not None
                            else "retrying"
                            if retryable
                            else "failed"
                        ),
                        "error": error,
                        "diagnostics": diagnostics,
                        "normalized": normalized,
                    }
                )
            if normalized is not None and accepted_callback is not None:
                accepted_callback(base_task, normalized)
            if normalized is not None or not retryable:
                return normalized, record
            if retryable:
                correction_defects.extend(diagnostics)
                retry_prompt = render_retry_prompt(
                    base_task.prompt,
                    error=error,
                    diagnostics=correction_defects,
                )
                prompt_error = (
                    retry_prompt_error(retry_prompt)
                    if retry_prompt_error is not None
                    else ""
                )
                if prompt_error:
                    record["error"] = prompt_error
                    record["status"] = "failed"
                    history = list(record.get("attempt_history") or [])
                    if history:
                        history[-1]["status"] = "failed"
                        history[-1]["error"] = prompt_error
                    record["attempt_history"] = history
                    if on_progress is not None:
                        on_progress(
                            {
                                "phase": str(base_task.metadata.get("stage") or "analysis"),
                                "task_id": base_task.task_id,
                                "attempt": attempt,
                                "status": "failed",
                                "error": prompt_error,
                                "diagnostics": diagnostics,
                            }
                        )
                    return None, record
                current_task = replace(
                    base_task,
                    prompt=retry_prompt,
                    output_name=base_task.output_name + f".retry-{attempt + 1}",
                    metadata={**base_task.metadata, "attempt": attempt + 1},
                )
        return None, record

    def collect(task: AgentRequest, outcome: tuple[dict[str, Any] | None, dict[str, Any]]) -> None:
        normalized, record = outcome
        records[task.task_id] = record
        if normalized is not None:
            accepted[task.task_id] = normalized

    if schedule is None:
        await run_item_pool(
            tasks,
            max_concurrency=max_concurrency,
            execute=process,
            on_result=collect,
            retain_results=False,
        )
    else:
        pending: dict[asyncio.Future[Any], AgentRequest] = {}

        async def collect_future(future: asyncio.Future[Any]) -> None:
            task = pending.pop(future)
            collect(task, await future)

        for task in tasks:
            value = schedule(task, process)
            scheduled = await value if inspect.isawaitable(value) else value
            if isinstance(scheduled, asyncio.Future):
                pending[scheduled] = task
            else:
                collect(task, scheduled)
            completed = [future for future in pending if future.done()]
            for future in completed:
                await collect_future(future)
        while pending:
            completed, _ = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for future in completed:
                await collect_future(future)
    return accepted, records


def _direct_artifact_result(
    *,
    task: dict[str, Any],
    worker: dict[str, Any],
) -> dict[str, Any]:
    findings = []
    for finding in worker.get("findings") or []:
        findings.append(
            {
                "id": str(finding["id"]),
                "confidence": str(finding["confidence"]),
                "domains": list(finding.get("domains") or []),
                "summary": str(finding["summary"]),
                "evidence": [
                    {
                        "artifact": str(task["artifact"]),
                        "chunk_index": 0,
                        "chunk_count": 1,
                        "ref": str(row["ref"]),
                        "fields": dict(row["fields"]),
                        "source": copy.deepcopy(row.get("source") or {}),
                    }
                    for row in finding.get("rows") or []
                ],
            }
        )
    return {
        "format": "artifact-analysis-v2",
        "task_id": str(task["task_id"]),
        "artifact": str(task["artifact"]),
        "question": "",
        "status": "complete",
        "coverage": {
            "planned_chunks": 1,
            "accepted_chunks": 1,
            "planned_rows": int(worker["row_count"]),
            "reviewed_rows": int(worker["row_count"]),
        },
        "answer": (
            f"{len(findings)} reportable finding(s) identified."
            if findings
            else "No reportable findings were identified in the assigned artifact rows."
        ),
        "findings": findings,
        "uplift_candidates": [
            {
                **copy.deepcopy(item),
                "artifact": str(task["artifact"]),
                "chunk_index": 0,
                "chunk_count": 1,
            }
            for item in worker.get("uplift_candidates") or []
            if isinstance(item, dict) and item.get("ref") and item.get("fields")
        ],
        "relevant_context": [
            {
                **copy.deepcopy(item),
                "artifact": str(task["artifact"]),
                "chunk_index": 0,
                "chunk_count": 1,
            }
            for item in worker.get("relevant_context") or []
            if isinstance(item, dict) and item.get("ref") and item.get("fields")
        ],
        "limitations": list(worker.get("limitations") or []),
        "bounded_follow_up": list(worker.get("bounded_follow_up") or []),
    }


def _failed_artifact_result(
    *,
    task: dict[str, Any],
    failures: list[str],
) -> dict[str, Any]:
    return {
        "format": "artifact-analysis-v2",
        "task_id": str(task["task_id"]),
        "artifact": str(task["artifact"]),
        "question": "",
        "status": "failed",
        "coverage": {
            "planned_chunks": int(task["chunk_count"]),
            "accepted_chunks": 0,
            "planned_rows": int(task["row_count"]),
            "reviewed_rows": 0,
        },
        "answer": "Artifact analysis failed before any chunk result was accepted.",
        "findings": [],
        "relevant_context": [],
        "limitations": failures,
        "bounded_follow_up": ["Retry only the failed artifact analysis task."],
    }


def _artifact_as_host_worker(
    result: dict[str, Any],
    *,
    index: int,
    count: int,
) -> dict[str, Any]:
    finding_ids = {
        str(finding["id"]): f"A{index + 1:04d}:{finding['id']}"
        for finding in result.get("findings") or []
    }
    rows_by_finding = []
    for finding in result.get("findings") or []:
        rows = []
        for item in finding.get("evidence") or []:
            rows.append(
                {
                    "ref": str(item["ref"]),
                    "fields": dict(item.get("fields") or {}),
                    "source": copy.deepcopy(item.get("source") or {}),
                    "_origin": {
                        "artifact": str(item.get("artifact") or result["artifact"]),
                        "chunk_index": int(item.get("chunk_index", 0)),
                        "chunk_count": int(item.get("chunk_count", 1)),
                    },
                }
            )
        rows_by_finding.append(
            {
                "id": finding_ids[str(finding["id"])],
                "confidence": str(finding["confidence"]),
                "domains": list(finding.get("domains") or []),
                "summary": str(finding["summary"]),
                "rows": rows,
            }
        )
    relevant_context = []
    for item in result.get("relevant_context") or []:
        if (
            not isinstance(item, dict)
            or not item.get("ref")
            or not item.get("fields")
            or "chunk_index" not in item
            or "chunk_count" not in item
        ):
            continue
        relevant_context.append(
            {
                "ref": str(item["ref"]),
                "finding_id": finding_ids.get(str(item.get("finding_id") or ""), ""),
                "context_type": str(item.get("context_type") or "environment"),
                "summary": str(item.get("summary") or ""),
                "fields": dict(item["fields"]),
                "source": copy.deepcopy(item.get("source") or {}),
                "_origin": {
                    "artifact": str(item.get("artifact") or result["artifact"]),
                    "chunk_index": int(item["chunk_index"]),
                    "chunk_count": int(item["chunk_count"]),
                },
            }
        )
    coverage = dict(result.get("coverage") or {})
    return {
        "protocol": collection_analysis.CONTEXT_WORKER_PROTOCOL,
        "artifact": str(result["artifact"]),
        "chunk_index": index,
        "chunk_count": count,
        "row_start": 0,
        "row_end": int(coverage.get("reviewed_rows") or 0),
        "row_count": int(coverage.get("reviewed_rows") or 0),
        "status": "complete",
        "result": "findings" if rows_by_finding else "no_reportable_findings",
        "answer": str(result.get("answer") or ""),
        "findings": rows_by_finding,
        "relevant_context": relevant_context,
        "explained": [],
        "limitations": list(result.get("limitations") or []),
        "bounded_follow_up": list(result.get("bounded_follow_up") or []),
    }


def _host_synthesis_limit_fallback(
    *,
    question: str,
    expected: list[dict[str, Any]],
    artifact_results: list[dict[str, Any]],
    accepted_chunks: dict[str, dict[str, Any]],
    failures: dict[str, str],
    error: str,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    relevant_context: list[Any] = []
    limitations: list[str] = []
    bounded_follow_up: list[str] = []
    finding_number = 0
    accepted_artifacts = {
        str(worker.get("artifact") or "") for worker in accepted_chunks.values()
    }
    for result in artifact_results:
        artifact = str(result.get("artifact") or "")
        if artifact not in accepted_artifacts:
            continue
        for item in result.get("relevant_context") or []:
            if isinstance(item, dict):
                normalized = copy.deepcopy(item)
                normalized.setdefault("artifact", artifact)
                relevant_context.append(normalized)
            else:
                relevant_context.append(
                    {
                        "artifact": artifact,
                        "kind": "relevant_context",
                        "ref": "-",
                        "summary": str(item),
                        "fields": {},
                    }
                )
        for finding in result.get("findings") or []:
            finding_number += 1
            retained = copy.deepcopy(finding)
            retained["id"] = f"M{finding_number}"
            findings.append(retained)
        limitations.extend(str(value) for value in result.get("limitations") or [])
        bounded_follow_up.extend(
            str(value) for value in result.get("bounded_follow_up") or []
        )
    limitations.extend(str(value) for value in failures.values())
    limitations.append(error)
    findings = analysis_summary.consolidate_exact_findings(
        findings,
        id_prefix="M",
    )
    return {
        "format": "host-analysis-v2",
        "task": "host-analysis",
        "question": question.strip(),
        "status": "complete_with_failures",
        "coverage": {
            "planned_chunks": len(expected),
            "accepted_chunks": len(accepted_chunks),
            "planned_rows": sum(
                int(item.get("row_count") or 0) for item in expected
            ),
            "reviewed_rows": sum(
                int(item.get("row_count") or 0)
                for item in accepted_chunks.values()
            ),
        },
        "answer": (
            "Automated host synthesis could not be accepted. Deterministic fallback "
            "retained all accepted findings, evidence, and grounded context."
        ),
        "findings": findings,
        "relevant_context": relevant_context,
        "limitations": list(dict.fromkeys(limitations)),
        "bounded_follow_up": list(dict.fromkeys(bounded_follow_up)),
    }


def artifact_domains(artifact: str) -> set[str]:
    normalized = artifact.lower().replace(".", "").replace("_", "")
    return {
        domain
        for domain, markers in DOMAIN_ARTIFACT_MARKERS.items()
        if any(marker in normalized for marker in markers)
    }


def derive_domain_assessments(
    *,
    plan: dict[str, Any],
    artifact_results: list[dict[str, Any]],
    host_findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Derive fail-closed domain conclusions from planned and accepted artifacts."""
    planned: dict[str, set[str]] = {
        domain: set() for domain in collection_analysis.COVERAGE_DOMAINS
    }
    failed: dict[str, set[str]] = {
        domain: set() for domain in collection_analysis.COVERAGE_DOMAINS
    }
    accepted: dict[str, set[str]] = {
        domain: set() for domain in collection_analysis.COVERAGE_DOMAINS
    }
    for task in plan.get("artifact_tasks") or []:
        artifact = str(task.get("artifact") or "")
        for domain in artifact_domains(artifact):
            planned[domain].add(artifact)
    for result in artifact_results:
        artifact = str(result.get("artifact") or "")
        for domain in artifact_domains(artifact):
            if result.get("status") == "complete":
                accepted[domain].add(artifact)
            else:
                failed[domain].add(artifact)
    for item in plan.get("collection_failures") or []:
        artifact = str(item.get("artifact") or "")
        for domain in artifact_domains(artifact):
            failed[domain].add(artifact)
    observed = {
        domain
        for finding in host_findings
        for domain, tactics in COVERAGE_TACTICS.items()
        if tactics.intersection(str(value) for value in finding.get("domains") or [])
    }
    assessments: dict[str, dict[str, Any]] = {}
    for domain in sorted(collection_analysis.COVERAGE_DOMAINS):
        if domain in observed:
            status = "observed"
        elif failed[domain]:
            status = "unknown_due_to_coverage"
        elif planned[domain]:
            status = "not_observed_in_accepted_evidence"
        else:
            status = "not_assessed"
        assessments[domain] = {
            "status": status,
            "planned_artifacts": sorted(planned[domain]),
            "accepted_artifacts": sorted(accepted[domain]),
            "failed_artifacts": sorted(failed[domain]),
        }
    return assessments


def apply_domain_guard(
    *,
    plan: dict[str, Any],
    artifact_results: list[dict[str, Any]],
    host_result: dict[str, Any],
) -> dict[str, Any]:
    guarded = dict(host_result)
    assessments = derive_domain_assessments(
        plan=plan,
        artifact_results=artifact_results,
        host_findings=list(guarded.get("findings") or []),
    )
    if guarded.get("status") == "failed" or dict(guarded.get("final_review") or {}).get("status") == "failed":
        for item in assessments.values():
            if (
                item["status"] == "not_observed_in_accepted_evidence"
                and item["planned_artifacts"]
            ):
                item["status"] = "unknown_due_to_coverage"
                item["failed_artifacts"] = sorted(
                    {*item["failed_artifacts"], "host-analysis-synthesis"}
                )
    guarded["domain_assessments"] = assessments
    unknown = [
        domain
        for domain, item in assessments.items()
        if item["status"] == "unknown_due_to_coverage"
    ]
    if unknown:
        limitation = (
            "Coverage prevents a complete assessment of: "
            + ", ".join(domain.replace("_", " ") for domain in unknown)
            + ". Conclusions describe accepted evidence only."
        )
        guarded["limitations"] = list(
            dict.fromkeys([*list(guarded.get("limitations") or []), limitation])
        )
    return guarded


async def execute_host_synthesis_from_artifact_results_async(
    *,
    plan: dict[str, Any],
    artifact_results: list[dict[str, Any]],
    question: str,
    execute: Callable[[AgentRequest], Any] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    schedule: Callable[[AgentRequest, Callable[[AgentRequest], Any]], Any] | None = None,
) -> dict[str, Any]:
    """Finalize artifact results into scope status, result, and task records."""
    if not question.strip():
        raise ValueError("investigation question cannot be empty")

    scope_type = str(plan.get("scope_type") or "host").strip().lower()
    if scope_type not in {"host", "hunt"}:
        raise ValueError(f"unsupported analysis scope type: {scope_type}")
    synthesis_task = f"{scope_type}-analysis"
    synthesis_task_id = f"{synthesis_task}-synthesis"
    result_format = f"{synthesis_task}-v2"

    completed_results = copy.deepcopy(artifact_results)
    collection_failures = list(plan.get("collection_failures") or [])
    if synthesis_policy.mode(str(plan.get("synthesis_mode", "full"))) == "none":
        result = synthesis_policy.preliminary(
            completed_results, question=question, scope=scope_type,
            failures=[f"{item.get('artifact', 'unknown')}: {item.get('error') or item.get('state') or 'collection incomplete'}"
                      for item in collection_failures],
        )
        return {"status": result["status"], "host_result": result, "tasks": []}
    remaining_collection_failures: list[tuple[dict[str, Any], str]] = []
    for item in collection_failures:
        message = (
            f"{item.get('artifact') or 'unknown artifact'}: "
            f"{item.get('error') or item.get('state') or 'collection failure'}"
        )
        artifact_result = next(
            (
                result
                for result in completed_results
                if result.get("artifact") == item.get("artifact")
            ),
            None,
        )
        if artifact_result is None:
            remaining_collection_failures.append((item, message))
            continue
        if artifact_result["status"] != "failed":
            artifact_result["status"] = "complete_with_failures"
        artifact_result["limitations"] = list(
            dict.fromkeys(
                [*list(artifact_result.get("limitations") or []), message]
            )
        )

    remaining_failure_messages = [
        message for _item, message in remaining_collection_failures
    ]
    host_records: dict[str, dict[str, Any]] = {}
    host_result: dict[str, Any]
    if not completed_results:
        host_result = {
            "format": result_format,
            "task": synthesis_task,
            "question": question.strip(),
            "status": "complete" if not collection_failures else "failed",
            "coverage": {
                "planned_chunks": 0,
                "accepted_chunks": 0,
                "planned_rows": 0,
                "reviewed_rows": 0,
            },
            "answer": "No artifact rows were available for analysis.",
            "findings": [],
            "relevant_context": [],
            "limitations": remaining_failure_messages,
            "bounded_follow_up": [],
        }
    elif len(completed_results) == 1 and scope_type != "host":
        host_result = {
            **completed_results[0],
            "format": result_format,
            "task": synthesis_task,
            "question": question.strip(),
        }
        if remaining_collection_failures:
            host_result["status"] = (
                "failed"
                if host_result["status"] == "failed"
                else "complete_with_failures"
            )
            host_result["limitations"] = list(
                dict.fromkeys(
                    [
                        *list(host_result.get("limitations") or []),
                        *remaining_failure_messages,
                    ]
                )
            )
    else:
        host_count = len(completed_results) + len(remaining_collection_failures)
        host_accepted = {
            f"artifact-{index}": _artifact_as_host_worker(
                result,
                index=index,
                count=host_count,
            )
            for index, result in enumerate(completed_results)
            if result["status"] in {"complete", "complete_with_failures"}
        }
        host_failures = {
            f"artifact-{index}": "; ".join(result.get("limitations") or [])
            or f"Artifact analysis ended with status {result['status']}"
            for index, result in enumerate(completed_results)
            if result["status"] != "complete"
        }
        host_failures.update(
            {
                f"artifact-{len(completed_results) + index}": message
                for index, message in enumerate(remaining_failure_messages)
            }
        )
        host_expected = [
            {
                "chunk_index": index,
                "chunk_count": host_count,
                "row_count": int(
                    dict(result.get("coverage") or {}).get("planned_rows") or 0
                ),
            }
            for index, result in enumerate(completed_results)
        ]
        host_expected.extend(
            {
                "chunk_index": len(completed_results) + index,
                "chunk_count": host_count,
                "row_count": 0,
            }
            for index, _item in enumerate(remaining_collection_failures)
        )
        host_visible = bounded_synthesis_chunks(host_accepted)
        host_prompt = render_synthesis_prompt(
            task=synthesis_task,
            question=question,
            accepted_chunks=host_visible,
            failures=host_failures,
            task_mode=str(plan.get("task_mode") or ""),
            response_depth=str(plan.get("response_depth") or ""),
        )
        if scope_type == "host":
            host_prompt += host_final_review.prompt_suffix(
                workers=host_visible, plan=plan, artifact_results=completed_results,
            )
        limit_error = (
            "Final review has no accepted artifact results or executor."
            if scope_type == "host" and (not host_accepted or execute is None)
            else _synthesis_prompt_limit_error(host_prompt, plan=plan)
        )
        if limit_error:
            host_records[synthesis_task_id] = _deterministic_task_record(
                task_id=synthesis_task_id,
                stage=f"{scope_type}-synthesis",
                error=limit_error,
            )
            host_result = _host_synthesis_limit_fallback(
                question=question,
                expected=host_expected,
                artifact_results=completed_results,
                accepted_chunks=host_accepted,
                failures=host_failures,
                error=limit_error,
            )
        else:
            if execute is None:
                raise ValueError(
                    "host final review executor is required for accepted artifact results"
                )
            host_task = AgentRequest(
                task_id=synthesis_task_id,
                prompt=host_prompt,
                output_name=f"{synthesis_task_id}.txt",
                metadata={
                    "stage": f"{scope_type}-synthesis",
                    "analysis_routing": analysis_limits.analysis_routing(
                        "synthesis"
                    ),
                },
            )

            def validate_host_story(_task: AgentRequest, output: str) -> dict[str, Any]:
                validator = (
                    host_final_review.validate if scope_type == "host"
                    else collection_analysis.validate_analysis_story
                )
                story = validator(
                    output,
                    task=synthesis_task,
                    question=question,
                    expected_chunks=host_expected,
                    accepted_chunks=host_visible,
                    failed_chunks=host_failures,
                )
                story["format"] = result_format
                return story

            accepted_host, host_records = await _validated_pool_async(
                [host_task],
                max_concurrency=1,
                execute=execute,
                validate=validate_host_story,
                on_progress=progress_callback,
                retry_prompt_error=lambda prompt: _synthesis_prompt_limit_error(
                    prompt,
                    plan=plan,
                ),
                schedule=schedule,
                correction_attempts=int(dict(plan.get("analysis_limits") or {}).get(
                    "synthesis_correction_attempts", analysis_limits.DEFAULT_SYNTHESIS_CORRECTION_ATTEMPTS)),
            )
            host_result = accepted_host.get(host_task.task_id)
            if host_result is None:
                host_result = _host_synthesis_limit_fallback(
                    question=question,
                    expected=host_expected,
                    artifact_results=completed_results,
                    accepted_chunks=host_accepted,
                    failures=host_failures,
                    error=host_records[host_task.task_id]["error"],
                )

    if scope_type == "host":
        host_result["coverage"] = {
            key: sum(int(dict(r.get("coverage") or {}).get(key) or 0) for r in completed_results)
            for key in ("planned_chunks", "accepted_chunks", "planned_rows", "reviewed_rows")
        }
        host_result["limitations"] = list(dict.fromkeys([
            *host_result.get("limitations", []), *remaining_failure_messages,
            *(str(value) for r in completed_results for value in r.get("limitations") or []),
        ]))
    if scope_type == "host" and not host_result.get("final_review"):
        host_result = host_final_review.fail_closed(
            host_result, host_visible if completed_results else {},
        )
    host_result = apply_domain_guard(
        plan=plan,
        artifact_results=completed_results,
        host_result=host_result,
    )
    host_result["format"] = result_format
    host_result["task"] = synthesis_task
    host_result["synthesis_mode"] = "full"
    host_result["analysis_status"] = str(host_result["status"])
    host_result["review_status"] = (
        str(host_result.get("final_review", {}).get("status", "complete"))
        if host_result.get("final_review") or host_result["status"] == "complete" else "failed"
    )
    artifact_results[:] = completed_results
    result = {
        "status": str(host_result["status"]),
        "host_result": host_result,
        "tasks": [host_records[key] for key in sorted(host_records)],
    }
    if progress_callback is not None:
        progress_callback(
            {
                "phase": "host",
                "task_id": synthesis_task_id,
                "status": str(result["status"]),
                "normalized": host_result,
            }
        )
    return result


async def execute_analysis_workload_async(
    *,
    plan: dict[str, Any],
    chunk_csv: dict[int, str],
    question: str,
    spec: ResolvedAgentExecution,
    workdir: Path,
    output_dir: Path,
    execute: Callable[[AgentRequest], Any] | None = None,
    agent_metadata: dict[str, Any] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    perform_scope_synthesis: bool = True,
    schedule: Callable[[AgentRequest, Callable[[AgentRequest], Any]], Any] | None = None,
    chunk_recovery: recovery.ChunkRecovery | None = None,
) -> dict[str, Any]:
    """Execute chunk, artifact-synthesis, then host-synthesis stages."""
    if not question.strip():
        raise ValueError("investigation question cannot be empty")

    def emit(event: dict[str, Any]) -> None:
        if progress_callback is not None:
            progress_callback(event)

    emit(
        {
            "phase": "analysis",
            "status": "running",
            "planned_tasks": len(plan.get("artifact_tasks") or []),
            "planned_rows": int(plan.get("total_rows") or 0),
        }
    )
    chunk_by_index = {
        int(chunk["chunk_index"]): dict(chunk) for chunk in plan.get("chunks") or []
    }
    if set(chunk_by_index) != set(chunk_csv):
        raise ValueError("ephemeral chunk payloads do not match the analysis plan")
    source_rows_by_index = {
        index: source_rows_from_csv(
            value,
            dict(plan.get("source_aliases") or {}),
        )
        for index, value in chunk_csv.items()
    }
    runner = (
        create_agent_runner(
            spec,
            limits=limits_from_plan(plan),
        )
        if execute is None and chunk_by_index
        else None
    )
    executor = execute or (
        lambda task: runner.run(  # type: ignore[union-attr,return-value]
            task,
            workdir=workdir,
            output_dir=output_dir,
            progress_callback=(
                lambda event: emit(
                    analysis_cli_output.agent_event_progress(event)
                )
            ),
        )
    )
    chunk_tasks = (
        AgentRequest(
            task_id=f"{chunk['task_id']}-chunk-{chunk['task_chunk_index']}",
            prompt=render_chunk_prompt(
                plan=plan,
                chunk=chunk,
                question=question,
                csv_evidence=chunk_csv[index],
            ),
            output_name=(
                f"chunk-{index:04d}-{str(chunk['task_id']).removeprefix('artifact-task-')}.txt"
            ),
            metadata={
                "stage": "chunk",
                "chunk": chunk,
                "analysis_routing": analysis_limits.stage_routing("chunk"),
            },
        )
        for index, chunk in sorted(chunk_by_index.items())
    )

    def validate_chunk(task: AgentRequest, output: str) -> dict[str, Any]:
        chunk = dict(task.metadata["chunk"])
        source_rows = source_rows_by_index[int(chunk["chunk_index"])]
        return collection_analysis.validate_context_worker_result(
            output,
            artifact=str(chunk["artifact"]),
            chunk_index=int(chunk["task_chunk_index"]),
            chunk_count=int(chunk["task_chunk_count"]),
            row_start=int(chunk["row_start"]),
            row_end=int(chunk["row_end"]),
            expected_row_count=int(chunk["row_count"]),
            source_rows=source_rows,
            allow_uplift_candidates=bool(plan.get("allow_uplift_candidates")),
        )

    reused_chunks: dict[str, dict[str, Any]] = {}
    reused_records: dict[str, dict[str, Any]] = {}

    def pending_chunks() -> Iterable[AgentRequest]:
        for task in chunk_tasks:
            cached = chunk_recovery.get(task) if chunk_recovery is not None else None
            if cached is not None:
                try:
                    reused_chunks[task.task_id] = validate_chunk(task, recovery.worker_text(cached))
                except (ValueError, KeyError, TypeError):
                    pass  # Changed/corrupt decisions are reviewed again, never trusted.
                else:
                    reused_records[task.task_id] = {
                        "task_id": task.task_id, "stage": "chunk", "status": "accepted",
                        "attempts": 0, "reused": True, "attempt_history": [],
                    }
                    continue
            yield task

    accepted_chunks, task_records = await _validated_pool_async(
        pending_chunks(),
        max_concurrency=spec.max_concurrency,
        execute=executor,
        validate=validate_chunk,
        on_progress=progress_callback,
        schedule=schedule,
        correction_attempts=int(dict(plan.get("analysis_limits") or {}).get(
            "validation_correction_attempts", analysis_limits.DEFAULT_VALIDATION_CORRECTION_ATTEMPTS)),
        accepted_callback=chunk_recovery.accept if chunk_recovery is not None else None,
    )
    accepted_chunks.update(reused_chunks)
    task_records.update(reused_records)
    artifact_results: list[dict[str, Any]] = []
    synthesis_tasks: list[AgentRequest] = []
    synthesis_context: dict[str, dict[str, Any]] = {}
    for artifact_task in plan.get("artifact_tasks") or []:
        owned = [
            chunk_by_index[index]
            for index in artifact_task.get("chunk_indices") or []
        ]
        accepted = {
            f"chunk-{chunk['task_chunk_index']}": accepted_chunks[
                f"{chunk['task_id']}-chunk-{chunk['task_chunk_index']}"
            ]
            for chunk in owned
            if f"{chunk['task_id']}-chunk-{chunk['task_chunk_index']}" in accepted_chunks
        }
        failures = {
            f"chunk-{chunk['task_chunk_index']}": task_records[
                f"{chunk['task_id']}-chunk-{chunk['task_chunk_index']}"
            ]["error"]
            for chunk in owned
            if f"{chunk['task_id']}-chunk-{chunk['task_chunk_index']}" not in accepted_chunks
        }
        if len(owned) == 1 and accepted:
            result = _direct_artifact_result(
                task=artifact_task,
                worker=next(iter(accepted.values())),
            )
            result["question"] = question.strip()
            artifact_results.append(result)
            emit(
                {
                    "phase": "artifact",
                    "task_id": str(artifact_task["task_id"]),
                    "status": str(result["status"]),
                    "normalized": result,
                }
            )
            continue
        if not accepted:
            result = _failed_artifact_result(
                task=artifact_task,
                failures=list(failures.values()),
            )
            result["question"] = question.strip()
            artifact_results.append(result)
            emit(
                {
                    "phase": "artifact",
                    "task_id": str(artifact_task["task_id"]),
                    "status": str(result["status"]),
                    "normalized": result,
                }
            )
            continue
        if synthesis_policy.mode(str(plan.get("synthesis_mode", "full"))) == "none":
            parts = []
            for worker in accepted.values():
                part = _direct_artifact_result(task=artifact_task, worker=worker)
                for finding in part["findings"]:
                    for row in finding["evidence"]:
                        row["chunk_index"] = worker["chunk_index"]
                        row["chunk_count"] = worker["chunk_count"]
                for row in part["relevant_context"]:
                    row["chunk_index"] = worker["chunk_index"]
                    row["chunk_count"] = worker["chunk_count"]
                parts.append(part)
            result = synthesis_policy.preliminary(
                parts, question=question, scope="artifact", failures=list(failures.values()),
            )
            result.update(task_id=artifact_task["task_id"], artifact=artifact_task["artifact"])
            result["coverage"].update(planned_chunks=len(owned),
                                       planned_rows=sum(int(c["row_count"]) for c in owned))
            artifact_results.append(result)
            emit({"phase": "artifact", "task_id": result["task_id"],
                  "status": result["status"], "normalized": result})
            continue
        expected = [
            {
                **chunk,
                "chunk_index": int(chunk["task_chunk_index"]),
                "chunk_count": int(chunk["task_chunk_count"]),
            }
            for chunk in owned
        ]
        synthesis_id = f"{artifact_task['task_id']}-synthesis"
        synthesis_visible = bounded_synthesis_chunks(accepted)
        synthesis_prompt = render_synthesis_prompt(
            task=str(artifact_task["artifact"]),
            question=question,
            accepted_chunks=synthesis_visible,
            failures=failures,
            task_mode=str(plan.get("task_mode") or ""),
            response_depth=str(plan.get("response_depth") or ""),
        )
        limit_error = _synthesis_prompt_limit_error(synthesis_prompt, plan=plan)
        if limit_error:
            result = _artifact_synthesis_limit_fallback(
                artifact_task=artifact_task,
                question=question,
                expected=expected,
                accepted=accepted,
                failures=failures,
                error=limit_error,
            )
            artifact_results.append(result)
            task_records[synthesis_id] = _deterministic_task_record(
                task_id=synthesis_id,
                stage="artifact-synthesis",
                error=limit_error,
            )
            emit(
                {
                    "phase": "artifact",
                    "task_id": str(result["task_id"]),
                    "status": str(result["status"]),
                    "normalized": result,
                }
            )
            continue
        synthesis_tasks.append(
            AgentRequest(
                task_id=synthesis_id,
                prompt=synthesis_prompt,
                output_name=f"{synthesis_id}.txt",
                metadata={
                    "stage": "artifact-synthesis",
                    "analysis_routing": analysis_limits.stage_routing(
                        "artifact-synthesis"
                    ),
                },
            )
        )
        synthesis_context[synthesis_id] = {
            "artifact_task": artifact_task,
            "expected": expected,
            "accepted": accepted,
            "visible": synthesis_visible,
            "failures": failures,
        }

    def validate_artifact_story(task: AgentRequest, output: str) -> dict[str, Any]:
        context = synthesis_context[task.task_id]
        artifact_task = context["artifact_task"]
        story = collection_analysis.validate_analysis_story(
            output,
            task=str(artifact_task["artifact"]),
            question=question,
            expected_chunks=context["expected"],
            accepted_chunks=context["visible"],
            failed_chunks=context["failures"],
        )
        story.update(
            {
                "format": "artifact-analysis-v2",
                "task_id": str(artifact_task["task_id"]),
                "artifact": str(artifact_task["artifact"]),
            }
        )
        return story

    if synthesis_tasks:
        accepted_synthesis, synthesis_records = await _validated_pool_async(
            synthesis_tasks,
            max_concurrency=spec.max_concurrency,
            execute=executor,
            validate=validate_artifact_story,
            on_progress=progress_callback,
            retry_prompt_error=lambda prompt: _synthesis_prompt_limit_error(
                prompt,
                plan=plan,
            ),
            schedule=schedule,
            correction_attempts=int(dict(plan.get("analysis_limits") or {}).get(
                "synthesis_correction_attempts", analysis_limits.DEFAULT_SYNTHESIS_CORRECTION_ATTEMPTS)),
        )
        task_records.update(synthesis_records)
        for task in synthesis_tasks:
            if task.task_id in accepted_synthesis:
                artifact_results.append(accepted_synthesis[task.task_id])
            else:
                context = synthesis_context[task.task_id]
                fallback = _artifact_synthesis_limit_fallback(
                    artifact_task=context["artifact_task"],
                    question=question,
                    expected=context["expected"],
                    accepted=context["accepted"],
                    failures=context["failures"],
                    error=task_records[task.task_id]["error"],
                )
                artifact_results.append(fallback)
            emitted_result = artifact_results[-1]
            emit(
                {
                    "phase": "artifact",
                    "task_id": str(emitted_result["task_id"]),
                    "status": str(emitted_result["status"]),
                    "normalized": emitted_result,
                }
            )

    artifact_order = {
        str(task["task_id"]): index
        for index, task in enumerate(plan.get("artifact_tasks") or [])
    }
    if plan.get("synthesis_mode", "full") == "none":
        for result in artifact_results:
            result.update(synthesis_mode="none", review_status="not_requested",
                          analysis_status=result["status"], result_role="preliminary_candidates")
            result["answer"] = (
                f"{len(result.get('findings') or [])} preliminary candidate(s); caller review required."
            )
    artifact_results.sort(key=lambda item: artifact_order[str(item["task_id"])])
    if perform_scope_synthesis:
        final = await execute_host_synthesis_from_artifact_results_async(
            plan=plan,
            artifact_results=artifact_results,
            question=question,
            execute=executor,
            progress_callback=progress_callback,
            schedule=schedule,
        )
        host_result = final["host_result"]
        task_records.update(
            {str(record["task_id"]): record for record in final["tasks"]}
        )
        final_status = str(final["status"])
    else:
        host_result = {}
        statuses = {str(result.get("status") or "failed") for result in artifact_results}
        final_status = (
            "complete"
            if statuses <= {"complete"}
            else "failed"
            if statuses == {"failed"} or not artifact_results
            else "complete_with_failures"
        )
    run = {
        "schema_version": RUN_SCHEMA_VERSION,
        "status": final_status,
        "question": question.strip(),
        "plan_fingerprint": str(plan.get("plan_fingerprint") or ""),
        "source_fingerprint": str(plan.get("source_fingerprint") or ""),
        "analyst_agent": (
            dict(agent_metadata)
            if agent_metadata is not None
            else analyst_execution_metadata(spec)
        ),
        "artifact_results": artifact_results,
        "host_result": host_result,
        "tasks": [task_records[key] for key in sorted(task_records)],
        "evidence_persisted": False,
        "scope_synthesis_performed": perform_scope_synthesis and plan.get("synthesis_mode", "full") == "full",
    }
    emit(
        {
            "phase": "complete",
            "status": str(run["status"]),
            "normalized": run,
        }
    )
    if runner is not None:
        await runner.close()
    return run


def render_running_host_report(
    *,
    plan: dict[str, Any],
    question: str,
    progress: dict[str, Any],
) -> str:
    """Render an atomically replaceable provisional host report."""
    task_events = dict(progress.get("tasks") or {})
    artifact_results = dict(progress.get("artifacts") or {})
    accepted_chunks = [
        event
        for event in task_events.values()
        if event.get("phase") == "chunk" and event.get("status") == "accepted"
    ]
    reviewed_rows = sum(
        int(dict(event.get("normalized") or {}).get("row_count") or 0)
        for event in accepted_chunks
    )
    failures = [
        event
        for event in task_events.values()
        if event.get("status") in {"failed", "retrying"}
    ]
    findings: list[dict[str, Any]] = []
    for result in artifact_results.values():
        findings.extend(list(dict(result).get("findings") or []))
    if not findings:
        for event in accepted_chunks:
            findings.extend(
                list(dict(event.get("normalized") or {}).get("findings") or [])
            )
    lines = [
        "# Velociraptor host analysis",
        "",
        "> Provisional running report. This file is atomically replaced as analysis progresses.",
        "",
        "## Analysis metadata",
        "",
        f"- Host: `{plan.get('hostname', '')}`",
        f"- Client: `{plan.get('client_id', '')}`",
        f"- Request: `{plan.get('request_id', '')}`",
        f"- Collection: `{plan.get('collection_type', '')}`",
        f"- Status: `{progress.get('status', 'running')}`",
        f"- Phase: `{progress.get('phase', 'analysis')}`",
        f"- Coverage: {reviewed_rows}/{int(plan.get('total_rows') or 0)} rows",
        f"- Last updated: `{now_utc()}`",
        "- Bulk result rows persisted by analysis: `false`",
    ]
    if plan.get("supersedes_request_id"):
        lines.append(
            f"- Supersedes request: `{plan.get('supersedes_request_id', '')}`"
        )
    if plan.get("unavailable_artifacts"):
        lines.append(
            "- Unavailable artifacts: "
            + ", ".join(
                f"`{value}`" for value in plan.get("unavailable_artifacts") or []
            )
        )
    lines.extend([
        "",
        "## Question",
        "",
        question,
        "",
        "## Progress",
        "",
        f"- Accepted tasks: {sum(event.get('status') == 'accepted' for event in task_events.values())}",
        f"- Retrying tasks: {sum(event.get('status') == 'retrying' for event in task_events.values())}",
        f"- Failed tasks: {sum(event.get('status') == 'failed' for event in task_events.values())}",
        f"- Completed artifact results: {len(artifact_results)}/{len(plan.get('artifact_tasks') or [])}",
        "",
        "## Provisional findings",
        "",
    ])
    if findings:
        for finding in findings[:10]:
            domains = ", ".join(
                str(value).replace("_", " ")
                for value in finding.get("domains") or []
            )
            domain_label = f" [{domains}]" if domains else ""
            lines.append(
                f"- [{finding.get('confidence', 'low')}]{domain_label} "
                f"{finding.get('summary', '')}"
            )
    else:
        lines.append("- None accepted yet.")
    lines.extend(["", "## Next action", ""])
    if progress.get("status") == "failed":
        lines.append("Analysis is blocked or incomplete; final review is not complete. Check the failure below and existing runner/monitor ownership before resuming.")
        if progress.get("resume_command"):
            lines.extend(["", "```sh", str(progress["resume_command"]), "```"])
    else:
        lines.append("Continue the active coordinator and monitoring through final review; do not start a duplicate runner.")
    lines.extend(["", "## Active limitations", ""])
    if failures:
        for event in failures:
            lines.append(
                f"- `{event.get('task_id', '')}`: "
                f"{event.get('status', '')} — {event.get('error') or 'awaiting retry'}"
            )
    else:
        lines.append("- None.")
    return "\n".join(lines).rstrip() + "\n"
