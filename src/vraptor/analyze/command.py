"""Canonical collection-and-analysis CLI for one Velociraptor host."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import inspect
import json
import shutil
import shlex
import sys
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from vraptor.analyze import final_review as host_final_review
from vraptor.analyze import synthesis as synthesis_policy
from vraptor.analyze import prompt_debug

from vraptor.agent import diagnostics as agent_diagnostics
from vraptor.analyze import limits as analysis_limits
from vraptor.common import atomic_io
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import analyst_execution_identity
from vraptor.agent.config import analyst_execution_metadata
from vraptor.agent.config import resolve_agent_execution
from vraptor.agent.factory import create_agent_runner
from vraptor.analyze.scheduler import DynamicAnalysisQueue
from vraptor.analyze.scheduler import SchedulerStatus
from vraptor.common.hashing import sha256_file
from vraptor.paths import add_case_root_arg
from vraptor.paths import resolve_autoruns_golden_db
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.analyze import model_options
from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.analyze import summary as analysis_summary
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.collect import requests as collection
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import profiles as collection_analysis_profiles
from vraptor.analyze import runtime as collection_analysis_runtime
from vraptor import context as engagement_context
from vraptor.analyze import references as evidence_references
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.analyze import checkpoints as host_analysis_state
from vraptor.collect import layout
from vraptor.logging import operations as operation_log
from vraptor.analyze import recovery
from vraptor.api import VeloApiClient
from vraptor.api import resolve_org_id


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
DEFAULT_ANALYSIS_QUESTION = (
    "What activity is malicious, security-relevant, or useful host context?"
)


async def _await_if_needed(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ensure exact host flows, query each result once, and run flat "
            "artifact-scoped provider API analysis."
        )
    )
    parser.add_argument(
        "--engagement-id",
        "--investigation-id",
        "--id",
        dest="investigation_id",
        help="Local engagement folder; defaults to --server-profile.",
    )
    add_case_root_arg(parser)
    collection.add_client_target_args(parser, action="collect or analyze")
    collection.add_connection_args(parser)
    collection.add_target_args(parser)
    collection.add_timeline_args(parser)
    collection.add_request_id_arg(parser)
    parser.add_argument("--question", default=DEFAULT_ANALYSIS_QUESTION)
    parser.add_argument(
        "--task-mode",
        choices=(
            "incident-response",
            "targeted-hunt",
            "host-forensics",
            "compromise-assessment",
        ),
        default="host-forensics",
        help="Explicit analysis intent. Defaults to host-forensics for this one-host workflow.",
    )
    parser.add_argument(
        "--response-depth",
        choices=("rapid", "standard", "deep"),
        default="",
        help="Presentation and synthesis depth. Defaults to the selected task mode.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="Maximum wait for each newly queued flow id.",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=int,
        default=30,
        help=(
            "Maximum reconciliation interval while waiting for flow completion; "
            "System.Flow.Completion events may wake the manager earlier."
        ),
    )
    parser.add_argument("--poll-timeout-seconds", type=int, default=3600)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument(
        "--reset-artifact",
        action="append",
        default=[],
        help=(
            "Discard the selected request's accepted local checkpoint for one "
            "artifact and reanalyze its existing Velociraptor flow. Repeatable."
        ),
    )
    parser.add_argument(
        "--reset-analysis",
        action="store_true",
        help=(
            "Discard all local analysis checkpoints for the selected request. "
            "This never queues or recollects evidence."
        ),
    )
    parser.add_argument(
        "--retry-failed", action="store_true",
        help="Retry failed analysis stages from the exact saved request, reusing validated chunks and artifacts. Requires --request-id.",
    )
    parser.add_argument(
        "--rebuild-host-summary",
        action="store_true",
        help=(
            "Rebuild the cumulative host report from completed request "
            "checkpoints and exit without launching analysis agents."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Persist bounded, value-free provider, timing, retry, validation, "
            "and synthesis diagnostics in the request analysis directory."
        ),
    )
    parser.add_argument(
        "--readiness-manifest",
        type=Path,
        help=(
            "Explicit engagement-state override. Defaults to "
            "<case-root>/<id>/engagement.json."
        ),
    )
    parser.add_argument("--autoruns-golden-db")
    parser.add_argument("--no-autoruns-golden", action="store_true")
    analysis_time_scope.add_arguments(parser)
    analysis_cli_arguments.add_skip_ai_argument(parser)
    analysis_cli_arguments.add_prompt_debug_argument(parser)
    analysis_cli_arguments.add_query_timeout_argument(parser)
    model_options.add_arguments(parser)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Build and persist the no-evidence analysis plan without launching agents.",
    )
    analysis_cli_output.add_analysis_output_args(parser)
    return parser


def analysis_paths(
    *,
    case_root: Path,
    investigation_id: str,
    hostname: str,
    request_id: str,
) -> dict[str, Path]:
    request_root = layout.request_dir(
        case_root,
        investigation_id,
        hostname,
        request_id,
    )
    request_analysis = request_root / "analysis"
    host_root = layout.system_dir(case_root, investigation_id, hostname)
    return {
        "request_dir": request_analysis,
        "runtime_dir": request_analysis / ".api-runtime",
        "plan_only": request_analysis / "analysis-plan.json",
        "request_checkpoint": request_analysis / "request-analysis.json",
        "validation_debug": request_analysis / "host-analysis-validation-debug.json",
        "diagnostics": request_analysis / "analysis-diagnostics.json",
        "chunk_recovery": request_analysis / "artifact-recovery",
        "artifact_reports_dir": request_analysis / "artifact-analysis",
        "host_artifact_reports_dir": host_root / "analysis",
        "host_report": host_root / "analysis-host.md",
        "host_state": host_root / "host-analysis-state.json",
    }


def _host_report_checkpoints(
    paths: dict[str, Path],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read hash-validated request history for host report rendering/publication."""
    host_root = paths["host_state"].parent
    checkpoints: list[dict[str, Any]] = []
    expected_hostname = ""
    expected_client_id = ""
    try:
        current_state = json.loads(paths["host_state"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        current_state = {}
    if isinstance(current_state, dict):
        expected_hostname = str(current_state.get("hostname") or "")
        expected_client_id = str(current_state.get("client_id") or "")
    for checkpoint_path in sorted(
        (host_root / "collection" / "requests").glob(
            "*/analysis/request-analysis.json"
        )
    ):
        try:
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(checkpoint, dict):
            continue
        if int(checkpoint.get("schema_version") or 0) != (
            host_analysis_state.REQUEST_CHECKPOINT_SCHEMA_VERSION
        ):
            continue
        if str(checkpoint.get("status") or "") not in {
            "complete",
            "complete_with_failures",
            "failed",
        }:
            continue
        expected_checkpoint_fingerprint = host_analysis_state.canonical_hash(
            {
                key: value
                for key, value in checkpoint.items()
                if key not in {"completed_at", "checkpoint_fingerprint"}
            }
        )
        if (
            str(checkpoint.get("checkpoint_fingerprint") or "")
            != expected_checkpoint_fingerprint
        ):
            continue
        if expected_hostname and str(checkpoint.get("hostname") or "") != expected_hostname:
            continue
        if expected_client_id and str(checkpoint.get("client_id") or "") != expected_client_id:
            continue
        valid_artifact_summaries: list[dict[str, Any]] = []
        for raw_summary in checkpoint.get("artifact_summaries") or []:
            summary = dict(raw_summary)
            report_path = Path(str(summary.get("report_file") or ""))
            expected_hash = str(summary.get("report_sha256") or "")
            if (
                report_path.is_file()
                and report_path.resolve().parent
                == (checkpoint_path.parent / "artifact-analysis").resolve()
                and expected_hash
                and sha256_file(report_path) == expected_hash
            ):
                valid_artifact_summaries.append(summary)
        checkpoint["artifact_summaries"] = valid_artifact_summaries
        checkpoint["checkpoint_file"] = str(checkpoint_path)
        checkpoints.append(checkpoint)
    records = sorted(
        checkpoints,
        key=lambda item: (
            str(item.get("completed_at") or ""),
            str(item.get("request_id") or ""),
        ),
        reverse=True,
    )
    return current_state, records


def publish_host_artifact_reports(
    *, paths: dict[str, Path], entries: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Publish current artifact reports without changing hashed request history."""
    if entries is None:
        _, records = _host_report_checkpoints(paths)
        latest = {}
        for record in records:
            for entry in record["artifact_summaries"]:
                latest.setdefault(str(entry.get("artifact") or entry.get("artifact_name") or ""), entry)
        entries = list(latest.values())
    request_root = paths["host_state"].parent / "collection" / "requests"
    published = {}
    for entry in entries:
        artifact = str(entry.get("artifact") or entry.get("artifact_name") or "")
        source = Path(str(entry.get("report_file") or "")).resolve()
        relative = source.relative_to(request_root.resolve())
        if len(relative.parts) != 4 or relative.parts[1:3] != ("analysis", "artifact-analysis"):
            raise ValueError(f"Artifact report is outside request history: {source}")
        content = source.read_bytes()
        if not artifact or hashlib.sha256(content).hexdigest() != entry.get("report_sha256"):
            raise ValueError(f"Artifact report integrity check failed: {source}")
        destination = paths["host_artifact_reports_dir"] / f"{analysis_summary.safe_artifact_name(artifact)}.md"
        if not destination.is_file() or destination.read_bytes() != content:
            atomic_io.write_text_atomic(destination, content.decode("utf-8"), newline="")
        published[artifact] = str(destination)
    return published


def render_cumulative_host_memory(
    *, paths: dict[str, Path],
) -> str:
    """Render validated request history without writing files or calling a model."""
    current_state, records = _host_report_checkpoints(paths)
    latest = records[0] if records else current_state
    lines = [
        "# Velociraptor host analysis",
        "",
        "## Host memory",
        "",
        f"- Host: `{latest.get('hostname', '')}`",
        f"- Client: `{latest.get('client_id', '')}`",
        f"- Updated: `{collection.now_utc()}`",
        f"- Completed analysis requests: {len(records)}",
        "- Velociraptor source of truth: yes",
        "- Bulk raw result export: no",
    ]
    for record in records:
        result = dict(record.get("result") or {})
        coverage = dict(result.get("coverage") or {})
        coverage_text = (
            f"{int(coverage.get('accepted_chunks') or 0)}/"
            f"{int(coverage.get('planned_chunks') or 0)} chunks; "
            f"{int(coverage.get('reviewed_rows') or 0)}/"
            f"{int(coverage.get('planned_rows') or 0)} rows"
        )
        time_filter_coverage = str(
            dict(record.get("time_filter") or {}).get(
                "coverage", "not_requested"
            )
        )
        lines.extend(
            [
                "",
                f"## Request {record.get('request_id', '')}",
                "",
                f"- Question: {record.get('question', '')}",
                f"- Task mode: `{record.get('task_mode') or 'unspecified'}`",
                f"- Response depth: `{record.get('response_depth') or 'unspecified'}`",
                f"- Status: `{record.get('status', 'failed')}`",
                f"- Completed: `{record.get('completed_at', '')}` (analysis, not collection)",
                "- Collection: " + ("complete" if dict(record.get("source_observation") or {}).get("all_artifacts_expected_complete") else "incomplete or unverified"),
                f"- Analysis: {analysis_summary.analysis_stage(result, str(record.get('status') or ''))}",
                f"- Coverage: {coverage_text}",
                f"- Analysis time filter: `{time_filter_coverage}`",
                f"- Request checkpoint: `{record.get('checkpoint_file', '')}`",
                "",
                str(result.get("answer") or "No answer was accepted."),
            ]
        )
        lines.extend(analysis_summary.render_flow_freshness(record.get("artifact_summaries") or []))
        lines.extend(analysis_summary.render_resume(result, str(record.get("status") or "")))
        if (
            str(record.get("task_mode") or "") == "host_forensics"
            and str(record.get("response_depth") or "") == "deep"
        ):
            lines.extend(
                [
                    "",
                    "### UTC timeline",
                    "",
                    *analysis_summary.render_utc_timeline(
                        result,
                        default_host=str(record.get("hostname") or ""),
                    ),
                ]
            )
        lines.extend(
            [
                "",
                "### Analysis time filter",
                "",
                *(
                    analysis_summary.render_time_filter_provenance(
                        record.get("time_filter")
                    )
                    or ["- Not requested."]
                ),
                "",
                "### Findings",
                "",
            ]
        )
        if result.get("findings"):
            for finding in result["findings"]:
                lines.append(
                    f"### {finding.get('id') or 'Finding'}: "
                    f"{finding.get('summary', '')}"
                )
                lines.append(
                    f"- Confidence: `{finding.get('confidence', 'unknown')}`"
                )
                for source in finding.get("sources") or []:
                    lines.append(
                        f"- Source: `{analysis_summary.source_group_text(source)}`"
                    )
                for example in finding.get("examples") or []:
                    fields = "; ".join(
                        f"{name}={value}"
                        for name, value in dict(example.get("fields") or {}).items()
                    )
                    lines.append(
                        f"- Example `{example.get('label') or example.get('ref') or '-'}`: {fields}"
                    )
                lines.append("")
        else:
            lines.extend(analysis_summary.render_compact_findings(result))
        lines.extend(["", "### Relevant context", ""])
        lines.extend(analysis_summary.render_relevant_context(result))
        lines.extend(analysis_summary.render_final_review(result))
        reports = list(record.get("artifact_summaries") or [])
        if reports:
            lines.extend(["", "### Artifact analysis", ""])
            for artifact_record in sorted(
                reports, key=lambda item: str(item.get("artifact") or "")
            ):
                report_file = str(artifact_record.get("report_file") or "")
                current_report = paths["host_artifact_reports_dir"] / (
                    f"{analysis_summary.safe_artifact_name(str(artifact_record.get('artifact') or ''))}.md"
                )
                if current_report.is_file() and sha256_file(current_report) == artifact_record.get("report_sha256"):
                    report_file = str(current_report)
                lines.append(
                    f"- [{artifact_record.get('artifact', '')}]"
                    f"({report_file}) — "
                    f"`{artifact_record.get('analysis_status', 'unknown')}`"
                )
        lines.extend(["", "### Limitations", ""])
        limitations = list(result.get("limitations") or [])
        lines.extend(f"- {value}" for value in limitations)
        if not limitations:
            lines.append("- None identified.")
        lines.extend(["", "### Bounded follow-up", ""])
        lines.extend(f"- {item}" for item in result.get("bounded_follow_up") or [])
        if not result.get("bounded_follow_up"):
            lines.append("- No bounded follow-up recorded; retain unresolved leads and coverage limitations above.")
    return "\n".join(lines).rstrip() + "\n"


def _target_arguments_present(args: argparse.Namespace) -> bool:
    return bool(
        getattr(args, "bundle", None)
        or getattr(args, "collection_group", None)
        or getattr(args, "target_mode", None)
        or args.collection_type
        or args.artifact
        or getattr(args, "supersedes_request_id", None)
        or getattr(args, "unavailable_artifact", None)
        or args.env
        or args.analysis_input
        or args.flow_timeout_seconds is not None
        or collection.timeline_options_present(collection.timeline_options_from_args(args))
    )


def _missing_saved_flow_ids(payload: dict[str, Any]) -> list[str]:
    artifact_flows = list(payload.get("artifact_flows") or [])
    missing = [
        str(item.get("artifact") or item.get("artifact_name") or "<unknown>")
        for item in artifact_flows
        if not str(item.get("flow_id") or "").strip()
    ]
    if artifact_flows:
        return sorted(set(missing))
    return sorted(
        {
            str(artifact)
            for artifact in payload.get("requested_artifacts") or []
            if str(artifact).strip()
        }
    )


def _raise_for_unresumable_saved_request(payload: dict[str, Any]) -> None:
    missing = _missing_saved_flow_ids(payload)
    if not missing:
        return
    queue_progress = dict(payload.get("queue_progress") or {})
    original_error = str(queue_progress.get("error") or "").strip()
    detail = f" Original queue error: {original_error}" if original_error else ""
    raise RuntimeError(
        f"Saved request {payload.get('request_id') or '<unknown>'} cannot be "
        "resumed or polled because it contains no flow ID for: "
        + ", ".join(missing)
        + ". Resolve the collection or artifact-availability failure and start "
        "a new corrected request."
        + detail
    )


def resume_analysis_command(
    args: argparse.Namespace, payload: dict[str, Any], *, retry_failed: bool = False,
) -> str:
    """Build an exact-request continuation command without collection selectors."""
    question = str(getattr(args, "question", "") or "")
    prefix = ["vraptor", "analyze"] if getattr(args, "existing_only", False) else ["vraptor", "collect", "analyze"]
    resume_argv = [*prefix, "--id", str(args.investigation_id),
                   "--case-root", str(collection.CASE_ROOT),
                   "--client", str(payload.get("client_id") or ""),
                   "--request-id", str(payload.get("request_id") or ""),
                   "--question", question, "--task-mode", str(getattr(args, "task_mode", "host-forensics"))]
    if getattr(args, "response_depth", ""):
        resume_argv.extend(["--response-depth", str(args.response_depth)])
    for option in ("server_profile", "api_client", "org_id", "time_after", "time_before", "autoruns_golden_db", "query_timeout_seconds"):
        if getattr(args, option, None):
            resume_argv.extend(["--" + option.replace("_", "-"), str(getattr(args, option))])
    for field in getattr(args, "time_field", []) or []:
        resume_argv.extend(["--time-field", str(field)])
    if getattr(args, "no_autoruns_golden", False):
        resume_argv.append("--no-autoruns-golden")
    if retry_failed:
        resume_argv.append("--retry-failed")
    return shlex.join(resume_argv)


def resolve_collection(
    api: Any,
    args: argparse.Namespace,
    *,
    policy: artifact_policy.ArtifactPolicySnapshot,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    emit_progress: bool = True,
) -> tuple[str, dict[str, Any], str]:
    hostname, payload, action, selected_client = start_collection(
        api,
        args,
        policy=policy,
    )
    request_id = str(payload.get("request_id") or "")
    if not payload.get("all_artifacts_expected_complete"):
        payload = collection.poll_collection(
            api,
            args.investigation_id,
            hostname,
            args.poll_interval_seconds,
            args.poll_timeout_seconds,
            request_id=request_id,
            client=selected_client,
            progress_callback=progress_callback,
            emit_progress=emit_progress,
        )
    if payload.get("poll_timed_out"):
        raise RuntimeError(
            "Collection polling timed out; analysis is incomplete. "
            "Check for an active runner or monitor before resuming the same exact flows:\n"
            + resume_analysis_command(args, payload)
        )
    return hostname, payload, action


def start_collection(
    api: Any,
    args: argparse.Namespace,
    *,
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> tuple[str, dict[str, Any], str, Any]:
    hostname, selected_client = collection.resolve_cli_collection_target(api, args)
    if getattr(args, "existing_only", False) and getattr(args, "flow_id", None):
        from vraptor.analyze.existing import adopt_flow
        return adopt_flow(api, args, hostname, selected_client)
    if getattr(args, "existing_only", False) and not args.request_id:
        raise RuntimeError("Existing analysis requires --flow or --request-id")
    if args.request_id:
        if getattr(args, "existing_only", False):
            from vraptor.analyze.existing import validate_saved_connection
            saved = collection.read_state(collection.get_state_path(args.investigation_id, hostname, args.request_id))
            validate_saved_connection(api, saved)
        if args.force_run:
            raise RuntimeError("--force-run cannot be combined with --request-id")
        if _target_arguments_present(args):
            raise RuntimeError(
                "--request-id cannot be combined with collection target arguments"
            )
        payload = collection.status_payload(
            api,
            args.investigation_id,
            hostname,
            request_id=args.request_id,
            client=selected_client,
        )
        _resolve_time_scopes(
            args,
            list(payload.get("requested_artifacts") or []),
            policy=policy,
        )
        _raise_for_unresumable_saved_request(payload)
        action = "resumed_saved_request"
    else:
        request = collection.build_request_from_args(args)
        if analysis_time_scope.from_args(args).bounded:
            _resolve_time_scopes(
                args,
                request.requested_artifacts,
                policy=policy,
            )
        collection.validate_request_supersession(
            args.investigation_id,
            hostname,
            request,
            api=api,
            client=selected_client,
        )
        payload = collection.ensure_collection(
            api,
            args.investigation_id,
            hostname,
            request,
            args.timeout_seconds,
            bool(args.force_run),
            client=selected_client,
            update_current_pointer=True,
        )
        action = str(payload.get("action") or "")
    return hostname, payload, action, selected_client


def _resolve_time_scopes(
    args: argparse.Namespace,
    artifacts: list[str],
    *,
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, analysis_time_scope.ResolvedTimeScope],
]:
    profiles = policy.profiles
    resolved = analysis_time_scope.resolve_all(
        artifacts,
        profiles,
        analysis_time_scope.from_args(args),
        profile_resolver=artifact_profiles.resolve_profile,
    )
    return profiles, resolved


def build_workload(
    api: Any,
    args: argparse.Namespace,
    payload: dict[str, Any],
    *,
    limits: analysis_limits.AnalysisLimits,
    policy: artifact_policy.ArtifactPolicySnapshot,
    source_aliases: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[int, str]]:
    collection_type = str(payload.get("target_collection_type") or "")
    artifacts = list(payload.get("requested_artifacts") or [])
    profiles, resolved_time_scopes = _resolve_time_scopes(
        args,
        artifacts,
        policy=policy,
    )
    requested_time_scope = analysis_time_scope.from_args(args)
    time_filter_provenance = analysis_time_scope.provenance(
        artifacts,
        profiles,
        requested_time_scope,
        resolved_time_scopes,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    profile = collection_analysis_profiles.profile_contract(
        collection_type,
        artifacts,
    )
    relevance = collection_analysis_profiles.question_relevance_policy(
        args.question,
        task_mode=getattr(args, "task_mode", "host-forensics"),
    )
    depth = collection_analysis_profiles.response_depth_policy(
        getattr(args, "response_depth", ""),
        task_mode=getattr(args, "task_mode", "host-forensics"),
    )
    strategies = (
        {}
        if args.no_autoruns_golden
        else dict(profile.get("artifact_strategies") or {})
    )
    golden_db: Path | None = None
    if strategies:
        golden_db = resolve_autoruns_golden_db(args.autoruns_golden_db, REPO_ROOT)
        if not golden_db.is_file():
            raise RuntimeError(
                f"Autoruns GoldenDB not found at {golden_db}; restore it or pass "
                "--no-autoruns-golden for explicit raw review."
            )
    return collection_analysis.build_analysis_workload(
        api,
        payload,
        collection_type=collection_type,
        source_aliases=source_aliases,
        limits=limits,
        analysis_profile_contract={
            **profile,
            "task_mode": relevance["mode"],
            "response_depth": depth["depth"],
            "question_relevance": relevance,
            "analysis_objectives": [
                *list(profile.get("analysis_objectives") or []),
                relevance["include"],
                relevance["context"],
                relevance["exclude"],
                depth["output"],
            ],
            "artifact_strategies": strategies,
            "time_scope": requested_time_scope.canonical(),
            "resolved_time_scopes": {
                artifact: resolved.canonical()
                for artifact, resolved in resolved_time_scopes.items()
            },
            "time_filter": time_filter_provenance,
            "artifact_policy": policy.metadata(),
        },
        artifact_strategies=strategies,
        autoruns_golden_db=golden_db,
        profiles=profiles,
        time_scopes=resolved_time_scopes,
    )


ANALYSIS_CACHE_IDENTITY_SCHEMA_VERSION = 4


def semantic_file_identity(path: Path) -> dict[str, str]:
    source = path.expanduser().resolve()
    return {
        "state": "present" if source.is_file() else "missing",
        "sha256": (
            sha256_file(source)
            if source.is_file()
            else ""
        ),
    }


def analysis_cache_identity(
    args: argparse.Namespace,
    *,
    question: str,
    spec: ResolvedAgentExecution,
    limits: analysis_limits.AnalysisLimits,
    policy: artifact_policy.ArtifactPolicySnapshot,
) -> str:
    resources = [
        {
            "role": "collection_analysis_profiles",
            **semantic_file_identity(collection_analysis_profiles.RESOURCE_PATH),
        },
    ]
    golden_path = resolve_autoruns_golden_db(
        getattr(args, "autoruns_golden_db", None),
        REPO_ROOT,
    )
    identity = {
        "schema_version": ANALYSIS_CACHE_IDENTITY_SCHEMA_VERSION,
        "question": question.strip(),
        "task_mode": collection_analysis_profiles.normalize_task_mode(
            getattr(args, "task_mode", "host-forensics")
        ),
        "response_depth": collection_analysis_profiles.response_depth_policy(
            getattr(args, "response_depth", ""),
            task_mode=getattr(args, "task_mode", "host-forensics"),
        )["depth"],
        "agent": analyst_execution_identity(spec),
        "analysis_limits_identity": limits.identity(),
        "time_scope": analysis_time_scope.from_args(args).canonical(),
        "no_autoruns_golden": bool(
            getattr(args, "no_autoruns_golden", False)
        ),
        "autoruns_golden_db": semantic_file_identity(golden_path),
        "context_worker_protocol": collection_analysis.CONTEXT_WORKER_PROTOCOL,
        "analysis_plan_schema": collection_analysis.ANALYSIS_PLAN_SCHEMA_VERSION,
        "runtime_schema": collection_analysis_runtime.RUN_SCHEMA_VERSION,
        "artifact_policy": policy.portable_identity(),
        "resources": resources,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def artifact_analysis_key(
    item: dict[str, Any],
    analysis_identity: str = "",
) -> str:
    identity = {
        "artifact": str(item.get("artifact") or item.get("artifact_name") or ""),
        "flow_id": str(item.get("flow_id") or ""),
        "analysis_identity": analysis_identity,
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]


def artifact_analysis_run_is_cacheable(run: dict[str, Any]) -> bool:
    """Reuse only terminal runs with no retryable analysis-task failures."""
    status = str(run.get("status") or "")
    if status == "complete":
        return True
    if status != "complete_with_failures":
        return False
    if any(
        str(result.get("status") or "") == "failed"
        for result in run.get("artifact_results") or []
    ):
        return False
    return not any(
        str(task.get("status") or "") == "failed"
        for task in run.get("tasks") or []
    )


def empty_artifact_result(
    *,
    artifact: str,
    question: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Return a durable complete result for a terminal successful zero-row flow."""
    return {
        "artifact": artifact,
        "status": "complete",
        "question": question,
        "answer": (
            "The terminal Velociraptor flow reported zero rows; no evidence was "
            "available for artifact analysis."
        ),
        "coverage": {
            "planned_rows": int(plan.get("total_rows") or 0),
            "reviewed_rows": 0,
            "planned_chunks": int(plan.get("chunk_count") or 0),
            "accepted_chunks": 0,
        },
        "findings": [],
        "relevant_context": [],
        "limitations": [
            "The terminal Velociraptor flow returned zero rows. This is not "
            "evidence of absence unless artifact applicability and adjacent "
            "source coverage support that conclusion."
        ],
        "bounded_follow_up": [],
    }


def apply_time_filter_result(
    result: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Attach deterministic analysis-time provenance and coverage."""
    payload = copy.deepcopy(result)
    time_filter = copy.deepcopy(dict(plan.get("time_filter") or {}))
    if not time_filter:
        return payload
    coverage_state = str(time_filter.get("coverage") or "not_requested")
    payload["time_filter"] = time_filter
    coverage = dict(payload.get("coverage") or {})
    coverage["time_filter"] = coverage_state
    if coverage_state in {"partial", "unsupported", "failed"} and str(
        coverage.get("overall") or ""
    ) not in {"failed", "incomplete"}:
        coverage["overall"] = (
            "incomplete" if coverage_state == "failed" else "partial"
        )
    payload["coverage"] = coverage
    if coverage_state in {"partial", "unsupported", "failed"}:
        validation_failed = any(
            str(dict(item).get("validation") or "") in {"failed", "partial"}
            for item in dict(time_filter.get("artifact_validation") or {}).values()
        )
        if coverage_state == "failed" or validation_failed:
            limitation = (
                "Server-side analysis-time filtering failed defensive validation; "
                "only components explicitly marked passed retain filtered coverage."
            )
        else:
            unsupported = ", ".join(
                str(value)
                for value in time_filter.get("unsupported_artifacts") or []
            ) or "the selected artifact"
            limitation = (
                "Requested analysis-time bounds were not applied to "
                f"{unsupported} because no verified requested/default time role "
                "was available; those rows were analyzed unfiltered."
            )
        payload["limitations"] = list(
            dict.fromkeys([*list(payload.get("limitations") or []), limitation])
        )
        if str(payload.get("status") or "") == "complete":
            payload["status"] = "complete_with_failures"
    return payload


def single_artifact_payload(
    payload: dict[str, Any],
    item: dict[str, Any],
) -> dict[str, Any]:
    artifact = str(item.get("artifact") or item.get("artifact_name") or "")
    return {
        **payload,
        "requested_artifacts": [artifact],
        "artifact_flows": [dict(item)],
        "all_artifacts_expected_complete": bool(item.get("is_finished")),
    }


def combine_incremental_plans(
    plans: list[dict[str, Any]],
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not plans:
        raise RuntimeError("No artifact analysis plans were produced.")
    for child_plan in plans:
        if (
            int(child_plan.get("schema_version") or 0)
            != collection_analysis.ANALYSIS_PLAN_SCHEMA_VERSION
            or str(child_plan.get("reference_protocol") or "")
            != evidence_references.REFERENCE_PROTOCOL
        ):
            raise RuntimeError(
                "Incremental artifact plan uses an obsolete evidence-reference contract."
            )
    first = dict(plans[0])
    source_aliases: dict[str, dict[str, Any]] = {}
    source_ids_by_alias: dict[str, str] = {}
    for child_plan in plans:
        for source_id, raw_metadata in dict(
            child_plan.get("source_aliases") or {}
        ).items():
            metadata = dict(raw_metadata)
            alias = str(metadata.get("alias") or "")
            evidence_references.parse_source_alias(alias)
            existing_source_id = source_ids_by_alias.get(alias)
            if existing_source_id is not None and existing_source_id != source_id:
                raise RuntimeError(
                    f"Incremental plans assign source alias {alias} to multiple sources."
                )
            existing = source_aliases.get(source_id)
            if existing is not None and existing != metadata:
                raise RuntimeError(
                    f"Incremental plans disagree on source metadata for {source_id}."
                )
            source_ids_by_alias[alias] = source_id
            source_aliases[source_id] = metadata
    artifacts = [
        dict(item)
        for plan in plans
        for item in plan.get("artifacts") or []
    ]
    chunks: list[dict[str, Any]] = []
    expected_chunk_headers: list[dict[str, Any]] = []
    artifact_tasks: list[dict[str, Any]] = []
    for child_plan in plans:
        index_map: dict[int, int] = {}
        for child_chunk in child_plan.get("chunks") or []:
            chunk = dict(child_chunk)
            old_index = int(chunk["chunk_index"])
            new_index = len(chunks)
            index_map[old_index] = new_index
            chunk["chunk_index"] = new_index
            chunks.append(chunk)
        for child_header in child_plan.get("expected_chunk_headers") or []:
            header = dict(child_header)
            header["chunk_index"] = index_map[int(header["chunk_index"])]
            expected_chunk_headers.append(header)
        for child_task in child_plan.get("artifact_tasks") or []:
            task = dict(child_task)
            task["chunk_indices"] = [
                index_map[int(index)] for index in task.get("chunk_indices") or []
            ]
            artifact_tasks.append(task)
    collection_failures = [
        dict(item)
        for plan in plans
        for item in plan.get("collection_failures") or []
    ]
    source_fingerprints = sorted(
        str(plan.get("source_fingerprint") or "") for plan in plans
    )
    source_fingerprint = hashlib.sha256(
        json.dumps(source_fingerprints, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    plan_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
                "source_fingerprint": source_fingerprint,
                "request_id": str(payload.get("request_id") or ""),
                "artifact_tasks": artifact_tasks,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        **first,
        "hostname": str(payload.get("hostname") or first.get("hostname") or ""),
        "client_id": str(payload.get("client_id") or first.get("client_id") or ""),
        "request_id": str(payload.get("request_id") or ""),
        "collection_type": str(payload.get("target_collection_type") or ""),
        "supersedes_request_id": str(
            payload.get("supersedes_request_id") or ""
        ),
        "unavailable_artifacts": list(
            payload.get("unavailable_artifacts") or []
        ),
        "analysis_mode": "incremental",
        "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
        "source_aliases": source_aliases,
        "total_rows": sum(int(plan.get("total_rows") or 0) for plan in plans),
        "chunk_count": sum(int(plan.get("chunk_count") or 0) for plan in plans),
        "chunks": chunks,
        "expected_chunk_headers": expected_chunk_headers,
        "artifact_task_count": len(artifact_tasks),
        "artifact_tasks": artifact_tasks,
        "artifacts": artifacts,
        "collection_failures": collection_failures,
        "direct_input_tokens": max(
            (int(plan.get("direct_input_tokens") or 0) for plan in plans),
            default=0,
        ),
        "total_evidence_tokens": sum(
            int(plan.get("total_evidence_tokens") or 0) for plan in plans
        ),
        "source_fingerprint": source_fingerprint,
        "plan_fingerprint": plan_fingerprint,
        "incremental_analysis": True,
        "evidence_persisted": False,
    }


def artifact_failure_result(
    *,
    artifact: str,
    question: str,
    item: dict[str, Any],
    request_id: str,
    error_class: str,
    failure_reason: str = "",
) -> dict[str, Any]:
    """Build one bounded terminal failure summary without persisting exceptions."""
    return {
        "artifact": artifact,
        "status": "failed",
        "question": question,
        "answer": "Local analysis failed; the Velociraptor result remains authoritative.",
        "coverage": {
            "planned_rows": int(item.get("total_rows") or 0),
            "reviewed_rows": 0,
            "planned_chunks": 0,
            "accepted_chunks": 0,
        },
        "findings": [],
        "relevant_context": [],
        "limitations": [
            f"Artifact analysis ended with {error_class or 'AnalysisError'}; "
            "no clean result is claimed.",
            *([failure_reason] if failure_reason else []),
        ],
        "bounded_follow_up": [
            f"Rerun only {artifact} with --reset-artifact {artifact} "
            f"--request-id {request_id}."
        ],
    }


def analysis_failures_from_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate terminal local/source failures into synthesis coverage gaps."""
    failures: list[dict[str, Any]] = []
    for name, raw_entry in sorted(dict(state.get("artifacts") or {}).items()):
        entry = dict(raw_entry)
        status = str(entry.get("analysis_status") or "")
        if status not in {"failed", "source_failed"}:
            continue
        failures.append(
            {
                "artifact": name,
                "state": status,
                "error": (
                    "local artifact analysis failed; use --reset-artifact to retry"
                    if status == "failed"
                    else "Velociraptor flow ended without analyzable output"
                ),
            }
        )
    return failures


def failure_only_incremental_plan(
    payload: dict[str, Any],
    failures: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create the minimal plan required to publish terminal failure coverage."""
    source_fingerprint = host_analysis_state.canonical_hash(
        {
            "request_id": str(payload.get("request_id") or ""),
            "failures": failures,
        }
    )
    return {
        "schema_version": collection_analysis.ANALYSIS_PLAN_SCHEMA_VERSION,
        "reference_protocol": evidence_references.REFERENCE_PROTOCOL,
        "scope_type": "host",
        "hostname": str(payload.get("hostname") or ""),
        "client_id": str(payload.get("client_id") or ""),
        "request_id": str(payload.get("request_id") or ""),
        "collection_type": str(payload.get("target_collection_type") or ""),
        "analysis_mode": "incremental",
        "total_rows": 0,
        "chunk_count": 0,
        "chunks": [],
        "expected_chunk_headers": [],
        "artifact_task_count": 0,
        "artifact_tasks": [],
        "artifacts": [],
        "collection_failures": failures,
        "source_fingerprint": source_fingerprint,
        "plan_fingerprint": host_analysis_state.canonical_hash(
            {"source_fingerprint": source_fingerprint, "failures": failures}
        ),
        "incremental_analysis": True,
        "evidence_persisted": False,
    }


async def execute_incremental_analysis_async(
    *,
    api: Any,
    args: argparse.Namespace,
    hostname: str,
    initial_payload: dict[str, Any],
    selected_client: Any,
    question: str,
    spec: ResolvedAgentExecution,
    limits: analysis_limits.AnalysisLimits,
    policy: artifact_policy.ArtifactPolicySnapshot,
    paths: dict[str, Path],
    update_progress: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run one in-process polling coordinator with a bounded artifact pool."""
    route = spec.route
    operation_log.emit("analysis_configuration", stage="analysis", provider=route.provider,
                       model=route.model, reasoning_effort=route.reasoning_effort,
                       mode=getattr(args, "synthesis", "none"))
    shared_runner: Any = None
    shared_limits: dict[str, Any] | None = None
    runner_lock = asyncio.Lock()

    def queue_status(status: SchedulerStatus) -> None:
        update_progress(
            {
                "phase": "scheduler",
                "status": "running",
                "scheduler": {
                    "produced": status.produced,
                    "queued": status.queued,
                    "active": status.active,
                    "completed": status.completed,
                    "failed": status.failed,
                    "production_credit_limit": status.production_credit_limit,
                    "production_credits_in_use": status.production_credits_in_use,
                    "production_weight_limit": status.production_weight_limit,
                    "production_weight_in_use": status.production_weight_in_use,
                    "lane_count": status.source_count,
                },
            }
        )

    queue: DynamicAnalysisQueue[Any, Any] = DynamicAnalysisQueue(
        max_concurrency=max(1, int(spec.max_concurrency)),
        prefetch=1,
        lane_queue_size=1,
        max_inflight_weight=(
            limits.maximum_evidence_tokens_per_item
            * max(1, int(spec.max_concurrency))
        ),
        on_status_change=queue_status,
    )

    async def shared_execute(
        task: Any,
        *,
        limits: Any,
        progress_callback: Any,
    ) -> Any:
        nonlocal shared_runner, shared_limits
        resolved_limits = asdict(limits)
        async with runner_lock:
            if shared_runner is None:
                shared_runner = create_agent_runner(
                    spec,
                    limits=limits,
                    persist_runtime_files=False,
                )
                shared_limits = resolved_limits
            elif shared_limits != resolved_limits:
                raise RuntimeError(
                    "Host artifact groups resolved incompatible analyst runtime limits."
                )
            runner = shared_runner
        return await _await_if_needed(
            runner.run(
                task,
                workdir=paths["request_dir"],
                output_dir=paths["runtime_dir"],
                progress_callback=progress_callback,
            )
        )

    try:
        await queue.start()
        value = _execute_incremental_analysis(
            api=api,
            args=args,
            hostname=hostname,
            initial_payload=initial_payload,
            selected_client=selected_client,
            question=question,
            spec=spec,
            limits=limits,
            policy=policy,
            paths=paths,
            update_progress=update_progress,
            analysis_queue=queue,
            shared_execute=shared_execute,
        )
        return await _await_if_needed(value)
    finally:
        await queue.close()
        if shared_runner is not None:
            await _await_if_needed(shared_runner.close())


async def _execute_incremental_analysis(
    *,
    api: Any,
    args: argparse.Namespace,
    hostname: str,
    initial_payload: dict[str, Any],
    selected_client: Any,
    question: str,
    spec: ResolvedAgentExecution,
    limits: analysis_limits.AnalysisLimits,
    policy: artifact_policy.ArtifactPolicySnapshot,
    paths: dict[str, Path],
    update_progress: Any,
    analysis_queue: DynamicAnalysisQueue[Any, Any],
    shared_execute: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Analyze terminal flows with one durable checkpoint per logical artifact."""
    route = spec.route
    state_lock = threading.RLock()
    debug_lock = threading.Lock()
    debug_enabled = bool(getattr(args, "debug", False))
    debug_attempts: dict[tuple[str, int], dict[str, Any]] = {}
    debug_base = {
        "schema_version": 1,
        "operation_id": operation_log.current_operation_id(),
        "scope_type": "host",
        "scope_id": str(initial_payload.get("client_id") or hostname),
        "request_id": str(initial_payload.get("request_id") or ""),
        "created_at": collection.now_utc(),
        "retention": "bounded_value_free_validation_failures",
    }
    cache_identity = analysis_cache_identity(
        args,
        question=question,
        spec=spec,
        limits=limits,
        policy=policy,
    )
    scheduled: dict[str, asyncio.Task[Any]] = {}
    artifact_results: dict[str, dict[str, Any]] = {}
    artifact_plans: dict[str, dict[str, Any]] = {}
    state = host_analysis_state.load_or_initialize(
        paths["host_state"],
        hostname=hostname,
        client_id=str(initial_payload.get("client_id") or ""),
        request_id=str(initial_payload.get("request_id") or ""),
        analysis_identity=cache_identity,
        request_checkpoint=paths["request_checkpoint"],
    )
    requested_artifacts = list(initial_payload.get("requested_artifacts") or [])
    if not requested_artifacts:
        requested_artifacts = [
            str(item.get("artifact") or item.get("artifact_name") or "")
            for item in initial_payload.get("artifact_flows") or []
        ]
    request_profiles, request_time_scopes = _resolve_time_scopes(
        args,
        requested_artifacts,
        policy=policy,
    )
    requested_time_scope = analysis_time_scope.from_args(args)
    request_time_filter = analysis_time_scope.provenance(
        requested_artifacts,
        request_profiles,
        requested_time_scope,
        request_time_scopes,
        profile_resolver=artifact_profiles.resolve_profile,
    )
    request_time_filter["application_stage"] = (
        "server_source_where"
        if request_time_filter.get("filtered_artifacts")
        else "not_applied"
    )
    request_time_filter["artifact_validation"] = {}
    state["time_filter"] = copy.deepcopy(request_time_filter)
    state["artifact_policy"] = policy.metadata()
    state["status"] = "running"
    if not debug_enabled and isinstance(state.get("last_validation_debug"), dict):
        state["last_validation_debug"] = {
            **dict(state["last_validation_debug"]),
            "current_run": False,
        }
    reset_pending = True
    diagnostics: dict[str, dict[str, Any]] = {}

    def save_diagnostics(run: dict[str, Any], artifact: str) -> None:
        for record in run.get("tasks") or []:
            safe = recovery.task_diagnostics(record)
            safe["artifact"] = artifact
            diagnostics[f"{artifact}:{safe['task_id']}"] = safe
        selected_diagnostics = sorted(diagnostics.values(), key=lambda item: item.get("status") != "failed")
        atomic_io.write_json_atomic(paths["diagnostics"], {
            "schema_version": 1, "request_id": initial_payload.get("request_id"),
            "client_id": initial_payload.get("client_id"),
            "model": spec.model, "provider": spec.provider,
            "correction_settings": {
                "validation_correction_attempts": limits.validation_correction_attempts,
                "synthesis_correction_attempts": limits.synthesis_correction_attempts,
            },
            "tasks": selected_diagnostics[:200],
            "omitted_task_count": max(0, len(selected_diagnostics) - 200),
            "retention": "bounded_diagnostics_without_source_values_or_model_output",
        }, sort_keys=True)

    def debug_reference() -> dict[str, Any]:
        path = paths["validation_debug"]
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {
            "path": str(path),
            "sha256": sha256_file(path),
            "retention": "bounded_validation_debug",
            "run_id": str(payload.get("run_id") or ""),
            "status": str(payload.get("status") or ""),
            "current_run": True,
        }

    def write_debug(*, status: str, completed_at: str = "") -> None:
        if not debug_enabled:
            return
        flow_analysis_coordinator.write_validation_debug(
            paths["validation_debug"],
            debug_base,
            debug_attempts.values(),
            status=status,
            completed_at=completed_at,
        )
        state["last_validation_debug"] = debug_reference()

    def capture_debug_records(
        run: dict[str, Any],
        *,
        artifact_key: str,
        artifact: str,
        row_count: int,
    ) -> None:
        if not debug_enabled:
            return
        with debug_lock:
            for record in run.get("tasks") or []:
                task_id = str(record.get("task_id") or "unknown")
                stage = str(record.get("stage") or "analysis")
                for history in record.get("attempt_history") or []:
                    if str(history.get("status") or "") == "accepted":
                        continue
                    attempt = max(1, int(history.get("attempt") or 1))
                    diagnostics = list(history.get("diagnostics") or [])
                    agent_run = dict(history.get("run") or {})
                    response = str(agent_run.get("output") or "")
                    event = {
                        "chunk_id": f"{artifact_key}:{task_id}",
                        "stage": stage,
                        "attempt": attempt,
                        "status": str(history.get("status") or "failed"),
                        "failure_type": (
                            "synthesis_validation_failed"
                            if diagnostics and "synthesis" in stage
                            else "worker_validation_failed"
                            if diagnostics
                            else "executor_error"
                        ),
                        "error": str(history.get("error") or "analysis failed"),
                        "diagnostics": diagnostics,
                        "response_sha256": (
                            hashlib.sha256(response.encode("utf-8")).hexdigest()
                            if response
                            else ""
                        ),
                        "exit_code": agent_run.get("exit_code"),
                        "error_class": "AgentExecutionError" if not diagnostics else "",
                    }
                    manifest = {
                        "artifact": artifact,
                        "row_count": row_count,
                        "input_tokens": 0,
                        "ordinal": 0,
                    }
                    debug_attempts[(event["chunk_id"], attempt)] = (
                        flow_analysis_coordinator.validation_debug_attempt(
                            event,
                            manifest,
                        )
                    )
            write_debug(status="running")

    write_debug(status="running")

    def persist_state() -> None:
        host_analysis_state.persist(paths["host_state"], state)

    def refresh_cached_results() -> None:
        artifact_results.clear()
        artifact_plans.clear()
        for entry in host_analysis_state.completed_artifacts(state):
            name = str(entry.get("artifact") or "")
            if name and isinstance(entry.get("result"), dict) and isinstance(
                entry.get("plan_summary"), dict
            ):
                artifact_results[name] = copy.deepcopy(entry.get("accepted_result") or entry["result"])
                artifact_plans[name] = copy.deepcopy(entry["plan_summary"])

    async def execute_artifact(
        name: str,
        item: dict[str, Any],
        payload_snapshot: dict[str, Any],
        source_aliases: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any], str, Path, int]:
        artifact_plan, chunk_csv = await asyncio.to_thread(
            build_workload,
            api,
            args,
            single_artifact_payload(payload_snapshot, item),
            limits=limits,
            policy=policy,
            source_aliases=source_aliases,
        )
        if (
            list(artifact_plan.get("collection_failures") or [])
            and int(artifact_plan.get("total_rows") or 0) == 0
        ):
            failure_text = " ".join(
                str(item.get("error") or "")
                for item in artifact_plan.get("collection_failures") or []
            )
            time_validation_failure = (
                "The server-side time filter returned out-of-window rows; "
                "the component was rejected and no clean result is claimed."
                if "server-side time filter validation failed" in failure_text
                else ""
            )
            raise RuntimeError(
                f"Artifact evidence acquisition failed for {name}; no rows "
                "were accepted for analysis. "
                f"{time_validation_failure}"
            )
        def artifact_progress(event: dict[str, Any]) -> None:
            scoped = dict(event)
            scoped["artifact"] = name
            if scoped.get("phase") == "complete":
                scoped["phase"] = "artifact_complete"
                scoped["status"] = "accepted"
            update_progress(scoped)

        if int(artifact_plan.get("total_rows") or 0) == 0:
            full_result = apply_time_filter_result(
                empty_artifact_result(
                    artifact=name,
                    question=question,
                    plan=artifact_plan,
                ),
                artifact_plan,
            )
            report_path = (
                paths["artifact_reports_dir"]
                / f"{analysis_summary.safe_artifact_name(name)}.md"
            )
            atomic_io.write_text_atomic(
                report_path,
                analysis_summary.render_artifact_report(full_result),
            )
            artifact_progress({"phase": "complete", "status": "accepted"})
            return (
                host_analysis_state.plan_summary(artifact_plan),
                analysis_summary.discard_full_rows(full_result),
                str(full_result.get("status") or "complete"),
                report_path,
                0,
            )

        runtime_limits = collection_analysis_runtime.limits_from_plan(artifact_plan)
        reset_artifact = bool(getattr(args, "reset_analysis", False)) or name in (
            getattr(args, "reset_artifact", []) or [])
        chunk_checkpoint = recovery.ChunkRecovery(
            paths["chunk_recovery"] / f"{analysis_summary.safe_artifact_name(name)}.json",
            recovery.fingerprint([cache_identity, artifact_plan.get("source_fingerprint"),
                                  artifact_plan.get("plan_fingerprint")]),
            reuse=bool(getattr(args, "retry_failed", False)) and not reset_artifact,
        )

        async def bounded_execute(task: Any) -> Any:
            return await shared_execute(
                task,
                limits=runtime_limits,
                progress_callback=lambda event: artifact_progress(
                    analysis_cli_output.agent_event_progress(event)
                ),
            )

        async def schedule_worker(task: Any, worker: Any) -> Any:
            chunk_metadata = dict(task.metadata.get("chunk") or {})
            return await analysis_queue.enqueue(
                name,
                task,
                execute=worker,
                weight=max(
                    1,
                    int(
                        chunk_metadata.get("input_tokens")
                        or max(1, len(str(task.prompt)) // 4)
                    ),
                ),
            )

        artifact_plan["synthesis_mode"] = getattr(args, "synthesis", "none")
        run = await _await_if_needed(collection_analysis_runtime.execute_analysis_workload_async(
                plan=artifact_plan,
                chunk_csv=chunk_csv,
                question=question,
                spec=spec,
                agent_metadata=analyst_execution_metadata(spec),
                workdir=paths["request_dir"],
                output_dir=paths["runtime_dir"],
                execute=bounded_execute,
                progress_callback=artifact_progress,
                schedule=schedule_worker,
                perform_scope_synthesis=False,
                chunk_recovery=chunk_checkpoint,
            ))
        save_diagnostics(run, name)
        state["artifacts"][name]["diagnostics"] = [
            recovery.task_diagnostics(record) for record in run.get("tasks") or []
        ]
        capture_debug_records(
            run,
            artifact_key=host_analysis_state.canonical_hash(name)[:16],
            artifact=str(item.get("artifact") or item.get("artifact_name") or "unknown"),
            row_count=int(artifact_plan.get("total_rows") or 0),
        )
        if not artifact_analysis_run_is_cacheable(run):
            raise RuntimeError(
                f"Artifact analysis did not produce a reusable result for {name}: "
                f"{run.get('status') or 'failed'}"
            )
        results = list(run.get("artifact_results") or [])
        if len(results) != 1:
            raise RuntimeError(
                f"Artifact analysis for {name} returned {len(results)} results; expected one."
            )
        full_result = apply_time_filter_result(dict(results[0]), artifact_plan)
        full_result["collection_coverage"] = {
            "status": "complete" if str(item.get("flow_state") or "").upper() == "FINISHED" else "partial",
            "flow_state": str(item.get("flow_state") or "UNKNOWN"),
            "exposed_rows": int(item.get("total_rows") or 0),
        }
        full_result["result_role"] = "provisional_candidates"
        report_path = (
            paths["artifact_reports_dir"]
            / f"{analysis_summary.safe_artifact_name(name)}.md"
        )
        atomic_io.write_text_atomic(
            report_path,
            analysis_summary.render_artifact_report(full_result),
        )
        compact_result = analysis_summary.discard_full_rows(full_result)
        retry_count = sum(
            max(0, int(task.get("attempts") or 0) - 1)
            for task in run.get("tasks") or []
        )
        return (
            host_analysis_state.plan_summary(artifact_plan),
            compact_result,
            str(full_result.get("status") or run.get("status") or "complete"),
            report_path,
            retry_count,
        )

    async def execute_and_record(
        name: str,
        item: dict[str, Any],
        payload_snapshot: dict[str, Any],
        source_aliases: dict[str, dict[str, Any]],
    ) -> None:
        try:
            (
                artifact_plan,
                artifact_result,
                artifact_status,
                report_path,
                retry_count,
            ) = await execute_artifact(
                name,
                item,
                payload_snapshot,
                source_aliases,
            )
        except Exception as exc:
            failure_diagnostic = {
                "task_id": name, "stage": "artifact", "status": "failed", "attempts": 0,
                "category": "artifact_execution_failed", "exception_type": type(exc).__name__,
                "message": "Artifact acquisition, planning or execution failed. Check flow status and analysis-diagnostics.json; no negative finding is inferred.",
            }
            # Preserve detailed validator diagnostics when execution finished before publication failed.
            state["artifacts"][name].setdefault("diagnostics", [failure_diagnostic])
            diagnostics.setdefault(f"{name}:artifact", failure_diagnostic)
            save_diagnostics({}, name)
            failure_reason = (
                "The server-side time filter returned out-of-window rows; the "
                "component was rejected and the filter must be corrected."
                if "server-side time filter returned out-of-window rows"
                in str(exc)
                else ""
            )
            failure_result = artifact_failure_result(
                artifact=name,
                question=question,
                item=item,
                request_id=str(payload_snapshot.get("request_id") or ""),
                error_class=type(exc).__name__,
                failure_reason=failure_reason,
            )
            failure_time_filter = copy.deepcopy(request_time_filter)
            if name in set(request_time_filter.get("filtered_artifacts") or []):
                failure_time_filter["coverage"] = "failed"
                failure_time_filter["artifact_validation"] = {
                    name: {
                        "application": "server_source_where",
                        "validation": "failed",
                    }
                }
            elif name in set(
                request_time_filter.get("unsupported_artifacts") or []
            ):
                failure_time_filter["coverage"] = "unsupported"
                failure_time_filter["artifact_validation"] = {
                    name: {
                        "application": "not_applied",
                        "validation": "not_required",
                    }
                }
            failure_result = apply_time_filter_result(
                failure_result,
                {"time_filter": failure_time_filter},
            )
            report_path = (
                paths["artifact_reports_dir"]
                / f"{analysis_summary.safe_artifact_name(name)}.md"
            )
            atomic_io.write_text_atomic(
                report_path,
                analysis_summary.render_artifact_report(failure_result),
            )
            with state_lock:
                host_analysis_state.mark_artifact_failed(
                    state,
                    name,
                    error_class=type(exc).__name__,
                    result=failure_result,
                    report_file=report_path,
                )
                persist_state()
                publish_host_artifact_reports(paths=paths, entries=[state["artifacts"][name]])
            update_progress(
                {
                    "phase": "artifact_complete",
                    "status": "failed",
                    "artifact": name,
                    "error_class": type(exc).__name__,
                }
            )
            return
        with state_lock:
            host_analysis_state.mark_artifact_complete(
                state,
                name,
                status=artifact_status,
                result=artifact_result,
                plan_summary=artifact_plan,
                report_file=report_path,
            )
            state["artifacts"][name]["retry_count"] = retry_count
            artifact_plans[name] = artifact_plan
            artifact_results[name] = artifact_result
            persist_state()
            publish_host_artifact_reports(paths=paths, entries=[state["artifacts"][name]])

    def schedule_ready(payload_snapshot: dict[str, Any]) -> None:
        nonlocal reset_pending
        with state_lock:
            requested_resets = (
                list(getattr(args, "reset_artifact", []) or [])
                if reset_pending
                else []
            )
            reset_all = (
                bool(getattr(args, "reset_analysis", False))
                if reset_pending
                else False
            )
            runnable = host_analysis_state.reconcile(
                state,
                payload=payload_snapshot,
                analysis_identity=cache_identity,
                reset_artifacts=requested_resets,
                reset_all=reset_all,
                report_root=paths["artifact_reports_dir"],
                retry_failed=reset_pending and bool(getattr(args, "retry_failed", False)),
            )
            if reset_pending and (requested_resets or reset_all):
                paths["request_checkpoint"].unlink(missing_ok=True)
                reset_names = (
                    set(state["artifacts"])
                    if reset_all
                    else {str(value).strip() for value in requested_resets}
                )
                artifact_root = paths["artifact_reports_dir"].resolve()
                for reset_name in reset_names:
                    report_path = (
                        artifact_root
                        / f"{analysis_summary.safe_artifact_name(reset_name)}.md"
                    ).resolve()
                    if report_path.parent == artifact_root:
                        report_path.unlink(missing_ok=True)
            reset_pending = False
            for active_name, active_future in scheduled.items():
                if (
                    not active_future.done()
                    and active_name in state["artifacts"]
                ):
                    state["artifacts"][active_name]["analysis_status"] = "running"
            refresh_cached_results()
        request_source_aliases = collection_analysis.ensure_collection_source_aliases(
            payload_snapshot,
            existing={},
        )
        for item_value in runnable:
            item = dict(item_value)
            name = str(
                item.get("artifact") or item.get("artifact_name") or ""
            ).strip()
            if not name:
                continue
            with state_lock:
                if name in scheduled:
                    continue
                host_analysis_state.mark_artifact_started(state, name)
                scheduled[name] = asyncio.create_task(
                    execute_and_record(
                        name,
                        item,
                        dict(payload_snapshot),
                        copy.deepcopy(request_source_aliases),
                    ),
                    name=f"artifact:{name}",
                )

    latest = dict(initial_payload)
    schedule_ready(latest)
    if not latest.get("all_artifacts_expected_complete"):
        loop = asyncio.get_running_loop()
        poll_updates: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1)

        def on_poll(payload_snapshot: dict[str, Any]) -> None:
            update = asyncio.run_coroutine_threadsafe(
                poll_updates.put(dict(payload_snapshot)),
                loop,
            )
            update.result()

        def publish_poll_progress(payload_snapshot: dict[str, Any]) -> None:
            poll_progress = list(payload_snapshot.get("poll_progress") or [])
            update_progress(
                {
                    "phase": "polling",
                    "status": "running",
                    "submitted": len(poll_progress),
                    "completed": sum(
                        1 for item in poll_progress if item.get("is_finished")
                    ),
                    "rows": sum(
                        int(item.get("total_rows") or 0) for item in poll_progress
                    ),
                    "request_id": str(payload_snapshot.get("request_id") or ""),
                }
            )

        publish_poll_progress(latest)
        poll_task = asyncio.create_task(
            asyncio.to_thread(
                collection.poll_collection,
                api,
                args.investigation_id,
                hostname,
                args.poll_interval_seconds,
                args.poll_timeout_seconds,
                request_id=str(latest.get("request_id") or ""),
                client=selected_client,
                progress_callback=on_poll,
                emit_progress=False,
            ),
            name="collection-poller",
        )
        while not poll_task.done():
            next_update = asyncio.create_task(poll_updates.get())
            done, _pending = await asyncio.wait(
                {poll_task, next_update},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if next_update in done:
                latest = next_update.result()
                publish_poll_progress(latest)
                schedule_ready(latest)
            else:
                next_update.cancel()
                await asyncio.gather(next_update, return_exceptions=True)
        latest = await poll_task
        while not poll_updates.empty():
            latest = poll_updates.get_nowait()
            schedule_ready(latest)
    schedule_ready(latest)
    if latest.get("poll_timed_out"):
        raise RuntimeError(
            "Collection polling timed out; analysis is incomplete. "
            "Check for an active runner or monitor before resuming the same exact flows:\n"
            + resume_analysis_command(args, latest)
        )
    artifact_outcomes = await asyncio.gather(
        *scheduled.values(),
        return_exceptions=True,
    )
    for outcome in artifact_outcomes:
        if isinstance(outcome, BaseException):
            raise outcome
    with state_lock:
        refresh_cached_results()
    ordered_keys = sorted(artifact_plans)
    analysis_failures = analysis_failures_from_state(state)
    if ordered_keys:
        combined_plan = combine_incremental_plans(
            [artifact_plans[key] for key in ordered_keys],
            latest,
        )
        combined_plan["collection_failures"] = [
            *list(combined_plan.get("collection_failures") or []),
            *analysis_failures,
        ]
    else:
        combined_plan = failure_only_incremental_plan(latest, analysis_failures)
    artifact_time_validation: dict[str, dict[str, Any]] = {}
    if requested_time_scope.bounded:
        artifact_time_validation = {
            str(artifact): copy.deepcopy(
                dict(dict(artifact_plans[artifact]).get("time_filter") or {}).get(
                    "artifact_validation", {}
                ).get(artifact, {})
            )
            for artifact in ordered_keys
        }
        for artifact in request_time_filter.get("filtered_artifacts") or []:
            if artifact in artifact_time_validation:
                continue
            entry = dict(dict(state.get("artifacts") or {}).get(artifact) or {})
            artifact_time_validation[str(artifact)] = {
                "application": "server_source_where",
                "validation": (
                    "failed"
                    if str(entry.get("analysis_status") or "")
                    in {"failed", "source_failed"}
                    else "not_completed"
                ),
            }
    combined_time_filter = {
        **copy.deepcopy(request_time_filter),
        "artifact_validation": artifact_time_validation,
    }
    validation_states = {
        str(item.get("validation") or "")
        for item in artifact_time_validation.values()
    }
    if "partial" in validation_states:
        combined_time_filter["coverage"] = "partial"
    elif "failed" in validation_states:
        combined_time_filter["coverage"] = (
            "partial" if "passed" in validation_states else "failed"
        )
    combined_plan["time_filter"] = combined_time_filter
    state["time_filter"] = copy.deepcopy(combined_time_filter)
    combined_plan["synthesis_mode"] = getattr(args, "synthesis", "none")
    ordered_results = [copy.deepcopy(artifact_results[key]) for key in ordered_keys]
    final_limits = (
        collection_analysis_runtime.limits_from_plan(combined_plan)
        if ordered_results
        else None
    )

    async def bounded_final_execute(task: Any) -> Any:
        if final_limits is None:
            raise RuntimeError("host synthesis executor is unavailable without results")
        return await shared_execute(
            task,
            limits=final_limits,
            progress_callback=lambda event: update_progress(
                analysis_cli_output.agent_event_progress(event)
            ),
        )

    async def schedule_final_worker(task: Any, worker: Any) -> Any:
        return await analysis_queue.enqueue(
            "host-synthesis",
            task,
            execute=worker,
            weight=max(1, len(str(task.prompt)) // 4),
        )

    with state_lock:
        state["synthesis"] = {
            "status": "running",
            "input_fingerprint": host_analysis_state.canonical_hash(
                [state["artifacts"][key]["source_fingerprint"] for key in ordered_keys]
            ),
            "started_at": collection.now_utc(),
        }
        persist_state()
    summary_key = synthesis_policy.cache_key(
        results=ordered_results, question=question, plan=combined_plan,
        execution=analyst_execution_identity(spec),
    )
    saved_cache = {}
    if paths["request_checkpoint"].is_file():
        try:
            saved = json.loads(paths["request_checkpoint"].read_text())
            expected = host_analysis_state.canonical_hash({k: v for k, v in saved.items()
                if k not in {"checkpoint_fingerprint", "completed_at"}})
            if expected == saved.get("checkpoint_fingerprint"):
                saved_cache = saved.get("synthesis_cache") or {}
        except (ValueError, OSError):
            pass
    cached = (synthesis_policy.cached_result(saved_cache, summary_key)
              if combined_plan["synthesis_mode"] == "full" else None)
    if cached is not None:
        host_run = {"status": cached["status"], "host_result": cached, "tasks": [], "reused": True}
        operation_log.emit("synthesis_cache_hit", stage="host_synthesis", status="complete")
    else:
        host_run = await _await_if_needed(
            collection_analysis_runtime.execute_host_synthesis_from_artifact_results_async(
                plan=combined_plan,
                artifact_results=ordered_results,
                question=question,
                execute=bounded_final_execute if ordered_results else None,
                progress_callback=update_progress,
                schedule=schedule_final_worker if ordered_results else None,
            )
        )
    if combined_plan["synthesis_mode"] == "full":
        state["synthesis_cache"] = synthesis_policy.cache_record(host_run["host_result"], summary_key)
    elif saved_cache:
        state["synthesis_cache"] = saved_cache
    capture_debug_records(
        host_run,
        artifact_key="host-synthesis",
        artifact="host-analysis",
        row_count=int(combined_plan.get("total_rows") or 0),
    )
    analysis_queue.mark_sources_exhausted()
    host_result = dict(host_run["host_result"])
    host_result["synthesis_metrics"] = {
        "mode": combined_plan["synthesis_mode"],
        "cache_hit": bool(host_run.get("reused")),
        "task_attempts": sum(int(task.get("attempts") or 0) for task in host_run.get("tasks") or []),
        "input_artifacts": len(ordered_results),
    }
    save_diagnostics(host_run, "host-analysis")
    host_result["troubleshooting"] = {
        "diagnostics_file": str(paths["diagnostics"]),
        "failed_stages": [item for item in diagnostics.values() if item["status"] == "failed"][:200],
        "resume_command": resume_analysis_command(args, initial_payload, retry_failed=True),
        "resume": {
            "command": "vraptor analyze" if getattr(args, "existing_only", False) else "vraptor collect analyze", "request_id": str(initial_payload.get("request_id") or ""),
            "client_id": str(initial_payload.get("client_id") or ""),
            "retry_failed": True, "question": question,
            "instruction": "Use the same case, request, question and analysis settings with --retry-failed.",
        },
    }
    host_result.setdefault("status", str(host_run["status"]))
    host_result = apply_time_filter_result(host_result, combined_plan)
    host_result["limitations"] = analysis_summary.unique_limitations(host_result.get("limitations") or [])
    host_status = str(host_result.get("status") or host_run["status"])
    final_run = {
        "schema_version": collection_analysis_runtime.RUN_SCHEMA_VERSION,
        "status": host_status,
        "question": question,
        "plan_fingerprint": str(combined_plan["plan_fingerprint"]),
        "source_fingerprint": str(combined_plan["source_fingerprint"]),
        "analyst_agent": analyst_execution_metadata(spec),
        "artifact_results": ordered_results,
        "host_result": host_result,
        "tasks": list(host_run.get("tasks") or []),
        "evidence_persisted": False,
        "incremental_analysis": True,
    }
    with state_lock:
        state["status"] = str(final_run["status"])
        state["completed_at"] = collection.now_utc()
        state["scheduler"] = asdict(analysis_queue.status)
        write_debug(status=str(final_run["status"]), completed_at=state["completed_at"])
        if debug_enabled:
            final_run["validation_debug"] = debug_reference()
        state["synthesis"].update(
            {
                "status": str(final_run["status"]),
                "completed_at": state["completed_at"],
                "result": analysis_summary.compact_result(
                    dict(final_run["host_result"])
                ),
            }
        )
        persist_state()
    return combined_plan, final_run, state


def cleanup_transient_runtime(paths: dict[str, Path]) -> None:
    """Remove only the request-owned transient API worker directory."""
    request_root = paths["request_dir"].resolve()
    runtime_root = paths["runtime_dir"].resolve()
    if runtime_root.parent != request_root or runtime_root.name != ".api-runtime":
        raise RuntimeError(f"refusing to remove unexpected runtime path: {runtime_root}")
    if runtime_root.exists():
        shutil.rmtree(runtime_root)


async def run_analysis_async(
    api: Any,
    args: argparse.Namespace,
    *,
    policy: artifact_policy.ArtifactPolicySnapshot,
    limits: analysis_limits.AnalysisLimits,
) -> dict[str, Any]:
    progress_reporter = getattr(args, "_progress_reporter", None)
    skip_ai = bool(getattr(args, "skip_ai", False))
    prepare_only = args.plan_only or skip_ai
    question = str(args.question or "").strip()
    if not question:
        raise RuntimeError("--question cannot be empty")
    reset_requested = bool(
        getattr(args, "reset_analysis", False)
        or list(getattr(args, "reset_artifact", []) or [])
    )
    retry_failed = bool(getattr(args, "retry_failed", False))
    if retry_failed and (reset_requested or prepare_only or bool(getattr(args, "force_run", False))):
        raise RuntimeError("--retry-failed cannot be combined with reset, --force-run, --plan-only or --skip-ai")
    if retry_failed and not getattr(args, "request_id", None):
        raise RuntimeError("--retry-failed requires --request-id")
    if skip_ai and reset_requested:
        raise RuntimeError("--skip-ai cannot be combined with analysis reset options")
    if reset_requested and not getattr(args, "request_id", None):
        raise RuntimeError(
            "--reset-artifact and --reset-analysis require --request-id so reset "
            "cannot queue or select a different collection."
        )
    if reset_requested and bool(getattr(args, "force_run", False)):
        raise RuntimeError("analysis reset cannot be combined with --force-run")
    if bool(getattr(args, "rebuild_host_summary", False)) and (
        reset_requested or retry_failed or bool(getattr(args, "force_run", False)) or prepare_only
    ):
        raise RuntimeError(
            "--rebuild-host-summary cannot be combined with reset, --force-run, "
            "or --plan-only/--skip-ai"
        )
    selected_client: Any = None
    chunk_csv: dict[int, str] = {}
    rebuild_only = bool(getattr(args, "rebuild_host_summary", False))
    if model_options.supplied(args):
        selected = getattr(args, "_cli_model_execution", None)
        if selected is None:
            selected = model_options.resolve(
                args, resolver=resolve_agent_execution,
                allow_missing_credentials=prepare_only or rebuild_only,
            )
        spec, limits = selected
        if prepare_only or rebuild_only:
            spec = None
    else:
        spec = None if prepare_only or rebuild_only else resolve_agent_execution()
    if spec is not None:
        limits = limits.for_execution(spec)
    if progress_reporter is not None:
        progress_reporter.emit(phase="ensuring_flows", status="running", force=True)
    if prepare_only or rebuild_only:
        def report_resolve_poll(payload_snapshot: dict[str, Any]) -> None:
            if progress_reporter is None:
                return
            poll_progress = list(payload_snapshot.get("poll_progress") or [])
            progress_reporter.update(
                {
                    "phase": "polling",
                    "status": "running",
                    "submitted": len(poll_progress),
                    "completed": sum(
                        1 for item in poll_progress if item.get("is_finished")
                    ),
                    "rows": sum(
                        int(item.get("total_rows") or 0) for item in poll_progress
                    ),
                    "request_id": str(payload_snapshot.get("request_id") or ""),
                }
            )

        hostname, payload, action = resolve_collection(
            api,
            args,
            policy=policy,
            progress_callback=report_resolve_poll,
            emit_progress=progress_reporter is None,
        )
        if prepare_only:
            plan, _chunk_csv = build_workload(
                api,
                args,
                payload,
                limits=limits,
                policy=policy,
            )
            # Explicit prompt inspection is also useful without model execution.
            for chunk in plan.get("chunks", [])[:getattr(args, "debug_chunk_prompts", 0)]:
                collection_analysis_runtime.render_chunk_prompt(
                    plan=plan, chunk=chunk, question=question,
                    csv_evidence=_chunk_csv[int(chunk["chunk_index"])],
                )
        else:
            plan = {}
    else:
        hostname, payload, action, selected_client = start_collection(
            api,
            args,
            policy=policy,
        )
        plan = {
            "hostname": hostname,
            "client_id": str(payload.get("client_id") or ""),
            "request_id": str(payload.get("request_id") or ""),
            "collection_type": str(payload.get("target_collection_type") or ""),
            "total_rows": sum(
                int(item.get("total_rows") or 0)
                for item in payload.get("artifact_flows") or []
            ),
            "artifact_tasks": [
                {
                    "task_id": "pending-" + artifact_analysis_key(dict(item)),
                    "artifact": str(
                        item.get("artifact") or item.get("artifact_name") or ""
                    ),
                }
                for item in payload.get("artifact_flows") or []
            ],
            "supersedes_request_id": str(
                payload.get("supersedes_request_id") or ""
            ),
            "unavailable_artifacts": list(
                payload.get("unavailable_artifacts") or []
            ),
        }
    paths = analysis_paths(
        case_root=collection.CASE_ROOT,
        investigation_id=args.investigation_id,
        hostname=hostname,
        request_id=str(payload["request_id"]),
    )
    if progress_reporter is not None:
        progress_reporter.emit(
            phase="collection_ready",
            status="running",
            force=True,
            hostname=hostname,
            client_id=str(payload.get("client_id") or ""),
            request_id=str(payload.get("request_id") or ""),
        )
    if rebuild_only:
        publish_host_artifact_reports(paths=paths)
        report = render_cumulative_host_memory(paths=paths)
        atomic_io.write_text_atomic(paths["host_report"], report)
        return {
            "schema_version": 1,
            "status": "rebuilt",
            "collection_action": action,
            "hostname": hostname,
            "client_id": str(payload.get("client_id") or ""),
            "request_id": str(payload["request_id"]),
            "host_report_file": str(paths["host_report"]),
            "evidence_persisted": False,
        }
    if prepare_only:
        plan.update(ai_review_status="skipped", review_complete=False)
        atomic_io.write_json_atomic(paths["plan_only"], plan, sort_keys=True)
        return {
            "schema_version": 1,
            "status": "planned",
            "ai_review_status": "skipped",
            "review_complete": False,
            "collection_action": action,
            "hostname": hostname,
            "client_id": str(payload.get("client_id") or ""),
            "request_id": str(payload["request_id"]),
            "analysis_mode": plan["analysis_mode"],
            "artifact_task_count": plan["artifact_task_count"],
            "chunk_count": plan["chunk_count"],
            "analysis_plan_file": str(paths["plan_only"]),
            "chat_summary": analysis_summary.render_chat_summary(
                {"ai_review_status": "skipped", "answer": "Evidence preparation only; no AI assessment was requested."},
                title=f"Host {hostname} preparation summary",
                status="planned",
                flow_metadata=payload.get("artifact_flows") or [],
                collection_complete=bool(payload.get("all_artifacts_expected_complete")),
            ),
            "evidence_persisted": False,
        }
    assert spec is not None
    diagnostics_session: agent_diagnostics.DebugSession | None = None
    if bool(getattr(args, "debug", False)):
        diagnostics_session = agent_diagnostics.DebugSession(
            paths["validation_debug"],
            scope_type="host",
            scope_id=str(payload.get("client_id") or hostname),
            lane=str(payload.get("target_collection_type") or "host_analysis"),
            request_id=str(payload.get("request_id") or ""),
        )
        diagnostics_session.__enter__()
    progress: dict[str, Any] = {
        "phase": "analysis",
        "status": "running",
        "tasks": {},
        "artifacts": {},
        "resume_command": resume_analysis_command(args, payload, retry_failed=True),
    }
    progress_lock = threading.Lock()

    def publish(text: str) -> None:
        atomic_io.write_text_atomic(paths["host_report"], text)

    def update_progress(event: dict[str, Any]) -> None:
        with progress_lock:
            progress["phase"] = str(event.get("phase") or progress["phase"])
            event_status = str(event.get("status") or "")
            progress["status"] = (
                event_status
                if progress["phase"] == "complete" and event_status
                else "running"
            )
            task_id = str(event.get("task_id") or "")
            if task_id:
                progress["tasks"][task_id] = dict(event)
            if event.get("phase") == "artifact" and task_id and event.get("normalized"):
                progress["artifacts"][task_id] = dict(event["normalized"])
            publish(
                collection_analysis_runtime.render_running_host_report(
                    plan=plan,
                    question=question,
                    progress=progress,
                )
            )
        if progress_reporter is not None:
            progress_reporter.update(event)

    update_progress({"phase": "analysis", "status": "running"})
    try:
        plan, run, state = await execute_incremental_analysis_async(
            api=api,
            args=args,
            hostname=hostname,
            initial_payload=payload,
            selected_client=selected_client,
            question=question,
            spec=spec,
            limits=limits,
            policy=policy,
            paths=paths,
            update_progress=update_progress,
        )
    except Exception as exc:
        if bool(getattr(args, "debug", False)):
            debug_path = paths["validation_debug"]
            try:
                existing_debug = (
                    json.loads(debug_path.read_text(encoding="utf-8"))
                    if debug_path.is_file()
                    else {
                        "schema_version": 1,
                        "scope_type": "host",
                        "scope_id": str(payload.get("client_id") or hostname),
                        "request_id": str(payload.get("request_id") or ""),
                        "created_at": collection.now_utc(),
                        "retention": "bounded_value_free_validation_failures",
                    }
                )
                attempts = list(existing_debug.get("attempt_failures") or [])
                attempts.append(
                    flow_analysis_coordinator.validation_debug_attempt(
                        {
                            "chunk_id": "analysis-runtime",
                            "stage": "host-runtime",
                            "attempt": 1,
                            "status": "failed",
                            "failure_type": "executor_error",
                            "error": str(exc),
                            "error_class": type(exc).__name__,
                        },
                        {
                            "artifact": "host-analysis",
                            "row_count": int(plan.get("total_rows") or 0),
                            "input_tokens": 0,
                            "ordinal": 0,
                        },
                    )
                )
                flow_analysis_coordinator.write_validation_debug(
                    debug_path,
                    existing_debug,
                    attempts,
                    status="failed",
                    completed_at=collection.now_utc(),
                )
            except (OSError, ValueError, TypeError):
                pass
        update_progress(
            {
                "phase": "failed",
                "status": "failed",
                "task_id": "analysis-runtime",
                "error": str(exc),
            }
        )
        progress["status"] = "failed"
        publish(
            collection_analysis_runtime.render_running_host_report(
                plan=plan,
                question=question,
                progress=progress,
            )
        )
        try:
            failed_state = json.loads(paths["host_state"].read_text(encoding="utf-8"))
            if (
                isinstance(failed_state, dict)
                and int(failed_state.get("schema_version") or 0)
                == host_analysis_state.SCHEMA_VERSION
            ):
                failed_state["synthesis"] = {
                    "status": "failed",
                    "failed_at": collection.now_utc(),
                    "last_error": "host synthesis failed; rerun to retry",
                    "error_class": type(exc).__name__,
                }
                failed_state["status"] = "failed"
                host_analysis_state.persist(paths["host_state"], failed_state)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        if diagnostics_session is not None:
            diagnostics_session.__exit__(type(exc), exc, exc.__traceback__)
            diagnostics_session = None
        raise
    finally:
        try:
            cleanup_transient_runtime(paths)
        except Exception as cleanup_exc:
            if diagnostics_session is not None:
                diagnostics_session.__exit__(
                    type(cleanup_exc),
                    cleanup_exc,
                    cleanup_exc.__traceback__,
                )
                diagnostics_session = None
            raise
    if diagnostics_session is not None:
        diagnostics_session.finalize(str(run.get("status") or "complete"))
        diagnostics_session.__exit__(None, None, None)
        diagnostics_session = None
    unavailable_artifacts = list(plan.get("unavailable_artifacts") or [])
    if unavailable_artifacts:
        superseded = str(plan.get("supersedes_request_id") or "<unknown>")
        limitation = (
            f"Request {superseded} was superseded after failed artifact "
            "preflight; unavailable artifacts were omitted: "
            + ", ".join(unavailable_artifacts)
            + ". Full baseline coverage is not claimed."
        )
        host_result = dict(run.get("host_result") or {})
        if str(host_result.get("status") or "") == "complete":
            host_result["status"] = "complete_with_failures"
        host_result["limitations"] = list(
            dict.fromkeys(
                [*list(host_result.get("limitations") or []), limitation]
            )
        )
        run["host_result"] = host_result
        run["status"] = str(host_result.get("status") or run.get("status") or "")
    reviewed = dict(run.get("host_result") or {})
    if reviewed.get("final_review") and reviewed.get("review_status") != "not_requested":
        for candidate_result in run.get("artifact_results") or []:
            name = candidate_result["artifact"]
            entry = state["artifacts"].get(name)
            if not entry or not entry.get("report_file"):
                continue
            publication = host_final_review.artifact_publication(candidate_result, reviewed)
            # Keep accepted candidate analysis for final-review-only resume.
            entry["accepted_result"] = copy.deepcopy(candidate_result)
            entry["accepted_result_role"] = "provisional_candidates"
            entry["result"] = analysis_summary.compact_result(publication)
            entry["result_role"] = "final_publication"
            report_text = analysis_summary.render_artifact_report(publication)
            report_hash = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
            # Never overwrite a report referenced by an accepted checkpoint:
            # an interruption before state commit must not invalidate resume.
            report_path = paths["artifact_reports_dir"] / (
                f"{analysis_summary.safe_artifact_name(name)}--review-{report_hash[:16]}.md"
            )
            if not report_path.is_file() or sha256_file(report_path) != report_hash:
                atomic_io.write_text_atomic(report_path, report_text, newline="")
            entry["report_file"] = str(report_path.resolve())
            entry["report_sha256"] = report_hash
    artifact_report_files = publish_host_artifact_reports(
        paths=paths, entries=[
            dict(entry) for _, entry in sorted(state.get("artifacts", {}).items())
            if entry.get("analysis_status") in host_analysis_state.TERMINAL_ANALYSIS_STATUSES
            and Path(str(entry.get("report_file") or "")).is_file()
        ],
    )
    run["artifact_report_files"] = artifact_report_files
    selected_finding_context_persisted = any(
        evidence.get("fields")
        for artifact_result in run.get("artifact_results") or []
        for finding in artifact_result.get("findings") or []
        for evidence in finding.get("evidence") or []
    )
    compact_host_result = analysis_summary.compact_result(
        dict(run.get("host_result") or {}),
        artifact_reports=artifact_report_files,
    )
    checkpoint = host_analysis_state.write_request_checkpoint(
        paths["request_checkpoint"],
        state=state,
        question=question,
        host_result=compact_host_result,
        status=str(run.get("status") or "failed"),
        task_mode=str(plan.get("task_mode") or ""),
        response_depth=str(plan.get("response_depth") or ""),
    )
    state["synthesis"]["request_checkpoint_file"] = str(
        paths["request_checkpoint"]
    )
    state["synthesis"]["request_checkpoint_sha256"] = hashlib.sha256(
        paths["request_checkpoint"].read_bytes()
    ).hexdigest()
    host_analysis_state.persist(paths["host_state"], state)
    cumulative_report = render_cumulative_host_memory(paths=paths)
    atomic_io.write_text_atomic(paths["host_report"], cumulative_report)
    result = {
        "schema_version": 1,
        "status": run["status"],
        "collection_action": action,
        "hostname": hostname,
        "client_id": str(payload.get("client_id") or ""),
        "request_id": str(payload["request_id"]),
        "artifact_policy": policy.metadata(),
        "analysis_mode": plan["analysis_mode"],
        "task_mode": str(plan.get("task_mode") or ""),
        "response_depth": str(plan.get("response_depth") or ""),
        "artifact_task_count": plan["artifact_task_count"],
        "chunk_count": plan["chunk_count"],
        "request_checkpoint_file": str(paths["request_checkpoint"]),
        "host_report_file": str(paths["host_report"]),
        "host_state_file": str(paths["host_state"]),
        **(
            {"validation_debug_file": str(paths["validation_debug"])}
            if bool(getattr(args, "debug", False))
            else {}
        ),
        "artifact_report_files": artifact_report_files,
        "selected_finding_context_persisted": bool(
            selected_finding_context_persisted
        ),
        "analysis_result": checkpoint["result"],
        "chat_summary": analysis_summary.render_chat_summary(
            checkpoint["result"],
            title=f"Host {hostname} analysis summary",
            status=str(run["status"]),
            flow_metadata=checkpoint.get("artifact_summaries") or [],
            analysis_completed_at=str(checkpoint.get("completed_at") or ""),
            collection_complete=bool(dict(checkpoint.get("source_observation") or {}).get("all_artifacts_expected_complete")),
        ),
        "evidence_persisted": False,
    }
    return result


async def async_main(argv: list[str] | None = None, *, existing_only: bool = False) -> int:
    parser = build_parser()
    if existing_only:
        parser.add_argument("--flow-id", "--flow", dest="flow_id")
    global_args = parser.parse_args(argv)
    global_args.existing_only = existing_only
    if existing_only:
        if bool(global_args.request_id) == bool(global_args.flow_id):
            parser.error("Select exactly one of --flow or --request-id")
        if global_args.force_run:
            parser.error("analyze does not accept --force-run")
    policy = artifact_policy.load_artifact_policy()
    if model_options.supplied(global_args):
        global_args._cli_model_execution = model_options.resolve(
            global_args, resolver=resolve_agent_execution,
            allow_missing_credentials=bool(
                global_args.plan_only or global_args.skip_ai or global_args.rebuild_host_summary
            ),
        )
        _, limits = global_args._cli_model_execution
    else:
        limits = analysis_limits.resolve_analysis_limits()
    progress_reporter = analysis_cli_output.ProgressReporter(
        scope="host",
        scope_id=str(global_args.host or global_args.client_id or ""),
        enabled=not bool(global_args.no_progress),
        heartbeat_seconds=float(global_args.progress_interval_seconds),
    )
    progress_reporter.start(phase="preflight")
    global_args._progress_reporter = progress_reporter
    try:
        org_id = resolve_org_id(
            global_args.org_id
        )
        context = engagement_context.resolve(
            repo_root=REPO_ROOT,
            engagement_id=global_args.investigation_id,
            server_profile=global_args.server_profile,
            api_client=global_args.api_client,
            case_root=global_args.case_root,
            readiness_manifest=global_args.readiness_manifest,
            expected_org_id=org_id,
            requested_client_id=str(global_args.client_id or ""),
            requested_hostname=str(global_args.host or ""),
        )
        global_args.investigation_id = context.engagement_id
        global_args.server_profile = context.server_profile
        case_root = context.case_root
        operation_log.bind_case(context.case_root, context.engagement_id)
        operation_log.emit(
            "readiness_validated",
            component="host_analysis",
            stage="preflight",
            status="complete",
            scope="host",
            scope_id=context.engagement_id,
            org_id=org_id,
        )
        collection.CASE_ROOT = case_root
        api_client = context.api_client
        readiness_manifest = context.state_path
        with VeloApiClient(
            api_client, org_id=org_id,
            query_timeout_seconds=global_args.query_timeout_seconds,
        ) as api:
            with prompt_debug.session(
                context.case_root / context.engagement_id,
                global_args.debug_chunk_prompts,
            ) as prompt_dump:
                result = await run_analysis_async(
                    api,
                    global_args,
                    policy=policy,
                    limits=limits,
                )
            if global_args.debug_chunk_prompts:
                result["debug_chunk_prompts"] = prompt_dump.summary()
        result["readiness_manifest"] = str(readiness_manifest)
        result.update(operation_log.correlation_metadata())
        progress_reporter.close(status=str(result.get("status") or "complete"))
        analysis_cli_output.emit_final_result(
            result,
            output_format=str(global_args.output_format),
        )
        if existing_only and result.get("status") not in {"complete", "completed", "prepared", "prepared_without_ai"}:
            return 2
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        operation_log.record_exception(exc, stage="host_analysis")
        progress_reporter.close(status="failed", phase="failed")
        print(str(exc), file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
