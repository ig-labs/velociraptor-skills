"""Read accepted candidates or synthesize them without collection/chunk execution."""

from __future__ import annotations

import argparse
import asyncio
import copy
import inspect
import json
import re
import time
from pathlib import Path

from vraptor.agent.config import analyst_execution_identity
from vraptor.agent.factory import create_agent_runner
from vraptor.analyze import (
    checkpoints,
    cli_output,
    model_options,
    recovery,
    runtime,
    summary,
    synthesis,
)
from vraptor.common import atomic_io
from vraptor.common.clock import now_utc
from vraptor.common.hashing import sha256_file
from vraptor.logging import operations
from vraptor.paths import add_case_root_arg, resolve_case_root
from vraptor.resources import repository_root


def resolve_checkpoint(args) -> Path:
    if args.checkpoint:
        return Path(args.checkpoint).expanduser().resolve()
    if not args.investigation_id:
        raise ValueError("--id is required with --request-id or --hunt")
    for value in (args.investigation_id, args.hunt_id, args.request_id):
        if value and (
            value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._-]+", value)
        ):
            raise ValueError("Use an exact investigation, hunt or request ID")
    root = resolve_case_root(args.case_root, repository_root()) / args.investigation_id
    if args.hunt_id:
        paths = list(
            (root / "hunts").glob(f"{args.hunt_id}/analysis/hunt-analysis-state.json")
        )
    else:
        paths = list(
            (root / "systems").glob(
                f"*/collection/requests/{args.request_id}/analysis/request-analysis.json"
            )
        )
        if args.client_id:
            paths = [
                p
                for p in paths
                if json.loads(p.read_text()).get("client_id") == args.client_id
            ]
    if len(paths) != 1:
        raise ValueError(
            "Expected one saved checkpoint; specify --checkpoint or an exact client/request"
        )
    return paths[0]


def load_accepted(path: Path) -> tuple[dict, list[dict], dict]:
    saved = json.loads(path.read_text())
    if "artifact_summaries" in saved:
        if not checkpoints.request_checkpoint_valid(saved):
            raise ValueError("Saved request checkpoint failed integrity validation")
        artifacts, plans = [], []
        for item in saved["artifact_summaries"]:
            report = Path(str(item.get("report_file") or ""))
            if not report.is_file() or sha256_file(report) != item.get("report_sha256"):
                raise ValueError("Accepted artifact report is missing or changed")
            result = item.get("accepted_result") or item.get("result")
            if result:
                artifacts.append(copy.deepcopy(result))
            plans.append(item.get("plan_summary") or {})
        plan = dict(plans[0]) if plans else {}
        plan.update(
            scope_type="host",
            task_mode=saved.get("task_mode", "host_forensics"),
            response_depth=saved.get("response_depth", "standard"),
            time_filter=saved.get("time_filter", {}),
            artifacts=[a for p in plans for a in p.get("artifacts", [])],
            collection_failures=[
                f for p in plans for f in p.get("collection_failures", [])
            ],
        )
    elif isinstance(saved.get("checkpoint"), dict):
        checkpoint = saved.get("partial_candidates") or saved["checkpoint"]
        accepted = checkpoint.get("accepted_result")
        if (
            accepted is None
            and dict(checkpoint.get("result") or {}).get("review_status")
            == "not_requested"
        ):
            accepted = checkpoint["result"]
        if not isinstance(accepted, dict):
            raise ValueError(
                "This older hunt checkpoint has no retained preliminary candidates; no analysis was rerun"
            )
        if checkpoint.get("accepted_fingerprint") != synthesis.fingerprint(accepted):
            raise ValueError("Saved hunt candidates failed integrity validation")
        accepted = copy.deepcopy(accepted)
        accepted.setdefault("artifact", "hunt-evidence")
        for finding in accepted.get("findings", []):
            for row in finding.get("evidence", []):
                row.setdefault("chunk_index", 0)
                row.setdefault("chunk_count", 1)
        artifacts = [accepted]
        plan = {
            "scope_type": "hunt",
            "task_mode": saved.get("task_mode", "targeted_hunt"),
            "response_depth": saved.get("response_depth", "standard"),
            "time_filter": saved.get("time_filter", {}),
            "collection_failures": [],
        }
    else:
        raise ValueError("Expected a saved host request or hunt analysis checkpoint")
    if not artifacts:
        raise ValueError(
            "No accepted artifact candidates are available; no analysis was rerun"
        )
    return saved, artifacts, plan


async def summarize(
    path: Path, *, execution, limits, execute=None, force=False, progress=None
) -> dict:
    started = time.monotonic()
    started_at = now_utc()
    original = path.read_bytes()
    saved, artifacts, plan = load_accepted(path)
    question = str(saved.get("question") or artifacts[0].get("question") or "").strip()
    if not question:
        raise ValueError("Saved analysis has no original question")
    plan.update(analysis_limits=limits.as_dict(), synthesis_mode="full")
    key = synthesis.cache_key(
        results=artifacts,
        question=question,
        plan=plan,
        execution=analyst_execution_identity(execution),
    )
    cached = (
        None
        if force
        else synthesis.cached_result(saved.get("synthesis_cache") or {}, key)
    )
    diagnostics_path = path.parent / "synthesis-diagnostics.json"
    diagnostics = {
        "schema_version": 1,
        "scope": "saved_synthesis",
        "operation_id": operations.current_operation_id(),
        "started_at": started_at,
        "completed_at": None,
        "status": "running",
        "reused": cached is not None,
        "provider": execution.route.provider,
        "model": execution.route.model,
        "correction_settings": {
            "synthesis_correction_attempts": limits.synthesis_correction_attempts,
        },
        "retention": "latest_synthesis_without_source_values_or_model_output",
        "provider_calls": [],
        "model_calls": 0,
        "tasks": [],
        "omitted_task_count": 0,
    }

    def persist_diagnostics(status, *, completed=False):
        diagnostics["status"] = status
        diagnostics["updated_at"] = now_utc()
        if completed:
            diagnostics["completed_at"] = now_utc()
            diagnostics["elapsed_seconds"] = round(time.monotonic() - started, 3)
        atomic_io.write_json_atomic(diagnostics_path, diagnostics, sort_keys=True)

    def publish_summary(result, *, model_calls=0):
        from vraptor.analyze.report_command import render_saved_report
        from vraptor.analyze.report_publication import publish_report

        report = path.parent / "synthesis-summary.md"
        publish_report(report, render_saved_report(
            result, checkpoint=path, checkpoint_hash=sha256_file(path), scope=plan["scope_type"],
            model_calls=model_calls,
        ))
        return str(report)

    persist_diagnostics("running")
    if cached is not None:
        operations.emit("synthesis_cache_hit", stage="synthesis", status="complete")
        try:
            if path.read_bytes() != original:
                diagnostics["error_category"] = "checkpoint_changed"
                raise RuntimeError("Checkpoint changed during synthesis; accepted analysis was left untouched")
            report = publish_summary(cached)
        except Exception:
            diagnostics.setdefault("error_category", "report_publication_failed")
            persist_diagnostics("failed", completed=True)
            raise
        persist_diagnostics(cached["status"], completed=True)
        return {
            "status": cached["status"],
            "reused": True,
            "model_calls": 0,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "analysis_result": cached,
            "checkpoint": str(path),
            "report": report,
            "diagnostics_file": str(diagnostics_path),
            **operations.correlation_metadata(),
        }
    runner = None
    attempt_results = {}
    attempt_records = {}
    if execute is None:
        try:
            runner = create_agent_runner(
                execution,
                limits=runtime.limits_from_plan(plan),
                persist_runtime_files=False,
            )
        except Exception:
            diagnostics["error_category"] = "runner_initialization_failed"
            persist_diagnostics("failed", completed=True)
            raise

        async def execute(task):
            return await runner.run(
                task,
                workdir=path.parent,
                output_dir=path.parent,
                progress_callback=(
                    lambda event: progress(cli_output.agent_event_progress(event))
                )
                if progress
                else None,
            )

    def record_progress(event):
        task_id, attempt = event.get("task_id"), event.get("attempt")
        if task_id and attempt and event.get("status") in {"accepted", "retrying", "failed"}:
            key = (task_id, attempt)
            if key in attempt_records or len(attempt_records) < 200:
                attempt_records[key] = {
                    "attempt": attempt,
                    "status": event["status"],
                    "diagnostics": event.get("diagnostics") or [],
                    "run": attempt_results.get(key, {}),
                }
                diagnostic = recovery.task_diagnostics({
                    "task_id": task_id, "stage": event.get("phase"),
                    "status": "accepted" if event["status"] == "accepted" else "failed",
                    "attempts": attempt,
                    "attempt_history": [value for (identifier, _), value in attempt_records.items()
                                        if identifier == task_id],
                })
                diagnostics["tasks"] = [t for t in diagnostics["tasks"] if t["task_id"] != task_id]
                diagnostics["tasks"].append(diagnostic)
                persist_diagnostics("running")
        if progress is not None:
            progress(event)

    async def recording_execute(task):
        call = {
            "task_id": task.task_id,
            "attempt": task.metadata.get("attempt", 1),
            "stage": task.metadata.get("stage", "synthesis"),
            "started_at": now_utc(),
            "completed_at": None,
            "status": "running",
        }
        if len(diagnostics["provider_calls"]) < 200:
            diagnostics["provider_calls"].append(call)
        else:
            diagnostics["omitted_provider_call_count"] = diagnostics.get("omitted_provider_call_count", 0) + 1
        diagnostics["model_calls"] += 1
        persist_diagnostics("running")
        try:
            value = execute(task)
            result = await value if inspect.isawaitable(value) else value
            call["status"] = result.status
            call["provider"] = result.provider or execution.route.provider
            call["model"] = result.model or execution.route.model
            if len(attempt_results) < 200:
                attempt_results[(task.task_id, call["attempt"])] = {
                    "status": result.status, "output": result.output,
                    "elapsed_seconds": result.elapsed_seconds,
                    "attempt_count": result.attempt_count,
                    "error_classification": result.error_classification,
                }
            return result
        except BaseException as exc:
            call["status"] = "interrupted" if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt)) else "failed"
            raise
        finally:
            call["completed_at"] = now_utc()
            persist_diagnostics("running")

    try:
        run = await runtime.execute_host_synthesis_from_artifact_results_async(
            plan=plan,
            artifact_results=artifacts,
            question=question,
            execute=recording_execute,
            progress_callback=record_progress,
        )
        tasks = list(run.get("tasks") or [])
        selected = sorted(tasks, key=lambda task: task.get("status") != "failed")
        diagnostics["tasks"] = [recovery.task_diagnostics(task) for task in selected[:200]]
        diagnostics["omitted_task_count"] = max(0, len(tasks) - 200)
        diagnostics["model_calls"] = sum(int(t.get("attempts", 0)) for t in tasks)
        result = summary.discard_full_rows(run["host_result"])
        # Never overwrite analysis that changed while a model was running.
        if path.read_bytes() != original:
            diagnostics["error_category"] = "checkpoint_changed"
            raise RuntimeError(
                "Checkpoint changed during synthesis; accepted analysis was left untouched"
            )
        saved["synthesis_cache"] = synthesis.cache_record(result, key, source_identity=synthesis.source_fingerprint(
            artifacts, question=question, scope=plan["scope_type"], plan=plan
        ))
        if "checkpoint_fingerprint" in saved:
            saved["checkpoint_fingerprint"] = checkpoints.request_checkpoint_fingerprint(saved)
        atomic_io.write_json_atomic(path, saved, sort_keys=True)
        report = publish_summary(result, model_calls=diagnostics["model_calls"])
        persist_diagnostics(result["status"], completed=True)
        return {
            "status": result["status"],
            "reused": False,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "model_calls": diagnostics["model_calls"],
            "analysis_result": result,
            "checkpoint": str(path),
            "report": str(report),
            "diagnostics_file": str(diagnostics_path),
            **operations.correlation_metadata(),
        }
    except BaseException as exc:
        diagnostics["error_category"] = diagnostics.get("error_category", "synthesis_execution_failed")
        status = "interrupted" if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt)) else "failed"
        persist_diagnostics(status, completed=True)
        raise
    finally:
        if runner is not None:
            await runner.close()



def main(argv=None, *, results_only=False) -> int:
    parser = argparse.ArgumentParser(
        prog="vraptor analysis-results" if results_only else "vraptor summarize",
        description=(
            "Read accepted candidates without inference."
            if results_only
            else "Synthesize saved candidates only; never recollect or rerun chunk analysis."
        ),
    )
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--checkpoint", type=Path)
    sources.add_argument("--request-id")
    sources.add_argument("--hunt", "--hunt-id", dest="hunt_id")
    parser.add_argument("--id", "--investigation-id", dest="investigation_id")
    parser.add_argument("--client", "--client-id", dest="client_id")
    parser.add_argument(
        "--server-profile",
        help="Use saved profile defaults; no server connection is made.",
    )
    add_case_root_arg(parser)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    if results_only:
        parser.add_argument("--offset", type=int, default=0)
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument("--evidence-offset", type=int, default=0)
        parser.add_argument("--context-offset", type=int, default=0)
        for name in ("artifact", "host", "candidate", "reference"):
            parser.add_argument("--" + name, default="")
    else:
        parser.add_argument(
            "--force-synthesis",
            action="store_true",
            help="Regenerate an otherwise reusable summary; accepted analysis stays unchanged.",
        )
        model_options.add_arguments(parser)
        parser.add_argument("--no-progress", action="store_true")
    args = parser.parse_args(argv)
    path = resolve_checkpoint(args)
    if results_only:
        saved, artifacts, plan = load_accepted(path)
        result = (
            artifacts[0]
            if plan["scope_type"] == "hunt"
            else synthesis.preliminary(
                artifacts, question=saved.get("question", ""), scope=plan["scope_type"]
            )
        )
        payload = synthesis.page(
            result,
            **{
                k: getattr(args, k)
                for k in (
                    "offset",
                    "limit",
                    "artifact",
                    "host",
                    "candidate",
                    "reference",
                    "evidence_offset",
                    "context_offset",
                )
            },
        )
        payload.update(
            checkpoint=str(path),
            question=result["question"],
            limitations=result["limitations"][:20],
            group_count=len(result.get("groups", [])),
        )
        if saved.get("detectraptor_stack"):
            payload["context_ledger"] = saved["detectraptor_stack"].get(
                "interesting_context_file", ""
            )
    else:
        execution, limits = model_options.resolve(args)
        if args.investigation_id:
            operations.bind_case(
                resolve_case_root(args.case_root, repository_root()),
                args.investigation_id,
            )
        reporter = cli_output.ProgressReporter(
            scope="synthesis", scope_id=path.parent.name, enabled=not args.no_progress
        )
        reporter.start(
            phase="synthesis",
            provider=execution.route.provider,
            model=execution.route.model,
            reasoning_effort=execution.route.reasoning_effort,
        )
        status = "failed"
        try:
            payload = asyncio.run(
                summarize(
                    path,
                    execution=execution,
                    limits=limits,
                    force=args.force_synthesis,
                    progress=reporter.update,
                )
            )
            status = payload["status"]
        finally:
            reporter.close(status=status)
    if args.format == "json" or results_only:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(summary.render_chat_summary(payload["analysis_result"]))
        print(f"Model calls: {payload['model_calls']}; reused: {payload['reused']}")
        print(f"Diagnostics: {payload['diagnostics_file']}")
    return 0 if payload.get("status") == "complete" else 2
