"""Standalone investigation initialization; no connection or global selection."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from itertools import chain
from pathlib import Path

from vraptor.case_layout import safe_component
from vraptor.paths import expand_home_path, read_dotenv_file, resolve_case_root
from vraptor.resources import repository_root


def configuration_checks() -> dict:
    """Report local configuration health without printing values or connecting."""
    from vraptor.agent import manage

    dotenv = []
    for source, path in (
        ("shared", Path.home() / ".codex" / ".env"),
        ("repository", repository_root() / ".env"),
    ):
        entry = {"source": source, "path": str(path)}
        try:
            values = read_dotenv_file(path)
            entry.update(status="loaded" if path.is_file() else "missing", key_count=len(values))
        except (OSError, UnicodeError):
            entry.update(status="unreadable")
        dotenv.append(entry)
    try:
        analyst, status = asyncio.run(manage.inspect_or_test("doctor", manage.parser_for("doctor").parse_args([])))
        if not analyst["configuration"]["execution"]["effective"]["enabled"]:
            analyst["issues"].append("Analyst execution is disabled by configuration.")
            analyst["status"], status = "disabled", 1
    except (RuntimeError, ValueError, OSError) as exc:
        # Resolver/parser exceptions can contain literal configuration values.
        analyst = {
            "status": "needs_configuration", "error_type": type(exc).__name__,
            "issues": ["Could not resolve analyst configuration; run dfir ai doctor for details."],
            "authentication": "not_checked", "inference": "not_tested",
        }
        status = 1
    needs_attention = bool(status) or any(item["status"] == "unreadable" for item in dotenv)
    return {
        "status": "needs_attention" if needs_attention else "ready",
        "mode": "offline", "dotenv": dotenv, "analyst_agent": analyst,
        "next_step": "Review dfir ai doctor; use dfir ai setup to configure the analyst." if needs_attention else "",
    }


def initialize(investigation_id: str, case_root: Path, investigation_dir: str | None = None) -> dict:
    identity = safe_component(investigation_id, label="investigation id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", identity):
        raise ValueError("Investigation ID must contain only letters, digits, dot, underscore or hyphen.")
    root = case_root.expanduser().resolve()
    directory = Path(investigation_dir).expanduser().resolve() if investigation_dir else (root / identity).resolve()
    if not investigation_dir and directory.parent != root:
        raise ValueError("Investigation folder resolves outside the selected case root.")
    if directory.name != identity or directory.parent.name == identity:
        raise ValueError("Investigation folder must end in the exact --id, without a duplicated nested ID.")
    # A named folder is authoritative: never redirect another investigation's commands.
    state = directory / "engagement.json"
    if state.exists():
        payload = json.loads(state.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or str(payload.get("engagement_id", "")).casefold() != identity.casefold():
            raise ValueError("Existing engagement.json belongs to a different investigation or has no identity.")
    created = not directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    guidance = directory / "AGENTS.md"
    guidance_created = False
    try:
        with guidance.open("x", encoding="utf-8") as output:
            output.write(
                f'# Investigation {identity}\n'
                '\n'
                'At session start, inspect `engagement.json` and reuse valid readiness; run `velociraptor-engagement-setup` only when missing, invalid, or affected by connection/credential/mapping changes or failures.\n'
                'Check shared/repository .env sources and effective analyst configuration once per session before analysis; reuse successful initialization/doctor checks already performed in this session.\n'
                "Repeat setup or `dfir ai doctor` only after relevant changes or failures, not before each collection. Keep the CLI's automatic per-operation identity, credential and target validation enabled.\n"
                f"Pass `--id {identity!r} --case-root {str(directory.parent)!r}` to operational commands.\n"
                '`dfir` and `vraptor` are equivalent. There is no global current investigation.\n'
                'Keep concurrent workstreams scoped to this folder and distinct hosts, hunts or requests.\n'
                'Reuse engagement.json, host/hunt reports and accepted checkpoints before acquiring evidence.\n'
                'Velociraptor is authoritative for server evidence; export raw evidence only when requested.\n'
                '`analyze` uses existing evidence; `collect analyze` may obtain missing collections.\n'
                'Keep credentials in the configured credential store, never in this folder.\n'
                'Preserve exact provenance, coverage gaps and uncertainty in findings.\n'
                '\n'
                '## Default collection and analysis behavior\n'
                '\n'
                'Requests to run a collection group or investigate a host imply collection/reuse through analysis and final review.\n'
                'Honor explicit collection-only, planning, no-AI, and existing-evidence-only scope; setup or inventory alone does not start an investigation.\n'
                'Use `collect analyze` for the combined workflow; successful `collect ensure` output alone does not complete it.\n'
                'Analyze terminal artifacts while remaining collections run. Continue monitoring during other work.\n'
                'Before ending a turn with unfinished work, verify an available, authorized continuation mechanism carrying the exact case, client, request and checkpoint paths.\n'
                'If none is available, keep monitoring in the active task or report a concrete blocker and exact resume command; never promise unarranged monitoring.\n'
                'Resume the saved request after polling timeouts, preserving accepted analysis and avoiding duplicate runners or replacement collections.\n'
                'Verify the analysis checkpoint, final-review outcome and coverage before reporting completion; distinguish partial, failed and prepared-only results.\n'
                'Honor explicit stop/pause requests. Follow `velociraptor-collection` and `velociraptor-host-analysis` for command and recovery details.\n'
                '\n'
                '## Analysis intent and efficiency\n'
                '\n'
                '- Infer intent from the request: `targeted-hunt` for cross-host IOC/behavior searches, `host-forensics` for one-machine investigation, `incident-response` for incident scope, or `compromise-assessment` for environment discovery. Ask only when unclear; retain the choice for follow-ups unless scope changes.\n'
                "- Choose response depth independently: `rapid`, `standard`, or `deep`. Honor explicit depth; otherwise use the selected workflow's default. Route cross-host work to `velociraptor-hunting` and machine analysis to `velociraptor-host-analysis`.\n"
                '- Read existing `systems/<host>/analysis-host.md`, `hunts/<hunt-id>/analysis-hunt.md` and accepted checkpoints first. Reuse valid accepted work through supported resume commands; analyze only new, changed or unresolved evidence when checkpoint/source identity permits.\n'
                '- Choose the smallest artifact scope that answers the question. Use source-native projection, filtering and stacking where supported before detailed review; preserve source references and report unreviewed coverage. Apply time bounds only when requested and supported by the artifact.\n'
                '- Let the canonical runtime own artifact/chunk scheduling. Keep one owner per host/hunt request and avoid duplicate queries, collections or analysis runners. Do not manually recreate its worker pool.\n'
                '- Keep cumulative Markdown findings and compact provenance as local memory; let the owning workflow update its reports. Keep bulk evidence on Velociraptor unless export is requested.\n'
                '\n'
                '## Bounded specialist delegation\n'
                '\n'
                '- The primary agent owns scope, coordination, synthesis and closure. Use subagents when independent work can progress in parallel, such as separate hosts, hunt hypotheses, saved-evidence review, CTI enrichment or an audit of findings. Small sequential tasks do not require delegation.\n'
                '- Give each subagent an exact question, case path, host/hunt/request IDs, evidence references, permitted actions, owned outputs and expected result. Delegation does not expand collection, export or external-service authorization.\n'
                '- Reuse established engagement readiness and successful session analyst checks. Repeat setup only when the delegated target or connection requires it; retain automatic CLI validation.\n'
                "- Assign non-overlapping work and one writer/coordinator per host or hunt request. Subagents return findings and provenance to that owner; they must not overwrite another agent's reports or accepted state.\n"
                '- Use available specialist roles: `hunt-agent` for cross-host searches, `investigation-agent` for one host or lead, `analyst-agent` for read-only evidence review, `collection-agent` for bounded acquisition, `cti-agent` for enrichment, and `audit-agent` for claims and coverage review. Use `setup-agent` for readiness recovery. If roles or delegation are unavailable, perform the bounded work locally.\n'
                '- Do not manually spawn artifact/chunk analysts around `collect analyze`; the canonical runtime owns that analyst pool. Delegate distinct investigations or specialist questions, not duplicate artifact analysis.\n'
                '- Track delegated work through completion or a concrete blocker. Review returned evidence, coverage, contradictions and unresolved work before merging results and declaring completion; honor stop requests across owned workers.\n'
                '\n'
                '## Findings and closure\n'
                '\n'
                '- Show collection dates separately from analysis completion and identify reused evidence. Unknown dates stay unknown; collection dates do not establish the event period or current host state. For incomplete work, show the blocker and exact saved-request resume command after checking existing runner/monitor ownership.\n'
                '- For incident response and host forensics, publish findings relevant to the question, scope, chronology, impact or recovery. Keep other actionable uncertainty as bounded leads.\n'
                '- For standalone hunts, include relevant suspicious behavior, exposure and control gaps even without confirmed compromise; label them accurately.\n'
                '- Separate facts, supported findings, hypotheses, security concerns and informational context. Consider benign explanations; presence, rarity or a control weakness alone does not prove execution or compromise.\n'
                '- Retain exact provenance and distinguish target execution from result-review coverage. Empty, failed, partial and unreviewed evidence are not clean results. Verify final review before closure and retain the next bounded action for unresolved leads.\n'
            )
            guidance_created = True
    except FileExistsError:
        pass
    outputs = []
    truncated = False
    patterns = (
        "engagement.json", "hunts/*/analysis-hunt.md",
        "hunts/*/analysis/hunt-analysis-state.json", "systems/*/analysis-host.md",
        "systems/*/host-analysis-state.json", "systems/*/collection/requests/*/state.json",
        "systems/*/collection/requests/*/analysis/request-analysis.json",
    )
    for path in chain.from_iterable(directory.glob(pattern) for pattern in patterns):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory):
            continue
        if len(outputs) == 500:
            truncated = True
            break
        outputs.append(str(path.relative_to(directory)))
    return {
        "status": "initialized" if created else "reused",
        "investigation_id": identity, "investigation_dir": str(directory),
        "case_root": str(directory.parent), "guidance_created": guidance_created,
        "existing_outputs": sorted(outputs), "outputs_truncated": truncated,
        "readiness_checked": False,
        "next_step": "Use setup live-remote, local-deaddisk or remote-deaddisk to verify Velociraptor readiness.",
    }


def main(argv=None, *, configuration_error=None):
    parser = argparse.ArgumentParser(description="Create or reuse an investigation folder and check local environment/analyst configuration offline.")
    parser.add_argument("--id", "--investigation-id", "--engagement-id", dest="investigation_id", required=True)
    parser.add_argument("--case-root", help="Investigations parent; defaults to CASE_ROOT or ~/cases.")
    parser.add_argument("--investigation-dir", help="Explicit folder ending in the exact investigation ID.")
    args = parser.parse_args(argv)
    if args.case_root and args.investigation_dir:
        directory = Path(args.investigation_dir).expanduser().resolve()
        if directory.parent != Path(args.case_root).expanduser().resolve():
            parser.error("--investigation-dir must be directly under --case-root when both are supplied")
    case_root = (
        expand_home_path(args.case_root or os.environ.get("CASE_ROOT") or Path.home() / "cases").resolve()
        if configuration_error else resolve_case_root(args.case_root, repository_root())
    )
    result = initialize(args.investigation_id, case_root, args.investigation_dir)
    result["configuration_checks"] = configuration_checks()
    if configuration_error:
        checks = result["configuration_checks"]
        checks["status"] = "needs_attention"
        checks["settings"] = {
            "status": "needs_configuration", "error_type": configuration_error,
            "issues": ["Could not load operational settings; run dfir setup show to diagnose configuration."],
        }
        checks["analyst_agent"]["issues"].append(
            "Operational settings were unavailable; selected analyst credential sources could not be verified."
        )
        checks["next_step"] = "Repair operational settings with dfir setup show, then rerun setup init."
    print(json.dumps(result, indent=2))
    return 0
