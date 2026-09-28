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
from vraptor.resources import repository_root, resource_root


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
    if not guidance.exists():
        template = resource_root() / "templates" / "investigation-agents.md"
        content = (
            template.read_text(encoding="utf-8")
            .replace("{{investigation_id}}", identity)
            .replace("{{investigation_id_arg}}", repr(identity))
            .replace("{{case_root_arg}}", repr(str(directory.parent)))
        )
        try:
            with guidance.open("x", encoding="utf-8") as output:
                output.write(content)
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
