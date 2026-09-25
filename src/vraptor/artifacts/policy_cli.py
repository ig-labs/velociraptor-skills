#!/usr/bin/env python3
"""Validate, inspect, and export one resolved artifact-policy snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from vraptor.common import atomic_io
from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.artifacts import scenarios as detection_scenarios


DIFF_EXIT_CODE = 3


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve artifact profiles and detection scenarios as one immutable, "
            "content-addressed operation policy."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate", "Validate the complete effective policy."),
        ("show", "Show effective policy metadata and ordered provenance."),
    ):
        child = commands.add_parser(command, help=help_text)
        analysis_cli_arguments.add_policy_reference_arguments(child)
    explain = commands.add_parser(
        "explain",
        help="Show one resolved artifact profile or detection scenario.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(explain)
    subject = explain.add_mutually_exclusive_group(required=True)
    subject.add_argument("--artifact")
    subject.add_argument("--scenario")
    diff = commands.add_parser(
        "diff",
        help="Compare effective policy content with a portable policy export.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(diff)
    diff.add_argument("--against", required=True)
    diff.add_argument(
        "--check",
        action="store_true",
        help=f"Exit {DIFF_EXIT_CODE} when policy content differs.",
    )
    export = commands.add_parser(
        "export",
        help="Write a portable resolved policy JSON document.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(export)
    export.add_argument("--output", required=True)
    return parser.parse_args(argv)


def compact_metadata(
    snapshot: artifact_policy.ArtifactPolicySnapshot,
) -> dict[str, Any]:
    metadata = snapshot.metadata()
    return {
        key: metadata[key]
        for key in (
            "schema_version",
            "sha256",
            "profile_sha256",
            "scenario_sha256",
            "profile_count",
            "scenario_count",
        )
    }


def read_portable_export(path: str | Path) -> tuple[Path, dict[str, Any]]:
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Policy export {source} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Policy export {source} is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Policy export {source} must be a JSON object.")
    for key in ("artifact_policy", "profiles", "scenarios"):
        if not isinstance(payload.get(key), dict):
            raise RuntimeError(
                f"Policy export {source} must contain an object named {key!r}."
            )
    artifact_policy.validate_portable_document(payload, source=source)
    return source, payload


def catalog_diff(
    current: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> dict[str, Any]:
    current_names = set(current)
    previous_names = set(previous)
    shared = current_names & previous_names
    changed = sorted(
        name
        for name in shared
        if artifact_policy.canonical_sha256(current[name])
        != artifact_policy.canonical_sha256(previous[name])
    )
    return {
        "added": sorted(current_names - previous_names),
        "removed": sorted(previous_names - current_names),
        "changed": changed,
        "unchanged_count": len(shared) - len(changed),
    }


def diff_payload(
    snapshot: artifact_policy.ArtifactPolicySnapshot,
    previous: Mapping[str, Any],
    *,
    source: Path,
) -> dict[str, Any]:
    current = snapshot.resolved_document()
    profiles = catalog_diff(current["profiles"], previous["profiles"])
    scenarios = catalog_diff(current["scenarios"], previous["scenarios"])
    previous_metadata = dict(previous["artifact_policy"])
    identity_changed = (
        str(previous_metadata.get("sha256") or "") != snapshot.policy_sha256
    )
    different = identity_changed or any(
        profiles[key] or scenarios[key]
        for key in ("added", "removed", "changed")
    )
    return {
        "status": "different" if different else "identical",
        "different": different,
        "identity_changed": identity_changed,
        "against_file": str(source),
        "current_policy": compact_metadata(snapshot),
        "against_policy": {
            key: previous_metadata.get(key)
            for key in (
                "schema_version",
                "sha256",
                "profile_sha256",
                "scenario_sha256",
                "profile_count",
                "scenario_count",
            )
        },
        "profiles": profiles,
        "scenarios": scenarios,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        snapshot = artifact_policy.load_artifact_policy(
            args.artifact_reference,
            args.scenario_reference,
        )
        exit_code = 0
        if args.command == "export":
            output = Path(args.output).expanduser().resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            atomic_io.write_json_atomic(
                output,
                snapshot.resolved_document(),
                sort_keys=True,
            )
            payload = {
                "status": "ok",
                "artifact_policy": snapshot.metadata(),
                "portable_export": True,
                "output_file": str(output),
            }
        elif args.command == "validate":
            payload = {
                "status": "ok",
                "artifact_policy": compact_metadata(snapshot),
            }
        elif args.command == "show":
            payload = {
                "status": "ok",
                "artifact_policy": snapshot.metadata(),
            }
        elif args.command == "explain" and args.artifact:
            profile = artifact_profiles.resolve_profile(
                args.artifact,
                snapshot.profiles,
            )
            if profile is None:
                raise RuntimeError(
                    f"No enabled artifact profile matches {args.artifact!r}."
                )
            payload = {
                "status": "ok",
                "kind": "artifact_profile",
                "requested_name": args.artifact,
                "artifact_policy": snapshot.metadata(),
                "profile": profile,
            }
        elif args.command == "explain":
            scenario = detection_scenarios.resolve_scenario(
                args.scenario,
                snapshot.scenarios,
            )
            if scenario is None:
                raise RuntimeError(
                    f"No enabled detection scenario matches {args.scenario!r}."
                )
            payload = {
                "status": "ok",
                "kind": "detection_scenario",
                "requested_name": args.scenario,
                "artifact_policy": snapshot.metadata(),
                "scenario": scenario,
            }
        elif args.command == "diff":
            source, previous = read_portable_export(args.against)
            payload = diff_payload(snapshot, previous, source=source)
            if args.check and payload["different"]:
                exit_code = DIFF_EXIT_CODE
        else:
            raise RuntimeError(f"Unsupported artifact policy command: {args.command}")
        print(json.dumps(payload, indent=2, sort_keys=False))
        return exit_code
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
