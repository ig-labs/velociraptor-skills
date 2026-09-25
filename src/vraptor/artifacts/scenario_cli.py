#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import scenarios as detection_scenarios
from vraptor.artifacts import detectraptor as detectraptor_contract


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate, inspect, search, or export resolved Velociraptor "
            "detection scenarios."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser(
        "validate",
        help="Validate built-in and configured detection-scenario references.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(validate)

    list_cmd = commands.add_parser("list", help="List enabled detection scenarios.")
    analysis_cli_arguments.add_policy_reference_arguments(list_cmd)

    show = commands.add_parser("show", help="Show one effective detection scenario.")
    analysis_cli_arguments.add_policy_reference_arguments(show)
    show.add_argument("--scenario", required=True)

    artifact = commands.add_parser(
        "for-artifact",
        help="List enabled detection scenarios that use an artifact.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(artifact)
    artifact.add_argument("--artifact", required=True)

    export = commands.add_parser(
        "export",
        help="Write resolved detection scenarios as JSON and CSV.",
    )
    analysis_cli_arguments.add_policy_reference_arguments(export)
    export.add_argument("--output-dir", required=True)
    return parser.parse_args(argv)


def summary_row(scenario_id: str, scenario: dict[str, object]) -> dict[str, object]:
    bindings = list(scenario.get("artifacts") or [])
    return {
        "scenario_id": scenario_id,
        "title": scenario.get("title", ""),
        "objective": scenario.get("objective", ""),
        "tactics": scenario.get("tactics", []),
        "question_shapes": scenario.get("question_shapes", []),
        "artifacts": [
            {
                "artifact": item.get("artifact", ""),
                "role": item.get("role", ""),
            }
            for item in bindings
            if isinstance(item, dict)
        ],
        "scenario_hash": scenario.get("_scenario_hash", ""),
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        policy = artifact_policy.load_artifact_policy(
            args.artifact_reference,
            args.scenario_reference,
        )
        profiles = policy.profiles
        profile_sources = policy.profile_sources
        detectraptor_validation = (
            detectraptor_contract.validate_contract_profiles(profiles)
        )
        scenarios = policy.scenarios
        scenario_sources = policy.scenario_sources

        if args.command == "show":
            scenario = detection_scenarios.resolve_scenario(
                args.scenario,
                scenarios,
            )
            if scenario is None:
                raise RuntimeError(
                    f"No enabled detection scenario matches {args.scenario!r}."
                )
            payload = {
                "scenario_id": args.scenario,
                "artifact_profile_sources": [
                    str(path) for path in profile_sources
                ],
                "detectraptor_contract_validation": detectraptor_validation,
                "scenario_sources": [str(path) for path in scenario_sources],
                "artifact_policy": policy.metadata(),
                "scenario": scenario,
            }
        elif args.command == "for-artifact":
            matches = detection_scenarios.scenarios_for_artifact(
                args.artifact,
                scenarios,
            )
            payload = {
                "artifact": args.artifact,
                "scenario_count": len(matches),
                "artifact_policy": policy.metadata(),
                "scenarios": [
                    summary_row(scenario_id, scenario)
                    for scenario_id, scenario in matches
                ],
            }
        elif args.command == "export":
            outputs = detection_scenarios.write_scenario_exports(
                args.output_dir,
                scenarios,
                scenario_sources,
            )
            payload = {
                "status": "ok",
                "scenario_count": len(scenarios),
                "artifact_profile_sources": [
                    str(path) for path in profile_sources
                ],
                "detectraptor_contract_validation": detectraptor_validation,
                "scenario_sources": [str(path) for path in scenario_sources],
                "artifact_policy": policy.metadata(),
                "output_files": outputs,
            }
        elif args.command == "list":
            payload = {
                "scenario_count": len(scenarios),
                "artifact_policy": policy.metadata(),
                "scenarios": [
                    summary_row(scenario_id, scenario)
                    for scenario_id, scenario in sorted(scenarios.items())
                    if scenario.get("enabled", True)
                ],
            }
        else:
            payload = {
                "status": "ok",
                "scenario_count": len(scenarios),
                "artifact_profile_sources": [
                    str(path) for path in profile_sources
                ],
                "detectraptor_contract_validation": detectraptor_validation,
                "scenario_sources": [str(path) for path in scenario_sources],
                "artifact_policy": policy.metadata(),
                "scenario_hashes": {
                    scenario_id: scenario.get("_scenario_hash", "")
                    for scenario_id, scenario in sorted(scenarios.items())
                },
            }
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
