#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate, inspect, or export resolved Velociraptor artifact-reference profiles."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate built-in and configured site artifact references.")
    analysis_cli_arguments.add_artifact_reference_argument(validate)

    show = commands.add_parser("show", help="Show one effective artifact profile.")
    analysis_cli_arguments.add_artifact_reference_argument(show)
    show.add_argument("--artifact", required=True)

    export = commands.add_parser("export", help="Write resolved artifact profiles as JSON and CSV.")
    analysis_cli_arguments.add_artifact_reference_argument(export)
    export.add_argument("--output-dir", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        policy = artifact_policy.load_artifact_policy(args.artifact_reference)
        profiles = policy.profiles
        source_paths = policy.profile_sources
        if args.command == "show":
            profile = artifact_profiles.resolve_profile(args.artifact, profiles)
            if profile is None:
                raise RuntimeError(f"No enabled artifact profile matches {args.artifact!r}.")
            payload = {
                "artifact": args.artifact,
                "source_files": [str(path) for path in source_paths],
                "artifact_policy": policy.metadata(),
                "profile": profile,
            }
        elif args.command == "export":
            outputs = artifact_profiles.write_profile_exports(args.output_dir, profiles, source_paths)
            payload = {
                "status": "ok",
                "profile_count": len(profiles),
                "source_files": [str(path) for path in source_paths],
                "artifact_policy": policy.metadata(),
                "output_files": outputs,
            }
        else:
            payload = {
                "status": "ok",
                "profile_count": len(profiles),
                "source_files": [str(path) for path in source_paths],
                "artifact_policy": policy.metadata(),
                "profile_hashes": {
                    name: profile.get("_profile_hash", "")
                    for name, profile in sorted(profiles.items())
                },
            }
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
