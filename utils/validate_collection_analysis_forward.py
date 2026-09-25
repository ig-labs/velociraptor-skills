#!/usr/bin/env python3
"""Run controlled saved-request collection-analysis forward validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from vraptor.analyze.forward import run_saved_request_forward_validation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay and validate an existing Velociraptor collection request. "
            "This harness never launches a new collection."
        )
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--case-root", type=Path, required=True)
    parser.add_argument("--investigation-id", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-client", type=Path)
    parser.add_argument("--org-id")
    parser.add_argument("--poll-interval-seconds", type=float, default=0.5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_saved_request_forward_validation(
            repo_root=args.repo_root.resolve(),
            case_root=args.case_root.resolve(),
            investigation_id=args.investigation_id,
            hostname=args.hostname,
            client_id=args.client_id,
            request_id=args.request_id,
            question=args.question,
            output=args.output.resolve(),
            api_client=args.api_client.resolve() if args.api_client else None,
            org_id=args.org_id,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
