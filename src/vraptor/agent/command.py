#!/usr/bin/env python3
"""Print the resolved analyst provider configuration without secret values."""

from __future__ import annotations

import argparse
import json

from vraptor.agent import cli as agent_cli
from vraptor.analyze import limits as analysis_limits
from vraptor.agent.config import resolve_agent_execution


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vraptor ai config",
        usage="%(prog)s [options]",
        description=(
            "Explain effective or code-default analyst routing, limits, route "
            "mapping, and credential references without secret values."
        )
    )
    agent_cli.add_agent_config_arguments(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cli_values = agent_cli.agent_config_cli_values(args)
    if args.view == "defaults":
        if cli_values:
            parser.error(
                "--view defaults cannot be combined with effective-route overrides"
            )
        payload = agent_cli.application_defaults_payload()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    try:
        execution = resolve_agent_execution(
            cli_values=cli_values,
            allow_missing_credentials=True,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    limits = analysis_limits.resolve_analysis_limits(execution=execution)
    if execution.route.model_context_tokens or execution.route.model_max_output_tokens:
        limits = limits.for_execution(execution)
    payload = agent_cli.agent_configuration_payload(
        execution,
        limits,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
