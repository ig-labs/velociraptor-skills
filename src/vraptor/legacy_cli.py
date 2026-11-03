from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from vraptor.artifacts import inventory as artifact_inventory
from vraptor.artifacts import policy_cli as artifact_policy_cli
from vraptor.artifacts import profile_cli as artifact_profile_cli
from vraptor.artifacts import schema as artifact_schema_compatibility
from vraptor.autoruns import golden as autoruns_golden
from vraptor.collect import requests as collection
from vraptor.analyze import command as collection_analysis_cli
from vraptor import query as client_query
from vraptor.artifacts import scenario_cli as detection_scenario_cli
from vraptor import readiness as engagement
from vraptor.hunt import analysis as hunt_analysis
from vraptor.hunt import command as hunt_workflow
from vraptor.hunt import operations as hunting
from vraptor.collect import hydrate as hydrate_exports
from vraptor.artifacts import linux as linux_host_profile
from vraptor.logging import operations as operation_log
from vraptor.logging import command as operation_log_cli


from vraptor.resources import resource_root
BOOTSTRAP_ROOT = resource_root() / "scripts" / "velociraptor"


@dataclass(frozen=True)
class CommandRoute:
    target: str
    strip_command: bool = False


COLLECT_COMMAND_ROUTES = {
    "analyze": CommandRoute("collection_analysis", strip_command=True),
    "check": CommandRoute("collection"),
    "ensure": CommandRoute("collection"),
    "export": CommandRoute("collection"),
    "export-registry-hunter": CommandRoute("collection"),
    "hydrate": CommandRoute("hydrate_exports", strip_command=True),
    "plan": CommandRoute("collection"),
    "poll": CommandRoute("collection"),
    "queue": CommandRoute("collection"),
    "status": CommandRoute("collection"),
}

NATIVE_HUNT_COMMANDS = frozenset(
    {
        "check",
        "download-results",
        "ensure",
        "export-results",
        "lookup",
        "profiles",
        "review-results",
        "search",
        "status",
        "stop",
    }
)

HUNT_COMMAND_ROUTES = {
    "analyze": CommandRoute("hunt_workflow"),
    "analyze-saved": CommandRoute("hunt_analysis", strip_command=True),
    "native": CommandRoute("hunting", strip_command=True),
    "retry-missing": CommandRoute("hunt_workflow"),
    "run": CommandRoute("hunt_workflow"),
    "snapshot": CommandRoute("hunt_workflow"),
    "status": CommandRoute("hunt_workflow"),
}


def invoke_route(route: CommandRoute, args: list[str]) -> int:
    forwarded = args[1:] if route.strip_command else args
    if route.target == "collection":
        return collection.main(forwarded)
    if route.target == "collection_analysis":
        return collection_analysis_cli.main(forwarded)
    if route.target == "hydrate_exports":
        return hydrate_exports.main(forwarded)
    if route.target == "hunt_analysis":
        return hunt_analysis.main(forwarded)
    if route.target == "hunt_workflow":
        return hunt_workflow.main(forwarded)
    if route.target == "hunting":
        return hunting.main(forwarded)
    raise RuntimeError(f"Unknown internal Velociraptor route target: {route.target}")


def collect_usage() -> str:
    return """Usage: vraptor collect <command> [args]

Normal analysis:
  analyze         Ensure exact flows and run flat artifact-scoped analysis

Collection operations:
  check           Check for exact prior flows
  plan            Resolve capabilities without finding or queueing flows
  ensure          Reuse exact flows or collect missing artifacts
  queue           Queue new artifact flows
  status          Refresh saved request state
  poll            Wait for a saved request
  export          Explicitly export completed results
  export-registry-hunter
                  Export curated Registry Hunter CSV views
  hydrate         Hydrate an explicit exported collection

Examples:
  vraptor collect plan --id IR1234 --client-id C.1234abcd \
    --bundle ir-standard-live
  vraptor collect analyze --id IR1234 --client-id C.1234abcd
  vraptor collect analyze --id IR1234 --client-id C.1234abcd \\
    --artifact Windows.Forensics.Prefetch --question "Was tool.exe executed?"
"""


def run_bootstrap(script_name: str, argv: list[str]) -> int:
    from .settings import current
    script = BOOTSTRAP_ROOT / script_name
    if not script.is_file():
        print(f"Velociraptor bootstrap command not found: {script}", file=sys.stderr)
        return 1
    snapshot = current()
    return subprocess.run([str(script), *argv], check=False,
                          env=dict(snapshot.environment) if snapshot else None).returncode


def _dispatch(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help", "help"}:
        print("Usage: vraptor <command> [args]; run vraptor --help for the command list.")
        return 0

    area = args.pop(0)
    if area == "setup":
        return engagement.main(args)

    if area == "config":
        if not args or args[0] in {"-h", "--help", "help"}:
            print(
                "Usage: vraptor config "
                "<fetch-api|fetch-client> [args]"
            )
            return 0
        command = args.pop(0)
        if command == "fetch-api":
            return run_bootstrap("fetch_live_api_client.sh", args)
        if command == "fetch-client":
            return run_bootstrap("fetch_live_client_config.sh", args)
        print(f"Unknown Velociraptor config command: {command}", file=sys.stderr)
        return 1

    if area == "mapped":
        if not args or args[0] in {"-h", "--help", "help"}:
            print(
                "Usage: vraptor mapped "
                "<add-remote|status> [args]"
            )
            return 0
        command = args.pop(0)
        if command == "add-remote":
            return run_bootstrap("add_remote_mapped_client.sh", args)
        if command == "status":
            return run_bootstrap("mapped_client_status.sh", args)
        print(f"Unknown Velociraptor mapped command: {command}", file=sys.stderr)
        return 1

    if area == "query":
        return client_query.main(["query", *args])

    if area == "clients":
        return client_query.main(["clients", *args])

    if area == "logs":
        return operation_log_cli.main(args)

    if area == "artifacts":
        if not args or args[0] in {"-h", "--help", "help"}:
            print(
                "Usage: vraptor artifacts "
                "<inventory|linux-plan|policy|profiles|scenarios> [args]\n"
                "       vraptor artifacts validate-schema [args]"
            )
            return 0
        command = args.pop(0)
        if command == "inventory":
            return artifact_inventory.main(args)
        if command == "linux-plan":
            return linux_host_profile.main(args)
        if command == "policy":
            return artifact_policy_cli.main(args)
        if command == "profiles":
            return artifact_profile_cli.main(args)
        if command == "scenarios":
            return detection_scenario_cli.main(args)
        if command == "validate-schema":
            return artifact_schema_compatibility.main(args)
        print(f"Unknown Velociraptor artifacts command: {command}", file=sys.stderr)
        return 1

    if area == "collect":
        if not args or args[0] in {"-h", "--help", "help"}:
            print(collect_usage())
            return 0
        command = args[0]
        route = COLLECT_COMMAND_ROUTES.get(command)
        if route is None:
            print(f"Unknown Velociraptor collect command: {command}", file=sys.stderr)
            return 1
        return invoke_route(route, args)

    if area == "autoruns":
        return autoruns_golden.main(args)

    if area == "hunt":
        if not args or args[0] in {"-h", "--help", "help"}:
            return hunt_workflow.main(["--help"])
        command = args[0]
        route = HUNT_COMMAND_ROUTES.get(command)
        if route is None:
            if command in NATIVE_HUNT_COMMANDS:
                print(f"Use: vraptor hunt native {command}", file=sys.stderr)
                return 1
            print(f"Unknown Velociraptor hunt command: {command}", file=sys.stderr)
            return 1
        if command == "native" and len(args) > 1:
            native_command = args[1]
            if (
                native_command not in NATIVE_HUNT_COMMANDS
                and native_command not in {"-h", "--help", "help"}
            ):
                print(
                    f"Unknown Velociraptor native hunt command: {native_command}",
                    file=sys.stderr,
                )
                return 1
        return invoke_route(route, args)

    print(f"Unknown Velociraptor area: {area}", file=sys.stderr)
    return 1


def _command_label(args: list[str]) -> str:
    parts = [value for value in args[:3] if value and not value.startswith("-")]
    if len(parts) >= 2 and parts[0] != "hunt":
        parts = parts[:2]
    elif len(parts) >= 2 and parts[0] == "hunt" and parts[1] != "native":
        parts = parts[:2]
    return ".".join(parts) or "velociraptor"


def _option_values(args: list[str], *names: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(args):
        item = args[index]
        matched = False
        for name in names:
            if item == name and index + 1 < len(args):
                values.append(args[index + 1])
                index += 2
                matched = True
                break
            prefix = name + "="
            if item.startswith(prefix):
                values.append(item[len(prefix) :])
                index += 1
                matched = True
                break
        if not matched:
            index += 1
    return values


def _integer_option(args: list[str], *names: str) -> int | None:
    value = operation_log.cli_option(args, *names)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _record_command_context(args: list[str]) -> None:
    """Record only allowlisted command options; never persist raw argv."""
    artifacts = _option_values(args, "--artifact")
    engagement_id = operation_log.cli_option(
        args,
        "--engagement-id",
        "--investigation-id",
        "--id",
    )
    operation_log.emit(
        "command_context",
        component="cli",
        command=_command_label(args),
        scope="hunt" if args and args[0] == "hunt" else "collection" if args and args[0] == "collect" else None,
        engagement_id=engagement_id,
        server_profile=operation_log.cli_option(args, "--server-profile"),
        client_id=operation_log.cli_option(args, "--client-id"),
        hostname=operation_log.cli_option(args, "--host", "--hostname"),
        hunt_id=operation_log.cli_option(args, "--hunt-id"),
        request_id=operation_log.cli_option(args, "--request-id"),
        artifact=artifacts[0] if len(artifacts) == 1 else "",
        artifacts="+".join(artifacts) if len(artifacts) > 1 else "",
        artifact_count=len(artifacts) if artifacts else None,
        bundle=operation_log.cli_option(args, "--bundle"),
        collection_type=operation_log.cli_option(args, "--collection-type"),
        analysis_mode=operation_log.cli_option(args, "--analysis-mode"),
        target_mode=operation_log.cli_option(args, "--target-mode"),
        timeout_seconds=_integer_option(
            args,
            "--poll-timeout-seconds",
            "--flow-timeout-seconds",
            "--timeout-seconds",
        ),
        debug=True if "--debug" in args else None,
        status="selected",
    )


def main(argv: list[str] | None = None, *, dispatch=None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    def run(args):
        operation_log.bind_cli_destination(args)
        _record_command_context(args)
        from .analyze import reporting
        return reporting.run_with_policy(args, dispatch or _dispatch)

    return operation_log.run_operation(raw_args, run)


if __name__ == "__main__":
    raise SystemExit(main())
