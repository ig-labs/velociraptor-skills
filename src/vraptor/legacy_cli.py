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


from vraptor.resources import repository_root, resource_root
BOOTSTRAP_ROOT = resource_root() / "scripts" / "velociraptor"


@dataclass(frozen=True)
class CommandRoute:
    target: str
    strip_command: bool = False
    lifecycle: str = "canonical"
    replacement: str = ""


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

# Retain compatibility routes until all callers use the explicit native namespace.
# Replacements are recorded here and checked by the CLI tests.
HUNT_COMMAND_ROUTES = {
    "analyze": CommandRoute("hunt_workflow"),
    "analyze-saved": CommandRoute("hunt_analysis", strip_command=True),
    "check": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native check",
    ),
    "download-results": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native download-results",
    ),
    "ensure": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native ensure",
    ),
    "export-results": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native export-results",
    ),
    "lookup": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native lookup",
    ),
    "native": CommandRoute("hunting", strip_command=True),
    "profiles": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native profiles",
    ),
    "retry-missing": CommandRoute("hunt_workflow"),
    "review-results": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native review-results",
    ),
    "run": CommandRoute("hunt_workflow"),
    "search": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native search",
    ),
    "snapshot": CommandRoute("hunt_workflow"),
    "status": CommandRoute("hunt_workflow"),
    "stop": CommandRoute(
        "hunting",
        lifecycle="compatibility",
        replacement="hunt native stop",
    ),
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


def usage() -> str:
    return """Usage: dfir <area> <command> [args]

Areas:
  setup       Prepare/verify local, remote dead-disk, or live readiness
  config      Resolve a server or fetch API/client configuration
  mapped      Add or inspect remote dead-disk mapped clients
  query       Execute bounded VQL through an engagement API client
  clients     Find or list clients with name, OS, label, and online filters
  artifacts   Inventory or manage artifact profiles, Linux plans, and scenarios
  autoruns    Create, update, publish, query, or remove Autoruns GoldenDB entries
  collect     Queue, monitor, explicitly export, or hydrate host collections
  hunt        Run, inspect, analyze, retry missing clients, review, or snapshot hunts
  logs        Show/follow progress or inspect local operation status

Global logging options (accepted anywhere):
  --log-level debug|info|warning|error
  --log-file PATH
  --no-log-file

Set VELO_PROGRESS_FILE_DEBUG=true to retain verbose DEBUG lines in the file.
Analysis --debug also enables them for that command.
Sanitized Velociraptor server messages and numeric progress are logged at INFO.
Credential values are redacted; operational text may include evidence context.

Examples:
  dfir setup live-remote --server-profile lab7 --engagement-id ir1234 --server-ip 192.0.2.10
  dfir mapped add-remote --api-client FILE --client-config FILE disk.E01
  dfir mapped status --client disk01 --json
  dfir query --server-profile lab7 --vql "SELECT * FROM clients() LIMIT 10"
  dfir clients find --server-profile lab7 --name host01
  dfir clients list --server-profile lab7 --label ir1234
  dfir artifacts inventory --server-profile lab7 --output-dir DIR
  dfir artifacts policy show
  dfir artifacts linux-plan --inventory FILE --mode standard
  dfir artifacts scenarios list
  dfir autoruns inspect
  dfir autoruns filter --manifest /path/to/collection-export.json
  dfir collect plan --engagement-id IR1234 --server-profile lab7 --client-id C.1234abcd --bundle ir-standard-live
  dfir collect analyze --engagement-id IR1234 --server-profile lab7 --client-id C.1234abcd
  dfir collect analyze --engagement-id IR1234 --server-profile lab7 --client-id C.1234abcd --artifact Windows.Forensics.Prefetch --question "Was the executable run?"
  dfir collect ensure --engagement-id IR1234 --server-profile lab7 --host host01 --collection-type all
  dfir hunt run --engagement-id IR1234 --server-profile lab7 --profile detectraptor --question "Find compromise leads"
  dfir hunt analyze --engagement-id IR1234 --server-profile lab7 --hunt-id H.1234
  dfir hunt retry-missing --id IR1234 --hunt-id H.1234 --after-hours 24
  dfir hunt native ensure --target linux --artifact Linux.Sys.Users
  dfir hunt analyze-saved --state-file /path/to/state.json
"""


def collect_usage() -> str:
    return """Usage: dfir collect <command> [args]

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
  dfir collect plan --id IR1234 --client-id C.1234abcd \
    --bundle ir-standard-live
  dfir collect analyze --id IR1234 --client-id C.1234abcd
  dfir collect analyze --id IR1234 --client-id C.1234abcd \\
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
        print(usage())
        return 0

    area = args.pop(0)
    if area == "setup":
        return engagement.main(args)

    if area == "config":
        if not args or args[0] in {"-h", "--help", "help"}:
            print(
                "Usage: dfir config "
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
                "Usage: dfir mapped "
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
                "Usage: dfir artifacts "
                "<inventory|linux-plan|policy|profiles|scenarios> [args]\n"
                "       dfir artifacts validate-schema [args]"
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


def _option_value(args: list[str], *names: str) -> str:
    for index, item in enumerate(args):
        for name in names:
            if item == name and index + 1 < len(args):
                return args[index + 1]
            prefix = name + "="
            if item.startswith(prefix):
                return item[len(prefix) :]
    return ""


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
    value = _option_value(args, *names)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _record_command_context(args: list[str]) -> None:
    """Record only allowlisted command options; never persist raw argv."""
    artifacts = _option_values(args, "--artifact")
    engagement_id = _option_value(
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
        server_profile=_option_value(args, "--server-profile"),
        client_id=_option_value(args, "--client-id"),
        hostname=_option_value(args, "--host", "--hostname"),
        hunt_id=_option_value(args, "--hunt-id"),
        request_id=_option_value(args, "--request-id"),
        artifact=artifacts[0] if len(artifacts) == 1 else "",
        artifacts="+".join(artifacts) if len(artifacts) > 1 else "",
        artifact_count=len(artifacts) if artifacts else None,
        bundle=_option_value(args, "--bundle"),
        collection_type=_option_value(args, "--collection-type"),
        analysis_mode=_option_value(args, "--analysis-mode"),
        target_mode=_option_value(args, "--target-mode"),
        timeout_seconds=_integer_option(
            args,
            "--poll-timeout-seconds",
            "--flow-timeout-seconds",
            "--timeout-seconds",
        ),
        debug=True if "--debug" in args else None,
        status="selected",
    )


def _bind_default_log(args: list[str]) -> None:
    if not args or args[0] not in {"setup", "collect", "hunt", "autoruns", "analyze", "export"}:
        return
    engagement_id = _option_value(
        args,
        "--engagement-id",
        "--investigation-id",
        "--id",
    )
    if not engagement_id:
        engagement_id = _option_value(args, "--server-profile")
    if not engagement_id:
        return
    case_root_arg = _option_value(args, "--case-root") or None
    from vraptor.paths import resolve_case_root

    case_root = resolve_case_root(case_root_arg, repository_root())
    operation_log.bind_case(case_root, engagement_id)


def main(argv: list[str] | None = None, *, dispatch=None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        args, log_options = operation_log.extract_global_options(raw_args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    with operation_log.OperationLogger(
        _command_label(args),
        options=log_options,
    ) as logger:
        _bind_default_log(args)
        _record_command_context(args)
        try:
            result = (dispatch or _dispatch)(args)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as exc:
            operation_log.record_exception(exc, stage="dispatch")
            raise
        logger.finalize(
            status="complete" if result == 0 else "failed",
            exit_code=result,
        )
        return result


if __name__ == "__main__":
    raise SystemExit(main())
