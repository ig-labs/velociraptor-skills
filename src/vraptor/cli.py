"""Short, lazy CLI over the shared operational workflows."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys

from .resources import repository_root, resource_root

HELP = """Usage: vraptor <command> [args]

Commands: query, clients, artifacts, collect, analyze, summarize, analysis-results, hunt, export,
          ai, tools prep, setup, config, mapped, autoruns, logs

analyze selects exactly one existing source: --flow (with --client/--host),
--request-id (with --client/--host), --hunt, or --from (hunt snapshot manifest).
It never collects, retries clients, uploads GoldenDB or publishes business state.
Existing case paths and --id/--case-root/--server-profile remain supported.
Use --server as a connection-profile alias; --profile selects analysis behavior.
dfir is an equivalent entrypoint. Use setup init --id ID once to prepare a folder.
To configure AI, run vraptor ai setup; agent is a compatible alias.
Inspect settings with config or ai config; both accept --view effective|defaults.
Use --grpc-max-message-bytes to override the shared API transport limit.
Use each command's --help for its supported options.
"""


def _aliases(args, command="query"):
    aliases = {"--server": "--server-profile", "--client": "--client-id", "--hunt": "--hunt-id", "--request": "--request-id", "--file": "--vql-file"}
    if command != "query":
        aliases.pop("--file")
    return [aliases.get(arg.partition("=")[0], arg.partition("=")[0]) + ("=" + arg.partition("=")[2] if "=" in arg else "") for arg in args]


def _has(args, name):
    return any(arg == name or arg.startswith(name + "=") for arg in args)


def analyze(args):
    from .results import operation_policy
    if args in ([], ["--help"], ["-h"]):
        import argparse
        from .analyze import cli_arguments, model_options

        print(HELP)
        parser = argparse.ArgumentParser(
            prog="vraptor analyze", add_help=False,
            usage="vraptor analyze SOURCE [options]",
            epilog="Select a source and add --help for the full host or hunt options.",
        )
        model_options.add_arguments(parser)
        cli_arguments.add_synthesis_argument(parser)
        print(parser.format_help())
        return 0
    hunt = _has(args, "--hunt-id")
    snapshot = _has(args, "--from")
    flow = _has(args, "--flow") or _has(args, "--flow-id")
    request = _has(args, "--request-id")
    if sum((hunt, snapshot, flow, request)) != 1:
        raise ValueError("analyze requires exactly one of --flow, --request-id, --hunt or --from")
    forbidden = ("--force-run", "--retry-missing-after-hours", "--retry-max-attempts", "--retry-batch-size", "--autoruns-golden-sync", "--group")
    if any(_has(args, flag) for flag in forbidden):
        raise ValueError("analyze does not accept collection, retry, group or upload options")
    if (hunt or snapshot) and (_has(args, "--client-id") or _has(args, "--host")):
        raise ValueError("Client selectors cannot be combined with --hunt or --from")
    with operation_policy(existing_only=True):
        if hunt or snapshot:
            from vraptor.hunt import command as hunt_workflow
            forwarded = [arg.replace("--from", "--snapshot", 1) if arg.partition("=")[0] == "--from" else arg for arg in args]
            if "--json" in forwarded:
                forwarded.remove("--json")
                forwarded += ["--format", "json"]
            return hunt_workflow.main(["analyze", *forwarded], existing_only=True)
        from vraptor.analyze import command as collection_analysis_cli
        if "--json" in args:
            args = [a for a in args if a != "--json"] + ["--format", "json"]
        return asyncio.run(collection_analysis_cli.async_main(args, existing_only=True))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["agent"]:
        args[0] = "ai"
    try:
        if args[:1] == ["config"] and (len(args) == 1 or args[1].startswith("-") or args[1] == "help"):
            from .settings import config_main
            return config_main(["--help"] if args[1:] == ["help"] else _aliases(args[1:], "config"))
        if args[:1] == ["setup"] and (len(args) == 1 or args[1] in {"--help", "-h"}):
            print("Usage: vraptor setup <configure|show|migrate|export|deploy|reset|start|status|resume|stop|init|local-deaddisk|remote-deaddisk|live-remote> [args]")
            print("Use start for guided three-mode setup; existing mode commands retain their lower-level interfaces.")
            print("Use configure in a terminal to save operational settings and optionally open AI setup.")
            print("To configure AI separately, run: vraptor ai setup (agent is also accepted).")
            return 0
        if args[:1] == ["setup"] and len(args) > 1:
            if args[1] in {"export", "deploy", "reset"}:
                from .setup_config import main as transfer
                return transfer(_aliases(args[1:], "setup"))
            if args[1] in {"configure", "show", "migrate"}:
                from .settings import main as configure
                return configure(_aliases(args[1:], "setup"))
            if args[1] in {"start", "status", "resume", "stop"}:
                from .setup import main as setup
                return setup(_aliases(args[1:], "setup"))
        # Offline snapshot validation must work without local credentials or
        # a usable connection configuration, just like the former utility.
        if args[:2] == ["artifacts", "validate-schema"]:
            from .artifacts.schema import main as validate_schema
            return validate_schema(args[2:])
        defaults_view = args[:2] == ["ai", "config"] and (
            "--view=defaults" in args or any(args[i:i + 2] == ["--view", "defaults"] for i in range(len(args))))
        if args and not defaults_view and not any(arg in {"-h", "--help", "help"} for arg in args):
            import argparse
            from . import settings
            selectors = argparse.ArgumentParser(add_help=False)
            selectors.add_argument("--settings-file")
            selectors.add_argument("--server", "--server-profile", dest="server_profile")
            selectors.add_argument("--case-root")
            selectors.add_argument("--api-client")
            selectors.add_argument("--org-id")
            selectors.add_argument("--grpc-max-message-bytes", type=int)
            selected, _ = selectors.parse_known_args(args)
            # Consume shared settings/transport selectors; forward operation flags.
            forwarded, skip = [], False
            for arg in args:
                if skip:
                    skip = False
                elif arg in {"--settings-file", "--grpc-max-message-bytes"}:
                    skip = True
                elif not arg.startswith(("--settings-file=", "--grpc-max-message-bytes=")):
                    forwarded.append(arg)
            try:
                snapshot = settings.resolve(selected.server_profile, vars(selected), selected.settings_file)
            except (RuntimeError, ValueError, OSError) as exc:
                if forwarded[:2] != ["setup", "init"]:
                    raise
                from .workspace import main as initialize
                return initialize(forwarded[2:], configuration_error=type(exc).__name__)
            with settings.activate(snapshot):
                return _main(forwarded)
        return _main(args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 1


def _main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"--help", "-h", "help"}:
        print(HELP)
        return 0
    command, args = args[0], (args[1:] if args[0] == "mapped" else _aliases(args[1:], args[0]))
    try:
        if command in {"summarize", "analysis-results"}:
            from .analyze import saved
            return saved.main(args, results_only=command == "analysis-results")
        if command == "case":
            raise ValueError("Case management was removed. Use setup init --id ID, then setup and analysis commands.")
        if command == "velociraptor":
            raise ValueError("The velociraptor namespace was removed. Use dfir <command> or vraptor <command>.")
        if command == "setup" and args[:1] == ["init"]:
            from vraptor.workspace import main as initialize
            return initialize(args[1:])
        if command == "ai":
            if not args or args[0] in {"--help", "-h"}:
                print("""Usage: vraptor ai <command> [options]

Configure and inspect
  setup    Create or update a named AI profile (interactive or CLI flags).
  config   Show effective settings and their sources, or application defaults.
  doctor   Check configuration and dependencies without inference.

Authentication and live checks
  login    Sign in through the native Codex or Claude Code CLI.
  models   Read model metadata online; Claude reports native login status.
  test     Send one small synthetic request (may incur usage).

Setup examples
  vraptor ai setup --from-harness codex
  vraptor ai setup --from-harness claude_code
  vraptor ai setup --provider openai
  vraptor ai setup --provider anthropic --model MODEL_ID

Inspect a profile
  vraptor ai config --execution-profile NAME
  vraptor ai config --view defaults
  vraptor ai doctor --execution-profile NAME

Use vraptor ai <command> --help for grouped options.
The agent alias is supported; ai is the preferred command.""")
                return 0
            subcommand = args.pop(0)
            if subcommand in {"setup", "doctor", "models", "test", "login"}:
                from vraptor.agent.manage import main as manage_main
                return manage_main(subcommand, args)
            if subcommand != "config":
                raise ValueError("Unknown AI command; use ai --help")
            from vraptor.agent.command import main as config_main
            return config_main(args)
        if command == "tools":
            if not args or args[0] in {"--help", "-h"}:
                print("Usage: vraptor tools prep [args]")
                return 0
            if args.pop(0) != "prep":
                raise ValueError("Unknown tools command; use tools prep")
            from . import settings
            active = settings.current()
            env = dict(active.environment if active else os.environ, AI_SKILLS_REPO_ROOT=str(repository_root()))
            return subprocess.run(["bash", str(resource_root() / "scripts/prep_dfir_tools.sh"), *args], env=env, check=False).returncode
        if command == "analyze":
            from vraptor import legacy_cli as legacy
            return legacy.main(["analyze", *args], dispatch=lambda selected: analyze(selected[1:]))
        if command in {"query", "clients"}:
            from vraptor import query as client_query
            if command == "clients" and (not args or args[0].startswith("--")):
                args.insert(0, "find" if _has(args, "--name") else "list")
            from vraptor.logging import operations as operation_log
            forwarded, options = operation_log.extract_global_options([command, *args])
            with operation_log.OperationLogger(command, options=options) as logger:
                status = client_query.main(forwarded)
                logger.finalize(status="complete" if status == 0 else "failed", exit_code=status)
                return status
        from vraptor import legacy_cli as legacy
        if command == "collect" and (not args or args[0].startswith("--")):
            args.insert(0, "ensure")
        if command == "export":
            return legacy.main(["collect", "export", *args])
        return legacy.main([command, *args])
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
