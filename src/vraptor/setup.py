"""Three setup journeys over shared settings, lifecycle and readiness checks."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

from . import readiness, readiness_state, settings, workspace
from .case_layout import safe_component
from .resources import resource_root

MODES = {"live-remote": "live_remote", "remote-deaddisk": "remote_dead_disk",
         "local-deaddisk": "local_dead_disk"}
SAVED = ("mode", "engagement_id", "case_root", "server_profile", "api_client",
         "client_config", "evidence_path", "hostname", "client_id", "host_label",
         "exclude_host_label", "environment_only_ok", "workspace", "velociraptor_bin",
         "api_role_profile", "org_id", "local_server_workspace", "local_server_options", "mapping_id", "evidence_type")
SHARED = ("mode", "engagement_id", "case_root", "server_profile", "api_client",
          "client_config", "velociraptor_bin", "api_role_profile", "org_id",
          "local_server_workspace", "local_server_options")


def mapping_records(payload):
    if "mappings" in payload:
        return dict(payload["mappings"])
    if payload.get("mode") in {"local_dead_disk", "remote_dead_disk"} and payload.get("setup"):
        return {"default": payload}
    return {}


def publish_setup(path, payload, mapping_id=None, records=None):
    """Atomically retain every mapping while publishing conservative case readiness."""
    if not mapping_id:
        readiness_state.publish(path, payload)
        return
    if records is None:
        records = mapping_records(readiness_state.load(path)) if path.exists() else {}
    records[mapping_id] = payload
    aggregate = {**payload, "mappings": records,
                 "setup": {key: value for key, value in payload.get("setup", {}).items() if key in SHARED}}
    states = {record.get("status") for record in records.values()}
    fingerprint = readiness_state.engagement_fingerprint(payload)
    consistent = all(record.get("api") == payload.get("api")
                     and readiness_state.engagement_fingerprint(record) == fingerprint
                     for record in records.values())
    if states == {"ready"} and consistent:
        aggregate["status"] = "ready"
    elif states == {"stopped"}:
        aggregate["status"] = "stopped"
    else:
        aggregate["status"] = "needs_attention"
    targets = [target for record in records.values()
               for target in record.get("readiness", {}).get("targets", [])]
    aggregate["readiness"] = {**payload.get("readiness", {}), "targets": targets,
                              "matched_client_count": len(targets)}
    aggregate["readiness"].pop("mapped_client", None)
    aggregate["engagement_fingerprint"] = readiness_state.engagement_fingerprint(aggregate)
    readiness_state.publish(path, aggregate)


def select_mapping(args, case):
    if not case:
        return {}
    records = mapping_records(case)
    if not args.mapping_id and "mappings" not in case:
        return case
    if not args.mapping_id:
        if len(records) != 1:
            raise ValueError("Select --mapping-id for this investigation: " + ", ".join(sorted(records)))
        args.mapping_id = next(iter(records))
    if args.mapping_id in records:
        return records[args.mapping_id]
    if args.action != "start":
        raise ValueError("Unknown --mapping-id; use setup start to add a mapping.")
    # A new host inherits only the common connection/server, never another image.
    return {key: value for key, value in case.items() if key not in
            {"mappings", "readiness", "status", "setup"}} | {
        "setup": {key: value for key, value in case.get("setup", {}).items() if key in SHARED}}


@contextmanager
def investigation_lock(directory):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".setup.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Setup is already running for this investigation.") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def parser():
    result = argparse.ArgumentParser(description="Start, inspect, resume or stop an investigation's managed local resources.")
    result.add_argument("action", choices=("start", "resume", "status", "stop"))
    result.add_argument("--id", "--engagement-id", "--investigation-id", dest="engagement_id")
    result.add_argument("--mode", choices=tuple(MODES))
    result.add_argument("--mapping-id", help="Stable host mapping name within a shared investigation")
    from .export_mapping import TYPES
    result.add_argument("--evidence-type", choices=TYPES)
    for flag in ("settings-file", "case-root", "server-profile", "api-client", "client-config",
                 "evidence-path", "hostname", "client-id", "workspace", "velociraptor-bin",
                 "server-ip", "api-user", "ssh-user", "ssh-key", "run-as", "org-id"):
        result.add_argument("--" + flag)
    result.add_argument("--api-role-profile", choices=("investigation", "provisioning-admin"))
    for flag in ("startup-timeout-seconds", "ready-timeout-seconds", "grpc-max-message-bytes"):
        result.add_argument("--" + flag, type=int)
    result.add_argument("--host-label", action="append")
    result.add_argument("--exclude-host-label", action="append")
    for flag in ("environment-only-ok", "fetch-config", "provision-api", "provision-client",
                 "force", "regenerate-remote-api", "stop-server"):
        result.add_argument("--" + flag, action="store_true", default=None)
    return result


def _required(args, name, prompt):
    if getattr(args, name, None):
        return
    if sys.stdin.isatty():
        setattr(args, name, input(prompt + ": ").strip())
    if not getattr(args, name, None):
        raise ValueError(f"Missing --{name.replace('_', '-')}")


def _scope(args):
    selections = (bool(args.hostname), bool(args.client_id),
                  bool(args.host_label or args.exclude_host_label), bool(args.environment_only_ok))
    if sum(selections) != 1:
        raise ValueError("Select one live scope: --hostname, --client-id, --host-label, or --environment-only-ok.")


def _check_binding(previous, args, metadata=None):
    if not previous:
        return
    if previous.get("engagement_id") != args.engagement_id:
        raise ValueError("Existing readiness belongs to a different investigation.")
    profile = previous.get("connection", {}).get("server_profile")
    if profile and profile != args.server_profile:
        raise ValueError("Existing investigation is bound to another server profile.")
    if previous.get("mode") and previous["mode"] != MODES[args.mode]:
        raise ValueError("Existing investigation is bound to another setup mode.")
    saved = previous.get("setup", {})
    bound_fields = ("evidence_path", "workspace", "local_server_workspace", "org_id")
    if args.mode != "live-remote":
        bound_fields += ("hostname",)
    for name in bound_fields:
        expected = saved.get(name)
        if expected and expected != getattr(args, name, None):
            raise ValueError(f"Existing investigation has a different {name}; preserve it or select another investigation.")
    if args.api_client and Path(args.api_client).is_file() and previous.get("server"):
        metadata = metadata if metadata is not None else readiness_state.api_metadata(Path(args.api_client))
        if metadata["server_fingerprint"] != previous["server"].get("fingerprint"):
            raise ValueError("API configuration points to a different server or organization.")
        if metadata["identity"] != previous.get("api", {}).get("identity"):
            raise ValueError("API configuration selects a different credential identity.")


def _acquire(args, snapshot, previous):
    """Validate fetched credentials before replacing any existing local files."""
    with ExitStack() as cleanup:
        candidates = argparse.Namespace(**vars(args))
        replacements = []
        _fetch(args, snapshot, candidates, replacements, cleanup)
        if not replacements:
            return
        try:
            metadata = readiness.validate_api_client_security(Path(candidates.api_client))
        except (RuntimeError, ValueError, OSError):
            raise ValueError("Fetched API configuration failed credential validation; existing files were preserved.") from None
        if args.api_user and args.api_user != metadata["identity"]:
            raise ValueError("Fetched API configuration has a different identity; existing files were preserved.")
        _check_binding(previous, candidates, metadata)
        if args.mode != "live-remote":
            def client_identity(path):
                try:
                    config = yaml.safe_load(Path(path).read_text())["Client"]
                    return config["ca_certificate"], config.get("nonce", "")
                except (OSError, yaml.YAMLError, KeyError, TypeError):
                    raise ValueError("Invalid endpoint configuration; existing files were preserved.") from None
            identity = client_identity(candidates.client_config)
            api_config = yaml.safe_load(Path(candidates.api_client).read_text())
            if identity[0] != api_config.get("ca_certificate"):
                raise ValueError("API and endpoint configurations belong to different servers.")
            if candidates.client_config != args.client_config and Path(args.client_config).is_file():
                if identity != client_identity(args.client_config):
                    raise ValueError("Endpoint server/enrollment identity changed; existing files were preserved.")
        for staged, destination in replacements:
            staged.replace(destination)


def _fetch(args, snapshot, candidates, replacements, cleanup):
    """Only explicit fetch/provision requests may enter SSH helpers."""
    needs_client = args.mode != "live-remote"
    needed = [("api_client", "fetch_live_api_client.sh", args.provision_api)]
    if needs_client:
        needed.append(("client_config", "fetch_live_client_config.sh", args.provision_client))
    for field, script, provision in needed:
        path = Path(getattr(args, field))
        refresh = bool(args.force or (field == "api_client" and args.regenerate_remote_api))
        if path.is_file() and not refresh:
            continue
        if not (args.fetch_config or provision or args.regenerate_remote_api):
            if sys.stdin.isatty():
                supplied = input(f"Existing {field.replace('_', ' ')} YAML path: ").strip()
                if supplied:
                    path = Path(supplied).expanduser().resolve()
                    setattr(args, field, str(path))
                    setattr(candidates, field, str(path))
                    if path.is_file():
                        continue
            raise ValueError(f"Missing {field.replace('_', ' ')}: supply existing YAML or explicitly select --fetch-config.")
        if not args.server_ip:
            raise ValueError("Credential acquisition requires --server-ip or a configured connection address.")
        path.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix=".setup-", dir=path.parent))) / path.name
        setattr(candidates, field, str(staged))
        command = ["bash", str(resource_root() / "scripts/velociraptor" / script),
                   "--server-profile", args.server_profile, "--server-ip", args.server_ip,
                   "--output-path", str(staged), "--json-out", str(staged.with_suffix(".status.json"))]
        if field == "api_client":
            command += ["--api-role-profile", args.api_role_profile]
            if args.regenerate_remote_api:
                command.append("--regenerate-remote-api")
        if refresh:
            command.append("--force")
        if provision:
            command.append("--provision-api" if field == "api_client" else "--provision-client")
        completed = subprocess.run(command, env=dict(snapshot.environment), capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL)
        if completed.returncode == 3:
            manifest = staged.with_suffix(".status.json")
            manual = json.loads(manifest.read_text()) if manifest.is_file() else {}
            instructions = manual.get("instructions") if manual.get("status") == "needs_user_action" else None
            if not isinstance(instructions, str):
                raise RuntimeError("Remote credential setup requires manual user action; rerun the fetch helper for instructions.")
            if sys.stdin.isatty():
                print(instructions, flush=True)
                if input("Configuration ready? Continue [y/N]: ").strip().lower() in {"y", "yes"}:
                    completed = subprocess.run(command, env=dict(snapshot.environment), capture_output=True,
                                               text=True, stdin=subprocess.DEVNULL)
            if completed.returncode == 3:
                raise RuntimeError(instructions + "\nPaused for user confirmation; retry the same setup command after Continue.")
        if completed.returncode:
            # Helpers may include deployment or credential-bearing native errors.
            raise RuntimeError(f"{script} failed (exit {completed.returncode}); check the selected host, SSH access and provisioning options.")
        replacements.append((staged, path))


def start(args, snapshot, previous, state_path, *, records=None):
    from . import lifecycle
    if args.mode not in MODES:
        raise ValueError("Unknown setup mode.")
    if args.mapping_id and args.mode == "live-remote":
        raise ValueError("--mapping-id applies only to dead-disk setup.")
    args.server_profile = args.server_profile or ("local" if args.mode == "local-deaddisk" else args.engagement_id)
    safe_component(args.server_profile, label="server profile")
    if args.mode == "live-remote":
        if not any((args.hostname, args.client_id, args.host_label, args.environment_only_ok)) and sys.stdin.isatty():
            _required(args, "hostname", "Live hostname")
        _scope(args)
    else:
        _required(args, "evidence_path", "Windows image or mounted Windows directory")
        args.evidence_path = str(Path(args.evidence_path).expanduser().resolve())
        if not Path(args.evidence_path).exists():
            raise ValueError("Evidence path does not exist.")
    runtime_override = snapshot.values.get("runtime_root")
    runtime = Path(runtime_override) if runtime_override else state_path.parent / "runtime/velociraptor"
    if args.mode != "live-remote":
        mapping_default = runtime / "mappings" / args.engagement_id if runtime_override else runtime / "mapping"
        if args.mapping_id:
            mapping_default = (runtime / "mappings" / args.engagement_id / args.mapping_id
                               if runtime_override else runtime / "mappings" / args.mapping_id)
        args.workspace = str(Path(args.workspace).expanduser().resolve()) if args.workspace else str(mapping_default)
    local_workspace = getattr(args, "local_server_workspace", None)
    if args.mode == "local-deaddisk" and (local_workspace or not args.api_client):
        local_workspace = local_workspace or str(runtime / "servers" / args.server_profile if runtime_override else runtime / "server")
        args.api_client = str(Path(local_workspace) / "api_client.yaml")
        args.client_config = str(Path(local_workspace) / "client.config.yaml")
    args.local_server_workspace = local_workspace
    cache = Path(snapshot.values["config_root"])
    args.api_client = args.api_client or str(cache / f"{args.server_profile}_api_client.yaml")
    args.client_config = args.client_config or str(cache / f"{args.server_profile}_client.config.yaml")
    for name in ("api_client", "client_config"):
        setattr(args, name, str(Path(getattr(args, name)).expanduser().resolve()))
    if args.mode != "live-remote":
        outputs = [Path(args.workspace)]
        if local_workspace:
            outputs.append(Path(local_workspace))
        for name, provision in (("api_client", args.provision_api), ("client_config", args.provision_client)):
            path = Path(getattr(args, name))
            if (args.fetch_config or provision or args.regenerate_remote_api) and (
                not path.is_file() or args.force or (name == "api_client" and args.regenerate_remote_api)
            ):
                outputs.append(path)
        lifecycle.validate_output_paths(Path(args.evidence_path), *outputs)
        from .export_mapping import detect
        args.evidence_type = detect(Path(args.evidence_path), args.evidence_type or "auto")
    args.api_role_profile = args.api_role_profile or "provisioning-admin"
    if local_workspace and not getattr(args, "local_server_options", None):
        args.local_server_options = {name: snapshot.values.get(name, default) for name, default in
                                    (("frontend_port", 8000), ("api_port", 8001), ("gui_port", 8889))}
        args.local_server_options["api_user"] = snapshot.values.get("local_api_user", "vraptor")
    _check_binding(previous, args)
    if args.mapping_id:
        for name, record in (records or {}).items():
            if name == args.mapping_id:
                continue
            other = record.get("setup", {})
            if other.get("workspace") == args.workspace:
                raise ValueError("Each mapping requires a separate workspace.")
            if args.hostname and str(other.get("hostname") or "").casefold() == args.hostname.casefold():
                raise ValueError("Each mapping requires a distinct hostname.")
    workspace.initialize(args.engagement_id, Path(args.case_root))
    intent = {name: getattr(args, name, None) for name in SAVED}
    preparing = {**previous, "engagement_id": args.engagement_id, "status": "preparing",
                 "mode": MODES[args.mode], "connection": {"server_profile": args.server_profile}, "setup": intent}
    publish_setup(state_path, preparing, args.mapping_id, records)
    try:
        if local_workspace:
            local = lifecycle.ensure_local_server(Path(local_workspace), args.velociraptor_bin,
                                                  **args.local_server_options)
            args.api_client, args.client_config = str(local["api_client"]), str(local["client_config"])
        else:
            _acquire(args, snapshot, previous)
        _check_binding(previous, args)
        if args.mode == "live-remote":
            args.manifest_out = None
            payload = readiness.command_live_remote(args)
        else:
            readiness.validate_api_client_security(Path(args.api_client))
            mapping = lifecycle.ensure_mapping(Path(args.evidence_path), Path(args.api_client), Path(args.client_config),
                                               Path(args.workspace), args.velociraptor_bin, hostname=args.hostname,
                                               evidence_type=args.evidence_type)
            payload = readiness.verify_mapped_readiness(args, mapping, Path(args.api_client), mode=MODES[args.mode])
        payload["setup"] = {name: getattr(args, name, None) for name in SAVED}
        readiness.publish_mapped_system_state(args, payload)
        publish_setup(state_path, payload, args.mapping_id, records)
        return {**payload, "engagement_state_file": str(state_path)}
    except (OSError, ValueError, RuntimeError):
        preparing["status"] = "needs_attention"
        publish_setup(state_path, preparing, args.mapping_id, records)
        raise


def main(argv=None):
    args = parser().parse_args(argv)
    _required(args, "engagement_id", "Investigation ID")
    safe_component(args.engagement_id, label="investigation id")
    if args.mapping_id:
        safe_component(args.mapping_id, label="mapping id")
    snapshot = settings.resolve(args.server_profile, vars(args), args.settings_file,
                                require_credentials=args.action not in {"status", "stop"})
    args.case_root = snapshot.values["case_root"]
    directory = Path(args.case_root) / args.engagement_id
    state_path = directory / "engagement.json"
    if args.action != "start" and not state_path.is_file():
        raise ValueError("No saved setup; use setup start first.")
    case = readiness_state.load(state_path) if state_path.is_file() else {}
    saved_setup = select_mapping(args, case).get("setup", {})
    if args.action in {"start", "resume"}:
        args.mode = args.mode or saved_setup.get("mode")
        _required(args, "mode", "Mode (local-deaddisk, remote-deaddisk, live-remote)")
        if args.mode != "live-remote":
            args.evidence_path = args.evidence_path or saved_setup.get("evidence_path")
            _required(args, "evidence_path", "Windows image or mounted Windows directory")
    evidence = args.evidence_path or saved_setup.get("evidence_path")
    if evidence:
        from .lifecycle import validate_output_paths
        validate_output_paths(Path(evidence), directory)
    with investigation_lock(directory):
        case = readiness_state.load(state_path) if state_path.exists() else {}
        previous = select_mapping(args, case)
        records = mapping_records(case) if args.mapping_id else None
        for name, value in previous.get("setup", {}).items():
            if name in SAVED and getattr(args, name, None) is None:
                setattr(args, name, value)
        if args.action == "resume" and not previous.get("setup"):
            raise ValueError("Older readiness remains usable; run setup start with explicit connection/evidence inputs to adopt it.")
        # Resolve a named connection only after saved selectors have been restored.
        profile = args.server_profile or ("local" if args.mode == "local-deaddisk" else args.engagement_id)
        snapshot = snapshot.select(profile, vars(args))
        snapshot.apply(args)
        # Every mapping in a case uses the same server/organization/API identity.
        if args.action in {"start", "resume"} and args.mapping_id and case:
            binding = {key: value for key, value in case.items() if key != "setup"}
            _check_binding(binding, args)
        with settings.activate(snapshot):
            if args.action in {"start", "resume"}:
                result = start(args, snapshot, previous, state_path, records=records)
            else:
                from . import lifecycle
                saved = previous.get("setup", {})
                mapping_path = saved.get("workspace") if previous.get("mode") != "live_remote" else None
                server_path = saved.get("local_server_workspace")
                if args.action == "stop":
                    if not mapping_path:
                        raise ValueError("This investigation has no managed local mapping to stop.")
                    uninitialized = (previous.get("status") == "needs_attention"
                                     and not (Path(mapping_path) / "mapping.json").exists()
                                     and not (Path(mapping_path) / "mapped-clients").exists())
                    if not (uninitialized and args.stop_server and server_path):
                        lifecycle.stop_mapping(Path(mapping_path))
                    previous["status"] = "stopped"
                    publish_setup(state_path, previous, args.mapping_id, records)
                    if args.stop_server and server_path:
                        lifecycle.stop_local_server(Path(server_path))
                result = {"recorded_status": previous.get("status"), "api_checked": False,
                          "engagement_state_file": str(state_path),
                          "mapping": lifecycle.mapping_status(Path(mapping_path)) if mapping_path else None,
                          "local_server": lifecycle.local_server_status(Path(server_path)) if server_path else None}
    print(json.dumps(result, indent=2))
    if args.action in {"start", "resume"}:
        print(settings.analyst_setup_next_step(args.settings_file), file=sys.stderr)
    return 0
