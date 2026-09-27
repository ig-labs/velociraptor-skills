"""Small operational settings snapshot; credentials remain in native files or env."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tomllib
from types import MappingProxyType
from typing import Mapping

from .common.atomic_io import write_text_atomic
from .paths import EnvironmentLayer, RepositoryEnvironment, read_dotenv_file, repository_environment

# TOML key: (operation field, legacy environment name, value type).
SCHEMA = {
    "workstation": {
        "case_root": ("case_root", "CASE_ROOT", "path"),
        "binary": ("velociraptor_bin", "VELO_BIN", "binary"),
        "runtime_root": ("runtime_root", None, "path"),
        "config_root": ("config_root", "VELO_LOCAL_CONFIG_ROOT", "path"),
    },
    "credentials": {"env_file": ("env_file", None, "path")},
    "analyst": {"config_file": ("analyst_config_file", None, "path")},
    "api": {"grpc_max_message_bytes": ("grpc_max_message_bytes", "VELO_GRPC_MAX_MESSAGE_BYTES", "message_bytes")},
    "connection_defaults": {
        "api_user": ("api_user", "VELO_REMOTE_API_USER", "string"),
        "api_role_profile": ("api_role_profile", "VELO_REMOTE_API_ROLE_PROFILE", "role"),
        "ssh_user": ("ssh_user", "VELO_REMOTE_SSH_USER", "string"),
        "ssh_key": ("ssh_key", "VELO_REMOTE_SSH_KEY", "path"),
        "server_config": ("server_config", "VELO_REMOTE_SERVER_CONFIG_PATH", "string"),
        "remote_client_config": ("remote_client_config", "VELO_REMOTE_CLIENT_CONFIG_PATH", "string"),
        "remote_bin": ("remote_bin", "VELO_REMOTE_BIN", "string"),
        "run_as": ("run_as", "VELO_REMOTE_RUN_AS", "string"),
    },
    "connections": {
        "api_client": ("api_client", "VELO_LOCAL_API_CLIENT", "path"),
        "client_config": ("client_config", None, "path"),
        "server_ip": ("server_ip", None, "string"),
        "org_id": ("org_id", "VELO_LOCAL_ORG_ID", "string"),
        "api_user": ("api_user", "VELO_REMOTE_API_USER", "string"),
        "api_role_profile": ("api_role_profile", "VELO_REMOTE_API_ROLE_PROFILE", "role"),
        "ssh_user": ("ssh_user", "VELO_REMOTE_SSH_USER", "string"),
        "ssh_key": ("ssh_key", "VELO_REMOTE_SSH_KEY", "path"),
        "server_config": ("server_config", "VELO_REMOTE_SERVER_CONFIG_PATH", "string"),
        "remote_client_config": ("remote_client_config", "VELO_REMOTE_CLIENT_CONFIG_PATH", "string"),
        "remote_api_config": ("remote_api_config", "VELO_REMOTE_API_CONFIG_PATH", "string"),
        "remote_bin": ("remote_bin", "VELO_REMOTE_BIN", "string"),
        "run_as": ("run_as", "VELO_REMOTE_RUN_AS", "string"),
    },
    "mapping": {
        key: (key, "VELO_MAPPED_CLIENT_" + key.upper(), "positive")
        for key in ("poll_seconds", "stale_seconds", "failure_threshold", "max_restarts", "restart_window_seconds",
                    "startup_timeout_seconds", "ready_timeout_seconds")
    },
    "local_server": {
        **{key: (key, None, "port") for key in ("gui_port", "frontend_port", "api_port")},
        "api_user": ("local_api_user", "VELO_LOCAL_API_USER", "string"),
    },
}
_FIELDS = {value[0]: value for section in SCHEMA.values() for value in section.values()}
APPLICATION_DEFAULTS = MappingProxyType({
    "case_root": "~/cases", "velociraptor_bin": "~/velociraptor/velociraptor",
    "config_root": "~/.config/velociraptor", "grpc_max_message_bytes": 64 * 1024 * 1024,
    "startup_timeout_seconds": 120, "ready_timeout_seconds": 45,
    "run_as": "velociraptor",
    "api_user": "vraptor", "api_role_profile": "provisioning-admin",
})
_ACTIVE: ContextVar[SettingsSnapshot | None] = ContextVar("vraptor_settings", default=None)


def _path(value, *, base: Path, home: Path) -> str:
    raw = str(value)
    for prefix in ("${HOME}", "$HOME", "~"):
        if raw == prefix or raw.startswith(prefix + "/"):
            raw = str(home) + raw[len(prefix):]
            break
    path = Path(raw)
    return str((path if path.is_absolute() else base / path).resolve())


def default_path(environment: Mapping[str, str] | None = None) -> Path:
    environment = os.environ if environment is None else environment
    home = Path(environment.get("HOME") or Path.home())
    return Path(environment.get("XDG_CONFIG_HOME") or home / ".config") / "vraptor/config.toml"


def validate(document: dict) -> dict:
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("Velociraptor settings require schema_version = 1")
    unknown = document.keys() - {"schema_version", *SCHEMA}
    if unknown:
        raise ValueError(f"Unknown settings sections: {', '.join(sorted(unknown))}")
    for group, schema in SCHEMA.items():
        table = document.get(group, {})
        if not isinstance(table, dict):
            raise ValueError(f"{group} must be a table")
        tables = table.items() if group == "connections" else [(group, table)]
        for name, entries in tables:
            if not isinstance(entries, dict):
                raise ValueError(f"{group}.{name} must be a table")
            if group == "connections" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
                raise ValueError("Connection names must contain letters, numbers, dots, underscores or hyphens")
            for key, value in entries.items():
                if key not in schema:
                    raise ValueError(f"Unknown setting: {group}.{key}")
                _validate_value(f"{group}.{key}", value, schema[key][2])
    return document


def _validate_value(label, value, kind):
    if kind in {"positive", "port", "message_bytes"}:
        maximum = {"port": 65535, "message_bytes": 2147483647}.get(kind)
        if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
            raise ValueError(f"{label} must be a positive integer" + (f" at most {maximum}" if maximum else ""))
    elif not isinstance(value, str) or not value.strip() or any(c in value for c in ("\x00", "\n", "\r")):
        raise ValueError(f"{label} must be a nonempty single-line string")
    if kind == "role" and value not in {"investigation", "provisioning-admin"}:
        raise ValueError(f"{label} must be investigation or provisioning-admin")


def _normalize(name, value, kind, *, base, home):
    if kind in {"positive", "port", "message_bytes"} and isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            raise ValueError(f"{name} requires an integer") from None
    _validate_value(name, value, kind)
    if kind == "path" or (kind == "binary" and "/" in value):
        value = _path(value, base=base, home=home)
    return value


def read(path: Path, *, required=False) -> dict:
    if not path.exists() and not required:
        return {"schema_version": 1}
    try:
        return validate(tomllib.loads(path.read_text(encoding="utf-8")))
    except tomllib.TOMLDecodeError as error:
        # TOML errors can contain source text; do not echo configuration contents.
        raise ValueError(f"Invalid TOML in {path}") from error


@dataclass(frozen=True)
class SettingsSnapshot:
    config_file: Path
    server_profile: str | None
    values: Mapping
    sources: Mapping
    environment: Mapping = field(repr=False)
    connections: Mapping = field(repr=False)
    connection_sources: Mapping = field(repr=False)
    environment_base: Mapping = field(repr=False)
    environment_layers: RepositoryEnvironment = field(repr=False)

    def value(self, name, server_profile=None):
        if server_profile and server_profile != self.server_profile and name in SCHEMA["connections"]:
            return self.select(server_profile).values.get(name)
        return self.values.get(name)

    def public_dict(self):
        from .agent.sources import resolve_config_path

        exists = self.config_file.is_file()
        with activate(self):
            analyst_path, explicit = resolve_config_path(self.environment_layers, {})
        analyst_exists = analyst_path.is_file()
        command = ["vraptor", "ai", "config"]
        if exists:
            command.extend(["--settings-file", str(self.config_file)])
        if analyst_exists or explicit:
            command.extend(["--config-file", str(analyst_path)])
        return {"config_file": str(self.config_file), "exists": exists,
                "server_profile": self.server_profile,
                "values": {key: value for key, value in self.values.items() if key != "analyst_config_file"},
                "sources": {key: value for key, value in self.sources.items() if key != "analyst_config_file"},
                "connections": sorted(name for name in self.connections if name),
                "analyst_agent": {"config_file": str(analyst_path), "exists": analyst_exists,
                                  "inspect_command": shlex.join(command)}}

    def select(self, server_profile, overrides=None):
        """Select an investigation's saved connection without rereading files."""
        keys = SCHEMA["connections"]
        values = {key: value for key, value in self.values.items() if key not in keys}
        sources = {key: value for key, value in self.sources.items() if key not in keys}
        items = dict(self.connections.get(server_profile or "", self.connections[""]))
        origins = dict(self.connection_sources.get(server_profile or "", self.connection_sources[""]))
        if server_profile and server_profile not in self.connections and origins.get("api_client", "").startswith("environment:"):
            items.pop("api_client", None)
            origins.pop("api_client", None)
        values.update(items)
        sources.update(origins)
        home = Path(self.environment_base.get("HOME") or Path.home())
        for name, raw in (overrides or {}).items():
            if name not in _FIELDS or raw is None:
                continue
            kind = _FIELDS[name][2]
            raw = _normalize(name, raw, kind, base=Path.cwd(), home=home)
            values[name], sources[name] = raw, "command_line"
        for name, raw in values.items():
            _validate_value(name, raw, _FIELDS[name][2])
        return replace(self, server_profile=server_profile, values=MappingProxyType(values),
                       sources=MappingProxyType(sources), environment=_environment(values, self.environment_base, sources))

    def apply(self, args):
        """Fill only unset parser fields; explicit operation inputs retain precedence."""
        for name, value in self.values.items():
            if hasattr(args, name) and getattr(args, name) is None:
                setattr(args, name, value)
        return args


def current():
    return _ACTIVE.get()


def active_value(name, server_profile=None):
    snapshot = current()
    return snapshot.value(name, server_profile) if snapshot else None


@contextmanager
def activate(snapshot):
    token = _ACTIVE.set(snapshot)
    try:
        yield snapshot
    finally:
        _ACTIVE.reset(token)


def resolve(server_profile=None, overrides=None, config_file=None, repo_root=None,
            process_environment=None, *, allow_missing=False, require_credentials=True) -> SettingsSnapshot:
    if repo_root is None:
        from .resources import repository_root
        repo_root = repository_root()
    repo_root = Path(repo_root).resolve()
    observed = dict(os.environ if process_environment is None else process_environment)
    home = Path(observed.get("HOME") or Path.home())
    path = Path(_path(config_file or default_path(observed), base=Path.cwd(), home=home))
    document = read(path, required=config_file is not None and not allow_missing)
    layers = repository_environment(repo_root, process_environment=observed)
    overrides = dict(overrides or {})
    dotenv = overrides.get("env_file") or document.get("credentials", {}).get("env_file")
    selected = {}
    if dotenv:
        dotenv = _path(dotenv, base=Path.cwd() if overrides.get("env_file") else path.parent, home=home)
        if require_credentials and not Path(dotenv).is_file():
            raise ValueError(f"Selected credential env file does not exist: {dotenv}")
        if Path(dotenv).is_file():
            selected = read_dotenv_file(Path(dotenv))
            layers = replace(layers, selected=EnvironmentLayer(
                kind="selected_dotenv", location=dotenv, values=MappingProxyType(selected),
            ))
    environment, env_sources = {}, {}
    for location, entries in ((layers.shared.location, layers.shared.values),
                              (layers.repository.location, layers.repository.values),
                              (dotenv, selected), ("process", layers.process.values)):
        for key, value in entries.items():
            environment[key], env_sources[key] = value, location
    values = {key: _normalize(key, value, _FIELDS[key][2], base=repo_root, home=home)
              for key, value in APPLICATION_DEFAULTS.items() if key not in SCHEMA["connections"]}
    sources = dict.fromkeys(values, "default")

    def populate(group, entries, output, provenance, profile=None):
        for key, (name, env_key, kind) in SCHEMA[group].items():
            raw, source, base = entries.get(key), f"{path}:{group}.{key}", path.parent
            use_env = env_key and not (env_key == "VELO_LOCAL_API_CLIENT" and profile and key not in entries)
            if use_env and environment.get(env_key, "").strip():
                raw, source, base = environment[env_key], f"environment:{env_sources[env_key]}:{env_key}", repo_root
            if group != "connections" and overrides.get(name) is not None:
                raw, source, base = overrides[name], "command_line", Path.cwd()
            if raw is None:
                continue
            # Validate a role after selecting the connection and its CLI override.
            raw = _normalize(name, raw, "string" if kind == "role" else kind, base=base, home=home)
            output[name], provenance[name] = raw, source

    for group in SCHEMA.keys() - {"connections", "connection_defaults"}:
        populate(group, document.get(group, {}), values, sources)
    defaults = {key: value for key, value in APPLICATION_DEFAULTS.items() if key in SCHEMA["connections"]}
    default_sources = dict.fromkeys(defaults, "default")
    for key, raw in document.get("connection_defaults", {}).items():
        defaults[key] = _normalize(key, raw, SCHEMA["connection_defaults"][key][2], base=path.parent, home=home)
        default_sources[key] = f"{path}:connection_defaults.{key}"
    connections, connection_sources = {}, {}
    for profile in {*document.get("connections", {}), server_profile or "", ""}:
        items, origins = dict(defaults), dict(default_sources)
        populate("connections", document.get("connections", {}).get(profile, {}), items, origins, profile)
        origins = {key: value.replace(":connections.", f":connections.{profile}.") for key, value in origins.items()}
        connections[profile], connection_sources[profile] = MappingProxyType(items), MappingProxyType(origins)
    values.update(connections[server_profile or ""])
    sources.update(connection_sources[server_profile or ""])
    snapshot = SettingsSnapshot(path, server_profile, MappingProxyType(values), MappingProxyType(sources),
                                MappingProxyType(environment), MappingProxyType(connections),
                                MappingProxyType(connection_sources), MappingProxyType(environment), layers)
    return snapshot.select(server_profile, overrides)


def _environment(values, baseline, sources):
    # Children receive this resolved snapshot instead of reloading dotfiles.
    environment = dict(baseline)
    for name, raw in values.items():
        env_key = _FIELDS[name][1]
        if env_key:
            environment[env_key] = str(raw)
    # Keep analyst file selection in its existing namespace for child processes.
    if values.get("analyst_config_file") and not environment.get("AI_SKILLS_ANALYST_AGENT_CONFIG_FILE", "").strip():
        environment["AI_SKILLS_ANALYST_AGENT_CONFIG_FILE"] = values["analyst_config_file"]
    # Preserve default provenance across the shell-helper boundary.
    environment["VRAPTOR_REMOTE_RUN_AS_DEFAULT"] = "1" if sources.get("run_as") == "default" else "0"
    environment["VRAPTOR_SETTINGS_RESOLVED"] = "1"
    # Internal interpreter handoff to shell helpers, not a user setting.
    environment["VRAPTOR_PYTHON"] = sys.executable
    return MappingProxyType(environment)


def render(document):
    lines = ["schema_version = 1", ""]
    for group in SCHEMA:
        entries = document.get(group, {})
        tables = ((f'connections.{json.dumps(name)}', values) for name, values in entries.items()) if group == "connections" else [(group, entries)]
        for name, values in tables:
            if values:
                lines.extend([f"[{name}]", *(f"{key} = {json.dumps(value)}" for key, value in values.items()), ""])
    return "\n".join(lines)


def analyst_setup_next_step(settings_file=None):
    """Advertise the wizard without loading a provider or changing analyst settings."""
    command = ["vraptor", "ai", "setup"]
    if settings_file:
        command.extend(["--settings-file", str(Path(settings_file).expanduser().resolve())])
    return "To configure AI, run: " + shlex.join(command)


def config_main(argv=None):
    """Inspect operational settings using the same views as ai config."""
    parser = argparse.ArgumentParser(
        prog="vraptor config",
        description="Explain effective operational settings or application defaults without secret values.",
        epilog="Use setup configure to edit settings. config fetch-api and config fetch-client retain their explicit acquisition commands.",
    )
    parser.add_argument("--view", choices=("effective", "defaults"), default="effective",
                        help="Report effective local configuration (default) or machine-independent application defaults.")
    parser.add_argument("--settings-file", "--config-file", dest="settings_file", help="Select an operational config.toml file.")
    parser.add_argument("--server-profile")
    for name, (_, _, kind) in _FIELDS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=int if kind in {"positive", "port", "message_bytes"} else str)
    args = parser.parse_args(argv)
    if args.view == "defaults":
        if any(value is not None for key, value in vars(args).items() if key != "view"):
            parser.error("--view defaults cannot be combined with effective-setting overrides")
        payload = {"view": "defaults", "values": dict(APPLICATION_DEFAULTS),
                   "sources": dict.fromkeys(APPLICATION_DEFAULTS, "default")}
    else:
        payload = {"view": "effective", **resolve(args.server_profile, overrides=vars(args),
                                                   config_file=args.settings_file).public_dict()}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _configure_interactively(args, snapshot):
    """Collect reusable settings only; do not acquire credentials or start resources."""
    def heading(title, description):
        print(f"\n{title}\n{'─' * len(title)}\n{description}\n", file=sys.stderr)

    def ask(label, *, default=False):
        while True:
            answer = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
            if not answer:
                return default
            if answer in {"n", "no"}:
                return False
            if answer in {"y", "yes"}:
                return True
            print("Enter yes or no.", file=sys.stderr)

    def prompt(name, label, *, save_default=False):
        value = snapshot.values.get(name)
        hint = str(value) if value is not None else "blank to leave unset"
        while True:
            answer = input(f"{label} [{hint}]: ").strip()
            if not answer:
                if save_default:
                    setattr(args, name, value)
                return
            try:
                value = _normalize(name, answer, _FIELDS[name][2], base=Path.cwd(), home=Path.home())
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                continue
            setattr(args, name, value)
            return

    print("Configure reusable settings. Enter keeps existing values; optional sections can be skipped.", file=sys.stderr)
    heading("Workstation", "Shared local paths for live and mapped investigations. Saved in [workstation].")
    prompt("case_root", "Investigation parent", save_default=True)
    prompt("velociraptor_bin", "Preferred local Velociraptor binary path", save_default=True)
    heading("Remote connection", "Use an existing live server's API-client YAML. Fresh setups suggest the name live; enter - to edit shared connection defaults.")
    if not args.server_profile:
        saved_servers = [name for name in snapshot.connections if name]
        default_server = (saved_servers[0] if len(saved_servers) == 1 else
                          "live" if not snapshot.config_file.exists() else "")
        while True:
            profile = input(f"Optional saved server name [{default_server or 'shared defaults'}] (Enter to keep, - for shared defaults): ").strip()
            profile = "" if profile == "-" else profile or default_server
            try:
                if profile:
                    validate({"schema_version": 1, "connections": {profile: {}}})
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                continue
            args.server_profile = profile or None
            break
    snapshot = snapshot.select(args.server_profile)
    destination = f'[connections."{args.server_profile}"]' if args.server_profile else "[connection_defaults]"
    print(f"Connection settings will be saved in {destination}.\n", file=sys.stderr)
    if args.server_profile:
        prompt("api_client", "Existing local API-client YAML path")
        prompt("server_ip", "Remote server address for SSH access")
        prompt("org_id", "Velociraptor organization ID")
    prompt("api_user", "Remote API username", save_default=True)
    prompt("api_role_profile", "Remote API role profile (investigation or provisioning-admin)")
    heading("Remote SSH access", f"Optional credential-fetching and generation settings. Saved in {destination}; no remote commands run during configure.")
    if ask("Configure remote SSH and configuration paths"):
        for name, label in (
            ("ssh_user", "Remote SSH login username"),
            ("ssh_key", "Local SSH private-key path"),
            ("server_config", "Velociraptor server YAML path on the remote server"),
            ("remote_client_config", "Endpoint-client YAML path on the remote server"),
            ("remote_bin", "Velociraptor binary path on the remote server"),
            ("run_as", "Remote account used to run Velociraptor"),
        ):
            prompt(name, label)
        if args.server_profile:
            prompt("remote_api_config", "API credential YAML path on the remote server (optional override)")
    heading("Local server", "For evidence mapped to a server on this workstation. Saved in [local_server].")
    if ask("Configure local server settings"):
        for name, label in (
            ("local_api_user", "Local server API username (built-in default vraptor)"),
            ("frontend_port", "Local server frontend port (built-in default 8000)"),
            ("api_port", "Local server API port (built-in default 8001)"),
            ("gui_port", "Local server GUI port (built-in default 8889)"),
        ):
            prompt(name, label)
    heading("Mapped evidence", "For local evidence mapped to a local or remote server. Supervision settings are saved in [mapping].")
    if ask("Configure mapped-evidence settings"):
        if args.server_profile:
            print(f"The endpoint-client YAML reference is saved in {destination}.\n", file=sys.stderr)
            prompt("client_config", "Existing local endpoint-client YAML path for remote mappings")
        for name, label in (
            ("startup_timeout_seconds", "Mapped-client startup timeout in seconds"),
            ("ready_timeout_seconds", "Mapped-client readiness timeout in seconds"),
            ("poll_seconds", "Mapped-client health polling interval in seconds"),
            ("stale_seconds", "Mapped-client stale threshold in seconds (blank retains mode-specific default)"),
            ("failure_threshold", "Mapped-client consecutive health failure threshold"),
            ("max_restarts", "Mapped-client maximum restarts per window"),
            ("restart_window_seconds", "Mapped-client restart window in seconds"),
        ):
            prompt(name, label)
    heading("Advanced paths and API transport", "Optional directory overrides in [workstation] and the message-size limit in [api].")
    if ask("Configure advanced local paths and API transport"):
        for name, label in (
            ("config_root", "Local Velociraptor configuration directory"),
            ("runtime_root", "Optional runtime directory override"),
            ("grpc_max_message_bytes", "API maximum gRPC message size in bytes"),
        ):
            prompt(name, label)
    heading("Credentials", "Optional .env file reference in [credentials]. Keep secret values in that file; environment overrides remain active.")
    prompt("env_file", "Optional credential .env path")
    heading("AI analyst configuration", "Open vraptor ai setup after saving operational settings (recommended). New AI profiles default to OpenAI; saved selections are retained. Preview mode never launches the AI wizard.")
    return ask("Configure AI analyst settings", default=True)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vraptor setup")
    parser.add_argument("action", choices=("show", "configure", "migrate"))
    parser.add_argument("--settings-file")
    parser.add_argument("--server-profile")
    parser.add_argument("--template", help="Apply missing values from an ordinary settings TOML template.")
    parser.add_argument("--preview", action="store_true", help="Preview configure without writing.")
    parser.add_argument("--write", action="store_true", help="Write migration; default is preview.")
    for name, (_, _, kind) in _FIELDS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=int if kind in {"positive", "port", "message_bytes"} else str)
    args = parser.parse_args(argv)
    path = Path(args.settings_file).expanduser().resolve() if args.settings_file else default_path()
    if args.action == "show":
        print(json.dumps(resolve(args.server_profile, overrides=vars(args), config_file=args.settings_file).public_dict(), indent=2))
        return 0
    document = read(path)
    before = path.read_text(encoding="utf-8") if path.is_file() else None
    if args.template:
        template_path = Path(args.template).expanduser().resolve()
        template = read(template_path, required=True)
        # Materialization must preserve paths relative to the source template.
        for group, schema in SCHEMA.items():
            tables = template.get(group, {})
            for entries in (tables.values() if group == "connections" else [tables]):
                for key, value in entries.items():
                    kind = schema[key][2]
                    if kind == "path" or (kind == "binary" and "/" in value):
                        entries[key] = _path(value, base=template_path.parent, home=Path.home())
        for group in SCHEMA:
            tables = template.get(group, {})
            destination = document.setdefault(group, {})
            if group == "connections":
                for name, values in tables.items():
                    for key, value in values.items():
                        destination.setdefault(name, {}).setdefault(key, value)
            else:
                for key, value in tables.items():
                    destination.setdefault(key, value)
    changes, conflicts = [], []
    # Configuration must remain usable to repair a moved/deleted credential file.
    # Operational commands still require the selected file to exist.
    snapshot = resolve(args.server_profile, config_file=path, allow_missing=True,
                       require_credentials=args.action != "configure",
                       overrides={"env_file": args.env_file} if args.env_file else None)
    configure_ai = False
    if args.action == "configure" and sys.stdin.isatty() and not any(getattr(args, key) is not None for key in _FIELDS) and not args.template:
        configure_ai = _configure_interactively(args, snapshot)
    for group, schema in SCHEMA.items():
        for key, (name, env_key, kind) in schema.items():
            # Shared flags configure a named profile when selected, otherwise defaults.
            if key in SCHEMA["connection_defaults"] and (
                (group == "connection_defaults" and args.server_profile)
                or (group == "connections" and not args.server_profile)
            ):
                continue
            explicit = getattr(args, name)
            migrating = args.action == "migrate" and env_key and snapshot.environment.get(env_key, "").strip() and str(snapshot.sources.get(name, "")).startswith("environment:")
            value = explicit if explicit is not None else snapshot.values.get(name) if migrating else None
            if value is None:
                continue
            if explicit is not None:
                value = _normalize(name, value, kind, base=Path.cwd(), home=Path.home())
            if group == "connections" and not args.server_profile:
                if explicit is not None:
                    parser.error(f"--{name.replace('_', '-')} requires --server-profile")
                continue
            table = document.setdefault(group, {})
            if group == "connections":
                table = table.setdefault(args.server_profile, {})
            if args.action == "migrate" and explicit is None and key in table and table[key] != value:
                conflicts.append(f"{group}.{key}")
                continue
            if table.get(key) != value:
                table[key] = value
                changes.append(f"{group}.{key}")
    if args.action == "configure":
        table = document.setdefault("connection_defaults", {})
        default_values = snapshot.select(None).values
        for key in SCHEMA["connection_defaults"]:
            if key not in table and key in default_values:
                table[key] = default_values[key]
                changes.append(f"connection_defaults.{key}")
    if args.action == "configure" and before is None and not document.get("workstation"):
        document["workstation"] = {"case_root": snapshot.values["case_root"], "binary": snapshot.values["velociraptor_bin"]}
    content = render(validate(document))
    writing = (args.action == "configure" and not args.preview) or (args.action == "migrate" and args.write)
    backup = None
    if writing and content != before:
        # Guard against edits made while interactive prompts were open.
        if (path.read_text(encoding="utf-8") if path.exists() else None) != before:
            raise ValueError("Settings changed during configuration; rerun to preserve the other edit")
        if before is not None:
            backup = path.with_name(path.name + ".bak")
            write_text_atomic(backup, before)
        write_text_atomic(path, content)
    print(json.dumps({"config_file": str(path), "written": writing and content != before,
                      "backup": str(backup) if backup else None, "changes": changes,
                      "conflicts_preserved": conflicts, "configuration": document,
                      "note": "Legacy environment overrides remain active; migration does not modify credential files."}, indent=2))
    if configure_ai and args.preview:
        print("Preview only: AI setup was not started.", file=sys.stderr)
    elif configure_ai:
        from .cli import main as cli_main

        print("\nAI analyst configuration\n────────────────────────\nOperational settings saved. Opening vraptor ai setup.\n", file=sys.stderr)
        # Resolve the saved operational file again so analyst and dotenv selectors
        # follow the same path as a separate `vraptor ai setup` invocation.
        with redirect_stdout(sys.stderr):
            status = cli_main(["ai", "setup", "--settings-file", str(path)])
        if status:
            print("Operational settings remain saved; AI setup did not complete.", file=sys.stderr)
            print(analyst_setup_next_step(path), file=sys.stderr)
        return status
    elif args.action == "configure" and not args.preview:
        print(analyst_setup_next_step(args.settings_file), file=sys.stderr)
    return 0
