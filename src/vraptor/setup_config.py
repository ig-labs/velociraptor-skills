#!/usr/bin/env python3
"""Export, deploy and reset operational settings without moving credentials."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import tomllib

from vraptor.common.atomic_io import write_json_atomic, write_text_atomic
from vraptor.paths import expand_home_path
from vraptor.settings import SCHEMA, default_path, render
from vraptor import settings
from vraptor.resources import repository_root

# Keep this tied to operational settings, not a broad VELO_* or AI_SKILLS_* wipe.
RESET_KEYS = {env for section in SCHEMA.values() for _, env, _ in section.values() if env} | {
    "VELO_LOCAL_ORG_ID", "VELO_LOCAL_WORKSPACE", "VELO_MAPPED_CLIENT_WORKSPACE",
    "VELO_MAPPED_CLIENT_WATCHDOG_MODE", "VELO_LOCAL_PORTS",
}


@dataclass
class Change:
    path: Path
    before: str
    after: str | None
    keys: list[str]


def absolute(value: str | Path, base: Path) -> Path:
    path = expand_home_path(value)
    return Path(os.path.abspath(path if path.is_absolute() else base / path))


def read_file(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError(f"Expected an owned regular file without symlinks or hard links: {path}")
    # Preserve line endings and never include file contents in an error.
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeError:
        raise ValueError(f"Expected UTF-8 configuration: {path}") from None


def plan(settings_file: Path, repo_root: Path, env_files: list[str]) -> list[Change]:
    before = read_file(settings_file)
    paths = [repo_root / ".env", Path.home() / ".codex/.env"]
    changes = []
    if before is not None:
        try:
            document = tomllib.loads(before)
            selected = document.get("credentials", {}).get("env_file")
            if selected:
                if not isinstance(selected, str):
                    raise ValueError("Credential dotenv must be a path")
                paths.append(absolute(selected, settings_file.parent))
        except (ValueError, TypeError, AttributeError):
            raise ValueError(f"Cannot discover credential dotenv from invalid settings: {settings_file}") from None
        # Preserve analyst routing and authentication when resetting setup only.
        retained = {"schema_version": 1}
        if selected:
            retained["credentials"] = {"env_file": selected}
        if document.get("analyst"):
            retained["analyst"] = document["analyst"]
        after = render(retained) if len(retained) > 1 else None
        if after != before:
            changes.append(Change(settings_file, before, after, []))
    paths.extend(absolute(path, Path.cwd()) for path in env_files)
    for path in dict.fromkeys(paths):
        if path == settings_file:
            raise ValueError("Settings TOML and credential dotenv must be different files")
        original = read_file(path)
        if original is None:
            continue
        kept, removed = [], set()
        for line in original.splitlines(keepends=True):
            key, separator, _ = line.strip().removeprefix("export ").partition("=")
            key = key.strip()
            if separator and key in RESET_KEYS:
                removed.add(key)
            else:
                kept.append(line)
        if removed:
            changes.append(Change(path, original, "".join(kept), sorted(removed)))
    return changes


def check_unchanged(changes: list[Change]) -> None:
    for change in changes:
        if read_file(change.path) != change.before:
            raise ValueError(f"Configuration changed during reset; rerun preview: {change.path}")


def apply(changes: list[Change], repo_root: Path) -> Path | None:
    if not changes:
        return None
    check_unchanged(changes)
    root = absolute(default_path().parent / "backups", Path.cwd())
    if any(root.resolve().is_relative_to(repo.resolve()) for repo in (repository_root(), repo_root)):
        raise ValueError("Configuration backups must stay outside the repository")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=root))
    records = []
    for index, change in enumerate(changes):
        destination = backup / f"{index:02d}-{change.path.name}"
        write_text_atomic(destination, change.before, newline="")
        records.append({"original": str(change.path), "backup": destination.name})
    write_json_atomic(backup / "manifest.json", {"files": records})
    # All originals are backed up before the first change; retain backups on failure.
    print(f"Backups: {backup}", file=sys.stderr, flush=True)
    check_unchanged(changes)
    for change in changes:
        check_unchanged([change])
        if change.after is None:
            change.path.unlink()
        else:
            write_text_atomic(change.path, change.after, newline="")
    return backup


def reset_main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Write the previewed reset; default is read-only.")
    parser.add_argument("--settings-file", help="Operational TOML; default follows XDG_CONFIG_HOME.")
    parser.add_argument("--repo-root", default=str(repository_root()), help="Checkout whose .env is included.")
    parser.add_argument("--env-file", action="append", default=[], help="Additional credential dotenv to clean; repeatable.")
    args = parser.parse_args(argv)
    try:
        repo = absolute(args.repo_root, Path.cwd())
        settings_file = absolute(args.settings_file or default_path(), Path.cwd())
        changes = plan(settings_file, repo, args.env_file)
        unset = sorted(RESET_KEYS & os.environ.keys())
        backup = apply(changes, repo) if args.apply else None
        print(json.dumps({
            "mode": "applied" if args.apply else "preview",
            "settings_file": str(settings_file),
            "changes": [{"path": str(item.path), "action": "remove" if item.after is None else
                         "remove_setup_keys" if item.keys else "reset_settings",
                         "keys": item.keys} for item in changes],
            "backup_directory": str(backup) if backup else None,
            "shell_unset": "unset " + " ".join(unset) if unset else None,
            "note": "Preserves credentials, analyst settings, tools, evidence, cases and running processes. "
                    "Exported overrides require shell_unset in the calling shell; remove persistent exports at their source.",
        }, indent=2))
        return 0
    except (OSError, ValueError) as error:
        print(f"Reset failed: {error}", file=sys.stderr)
        return 1


def portable_value(value, kind):
    if kind == "path" or (kind == "binary" and "/" in value):
        try:
            relative = Path(value).relative_to(Path.home())
            return "~/" + str(relative) if relative.parts else "~"
        except ValueError:
            pass
    return value


def export_document(snapshot):
    """Materialize only schema-owned settings; never serialize the environment."""
    document = {"schema_version": 1}
    profiles = sorted(name for name in snapshot.connections if name)
    baseline = snapshot.select(None)
    if not profiles and set(baseline.connections[""]) - SCHEMA["connection_defaults"].keys():
        raise ValueError("Environment connection settings require --server-profile for export.")
    for group, schema in SCHEMA.items():
        names = profiles if group == "connections" else [None]
        for profile in names:
            selected = snapshot.select(profile) if profile else baseline
            values = selected.values if group in {"connections", "connection_defaults"} else snapshot.values
            entries = {key: portable_value(values[name], kind)
                       for key, (name, _, kind) in schema.items() if name in values}
            if group == "connections":
                entries = {key: value for key, value in entries.items()
                           if key not in SCHEMA["connection_defaults"]
                           or selected.sources[key] != baseline.sources.get(key)}
            if entries:
                if profile:
                    document.setdefault(group, {})[profile] = entries
                else:
                    document[group] = entries
    analyst = snapshot.public_dict()["analyst_agent"]
    if analyst["exists"] or "analyst_config_file" in snapshot.values:
        document["analyst"] = {"config_file": portable_value(analyst["config_file"], "path")}
    return settings.validate(document)


def create_file(path, content):
    """Never overwrite an existing export or a concurrently created settings file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def deploy_document(source, target):
    content = read_file(source)
    if content is None:
        raise ValueError(f"Settings snapshot does not exist: {source}")
    try:
        incoming = settings.validate(tomllib.loads(content))
        before = read_file(target)
        document = settings.validate(tomllib.loads(before)) if before is not None else {"schema_version": 1}
    except tomllib.TOMLDecodeError:
        raise ValueError("Invalid settings TOML; no configuration was changed.") from None
    changes = []
    for group, schema in SCHEMA.items():
        tables = incoming.get(group, {})
        for profile, entries in (tables.items() if group == "connections" else [(None, tables)]):
            for key, raw in entries.items():
                name, _, kind = schema[key]
                value = settings._normalize(name, raw, kind, base=source.parent, home=Path.home())
                table = document.setdefault(group, {})
                if profile is not None:
                    table = table.setdefault(profile, {})
                if table.get(key) != value:
                    table[key] = value
                    changes.append(".".join(part for part in (group, profile, key) if part))
    return before, render(settings.validate(document)), changes


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["reset"]:
        return reset_main(arguments[1:])
    parser = argparse.ArgumentParser(prog="vraptor setup")
    parser.add_argument("action", choices=("export", "deploy"))
    parser.add_argument("--settings-file")
    parser.add_argument("--repo-root", default=str(repository_root()))
    parser.add_argument("--server-profile", help="Name an environment-only connection when exporting.")
    parser.add_argument("--output", help="New settings snapshot file for export.")
    parser.add_argument("--from", dest="source", help="Settings snapshot to deploy.")
    parser.add_argument("--apply", action="store_true", help="Apply deployment; default is preview.")
    args = parser.parse_args(arguments)
    repo = absolute(args.repo_root, Path.cwd())
    target = absolute(args.settings_file or default_path(), Path.cwd())
    if args.action == "export":
        if not args.output or args.source or args.apply:
            parser.error("export requires --output and does not accept --from or --apply")
        snapshot = settings.resolve(args.server_profile, config_file=args.settings_file, repo_root=repo,
                                    require_credentials=False)
        document = export_document(snapshot)
        output = absolute(args.output, Path.cwd())
        create_file(output, render(document))
        print(json.dumps({"action": "export", "output": str(output),
                          "connections": sorted(document.get("connections", {})),
                          "credentials_included": False, "note": "Local home paths use ~; credentials and analyst configuration are references only."}, indent=2))
        return 0
    if not args.source or args.output or args.server_profile:
        parser.error("deploy requires --from and does not accept --output or --server-profile")
    source = absolute(args.source, Path.cwd())
    if source == target:
        raise ValueError("Deploy source and destination must be different files.")
    before, content, changes = deploy_document(source, target)
    backup = None
    written = bool(args.apply and changes)
    if written:
        if before is None:
            create_file(target, content)
        else:
            backup = apply([Change(target, before, content, [])], repo)
    print(json.dumps({"action": "deploy", "mode": "applied" if args.apply else "preview",
                      "settings_file": str(target), "written": written, "changes": changes,
                      "backup_directory": str(backup) if backup else None,
                      "note": "Unrelated settings are retained; environment overrides still take precedence. No credentials, binaries or remote resources are deployed."}, indent=2))
    return 0
