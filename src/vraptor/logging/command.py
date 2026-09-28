"""Read-only inspection commands for the Velociraptor progress log."""

from __future__ import annotations

import argparse
import re
import shlex
import socket
import stat
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vraptor import case_layout
from vraptor.paths import add_case_root_arg
from vraptor.paths import resolve_case_root
from vraptor.logging import operations as operation_log


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
LINE_FIELDS_RE = re.compile(
    r"^(?P<timestamp>\S+) (?P<level>DEBUG|INFO|WARNING|ERROR) "
    r"\[(?P<operation>op-v1-[0-9a-f]{16})\] "
)
SINCE_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[smhd])$")


def _log_dir(args: argparse.Namespace) -> Path:
    engagement_id = case_layout.safe_component(
        str(args.engagement_id),
        label="engagement id",
    )
    return (
        case_layout.engagement_dir(
            resolve_case_root(args.case_root, REPO_ROOT),
            engagement_id,
        )
        / "logs"
    )


def _resolve_log(args: argparse.Namespace) -> Path:
    directory = _log_dir(args).resolve()
    candidate = Path(args.file or operation_log.LOG_FILENAME)
    path = (
        (directory / candidate).resolve()
        if not candidate.is_absolute()
        else candidate.resolve()
    )
    allowed_names = {
        operation_log.LOG_FILENAME,
        *{
            f"{operation_log.LOG_FILENAME}.{index}"
            for index in range(1, operation_log.MAX_LOG_FILES)
        },
    }
    if path.parent != directory or path.name not in allowed_names:
        raise ValueError(
            "--file must identify this engagement's progress log or a rotated copy"
        )
    return path


def _parse_since(value: str | None, *, now: datetime | None = None) -> datetime | None:
    if not value:
        return None
    match = SINCE_RE.fullmatch(str(value).strip().lower())
    if match:
        seconds = int(match.group("amount")) * {
            "s": 1,
            "m": 60,
            "h": 3600,
            "d": 86400,
        }[match.group("unit")]
        reference = now or datetime.now(timezone.utc)
        return reference - timedelta(seconds=seconds)
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "--since must be a duration such as 30m or an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError("--since ISO-8601 timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _filter_lines(
    lines: list[str],
    *,
    operation: str = "",
    level: str = "",
    since: datetime | None = None,
    scope: str = "",
    hunt_id: str = "",
    task_id: str = "",
) -> list[str]:
    minimum_level = operation_log.LEVELS.get(level.lower(), 0) if level else 0
    selected: list[str] = []
    for line in lines:
        match = LINE_FIELDS_RE.match(line)
        if match is None:
            continue
        if operation and match.group("operation") != operation:
            continue
        if operation_log.LEVELS[match.group("level").lower()] < minimum_level:
            continue
        timestamp = datetime.fromisoformat(
            match.group("timestamp").replace("Z", "+00:00")
        )
        if since is not None and timestamp < since:
            continue
        if scope and not _line_has_field(line, ("scope",), scope):
            continue
        if hunt_id and not _line_has_field(
            line,
            ("hunt_id", "scope_id"),
            hunt_id,
        ):
            continue
        if task_id and not _line_has_field(line, ("task_id",), task_id):
            continue
        selected.append(line)
    return selected


def _line_has_field(line: str, names: tuple[str, ...], value: str) -> bool:
    fields = _line_fields(line)
    return any(fields.get(name) == value for name in names)


def _line_fields(line: str) -> dict[str, str]:
    """Parse quoted server text as a value, never as correlation metadata."""
    try:
        parts = shlex.split(line.partition(" | ")[2])
    except ValueError:
        return {}
    return {
        key: value
        for part in parts
        for key, sep, value in [part.partition("=")]
        if sep
    }


def _operation_status(lines: list[str], *, now: datetime | None = None) -> list[dict[str, str]]:
    now = now or datetime.now(timezone.utc)
    records: dict[str, dict[str, str]] = {}
    for line in lines:
        match = LINE_FIELDS_RE.match(line)
        if match is None:
            continue
        record = records.setdefault(match["operation"], {"operation": match["operation"]})
        fields = _line_fields(line)
        for key in ("command", "pid", "process_started", "log_host", "hunt_id", "artifact", "scope", "scope_id", "client_id"):
            if fields.get(key):
                record[key] = fields[key]
        record["updated"] = match["timestamp"]
        message = line[match.end():].partition(" | ")[0].strip()
        if fields.get("query_id") or fields.get("query_instance_id"):
            record["query"] = fields.get("query_id") or fields["query_instance_id"]
            record["purpose"] = fields.get("purpose") or fields.get("query", "unknown")
        if fields.get("server_message"):
            record["last_server_message"] = fields["server_message"]
        if message in {"Command completed", "Command failed", "Command interrupted"}:
            record["terminal"] = message.removeprefix("Command ")
    for record in records.values():
        age = max(0, int((now - datetime.fromisoformat(record["updated"].replace("Z", "+00:00"))).total_seconds()))
        record["age_seconds"] = str(age)
        if record.get("terminal"):
            record["state"] = record["terminal"]
            continue
        state = "unknown"
        if (
            record.get("log_host") == socket.gethostname()
            and record.get("pid", "").isdigit()
            and record.get("process_started")
        ):
            state, started = operation_log.process_snapshot(int(record["pid"]))
            if started and started != record["process_started"]:
                state = "exited-pid-reused"
        record["state"] = state
        record["stale"] = "yes" if age > 360 else "no"
    active_scopes: dict[tuple[str, ...], list[dict[str, str]]] = {}
    for record in records.values():
        if record["state"] not in {"alive", "stopped"}:
            continue
        target = record.get("hunt_id") or record.get("client_id")
        if target:
            key = (record.get("command", ""), target, record.get("artifact", ""))
            active_scopes.setdefault(key, []).append(record)
    for group in active_scopes.values():
        if len(group) > 1:
            for record in group:
                record["overlap"] = ",".join(other["operation"] for other in group if other is not record)
    return list(records.values())


def _status(args: argparse.Namespace, path: Path) -> int:
    lines: list[str] = []
    paths = [path]
    if path.name == operation_log.LOG_FILENAME:
        paths = [path.with_name(f"{path.name}.{i}") for i in range(operation_log.MAX_LOG_FILES - 1, 0, -1)] + paths
    for candidate in paths:
        if candidate.exists():
            lines.extend(operation_log.validate_log(candidate))
    records = _operation_status(lines)
    records = [
        record for record in records
        if (not args.operation or args.operation == record["operation"])
        and (not args.hunt_id or args.hunt_id in {record.get("hunt_id"), record.get("scope_id")})
    ]
    for record in records[-args.lines:]:
        print(f"{record['operation']}: {record['state'].upper()}")
        print(f"  Command: {record.get('command', 'unknown')}; PID: {record.get('pid', 'not recorded')}")
        for key, label in (("hunt_id", "Hunt"), ("client_id", "Client"), ("artifact", "Artifact"), ("purpose", "Last query purpose"), ("query", "Query")):
            if record.get(key):
                print(f"  {label}: {record[key]}")
        print(f"  Last log update: {record['age_seconds']}s ago; remote query state: unknown")
        if record.get("stale") == "yes":
            print("  No recent log updates; check local process state before restarting.")
        if record.get("last_server_message"):
            print(f"  Last server message: {operation_log.sanitize_server_message(record['last_server_message'])[0]}")
        if record.get("overlap"):
            print(f"  Overlapping operation(s): {record['overlap']}")
    if not records:
        print("No matching operations found in retained logs.")
    return 0


def _add_read_args(parser: argparse.ArgumentParser) -> None:
    add_case_root_arg(parser)
    parser.add_argument("--engagement-id", "--id", required=True)
    parser.add_argument("--file")
    parser.add_argument("--lines", type=int, default=200)
    parser.add_argument(
        "--operation",
        help="Show only one op-v1 operation id.",
    )
    parser.add_argument(
        "--level",
        choices=tuple(operation_log.LEVELS),
        help="Show this severity and higher.",
    )
    parser.add_argument(
        "--since",
        help="Show entries since a duration (for example 30m) or ISO timestamp.",
    )
    parser.add_argument("--scope", help="Show only one scope, such as host or hunt.")
    parser.add_argument("--hunt-id", help="Show only one hunt or matching scope id.")
    parser.add_argument("--task-id", help="Show only one model task id.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfir logs",
        description=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    add_case_root_arg(list_parser)
    list_parser.add_argument("--engagement-id", "--id", required=True)
    for command in ("show", "follow"):
        _add_read_args(subparsers.add_parser(command))
    status_parser = subparsers.add_parser("status", help="Summarize retained operations and check local process state.")
    add_case_root_arg(status_parser)
    status_parser.add_argument("--engagement-id", "--id", required=True)
    status_parser.add_argument("--operation")
    status_parser.add_argument("--hunt-id")
    status_parser.set_defaults(file=None, lines=200, scope=None, task_id=None)
    return parser


def _read_selected(args: argparse.Namespace, path: Path) -> list[str]:
    lines = operation_log.validate_log(path)
    return _filter_lines(
        lines,
        operation=str(args.operation or ""),
        level=str(args.level or ""),
        since=_parse_since(args.since),
        scope=str(args.scope or ""),
        hunt_id=str(args.hunt_id or ""),
        task_id=str(args.task_id or ""),
    )


def _read_follow_chunk(
    path: Path,
    identity: tuple[int, int],
    offset: int,
    pending: str,
) -> tuple[tuple[int, int], int, str, list[str]]:
    """Read and validate complete lines appended since the previous poll."""
    try:
        current = path.stat()
    except FileNotFoundError:
        return identity, offset, pending, []
    if path.is_symlink() or not stat.S_ISREG(current.st_mode):
        raise ValueError(f"Progress log is not a regular file: {path}")
    if stat.S_IMODE(current.st_mode) != 0o600:
        raise ValueError(f"Progress log permissions must be 0600: {path}")
    if current.st_size > operation_log.MAX_FILE_BYTES:
        raise ValueError(
            f"Progress log exceeds {operation_log.MAX_FILE_BYTES} bytes: {path}"
        )
    current_identity = (current.st_dev, current.st_ino)
    if current_identity != identity or current.st_size < offset:
        identity = current_identity
        offset = 0
        pending = ""
    if current.st_size == offset:
        return identity, offset, pending, []
    with path.open("r", encoding="utf-8") as handle:
        handle.seek(offset)
        chunk = handle.read()
        offset = handle.tell()
    combined = pending + chunk
    parts = combined.splitlines(keepends=True)
    pending = ""
    complete: list[str] = []
    for part in parts:
        if not part.endswith(("\n", "\r")):
            pending = part
            continue
        line = part.rstrip("\r\n")
        if not operation_log.LOG_LINE_RE.fullmatch(line):
            raise ValueError(f"Progress log contains an invalid appended line: {path}")
        complete.append(line)
    return identity, offset, pending, complete


def _follow(args: argparse.Namespace, path: Path) -> int:
    selected = _read_selected(args, path)
    if selected:
        print("\n".join(selected[-args.lines :]), flush=True)
    stat_result = path.stat()
    identity = (stat_result.st_dev, stat_result.st_ino)
    offset = stat_result.st_size
    pending = ""
    since = _parse_since(args.since)
    while True:
        time.sleep(0.5)
        identity, offset, pending, complete = _read_follow_chunk(
            path,
            identity,
            offset,
            pending,
        )
        for line in _filter_lines(
            complete,
            operation=str(args.operation or ""),
            level=str(args.level or ""),
            since=since,
            scope=str(args.scope or ""),
            hunt_id=str(args.hunt_id or ""),
            task_id=str(args.task_id or ""),
        ):
            print(line, flush=True)


def _run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        directory = _log_dir(args)
        found = False
        for index in range(0, operation_log.MAX_LOG_FILES):
            suffix = "" if index == 0 else f".{index}"
            path = directory / f"{operation_log.LOG_FILENAME}{suffix}"
            if not path.is_file() or path.is_symlink():
                continue
            found = True
            print(f"{path} ({path.stat().st_size} bytes)")
        if not found:
            print(f"No Velociraptor progress log found under {directory}")
        return 0

    if not 1 <= args.lines <= operation_log.MAX_EVENTS:
        raise ValueError(f"--lines must be between 1 and {operation_log.MAX_EVENTS}")
    path = _resolve_log(args)
    if args.operation and not operation_log.OPERATION_ID_RE.fullmatch(args.operation):
        raise ValueError("--operation must be a complete op-v1 operation id")
    for option, value in (
        ("--scope", args.scope),
        ("--hunt-id", args.hunt_id),
        ("--task-id", args.task_id),
    ):
        if value and not operation_log.SAFE_IDENTIFIER_RE.fullmatch(value):
            raise ValueError(f"{option} must be a safe exact identifier")
    if args.command == "follow":
        return _follow(args, path)
    if args.command == "status":
        return _status(args, path)
    lines = _read_selected(args, path)
    if lines:
        print("\n".join(lines[-args.lines :]))
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
