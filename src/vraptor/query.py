from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from vraptor.common.cli_arguments import non_negative_int
from vraptor.common.cli_arguments import positive_int
from vraptor.paths import resolve_velociraptor_api_client_path
from vraptor.api import VeloApiClient
from vraptor.api import resolve_org_id


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
DEFAULT_QUERY_MAX_ROWS = 1000
DEFAULT_CLIENT_LIMIT = 1000
DEFAULT_BATCH_SIZE = 1000


def vql_string_literal(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def regex_pattern(value: str, *, exact: bool, ignore_case: bool) -> str:
    pattern = re.escape(value) if exact else value
    if exact:
        pattern = f"^{pattern}$"
    if ignore_case and not pattern.startswith("(?i)"):
        pattern = f"(?i){pattern}"
    return pattern


def build_client_vql(
    *,
    name: str = "",
    client_id: str = "",
    search: str = "",
    os_filters: Iterable[str] = (),
    ignore_case: bool = False,
) -> str:
    clauses: list[str] = []

    if name:
        pattern = vql_string_literal(
            regex_pattern(name, exact=True, ignore_case=ignore_case)
        )
        clauses.append(
            f"(os_info.hostname =~ {pattern} OR os_info.fqdn =~ {pattern})"
        )

    if client_id:
        pattern = vql_string_literal(
            regex_pattern(client_id, exact=True, ignore_case=ignore_case)
        )
        clauses.append(f"client_id =~ {pattern}")

    if search:
        pattern = vql_string_literal(
            regex_pattern(search, exact=False, ignore_case=ignore_case)
        )
        clauses.append(
            "("
            f"os_info.hostname =~ {pattern} OR "
            f"os_info.fqdn =~ {pattern} OR "
            f"client_id =~ {pattern}"
            ")"
        )

    normalized_os = sorted(
        {str(value).strip() for value in os_filters if str(value).strip()}
    )
    if normalized_os:
        os_pattern = "^(?:" + "|".join(re.escape(value) for value in normalized_os) + ")$"
        if ignore_case:
            os_pattern = f"(?i){os_pattern}"
        clauses.append(f"os_info.system =~ {vql_string_literal(os_pattern)}")

    where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return (
        "SELECT "
        "client_id, "
        "timestamp(epoch=first_seen_at) AS FirstSeen, "
        "timestamp(epoch=last_seen_at) AS LastSeen, "
        "os_info.hostname AS Hostname, "
        "os_info.fqdn AS Fqdn, "
        "os_info.system AS OSType, "
        "os_info.release AS OS, "
        "os_info.machine AS Machine, "
        "agent_information.version AS AgentVersion, "
        "last_ip AS LastIP, "
        "labels AS Labels "
        "FROM clients()"
        f"{where_clause} "
        "ORDER BY last_seen_at DESC"
    )


def parse_label_values(raw_value: Any) -> list[str]:
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return sorted(
            {str(item).strip() for item in raw_value if str(item).strip()}
        )
    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return sorted(
                {str(item).strip() for item in parsed if str(item).strip()}
            )
        return sorted(
            {token.strip() for token in stripped.split(",") if token.strip()}
        )
    return [str(raw_value).strip()] if str(raw_value).strip() else []


def parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def comparable_values(values: Iterable[str], *, ignore_case: bool) -> set[str]:
    normalized = {str(value).strip() for value in values if str(value).strip()}
    if ignore_case:
        return {value.casefold() for value in normalized}
    return normalized


def filter_client_rows(
    rows: Iterable[dict[str, Any]],
    *,
    required_labels: Iterable[str] = (),
    excluded_labels: Iterable[str] = (),
    online_within_minutes: int | None = None,
    limit: int = DEFAULT_CLIENT_LIMIT,
    ignore_case: bool = False,
    evaluated_at: datetime | None = None,
) -> tuple[list[dict[str, Any]], int]:
    required = comparable_values(required_labels, ignore_case=ignore_case)
    excluded = comparable_values(excluded_labels, ignore_case=ignore_case)
    now = (evaluated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    returned: list[dict[str, Any]] = []
    match_count = 0

    for raw_row in rows:
        labels = parse_label_values(raw_row.get("Labels"))
        comparable_labels = comparable_values(labels, ignore_case=ignore_case)
        if required and not required.issubset(comparable_labels):
            continue
        if excluded and excluded.intersection(comparable_labels):
            continue

        last_seen = parse_timestamp(raw_row.get("LastSeen"))
        age_seconds: float | None = None
        if last_seen is not None:
            age_seconds = max(0.0, (now - last_seen).total_seconds())
        if online_within_minutes is not None:
            if age_seconds is None or age_seconds > online_within_minutes * 60:
                continue

        match_count += 1
        if limit and len(returned) >= limit:
            continue

        row = dict(raw_row)
        row["Labels"] = labels
        if age_seconds is not None:
            row["LastSeenAgeSeconds"] = round(age_seconds, 3)
        returned.append(row)

    return returned, match_count


def parse_env(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_value in values:
        if "=" not in raw_value:
            raise ValueError(f"Invalid --env value {raw_value!r}; expected KEY=VALUE.")
        key, value = raw_value.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"Invalid VQL environment key: {key!r}")
        result[key] = value
    return result


def read_vql(args: argparse.Namespace) -> tuple[str, str]:
    if args.vql:
        query = str(args.vql)
        source = "argument"
    elif args.vql_file:
        path = Path(args.vql_file).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"VQL file not found: {path}")
        query = path.read_text(encoding="utf-8")
        source = str(path)
    else:
        if sys.stdin.isatty():
            raise ValueError("Provide --vql, --vql-file, or pipe VQL on stdin.")
        query = sys.stdin.read()
        source = "stdin"

    query = query.strip()
    if not query:
        raise ValueError("VQL query must not be empty.")
    return query, source


def run_vql_query(
    api: VeloApiClient,
    vql: str,
    *,
    env: dict[str, str] | None = None,
    max_rows: int = DEFAULT_QUERY_MAX_ROWS,
    timeout: int = 0,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    target_rows = max_rows + 1 if max_rows else 0

    for batch in api.query_batches(
        vql,
        env=env,
        timeout=timeout,
        max_row=batch_size,
    ):
        for row in batch:
            rows.append(row)
            if target_rows and len(rows) >= target_rows:
                return rows[:max_rows], True
    return rows, False


def resolve_connection(args: argparse.Namespace) -> tuple[Path, str]:
    api_client = resolve_velociraptor_api_client_path(
        getattr(args, "api_client", None),
        REPO_ROOT,
        server_profile=getattr(args, "server_profile", None),
    )
    if not api_client.is_file():
        raise FileNotFoundError(f"Velociraptor API client config not found: {api_client}")
    org_id = resolve_org_id(getattr(args, "org_id", None))
    return api_client, org_id


def emit_rows(payload: dict[str, Any], *, output_format: str) -> None:
    if output_format == "jsonl":
        for row in payload.get("rows") or payload.get("clients") or []:
            print(json.dumps(row, sort_keys=False, default=str))
        return
    print(json.dumps(payload, indent=2, sort_keys=False, default=str))


def command_query(args: argparse.Namespace) -> dict[str, Any]:
    vql, source = read_vql(args)
    api_client, org_id = resolve_connection(args)
    env = parse_env(args.env)
    with VeloApiClient(api_client, org_id=org_id) as api:
        rows, truncated = run_vql_query(
            api,
            vql,
            env=env,
            max_rows=args.max_rows,
            timeout=args.timeout,
            batch_size=args.batch_size,
        )
    return {
        "status": "ok",
        "action": "vql_query",
        "org_id": org_id,
        "query_source": source,
        "query_sha256": hashlib.sha256(vql.encode("utf-8")).hexdigest(),
        "row_count": len(rows),
        "truncated": truncated,
        "max_rows": args.max_rows,
        "rows": rows,
    }


def command_clients(args: argparse.Namespace) -> dict[str, Any]:
    api_client, org_id = resolve_connection(args)
    selector_name = str(getattr(args, "name", "") or "").strip()
    selector_client_id = str(getattr(args, "client_id", "") or "").strip()
    search = str(getattr(args, "search", "") or "").strip()
    query = build_client_vql(
        name=selector_name,
        client_id=selector_client_id,
        search=search,
        os_filters=args.os,
        ignore_case=args.ignore_case,
    )
    evaluated_at = datetime.now(timezone.utc)
    with VeloApiClient(api_client, org_id=org_id) as api:
        rows = api.query(query, max_row=args.batch_size)
    clients, match_count = filter_client_rows(
        rows,
        required_labels=args.label,
        excluded_labels=args.exclude_label,
        online_within_minutes=args.online_within_minutes,
        limit=args.limit,
        ignore_case=args.ignore_case,
        evaluated_at=evaluated_at,
    )
    return {
        "status": "ok",
        "action": f"clients_{args.client_command}",
        "org_id": org_id,
        "evaluated_at": evaluated_at.isoformat(),
        "filters": {
            "name": selector_name,
            "client_id": selector_client_id,
            "search": search,
            "os": list(args.os),
            "labels": list(args.label),
            "exclude_labels": list(args.exclude_label),
            "online_within_minutes": args.online_within_minutes,
            "ignore_case": args.ignore_case,
        },
        "match_count": match_count,
        "returned_count": len(clients),
        "limit": args.limit,
        "truncated": bool(args.limit and match_count > len(clients)),
        "clients": clients,
    }


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--api-client",
        help=(
            "Velociraptor API client YAML. Defaults to the selected "
            "<VELO_LOCAL_CONFIG_ROOT>/<server-profile>_api_client.yaml, then "
            "configured and default clients."
        ),
    )
    parser.add_argument(
        "--server-profile",
        "--id",
        dest="server_profile",
        help=(
            "Velociraptor server/config profile used for API-client resolution. "
            "The --id alias is retained for this instance-only command."
        ),
    )
    parser.add_argument("--org-id", help="Velociraptor org id. Defaults to the selected connection/environment, then root.")


def add_output_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "jsonl"),
        default="json",
        help="Output a metadata envelope as JSON or rows only as JSONL.",
    )


def add_client_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--os",
        action="append",
        default=[],
        help="Require an exact client OS type such as windows, linux, or darwin. Repeat as needed.",
    )
    parser.add_argument(
        "--label",
        "--tag",
        action="append",
        default=[],
        help="Require this exact client label. Repeated labels use AND semantics.",
    )
    parser.add_argument(
        "--exclude-label",
        "--exclude-tag",
        action="append",
        default=[],
        help="Exclude clients carrying this exact label. Repeat as needed.",
    )
    parser.add_argument(
        "--online-within-minutes",
        type=positive_int,
        help="Return only clients whose LastSeen is within this many minutes.",
    )
    parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Match name, search, OS, and label filters case-insensitively.",
    )
    parser.add_argument(
        "--limit",
        type=non_negative_int,
        default=DEFAULT_CLIENT_LIMIT,
        help="Maximum returned clients; use 0 for all matches.",
    )
    parser.add_argument(
        "--batch-size",
        type=positive_int,
        default=DEFAULT_BATCH_SIZE,
        help="Velociraptor gRPC response batch size.",
    )
    add_output_format_arg(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded VQL and discover Velociraptor clients."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    query = commands.add_parser(
        "query",
        help="Execute an operator-provided VQL query through the Velociraptor API.",
    )
    add_connection_args(query)
    source = query.add_mutually_exclusive_group()
    source.add_argument("--vql", help="Inline VQL query.")
    source.add_argument("--vql-file", help="Read VQL from a UTF-8 file.")
    query.add_argument(
        "--env",
        action="append",
        default=[],
        help="VQL environment value in KEY=VALUE form. Repeat as needed.",
    )
    query.add_argument(
        "--max-rows",
        type=non_negative_int,
        default=DEFAULT_QUERY_MAX_ROWS,
        help="Maximum returned rows; use 0 only for deliberate unbounded output.",
    )
    query.add_argument(
        "--batch-size",
        type=positive_int,
        default=DEFAULT_BATCH_SIZE,
        help="Velociraptor gRPC response batch size.",
    )
    query.add_argument(
        "--timeout",
        type=non_negative_int,
        default=0,
        help="Velociraptor query timeout in seconds; zero uses the server default.",
    )
    add_output_format_arg(query)

    clients = commands.add_parser(
        "clients",
        help="Find exact clients or list clients using inventory filters.",
    )
    client_commands = clients.add_subparsers(dest="client_command", required=True)

    find = client_commands.add_parser(
        "find",
        help="Find client details and labels by exact hostname, FQDN, or client id.",
    )
    add_connection_args(find)
    selector = find.add_mutually_exclusive_group(required=True)
    selector.add_argument("--name", help="Exact hostname or FQDN.")
    selector.add_argument("--client-id", help="Exact Velociraptor client id.")
    add_client_filter_args(find)

    list_clients = client_commands.add_parser(
        "list",
        help="List clients with optional name, OS, label, and online filters.",
    )
    add_connection_args(list_clients)
    list_clients.add_argument(
        "--search",
        help="Regex matched against hostname, FQDN, or client id.",
    )
    add_client_filter_args(list_clients)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "query":
            payload = command_query(args)
        else:
            payload = command_clients(args)
        emit_rows(payload, output_format=args.format)
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "action": str(getattr(args, "command", "") or ""),
                    "message": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
