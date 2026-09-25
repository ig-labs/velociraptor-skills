#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


DEFAULT_CONTEXT_CHARS = 180
DEFAULT_MAX_MATCHES = 5000
DEFAULT_SUMMARY_FIELDS = [
    "EventTime",
    "Timestamp",
    "Computer",
    "Fqdn",
    "Hostname",
    "Channel",
    "Provider",
    "EventID",
    "EventRecordID",
    "Username",
    "User",
    "AccountName",
    "ProcessName",
    "CommandLine",
    "ImagePath",
]
OUTPUT_FIELDS = [
    "RowNumber",
    "MatchedField",
    "MatchType",
    "MatchedPattern",
    "MatchedText",
    "Snippet",
    "SourceFile",
    *DEFAULT_SUMMARY_FIELDS,
]


def configure_csv_field_limit() -> int:
    limit = sys.maxsize
    while limit > 0:
        try:
            csv.field_size_limit(limit)
            return limit
        except OverflowError:
            limit //= 10
    return csv.field_size_limit()


CSV_FIELD_LIMIT = configure_csv_field_limit()


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collapse_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


@dataclass(frozen=True)
class MatchSpec:
    pattern: str
    match_type: str
    regex: re.Pattern[str]


def literal_to_regex(value: str, *, case_sensitive: bool) -> re.Pattern[str]:
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(re.escape(value), flags)


def compile_regex(value: str, *, case_sensitive: bool) -> re.Pattern[str]:
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile(value, flags)
    except re.error as exc:
        raise RuntimeError(f"Invalid regex pattern {value!r}: {exc}") from exc


def build_match_specs(literals: list[str], regexes: list[str], *, case_sensitive: bool) -> list[MatchSpec]:
    specs: list[MatchSpec] = []
    for literal in literals:
        text = str(literal or "").strip()
        if text:
            specs.append(MatchSpec(text, "literal", literal_to_regex(text, case_sensitive=case_sensitive)))
    for regex in regexes:
        text = str(regex or "").strip()
        if text:
            specs.append(MatchSpec(text, "regex", compile_regex(text, case_sensitive=case_sensitive)))
    if not specs:
        raise RuntimeError("At least one --literal or --regex value is required.")
    return specs


def selected_fields(headers: list[str], requested_fields: list[str]) -> list[str]:
    requested = [str(field or "").strip() for field in requested_fields if str(field or "").strip()]
    if requested:
        missing = [field for field in requested if field not in headers]
        if missing:
            raise RuntimeError(f"Requested field(s) not present in CSV header: {', '.join(missing)}")
        return requested
    return list(headers)


def snippet_for_match(text: str, start: int, end: int, context_chars: int) -> str:
    normalized = collapse_text(text)
    if normalized != text:
        matched_text = collapse_text(text[start:end])
        normalized_index = normalized.lower().find(matched_text.lower()) if matched_text else -1
        if normalized_index >= 0:
            start = normalized_index
            end = normalized_index + len(matched_text)
            text = normalized
    prefix_start = max(start - context_chars, 0)
    suffix_end = min(end + context_chars, len(text))
    snippet = text[prefix_start:suffix_end]
    if prefix_start > 0:
        snippet = "..." + snippet
    if suffix_end < len(text):
        snippet += "..."
    return collapse_text(snippet)


def iter_csv_rows(path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise RuntimeError(f"CSV file {path} has no header row.")
            for row_number, row in enumerate(reader, start=2):
                yield row_number, {str(key): str(value or "") for key, value in row.items() if key is not None}
    except csv.Error as exc:
        raise RuntimeError(f"CSV file {path} could not be parsed safely: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"CSV file {path} could not be read: {exc}") from exc


def output_row(
    *,
    source_path: Path,
    row_number: int,
    row: dict[str, str],
    field: str,
    spec: MatchSpec,
    match: re.Match[str],
    context_chars: int,
) -> dict[str, str]:
    text = row.get(field, "")
    result = {key: "" for key in OUTPUT_FIELDS}
    result.update(
        {
            "RowNumber": str(row_number),
            "MatchedField": field,
            "MatchType": spec.match_type,
            "MatchedPattern": spec.pattern,
            "MatchedText": collapse_text(match.group(0)),
            "Snippet": snippet_for_match(text, match.start(), match.end(), context_chars),
            "SourceFile": str(source_path),
        }
    )
    for field_name in DEFAULT_SUMMARY_FIELDS:
        result[field_name] = collapse_text(row.get(field_name, ""))
    return result


def review_evtx_csv(
    *,
    input_path: Path,
    output_path: Path,
    manifest_path: Path,
    literals: list[str],
    regexes: list[str],
    fields: list[str],
    context_chars: int,
    max_matches: int,
    case_sensitive: bool,
) -> dict[str, Any]:
    if context_chars < 0:
        raise RuntimeError("--context-chars must be zero or greater.")
    if max_matches <= 0:
        raise RuntimeError("--max-matches must be a positive integer.")
    paths = [("input", input_path), ("output", output_path), ("manifest", manifest_path)]
    for index, (label, path) in enumerate(paths):
        for other_label, other in paths[index + 1:]:
            if path.resolve() == other.resolve() or (
                path.exists() and other.exists() and path.samefile(other)
            ):
                raise RuntimeError(f"{label} and {other_label} must be different files.")
    specs = build_match_specs(literals, regexes, case_sensitive=case_sensitive)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    rows_read = 0
    matches_written = 0
    matched_rows: set[int] = set()
    matched_fields: dict[str, int] = {}
    matched_patterns: dict[str, int] = {}
    headers: list[str] = []
    search_fields: list[str] = []

    try:
        with input_path.open("r", encoding="utf-8", newline="") as input_handle:
            reader = csv.DictReader(input_handle)
            headers = list(reader.fieldnames or [])
            if not headers:
                raise RuntimeError(f"CSV file {input_path} has no header row.")
            search_fields = selected_fields(headers, fields)
            with output_path.open("w", encoding="utf-8", newline="") as output_handle:
                writer = csv.DictWriter(output_handle, fieldnames=OUTPUT_FIELDS)
                writer.writeheader()
                for rows_read, row in enumerate(reader, start=1):
                    normalized_row = {str(key): str(value or "") for key, value in row.items() if key is not None}
                    row_number = rows_read + 1
                    for field in search_fields:
                        value = normalized_row.get(field, "")
                        if not value:
                            continue
                        for spec in specs:
                            for match in spec.regex.finditer(value):
                                writer.writerow(
                                    output_row(
                                        source_path=input_path,
                                        row_number=row_number,
                                        row=normalized_row,
                                        field=field,
                                        spec=spec,
                                        match=match,
                                        context_chars=context_chars,
                                    )
                                )
                                matches_written += 1
                                matched_rows.add(row_number)
                                matched_fields[field] = matched_fields.get(field, 0) + 1
                                matched_patterns[spec.pattern] = matched_patterns.get(spec.pattern, 0) + 1
                                if matches_written >= max_matches:
                                    raise StopIteration
    except StopIteration:
        pass
    except csv.Error as exc:
        raise RuntimeError(f"CSV file {input_path} could not be parsed safely: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"CSV file {input_path} could not be read or written: {exc}") from exc

    manifest = {
        "reviewed_at": now_utc(),
        "input_file": str(input_path),
        "output_file": str(output_path),
        "manifest_file": str(manifest_path),
        "csv_field_size_limit": CSV_FIELD_LIMIT,
        "headers": headers,
        "searched_fields": search_fields,
        "literals": [spec.pattern for spec in specs if spec.match_type == "literal"],
        "regexes": [spec.pattern for spec in specs if spec.match_type == "regex"],
        "case_sensitive": case_sensitive,
        "context_chars": context_chars,
        "max_matches": max_matches,
        "truncated": matches_written >= max_matches,
        "rows_read": rows_read,
        "matched_row_count": len(matched_rows),
        "matches_written": matches_written,
        "matched_fields": dict(sorted(matched_fields.items())),
        "matched_patterns": dict(sorted(matched_patterns.items())),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review large-field EVTX CSV exports and write compact matched-term snippets."
    )
    parser.add_argument("--input", type=Path, required=True, help="Raw EVTX CSV export to review.")
    parser.add_argument("--output", type=Path, required=True, help="Snippet CSV output path.")
    parser.add_argument("--manifest", type=Path, help="Optional JSON manifest path. Defaults to <output>.manifest.json.")
    parser.add_argument("--literal", action="append", default=[], help="Literal term to search for. Repeat as needed.")
    parser.add_argument("--regex", action="append", default=[], help="Regex to search for. Repeat as needed.")
    parser.add_argument("--field", action="append", default=[], help="CSV field to search. Defaults to all fields.")
    parser.add_argument("--context-chars", type=int, default=DEFAULT_CONTEXT_CHARS)
    parser.add_argument("--max-matches", type=int, default=DEFAULT_MAX_MATCHES)
    parser.add_argument("--case-sensitive", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        manifest_path = args.manifest or args.output.with_suffix(args.output.suffix + ".manifest.json")
        payload = review_evtx_csv(
            input_path=args.input.expanduser(),
            output_path=args.output.expanduser(),
            manifest_path=manifest_path.expanduser(),
            literals=args.literal,
            regexes=args.regex,
            fields=args.field,
            context_chars=args.context_chars,
            max_matches=args.max_matches,
            case_sensitive=args.case_sensitive,
        )
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
