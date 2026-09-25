#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Iterator


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import cli_arguments as analysis_cli_arguments
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.autoruns import pipeline as autoruns
from vraptor.analyze import records as evidence_records
from vraptor.analyze import planning as review_planning

from vraptor.paths import add_case_root_arg
from vraptor.paths import default_case_root
from vraptor.paths import load_repo_env
from vraptor.common import token_budget
from vraptor.common.sequences import unique_ordered

load_repo_env(REPO_ROOT)
CASE_ROOT = default_case_root(REPO_ROOT)
TARGET_CHOICES = ("windows", "linux", "macos")
UNSCOPED_TARGET_NAMESPACE = "all"
TARGET_NAMESPACES = (UNSCOPED_TARGET_NAMESPACE, *TARGET_CHOICES)
CONTRACT_VERSION = "2"
DEFAULT_SAMPLE_LIMIT = 50
SUMMARY_SAMPLE_LIMIT = 3
DEFAULT_SUMMARY_CHARS = 240
DEFAULT_MAX_SOURCE_FIELDS = 8
GENERATED_REVIEW_FIELDS = (
    "ReviewArtifact",
    "ReviewTimestamp",
    "ReviewHost",
    "ReviewSummary",
)
DEFAULT_SAVED_HUNT_SAMPLE_FIELDS = (
    "EventTime",
    "Timestamp",
    "Time",
    "Hostname",
    "HostName",
    "Host",
    "Computer",
    "Fqdn",
    "Channel",
    "Provider",
    "EventID",
    "Description",
    "Message",
    "Path",
    "OSPath",
    "FileName",
    "Username",
    "UserName",
    "SourceIP",
    "CommandLine",
)
DEFAULT_SAVED_HUNT_SUMMARY_FIELDS = (
    "Description",
    "Message",
    "Path",
    "OSPath",
    "FileName",
    "CommandLine",
    "EventID",
    "Provider",
    "Username",
    "UserName",
    "SourceIP",
)
DEFAULT_SAVED_HUNT_TIMESTAMP_FIELDS = (
    "EventTime",
    "Timestamp",
    "Time",
    "Created0x10",
    "Created0x30",
    "LastModified0x10",
    "LastModified0x30",
    "Created",
    "LastModified",
)
DEFAULT_SAVED_HUNT_HOST_FIELDS = (
    "Hostname",
    "HostName",
    "Host",
    "Computer",
    "Fqdn",
    "ClientId",
)
HEADER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def configure_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit > 0:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


configure_csv_field_limit()


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path, description: str = "JSON file") -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"{description} {path} could not be read: {exc}") from exc
    except JSONDecodeError as exc:
        raise RuntimeError(f"{description} {path} is not valid JSON: {exc}") from exc


def read_json_object(path: Path, description: str) -> dict[str, Any]:
    payload = read_json(path, description=description)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{description} {path} is not a JSON object.")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip())
    return slug.strip("._") or "artifact"


def normalize_target_os(value: str | None) -> str:
    target = str(value or "").strip().lower()
    return target if target in TARGET_CHOICES else ""


def target_namespace(value: str | None) -> str:
    target = str(value or "").strip().lower()
    if target == UNSCOPED_TARGET_NAMESPACE:
        return UNSCOPED_TARGET_NAMESPACE
    return normalize_target_os(target) or UNSCOPED_TARGET_NAMESPACE


def normalize_case_root(path_value: str | None) -> Path:
    if path_value:
        return Path(path_value).expanduser().resolve()
    return CASE_ROOT


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build deterministic slim review artifacts from saved Velociraptor "
            "hunt exports or downloads."
        )
    )
    selector = parser.add_mutually_exclusive_group(required=False)
    selector.add_argument("--state-file", help="Path to a saved hunt state.json file.")
    selector.add_argument("--export-manifest", help="Path to exports/velociraptor-hunting-export.json.")
    selector.add_argument("--hunt-id", help="Analyze a saved hunt by investigation id and hunt id.")
    selector.add_argument("--snapshot", help="Path to an immutable hunt snapshot.json file.")
    parser.add_argument("--download-manifest", help="Optional path to downloads/velociraptor-hunting-download.json.")
    parser.add_argument("--investigation-id", help="Case folder name when resolving --hunt-id.")
    add_case_root_arg(parser)
    parser.add_argument(
        "--target",
        choices=TARGET_NAMESPACES,
        help="Optional target namespace when resolving --hunt-id. Use all for unscoped or label-scoped hunts.",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Limit analysis to one or more artifact labels or artifact names.",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=DEFAULT_SAMPLE_LIMIT,
        help="Number of source rows to sample when selecting review fields.",
    )
    analysis_cli_arguments.add_artifact_reference_argument(parser)
    analysis_cli_arguments.add_skip_ai_argument(parser)
    analysis_cli_arguments.add_snapshot_review_arguments(parser)
    return analysis_cli_arguments.normalize_snapshot_review_arguments(
        parser.parse_args(argv)
    )


def validate_args(args: argparse.Namespace) -> None:
    if not any((args.state_file, args.export_manifest, args.download_manifest, args.hunt_id, args.snapshot)):
        raise RuntimeError(
            "One of --snapshot, --state-file, --export-manifest, --download-manifest, or --hunt-id is required."
        )
    if args.hunt_id and (args.export_manifest or args.download_manifest):
        raise RuntimeError("--hunt-id cannot be combined with explicit manifest arguments.")
    if args.snapshot and args.download_manifest:
        raise RuntimeError("--snapshot cannot be combined with --download-manifest.")
    if args.hunt_id and not args.investigation_id:
        raise RuntimeError("--investigation-id is required with --hunt-id.")
    if args.sample_limit < 1:
        raise RuntimeError("--sample-limit must be at least 1.")


def artifact_matches_selector(entry: dict[str, Any], selectors: list[str]) -> bool:
    if not selectors:
        return True
    values = {
        str(entry.get(key) or "").strip()
        for key in (
            "artifact",
            "artifact_name",
            "artifact_source",
            "parent_artifact",
            "parent_artifact_name",
        )
        if str(entry.get(key) or "").strip()
    }
    return any(selector in values for selector in selectors)


def find_saved_state_by_hunt_id(case_root: Path, investigation_id: str, hunt_id: str, target: str | None = None) -> Path | None:
    state_path = case_root / investigation_id / "hunts" / hunt_id / "state.json"
    return state_path if state_path.exists() else None


def resolve_state_path(args: argparse.Namespace, case_root: Path) -> Path | None:
    if args.state_file:
        path = Path(args.state_file).expanduser().resolve()
        if not path.exists():
            raise RuntimeError(f"State file {path} was not found.")
        return path
    if args.hunt_id:
        state_path = find_saved_state_by_hunt_id(case_root, str(args.investigation_id), str(args.hunt_id), args.target)
        if state_path is not None:
            return state_path
        raise RuntimeError(
            f"Saved hunt state for investigation {args.investigation_id} and hunt {args.hunt_id} was not found."
        )
    return None


def resolve_manifest_path(path_value: str | None, description: str) -> Path | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser().resolve()
    if not path.exists():
        raise RuntimeError(f"{description} {path} was not found.")
    return path


def resolve_optional_manifest_path(path_value: str | None) -> Path | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser().resolve()
    if not path.exists():
        return None
    return path


def manifest_with_path(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = read_json_object(path, "Manifest")
    payload.setdefault("manifest_file", str(path))
    return payload


def int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_required_int(value: Any, description: str) -> int:
    parsed = int_or_none(value)
    if parsed is None:
        raise RuntimeError(f"{description} must be an integer, got {value!r}.")
    return parsed


def parse_manifest_row_count(item: dict[str, Any] | None, description: str) -> int:
    if item is None:
        return 0
    if "row_count" not in item:
        raise RuntimeError(f"{description} is required in the manifest.")
    return parse_required_int(item.get("row_count"), description)


def canonical_artifact_key(
    item: dict[str, Any],
    expected_spec_arguments: list[dict[str, Any]],
    requested_artifacts: list[str],
    allow_unmatched_fallback: bool = True,
) -> str:
    artifact_source = str(item.get("artifact_source") or "").strip()
    if artifact_source:
        return artifact_source
    candidates = unique_ordered(
        [
            str(item.get("artifact") or "").strip(),
            str(item.get("artifact_name") or "").strip(),
        ]
    )
    for spec in expected_spec_arguments:
        if not isinstance(spec, dict):
            continue
        label = str(spec.get("label") or "").strip()
        artifact = str(spec.get("artifact") or "").strip()
        aliases = {value for value in (label, artifact) if value}
        if aliases.intersection(candidates):
            return label or artifact
    for requested in requested_artifacts:
        requested_value = str(requested or "").strip()
        if requested_value and requested_value in candidates:
            return requested_value
    if not allow_unmatched_fallback:
        return ""
    for candidate in candidates:
        if candidate:
            return candidate
    return ""


def build_manifest_item_map(
    items: list[Any],
    expected_spec_arguments: list[dict[str, Any]],
    requested_artifacts: list[str],
    allow_unmatched_fallback: bool = True,
) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = canonical_artifact_key(
            item,
            expected_spec_arguments,
            requested_artifacts,
            allow_unmatched_fallback=allow_unmatched_fallback,
        )
        if not key:
            continue
        if key in mapped:
            raise RuntimeError(f"Manifest contains duplicate entries for artifact {key}.")
        mapped[key] = item
    return mapped


def hunt_dir_from_manifest_path(path: Path) -> Path:
    if path.parent.name not in {"exports", "downloads"}:
        raise RuntimeError(f"Manifest path {path} is not under exports/ or downloads/.")
    return path.parent.parent


def read_baseline_target_count(path: Path) -> int | None:
    if not path.exists():
        return None
    payload = read_json_object(path, "Baseline targets file")
    return int_or_none(payload.get("target_count"))


def sample_csv(path: Path, sample_limit: int) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            sample_text = handle.read(4096)
            handle.seek(0)
            try:
                has_header = csv.Sniffer().has_header(sample_text) if sample_text.strip() else False
            except (csv.Error, ValueError):
                has_header = False
            reader = csv.DictReader(handle)
            headers = list(reader.fieldnames or [])
            rows: list[dict[str, str]] = []
            for index, row in enumerate(reader):
                rows.append({str(key): str(value or "") for key, value in row.items() if key is not None})
                if index + 1 >= sample_limit:
                    break
            identifier_headers = bool(headers) and all(HEADER_NAME_RE.match(str(header or "")) for header in headers)
            if (not has_header and not identifier_headers) or (not rows and not identifier_headers):
                return [], []
    except OSError as exc:
        raise RuntimeError(f"CSV file {path} could not be read: {exc}") from exc
    return headers, rows


def iter_csv_rows(path: Path) -> Iterator[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                yield {str(key): str(value or "") for key, value in row.items() if key is not None}
    except OSError as exc:
        raise RuntimeError(f"CSV file {path} could not be read: {exc}") from exc


def sample_jsonl(path: Path, sample_limit: int) -> tuple[list[str], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    headers: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except JSONDecodeError as exc:
                    raise RuntimeError(f"JSONL file {path} contains invalid JSON on line {index}: {exc}") from exc
                if not isinstance(row, dict):
                    continue
                rows.append(row)
                for key in row:
                    if key in seen:
                        continue
                    seen.add(key)
                    headers.append(str(key))
                if len(rows) >= sample_limit:
                    break
    except OSError as exc:
        raise RuntimeError(f"JSONL file {path} could not be read: {exc}") from exc
    return headers, rows


def compact_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    return str(value)


def first_non_empty(row: dict[str, Any], candidates: list[str]) -> str:
    for key in candidates:
        value = compact_value(row.get(key))
        if value.strip():
            return value.strip()
    return ""


def truncate_text(text: str, limit: int = DEFAULT_SUMMARY_CHARS) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: max(limit - 3, 0)] + "..."


def build_review_summary(row: dict[str, Any], summary_fields: list[str], selected_source_fields: list[str]) -> str:
    fields = summary_fields or selected_source_fields
    parts: list[str] = []
    for field in fields:
        value = truncate_text(compact_value(row.get(field)))
        if not value:
            continue
        parts.append(f"{field}={value}")
        if len(parts) >= 4:
            break
    return " | ".join(parts)


def write_review_csv(path: Path, fieldnames: list[str], rows: Iterator[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    row_count = 0
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: compact_value(row.get(field)) for field in fieldnames})
            row_count += 1
    return row_count


def write_review_jsonl(path: Path, rows: Iterator[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    row_count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=False, default=str))
            handle.write("\n")
            row_count += 1
    return row_count


def build_saved_hunt_projection(
    artifact_profile_key: str,
    artifact_profile: dict[str, Any] | None,
    artifact_profile_resolution: str,
    artifact_entry: dict[str, Any],
    available_fields: list[str],
    sample_limit: int,
) -> dict[str, Any]:
    review = dict((artifact_profile or {}).get("review") or {})
    projection_config = dict(review.get("saved_hunt_projection") or {})
    field_candidates = [
        field
        for field in (review.get("sample_fields") or DEFAULT_SAVED_HUNT_SAMPLE_FIELDS)
        if field in available_fields
    ]
    max_source_fields = int(
        projection_config.get("max_source_fields", DEFAULT_MAX_SOURCE_FIELDS)
    )
    if not field_candidates:
        field_candidates = available_fields[:max_source_fields]
    selected_source_fields = field_candidates[:max_source_fields]
    summary_fields = [
        field
        for field in (
            projection_config.get("summary_fields")
            or DEFAULT_SAVED_HUNT_SUMMARY_FIELDS
        )
        if field in available_fields
    ]
    timestamp_fields = [
        field
        for field in (
            review.get("timestamp_fields")
            or DEFAULT_SAVED_HUNT_TIMESTAMP_FIELDS
        )
        if field in available_fields
    ]
    host_fields = [
        field
        for field in (review.get("host_fields") or DEFAULT_SAVED_HUNT_HOST_FIELDS)
        if field in available_fields
    ]
    output_fields = unique_ordered([*GENERATED_REVIEW_FIELDS, *selected_source_fields])
    projection = {
        "contract_version": CONTRACT_VERSION,
        "generated_at": now_utc(),
        "catalog_schema_version": artifact_profiles.SCHEMA_VERSION,
        "artifact_profile_key": artifact_profile_key,
        "artifact_profile_resolution": artifact_profile_resolution,
        "artifact_profile_hash": str((artifact_profile or {}).get("_profile_hash") or ""),
        "artifact_profile_sources": list((artifact_profile or {}).get("_provenance") or []),
        "artifact": artifact_entry["artifact"],
        "artifact_name": artifact_entry["artifact_name"],
        "available_fields": available_fields,
        "selected_source_fields": selected_source_fields,
        "summary_fields": summary_fields,
        "timestamp_fields": timestamp_fields,
        "host_fields": host_fields,
        "output_fields": output_fields,
        "sample_limit": sample_limit,
        "preserve_source_order": True,
    }
    projection["projection_hash"] = artifact_profiles.sha256_value(
        {
            key: value
            for key, value in projection.items()
            if key not in {"generated_at", "artifact_profile_sources"}
        }
    )
    return projection


def choose_primary_source(artifact_entry: dict[str, Any]) -> tuple[str, Path]:
    csv_file = artifact_entry.get("csv_file")
    jsonl_file = artifact_entry.get("jsonl_file")
    csv_headers = artifact_entry.get("csv_headers", [])
    csv_sample_rows = artifact_entry.get("csv_sample_rows", 0)
    expected_csv_rows = int(artifact_entry.get("row_count_csv") or 0)
    csv_exists = bool(csv_file) and Path(str(csv_file)).exists()
    jsonl_exists = bool(jsonl_file) and Path(str(jsonl_file)).exists()
    if csv_exists and csv_headers and int(csv_sample_rows or 0) > 0:
        return "csv", Path(str(csv_file))
    if jsonl_exists:
        return "jsonl", Path(str(jsonl_file))
    if csv_exists and expected_csv_rows == 0:
        return "csv", Path(str(csv_file))
    if csv_exists:
        raise RuntimeError(
            f"CSV file for artifact {artifact_entry['artifact']} appears to be headerless or empty and no JSONL fallback exists "
            f"(csv={csv_file or ''})."
        )
    if csv_file or jsonl_file:
        raise RuntimeError(
            f"No readable source file exists for artifact {artifact_entry['artifact']} "
            f"(csv={csv_file or ''}, jsonl={jsonl_file or ''})."
        )
    raise RuntimeError(f"No source file exists for artifact {artifact_entry['artifact']}.")


def transform_review_row(row: dict[str, Any], profile: dict[str, Any], artifact: str) -> dict[str, Any]:
    transformed: dict[str, Any] = {
        "ReviewArtifact": artifact,
        "ReviewTimestamp": first_non_empty(row, list(profile.get("timestamp_fields", []))),
        "ReviewHost": first_non_empty(row, list(profile.get("host_fields", []))),
        "ReviewSummary": build_review_summary(row, list(profile.get("summary_fields", [])), list(profile.get("selected_source_fields", []))),
    }
    for field in profile.get("selected_source_fields", []):
        transformed[field] = compact_value(row.get(field))
    return transformed


def artifact_output_stem(artifact: str) -> str:
    return safe_slug(artifact)


def build_artifact_entry(export_item: dict[str, Any] | None, download_item: dict[str, Any] | None, sample_limit: int) -> dict[str, Any]:
    item = export_item or download_item or {}
    parent_artifact = str(item.get("artifact") or item.get("artifact_name") or "")
    parent_artifact_name = str(item.get("artifact_name") or parent_artifact)
    artifact_source = str(item.get("artifact_source") or "").strip()
    artifact = artifact_source or parent_artifact
    artifact_name = artifact_source or parent_artifact_name or artifact
    csv_file = Path(str(export_item.get("output_file"))) if export_item and export_item.get("output_file") else None
    jsonl_file = Path(str(download_item.get("output_file"))) if download_item and download_item.get("output_file") else None
    csv_headers: list[str] = []
    csv_sample: list[dict[str, Any]] = []
    if csv_file and csv_file.exists():
        csv_headers, csv_sample = sample_csv(csv_file, sample_limit)
    jsonl_headers: list[str] = []
    jsonl_sample: list[dict[str, Any]] = []
    if jsonl_file and jsonl_file.exists():
        jsonl_headers, jsonl_sample = sample_jsonl(jsonl_file, sample_limit)
    available_fields = unique_ordered(csv_headers + jsonl_headers)
    return {
        "artifact": artifact,
        "artifact_name": artifact_name,
        "artifact_source": artifact_source,
        "parent_artifact": parent_artifact,
        "parent_artifact_name": parent_artifact_name,
        "csv_file": str(csv_file) if csv_file else "",
        "jsonl_file": str(jsonl_file) if jsonl_file else "",
        "row_count_csv": parse_manifest_row_count(export_item, f"Export row_count for artifact {artifact}"),
        "row_count_jsonl": parse_manifest_row_count(download_item, f"Download row_count for artifact {artifact}"),
        "csv_headers": csv_headers,
        "csv_sample_rows": len(csv_sample),
        "jsonl_headers": jsonl_headers,
        "available_fields": available_fields,
        "sample_rows": csv_sample if csv_sample else jsonl_sample,
    }


def merge_two_artifact_entries(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    preferred_artifact = left["artifact"] or right["artifact"]
    preferred_artifact_name = left["artifact_name"] or right["artifact_name"] or preferred_artifact
    csv_headers = unique_ordered(list(left.get("csv_headers", [])) + list(right.get("csv_headers", [])))
    jsonl_headers = unique_ordered(list(left.get("jsonl_headers", [])) + list(right.get("jsonl_headers", [])))
    available_fields = unique_ordered(csv_headers + jsonl_headers)
    return {
        "artifact": preferred_artifact,
        "artifact_name": preferred_artifact_name,
        "artifact_source": str(left.get("artifact_source") or right.get("artifact_source") or ""),
        "parent_artifact": str(left.get("parent_artifact") or right.get("parent_artifact") or ""),
        "parent_artifact_name": str(left.get("parent_artifact_name") or right.get("parent_artifact_name") or ""),
        "csv_file": str(left.get("csv_file") or right.get("csv_file") or ""),
        "jsonl_file": str(left.get("jsonl_file") or right.get("jsonl_file") or ""),
        "row_count_csv": int(left.get("row_count_csv") or right.get("row_count_csv") or 0),
        "row_count_jsonl": int(left.get("row_count_jsonl") or right.get("row_count_jsonl") or 0),
        "csv_headers": csv_headers,
        "csv_sample_rows": int(left.get("csv_sample_rows") or right.get("csv_sample_rows") or 0),
        "jsonl_headers": jsonl_headers,
        "available_fields": available_fields,
        "sample_rows": list(left.get("sample_rows") or right.get("sample_rows") or []),
    }


def normalize_aliases(entry: dict[str, Any]) -> set[str]:
    artifact_source = str(entry.get("artifact_source") or "").strip()
    if artifact_source:
        return {artifact_source}
    return {
        value
        for value in (
            str(entry.get("artifact") or "").strip(),
            str(entry.get("artifact_name") or "").strip(),
        )
        if value
    }


def coalesce_artifact_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for entry in entries:
        matched = False
        entry_aliases = normalize_aliases(entry)
        for index, existing in enumerate(merged):
            existing_aliases = normalize_aliases(existing)
            if entry_aliases.intersection(existing_aliases):
                merged[index] = merge_two_artifact_entries(existing, entry)
                matched = True
                break
        if not matched:
            merged.append(entry)
    return merged


def iter_review_source_rows(source_kind: str, source_path: Path, artifact_entry: dict[str, Any]) -> Iterator[dict[str, Any]]:
    if source_kind == "csv":
        yield from iter_csv_rows(source_path)
        return
    yield from iter_jsonl_rows(source_path)


def validate_matching_manifest_metadata(
    export_manifest_path: Path | None,
    export_manifest: dict[str, Any] | None,
    download_manifest_path: Path | None,
    download_manifest: dict[str, Any] | None,
) -> None:
    if export_manifest_path is not None and download_manifest_path is not None:
        export_hunt_dir = hunt_dir_from_manifest_path(export_manifest_path)
        download_hunt_dir = hunt_dir_from_manifest_path(download_manifest_path)
        if export_hunt_dir != download_hunt_dir:
            raise RuntimeError(
                "Export and download manifests do not refer to the same hunt directory: "
                f"{export_hunt_dir} != {download_hunt_dir}."
            )

    for field_name, field_label in (("investigation_id", "investigation id"), ("hunt_id", "hunt id")):
        values: list[tuple[str, str]] = []
        if export_manifest is not None:
            value = str(export_manifest.get(field_name) or "").strip()
            if value:
                values.append(("export manifest", value))
        if download_manifest is not None:
            value = str(download_manifest.get(field_name) or "").strip()
            if value:
                values.append(("download manifest", value))
        distinct_values = {value for _, value in values}
        if len(distinct_values) > 1:
            details = ", ".join(f"{source}={value}" for source, value in values)
            raise RuntimeError(f"Export and download manifests disagree on {field_label}: {details}.")


def normalize_requested_artifact_set(manifest: dict[str, Any] | None) -> set[str]:
    if manifest is None:
        return set()
    return {str(item).strip() for item in manifest.get("requested_artifacts", []) if str(item).strip()}


def normalize_expected_spec_set(manifest: dict[str, Any] | None) -> set[tuple[str, str]]:
    if manifest is None:
        return set()
    normalized: set[tuple[str, str]] = set()
    for item in manifest.get("expected_spec_arguments", []):
        if not isinstance(item, dict):
            continue
        normalized.add(
            (
                str(item.get("label") or "").strip(),
                str(item.get("artifact") or "").strip(),
            )
        )
    return normalized


def validate_manifest_scope_alignment(
    export_manifest: dict[str, Any] | None,
    download_manifest: dict[str, Any] | None,
) -> None:
    if export_manifest is None or download_manifest is None:
        return
    export_requested = normalize_requested_artifact_set(export_manifest)
    download_requested = normalize_requested_artifact_set(download_manifest)
    if export_requested and download_requested and export_requested != download_requested:
        raise RuntimeError(
            "Export and download manifests disagree on requested_artifacts: "
            f"{sorted(export_requested)} != {sorted(download_requested)}."
        )
    export_specs = normalize_expected_spec_set(export_manifest)
    download_specs = normalize_expected_spec_set(download_manifest)
    if export_specs and download_specs and export_specs != download_specs:
        raise RuntimeError(
            "Export and download manifests disagree on expected_spec_arguments."
        )


def validate_manifest_output_files(
    manifest: dict[str, Any] | None,
    manifest_kind: str,
    hunt_dir: Path,
) -> None:
    if manifest is None:
        return
    file_list_name = "exported_files" if manifest_kind == "export" else "downloaded_files"
    expected_dir = (hunt_dir / ("exports" if manifest_kind == "export" else "downloads")).resolve()
    for item in manifest.get(file_list_name, []):
        if not isinstance(item, dict):
            continue
        output_file_value = str(item.get("output_file") or "").strip()
        if not output_file_value:
            continue
        output_path = Path(output_file_value).expanduser().resolve()
        if not output_path.is_relative_to(expected_dir):
            raise RuntimeError(
                f"{manifest_kind.capitalize()} manifest output file {output_path} is outside the expected hunt "
                f"{expected_dir}."
            )


def promote_review_outputs(staging_dir: Path, review_dir: Path) -> None:
    if review_dir.exists():
        shutil.rmtree(review_dir)
    staging_dir.replace(review_dir)


def cleanup_staging_dir(staging_dir: Path) -> None:
    if staging_dir.exists():
        shutil.rmtree(staging_dir)


def prepare_review_staging_dir(hunt_dir: Path) -> tuple[Path, Path]:
    review_dir = hunt_dir / "review"
    staging_dir = hunt_dir / "review.__tmp__"
    cleanup_staging_dir(staging_dir)
    for child_name in ("by-artifact", "projections"):
        (staging_dir / child_name).mkdir(parents=True, exist_ok=True)
    return review_dir, staging_dir


def remap_artifact_result_paths(artifact_result: dict[str, Any], staging_dir: Path, review_dir: Path) -> dict[str, Any]:
    remapped = dict(artifact_result)
    for key in ("projection_file", "review_csv_file", "review_jsonl_file"):
        value = str(remapped.get(key) or "")
        if not value:
            continue
        relative_path = Path(value).resolve().relative_to(staging_dir.resolve())
        remapped[key] = str(review_dir / relative_path)
    return remapped


def validate_state_against_manifests(
    state_path: Path | None,
    state: dict[str, Any] | None,
    export_manifest_path: Path | None,
    export_manifest: dict[str, Any] | None,
    download_manifest_path: Path | None,
    download_manifest: dict[str, Any] | None,
) -> None:
    if state_path is None or state is None:
        return
    state_hunt_dir = state_path.parent
    manifest_paths = [path for path in (export_manifest_path, download_manifest_path) if path is not None]
    for manifest_path in manifest_paths:
        manifest_hunt_dir = hunt_dir_from_manifest_path(manifest_path)
        if manifest_hunt_dir != state_hunt_dir:
            raise RuntimeError(
                "Explicit manifest does not belong to the same hunt as the selected state file: "
                f"{manifest_hunt_dir} != {state_hunt_dir}."
            )

    state_investigation_id = str(state.get("investigation_id") or "").strip()
    state_hunt_id = str(state.get("hunt_id") or "").strip()
    for manifest_name, manifest in (("export manifest", export_manifest), ("download manifest", download_manifest)):
        if manifest is None:
            continue
        manifest_investigation_id = str(manifest.get("investigation_id") or "").strip()
        manifest_hunt_id = str(manifest.get("hunt_id") or "").strip()
        if state_investigation_id and manifest_investigation_id and state_investigation_id != manifest_investigation_id:
            raise RuntimeError(
                f"State file and {manifest_name} disagree on investigation id: "
                f"{state_investigation_id} != {manifest_investigation_id}."
            )
        if state_hunt_id and manifest_hunt_id and state_hunt_id != manifest_hunt_id:
            raise RuntimeError(
                f"State file and {manifest_name} disagree on hunt id: {state_hunt_id} != {manifest_hunt_id}."
            )


def resolve_input_contract(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    case_root = normalize_case_root(getattr(args, "case_root", None))
    state_path = resolve_state_path(args, case_root)
    state: dict[str, Any] | None = read_json_object(state_path, "State file") if state_path is not None else None

    export_manifest_path = resolve_manifest_path(args.export_manifest, "Export manifest")
    download_manifest_path = resolve_manifest_path(args.download_manifest, "Download manifest")
    hunt_dir: Path | None = state_path.parent if state_path is not None else None

    if state is not None:
        if export_manifest_path is None:
            latest_export = str(state.get("latest_export_manifest_file") or "").strip()
            export_manifest_path = resolve_optional_manifest_path(latest_export)
        if download_manifest_path is None:
            latest_download = str(state.get("latest_download_manifest_file") or "").strip()
            download_manifest_path = resolve_optional_manifest_path(latest_download)

    if export_manifest_path is None and download_manifest_path is None:
        raise RuntimeError("No hunt output manifest was found. Pass --state-file with saved manifests or an explicit manifest path.")

    explicit_manifest_mode = state_path is None and (export_manifest_path is not None or download_manifest_path is not None)
    if hunt_dir is None:
        manifest_path = export_manifest_path or download_manifest_path
        if manifest_path is None:
            raise RuntimeError("Could not resolve the hunt directory.")
        hunt_dir = hunt_dir_from_manifest_path(manifest_path)
        state_candidate = hunt_dir / "state.json"
        if not explicit_manifest_mode and state is None and state_candidate.exists():
            state = read_json_object(state_candidate, "State file")
            state_path = state_candidate

    export_manifest = manifest_with_path(export_manifest_path)
    download_manifest = manifest_with_path(download_manifest_path)
    validate_matching_manifest_metadata(export_manifest_path, export_manifest, download_manifest_path, download_manifest)
    if explicit_manifest_mode:
        validate_manifest_scope_alignment(export_manifest, download_manifest)
    validate_state_against_manifests(
        state_path,
        state,
        export_manifest_path,
        export_manifest,
        download_manifest_path,
        download_manifest,
    )
    baseline_path = hunt_dir / "baseline-targets.json"
    validate_manifest_output_files(export_manifest, "export", hunt_dir)
    validate_manifest_output_files(download_manifest, "download", hunt_dir)

    investigation_id = str(
        (state or {}).get("investigation_id")
        or (export_manifest or {}).get("investigation_id")
        or (download_manifest or {}).get("investigation_id")
        or ""
    )
    hunt_id = str(
        (state or {}).get("hunt_id")
        or (export_manifest or {}).get("hunt_id")
        or (download_manifest or {}).get("hunt_id")
        or ""
    )
    target_os = normalize_target_os((state or {}).get("target_os"))
    profile_key = str((state or {}).get("profile") or (state or {}).get("target_collection_type") or hunt_id)
    requested_artifacts = list(
        (state or {}).get("requested_artifacts")
        or (export_manifest or {}).get("requested_artifacts")
        or (download_manifest or {}).get("requested_artifacts")
        or []
    )
    requested_groups = list(
        (state or {}).get("requested_groups")
        or (export_manifest or {}).get("requested_groups")
        or (download_manifest or {}).get("requested_groups")
        or []
    )
    expected_spec_arguments = list(
        (state or {}).get("expected_spec_arguments")
        or (export_manifest or {}).get("expected_spec_arguments")
        or (download_manifest or {}).get("expected_spec_arguments")
        or []
    )
    target_collection_type = str(
        (state or {}).get("target_collection_type")
        or (export_manifest or {}).get("target_collection_type")
        or (download_manifest or {}).get("target_collection_type")
        or ""
    )
    baseline_target_count = int_or_none((state or {}).get("baseline_target_count"))
    if baseline_target_count is None:
        baseline_target_count = read_baseline_target_count(baseline_path)

    state_requested_artifacts = list((state or {}).get("requested_artifacts") or [])
    state_expected_spec_arguments = list((state or {}).get("expected_spec_arguments") or [])
    authoritative_requested_artifacts = state_requested_artifacts or requested_artifacts
    authoritative_expected_spec_arguments = state_expected_spec_arguments or expected_spec_arguments
    allow_unmatched_fallback = not bool(state is not None and (authoritative_requested_artifacts or authoritative_expected_spec_arguments))

    export_items = build_manifest_item_map(
        list((export_manifest or {}).get("exported_files", [])),
        authoritative_expected_spec_arguments,
        authoritative_requested_artifacts,
        allow_unmatched_fallback=allow_unmatched_fallback,
    )
    download_items = build_manifest_item_map(
        list((download_manifest or {}).get("downloaded_files", [])),
        authoritative_expected_spec_arguments,
        authoritative_requested_artifacts,
        allow_unmatched_fallback=allow_unmatched_fallback,
    )
    artifact_keys = unique_ordered(list(export_items.keys()) + list(download_items.keys()))
    artifact_entries = [
        build_artifact_entry(export_items.get(key), download_items.get(key), args.sample_limit)
        for key in artifact_keys
    ]
    artifact_entries = coalesce_artifact_entries(artifact_entries)
    selectors = [str(item) for item in getattr(args, "artifact", []) or [] if str(item).strip()]
    artifact_entries = [
        entry
        for entry in artifact_entries
        if artifact_matches_selector(entry, selectors)
    ]
    if not artifact_entries:
        raise RuntimeError("No matching artifact outputs were found for hunt analysis.")

    contract = {
        "contract_version": CONTRACT_VERSION,
        "generated_at": now_utc(),
        "investigation_id": investigation_id,
        "hunt_id": hunt_id,
        "target_os": target_os,
        "profile_key": profile_key,
        "hunt_description": str((state or {}).get("hunt_description") or ""),
        "state_file": str(state_path) if state_path is not None else "",
        "export_manifest_file": str(export_manifest_path) if export_manifest_path is not None else "",
        "download_manifest_file": str(download_manifest_path) if download_manifest_path is not None else "",
        "baseline_targets_file": str(baseline_path) if baseline_path.exists() else "",
        "target_collection_type": target_collection_type,
        "requested_groups": requested_groups,
        "requested_artifacts": requested_artifacts,
        "expected_spec_arguments": expected_spec_arguments,
        "review_readiness": str((state or {}).get("review_readiness") or ""),
        "completion_ratio": (state or {}).get("completion_ratio"),
        "baseline_target_count": baseline_target_count,
        "artifacts": artifact_entries,
    }
    return contract, hunt_dir


def analyze_artifact(
    review_dir: Path,
    artifact_entry: dict[str, Any],
    sample_limit: int,
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_kind, source_path = choose_primary_source(artifact_entry)
    source_available_fields = list(
        artifact_entry["csv_headers"] if source_kind == "csv" else artifact_entry["jsonl_headers"]
    )
    profile_key, artifact_profile, resolution = artifact_profiles.resolve_profile_match(
        artifact_entry["artifact"], profiles
    )
    if artifact_profile is None and artifact_entry["artifact_name"] != artifact_entry["artifact"]:
        profile_key, artifact_profile, resolution = artifact_profiles.resolve_profile_match(
            artifact_entry["artifact_name"], profiles
        )
    profile = build_saved_hunt_projection(
        profile_key,
        artifact_profile,
        resolution,
        artifact_entry,
        source_available_fields,
        sample_limit,
    )
    stem = artifact_output_stem(artifact_entry["artifact"])
    review_csv_path = review_dir / "by-artifact" / f"{stem}_review.csv"
    review_jsonl_path = review_dir / "by-artifact" / f"{stem}_review.jsonl"
    projection_path = review_dir / "projections" / f"{stem}_saved-hunt-projection.json"
    write_json(projection_path, profile)

    def transformed_rows() -> Iterator[dict[str, Any]]:
        iterator = iter_review_source_rows(source_kind, source_path, artifact_entry)
        for row in iterator:
            yield transform_review_row(row, profile, artifact_entry["artifact"])

    sample_rows: list[dict[str, Any]] = []

    def rows_with_samples() -> Iterator[dict[str, Any]]:
        for index, row in enumerate(transformed_rows()):
            if index < SUMMARY_SAMPLE_LIMIT:
                sample_rows.append(dict(row))
            yield row

    csv_count = write_review_csv(review_csv_path, list(profile["output_fields"]), rows_with_samples())
    jsonl_count = write_review_jsonl(
        review_jsonl_path,
        (transform_review_row(row, profile, artifact_entry["artifact"]) for row in iter_review_source_rows(source_kind, source_path, artifact_entry)),
    )
    expected_source_count = (
        int(artifact_entry["row_count_csv"])
        if source_kind == "csv"
        else int(artifact_entry["row_count_jsonl"])
    )
    actual_source_count = csv_count if source_kind == "csv" else jsonl_count
    if actual_source_count != expected_source_count:
        raise RuntimeError(
            f"{source_kind.upper()} row_count mismatch for artifact {artifact_entry['artifact']}: "
            f"manifest={expected_source_count}, actual={actual_source_count}."
        )

    return {
        "artifact": artifact_entry["artifact"],
        "artifact_name": artifact_entry["artifact_name"],
        "source_kind": source_kind,
        "source_file": str(source_path),
        "catalog_schema_version": profile["catalog_schema_version"],
        "artifact_profile_key": profile["artifact_profile_key"],
        "artifact_profile_resolution": profile["artifact_profile_resolution"],
        "artifact_profile_hash": profile["artifact_profile_hash"],
        "artifact_profile_sources": profile["artifact_profile_sources"],
        "projection_hash": profile["projection_hash"],
        "available_fields": artifact_entry["available_fields"],
        "selected_source_fields": profile["selected_source_fields"],
        "summary_fields": profile["summary_fields"],
        "timestamp_fields": profile["timestamp_fields"],
        "host_fields": profile["host_fields"],
        "output_fields": profile["output_fields"],
        "projection_file": str(projection_path),
        "review_csv_file": str(review_csv_path),
        "review_jsonl_file": str(review_jsonl_path),
        "review_row_count_csv": csv_count,
        "review_row_count_jsonl": jsonl_count,
        "sample_rows": sample_rows,
    }


STACK_ANALYSIS_VERSION = 8
STACK_EXAMPLE_LIMIT = 3
STACK_DISPLAY_CHARS = 500
STACK_EXAMPLE_CHARS = 1200
STACK_GUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
STACK_SID_RE = re.compile(r"(?i)\bS-1-(?:\d+-){1,14}\d+\b")
STACK_USER_PATH_RE = re.compile(
    r"(?i)((?:[A-Z]:)?\\(?:Users|Documents and Settings)\\)[^\\\s\"]+"
)
STACK_WHITESPACE_RE = re.compile(r"\s+")


def snapshot_result_path(snapshot_dir: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = snapshot_dir / path
    return path.resolve()


def iter_jsonl_rows(path: Path) -> Iterator[dict[str, Any]]:
    for _, row in iter_jsonl_rows_with_line(path):
        yield row


def iter_jsonl_rows_with_line(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except JSONDecodeError as exc:
                raise RuntimeError(f"Invalid JSONL in {path} at line {line_number}: {exc}") from exc
            if isinstance(row, dict):
                yield line_number, row


def decode_canonical_csv_value(value: str) -> Any:
    text = value.strip()
    if text.startswith(("{", "[")):
        try:
            return json.loads(text)
        except JSONDecodeError:
            return value
    return value


def iter_canonical_csv_rows_with_line(
    path: Path,
) -> Iterator[tuple[int, dict[str, Any]]]:
    configure_csv_field_limit()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise RuntimeError(f"Snapshot CSV has no header: {path}")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise RuntimeError(f"Snapshot CSV has duplicate header fields: {path}")
        for source_index, csv_row in enumerate(reader, start=1):
            row: dict[str, Any] = {}
            for field, value in csv_row.items():
                if field is None:
                    raise RuntimeError(
                        f"Snapshot CSV row has more values than headers: {path}"
                    )
                if value is None:
                    raise RuntimeError(
                        f"Snapshot CSV row has fewer values than headers: {path}"
                    )
                if value == "":
                    continue
                row[field] = decode_canonical_csv_value(value)
            yield source_index, row


def snapshot_uses_canonical_csv_chunks(snapshot: dict[str, Any]) -> bool:
    return (
        int(snapshot.get("snapshot_version") or 1) >= 2
        and str(snapshot.get("chunk_format") or "")
        == "canonical-csv-v1"
    )


def normalize_snapshot_manifest(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return the stable internal snapshot view used by analysis.

    Snapshot v2 already uses this shape. Snapshot v3 stores the same evidence
    contract with compact nested names and relative chunk paths.
    """
    if int(snapshot.get("snapshot_version") or 1) < 3:
        return snapshot
    hunt = snapshot.get("hunt")
    chunking = snapshot.get("chunking")
    artifacts = snapshot.get("artifacts")
    if not isinstance(hunt, dict):
        raise RuntimeError("Snapshot v3 does not contain a hunt object.")
    if not isinstance(chunking, dict):
        raise RuntimeError("Snapshot v3 does not contain a chunking object.")
    if not isinstance(artifacts, list):
        raise RuntimeError("Snapshot v3 does not contain an artifacts list.")
    results: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        chunk_root = Path(str(artifact.get("chunk_root") or ""))
        files: list[dict[str, Any]] = []
        for chunk in artifact.get("chunks") or []:
            if not isinstance(chunk, dict):
                continue
            chunk_hash = str(chunk.get("hash") or "")
            files.append(
                {
                    "file": str(chunk_root / str(chunk.get("path") or "")),
                    "partition": str(chunk.get("partition") or ""),
                    "row_count": int(chunk.get("rows") or 0),
                    "size_bytes": int(chunk.get("bytes") or 0),
                    "estimated_tokens": int(chunk.get("tokens") or 0),
                    "sha256": chunk_hash,
                    "chunk_hash": chunk_hash,
                }
            )
        results.append(
            {
                "artifact": str(
                    artifact.get("label")
                    or artifact.get("name")
                    or "artifact"
                ),
                "artifact_name": str(
                    artifact.get("name")
                    or artifact.get("label")
                    or "artifact"
                ),
                "expected_row_count": int(
                    artifact.get("expected_rows") or 0
                ),
                "extracted_row_count": int(
                    artifact.get("extracted_rows") or 0
                ),
                "complete": str(artifact.get("status") or "") == "complete",
                "vql_select": list(artifact.get("projection") or ["*"]),
                "files": files,
            }
        )
    status = str(snapshot.get("status") or "")
    return {
        "snapshot_version": int(snapshot.get("snapshot_version") or 3),
        "created_at": str(snapshot.get("created_at") or ""),
        "hunt_id": str(hunt.get("id") or ""),
        "group": str(hunt.get("group") or ""),
        "hunt_description": str(hunt.get("description") or ""),
        "fingerprint": str(snapshot.get("fingerprint") or ""),
        "status": status,
        "consistent": status == "complete",
        "chunk_format": str(chunking.get("format") or ""),
        "max_tokens_per_chunk": int(chunking.get("max_tokens") or 0),
        "token_encoding": str(chunking.get("encoding") or ""),
        "token_estimator": str(chunking.get("estimator") or ""),
        "results": results,
    }


def row_partition(row: dict[str, Any]) -> str:
    for key in ("ClientId", "client_id", "Fqdn", "Hostname", "HostName", "ComputerName"):
        value = str(row.get(key) or "").strip()
        if value:
            return f"{key}-{safe_slug(value)}"
    return "unscoped"


def stack_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return str(value).strip()


def nested_row_value(row: dict[str, Any], field: str) -> Any:
    current: Any = row
    for part in str(field).split("."):
        if isinstance(current, str):
            text = current.strip()
            if text.startswith("{"):
                try:
                    current = json.loads(text)
                except JSONDecodeError:
                    return None
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def normalize_stack_text(value: str, kind: str) -> str:
    text = STACK_WHITESPACE_RE.sub(" ", str(value or "")).strip()
    if not text:
        return ""
    if kind == "windows_path":
        text = text.replace("/", "\\")
    if kind == "autoruns_user_path":
        text = autoruns.normalize_user_path(text)
    else:
        text = STACK_USER_PATH_RE.sub(r"\1<USER>", text)
    text = STACK_GUID_RE.sub("<GUID>", text)
    text = STACK_SID_RE.sub("<SID>", text)
    if kind in {
        "autoruns_user_path",
        "detectraptor_evtx",
        "windows_path",
        "powershell_command",
        "command_line",
        "registry_path",
    }:
        text = text.casefold()
    return text


def normalizer_value(row: dict[str, Any], normalizer: dict[str, Any]) -> str:
    values = [
        stack_string(nested_row_value(row, field))
        for field in normalizer.get("source_fields", [])
    ]
    values = [value for value in values if value]
    if not values:
        return ""
    if normalizer.get("mode") == "join_non_empty":
        source = " | ".join(values)
    else:
        source = values[0]
    return normalize_stack_text(source, str(normalizer.get("kind") or "identity"))


def stack_dimension_values(
    row: dict[str, Any],
    profile: dict[str, Any],
    stack: dict[str, Any],
) -> list[str]:
    review = profile.get("review", {})
    normalizers = {
        str(item.get("output") or ""): item
        for item in review.get("normalizers", [])
        if isinstance(item, dict)
    }
    values: list[str] = []
    for field in stack.get("dimensions", []):
        if field in normalizers:
            value = normalizer_value(row, normalizers[field])
        else:
            value = stack_string(nested_row_value(row, field))
        values.append(value)
    return values


def first_stack_value(row: dict[str, Any], fields: list[str]) -> str:
    for field in fields:
        value = stack_string(nested_row_value(row, field))
        if value:
            return value
    return ""


def bounded_stack_value(value: Any, limit: int) -> Any:
    if isinstance(value, dict):
        return {
            str(key): bounded_stack_value(item, limit)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [bounded_stack_value(item, limit) for item in value[:20]]
    text = stack_string(value)
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def stack_example_row(row: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    fields = list(profile.get("review", {}).get("sample_fields", []))
    output: dict[str, Any] = {}
    for field in fields:
        value = nested_row_value(row, field)
        if value not in (None, "", [], {}):
            output[field] = bounded_stack_value(value, STACK_EXAMPLE_CHARS)
    return output


class StackViewAccumulator:
    def __init__(self, stack_id: str, stack: dict[str, Any]):
        self.stack_id = stack_id
        self.stack = stack
        self.rows_stacked = 0
        self.groups: dict[tuple[str, ...], dict[str, Any]] = {}

    def add(self, row: dict[str, Any], profile: dict[str, Any]) -> bool:
        dimensions = stack_dimension_values(row, profile, self.stack)
        if not dimensions or any(not value for value in dimensions):
            return False
        self.rows_stacked += 1
        key = tuple(dimensions)
        review = profile.get("review", {})
        group = self.groups.setdefault(
            key,
            {
                "count": 0,
                "hosts": set(),
                "first_seen": "",
                "last_seen": "",
                "examples": [],
            },
        )
        group["count"] += 1
        host = first_stack_value(row, list(review.get("host_fields", [])))
        if host:
            group["hosts"].add(host)
        timestamp = first_stack_value(row, list(review.get("timestamp_fields", [])))
        if timestamp:
            if not group["first_seen"] or timestamp < group["first_seen"]:
                group["first_seen"] = timestamp
            if not group["last_seen"] or timestamp > group["last_seen"]:
                group["last_seen"] = timestamp
        if len(group["examples"]) < STACK_EXAMPLE_LIMIT:
            example = stack_example_row(row, profile)
            if example:
                group["examples"].append(example)
        return True

    def finish(self, profile: dict[str, Any], rows_seen: int) -> dict[str, Any]:
        dimensions = list(self.stack.get("dimensions", []))
        max_groups = int(self.stack.get("max_groups", 10000))
        ordered = sorted(
            self.groups.items(),
            key=lambda item: (-int(item[1]["count"]), item[0]),
        )
        groups: list[dict[str, Any]] = []
        for key, value in ordered[:max_groups]:
            groups.append(
                {
                    "key_sha256": artifact_profiles.sha256_value(list(key)),
                    "values": {
                        dimension: bounded_stack_value(item, STACK_DISPLAY_CHARS)
                        for dimension, item in zip(dimensions, key)
                    },
                    "count": value["count"],
                    "distinct_host_count": len(value["hosts"]),
                    "first_seen": value["first_seen"],
                    "last_seen": value["last_seen"],
                    "examples": value["examples"],
                }
            )
        return {
            "stack_id": self.stack_id,
            "purpose": self.stack.get("purpose", ""),
            "priority": int(self.stack.get("priority", 100)),
            "analysis_route": self.stack.get("analysis_route")
            or profile.get("analysis_routes", {}).get("chunk_review", ""),
            "dimensions": dimensions,
            "server_dimensions": list(self.stack.get("server_dimensions", [])),
            "collection_parameters": dict(self.stack.get("collection_parameters", {})),
            "metrics": list(self.stack.get("metrics", [])),
            "rows_seen": rows_seen,
            "rows_stacked": self.rows_stacked,
            "rows_unstacked": rows_seen - self.rows_stacked,
            "group_count": len(self.groups),
            "returned_group_count": len(groups),
            "groups_truncated": len(self.groups) > max_groups,
            "groups": groups,
        }


class ProfileStackAccumulator:
    def __init__(self, artifact: str, artifact_name: str, profile: dict[str, Any] | None):
        self.artifact = artifact
        self.artifact_name = artifact_name
        self.profile = profile
        self.rows_seen = 0
        self.rows_stacked = 0
        self.views = {
            stack_id: StackViewAccumulator(stack_id, stack)
            for stack_id, stack in artifact_profiles.ordered_stack_views(profile or {})
        }

    def add(self, row: dict[str, Any]) -> None:
        self.rows_seen += 1
        if not self.profile:
            return
        stacked = False
        for view in self.views.values():
            stacked = view.add(row, self.profile) or stacked
        if stacked:
            self.rows_stacked += 1

    def finish(self) -> dict[str, Any]:
        if not self.profile:
            return {
                "stack_analysis_version": STACK_ANALYSIS_VERSION,
                "status": "no_artifact_profile",
                "artifact": self.artifact,
                "artifact_name": self.artifact_name,
                "rows_seen": self.rows_seen,
                "rows_stacked": 0,
                "rows_unstacked": self.rows_seen,
                "default_stack": "",
                "stack_count": 0,
                "stacks": {},
            }
        review = self.profile.get("review", {})
        stack_results = {
            stack_id: view.finish(self.profile, self.rows_seen)
            for stack_id, view in self.views.items()
        }
        return {
            "stack_analysis_version": STACK_ANALYSIS_VERSION,
            "status": "ok" if stack_results else "profile_has_no_stacks",
            "artifact": self.artifact,
            "artifact_name": self.artifact_name,
            "profile_hash": self.profile.get("_profile_hash", ""),
            "profile_sources": self.profile.get("_provenance", []),
            "strategy": review.get("strategy", ""),
            "default_stack": review.get("default_stack", ""),
            "stack_count": len(stack_results),
            "stack_ids": list(stack_results),
            "analysis_routes": self.profile.get("analysis_routes", {}),
            "rows_seen": self.rows_seen,
            "rows_stacked": self.rows_stacked,
            "rows_unstacked": self.rows_seen - self.rows_stacked,
            "stacks": stack_results,
        }


def profile_stack(rows: list[dict[str, Any]], artifact: str, artifact_name: str, profile: dict[str, Any] | None) -> dict[str, Any]:
    accumulator = ProfileStackAccumulator(artifact, artifact_name, profile)
    for row in rows:
        accumulator.add(row)
    return accumulator.finish()


def chunk_analysis_payload(
    *,
    chunk_hash: str,
    chunk_file: Path,
    artifact: str,
    artifact_name: str,
    partition: str,
    rows: list[dict[str, Any]],
    size_bytes: int,
    estimated_tokens: int,
    token_encoding: str,
    profile: dict[str, Any] | None,
    include_sample_rows: bool = True,
) -> dict[str, Any]:
    payload = {
        "analysis_version": STACK_ANALYSIS_VERSION,
        "chunk_hash": chunk_hash,
        "chunk_file": str(chunk_file),
        "artifact": artifact,
        "artifact_name": artifact_name,
        "partition": partition,
        "row_count": len(rows),
        "size_bytes": size_bytes,
        "estimated_tokens": estimated_tokens,
        "token_estimator": token_budget.token_estimator_name(token_encoding),
        "fields": sorted({str(key) for row in rows for key in row}),
        "stack_profile_hash": str((profile or {}).get("_profile_hash") or ""),
        "stacks": profile_stack(rows, artifact, artifact_name, profile),
        "model_review": {
            "status": "planned_at_artifact_level",
            "dispatch_rule": (
                "Use the artifact model-review manifest. Do not submit every raw "
                "chunk solely because it exists."
            ),
            "required_output": [
                "findings",
                "notable_rows",
                "entities",
                "confidence",
                "rationale",
            ],
        },
    }
    if include_sample_rows:
        payload["sample_rows"] = rows[:3]
    return payload


def artifact_review_route(
    profile: dict[str, Any] | None,
    override: str | None,
) -> str:
    if str(override or "").strip():
        return analysis_limits.analysis_route(override)
    profile_route = str(
        (profile or {}).get("analysis_routes", {}).get("chunk_review") or ""
    ).strip()
    return analysis_limits.analysis_route(profile_route or None)


def direct_chunk_term_matches(
    chunk: dict[str, Any],
    terms: list[str],
) -> int:
    if not terms:
        return 0
    searchable = json.dumps(
        chunk.get("_rows", []),
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    ).casefold()
    return sum(
        1
        for term in terms
        if str(term).strip().casefold() in searchable
    )


def build_direct_chunk_review_plan(
    chunks: list[dict[str, Any]],
    *,
    artifact: str,
    limits: analysis_limits.AnalysisLimits,
    route: str,
    review_mode: str,
    maximum_total_analysis_tokens: int | None,
    terms: list[str],
    selection_policy: str,
) -> dict[str, Any]:
    routing = analysis_limits.analysis_routing(route)
    decorated: list[dict[str, Any]] = []
    normalized_terms = [
        str(term).strip() for term in terms if str(term).strip()
    ]
    for source_index, chunk in enumerate(chunks):
        item = dict(chunk)
        item["_source_index"] = source_index
        item["_term_match_count"] = direct_chunk_term_matches(
            item,
            normalized_terms,
        )
        decorated.append(item)

    if review_mode == "selective":
        budget = int(maximum_total_analysis_tokens or 0)
        if selection_policy == "indicator-first":
            ranked = sorted(
                decorated,
                key=lambda item: (
                    -int(item["_term_match_count"]),
                    int(item["row_count"]),
                    int(item["_source_index"]),
                    str(item["chunk_hash"]),
                ),
            )
        elif selection_policy == "rare-first":
            ranked = sorted(
                decorated,
                key=lambda item: (
                    int(item["row_count"]),
                    -int(item["_term_match_count"]),
                    int(item["_source_index"]),
                    str(item["chunk_hash"]),
                ),
            )
        else:
            raise review_planning.ReviewPlanningError(
                f"Unknown evidence selection policy {selection_policy!r}."
            )
        selected: list[dict[str, Any]] = []
        selected_tokens = 0
        oversized: list[str] = []
        for chunk in ranked:
            chunk_tokens = int(chunk["estimated_tokens"])
            if chunk_tokens > budget:
                oversized.append(str(chunk["chunk_hash"]))
                continue
            if selected_tokens + chunk_tokens > budget:
                continue
            selected.append(chunk)
            selected_tokens += chunk_tokens
    else:
        selected = decorated
        selected_tokens = sum(
            int(chunk["estimated_tokens"]) for chunk in selected
        )
        oversized = []
        if (
            maximum_total_analysis_tokens is not None
            and selected_tokens > maximum_total_analysis_tokens
        ):
            raise review_planning.ReviewPlanningError(
                "Exhaustive snapshot CSV chunks require "
                f"{selected_tokens} tokens, exceeding "
                "maximum_total_analysis_tokens="
                f"{maximum_total_analysis_tokens}. Increase the ceiling or "
                "use --review-mode selective."
            )

    selected_hashes = {
        str(chunk["chunk_hash"]) for chunk in selected
    }
    matched_hashes = {
        str(chunk["chunk_hash"])
        for chunk in decorated
        if int(chunk["_term_match_count"]) > 0
    }
    packages = [
        {
            "package_id": f"chunk-{index:06d}",
            "chunk_hash": str(chunk["chunk_hash"]),
            "partition": str(chunk["partition"]),
            "row_count": int(chunk["row_count"]),
            "package_csv_file": str(chunk["chunk_file"]),
            "package_csv_tokens": int(chunk["estimated_tokens"]),
            "package_csv_size_bytes": int(chunk["size_bytes"]),
            "source_snapshot_chunk": True,
        }
        for index, chunk in enumerate(selected, start=1)
    ]
    selected_rows = sum(int(chunk["row_count"]) for chunk in selected)
    candidate_rows = sum(int(chunk["row_count"]) for chunk in decorated)
    complete = len(selected) == len(decorated)
    return {
        "review_plan_version": review_planning.REVIEW_PLAN_VERSION,
        "artifact": artifact,
        "status": "ready" if packages else "empty",
        "review_mode": review_mode,
        "analysis_limits": limits.as_dict(),
        "analysis_routing": routing,
        "selection": {
            "review_mode": review_mode,
            "selection_policy": (
                selection_policy if review_mode == "selective" else ""
            ),
            "selection_terms": (
                normalized_terms if review_mode == "selective" else []
            ),
            "maximum_total_analysis_tokens": (
                maximum_total_analysis_tokens
                if review_mode == "selective"
                else None
            ),
            "candidate_evidence_count": candidate_rows,
            "selected_evidence_count": selected_rows,
            "unselected_evidence_count": candidate_rows - selected_rows,
            "selected_evidence_tokens": selected_tokens,
            "token_estimator": token_budget.token_estimator_name(
                limits.token_encoding
            ),
            "matched_evidence_count": sum(
                int(chunk["row_count"])
                for chunk in decorated
                if int(chunk["_term_match_count"]) > 0
            ),
            "selected_matched_evidence_count": sum(
                int(chunk["row_count"])
                for chunk in selected
                if str(chunk["chunk_hash"]) in matched_hashes
            ),
            "oversized_evidence_ids": oversized,
            "complete_evidence_coverage": complete,
            "selection_truncated": not complete,
        },
        "package_count": len(packages),
        "packages": packages,
        "source_chunk_count": len(decorated),
        "selected_chunk_count": len(selected_hashes),
        "evidence_materialization": "snapshot_csv_chunks_reused_in_place",
    }


def materialize_direct_chunk_review_plan(
    plan: dict[str, Any],
    *,
    artifact: str,
    model_review_root: Path,
    snapshot_output: str,
) -> tuple[dict[str, Any], Path | None]:
    if snapshot_output != "derived":
        return plan, None
    manifest_path = (
        model_review_root / "artifacts" / f"{safe_slug(artifact)}.json"
    )
    write_json(manifest_path, plan)
    return plan, manifest_path


def write_markdown_summary(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"# Hunt snapshot analysis: {summary['hunt_id']}",
        "",
        f"- Snapshot: `{summary['snapshot_file']}`",
        f"- Content fingerprint: `{summary['fingerprint']}`",
        f"- Rows prepared: {summary['row_count']}",
        f"- Chunks: {summary['chunk_count']}",
        f"- Reused chunk analyses: {summary['reused_chunk_analysis_count']}",
        f"- New chunk analyses: {summary['new_chunk_analysis_count']}",
        f"- Partitions: {summary['partition_count']}",
        f"- Raw evidence tokens: {summary.get('raw_evidence_tokens', 0)}",
        f"- Deduplicated evidence tokens: {summary.get('deduplicated_evidence_tokens', 0)}",
        f"- Packaged evidence tokens: {summary.get('packaged_evidence_tokens', 0)}",
        f"- Complete evidence coverage: {summary.get('complete_evidence_coverage', False)}",
        f"- Model-review packages: {summary.get('model_review_package_count', 0)}",
        "",
        "## Artifact inventory",
        "",
    ]
    for artifact in summary["artifacts"]:
        lines.append(
            f"- `{artifact['artifact']}`: {artifact['row_count']} rows, "
            f"{artifact['chunk_count']} chunks, {artifact['partition_count']} partitions, "
            f"{artifact.get('unique_evidence_count', 0)} unique evidence records, "
            f"{artifact.get('packaged_evidence_tokens', 0)} packaged evidence tokens, "
            f"stack `{artifact.get('stack_status', '')}` on "
            f"{', '.join(artifact.get('stack_dimensions', [])) or 'no configured dimensions'}"
        )
    lines.extend(
        [
            "",
            "## Review rule",
            "",
            "Dispatch every bounded package in exhaustive mode. Use selective "
            "mode only when an explicit total evidence ceiling is required. "
            "Raw snapshot files remain immutable.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def analyze_snapshot(
    snapshot_path: Path | str,
    *,
    artifact_references: list[str] | None = None,
    policy_snapshot: artifact_policy.ArtifactPolicySnapshot | None = None,
    limits: analysis_limits.AnalysisLimits | None = None,
    analysis_route: str | None = None,
    review_terms: list[str] | None = None,
    selection_policy: str = review_planning.DEFAULT_SELECTION_POLICY,
    review_mode: str | None = None,
    max_total_analysis_tokens: int | None = None,
    snapshot_output: str = review_planning.DEFAULT_SNAPSHOT_OUTPUT,
) -> dict[str, Any]:
    path = Path(snapshot_path).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"Snapshot manifest not found: {path}")
    resolved_limits = limits or analysis_limits.resolve_analysis_limits()
    resolved_limits.validate()
    limits_payload = resolved_limits.as_dict()
    limits_identity = resolved_limits.identity()
    (
        resolved_review_mode,
        resolved_max_total_analysis_tokens,
    ) = review_planning.resolve_review_options(
        review_mode=review_mode,
        maximum_total_analysis_tokens=max_total_analysis_tokens,
    )
    resolved_snapshot_output = review_planning.resolve_snapshot_output(
        snapshot_output
    )
    snapshot = normalize_snapshot_manifest(
        read_json_object(path, "snapshot manifest")
    )
    snapshot_dir = path.parent
    if not snapshot_uses_canonical_csv_chunks(snapshot):
        raise RuntimeError(
            "Unsupported snapshot format. Create a new snapshot with the "
            "token-bounded canonical CSV snapshot pipeline."
        )
    hunt_id = str(snapshot.get("hunt_id") or "")
    if not hunt_id:
        raise RuntimeError(f"Snapshot manifest {path} does not contain hunt_id.")

    analysis_root = snapshot_dir / f"analysis-v{STACK_ANALYSIS_VERSION}"
    stacks_root = analysis_root / "stacks"
    model_review_root = analysis_root / "model-review"
    hunt_root = snapshot_dir.parent.parent
    cache_root = (
        hunt_root
        / "analysis-cache"
        / "by-chunk"
        / f"v{STACK_ANALYSIS_VERSION}"
    )
    directories = (
        (stacks_root, model_review_root, cache_root)
        if resolved_snapshot_output == "derived"
        else ()
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

    resolved_policy = artifact_policy.resolve_operation_policy(
        artifact_references=artifact_references,
        policy_snapshot=policy_snapshot,
    )
    resolved_profiles = resolved_policy.profiles
    snapshot_limit = int(snapshot.get("max_tokens_per_chunk") or 0)
    if snapshot_limit <= 0:
        raise RuntimeError(
            "Canonical CSV snapshot does not declare a positive "
            "max_tokens_per_chunk."
        )
    resolved_item_limit = min(
        review_planning.resolve_maximum_evidence_tokens_per_item(resolved_limits),
        snapshot_limit,
    )
    policy_encoding = resolved_limits.token_encoding
    snapshot_encoding = str(snapshot.get("token_encoding") or "")
    if snapshot_encoding != policy_encoding:
        raise RuntimeError(
            "Snapshot token encoding does not match the canonical analysis "
            f"limits ({snapshot_encoding!r}!={policy_encoding!r})."
        )

    chunk_records: list[dict[str, Any]] = []
    artifact_summaries: list[dict[str, Any]] = []
    artifact_review_contexts: list[dict[str, Any]] = []
    total_rows = 0
    reused_count = 0
    new_count = 0

    for result in snapshot.get("results", []):
        if not isinstance(result, dict):
            continue
        artifact = str(result.get("artifact") or result.get("artifact_name") or "artifact")
        artifact_name = str(result.get("artifact_name") or artifact)
        profile = (
            artifact_profiles.resolve_profile(artifact_name, resolved_profiles)
            or artifact_profiles.resolve_profile(artifact, resolved_profiles)
        )
        stack_accumulator = (
            ProfileStackAccumulator(artifact, artifact_name, profile)
            if resolved_snapshot_output == "derived"
            else None
        )
        evidence_accumulator = evidence_records.EvidenceAccumulator(artifact)
        artifact_chunks: list[dict[str, Any]] = []
        artifact_partitions: set[str] = set()
        artifact_rows = 0
        for file_record in result.get("files", []):
            if not isinstance(file_record, dict):
                continue
            source = snapshot_result_path(snapshot_dir, str(file_record.get("file") or ""))
            if not source.is_file():
                raise RuntimeError(f"Snapshot result file not found: {source}")
            if source.suffix.casefold() != ".csv":
                raise RuntimeError(
                    f"Canonical snapshot chunk is not CSV: {source}"
                )
            encoded = source.read_bytes()
            chunk_hash = hashlib.sha256(encoded).hexdigest()
            expected_hash = str(
                file_record.get("chunk_hash")
                or file_record.get("sha256")
                or ""
            )
            if not expected_hash or chunk_hash != expected_hash:
                raise RuntimeError(
                    f"Snapshot chunk hash mismatch for {source}."
                )
            if int(file_record.get("size_bytes") or -1) != len(encoded):
                raise RuntimeError(
                    f"Snapshot chunk size mismatch for {source}."
                )
            estimated_tokens = token_budget.estimate_tokens(
                encoded.decode("utf-8"),
                policy_encoding,
            )
            if (
                int(file_record.get("estimated_tokens") or -1)
                != estimated_tokens
            ):
                raise RuntimeError(
                    f"Snapshot chunk token metadata mismatch for {source}."
                )
            if estimated_tokens > resolved_item_limit:
                raise RuntimeError(
                    f"Snapshot CSV chunk {source} contains "
                    f"{estimated_tokens} tokens, exceeding the analysis "
                    f"limit of {resolved_item_limit}. Re-snapshot with the "
                    "same canonical analysis-limit environment."
                )
            partition = str(file_record.get("partition") or "")
            if not partition:
                raise RuntimeError(
                    f"Snapshot chunk does not declare a partition: {source}"
                )
            rows = [
                row
                for _, row in iter_canonical_csv_rows_with_line(source)
            ]
            if int(file_record.get("row_count") or -1) != len(rows):
                raise RuntimeError(
                    f"Snapshot chunk row-count mismatch for {source}."
                )
            for line_number, row in enumerate(rows, start=1):
                actual_partition = row_partition(row)
                if actual_partition != partition:
                    raise RuntimeError(
                        "Snapshot CSV partition mismatch "
                        f"for {source} at row {line_number}: "
                        f"{actual_partition!r}!={partition!r}."
                    )
                if stack_accumulator is not None:
                    stack_accumulator.add(row)
                evidence_accumulator.add(
                    row,
                    partition=partition,
                    source_file=str(source),
                    source_line=line_number,
                )
            artifact_partitions.add(partition)
            profile_hash = str(
                (profile or {}).get("_profile_hash") or "no-profile"
            )
            analysis_key = hashlib.sha256(
                (
                    f"{STACK_ANALYSIS_VERSION}:{chunk_hash}:"
                    f"{profile_hash}:{resolved_policy.policy_sha256}:"
                    f"{limits_identity}"
                ).encode("utf-8")
            ).hexdigest()
            analysis_file: Path | None = None
            reused = False
            if resolved_snapshot_output == "derived":
                analysis_file = cache_root / f"{analysis_key}.json"
                reused = analysis_file.exists()
                if reused:
                    reused_count += 1
                else:
                    payload = chunk_analysis_payload(
                        chunk_hash=chunk_hash,
                        chunk_file=source,
                        artifact=artifact,
                        artifact_name=artifact_name,
                        partition=partition,
                        rows=rows,
                        size_bytes=len(encoded),
                        estimated_tokens=estimated_tokens,
                        token_encoding=policy_encoding,
                        profile=profile,
                        include_sample_rows=False,
                    )
                    write_json(analysis_file, payload)
                    new_count += 1
            record = {
                "chunk_hash": chunk_hash,
                "analysis_key": analysis_key,
                "artifact": artifact,
                "artifact_name": artifact_name,
                "partition": partition,
                "row_count": len(rows),
                "size_bytes": len(encoded),
                "estimated_tokens": estimated_tokens,
                "token_estimator": token_budget.token_estimator_name(
                    policy_encoding
                ),
                "chunk_file": str(source),
                "analysis_file": (
                    str(analysis_file) if analysis_file else ""
                ),
                "analysis_reused": reused,
                "source_snapshot_chunk": True,
                "_rows": rows,
            }
            chunk_records.append(record)
            artifact_chunks.append(record)
            artifact_rows += len(rows)
            total_rows += len(rows)
        stack_summary = (
            stack_accumulator.finish()
            if stack_accumulator is not None
            else {
                "status": "not_materialized_quick",
                "profile_hash": str((profile or {}).get("_profile_hash") or ""),
                "default_stack": "",
                "stack_ids": [],
                "stack_count": 0,
                "stacks": {},
            }
        )
        ledger_records = evidence_accumulator.records()
        evidence_metrics = evidence_accumulator.metrics()
        stack_file: Path | None = None
        if resolved_snapshot_output == "derived":
            stack_file = stacks_root / f"{safe_slug(artifact)}.json"
            write_json(stack_file, stack_summary)
        artifact_summary = {
            "artifact": artifact,
            "artifact_name": artifact_name,
            "row_count": artifact_rows,
            "chunk_count": len(artifact_chunks),
            "partition_count": len(artifact_partitions),
            "partitions": sorted(artifact_partitions),
            "stack_status": stack_summary["status"],
            "stack_profile_hash": stack_summary.get("profile_hash", ""),
            "default_stack": stack_summary.get("default_stack", ""),
            "stack_ids": stack_summary.get("stack_ids", []),
            "stack_count": stack_summary.get("stack_count", 0),
            "stack_group_counts": {
                stack_id: stack.get("group_count", 0)
                for stack_id, stack in stack_summary.get("stacks", {}).items()
            },
            "stack_file": str(stack_file) if stack_file else "",
            "evidence_file": "",
            **evidence_metrics,
        }
        artifact_summaries.append(artifact_summary)
        artifact_review_contexts.append(
            {
                "summary": artifact_summary,
                "profile": profile,
                "records": ledger_records,
                "chunks": artifact_chunks,
            }
        )

    demands = [
        sum(
            int(chunk["estimated_tokens"])
            for chunk in context["chunks"]
        )
        for context in artifact_review_contexts
    ]
    if resolved_review_mode == "selective":
        artifact_budgets = review_planning.allocate_token_budgets(
            demands,
            int(resolved_max_total_analysis_tokens),
        )
    else:
        total_demand = sum(demands)
        if (
            resolved_max_total_analysis_tokens is not None
            and total_demand > resolved_max_total_analysis_tokens
        ):
            raise review_planning.ReviewPlanningError(
                "Exhaustive hunt evidence requires "
                f"{total_demand} tokens, exceeding "
                "maximum_total_analysis_tokens="
                f"{resolved_max_total_analysis_tokens}. Increase the ceiling "
                "or use --review-mode selective."
            )
        artifact_budgets = demands
    model_review_artifacts: list[dict[str, Any]] = []
    for context, artifact_budget in zip(artifact_review_contexts, artifact_budgets):
        artifact_summary = context["summary"]
        route = artifact_review_route(
            context["profile"],
            analysis_route,
        )
        plan = build_direct_chunk_review_plan(
            context["chunks"],
            artifact=str(artifact_summary["artifact"]),
            limits=resolved_limits,
            route=route,
            review_mode=resolved_review_mode,
            maximum_total_analysis_tokens=(
                artifact_budget
                if resolved_review_mode == "selective"
                else resolved_max_total_analysis_tokens
            ),
            terms=list(review_terms or []),
            selection_policy=selection_policy,
        )
        materialized_plan, plan_path = (
            materialize_direct_chunk_review_plan(
                plan,
                artifact=str(artifact_summary["artifact"]),
                model_review_root=model_review_root,
                snapshot_output=resolved_snapshot_output,
            )
        )
        selection = materialized_plan["selection"]
        review_csv_files = [
            str(package["package_csv_file"])
            for package in materialized_plan["packages"]
        ]
        artifact_summary.update(
            {
                "model_review_manifest": str(plan_path) if plan_path else "",
                "review_csv_files": review_csv_files,
                "review_csv_tokens": sum(
                    int(package["package_csv_tokens"])
                    for package in materialized_plan["packages"]
                ),
                "analysis_route": materialized_plan["analysis_routing"]["route"],
                "analysis_task": materialized_plan["analysis_routing"]["task"],
                "review_mode": resolved_review_mode,
                "source_chunk_token_ceiling": resolved_item_limit,
                "maximum_total_analysis_tokens": (
                    artifact_budget
                    if resolved_review_mode == "selective"
                    else None
                ),
                "review_budget_tokens": (
                    artifact_budget
                    if resolved_review_mode == "selective"
                    else None
                ),
                "selected_review_tokens": int(
                    selection["selected_evidence_tokens"]
                ),
                "packaged_evidence_tokens": sum(
                    int(package["package_csv_tokens"])
                    for package in materialized_plan["packages"]
                ),
                "selected_evidence_count": int(
                    selection["selected_evidence_count"]
                ),
                "packaged_evidence_count": int(
                    selection["selected_evidence_count"]
                ),
                "model_review_package_count": int(
                    materialized_plan["package_count"]
                ),
                "complete_evidence_coverage": bool(
                    selection["complete_evidence_coverage"]
                ),
            }
        )
        model_review_artifacts.append(materialized_plan)

    model_review_manifest = {
        "review_plan_version": review_planning.REVIEW_PLAN_VERSION,
        "generated_at": now_utc(),
        "hunt_id": hunt_id,
        "snapshot_file": str(path),
        "analysis_limits": limits_payload,
        "analysis_limits_identity": limits_identity,
        "source_chunk_token_ceiling": resolved_item_limit,
        "review_mode": resolved_review_mode,
        "maximum_total_analysis_tokens": resolved_max_total_analysis_tokens,
        "selection_policy": selection_policy,
        "selection_terms": list(review_terms or []),
        "total_review_budget_tokens": resolved_max_total_analysis_tokens,
        "allocated_review_budget_tokens": (
            sum(artifact_budgets)
            if resolved_review_mode == "selective"
            else None
        ),
        "selected_review_tokens": sum(
            int(item["selection"]["selected_evidence_tokens"])
            for item in model_review_artifacts
        ),
        "packaged_evidence_tokens": sum(
            int(package["package_csv_tokens"])
            for item in model_review_artifacts
            for package in item["packages"]
        ),
        "selected_evidence_count": sum(
            int(item["selection"]["selected_evidence_count"])
            for item in model_review_artifacts
        ),
        "package_count": sum(
            int(item["package_count"]) for item in model_review_artifacts
        ),
        "complete_evidence_coverage": all(
            bool(item["selection"]["complete_evidence_coverage"])
            for item in model_review_artifacts
        ),
        "artifacts": [
            {
                "artifact": item["artifact"],
                "status": item["status"],
                "analysis_route": item["analysis_routing"]["route"],
                "analysis_task": item["analysis_routing"]["task"],
                "review_mode": item["review_mode"],
                "selected_evidence_count": item["selection"][
                    "selected_evidence_count"
                ],
                "selected_evidence_tokens": item["selection"][
                    "selected_evidence_tokens"
                ],
                "package_count": item["package_count"],
            }
            for item in model_review_artifacts
        ],
    }
    model_review_manifest_path: Path | None = None
    if resolved_snapshot_output == "derived":
        model_review_manifest_path = model_review_root / "manifest.json"
        write_json(model_review_manifest_path, model_review_manifest)

    summary = {
        "ai_review_status": "skipped",
        "review_complete": False,
        "analysis_version": STACK_ANALYSIS_VERSION,
        "analyzed_at": now_utc(),
        "snapshot_output": resolved_snapshot_output,
        "hunt_id": hunt_id,
        "group": str(snapshot.get("group") or ""),
        "snapshot_file": str(path),
        "fingerprint": str(snapshot.get("fingerprint") or ""),
        "snapshot_consistent": bool(snapshot.get("consistent")),
        "artifact_policy": resolved_policy.metadata(),
        "analysis_limits": limits_payload,
        "analysis_limits_identity": limits_identity,
        "max_tokens_per_chunk": resolved_item_limit,
        "token_estimator": token_budget.token_estimator_name(policy_encoding),
        "review_mode": resolved_review_mode,
        "maximum_total_analysis_tokens": resolved_max_total_analysis_tokens,
        "total_review_budget_tokens": resolved_max_total_analysis_tokens,
        "selection_policy": selection_policy,
        "selection_terms": list(review_terms or []),
        "row_count": total_rows,
        "chunk_count": len(chunk_records),
        "partition_count": sum(
            int(item["partition_count"]) for item in artifact_summaries
        ),
        "new_chunk_analysis_count": new_count,
        "reused_chunk_analysis_count": reused_count,
        "raw_evidence_tokens": sum(
            int(item.get("raw_tokens") or 0) for item in artifact_summaries
        ),
        "deduplicated_evidence_tokens": sum(
            int(item.get("deduplicated_tokens") or 0)
            for item in artifact_summaries
        ),
        "selected_review_tokens": model_review_manifest[
            "selected_review_tokens"
        ],
        "packaged_evidence_tokens": model_review_manifest[
            "packaged_evidence_tokens"
        ],
        "selected_evidence_count": model_review_manifest[
            "selected_evidence_count"
        ],
        "model_review_package_count": model_review_manifest["package_count"],
        "complete_evidence_coverage": model_review_manifest[
            "complete_evidence_coverage"
        ],
        "model_review_manifest": (
            str(model_review_manifest_path) if model_review_manifest_path else ""
        ),
        "review_csv_files": [
            csv_file
            for item in artifact_summaries
            for csv_file in item.get("review_csv_files", [])
        ],
        "review_csv_tokens": sum(
            int(item.get("review_csv_tokens") or 0)
            for item in artifact_summaries
        ),
        "artifacts": artifact_summaries,
        "chunks": [
            {
                key: value
                for key, value in record.items()
                if not key.startswith("_")
            }
            for record in chunk_records
        ],
        "analysis_dir": (
            str(analysis_root) if resolved_snapshot_output == "derived" else ""
        ),
        "summary_json": (
            str(analysis_root / "summary.json")
            if resolved_snapshot_output == "derived"
            else ""
        ),
        "summary_markdown": (
            str(analysis_root / "summary.md")
            if resolved_snapshot_output == "derived"
            else ""
        ),
    }
    if resolved_snapshot_output == "derived":
        write_json(analysis_root / "summary.json", summary)
        write_markdown_summary(analysis_root / "summary.md", summary)
    return summary


def command_analyze(args: argparse.Namespace) -> dict[str, Any]:
    resolved_policy = artifact_policy.load_artifact_policy(
        list(getattr(args, "artifact_reference", []) or [])
    )
    if getattr(args, "snapshot", None):
        resolved_limits = analysis_limits.resolve_analysis_limits()
        return analyze_snapshot(
            args.snapshot,
            policy_snapshot=resolved_policy,
            limits=resolved_limits,
            analysis_route=getattr(args, "analysis_route", None),
            review_terms=list(getattr(args, "review_term", []) or []),
            selection_policy=getattr(
                args,
                "selection_policy",
                review_planning.DEFAULT_SELECTION_POLICY,
            ),
            review_mode=getattr(
                args, "review_mode", review_planning.DEFAULT_REVIEW_MODE
            ),
            max_total_analysis_tokens=getattr(
                args,
                "max_total_analysis_tokens",
                None,
            ),
            snapshot_output=getattr(
                args,
                "snapshot_output",
                review_planning.DEFAULT_SNAPSHOT_OUTPUT,
            ),
        )
    contract, hunt_dir = resolve_input_contract(args)
    profiles = resolved_policy.profiles
    profile_sources = resolved_policy.profile_sources
    review_dir, staging_dir = prepare_review_staging_dir(hunt_dir)
    try:
        input_contract_path = staging_dir / "hunt-analysis-input.json"
        write_json(input_contract_path, contract)

        artifact_results = [
            analyze_artifact(staging_dir, artifact_entry, args.sample_limit, profiles)
            for artifact_entry in contract["artifacts"]
        ]
        artifact_results = [remap_artifact_result_paths(result, staging_dir, review_dir) for result in artifact_results]

        manifest = {
            "ai_review_status": "skipped",
            "review_complete": False,
            "contract_version": CONTRACT_VERSION,
            "catalog_schema_version": artifact_profiles.SCHEMA_VERSION,
            "artifact_profile_sources": [str(path) for path in profile_sources],
            "artifact_policy": resolved_policy.metadata(),
            "analyzed_at": now_utc(),
            "investigation_id": contract["investigation_id"],
            "hunt_id": contract["hunt_id"],
            "target_os": contract["target_os"],
            "profile_key": contract["profile_key"],
            "review_dir": str(review_dir),
            "input_contract_file": str(review_dir / "hunt-analysis-input.json"),
            "state_file": contract["state_file"],
            "export_manifest_file": contract["export_manifest_file"],
            "download_manifest_file": contract["download_manifest_file"],
            "baseline_targets_file": contract["baseline_targets_file"],
            "target_collection_type": contract["target_collection_type"],
            "requested_groups": contract["requested_groups"],
            "requested_artifacts": contract["requested_artifacts"],
            "expected_spec_arguments": contract["expected_spec_arguments"],
            "review_readiness": contract["review_readiness"],
            "completion_ratio": contract["completion_ratio"],
            "baseline_target_count": contract["baseline_target_count"],
            "artifacts_analyzed": len(artifact_results),
            "artifacts": artifact_results,
            "manifest_file": str(review_dir / "hunt-analysis.json"),
        }
        manifest_path = staging_dir / "hunt-analysis.json"
        write_json(manifest_path, manifest)
        promote_review_outputs(staging_dir, review_dir)
        return manifest
    except Exception:
        cleanup_staging_dir(staging_dir)
        raise


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        validate_args(args)
        payload = command_analyze(args)
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
