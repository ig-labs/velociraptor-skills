#!/usr/bin/env python3
"""Build, validate, merge, query, and publish Autoruns GoldenDB files."""

from __future__ import annotations
from vraptor.resources import resource_root

import argparse
from contextlib import closing
import base64
import csv
import fcntl
import fnmatch
import functools
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Iterator

from vraptor.common import atomic_io
from vraptor import paths as dfir_paths
from vraptor.common.hashing import sha256_file as file_sha256
from vraptor import api as velociraptor_api
from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import regex as autoruns_regex
from vraptor import context as engagement_context
from vraptor.analyze import flow as flow_analysis


from vraptor.resources import repository_root
REPO_ROOT = repository_root()
SCHEMA_VERSION = "6"
READABLE_SCHEMA_VERSIONS = {"3", "4", "5", SCHEMA_VERSION}
DEFAULT_TOOL_NAME = "Autoruns.GoldenDB"
DEFAULT_TOOL_VERSION = "current"
DEFAULT_TOOL_FILENAME = "autoruns-golden.sqlite"
FILTER_STATUS_FIELD = "GoldenDBStatus"
FILTER_HASH_FIELD = "HashKey"
DEFAULT_AUTORUNS_ARTIFACT = "IG.Windows.Sysinternals.Autoruns"
SUPPORTED_AUTORUNS_ARTIFACTS = (
    DEFAULT_AUTORUNS_ARTIFACT,
    "Windows.Sysinternals.Autoruns",
)
AUTORUNS_GOLDEN_DELTA_FILENAME = "autoruns-golden-delta.sqlite"
AUTORUNS_GOLDEN_DELTA_MANIFEST_FILENAME = "autoruns-golden-delta.json"
AUTORUNS_POTENTIAL_GOLDEN_FILENAME = "autoruns_potential_golden.csv"
AUTORUNS_RESIDUAL_STACK_FILENAME = "autoruns_residual_stack.csv"
AUTORUNS_POTENTIAL_GOLDEN_ENRICHED_FILENAME = (
    "autoruns_potential_golden_enriched.csv"
)
AUTORUNS_GOLDEN_DELTA_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_RMM_SOURCE = "https://lolrmm.io/api/rmm_tools.csv"
DEFAULT_RMM_PROJECT = "https://github.com/magicsword-io/LOLRMM"
DEFAULT_RMM_LICENSE = "Apache-2.0"
MAX_LOOKUP_ROWS = 1_000_000
MAX_PUBLISH_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_PUBLISH_BASE64_BYTES = 60 * 1024 * 1024
PUBLISH_GRPC_OVERHEAD_BYTES = 4 * 1024 * 1024
PUBLISH_GZIP_LEVEL = 9
MAX_LIVE_LOOKUP_BASE64_BYTES = 48 * 1024 * 1024
RMM_REFERENCE_PATH = (
    resource_root()
    / "windows-rmm-greyware.json"
)
HASH_RE = re.compile(r"^[0-9a-f]{40}$")
MISSING_FILE_RE = re.compile(r"(?i)^\s*file not found:")
WINDOWS_EXECUTABLE_RE = re.compile(
    r"(?i)([^\\/,;\"']+\.(?:exe|com|msi|bat|cmd|ps1|vbs|scr))"
)
DESCRIPTION_MAX_LENGTH = 256
REVIEW_CONTEXT_FIELD_LIMITS = {
    "example_entry_location": 512,
    "example_entry": 256,
    "example_description": DESCRIPTION_MAX_LENGTH,
    "example_company": 128,
}

SCHEMA_RESOURCE = (
    resources.files("vraptor")
    .joinpath("resources")
    .joinpath("autoruns")
    .joinpath("windows-autoruns-known-good-schema.sql")
)
SCHEMA_SQL = SCHEMA_RESOURCE.read_text(encoding="utf-8")

REQUIRED_METADATA = {
    "schema_version": SCHEMA_VERSION,
    "canonicalization_version": str(autoruns.CANONICALIZATION_VERSION),
    "hash_algorithm": autoruns.TRUSTED_KEY_HASH,
    "transform_key": autoruns.PATH_TRANSFORM_CACHE_KEY,
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def field(
    row: dict[str, Any],
    *names: str,
) -> Any:
    folded = {str(key).casefold(): value for key, value in row.items()}
    for name in names:
        if name in row:
            return row[name]
        value = folded.get(name.casefold())
        if value is not None:
            return value
    return ""


def normalize_description(value: Any) -> str:
    return autoruns.normalize_context_value(
        value,
        max_length=DESCRIPTION_MAX_LENGTH,
    )


def context_payload(row: dict[str, Any]) -> dict[str, str]:
    values = {
        "example_entry_location": field(
            row,
            "EntryLocation",
            "Entry Location",
            "entry_location",
            "example_entry_location",
        ),
        "example_entry": field(
            row,
            "Entry",
            "entry",
            "example_entry",
        ),
        "example_description": field(
            row,
            "Description",
            "description",
            "example_description",
        ),
        "example_company": field(
            row,
            "Company",
            "company",
            "example_company",
        ),
    }
    return {
        name: autoruns.normalize_context_value(
            value,
            max_length=REVIEW_CONTEXT_FIELD_LIMITS[name],
        )
        for name, value in values.items()
    }


def context_key(payload: dict[str, str]) -> str:
    return hashlib.sha256(
        stable_json(payload).encode("utf-8")
    ).hexdigest()


def description_selection_key(value: Any) -> tuple[int, int, str]:
    text = normalize_description(value)
    return (
        -int(bool(text)),
        -len(text),
        text.casefold(),
    )


def normalized_record(row: dict[str, Any]) -> dict[str, str]:
    record = autoruns.trusted_record(
        category=field(row, "Category", "category"),
        signer=field(row, "Signer", "signer"),
        image_path=field(
            row,
            "ImagePath",
            "Image Path",
            "image_path",
        ),
        launch_string=field(
            row,
            "LaunchString",
            "Launch String",
            "launch_string",
        ),
    )
    supplied_hash = str(
        field(row, "HashKey", "hash_key", "trusted_key")
        or ""
    ).strip().casefold()
    if supplied_hash and supplied_hash != record["hash_key"]:
        raise RuntimeError(
            "Autoruns row HashKey does not match normalized "
            f"ImagePath+LaunchString+Signer: {supplied_hash} != "
            f"{record['hash_key']}."
        )
    normalized = {
        key: str(value)
        for key, value in record.items()
    }
    normalized["description"] = normalize_description(
        field(
            row,
            "Description",
            "description",
            "example_description",
        )
    )
    review_context = context_payload(row)
    normalized.update(review_context)
    normalized["context_key"] = context_key(review_context)
    return normalized


def is_missing_file(
    *,
    image_path: Any,
    launch_string: Any,
) -> bool:
    return bool(
        MISSING_FILE_RE.search(str(image_path or ""))
        or MISSING_FILE_RE.search(str(launch_string or ""))
    )


def load_hashes(paths: Iterable[Path]) -> set[str]:
    values: set[str] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        if isinstance(payload, dict):
            payload = (
                payload.get("hashes")
                or payload.get("HashKeys")
                or payload.get("items")
                or []
            )
        if not isinstance(payload, list):
            raise RuntimeError(
                f"Hash exclusion file {path} must contain a JSON list, "
                "a hashes object, or one SHA-1 per line."
            )
        for item in payload:
            value = (
                str(item.get("HashKey") or item.get("hash_key") or "")
                if isinstance(item, dict)
                else str(item)
            ).strip().casefold()
            if not HASH_RE.fullmatch(value):
                raise RuntimeError(
                    f"Invalid Autoruns SHA-1 identity in {path}: {value!r}."
                )
            values.add(value)
    return values


def _input_field_key(name: str) -> str:
    key = name.casefold().replace(" ", "").replace("_", "")
    return "hashkey" if key == "trustedkey" else key


def _validate_input_fields(
    names: Iterable[str], *, required: Iterable[str], source: str,
) -> None:
    seen: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise RuntimeError(f"Autoruns input {source} has an invalid field name.")
        key = _input_field_key(name)
        if key in seen:
            raise RuntimeError(f"Autoruns input {source} has duplicate field {name!r}.")
        seen.add(key)
    missing = sorted({_input_field_key(name) for name in required} - seen)
    if missing:
        raise RuntimeError(
            f"Autoruns input {source} is missing required fields: {', '.join(missing)}."
        )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"Autoruns JSON contains duplicate field {key!r}.")
        result[key] = value
    return result


def iter_rows(
    path: Path, *, content: bytes | None = None,
    required_fields: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        with (
            io.StringIO(content.decode("utf-8-sig"), newline="")
            if content is not None
            else path.open("r", encoding="utf-8-sig", newline="")
        ) as handle:
            # Only a leading metadata preamble is a comment. Once the header
            # begins, every physical line belongs to the CSV grammar.
            def csv_lines() -> Iterator[str]:
                started = False
                for line in handle:
                    if not started and (not line.strip() or line.lstrip().startswith("#")):
                        continue
                    started = True
                    yield line

            reader = csv.DictReader(csv_lines(), strict=True)
            try:
                _validate_input_fields(
                    reader.fieldnames or (), required=required_fields, source=str(path),
                )
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise RuntimeError(
                            f"Autoruns input {path}:{reader.line_num} has an incorrect column count."
                        )
                    yield row
            except csv.Error as exc:
                raise RuntimeError(f"Invalid Autoruns CSV {path}:{reader.line_num}: {exc}") from exc
        return
    text = content.decode("utf-8-sig") if content is not None else path.read_text(encoding="utf-8-sig")
    if suffix in {".jsonl", ".ndjson"}:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line, object_pairs_hook=_unique_json_object)
            if not isinstance(value, dict):
                raise RuntimeError(
                    f"{path}:{line_number} must contain a JSON object."
                )
            _validate_input_fields(value, required=required_fields, source=f"{path}:{line_number}")
            yield value
        return
    payload = json.loads(text, object_pairs_hook=_unique_json_object)
    if isinstance(payload, dict):
        for key in ("rows", "items", "results", "data"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        raise RuntimeError(
            f"Autoruns input {path} must be CSV, JSONL, a JSON list, "
            "or an object containing rows/items/results/data."
        )
    for index, value in enumerate(payload, start=1):
        if not isinstance(value, dict):
            raise RuntimeError(
                f"{path} JSON row {index} must be an object."
            )
        _validate_input_fields(value, required=required_fields, source=f"{path}:{index}")
        yield value


def _split_csv_values(value: Any) -> list[str]:
    return [
        item.strip().strip("\"'")
        for item in str(value or "").split(",")
        if item.strip().strip("\"'")
    ]


def _extract_windows_executables(value: Any) -> set[str]:
    output: set[str] = set()
    for match in WINDOWS_EXECUTABLE_RE.finditer(str(value or "")):
        name = match.group(1).strip().casefold()
        if (
            name
            and "<" not in name
            and ">" not in name
            and "…" not in name
        ):
            output.add(name)
    return output


def parse_lolrmm_csv(text: str, *, source: str) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    executable_names: set[str] = set()
    path_fragments: set[str] = set()
    for row in csv.DictReader(io.StringIO(text)):
        name = str(row.get("Name") or "").strip()
        category = str(row.get("Category") or "").strip()
        if not name:
            continue
        names: set[str] = set()
        for column in (
            "Filename",
            "OriginalFileName",
            "InstallationPaths",
        ):
            names.update(_extract_windows_executables(row.get(column)))
        paths = [
            autoruns.normalize_user_path(value)
            for value in _split_csv_values(row.get("InstallationPaths"))
            if "\\" in value and not value.startswith("/")
        ]
        executable_names.update(names)
        path_fragments.update(paths)
        tools.append(
            {
                "name": name,
                "category": category,
                "executables": sorted(names),
                "installation_paths": sorted(paths),
            }
        )
    return {
        "schema_version": 1,
        "source": source,
        "source_project": DEFAULT_RMM_PROJECT,
        "source_license": DEFAULT_RMM_LICENSE,
        "updated_at": now_utc(),
        "tool_count": len(tools),
        "executables": sorted(executable_names),
        "installation_paths": sorted(path_fragments),
        "tools": sorted(tools, key=lambda item: item["name"].casefold()),
    }


def refresh_rmm_reference(
    output: Path,
    *,
    source: str = DEFAULT_RMM_SOURCE,
) -> dict[str, Any]:
    with urllib.request.urlopen(source, timeout=30) as response:
        text = response.read().decode("utf-8-sig")
    payload = parse_lolrmm_csv(text, source=source)
    atomic_io.write_json_atomic(output, payload, sort_keys=True)
    return payload


class RmmClassifier:
    def __init__(self, path: Path | None = None):
        self.path = path or RMM_REFERENCE_PATH
        stat = self.path.stat()
        payload = _load_rmm_reference(
            str(self.path),
            stat.st_mtime_ns,
            stat.st_size,
        )
        names = payload.get("executables")
        paths = payload.get("installation_paths")
        if not isinstance(names, list) or not isinstance(paths, list):
            raise RuntimeError(
                f"RMM reference {self.path} requires executables and "
                "installation_paths lists."
            )
        self.executables = {
            str(value).strip().casefold()
            for value in names
            if str(value).strip()
        }
        self.exact_executables = {
            value
            for value in self.executables
            if "*" not in value and "?" not in value
        }
        self.wildcard_executables = {
            value
            for value in self.executables
            if "*" in value or "?" in value
        }
        self.installation_paths = {
            autoruns.normalize_user_path(value).strip()
            for value in paths
            if str(value).strip()
        }
        self.reference_hash = hashlib.sha256(
            stable_json(payload).encode("utf-8")
        ).hexdigest()

    def regex(self) -> str:
        names = sorted(self.executables)
        paths = sorted(self.installation_paths)
        if not names and not paths:
            return r"(?!)"
        patterns = []
        for name in names:
            rendered = re.escape(name)
            rendered = rendered.replace(r"\*", r"[^\\/\s\"']*")
            rendered = rendered.replace(r"\?", r"[^\\/\s\"']")
            patterns.append(rendered)
        name_expression = (
            r"(?:^|[\\/\s\"'])(?:"
            + "|".join(patterns)
            + r")(?:$|[\s\"'])"
            if patterns
            else r"(?!)"
        )
        path_patterns = [
            _glob_to_regex(value)
            for value in paths
        ]
        path_expression = (
            "(?:" + "|".join(path_patterns) + ")"
            if path_patterns
            else r"(?!)"
        )
        return f"(?i)(?:{name_expression}|{path_expression})"

    def reasons(
        self,
        *,
        image_path: Any,
        launch_string: Any,
    ) -> list[str]:
        image = autoruns.normalize_user_path(image_path)
        launch = autoruns.normalize_user_path(launch_string)
        combined = f"{image} {launch}"
        found_names = sorted(
            {
                token
                for token in re.findall(
                    r"(?i)[^\\/\s\"']+\.(?:exe|com|msi|bat|cmd|ps1|vbs|scr)",
                    combined,
                )
                if token in self.exact_executables
                or any(
                    fnmatch.fnmatch(token, pattern)
                    for pattern in self.wildcard_executables
                )
            }
        )
        found_paths = sorted(
            value
            for value in self.installation_paths
            if _glob_fragment_matches(value, image)
            or _glob_fragment_matches(value, launch)
        )
        reasons = [
            f"rmm-executable:{name}"
            for name in found_names[:5]
        ]
        reasons.extend(
            f"rmm-installation-path:{value}"
            for value in found_paths[:5]
        )
        return reasons


@functools.lru_cache(maxsize=16)
def _load_rmm_reference(
    path: str,
    mtime_ns: int,
    size: int,
) -> dict[str, Any]:
    del mtime_ns, size
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"RMM reference {path} must be a JSON object.")
    return payload


def _glob_fragment_matches(pattern: str, value: str) -> bool:
    if not pattern or not value:
        return False
    normalized = pattern.replace("**", "*")
    if fnmatch.fnmatch(value, normalized):
        return True
    literal = normalized.strip("*")
    return bool(literal and literal in value)


def _glob_to_regex(pattern: str) -> str:
    rendered = re.escape(pattern.replace("**", "*"))
    rendered = rendered.replace(r"\*", ".*")
    rendered = rendered.replace(r"\?", ".")
    return rendered


def connect_database(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    else:
        # SQLite otherwise creates replacement databases using 0666 & umask.
        # Keep new working files private even in a shared target directory.
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(
    connection: sqlite3.Connection,
    *,
    built_at: str,
) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(autoruns_known_good)")}
    if (columns or connection.execute("PRAGMA table_info(GoldenRules)").fetchone()) and metadata(connection).get("schema_version") in {"7", "8", "9", "10"}:
        raise RuntimeError("Regex-only GoldenDB requires autoruns regex-import; legacy exact/delta writes are disabled.")
    if columns and ("category" in columns or metadata(connection).get("schema_version") != SCHEMA_VERSION):
        raise RuntimeError("Legacy GoldenDB writes require an explicit merge into schema 6 first.")
    connection.executescript(SCHEMA_SQL)
    required_metadata = dict(REQUIRED_METADATA)
    connection.executemany(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        sorted(required_metadata.items()),
    )
    connection.execute(
        "INSERT OR IGNORE INTO metadata (key, value) VALUES ('built_at', ?)",
        (built_at,),
    )


def metadata(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        str(row["key"]): str(row["value"])
        for row in connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        )
    }


def regex_records(
    connection: sqlite3.Connection, *, deduplicate: bool = True,
) -> list[dict[str, str]]:
    # Legacy category associations collapse in memory; reads never migrate disk.
    version = metadata(connection).get("schema_version")
    if version in {"7", "8", "9", "10"}:
        from vraptor.autoruns.regex_store import records
        return records(connection)
    if version == "3":
        return []
    signer = "signer_regex" if version in {"5", SCHEMA_VERSION} else "'' AS signer_regex"
    stored = [dict(row) for row in connection.execute(
        f"SELECT image_path_regex, launch_string_regex, {signer}, description, "
        "modified_time FROM autoruns_regex_rules ORDER BY image_path_regex, launch_string_regex"
    )]
    if not deduplicate:
        return stored
    records: dict[tuple[str, str], dict[str, str]] = {}
    for record in stored:
        key = regex_record_key(record)
        existing = records.get(key)
        if existing is None:
            records[key] = record
        else:
            for field_name in ("description", "signer_regex"):
                existing[field_name] = min((existing[field_name], record[field_name]), key=description_selection_key)
            existing["modified_time"] = max(existing["modified_time"], record["modified_time"])
    return list(records.values())


def exact_records(connection: sqlite3.Connection) -> list[dict[str, str]]:
    if metadata(connection).get("schema_version") == "10":
        return []
    """Read schema 3-6 identities with deterministic legacy deduplication."""
    records: dict[str, dict[str, str]] = {}
    for row in connection.execute(
        "SELECT hash_key, image_path, launch_string, signer, description, modified_time "
        "FROM autoruns_known_good ORDER BY hash_key"
    ):
        record = dict(row)
        key = record["hash_key"]
        existing = records.get(key)
        if existing is None:
            records[key] = record
        else:
            if any(existing[name] != record[name] for name in ("image_path", "launch_string", "signer")):
                raise RuntimeError(f"GoldenDB hash collision or canonicalization mismatch for {key}.")
            existing["description"] = min((existing["description"], record["description"]), key=description_selection_key)
            existing["modified_time"] = max(existing["modified_time"], record["modified_time"])
    return list(records.values())

def normalized_regex_record(row: dict[str, Any]) -> dict[str, str]:
    record = {
        "image_path_regex": str(field(row, "image_path_regex", "ImagePathRegex")),
        "launch_string_regex": str(field(row, "launch_string_regex", "LaunchStringRegex")),
        "description": normalize_description(field(row, "description", "Description")),
        "signer_regex": str(field(row, "signer_regex", "SignerRegex")),
    }
    if record["signer_regex"]:
        autoruns_regex.compile_pattern(record["signer_regex"])
    for name in ("image_path_regex", "launch_string_regex"):
        autoruns_regex.compile_pattern(record[name])
    return record


def regex_record_key(record: dict[str, Any]) -> tuple[str, str]:
    return (record["image_path_regex"], record["launch_string_regex"])


def insert_regex_record(
    connection: sqlite3.Connection, record: dict[str, str], *, modified_time: str,
) -> bool:
    key = regex_record_key(record)
    existing = connection.execute(
        "SELECT description, signer_regex, modified_time FROM autoruns_regex_rules "
        "WHERE image_path_regex=? AND launch_string_regex=?", key,
    ).fetchone()
    if existing is None:
        connection.execute(
            "INSERT INTO autoruns_regex_rules (image_path_regex, launch_string_regex, description, modified_time, signer_regex) VALUES (?, ?, ?, ?, ?)",
            (*key, record["description"], modified_time, record.get("signer_regex", "")),
        )
        return True
    reference_changed = description_selection_key(record.get("signer_regex", "")) < description_selection_key(existing["signer_regex"])
    if reference_changed:
        connection.execute("UPDATE autoruns_regex_rules SET signer_regex=?, modified_time=? WHERE image_path_regex=? AND launch_string_regex=?", (record["signer_regex"], max(modified_time, existing["modified_time"]), *key))
    if description_selection_key(record["description"]) < (
        description_selection_key(existing["description"])
    ):
        connection.execute(
            "UPDATE autoruns_regex_rules SET description=?, modified_time=? "
            "WHERE image_path_regex=? AND launch_string_regex=?",
            (record["description"], max(modified_time, existing["modified_time"]), *key),
        )
    return reference_changed


def insert_record(
    connection: sqlite3.Connection, record: dict[str, str], *, modified_time: str,
) -> bool:
    existing = connection.execute(
        "SELECT image_path, launch_string, signer, description, modified_time "
        "FROM autoruns_known_good WHERE hash_key = ?", (record["hash_key"],),
    ).fetchone()
    description = normalize_description(record.get("description"))
    if existing is None:
        connection.execute(
            "INSERT INTO autoruns_known_good (hash_key, image_path, launch_string, signer, description, modified_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (record["hash_key"], record["image_path"], record["launch_string"], record["signer"], description, modified_time),
        )
        return True
    if any(existing[name] != record[name] for name in ("image_path", "launch_string", "signer")):
        raise RuntimeError(f"GoldenDB hash collision or canonicalization mismatch for {record['hash_key']}.")
    selected_description = min((existing["description"], description), key=description_selection_key)
    selected_time = max(existing["modified_time"], modified_time)
    if selected_description != existing["description"] or selected_time != existing["modified_time"]:
        connection.execute(
            "UPDATE autoruns_known_good SET description=?, modified_time=? WHERE hash_key=?",
            (selected_description, selected_time, record["hash_key"]),
        )
    return False

def baseline_record_changes(
    record: dict[str, str], connections: Iterable[sqlite3.Connection],
) -> tuple[bool, bool, bool]:
    descriptions: list[str] = []
    for connection in connections:
        for existing in connection.execute(
            "SELECT image_path, launch_string, signer, description FROM autoruns_known_good WHERE hash_key=?",
            (record["hash_key"],),
        ):
            if any(existing[name] != record[name] for name in ("image_path", "launch_string", "signer")):
                raise RuntimeError(f"Baseline GoldenDB hash collision or canonicalization mismatch for {record['hash_key']}.")
            descriptions.append(existing["description"])
    if not descriptions:
        return True, False, bool(record.get("description"))
    existing_description = min(descriptions, key=description_selection_key)
    improves_description = description_selection_key(record.get("description")) < description_selection_key(existing_description)
    return improves_description, True, improves_description

def promote_records(
    database: Path,
    rows: Iterable[dict[str, Any]],
    *,
    rmm_reference: Path | None = None,
    exclude_hashes: set[str] | None = None,
    modified_time: str | None = None,
    created_at: str | None = None,
    baseline_databases: Iterable[Path] | None = None,
    regex_rows: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    if modified_time and created_at:
        raise RuntimeError(
            "Pass modified_time or legacy created_at, not both."
        )
    timestamp = modified_time or created_at or now_utc()
    reviewed_regex_rows = [normalized_regex_record(row) for row in regex_rows]
    classifier = RmmClassifier(rmm_reference)
    excluded = exclude_hashes or set()
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists():
        validate_database(
            database,
            rmm_reference=rmm_reference,
        )
    inserted = 0
    existing = 0
    inserted_records = 0
    inserted_regex_rules = 0
    skipped_baseline_regex_rules = 0
    skipped_missing = 0
    skipped_non_promotable = 0
    skipped_excluded = 0
    skipped_baseline = 0
    retained_baseline_enrichment = 0
    baseline_paths = [
        Path(path)
        for path in (baseline_databases or [])
    ]
    for path in baseline_paths:
        if validate_database(path, rmm_reference=rmm_reference).get("regex_only"):
            raise RuntimeError("Regex-only GoldenDB baselines require regex-import; legacy delta creation is disabled.")
    baseline_connections: list[sqlite3.Connection] = []
    try:
        for path in baseline_paths:
            baseline_connections.append(
                connect_database(path, readonly=True)
            )
    except Exception:
        for baseline_connection in baseline_connections:
            baseline_connection.close()
        raise
    try:
        connection = connect_database(database)
    except Exception:
        for baseline_connection in baseline_connections:
            baseline_connection.close()
        raise
    try:
        initialize_database(connection, built_at=timestamp)
        build_metadata = {
            "build_mode": "delta" if baseline_paths else "full",
            "baseline_database_count": str(len(baseline_paths)),
            "baseline_database_sha256s": stable_json(
                sorted(file_sha256(path) for path in baseline_paths)
            ),
        }
        connection.executemany(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            sorted(build_metadata.items()),
        )
        baseline_regex: dict[tuple[str, str], str] = {}
        baseline_signers: dict[tuple[str, str], str] = {}
        for baseline in baseline_connections:
            for rule in regex_records(baseline):
                key = regex_record_key(rule)
                baseline_signers[key] = min((baseline_signers.get(key, ""), rule.get("signer_regex", "")), key=description_selection_key)
                baseline_regex[key] = min(
                    (baseline_regex.get(key, ""), rule["description"]),
                    key=description_selection_key,
                )
        for rule in reviewed_regex_rows:
            key = regex_record_key(rule)
            if key in baseline_regex and description_selection_key(rule["description"]) >= (
                description_selection_key(baseline_regex[key])
            ) and description_selection_key(rule.get("signer_regex", "")) >= description_selection_key(baseline_signers.get(key, "")):
                skipped_baseline_regex_rules += 1
                continue
            inserted_regex_rules += int(insert_regex_record(
                connection, rule, modified_time=timestamp,
            ))
        for row in rows:
            record = normalized_record(row)
            if record["hash_key"] in excluded:
                skipped_excluded += 1
                continue
            if is_missing_file(
                image_path=record["image_path"],
                launch_string=record["launch_string"],
            ):
                skipped_missing += 1
                continue
            if classifier.reasons(
                image_path=record["image_path"],
                launch_string=record["launch_string"],
            ):
                skipped_non_promotable += 1
                continue
            (
                required,
                baseline_identity_found,
                _,
            ) = baseline_record_changes(
                    record,
                    baseline_connections,
            )
            if not required:
                skipped_baseline += 1
                continue
            if baseline_identity_found:
                retained_baseline_enrichment += 1
            row_inserted = insert_record(
                connection,
                record,
                modified_time=timestamp,
            )
            if row_inserted:
                inserted_records += 1
                inserted += 1
            else:
                existing += 1
        connection.commit()
        report = validate_database(
            database,
            rmm_reference=rmm_reference,
        )
    finally:
        connection.close()
        for baseline_connection in baseline_connections:
            baseline_connection.close()
    return {
        "inserted": inserted,
        "existing": existing,
        "inserted_records": inserted_records,
        "inserted_regex_rules": inserted_regex_rules,
        "skipped_baseline_regex_rules": skipped_baseline_regex_rules,
        "skipped_missing_file": skipped_missing,
        "skipped_non_promotable": skipped_non_promotable,
        "skipped_excluded": skipped_excluded,
        "skipped_baseline": skipped_baseline,
        "retained_baseline_enrichment": (
            retained_baseline_enrichment
        ),
        "baseline_database_count": len(baseline_paths),
        "database": str(database),
        "validation": report,
    }


def _atomic_database_path(output: Path) -> Path:
    return atomic_io.sibling_work_path(output, suffix=".sqlite.tmp")


def build_database(
    output: Path,
    inputs: Iterable[Path],
    *,
    replace: bool = False,
    exclude_hashes: set[str] | None = None,
    rmm_reference: Path | None = None,
    built_at: str | None = None,
    baseline_databases: Iterable[Path] | None = None,
    regex_inputs: Iterable[Path] = (),
) -> dict[str, Any]:
    if output.exists() and not replace:
        raise RuntimeError(
            f"GoldenDB already exists: {output}. Use --replace."
        )
    temporary = _atomic_database_path(output)
    try:
        result = promote_records(
            temporary,
            (
                row
                for path in inputs
                for row in iter_rows(path)
            ),
            rmm_reference=rmm_reference,
            exclude_hashes=exclude_hashes,
            modified_time=built_at,
            baseline_databases=baseline_databases,
            regex_rows=(row for path in regex_inputs for row in iter_rows(path)),
        )
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    result["database"] = str(output)
    result["validation"]["database"] = str(output)
    result["sha256"] = file_sha256(output)
    return result


def validate_database(
    path: Path,
    *,
    rmm_reference: Path | None = None,
    max_rows: int = MAX_LOOKUP_ROWS,
) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"GoldenDB not found: {path}")
    with closing(connect_database(path, readonly=True)) as probe:
        version = metadata(probe).get("schema_version")
    if version in {"7", "8", "9", "10"}:
        from vraptor.autoruns.regex_store import report
        return report(path, rmm_reference=rmm_reference)
    classifier = RmmClassifier(rmm_reference)
    connection = connect_database(path, readonly=True)
    try:
        quick_check = str(
            connection.execute("PRAGMA quick_check").fetchone()[0]
        )
        if quick_check != "ok":
            raise RuntimeError(
                f"GoldenDB SQLite quick_check failed: {quick_check}."
            )
        db_metadata = metadata(connection)
        if db_metadata.get("canonicalization_version") != str(autoruns.CANONICALIZATION_VERSION):
            raise RuntimeError(
                "GoldenDB canonicalization is incompatible. Rebuild a new database "
                "from reviewed original rows; old case-folded keys cannot be safely "
                "migrated or reused for suppression. Use --no-autoruns-golden for "
                "unfiltered host/hunt review while preparing the replacement."
            )
        for key, expected in REQUIRED_METADATA.items():
            if key == "schema_version" and db_metadata.get(key) in READABLE_SCHEMA_VERSIONS:
                continue
            if db_metadata.get(key) != expected:
                raise RuntimeError(
                    f"GoldenDB metadata {key!r} is "
                    f"{db_metadata.get(key)!r}; expected {expected!r}."
                )
        if db_metadata["schema_version"] == SCHEMA_VERSION:
            for table, expected_key in (
                ("autoruns_known_good", ("hash_key",)),
                ("autoruns_regex_rules", ("image_path_regex", "launch_string_regex")),
            ):
                columns = list(connection.execute(f"PRAGMA table_info({table})"))
                primary_key = tuple(row["name"] for row in sorted(columns, key=lambda row: row["pk"]) if row["pk"])
                if any(row["name"] == "category" for row in columns) or primary_key != expected_key:
                    raise RuntimeError(f"GoldenDB schema 6 requires a category-free {table} with primary key {expected_key}.")
        identity_count = int(
            connection.execute(
                "SELECT count(DISTINCT hash_key) FROM autoruns_known_good"
            ).fetchone()[0]
        )
        record_count = identity_count
        description_count = int(
            connection.execute(
                """
                SELECT count(DISTINCT hash_key) FROM autoruns_known_good
                WHERE description != ''
                """
            ).fetchone()[0]
        )
        if identity_count > max_rows:
            raise RuntimeError(
                f"GoldenDB contains {identity_count} identities; the live "
                f"memoized lookup limit is {max_rows}."
            )
        for row in connection.execute(
            """
            SELECT hash_key, image_path, launch_string, signer,
                   description, modified_time
            FROM autoruns_known_good
            ORDER BY hash_key
            """
        ):
            hash_key = str(row["hash_key"])
            if not HASH_RE.fullmatch(hash_key):
                raise RuntimeError(
                    f"GoldenDB contains an invalid hash_key: {hash_key!r}."
                )
            expected = autoruns.trusted_key(
                signer=row["signer"],
                image_path=row["image_path"],
                launch_string=row["launch_string"],
            )
            if expected != hash_key:
                raise RuntimeError(
                    f"GoldenDB identity {hash_key} fails canonical hash "
                    "verification."
                )
            if is_missing_file(
                image_path=row["image_path"],
                launch_string=row["launch_string"],
            ):
                raise RuntimeError(
                    f"GoldenDB contains non-promotable missing-file identity "
                    f"{hash_key}."
                )
            description = str(row["description"])
            if description != normalize_description(description):
                raise RuntimeError(
                    "GoldenDB contains an unsanitized or oversized "
                    "description."
                )
            if not str(row["modified_time"]):
                raise RuntimeError(
                    "GoldenDB contains an empty modified_time."
                )
            if classifier.reasons(
                image_path=row["image_path"],
                launch_string=row["launch_string"],
            ):
                raise RuntimeError(
                    f"GoldenDB contains non-promotable RMM/greyware identity "
                    f"{hash_key}."
                )
        stored_rules = regex_records(connection, deduplicate=False)
        if len(stored_rules) > max_rows:
            raise RuntimeError(f"GoldenDB exceeds the {max_rows} regex rule limit.")
        for rule in stored_rules:
            normalized = normalized_regex_record(rule)
            if any(normalized[key] != rule[key] for key in normalized):
                raise RuntimeError("GoldenDB contains a non-normalized regex rule.")
            if not rule["modified_time"]:
                raise RuntimeError("GoldenDB regex rule has an empty modified_time.")
        return {
            "database": str(path),
            "identity_count": identity_count,
            "record_count": record_count,
            "description_count": description_count,
            "regex_rule_count": len({regex_record_key(rule) for rule in stored_rules}),
            "metadata": db_metadata,
            "sha256": file_sha256(path),
            "rmm_reference": str(classifier.path),
            "rmm_reference_hash": classifier.reference_hash,
        }
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Invalid GoldenDB SQLite file {path}: {exc}"
        ) from exc
    finally:
        connection.close()


def live_lookup_payload(
    path: Path,
    *,
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    """Build the compact in-memory key index used by server-side VQL."""
    report = validate_database(
        path,
        rmm_reference=rmm_reference,
    )
    connection = connect_database(path, readonly=True)
    try:
        keys = sorted({str(row["hash_key"]) for row in exact_records(connection)})
        regex_rules: list[dict[str, str]] = []
        for rule in regex_records(connection):
            if report["metadata"]["schema_version"] == "10":
                regex_rules.append({field + "Regex": rule[field] for field in
                    ("Category", "ImagePath", "LaunchString", "Signer")})
            elif report.get("regex_only"):
                regex_rules.append({"CategoryRegex": autoruns_regex.full_pattern(autoruns_regex.category_pattern(rule["category_regex"])),
                    "ImagePathRegex": autoruns_regex.full_pattern(rule["image_path_regex"]), "LaunchStringRegex": autoruns_regex.full_pattern(rule["launch_string_regex"]),
                    "SignerRegex": autoruns_regex.full_pattern(rule["signer_regex"])})
            else:
                regex_rules.append({
                    "ImagePathRegex": autoruns_regex.full_pattern(rule["image_path_regex"]),
                    "LaunchStringRegex": autoruns_regex.full_pattern(rule["launch_string_regex"]),
                })
    finally:
        connection.close()
    serialized = stable_json(keys).encode("utf-8")
    compressed = gzip.compress(
        serialized,
        compresslevel=PUBLISH_GZIP_LEVEL,
        mtime=0,
    )
    encoded = base64.b64encode(compressed).decode("ascii")
    regex_serialized = stable_json(regex_rules).encode("utf-8") if regex_rules else b""
    regex_compressed = (
        gzip.compress(regex_serialized, compresslevel=PUBLISH_GZIP_LEVEL, mtime=0)
        if regex_rules else b""
    )
    regex_encoded = base64.b64encode(regex_compressed).decode("ascii")
    # Invalidate earlier suppression caches when the approved-rule contract changes.
    regex_policy = report.get("matching_policy", autoruns_regex.MATCHING_POLICY).encode("utf-8") if regex_rules else b""
    if len(encoded) + len(regex_encoded) > MAX_LIVE_LOOKUP_BASE64_BYTES:
        raise RuntimeError(
            "Autoruns GoldenDB live lookup payload requires "
            f"{len(encoded) + len(regex_encoded)} base64 bytes; the limit is "
            f"{MAX_LIVE_LOOKUP_BASE64_BYTES}. Split or compact the "
            "GoldenDB before live analysis."
        )
    return {
        **report,
        "lookup_key_count": len(keys),
        "lookup_payload_sha256": hashlib.sha256(serialized + regex_serialized + regex_policy).hexdigest(),
        "lookup_uncompressed_bytes": len(serialized) + len(regex_serialized),
        "lookup_compressed_bytes": len(compressed) + len(regex_compressed),
        "lookup_base64_bytes": len(encoded) + len(regex_encoded),
        "lookup_gzip_base64": encoded,
        "regex_lookup_gzip_base64": regex_encoded,
        "lookup_transport": "gzip-base64-json",
    }


def merge_databases(
    output: Path,
    inputs: Iterable[Path],
    *,
    replace: bool = False,
    rmm_reference: Path | None = None,
    built_at: str | None = None,
) -> dict[str, Any]:
    source_paths = [Path(path) for path in inputs]
    if output.exists() and not replace:
        raise RuntimeError(
            f"GoldenDB already exists: {output}. Use --replace."
        )
    for path in source_paths:
        if validate_database(path, rmm_reference=rmm_reference).get("regex_only"):
            raise RuntimeError("Regex-only GoldenDB requires regex-import; legacy merge cannot preserve four-field semantics.")
    timestamp = built_at or now_utc()
    temporary = _atomic_database_path(output)
    try:
        destination = connect_database(temporary)
        inserted = 0
        try:
            initialize_database(destination, built_at=timestamp)
            merge_metadata = {
                "build_mode": "merged",
                "source_database_count": str(len(source_paths)),
                "source_database_sha256s": stable_json(
                    sorted(file_sha256(path) for path in source_paths)
                ),
            }
            destination.executemany(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                sorted(merge_metadata.items()),
            )
            for source_path in sorted(source_paths, key=lambda value: str(value)):
                source = connect_database(source_path, readonly=True)
                try:
                    source_metadata = metadata(source)
                    for key, expected in REQUIRED_METADATA.items():
                        if key == "schema_version" and source_metadata.get(key) in READABLE_SCHEMA_VERSIONS:
                            continue
                        if source_metadata.get(key) != expected:
                            raise RuntimeError(
                                f"Cannot merge {source_path}: incompatible {key}."
                            )
                    for record in exact_records(source):
                        if insert_record(
                            destination,
                            record,
                            modified_time=str(record["modified_time"]),
                        ):
                            inserted += 1
                    for rule in regex_records(source):
                        insert_regex_record(
                            destination, rule, modified_time=rule["modified_time"],
                        )
                finally:
                    source.close()
            destination.commit()
        finally:
            destination.close()
        report = validate_database(
            temporary,
            rmm_reference=rmm_reference,
        )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    report.update(
        {
            "database": str(output),
            "source_count": len(source_paths),
            "inserted": inserted,
            "sha256": file_sha256(output),
        }
    )
    return report


def database_change_summary(
    target: Path | None, delta: Path, *, rmm_reference: Path | None = None,
) -> dict[str, Any]:
    delta_report = validate_database(delta, rmm_reference=rmm_reference)
    target_report = validate_database(target, rmm_reference=rmm_reference) if target is not None and target.exists() else None
    if delta_report.get("regex_only") or (target_report and target_report.get("regex_only")):
        raise RuntimeError("Regex-only GoldenDB requires regex-import; legacy delta/apply is disabled.")
    delta_connection = connect_database(delta, readonly=True)
    target_connection = connect_database(target, readonly=True) if target_report is not None else None
    try:
        target_rows = {row["hash_key"]: row for row in exact_records(target_connection)} if target_connection else {}
        delta_rows = exact_records(delta_connection)
        new_records = improved_descriptions = unchanged_descriptions = 0
        for row in delta_rows:
            existing = target_rows.get(row["hash_key"])
            if existing is None:
                new_records += 1
            else:
                if any(existing[name] != row[name] for name in ("image_path", "launch_string", "signer")):
                    raise RuntimeError(f"GoldenDB delta contains a hash collision or canonicalization mismatch for {row['hash_key']}.")
                if description_selection_key(row["description"]) < description_selection_key(existing["description"]):
                    improved_descriptions += 1
                else:
                    unchanged_descriptions += 1
        target_rules = {regex_record_key(rule): rule for rule in regex_records(target_connection)} if target_connection else {}
        new_regex_rules = improved_regex_descriptions = improved_regex_signers = 0
        for rule in regex_records(delta_connection):
            existing = target_rules.get(regex_record_key(rule))
            if existing is None:
                new_regex_rules += 1
            else:
                improved_regex_descriptions += int(description_selection_key(rule["description"]) < description_selection_key(existing["description"]))
                improved_regex_signers += int(description_selection_key(rule["signer_regex"]) < description_selection_key(existing["signer_regex"]))
    finally:
        delta_connection.close()
        if target_connection is not None:
            target_connection.close()
    existing_records = len(delta_rows) - new_records
    return {
        "target_exists": target_report is not None, "target": target_report or {}, "delta": delta_report,
        "new_identity_count": new_records, "existing_identity_count": existing_records,
        "new_record_count": new_records, "existing_record_count": existing_records,
        "improved_description_count": improved_descriptions, "unchanged_description_count": unchanged_descriptions,
        "new_regex_rule_count": new_regex_rules, "improved_regex_description_count": improved_regex_descriptions,
        "improved_regex_signer_reference_count": improved_regex_signers,
        "effective_change_count": new_records + improved_descriptions + new_regex_rules + improved_regex_descriptions + improved_regex_signers,
    }

def _delta_baseline_hashes(report: dict[str, Any]) -> list[str]:
    metadata_values = dict(report.get("metadata") or {})
    raw = str(
        metadata_values.get("baseline_database_sha256s") or "[]"
    )
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "GoldenDB delta has invalid baseline hash metadata."
        ) from exc
    if not isinstance(values, list):
        raise RuntimeError(
            "GoldenDB delta baseline hash metadata must be a list."
        )
    return sorted(
        str(value).strip().casefold()
        for value in values
        if str(value).strip()
    )


def write_delta_manifest(
    path: Path,
    *,
    delta: Path,
    baseline: Path | None,
    investigation_id: str,
    hunt_id: str,
    artifact: str,
    status: str,
    rmm_reference: Path | None = None,
    candidate_review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    delta_report = validate_database(
        delta,
        rmm_reference=rmm_reference,
    )
    baseline_report = (
        validate_database(baseline, rmm_reference=rmm_reference)
        if baseline is not None and baseline.exists()
        else None
    )
    payload = {
        "schema_version": AUTORUNS_GOLDEN_DELTA_MANIFEST_SCHEMA_VERSION,
        "kind": "autoruns_golden_delta",
        "created_at": now_utc(),
        "status": str(status),
        "source": {
            "investigation_id": str(investigation_id),
            "hunt_id": str(hunt_id),
            "artifact": str(artifact),
        },
        "baseline": baseline_report or {
            "database": str(baseline) if baseline is not None else "",
            "identity_count": 0,
            "record_count": 0,
            "description_count": 0,
            "sha256": "",
        },
        "delta": delta_report,
    }
    if candidate_review:
        payload["candidate_review"] = dict(candidate_review)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return payload


def _apply_delta_database_locked(
    target: Path,
    delta: Path,
    *,
    dry_run: bool = False,
    backup_dir: Path | None = None,
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    target = target.expanduser().resolve()
    delta = delta.expanduser().resolve()
    if target == delta:
        raise RuntimeError("GoldenDB target and delta must be different files.")
    for path in (target, delta):
        if path.exists():
            _require_standalone_database(path)
    summary = database_change_summary(
        target if target.exists() else None,
        delta,
        rmm_reference=rmm_reference,
    )
    delta_report = dict(summary["delta"])
    delta_metadata = dict(delta_report.get("metadata") or {})
    build_mode = str(delta_metadata.get("build_mode") or "")
    if build_mode != "delta":
        raise RuntimeError(
            "autoruns apply requires a GoldenDB with build_mode=delta."
        )
    baseline_count = int(
        delta_metadata.get("baseline_database_count") or 0
    )
    baseline_hashes = _delta_baseline_hashes(delta_report)
    before = dict(summary.get("target") or {})
    if target.exists():
        if baseline_count < 1:
            raise RuntimeError(
                "This delta was created without a baseline and may only "
                "install a new GoldenDB."
            )
        if str(before.get("sha256") or "").casefold() not in baseline_hashes:
            raise RuntimeError(
                "GoldenDB target revision does not match the delta baseline; "
                "regenerate the delta against the current shared database."
            )
    elif baseline_count or baseline_hashes:
        raise RuntimeError(
            "This delta requires an existing GoldenDB baseline."
        )
    result = {
        "action": "autoruns_golden_apply",
        "dry_run": bool(dry_run),
        "target": str(target),
        "delta": str(delta),
        "before": before,
        "changes": {
            key: summary[key]
            for key in (
                "new_identity_count",
                "existing_identity_count",
                "new_record_count",
                "existing_record_count",
                "improved_description_count",
                "unchanged_description_count",
                "new_regex_rule_count",
                "improved_regex_description_count",
                "improved_regex_signer_reference_count",
                "effective_change_count",
            )
        },
        "backup": "",
        "after": {},
        "installed": False,
        "no_changes": summary["effective_change_count"] == 0,
    }
    if dry_run or (result["no_changes"] and target.exists()):
        return result
    target.parent.mkdir(parents=True, exist_ok=True)
    next_database = _atomic_database_path(target)
    backup = None
    try:
        if target.exists():
            merge_databases(
                next_database,
                [target, delta],
                rmm_reference=rmm_reference,
            )
            backup_root = (
                backup_dir.expanduser().resolve()
                if backup_dir is not None
                else target.parent / "backups"
            )
            backup_root.mkdir(parents=True, exist_ok=True)
            token = datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            backup = backup_root / (
                f"{target.stem}.{token}."
                f"{str(before.get('sha256') or '')[:8]}.sqlite"
            )
            shutil.copy2(target, backup)
            validate_database(backup, rmm_reference=rmm_reference)
            if file_sha256(backup) != before["sha256"]:
                raise RuntimeError("GoldenDB changed while preparing the backup.")
            with backup.open("rb") as handle:
                os.fsync(handle.fileno())
        else:
            shutil.copy2(delta, next_database)
        validate_database(next_database, rmm_reference=rmm_reference)
        if target.exists():
            if file_sha256(target) != before["sha256"]:
                raise RuntimeError("GoldenDB changed while preparing the replacement.")
            os.chmod(next_database, stat.S_IMODE(target.stat().st_mode))
        with next_database.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(next_database, target)
    finally:
        if next_database.exists():
            next_database.unlink()
    after = validate_database(target, rmm_reference=rmm_reference)
    result["backup"] = str(backup) if backup is not None else ""
    result["after"] = after
    result["installed"] = True
    return result


def apply_delta_database(
    target: Path,
    delta: Path,
    *,
    dry_run: bool = False,
    backup_dir: Path | None = None,
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    target = target.expanduser().resolve()
    if dry_run:
        return _apply_delta_database_locked(
            target,
            delta,
            dry_run=True,
            backup_dir=backup_dir,
            rmm_reference=rmm_reference,
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(f".{target.name}.lock")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _apply_delta_database_locked(
                target,
                delta,
                dry_run=dry_run,
                backup_dir=backup_dir,
                rmm_reference=rmm_reference,
            )
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def lookup_hashes(database: Path, hashes: Iterable[str]) -> list[dict[str, Any]]:
    validate_database(database)
    connection = connect_database(database, readonly=True)
    output: list[dict[str, Any]] = []
    try:
        records = {row["hash_key"]: row for row in exact_records(connection)}
        for raw_hash in hashes:
            hash_key = str(raw_hash).strip().casefold()
            if not HASH_RE.fullmatch(hash_key):
                raise RuntimeError(f"Invalid Autoruns SHA-1 identity: {hash_key!r}.")
            row = records.get(hash_key)
            if row is None:
                output.append({"hash_key": hash_key, "known_good": False})
                continue
            output.append({
                **row, "known_good": True,
                "records": [{name: row[name] for name in ("description", "modified_time")}],
                "context": {"example_entry_location": "", "example_entry": "", "example_description": row["description"], "example_company": ""},
            })
    finally:
        connection.close()
    return output

def lookup_identity(
    database: Path,
    *,
    category: Any = "",
    signer: Any,
    image_path: Any,
    launch_string: Any,
) -> dict[str, Any]:
    record = autoruns.trusted_record(
        category=category,
        signer=signer,
        image_path=image_path,
        launch_string=launch_string,
    )
    result = lookup_hashes(database, [str(record["hash_key"])])[0]
    result.update(
        {
            "query": {
                "category": str(record["category"]),
                "image_path": str(record["image_path"]),
                "launch_string": str(record["launch_string"]),
                "signer": str(record["signer"]),
            },
            "hash_match": bool(result["known_good"]),
        }
    )
    connection = connect_database(database, readonly=True)
    try:
        result["regex_match"] = autoruns_regex.RegexIndex(regex_records(connection)).matches(record)
    finally:
        connection.close()
    result["filter_match"] = result["hash_match"] or result["regex_match"]
    return result


def _csv_fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    fields: list[str] = []
    for row in rows:
        for name in row:
            value = str(name)
            if value not in fields:
                fields.append(value)
    for name in (FILTER_HASH_FIELD, FILTER_STATUS_FIELD):
        if name not in fields:
            fields.append(name)
    return fields


def write_csv_rows(
    output: Path,
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with temporary.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()


def filter_autoruns_rows(
    database: Path,
    rows: Iterable[dict[str, Any]],
    *,
    output: Path,
) -> dict[str, Any]:
    validate_database(database)
    source_rows = [dict(row) for row in rows]
    residual_rows: list[dict[str, Any]] = []
    input_rows = 0
    known_good_rows = 0
    empty_identity_rows = 0
    cached_matches: dict[tuple[str, str], bool] = {}
    connection = connect_database(database, readonly=True)
    try:
        regex_index = autoruns_regex.RegexIndex(regex_records(connection))
        regex_only = metadata(connection).get("schema_version") == "10"
        for row in source_rows:
            input_rows += 1
            record = normalized_record(row)
            if not record["image_path"] and not record["launch_string"]:
                empty_identity_rows += 1
                continue
            hash_key = record["hash_key"]
            cache_key = (record["category"], hash_key)
            match = cached_matches.get(cache_key)
            if match is None:
                match = (not regex_only and connection.execute(
                    "SELECT 1 FROM autoruns_known_good WHERE hash_key=?", (hash_key,),
                ).fetchone() is not None) or regex_index.matches(record)
                cached_matches[cache_key] = match
            if match:
                known_good_rows += 1
                continue
            status = "not_known_good"
            residual_rows.append(
                {
                    **row,
                    FILTER_HASH_FIELD: hash_key,
                    FILTER_STATUS_FIELD: status,
                }
            )
    finally:
        connection.close()
    fieldnames = _csv_fieldnames(source_rows)
    write_csv_rows(output, residual_rows, fieldnames=fieldnames)
    return {
        "database": str(database),
        "database_mode": "read_only",
        "output": str(output),
        "input_rows": input_rows,
        "known_good_filtered_rows": known_good_rows,
        "empty_identity_dropped_rows": empty_identity_rows,
        "residual_rows": len(residual_rows),
    }


def _manifest_autoruns_sources(
    manifest_path: Path,
) -> list[tuple[str, Path]]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"Collection manifest {manifest_path} must be a JSON object."
        )
    candidates: list[tuple[str, str]] = []
    for item in payload.get("exported_files") or []:
        if not isinstance(item, dict):
            continue
        artifact = str(
            item.get("artifact") or item.get("artifact_name") or ""
        ).strip()
        output_file = str(item.get("output_file") or "").strip()
        if artifact in SUPPORTED_AUTORUNS_ARTIFACTS and output_file:
            candidates.append((artifact, output_file))
    if not candidates:
        for item in payload.get("items") or []:
            if not isinstance(item, dict):
                continue
            artifact = str(item.get("artifact") or "").strip()
            if artifact not in SUPPORTED_AUTORUNS_ARTIFACTS:
                continue
            for value in item.get("exported_files") or []:
                output_file = str(value or "").strip()
                if output_file:
                    candidates.append((artifact, output_file))
    sources: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for artifact, value in candidates:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = manifest_path.parent / path
        path = path.resolve()
        if path in seen:
            continue
        if not path.is_file():
            raise RuntimeError(
                f"Autoruns collection export not found: {path}"
            )
        seen.add(path)
        sources.append((artifact, path))
    if not sources:
        raise RuntimeError(
            "Collection manifest contains no exported "
            "IG.Windows.Sysinternals.Autoruns or "
            "Windows.Sysinternals.Autoruns results."
        )
    return sources


def filter_autoruns_inputs(
    database: Path,
    *,
    inputs: Iterable[Path] = (),
    manifest: Path | None = None,
    output: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    source_paths = [Path(path).expanduser().resolve() for path in inputs]
    source_artifacts: dict[Path, str] = {}
    if manifest is not None:
        manifest = Path(manifest).expanduser().resolve()
        for artifact, path in _manifest_autoruns_sources(manifest):
            source_paths.append(path)
            source_artifacts[path] = artifact
    if not source_paths:
        raise RuntimeError("Pass --input or --manifest.")
    if output is not None and len(source_paths) != 1:
        raise RuntimeError(
            "--output is valid only when filtering one input file."
        )
    if output is not None and output_dir is not None:
        raise RuntimeError("--output and --output-dir are mutually exclusive.")
    if output_dir is None:
        output_dir = (
            manifest.parent / "autoruns-golden-filter"
            if manifest is not None
            else source_paths[0].parent
        )
    output_dir = Path(output_dir).expanduser().resolve()
    results: list[dict[str, Any]] = []
    for source in source_paths:
        target = (
            Path(output).expanduser().resolve()
            if output is not None
            else output_dir / f"{source.stem}.golden-residual.csv"
        )
        result = filter_autoruns_rows(
            database,
            iter_rows(source),
            output=target,
        )
        result.update(
            {
                "input": str(source),
                "artifact": source_artifacts.get(source, ""),
            }
        )
        results.append(result)
    return {
        "action": "autoruns_golden_filter",
        "database": str(database),
        "database_mode": "read_only",
        "manifest": str(manifest) if manifest is not None else "",
        "results": results,
        "input_rows": sum(item["input_rows"] for item in results),
        "known_good_filtered_rows": sum(
            item["known_good_filtered_rows"] for item in results
        ),
        "empty_identity_dropped_rows": sum(
            item["empty_identity_dropped_rows"] for item in results
        ),
        "residual_rows": sum(item["residual_rows"] for item in results),
    }


def remove_hashes(
    database: Path,
    hashes: Iterable[str],
    *,
    category: str = "",
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    report = validate_database(database, rmm_reference=rmm_reference)
    if report.get("regex_only"):
        raise RuntimeError("Regex-only GoldenDB has no removable hash entries; use reviewed regex maintenance.")
    if report["metadata"]["schema_version"] != SCHEMA_VERSION:
        raise RuntimeError("Legacy GoldenDB writes require an explicit merge into schema 6 first.")
    normalized_hashes: list[str] = []
    for raw_hash in hashes:
        hash_key = str(raw_hash).strip().casefold()
        if not HASH_RE.fullmatch(hash_key):
            raise RuntimeError(
                f"Invalid Autoruns SHA-1 identity: {hash_key!r}."
            )
        if hash_key not in normalized_hashes:
            normalized_hashes.append(hash_key)
    if category:
        raise RuntimeError("GoldenDB category-scoped removal is unsupported; remove the whole hash explicitly.")
    removed_identities = 0
    connection = connect_database(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        missing: list[str] = []
        for hash_key in normalized_hashes:
            exists = connection.execute(
                """
                SELECT 1
                FROM autoruns_known_good
                WHERE hash_key = ?
                """,
                (hash_key,),
            ).fetchone()
            if exists is None:
                missing.append(hash_key)
                continue
        if missing:
            raise RuntimeError(
                "GoldenDB removal target not found: "
                + ", ".join(missing)
            )
        for hash_key in normalized_hashes:
            connection.execute("DELETE FROM autoruns_known_good WHERE hash_key = ?", (hash_key,))
            removed_identities += 1
        connection.execute(
            """
            INSERT OR REPLACE INTO metadata (key, value)
            VALUES ('last_modified_at', ?)
            """,
            (now_utc(),),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    validation = validate_database(
        database,
        rmm_reference=rmm_reference,
    )
    return {
        "database": str(database),
        "requested_hash_count": len(normalized_hashes),
        "removed_identity_count": removed_identities,
        "removed_record_count": removed_identities,
        "validation": validation,
        "sha256": validation["sha256"],
    }


def publish_database(
    client: Any,
    database: Path,
    *,
    tool_name: str,
    tool_version: str = DEFAULT_TOOL_VERSION,
    filename: str = DEFAULT_TOOL_FILENAME,
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    from vraptor.results import require_remote_mutation
    require_remote_mutation("publish_database")
    report = validate_database(
        database,
        rmm_reference=rmm_reference,
    )
    size = database.stat().st_size
    if size > MAX_PUBLISH_UNCOMPRESSED_BYTES:
        raise RuntimeError(
            f"GoldenDB is {size} bytes; publication is limited to "
            f"{MAX_PUBLISH_UNCOMPRESSED_BYTES} uncompressed bytes because "
            "Velociraptor gunzip() materializes the restored database in "
            "server memory."
        )
    verify_vql = """
SELECT inventory_get(
    tool=ToolName,
    version=ToolVersion,
    probe=TRUE) AS Definition
FROM scope()
""".strip()
    try:
        existing = client.query(
            verify_vql,
            env={"ToolName": tool_name, "ToolVersion": tool_version},
            max_row=10,
        )
    except velociraptor_api.InventoryNotFoundError:
        existing = []
    existing_value = (existing[0] if existing else {}).get("Definition")
    definition = (
        existing_value.get("Definition", existing_value)
        if isinstance(existing_value, dict) else {}
    )
    remote_hash = (
        str(definition.get("hash") or "").strip().lower()
        if isinstance(definition, dict) else ""
    )
    if remote_hash == report["sha256"]:
        return {
            "tool": tool_name,
            "version": tool_version,
            "filename": filename,
            "database": str(database),
            "database_sha256": report["sha256"],
            "database_built_at": str((report.get("metadata") or {}).get("built_at") or ""),
            "database_bytes": size,
            "status": "current",
            "uploaded": False,
            "transport": "none",
            "verified": existing_value,
        }
    database_bytes = database.read_bytes()
    compressed = gzip.compress(
        database_bytes,
        compresslevel=PUBLISH_GZIP_LEVEL,
        mtime=0,
    )
    grpc_message_limit = velociraptor_api.grpc_max_message_bytes()
    encoded_limit = min(
        MAX_PUBLISH_BASE64_BYTES,
        max(0, grpc_message_limit - PUBLISH_GRPC_OVERHEAD_BYTES),
    )
    if encoded_limit <= 0:
        raise RuntimeError(
            "Configured VELO_GRPC_MAX_MESSAGE_BYTES leaves no room for the "
            "GoldenDB payload after the publication safety margin."
        )
    encoded_size = 4 * ((len(compressed) + 2) // 3)
    if encoded_size > encoded_limit:
        raise RuntimeError(
            f"GoldenDB gzip payload requires {encoded_size} base64 bytes; "
            f"publication is limited to {encoded_limit} bytes "
            "so the request remains below the configured gRPC message "
            "ceiling."
        )
    encoded = base64.b64encode(compressed).decode("ascii")
    upload_vql = """
SELECT inventory_add(
    tool=ToolName,
    file=gunzip(string=base64decode(string=DatabaseGzipBase64)),
    accessor="data",
    serve_locally=TRUE,
    filename=ToolFilename,
    version=ToolVersion) AS Published
FROM scope()
""".strip()
    rows = client.query(
        upload_vql,
        env={
            "DatabaseGzipBase64": encoded,
            "ToolName": tool_name,
            "ToolFilename": filename,
            "ToolVersion": tool_version,
        },
        max_row=10,
    )
    if not rows:
        raise RuntimeError("Velociraptor inventory_add returned no result.")
    if not rows[0].get("Published"):
        raise RuntimeError(
            "Velociraptor inventory_add did not return a tool definition."
        )
    verified = client.query(
        verify_vql,
        env={
            "ToolName": tool_name,
            "ToolVersion": tool_version,
        },
        max_row=10,
    )
    if not verified:
        raise RuntimeError(
            "GoldenDB was uploaded but inventory_get verification returned "
            "no result."
        )
    if not verified[0].get("Definition"):
        raise RuntimeError(
            "GoldenDB inventory_get verification returned no definition."
        )
    verified_value = verified[0]["Definition"]
    if not isinstance(verified_value, dict):
        raise RuntimeError(
            "GoldenDB inventory_get verification returned an invalid "
            "definition."
        )
    definition = verified_value.get("Definition", verified_value)
    if not isinstance(definition, dict):
        raise RuntimeError(
            "GoldenDB inventory_get verification returned invalid nested "
            "metadata."
        )
    remote_hash = str(definition.get("hash") or "").strip().lower()
    if not remote_hash:
        raise RuntimeError(
            "GoldenDB inventory_get verification returned no file hash."
        )
    if remote_hash != report["sha256"]:
        raise RuntimeError(
            "GoldenDB inventory hash mismatch: "
            f"expected {report['sha256']}, received {remote_hash}."
        )
    return {
        "tool": tool_name,
        "version": tool_version,
        "filename": filename,
        "database": str(database),
        "database_sha256": report["sha256"],
        "database_built_at": str((report.get("metadata") or {}).get("built_at") or ""),
        "database_bytes": size,
        "status": "updated",
        "uploaded": True,
        "transport": "grpc-vql-gzip-base64",
        "gzip_bytes": len(compressed),
        "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
        "base64_bytes": encoded_size,
        "base64_limit_bytes": encoded_limit,
        "grpc_message_limit_bytes": grpc_message_limit,
        "compression_ratio": round(len(compressed) / size, 6),
        "published": rows[0].get("Published", rows[0]),
        "verified": verified_value,
    }


def autoruns_analysis_paths(
    *,
    case_root: Path,
    investigation_id: str,
    hunt_id: str,
) -> dict[str, Path]:
    analysis_root = (
        case_root
        / investigation_id
        / "hunts"
        / hunt_id
        / "analysis"
    )
    return {
        "root": analysis_root,
        "delta": analysis_root / AUTORUNS_GOLDEN_DELTA_FILENAME,
        "delta_manifest": (
            analysis_root / AUTORUNS_GOLDEN_DELTA_MANIFEST_FILENAME
        ),
        "potential_golden": (
            analysis_root / AUTORUNS_POTENTIAL_GOLDEN_FILENAME
        ),
        "residual_stack": (
            analysis_root / AUTORUNS_RESIDUAL_STACK_FILENAME
        ),
        "potential_golden_enriched": (
            analysis_root / AUTORUNS_POTENTIAL_GOLDEN_ENRICHED_FILENAME
        ),
    }


def validate_candidate_subset(
    canonical_path: Path,
    selected_path: Path,
    *,
    live: Any,
) -> dict[str, Any]:
    if not canonical_path.is_file():
        raise RuntimeError(
            f"Canonical potential GoldenDB CSV not found: {canonical_path}"
        )
    if not selected_path.is_file():
        raise RuntimeError(
            f"Selected potential GoldenDB CSV not found: {selected_path}"
        )

    def attestation_prefix(path: Path) -> list[str]:
        prefix: list[str] = []
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            prefix.append(line)
            if not line.startswith("#"):
                break
        return prefix

    if attestation_prefix(selected_path) != attestation_prefix(canonical_path):
        raise RuntimeError(
            "Selected potential GoldenDB CSV comments and header must "
            "exactly match the canonical candidate file."
        )
    canonical_metadata, canonical_rows, canonical_fields = (
        live.parse_csv_with_metadata(canonical_path)
    )
    if canonical_metadata.get("CanonicalizationVersion") != str(autoruns.CANONICALIZATION_VERSION):
        raise RuntimeError(
            "Potential GoldenDB candidates use an incompatible canonicalization "
            "version. Rerun analysis against original evidence and review the "
            "new candidates; do not relabel or rehash the old candidate file."
        )
    selected_metadata, selected_rows, selected_fields = (
        live.parse_csv_with_metadata(selected_path)
    )
    expected_fields = list(live.AUTORUNS_POTENTIAL_GOLDEN_FIELDS)
    if canonical_fields != expected_fields:
        raise RuntimeError("Canonical potential GoldenDB CSV fields are invalid.")
    if selected_fields != expected_fields:
        raise RuntimeError("Selected potential GoldenDB CSV fields are invalid.")
    if selected_metadata != canonical_metadata:
        raise RuntimeError(
            "Selected potential GoldenDB CSV metadata must exactly match the "
            "canonical candidate file."
        )

    def row_key(row: dict[str, Any]) -> tuple[str, ...]:
        return tuple(str(row.get(field) or "") for field in expected_fields)

    canonical_keys = [row_key(row) for row in canonical_rows]
    if len(set(canonical_keys)) != len(canonical_keys):
        raise RuntimeError(
            "Canonical potential GoldenDB CSV contains duplicate rows."
        )
    canonical_set = set(canonical_keys)
    selected_keys: set[tuple[str, ...]] = set()
    for index, row in enumerate(selected_rows, start=1):
        key = row_key(row)
        if key in selected_keys:
            raise RuntimeError(
                "Selected potential GoldenDB CSV contains a duplicate row at "
                f"data row {index}."
            )
        if key not in canonical_set:
            raise RuntimeError(
                "Selected potential GoldenDB CSV contains an added or edited "
                f"row at data row {index}; only deletion of canonical rows is "
                "allowed."
            )
        selected_keys.add(key)
    retained_in_canonical_order = [
        key for key in canonical_keys if key in selected_keys
    ]
    if retained_in_canonical_order != [row_key(row) for row in selected_rows]:
        raise RuntimeError(
            "Selected potential GoldenDB CSV changes canonical row order; "
            "only deletion of canonical rows is allowed."
        )
    return {
        "metadata": canonical_metadata,
        "rows": selected_rows,
        "fields": selected_fields,
        "canonical_row_count": len(canonical_rows),
        "selected_row_count": len(selected_rows),
        "removed_row_count": len(canonical_rows) - len(selected_rows),
        "canonical_path": str(canonical_path),
        "canonical_sha256": file_sha256(canonical_path),
        "selected_path": str(selected_path),
        "selected_sha256": file_sha256(selected_path),
    }


def candidate_path_context(path: Path) -> dict[str, str]:
    """Infer standard case context from a candidate file beside analysis."""

    selected = path.expanduser().resolve()
    analysis_root = selected.parent
    hunt_root = analysis_root.parent
    hunts_root = hunt_root.parent
    engagement_root = hunts_root.parent
    if analysis_root.name != "analysis" or hunts_root.name != "hunts":
        return {}
    return {
        "EngagementId": engagement_root.name,
        "HuntId": hunt_root.name,
        "CaseRoot": str(engagement_root.parent),
    }


def resolve_promotion_source_args(args: argparse.Namespace) -> None:
    """Resolve omitted case-bound promotion arguments from the selected CSV."""

    from vraptor.hunt import live

    selected_path = Path(args.input).expanduser().resolve()
    metadata, _, _ = live.parse_csv_with_metadata(selected_path)
    inferred = candidate_path_context(selected_path)

    def select_value(
        *,
        explicit: Any,
        metadata_name: str,
        path_name: str = "",
        label: str,
        required: bool = True,
    ) -> str:
        explicit_value = str(explicit or "").strip()
        metadata_value = str(metadata.get(metadata_name) or "").strip()
        path_value = str(inferred.get(path_name or metadata_name) or "").strip()
        if (
            metadata_value
            and path_value
            and metadata_value.casefold() != path_value.casefold()
        ):
            raise RuntimeError(
                f"Candidate {label} metadata {metadata_value!r} does not "
                f"match path-derived provenance {path_value!r}."
            )
        discovered = metadata_value or path_value
        if (
            explicit_value
            and discovered
            and explicit_value.casefold() != discovered.casefold()
        ):
            raise RuntimeError(
                f"Promotion {label} {explicit_value!r} does not match "
                f"candidate provenance {discovered!r}."
            )
        selected = explicit_value or discovered
        if required and not selected:
            raise RuntimeError(
                f"Cannot infer promotion {label} from {selected_path}; "
                f"provide --{label.replace(' ', '-')} or use a candidate "
                "CSV with embedded provenance."
            )
        return selected

    args.investigation_id = select_value(
        explicit=getattr(args, "investigation_id", None),
        metadata_name="EngagementId",
        label="engagement-id",
    )
    args.hunt_id = select_value(
        explicit=getattr(args, "hunt_id", None),
        metadata_name="HuntId",
        label="hunt-id",
    )
    args.artifact = select_value(
        explicit=getattr(args, "artifact", None),
        metadata_name="Artifact",
        label="artifact",
        required=False,
    ) or DEFAULT_AUTORUNS_ARTIFACT
    explicit_case_root = str(getattr(args, "case_root", None) or "").strip()
    inferred_case_root = str(inferred.get("CaseRoot") or "").strip()
    if explicit_case_root and inferred_case_root:
        if (
            Path(explicit_case_root).expanduser().resolve()
            != Path(inferred_case_root).resolve()
        ):
            raise RuntimeError(
                "Promotion case root does not match the candidate path."
            )
    if not explicit_case_root and inferred_case_root:
        args.case_root = inferred_case_root


def apply_engagement_context(args: argparse.Namespace) -> None:
    context = engagement_context.resolve(
        repo_root=REPO_ROOT,
        engagement_id=args.investigation_id,
        server_profile=args.server_profile,
        api_client=args.api_client,
        case_root=args.case_root,
        expected_org_id=args.org_id,
    )
    args.investigation_id = context.engagement_id
    args.server_profile = context.server_profile
    args.api_client = str(context.api_client)
    args.case_root = str(context.case_root)


def candidate_identity(row: dict[str, Any]) -> tuple[str, str, str]:
    payload = autoruns.trusted_key_payload(
        signer=row.get("Signer", row.get("signer")),
        image_path=row.get("ImagePath", row.get("image_path")),
        launch_string=row.get("LaunchString", row.get("launch_string")),
    )
    return (
        str(payload["ImagePath"]),
        str(payload["LaunchString"]),
        str(payload["Signer"]),
    )


def database_rows(database: Path) -> list[dict[str, str]]:
    connection = connect_database(database, readonly=True)
    try:
        fields = {"hash_key": "HashKey", "image_path": "ImagePath", "launch_string": "LaunchString", "signer": "Signer", "description": "Description"}
        return [{target: row[source] for source, target in fields.items()} for row in exact_records(connection)]
    finally:
        connection.close()

def reconcile_database_rows(
    database: Path,
    rows: Iterable[dict[str, Any]],
    *,
    candidate_rows: Iterable[dict[str, Any]] = (),
    rmm_reference: Path | None = None,
) -> dict[str, Any]:
    """Classify exact HashKey rows against the current GoldenDB."""

    candidate_numbers = {
        candidate_identity(row): index
        for index, row in enumerate(candidate_rows, start=1)
    }
    grouped: dict[str, dict[str, str]] = {}
    for raw in rows:
        record = normalized_record(dict(raw))
        key = record["hash_key"]
        current = grouped.get(key)
        if current is None or description_selection_key(
            record["description"]
        ) < description_selection_key(current["description"]):
            grouped[key] = record

    validate_database(database, rmm_reference=rmm_reference)
    connection = connect_database(database, readonly=True)
    results: list[dict[str, Any]] = []
    try:
        for key in sorted(grouped):
            record = grouped[key]
            required, found_identity, improves_description = (
                baseline_record_changes(record, [connection])
            )
            if not required:
                status = "already_applied"
            elif not found_identity:
                status = "new_identity"
            elif improves_description:
                status = "description_update"
            else:
                raise RuntimeError(
                    "GoldenDB reconciliation produced an unknown row state."
                )
            identity = (
                record["image_path"],
                record["launch_string"],
                record["signer"],
            )
            results.append(
                {
                    "candidate_row": int(candidate_numbers.get(identity) or 0),
                    "status": status,
                    "hash_key": record["hash_key"],
                    "category": record["category"],
                    "image_path": record["image_path"],
                    "launch_string": record["launch_string"],
                    "signer": record["signer"],
                }
            )
    finally:
        connection.close()
    results.sort(
        key=lambda row: (
            int(row.get("candidate_row") or 0),
            str(row.get("category") or ""),
            str(row.get("hash_key") or ""),
        )
    )
    counts: dict[str, int] = {}
    for row in results:
        status = str(row["status"])
        counts[status] = counts.get(status, 0) + 1
    return {
        "row_count": len(results),
        "counts": counts,
        "rows": results,
    }


def stage_analysis_candidates(
    args: argparse.Namespace,
    *,
    candidate_path: Path | None = None,
) -> dict[str, Any]:
    from vraptor.hunt import command as hunt_workflow
    from vraptor.hunt import live

    database = dfir_paths.resolve_autoruns_golden_db(args.db, REPO_ROOT)
    database_validation = validate_database(
        database,
        rmm_reference=args.rmm_reference,
    )
    case_root = dfir_paths.resolve_case_root(args.case_root, REPO_ROOT)
    paths = autoruns_analysis_paths(
        case_root=case_root,
        investigation_id=args.investigation_id,
        hunt_id=args.hunt_id,
    )
    if not paths["potential_golden"].is_file():
        raise RuntimeError(
            "Potential GoldenDB CSV not found: "
            f"{paths['potential_golden']}"
        )
    state_path = paths["root"] / "hunt-analysis-state.json"
    if not state_path.is_file():
        raise RuntimeError(f"Live analysis state not found: {state_path}")
    canonical_state = json.loads(state_path.read_text(encoding="utf-8"))
    if int(canonical_state.get("schema_version") or 0) != flow_analysis.SCHEMA_VERSION:
        raise RuntimeError(
            "Autoruns stage requires the current hunt-analysis-state.json schema."
        )
    state = canonical_state.get("specialized_analysis")
    if not isinstance(state, dict):
        raise RuntimeError(
            "Canonical analysis state has no specialized Autoruns checkpoint."
        )
    if str(state.get("hunt_id") or "") != args.hunt_id:
        raise RuntimeError("Live analysis state belongs to another hunt.")
    review_scope = str(state.get("review_scope") or "").casefold()
    target_execution_coverage = str(
        state.get("target_execution_coverage") or ""
    ).casefold()
    target_coverage_accepted = target_execution_coverage == "complete" or (
        review_scope == "ad_hoc_review"
        and target_execution_coverage == "not_assessed"
    )
    if not target_coverage_accepted:
        raise RuntimeError(
            "Autoruns stage requires complete target execution coverage for "
            "managed collections, or not_assessed target execution in "
            "ad_hoc_review scope."
        )
    selected_path = (
        candidate_path.expanduser().resolve()
        if candidate_path is not None
        else paths["potential_golden"]
    )
    if not selected_path.is_file():
        raise RuntimeError(
            f"Selected potential GoldenDB CSV not found: {selected_path}"
        )
    candidate_review = validate_candidate_subset(
        paths["potential_golden"],
        selected_path,
        live=live,
    )
    classification_metadata = dict(candidate_review["metadata"])
    candidates = list(candidate_review["rows"])
    if int(classification_metadata.get("SchemaVersion") or 0) != 2:
        raise RuntimeError("Potential GoldenDB CSV requires SchemaVersion 2.")
    if classification_metadata.get("ReviewComplete", "").casefold() != "true":
        raise RuntimeError("Potential GoldenDB review is incomplete.")
    reviewed_group_count = int(
        classification_metadata.get("ReviewedGroupCount") or -1
    )
    source_group_count = int(
        classification_metadata.get("SourceGroupCount") or -1
    )
    if reviewed_group_count < 0 or reviewed_group_count != source_group_count:
        raise RuntimeError(
            "Potential GoldenDB reviewed/source group counts do not match."
        )
    workflow: dict[str, Any] = {}
    for artifact_state in dict(state.get("artifacts") or {}).values():
        if not isinstance(artifact_state, dict):
            continue
        candidate_workflow = artifact_state.get("autoruns_residual_workflow")
        if isinstance(candidate_workflow, dict):
            workflow = candidate_workflow
            break
    if not workflow:
        raise RuntimeError("Canonical state has no Autoruns residual workflow.")
    stack = dict(workflow.get("stack") or {})
    potential_reference = dict(
        dict(workflow.get("classification") or {}).get("potential_golden")
        or {}
    )
    candidate_sha256 = str(candidate_review["canonical_sha256"])
    if potential_reference.get("sha256") != candidate_sha256:
        raise RuntimeError(
            "Potential GoldenDB CSV SHA-256 does not match canonical state."
        )
    if int(potential_reference.get("row_count") or 0) != int(
        candidate_review["canonical_row_count"]
    ):
        raise RuntimeError(
            "Potential GoldenDB row count does not match canonical state."
        )
    reference_reviewed_group_count = potential_reference.get(
        "reviewed_group_count"
    )
    if (
        int(
            reference_reviewed_group_count
            if reference_reviewed_group_count is not None
            else -1
        )
        != reviewed_group_count
    ):
        raise RuntimeError(
            "Potential GoldenDB reviewed count does not match canonical state."
        )
    if classification_metadata.get("SourceStackSHA256") != stack.get("sha256"):
        raise RuntimeError(
            "Potential GoldenDB source-stack hash does not match canonical state."
        )
    if classification_metadata.get("SourceQuerySHA256") != stack.get(
        "query_hash"
    ):
        raise RuntimeError(
            "Potential GoldenDB query hash does not match canonical state."
        )
    source_baseline_sha256 = str(
        classification_metadata.get("GoldenDBSHA256") or ""
    ).casefold()
    current_database_sha256 = str(
        database_validation.get("sha256") or ""
    ).casefold()
    source_baseline_matches = (
        source_baseline_sha256 == current_database_sha256
    )
    seen_candidates: set[tuple[str, str, str]] = set()
    operator_approved_priority_rows: list[dict[str, Any]] = []
    prohibited_rows: list[str] = []
    classifier = RmmClassifier(args.rmm_reference)
    for row in candidates:
        identity = live.autoruns_residual_identity(row)
        if identity in seen_candidates:
            raise RuntimeError(
                "Potential GoldenDB CSV contains a duplicate identity."
            )
        seen_candidates.add(identity)
        try:
            total = int(row.get("Total") or 0)
        except ValueError as exc:
            raise RuntimeError(
                "Potential GoldenDB CSV contains an invalid Total."
            ) from exc
        if total <= 0 or not str(row.get("Reason") or "").strip():
            raise RuntimeError(
                "Potential GoldenDB rows require a positive Total and reason."
            )
        priority_reasons = live.autoruns_priority_review_reasons(
            logical_dimensions=["ImagePath", "LaunchString", "Signer"],
            values=[
                str(row.get("ImagePath") or ""),
                str(row.get("LaunchString") or ""),
                str(row.get("Signer") or ""),
            ],
        )
        non_promotable_reasons = classifier.reasons(
            image_path=str(row.get("ImagePath") or ""),
            launch_string=str(row.get("LaunchString") or ""),
        )
        if is_missing_file(
            image_path=str(row.get("ImagePath") or ""),
            launch_string=str(row.get("LaunchString") or ""),
        ):
            non_promotable_reasons.append("missing-file")
        priority_reasons = sorted(set(priority_reasons))
        if priority_reasons:
            operator_approved_priority_rows.append(
                {
                    "row_number": len(seen_candidates),
                    "reasons": priority_reasons,
                }
            )
        non_promotable_reasons = sorted(set(non_promotable_reasons))
        if non_promotable_reasons:
            prohibited_rows.append(
                f"{len(seen_candidates)} "
                f"({', '.join(non_promotable_reasons)})"
            )
    if prohibited_rows:
        raise RuntimeError(
            "Selected potential GoldenDB CSV retains rows prohibited from "
            "promotion. Remove these data rows: "
            + "; ".join(prohibited_rows)
        )
    candidate_by_identity: dict[
        tuple[str, str, str],
        dict[str, str],
    ] = {}
    for candidate in candidates:
        identity = live.autoruns_residual_identity(candidate)
        candidate_by_identity[identity] = candidate
    env = {
        "HuntId": args.hunt_id,
        "ArtifactName": args.artifact,
    }
    selected_by_identity: dict[tuple[str, str, str], dict[str, str]] = {}
    enriched_rows: list[dict[str, Any]] = []
    if candidates:
        selected_where, selected_by_identity = (
            live.autoruns_selected_hash_where(candidates, env=env)
        )
        hash_expression = autoruns.trusted_key_vql()
        vql = (
            live.autoruns_golden_query_preamble(selected_where)
            + "LET CandidateRows = SELECT\n"
            f"    {hash_expression} AS HashKey,\n"
            "    Category,\n"
            f"    {autoruns.user_path_vql('`Image Path`')} AS ImagePath,\n"
            f"    {autoruns.user_path_vql('`Launch String`')} AS LaunchString,\n"
            f"    {autoruns.ascii_lower_vql('Signer')} AS Signer,\n"
            f"    {autoruns.user_path_vql('`Entry Location`')} AS EntryLocation,\n"
            "    Entry,\n"
            "    Description,\n"
            "    Company\n"
            "FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)\n"
            f"WHERE {selected_where}\n"
            "SELECT HashKey, Category, ImagePath, LaunchString, Signer,\n"
            "       EntryLocation, Entry, Description, Company,\n"
            "       count() AS Total\n"
            "FROM CandidateRows\n"
            "GROUP BY HashKey, Category, ImagePath, LaunchString, Signer,\n"
            "         EntryLocation, Entry, Description, Company"
        )
        api_client = hunt_workflow.resolve_api_client(
            args,
            args.investigation_id,
        )
        if not api_client.exists():
            raise RuntimeError(f"API client config not found at {api_client}")
        with velociraptor_api.VeloApiClient(
            api_client,
            org_id=hunt_workflow.resolve_org_id(args),
        ) as api:
            for batch in api.query_batches(
                vql,
                env,
                max_wait=30,
                max_row=2_500,
            ):
                enriched_rows.extend(dict(row) for row in batch)
    observed_identities: set[tuple[str, str, str]] = set()
    validated_rows: list[dict[str, Any]] = []
    for row in enriched_rows:
        server_hash_key = str(row.get("HashKey") or "").casefold()
        normalized = normalized_record(
            {
                key: value
                for key, value in row.items()
                if key != "HashKey"
            }
        )
        identity = (
            normalized["image_path"],
            normalized["launch_string"],
            normalized["signer"],
        )
        candidate = selected_by_identity.get(identity)
        if candidate is None or identity not in candidate_by_identity:
            raise RuntimeError(
                "Potential GoldenDB enrichment returned an unknown "
                "normalized identity."
            )
        if normalized["hash_key"] != server_hash_key:
            raise RuntimeError(
                "Potential GoldenDB identity cannot be staged because the "
                "Python and VQL HashKey serializers differ. The identity "
                "does not conform to the current canonicalization contract; "
                "review Unicode normalization and JSON serialization before promotion."
            )
        observed_identities.add(identity)
        validated_rows.append(
            {
                "HashKey": server_hash_key,
                "Category": str(row.get("Category") or ""),
                "ImagePath": normalized["image_path"],
                "LaunchString": normalized["launch_string"],
                "Signer": normalized["signer"],
                "EntryLocation": str(row.get("EntryLocation") or ""),
                "Entry": str(row.get("Entry") or ""),
                "Description": str(row.get("Description") or ""),
                "Company": str(row.get("Company") or ""),
                "Total": int(row.get("Total") or 0),
            }
        )
    missing = sorted(set(candidate_by_identity) - observed_identities)
    if missing:
        raise RuntimeError(
            "Potential GoldenDB enrichment did not return every selected "
            f"identity ({len(missing)} missing)."
        )
    validated_rows.sort(
        key=lambda row: (
            row["HashKey"],
            str(row["Category"]).casefold(),
            str(row["EntryLocation"]).casefold(),
            str(row["Entry"]).casefold(),
        )
    )
    reconciliation = reconcile_database_rows(
        database,
        validated_rows,
        candidate_rows=candidates,
        rmm_reference=args.rmm_reference,
    )
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=(
            "HashKey",
            "Category",
            "ImagePath",
            "LaunchString",
            "Signer",
            "EntryLocation",
            "Entry",
            "Description",
            "Company",
            "Total",
        ),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(validated_rows)
    paths["potential_golden_enriched"].parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    paths["potential_golden_enriched"].write_text(
        buffer.getvalue(),
        encoding="utf-8",
    )
    build = build_database(
        paths["delta"],
        [paths["potential_golden_enriched"]],
        replace=True,
        rmm_reference=args.rmm_reference,
        baseline_databases=[database],
    )
    manifest = write_delta_manifest(
        paths["delta_manifest"],
        delta=paths["delta"],
        baseline=database,
        investigation_id=args.investigation_id,
        hunt_id=args.hunt_id,
        artifact=args.artifact,
        status="complete",
        rmm_reference=args.rmm_reference,
        candidate_review={
            **{
                key: candidate_review[key]
                for key in (
                    "canonical_path",
                    "canonical_sha256",
                    "selected_path",
                    "selected_sha256",
                    "canonical_row_count",
                    "selected_row_count",
                    "removed_row_count",
                )
            },
            "operator_approved_priority_rows": (
                operator_approved_priority_rows
            ),
            "source_golden_db_sha256": source_baseline_sha256,
            "current_golden_db_sha256": current_database_sha256,
            "source_baseline_matches": source_baseline_matches,
        },
    )
    return {
        "action": "autoruns_golden_stage",
        "database": str(database),
        "database_mode": "read_only_baseline",
        "source_stack": str(paths["residual_stack"]),
        "source_stack_sha256": stack["sha256"],
        "source_group_count": stack["group_count"],
        "source_review_complete": (
            classification_metadata.get("ReviewComplete", "").casefold()
            == "true"
        ),
        "canonical_candidate_csv": str(paths["potential_golden"]),
        "candidate_csv": str(selected_path),
        "candidate_csv_sha256": candidate_review["selected_sha256"],
        "canonical_candidate_count": candidate_review["canonical_row_count"],
        "candidate_count": len(candidates),
        "removed_candidate_count": candidate_review["removed_row_count"],
        "operator_approved_priority_rows": operator_approved_priority_rows,
        "reconciliation": reconciliation,
        "enriched_csv": str(paths["potential_golden_enriched"]),
        "enriched_row_count": len(validated_rows),
        "delta": str(paths["delta"]),
        "delta_manifest": str(paths["delta_manifest"]),
        "build": build,
        "manifest": manifest,
        "next": (
            f"Inspect the delta, then explicitly run autoruns apply --diff "
            f"{paths['delta']} if approved."
        ),
    }


def previous_promotion_noop(
    args: argparse.Namespace,
    *,
    selected_path: Path,
) -> dict[str, Any] | None:
    """Return an exact row-level no-op replay without live enrichment."""

    from vraptor.hunt import live

    investigation_id = str(getattr(args, "investigation_id", "") or "")
    hunt_id = str(getattr(args, "hunt_id", "") or "")
    if not investigation_id or not hunt_id:
        return None
    case_root = dfir_paths.resolve_case_root(
        getattr(args, "case_root", None),
        REPO_ROOT,
    )
    paths = autoruns_analysis_paths(
        case_root=case_root,
        investigation_id=investigation_id,
        hunt_id=hunt_id,
    )
    manifest_path = paths["delta_manifest"]
    delta_path = paths["delta"]
    canonical_path = paths["potential_golden"]
    if not all(
        path.is_file()
        for path in (manifest_path, delta_path, canonical_path, selected_path)
    ):
        return None
    candidate_review = validate_candidate_subset(
        canonical_path,
        selected_path,
        live=live,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if str(manifest.get("kind") or "") != "autoruns_golden_delta":
        return None
    source = dict(manifest.get("source") or {})
    if (
        str(source.get("investigation_id") or "").casefold()
        != investigation_id.casefold()
        or str(source.get("hunt_id") or "") != hunt_id
        or str(source.get("artifact") or "")
        != str(getattr(args, "artifact", "") or "")
    ):
        return None
    prior_review = dict(manifest.get("candidate_review") or {})
    if (
        str(prior_review.get("selected_sha256") or "")
        != str(candidate_review["selected_sha256"])
        or str(prior_review.get("canonical_sha256") or "")
        != str(candidate_review["canonical_sha256"])
    ):
        return None
    delta_report = validate_database(
        delta_path,
        rmm_reference=getattr(args, "rmm_reference", None),
    )
    if str(dict(manifest.get("delta") or {}).get("sha256") or "") != str(
        delta_report.get("sha256") or ""
    ):
        return None
    if (
        int(candidate_review["selected_row_count"]) > 0
        and int(delta_report.get("record_count") or 0) == 0
    ):
        return None
    target = dfir_paths.resolve_autoruns_golden_db(
        getattr(args, "db", None),
        REPO_ROOT,
    )
    if not target.is_file():
        return None
    reconciliation = reconcile_database_rows(
        target,
        database_rows(delta_path),
        candidate_rows=candidate_review["rows"],
        rmm_reference=getattr(args, "rmm_reference", None),
    )
    if any(
        str(row.get("status") or "") != "already_applied"
        for row in reconciliation["rows"]
    ):
        return None
    before = validate_database(
        target,
        rmm_reference=getattr(args, "rmm_reference", None),
    )
    record_count = int(reconciliation["row_count"])
    identity_count = len(
        {str(row["hash_key"]) for row in reconciliation["rows"]}
    )
    application = {
        "action": "autoruns_golden_apply",
        "dry_run": bool(args.dry_run),
        "target": str(target),
        "delta": str(delta_path),
        "before": before,
        "changes": {
            "new_identity_count": 0,
            "existing_identity_count": identity_count,
            "new_record_count": 0,
            "existing_record_count": record_count,
            "improved_description_count": 0,
            "unchanged_description_count": record_count,
            "effective_change_count": 0,
        },
        "backup": "",
        "after": {},
        "installed": False,
        "no_changes": True,
        "idempotent_replay": True,
    }
    return {
        "action": "autoruns_golden_promote",
        "dry_run": bool(args.dry_run),
        "staging": {
            "action": "autoruns_golden_stage_reuse",
            "canonical_candidate_csv": str(canonical_path),
            "candidate_csv": str(selected_path),
            "canonical_candidate_count": candidate_review[
                "canonical_row_count"
            ],
            "candidate_count": candidate_review["selected_row_count"],
            "removed_candidate_count": candidate_review["removed_row_count"],
            "delta": str(delta_path),
            "delta_manifest": str(manifest_path),
            "reconciliation": {
                "row_count": reconciliation["row_count"],
                "counts": reconciliation["counts"],
            },
            "reused_enrichment": True,
        },
        "application": application,
        "reconciliation": reconciliation,
        "publication_required": False,
        "next": "No GoldenDB changes were required.",
    }


def promote_analysis_candidates(
    args: argparse.Namespace,
    *,
    resolve_context: bool = False,
) -> dict[str, Any]:
    if not str(getattr(args, "artifact", "") or "").strip():
        args.artifact = DEFAULT_AUTORUNS_ARTIFACT
    selected_path = Path(args.input).expanduser().resolve()
    replay = previous_promotion_noop(args, selected_path=selected_path)
    if replay is not None:
        return replay
    if resolve_context:
        apply_engagement_context(args)
    staged = stage_analysis_candidates(args, candidate_path=selected_path)
    target = dfir_paths.resolve_autoruns_golden_db(args.db, REPO_ROOT)
    preview = apply_delta_database(
        target,
        Path(staged["delta"]),
        dry_run=True,
        backup_dir=(
            Path(args.backup_dir).expanduser().resolve()
            if args.backup_dir
            else None
        ),
        rmm_reference=args.rmm_reference,
    )
    effective_changes = int(
        dict(preview.get("changes") or {}).get("effective_change_count") or 0
    )
    if args.dry_run or effective_changes == 0:
        application = preview
        application["dry_run"] = bool(args.dry_run)
        application["no_changes"] = effective_changes == 0
        application["installed"] = False
    else:
        application = apply_delta_database(
            target,
            Path(staged["delta"]),
            dry_run=False,
            backup_dir=(
                Path(args.backup_dir).expanduser().resolve()
                if args.backup_dir
                else None
            ),
            rmm_reference=args.rmm_reference,
        )
    manifest_path = Path(staged["delta_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if args.dry_run:
        manifest["status"] = "dry_run"
    elif effective_changes == 0:
        manifest["status"] = "no_changes"
    else:
        manifest["status"] = "applied"
    manifest["promotion"] = application
    atomic_io.write_text_atomic(
        manifest_path,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        newline="",
    )
    staging_output = dict(staged)
    staging_output["reconciliation"] = {
        "row_count": int(
            dict(staged.get("reconciliation") or {}).get("row_count") or 0
        ),
        "counts": dict(
            dict(staged.get("reconciliation") or {}).get("counts") or {}
        ),
    }
    return {
        "action": "autoruns_golden_promote",
        "dry_run": bool(args.dry_run),
        "staging": staging_output,
        "application": application,
        "reconciliation": staged.get("reconciliation") or {},
        "publication_required": (
            not bool(args.dry_run) and effective_changes > 0
        ),
        "next": (
            "Review the dry-run change summary, then rerun without --dry-run."
            if args.dry_run
            else (
                "No GoldenDB changes were required."
                if effective_changes == 0
                else (
                    "Run autoruns push when the updated GoldenDB should be "
                    "published."
                )
            )
        ),
    }


def _offline_input_rows(
    inputs: Iterable[Path], *, required_fields: tuple[str, ...],
    input_reports: list[dict[str, str]],
) -> Iterator[tuple[str, dict[str, Any]]]:
    for path in inputs:
        if not path.is_file():
            raise RuntimeError(f"Offline Autoruns import not found: {path}")
        # Digest exactly the bytes parsed, before any target write. Inputs may
        # be moved or edited later without corrupting the operation report.
        content = path.read_bytes()
        input_reports.append({"path": str(path), "sha256": hashlib.sha256(content).hexdigest()})
        for row_number, row in enumerate(
            iter_rows(path, content=content, required_fields=required_fields), start=1,
        ):
            source = f"{path}:{row_number}"
            values = {_input_field_key(name): value for name, value in row.items()}
            text_fields = (*required_fields, "Description", "SignerRegex")
            for name in text_fields:
                if _input_field_key(name) not in values:
                    continue
                if not isinstance(values[_input_field_key(name)], str):
                    raise RuntimeError(f"Offline Autoruns import {source} requires text {name}.")
            yield source, row


def _validated_offline_exact_rows(
    inputs: Iterable[Path],
    *,
    rmm_reference: Path | None = None,
    input_reports: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Load exact-rule import rows without relying on live enrichment."""

    classifier = RmmClassifier(rmm_reference)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source, row in _offline_input_rows(
        inputs, required_fields=("HashKey", "ImagePath", "LaunchString", "Signer"),
        input_reports=input_reports if input_reports is not None else [],
    ):
        supplied_hash = str(
            field(row, "HashKey", "hash_key", "trusted_key") or ""
        ).strip().casefold()
        if not HASH_RE.fullmatch(supplied_hash):
            raise RuntimeError(
                f"Offline Autoruns import {source} requires "
                "a canonical HashKey."
            )
        record = normalized_record(row)
        if not record["image_path"].strip() and not record["launch_string"].strip():
            raise RuntimeError(
                f"Offline Autoruns import {source} requires "
                "ImagePath or LaunchString."
            )
        key = record["hash_key"]
        if key in seen:
            raise RuntimeError(
                "Offline Autoruns import contains duplicate "
                f"HashKey {key}."
            )
        seen.add(key)
        if is_missing_file(
            image_path=record["image_path"],
            launch_string=record["launch_string"],
        ):
            raise RuntimeError(
                f"Offline Autoruns import {source} contains "
                "a missing-file identity."
            )
        reasons = classifier.reasons(
            image_path=record["image_path"],
            launch_string=record["launch_string"],
        )
        if reasons:
            raise RuntimeError(
                f"Offline Autoruns import {source} contains "
                "a prohibited RMM/greyware identity: "
                + ", ".join(sorted(set(reasons)))
            )
        rows.append(dict(row))
    return rows


def _validated_offline_regex_rows(
    inputs: Iterable[Path],
    *, input_reports: list[dict[str, str]] | None = None,
    rmm_reference: Path | None = None,
) -> list[dict[str, Any]]:
    """Load reviewed paired regex rules and reject duplicates."""

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source, row in _offline_input_rows(
        inputs, required_fields=("image_path_regex", "launch_string_regex", "description"),
        input_reports=input_reports if input_reports is not None else [],
    ):
        record = normalized_regex_record(row)
        key = regex_record_key(record)
        if key in seen:
            raise RuntimeError(
                "Offline Autoruns regex import contains duplicate rule "
                f"at {source}."
            )
        seen.add(key)
        rows.append(dict(row))
    return rows


def _require_standalone_database(target: Path) -> None:
    # A raw file digest cannot bind uncheckpointed WAL content. Fail before
    # opening SQLite (including read-only connections that can create sidecars).
    with target.open("rb") as handle:
        header = handle.read(20)
    if header[18:20] == b"\x02\x02" or any(
        path.exists() and path.stat().st_size
        for path in (Path(str(target) + "-wal"), Path(str(target) + "-journal"))
    ):
        raise RuntimeError(
            "GoldenDB apply/import requires a standalone GoldenDB without WAL or an active journal; "
            "checkpoint and close the writer, then use journal_mode=DELETE before retrying."
        )


def _snapshot_import_baseline(target: Path, snapshot: Path) -> None:
    _require_standalone_database(target)
    shutil.copyfile(target, snapshot)
    if file_sha256(snapshot) != file_sha256(target):
        raise RuntimeError("GoldenDB changed while taking the import baseline snapshot; retry.")


def import_offline_rules(args: argparse.Namespace) -> dict[str, Any]:
    """Atomically apply reviewed exact and regex CSV/JSON rules offline."""

    exact_inputs = _paths(getattr(args, "input", []) or [])
    regex_inputs = _paths(getattr(args, "regex_input", []) or [])
    if not exact_inputs and not regex_inputs:
        raise RuntimeError(
            "Pass --input and/or --regex-input to import Autoruns rules."
        )
    target = dfir_paths.resolve_autoruns_golden_db(args.db, REPO_ROOT)
    if not target.is_file():
        raise RuntimeError(
            "Offline Autoruns import requires an existing GoldenDB target: "
            f"{target}"
        )
    rmm_reference = (
        Path(args.rmm_reference).expanduser().resolve()
        if args.rmm_reference
        else None
    )
    backup_dir = (
        Path(args.backup_dir).expanduser().resolve()
        if args.backup_dir
        else None
    )
    input_reports: list[dict[str, str]] = []
    regex_input_reports: list[dict[str, str]] = []
    exact_rows = _validated_offline_exact_rows(
        exact_inputs,
        rmm_reference=rmm_reference,
        input_reports=input_reports,
    )
    regex_rows = _validated_offline_regex_rows(
        regex_inputs, input_reports=regex_input_reports, rmm_reference=rmm_reference,
    )
    with tempfile.TemporaryDirectory(
        prefix="autoruns-golden-import-"
    ) as temp_dir:
        baseline = Path(temp_dir) / "baseline.sqlite"
        _snapshot_import_baseline(target, baseline)
        reconciliation = reconcile_database_rows(
            baseline, exact_rows, rmm_reference=rmm_reference,
        )
        delta = Path(temp_dir) / AUTORUNS_GOLDEN_DELTA_FILENAME
        build = promote_records(
            delta,
            exact_rows,
            baseline_databases=[baseline],
            regex_rows=regex_rows,
            rmm_reference=rmm_reference,
        )
        application = apply_delta_database(
            target,
            delta,
            dry_run=bool(args.dry_run),
            backup_dir=backup_dir,
            rmm_reference=rmm_reference,
        )
        effective_changes = int(
            dict(application.get("changes") or {}).get(
                "effective_change_count"
            )
            or 0
        )
        delta_validation = dict(build.get("validation") or {})
        delta_validation.pop("database", None)
        application = dict(application)
        application["delta"] = ""
        application["temporary_delta_removed"] = True
    return {
        "action": "autoruns_golden_import",
        "offline": True,
        "dry_run": bool(args.dry_run),
        "target": str(target),
        "before": application["before"],
        "inputs": input_reports,
        "regex_inputs": regex_input_reports,
        "exact_input_row_count": len(exact_rows),
        "regex_input_row_count": len(regex_rows),
        "reconciliation": reconciliation,
        "delta": {
            "build": {
                key: value
                for key, value in build.items()
                if key not in {"database", "validation"}
            },
            "validation": delta_validation,
        },
        "application": application,
        "publication_required": (
            not bool(args.dry_run) and effective_changes > 0
        ),
        "next": (
            "Review the dry-run change summary, then rerun without --dry-run."
            if args.dry_run
            else (
                "No GoldenDB changes were required."
                if effective_changes == 0
                else "Review the local database diff and submit the approved GoldenDB update in a PR."
            )
        ),
    }


def _paths(values: Iterable[str]) -> list[Path]:
    return [Path(value).expanduser().resolve() for value in values]


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="dfir autoruns",
        description="Manage the reusable Autoruns GoldenDB.",
    )
    commands = root.add_subparsers(dest="command", required=True)
    regex_build = commands.add_parser("regex-build", help="Create or replace GoldenDB from a complete CSV; dates are automatic and unchanged rows retain their dates.")
    regex_build.add_argument("--db", type=Path, required=True)
    regex_build.add_argument("--input", type=Path, required=True)
    regex_build.add_argument("--backup-dir", type=Path, required=True)
    regex_build.add_argument("--dry-run", action="store_true")
    regex_import = commands.add_parser("regex-import", help="Add/update five-field CSV rules in schema 10; legacy schema-9 JSON remains supported.")
    regex_import.add_argument("--db", type=Path, required=True)
    regex_import.add_argument("--input", type=Path, required=True)
    regex_import.add_argument("--backup-dir", type=Path, required=True)
    regex_import.add_argument("--dry-run", action="store_true")
    migration = commands.add_parser("regex-migrate", help="Back up and migrate a local GoldenDB to reviewed regex-only schema 9.")
    migration.add_argument("--source", type=Path, required=True)
    migration.add_argument("--output", type=Path, required=True)
    migration.add_argument("--backup-dir", type=Path, required=True)
    migration.add_argument("--exclude-exact", action="store_true", help="Remove exact entries; retain only existing regex rules.")


    def add_hunt_update_args(
        command: argparse.ArgumentParser,
        *,
        writable_database: bool = False,
        hunt_required: bool = True,
        artifact_default: str | None = DEFAULT_AUTORUNS_ARTIFACT,
    ) -> None:
        command.add_argument(
            "--engagement-id",
            "--id",
            "--investigation-id",
            dest="investigation_id",
            help="Local engagement folder; defaults to --server-profile.",
        )
        command.add_argument("--hunt-id", required=hunt_required)
        command.add_argument(
            "--db",
            help=(
                (
                    "Target GoldenDB path. "
                    if writable_database
                    else "Read-only baseline GoldenDB path. "
                )
                + "Defaults to the shared DFIR tools data location or "
                "VELO_AUTORUNS_GOLDEN_DB."
            ),
        )
        command.add_argument(
            "--artifact",
            choices=SUPPORTED_AUTORUNS_ARTIFACTS,
            default=artifact_default,
        )
        command.add_argument("--api-client")
        command.add_argument("--server-profile")
        command.add_argument("--org-id")
        command.add_argument("--case-root")
        command.add_argument("--rmm-reference")

    stage = commands.add_parser(
        "stage",
        help=(
            "Enrich the hunt-local potential-GoldenDB CSV and create a "
            "mergeable delta without modifying the shared database."
        ),
    )
    add_hunt_update_args(stage)

    promote = commands.add_parser(
        "promote",
        help=(
            "Validate a deletion-only reviewed candidate CSV, create a "
            "hunt-local delta, and atomically apply it to GoldenDB."
        ),
    )
    add_hunt_update_args(
        promote,
        writable_database=True,
        hunt_required=False,
        artifact_default=None,
    )
    promote.add_argument(
        "--input",
        required=True,
        help=(
            "Reviewed copy of autoruns_potential_golden.csv. It may remove "
            "canonical rows but may not add or edit rows or metadata."
        ),
    )
    promote.add_argument("--backup-dir")
    promote.add_argument("--dry-run", action="store_true")

    import_command = commands.add_parser(
        "import",
        help=(
            "Validate and atomically apply reviewed enriched exact and regex "
            "rules to a local GoldenDB without Velociraptor API access."
        ),
    )
    import_command.add_argument(
        "--input",
        action="append",
        default=[],
        help=(
            "Reviewed enriched CSV/JSON containing HashKey, "
            "ImagePath, LaunchString, and Signer. Repeat as needed."
        ),
    )
    import_command.add_argument(
        "--regex-input",
        action="append",
        default=[],
        help=(
            "Reviewed CSV/JSON containing image_path_regex, "
            "launch_string_regex, and description. Repeat as needed."
        ),
    )
    import_command.add_argument(
        "--db",
        help=(
            "Target GoldenDB. Defaults to the shared DFIR tools data "
            "location or VELO_AUTORUNS_GOLDEN_DB."
        ),
    )
    import_command.add_argument("--backup-dir")
    import_command.add_argument("--dry-run", action="store_true")
    import_command.add_argument("--rmm-reference")

    push = commands.add_parser(
        "push",
        help="Publish GoldenDB as Autoruns.GoldenDB with an automatic version.",
    )
    push.add_argument("--db")
    push.add_argument("--api-client")
    push.add_argument("--server-profile")
    push.add_argument("--org-id")
    push.add_argument("--rmm-reference")

    apply_command = commands.add_parser(
        "apply",
        help=(
            "Validate and atomically merge a reviewed hunt-local delta into "
            "the shared GoldenDB."
        ),
    )
    apply_command.add_argument("--diff", required=True)
    apply_command.add_argument(
        "--db",
        help=(
            "Target GoldenDB. Defaults to the shared DFIR tools data "
            "location or VELO_AUTORUNS_GOLDEN_DB."
        ),
    )
    apply_command.add_argument("--backup-dir")
    apply_command.add_argument("--dry-run", action="store_true")
    apply_command.add_argument("--rmm-reference")

    remove = commands.add_parser(
        "remove",
        help="Remove a GoldenDB identity by hash.",
    )
    remove.add_argument("--db")
    remove.add_argument("--hash", action="append", required=True)
    remove.add_argument("--category", default="", help=argparse.SUPPRESS)
    remove.add_argument("--rmm-reference")

    test_build = commands.add_parser(
        "test-build", help="Build an isolated autoruns_test database without changing production GoldenDB.",
    )
    test_build.add_argument("--source-db", required=True)
    test_build.add_argument("--output", required=True, help="New operator-owned path; existing paths are never replaced.")
    test_build.add_argument("--rmm-reference")
    test_build.add_argument("--category-map", help="Optional exact-hash Category association JSON pinned to the source database.")

    test_categories = commands.add_parser("test-categories", help="Recover observed categories by exact identity joins to legacy GoldenDB sources.")
    test_categories.add_argument("--source-db", required=True)
    test_categories.add_argument("--category-source", action="append", required=True)
    test_categories.add_argument("--output", required=True, help="New category-map JSON path; existing paths are never replaced.")

    test_review = commands.add_parser("test-review", help="Export grouped regex fields and descriptions, one identity per row.")
    test_review.add_argument("--db", required=True)
    test_review.add_argument("--output", required=True, help="New Markdown review path; existing paths are never replaced.")

    build = commands.add_parser("build")
    build.add_argument("--output", required=True)
    build.add_argument("--input", action="append", default=[])
    build.add_argument(
        "--regex-input", action="append", default=[],
        help="Reviewed CSV/JSON rules: image_path_regex, launch_string_regex, description.",
    )
    build.add_argument(
        "--baseline-db",
        action="append",
        default=[],
        help=(
            "Existing GoldenDB to subtract. Repeat for multiple baselines; "
            "new categories or improved descriptions are retained in the "
            "delta."
        ),
    )
    build.add_argument("--exclude-hashes", action="append", default=[])
    build.add_argument("--rmm-reference")
    build.add_argument("--replace", action="store_true")

    merge = commands.add_parser("merge")
    merge.add_argument("--output", required=True)
    merge.add_argument("--input", action="append", required=True)
    merge.add_argument("--rmm-reference")
    merge.add_argument("--replace", action="store_true")

    inspect = commands.add_parser("inspect")
    inspect.add_argument("--db")
    inspect.add_argument("--rmm-reference")

    lookup = commands.add_parser("lookup")
    lookup.add_argument("--db")
    lookup.add_argument("hash", nargs="*")
    lookup.add_argument("--category", default="")
    lookup.add_argument("--signer")
    lookup.add_argument("--image-path")
    lookup.add_argument("--launch-string")

    filter_command = commands.add_parser(
        "filter",
        help=(
            "Filter downloaded Autoruns collection rows against GoldenDB "
            "without modifying the database."
        ),
    )
    filter_command.add_argument("--db")
    filter_source = filter_command.add_mutually_exclusive_group(required=True)
    filter_source.add_argument("--input", action="append")
    filter_source.add_argument("--manifest")
    filter_command.add_argument("--output")
    filter_command.add_argument("--output-dir")

    publish = commands.add_parser("publish")
    publish.add_argument("--db")
    publish.add_argument("--api-client")
    publish.add_argument("--server-profile")
    publish.add_argument("--org-id")
    publish.add_argument("--tool-name", default=DEFAULT_TOOL_NAME)
    publish.add_argument("--tool-version", default=DEFAULT_TOOL_VERSION)
    publish.add_argument("--filename", default=DEFAULT_TOOL_FILENAME)
    publish.add_argument("--rmm-reference")

    refresh = commands.add_parser("refresh-rmm")
    refresh.add_argument(
        "--output",
        default=str(RMM_REFERENCE_PATH),
    )
    refresh.add_argument("--source", default=DEFAULT_RMM_SOURCE)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "regex-build":
        from vraptor.autoruns.csv_store import write_csv
        result = write_csv(args.db, args.input, backup_dir=args.backup_dir, replace=True, dry_run=args.dry_run)
    elif args.command == "regex-import":
        from vraptor.autoruns.regex_store import import_rules
        result = import_rules(args.db, args.input, backup_dir=args.backup_dir, dry_run=args.dry_run)
    elif args.command == "regex-migrate":
        from vraptor.autoruns.regex_store import migrate
        result = migrate(args.source, args.output, backup_dir=args.backup_dir, exclude_exact=args.exclude_exact)
    elif args.command == "stage":
        apply_engagement_context(args)
        args.rmm_reference = (
            Path(args.rmm_reference).expanduser().resolve()
            if args.rmm_reference
            else None
        )
        result = stage_analysis_candidates(args)
    elif args.command == "promote":
        resolve_promotion_source_args(args)
        args.rmm_reference = (
            Path(args.rmm_reference).expanduser().resolve()
            if args.rmm_reference
            else None
        )
        result = promote_analysis_candidates(args, resolve_context=True)
    elif args.command == "import":
        result = import_offline_rules(args)
    elif args.command == "push":
        database = dfir_paths.resolve_autoruns_golden_db(
            args.db,
            REPO_ROOT,
        )
        rmm_reference = (
            Path(args.rmm_reference).expanduser().resolve()
            if args.rmm_reference
            else None
        )
        version = DEFAULT_TOOL_VERSION
        with velociraptor_api.VeloApiClient(
            dfir_paths.resolve_velociraptor_api_client_path(
                args.api_client,
                REPO_ROOT,
                server_profile=args.server_profile,
            ),
            org_id=args.org_id,
        ) as client:
            result = publish_database(
                client,
                database,
                tool_name=DEFAULT_TOOL_NAME,
                tool_version=version,
                filename=DEFAULT_TOOL_FILENAME,
                rmm_reference=rmm_reference,
            )
    elif args.command == "apply":
        result = apply_delta_database(
            dfir_paths.resolve_autoruns_golden_db(
                args.db,
                REPO_ROOT,
            ),
            Path(args.diff).expanduser().resolve(),
            dry_run=bool(args.dry_run),
            backup_dir=(
                Path(args.backup_dir).expanduser().resolve()
                if args.backup_dir
                else None
            ),
            rmm_reference=(
                Path(args.rmm_reference).expanduser().resolve()
                if args.rmm_reference
                else None
            ),
        )
    elif args.command == "remove":
        result = remove_hashes(
            dfir_paths.resolve_autoruns_golden_db(
                args.db,
                REPO_ROOT,
            ),
            args.hash,
            category=args.category,
            rmm_reference=(
                Path(args.rmm_reference).expanduser().resolve()
                if args.rmm_reference
                else None
            ),
        )
    elif args.command == "test-categories":
        from vraptor.autoruns import test_store as autoruns_test_db
        result = autoruns_test_db.recover_categories(
            Path(args.source_db), [Path(path) for path in args.category_source], Path(args.output),
        )
    elif args.command == "test-review":
        from vraptor.autoruns import test_store as autoruns_test_db
        result = autoruns_test_db.export_grouped_review(Path(args.db).expanduser().resolve(), Path(args.output))
    elif args.command == "test-build":
        from vraptor.autoruns import test_store as autoruns_test_db

        result = autoruns_test_db.build_database(
            Path(args.source_db), Path(args.output),
            rmm_reference=Path(args.rmm_reference).expanduser().resolve() if args.rmm_reference else None,
            category_map=Path(args.category_map).expanduser().resolve() if args.category_map else None,
        )
    elif args.command == "build":
        if not args.input and not args.regex_input:
            raise RuntimeError("Pass --input and/or --regex-input to build GoldenDB.")
        result = build_database(
            Path(args.output).expanduser().resolve(),
            _paths(args.input),
            replace=bool(args.replace),
            exclude_hashes=load_hashes(_paths(args.exclude_hashes)),
            rmm_reference=(
                Path(args.rmm_reference).expanduser().resolve()
                if args.rmm_reference
                else None
            ),
            baseline_databases=_paths(args.baseline_db),
            regex_inputs=_paths(args.regex_input),
        )
    elif args.command == "merge":
        result = merge_databases(
            Path(args.output).expanduser().resolve(),
            _paths(args.input),
            replace=bool(args.replace),
            rmm_reference=(
                Path(args.rmm_reference).expanduser().resolve()
                if args.rmm_reference
                else None
            ),
        )
    elif args.command == "inspect":
        result = validate_database(
            dfir_paths.resolve_autoruns_golden_db(
                args.db,
                REPO_ROOT,
            ),
            rmm_reference=(
                Path(args.rmm_reference).expanduser().resolve()
                if args.rmm_reference
                else None
            ),
        )
    elif args.command == "lookup":
        database = dfir_paths.resolve_autoruns_golden_db(
            args.db,
            REPO_ROOT,
        )
        hashes = list(args.hash)
        row_query_requested = any(
            value is not None
            for value in (
                args.signer,
                args.image_path,
                args.launch_string,
            )
        )
        if not hashes and not row_query_requested:
            raise RuntimeError(
                "Pass at least one HashKey or row identity fields."
            )
        results = lookup_hashes(database, hashes)
        if row_query_requested:
            results.append(
                lookup_identity(
                    database,
                    category=args.category,
                    signer=args.signer,
                    image_path=args.image_path,
                    launch_string=args.launch_string,
                )
            )
        result = {
            "database": str(database),
            "database_mode": "read_only",
            "results": results,
        }
    elif args.command == "filter":
        database = dfir_paths.resolve_autoruns_golden_db(
            args.db,
            REPO_ROOT,
        )
        result = filter_autoruns_inputs(
            database,
            inputs=_paths(args.input or []),
            manifest=(
                Path(args.manifest).expanduser().resolve()
                if args.manifest
                else None
            ),
            output=(
                Path(args.output).expanduser().resolve()
                if args.output
                else None
            ),
            output_dir=(
                Path(args.output_dir).expanduser().resolve()
                if args.output_dir
                else None
            ),
        )
    elif args.command == "publish":
        database = dfir_paths.resolve_autoruns_golden_db(
            args.db,
            REPO_ROOT,
        )
        rmm_reference = (
            Path(args.rmm_reference).expanduser().resolve()
            if args.rmm_reference
            else None
        )
        version = str(args.tool_version or "").strip() or DEFAULT_TOOL_VERSION
        with velociraptor_api.VeloApiClient(
            dfir_paths.resolve_velociraptor_api_client_path(
                args.api_client,
                REPO_ROOT,
                server_profile=args.server_profile,
            ),
            org_id=args.org_id,
        ) as client:
            result = publish_database(
                client,
                database,
                tool_name=args.tool_name,
                tool_version=version,
                filename=args.filename,
                rmm_reference=rmm_reference,
            )
    elif args.command == "refresh-rmm":
        output = Path(args.output).expanduser().resolve()
        payload = refresh_rmm_reference(
            output,
            source=args.source,
        )
        result = {
            "output": str(output),
            "source": payload["source"],
            "updated_at": payload["updated_at"],
            "tool_count": payload["tool_count"],
            "executable_count": len(payload["executables"]),
            "installation_path_count": len(
                payload["installation_paths"]
            ),
        }
    else:
        raise RuntimeError(f"Unknown command: {args.command}")
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
