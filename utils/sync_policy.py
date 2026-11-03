"""Manifest, held-file, deny-pattern, path and sync-state rules for the sync and export tools.

Each loader raises PolicyError at the first problem. A caller that reports every
problem passes an ``errors`` list instead: rows that cannot be read are skipped,
and each error's ``reason``, ``line`` and ``value`` let the caller word its own
message, while ``str(error)`` stays the synchronization message.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator


SCHEMA_VERSION = 1
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64};mode:100(?:644|755)")


class PolicyError(ValueError):
    def __init__(self, message: str, reason: str = "", line: int = 0, value: object = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.line = line
        self.value = value


@dataclass(frozen=True)
class Mapping:
    ai_path: str
    public_path: str
    kind: str
    exclude: tuple[str, ...] = ()


def report(errors: list[PolicyError] | None, error: PolicyError) -> None:
    if errors is None:
        raise error
    errors.append(error)


def validate_relative_path(raw: object, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise PolicyError(f"invalid {label} path")
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or ".." in path.parts or path.as_posix() != raw:
        raise PolicyError(f"invalid {label} path: {raw!r}")
    return path.as_posix()


def pair_key(ai_path: str, public_path: str) -> str:
    return f"{ai_path} => {public_path}"


def table_rows(path: Path) -> Iterator[tuple[int, str]]:
    """Yield numbered rows of a tab-separated policy file, skipping blanks and comments."""
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw.strip() and not raw.lstrip().startswith("#"):
            yield line_number, raw


def load_manifest(path: Path, errors: list[PolicyError] | None = None) -> list[Mapping]:
    mappings: list[Mapping] = []
    for line_number, raw in table_rows(path):
        location = f"{path}:{line_number}"
        fields = [field.strip() for field in raw.split("\t")]
        exclude = tuple(glob.strip() for glob in fields[3].split(",")) if len(fields) == 4 else ()
        if len(fields) not in {3, 4}:
            problem = "expected three or four tab-separated fields"
        elif fields[2] not in {"file", "tree"}:
            problem = "kind must be file or tree"
        elif exclude and (fields[2] != "tree" or not all(exclude)):
            problem = "exclude globs need a tree row and non-empty patterns"
        else:
            problem = ""
        if problem:
            report(errors, PolicyError(f"{location}: {problem}", "row", line_number))
            continue
        mapping = Mapping(fields[0], fields[1], fields[2], exclude)
        for side, label in (("ai_path", "ai_skills"), ("public_path", "public")):
            try:
                validate_relative_path(getattr(mapping, side), label)
            except PolicyError as exc:
                report(errors, PolicyError(str(exc), side, line_number, getattr(mapping, side)))
        if any(mapping.ai_path == prior.ai_path or mapping.public_path == prior.public_path
               for prior in mappings):
            report(errors, PolicyError(f"{location}: duplicate manifest path", "duplicate", line_number))
        for side in ("ai_path", "public_path"):
            current = getattr(mapping, side)
            priors = (getattr(prior, side) for prior in mappings)
            if any(current.startswith(prior + "/") or prior.startswith(current + "/") for prior in priors):
                report(errors, PolicyError(f"{location}: overlapping manifest paths", "overlap", line_number))
        mappings.append(mapping)
    if not mappings:
        report(errors, PolicyError(f"manifest has no mappings: {path}", "empty"))
    return mappings


@dataclass(frozen=True)
class Held:
    reviewed: str
    reason: str


def load_held(path: Path, errors: list[PolicyError] | None = None) -> dict[str, Held]:
    """Return held public paths with the upstream fingerprint last reviewed for each.

    Each row is ``public_path``, the reviewed upstream fingerprint (the ai_skills
    file in this repository's layout) and a reason. Synchronization never writes a
    held file in either direction. A missing file holds nothing.
    """
    held: dict[str, Held] = {}
    if not path.exists():
        return held
    for line_number, raw in table_rows(path):
        location = f"{path}:{line_number}"
        fields = [field.strip() for field in raw.split("\t")]
        if len(fields) != 3 or not fields[2]:
            report(errors, PolicyError(
                f"{location}: expected public path, reviewed fingerprint and reason", "row", line_number))
            continue
        try:
            public_path = validate_relative_path(fields[0], "held public")
        except PolicyError as exc:
            report(errors, PolicyError(f"{location}: {exc}", "path", line_number, fields[0]))
            continue
        if not FINGERPRINT.fullmatch(fields[1]):
            report(errors, PolicyError(f"{location}: invalid reviewed fingerprint", "fingerprint", line_number))
            continue
        if public_path in held:
            report(errors, PolicyError(f"{location}: duplicate held path", "duplicate", line_number))
            continue
        held[public_path] = Held(fields[1], fields[2])
    return held


def load_deny_patterns(path: Path) -> list[tuple[str, re.Pattern[str]]]:
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for line_number, raw in table_rows(path):
        fields = raw.split("\t", 1)
        if len(fields) != 2:
            raise PolicyError(f"{path}:{line_number}: expected label and regex")
        try:
            patterns.append((fields[0], re.compile(fields[1], re.IGNORECASE)))
        except re.error as exc:
            raise PolicyError(f"{path}:{line_number}: invalid regex: {exc}") from exc
    return patterns


def load_state(path: Path, errors: list[PolicyError] | None = None) -> dict:
    """Return the sync baseline; a missing file is an empty one.

    Read and JSON errors propagate. With ``errors``, the result is meaningful only
    when no problem was collected.
    """
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "files": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(state, dict) or state.get("schema_version") != SCHEMA_VERSION
            or not isinstance(state.get("files"), dict)):
        report(errors, PolicyError(f"unsupported or malformed sync state: {path}", "schema"))
        return {}
    malformed = f"malformed sync state key or fingerprint: {path}"
    for number, (key, record) in enumerate(state["files"].items(), 1):
        if not isinstance(record, dict):
            report(errors, PolicyError(f"malformed sync state record: {path}", "record", number))
            continue
        try:
            ai_path = validate_relative_path(record.get("ai_path"), "sync state ai_skills")
            public_path = validate_relative_path(record.get("public_path"), "sync state public")
            if key != pair_key(ai_path, public_path):
                raise PolicyError(malformed)
        except PolicyError as exc:
            report(errors, PolicyError(str(exc), "paths", number))
        fingerprint = record.get("fingerprint")
        if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
            report(errors, PolicyError(malformed, "fingerprint", number))
    return state
