"""Six-column GoldenDB with CSV maintenance and native regex-search semantics."""
from __future__ import annotations

import csv
import fcntl
import hashlib
import io
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import date
from pathlib import Path

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import regex as autoruns_regex

SCHEMA = "10"
POLICY = "goldendb-four-field-search-v1"
FIELDS = ("Category", "ImagePath", "LaunchString", "Signer")
COLUMNS = (*FIELDS, "Notes", "LastModified")
SQL = """
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE GoldenRules(
    Category TEXT NOT NULL, ImagePath TEXT NOT NULL,
    LaunchString TEXT NOT NULL, Signer TEXT NOT NULL, Notes TEXT NOT NULL,
    LastModified TEXT NOT NULL DEFAULT (date('now','localtime')),
    UNIQUE(Category,ImagePath,LaunchString,Signer)
);
CREATE TRIGGER GoldenRules_LastModified
AFTER UPDATE OF Category,ImagePath,LaunchString,Signer,Notes ON GoldenRules
WHEN NEW.Category IS NOT OLD.Category OR NEW.ImagePath IS NOT OLD.ImagePath
 OR NEW.LaunchString IS NOT OLD.LaunchString OR NEW.Signer IS NOT OLD.Signer
 OR NEW.Notes IS NOT OLD.Notes
BEGIN
    UPDATE GoldenRules SET LastModified=date('now','localtime') WHERE rowid=NEW.rowid;
END;
"""


def records(connection):
    return [dict(zip(COLUMNS, row)) for row in connection.execute(
        "SELECT Category,ImagePath,LaunchString,Signer,Notes,LastModified FROM GoldenRules ORDER BY rowid")]


def load_connection(connection, metadata, *, max_rows):
    expected = {"schema_version": SCHEMA, "canonicalization_version": str(autoruns.CANONICALIZATION_VERSION),
                "matching": "regex-only-four-field", "hash_algorithm": "none", "approval_policy": POLICY,
                "category_matching": "regex-search"}
    if any(metadata.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Invalid schema-10 GoldenDB matching metadata.")
    if tuple(r[1] for r in connection.execute("PRAGMA table_info(GoldenRules)")) != COLUMNS:
        raise RuntimeError("Schema 10 requires exactly Category, ImagePath, LaunchString, Signer, Notes, LastModified.")
    tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if tables != {"metadata", "GoldenRules"}:
        raise RuntimeError("Unexpected schema-10 GoldenDB tables.")
    stored = records(connection)
    if not 0 < len(stored) <= max_rows or metadata.get("rule_count") != str(len(stored)):
        raise RuntimeError("Schema-10 GoldenDB rule count mismatch or limit exceeded.")
    rules, keys = [], set()
    for row in stored:
        if any(not isinstance(v, str) or not v for v in row.values()):
            raise RuntimeError("GoldenDB fields must be nonempty strings.")
        try:
            if date.fromisoformat(row["LastModified"]).isoformat() != row["LastModified"]:
                raise ValueError
        except ValueError as exc:
            raise RuntimeError("LastModified must be a YYYY-MM-DD date.") from exc
        key = tuple(row[f] for f in FIELDS)
        if key in keys:
            raise RuntimeError("Duplicate four-field GoldenDB rule.")
        keys.add(key)
        for field in FIELDS:
            autoruns_regex.compile_pattern(row[field], whole_field=False)
        rules.append({field: row[field] for field in FIELDS})
    return dict(records=stored, rules=rules, metadata=metadata, matching_policy=POLICY)


def write_csv(target, input_path, *, backup_dir, replace=False, dry_run=False):
    """Build a complete snapshot or upsert CSV rules; input dates are never trusted."""
    from vraptor.autoruns import golden
    from vraptor.autoruns import regex_store as autoruns_regex_db

    target, input_path = Path(target).expanduser().resolve(), Path(input_path).expanduser().resolve()
    raw = input_path.read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
    if reader.fieldnames not in (list(COLUMNS[:-1]), list(COLUMNS)):
        raise RuntimeError("CSV requires Category,ImagePath,LaunchString,Signer,Notes in that order; optional LastModified is ignored.")
    proposed, seen = [], set()
    for number, row in enumerate(reader, 2):
        if set(row) != set(reader.fieldnames) or any(not isinstance(row[f], str) or not row[f] for f in COLUMNS[:-1]):
            raise RuntimeError(f"Malformed or empty GoldenDB CSV fields at record {number}.")
        key = tuple(row[f] for f in FIELDS)
        if key in seen:
            raise RuntimeError(f"Duplicate four-field rule at CSV record {number}.")
        seen.add(key)
        for field in FIELDS:
            autoruns_regex.compile_pattern(row[field], whole_field=False)
        proposed.append({f: row[f] for f in COLUMNS[:-1]})
        if len(proposed) > golden.MAX_LOOKUP_ROWS:
            raise RuntimeError("GoldenDB CSV rule limit exceeded.")
    if not proposed:
        raise RuntimeError("GoldenDB CSV must contain at least one rule.")

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.with_name("." + target.name + ".lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        before = target.read_bytes() if target.exists() else None
        previous = []
        if before is not None:
            checked = golden.validate_database(target)
            if hashlib.sha256(before).hexdigest() != checked["sha256"]:
                raise RuntimeError("GoldenDB changed during validation.")
            if checked["metadata"]["schema_version"] == SCHEMA:
                previous = autoruns_regex_db.load(target)["records"]
            elif not replace:
                raise RuntimeError("CSV import requires schema 10; use regex-build with a complete CSV to replace an older database.")
        existing = {tuple(r[f] for f in FIELDS): r for r in previous}
        resulting = {} if replace else dict(existing)
        stamp = date.today().isoformat()
        added = updated = 0
        for row in proposed:
            key = tuple(row[f] for f in FIELDS)
            prior = existing.get(key)
            unchanged = prior is not None and prior["Notes"] == row["Notes"]
            resulting[key] = {**row, "LastModified": prior["LastModified"] if unchanged else stamp}
            added += prior is None
            updated += prior is not None and not unchanged
        deleted = len(set(existing) - set(resulting))
        rows = sorted(resulting.values(), key=lambda row: row["Category"].strip("^$").casefold())
        if len(rows) > golden.MAX_LOOKUP_ROWS:
            raise RuntimeError("GoldenDB rule limit exceeded.")
        result = dict(database=str(target), added_rules=added, updated_rules=updated,
                      removed_rules=deleted, rule_count=len(rows), dry_run=dry_run, remote_uploaded=False)
        if rows == previous:
            return {**result, "unchanged": True, "sha256": hashlib.sha256(before).hexdigest()}
        metadata = {"schema_version": SCHEMA, "canonicalization_version": str(autoruns.CANONICALIZATION_VERSION),
                    "hash_algorithm": "none", "matching": "regex-only-four-field",
                    "category_matching": "regex-search", "approval_policy": POLICY,
                    "rule_count": str(len(rows)), "transform_key": autoruns.PATH_TRANSFORM_CACHE_KEY}
        fd, name = tempfile.mkstemp(prefix=".golden-csv-", suffix=".sqlite", dir=target.parent)
        os.close(fd)
        temporary = Path(name)
        try:
            with closing(sqlite3.connect(temporary)) as db:
                db.executescript(SQL)
                db.executemany("INSERT INTO metadata VALUES (?,?)", sorted(metadata.items()))
                db.executemany("INSERT INTO GoldenRules VALUES (?,?,?,?,?,?)", [tuple(r[f] for f in COLUMNS) for r in rows])
                db.commit()
            loaded = autoruns_regex_db.load(temporary)
            if loaded["records"] != rows:
                raise RuntimeError("CSV/GoldenDB round-trip mismatch.")
            result["sha256"] = loaded["database_sha256"]
            if dry_run:
                return result
            if input_path.read_bytes() != raw or (target.read_bytes() if target.exists() else None) != before:
                raise RuntimeError("CSV or GoldenDB changed before publication.")
            if before is not None:
                directory = Path(backup_dir).expanduser().resolve()
                directory.mkdir(parents=True, exist_ok=True)
                backup = directory / (target.name + "." + hashlib.sha256(before).hexdigest() + ".bak")
                if not backup.exists():
                    with backup.open("xb") as stream:
                        stream.write(before)
                        stream.flush()
                        os.fsync(stream.fileno())
                    backup.chmod(0o600)
                if backup.read_bytes() != before:
                    raise RuntimeError("GoldenDB backup differs from the source.")
                result["backup"] = str(backup)
            os.replace(temporary, target)
            return result
        finally:
            temporary.unlink(missing_ok=True)
