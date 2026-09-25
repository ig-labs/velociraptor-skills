"""Reviewed regex-only GoldenDB storage, import and backed-up migration."""
from __future__ import annotations

from contextlib import closing
import fcntl
import json
import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import regex as autoruns_regex

SCHEMA = "9"
LEGACY_SCHEMAS = {"7", "8"}
COLUMNS = ("category_regex", "image_path_regex", "launch_string_regex", "signer_regex",
           "notes", "modified_time")
LEGACY_COLUMNS = (*COLUMNS[:4], "description", "modified_time", "origin", "source_hash", "signer_reference")
FIELDS = ("Category", "ImagePath", "LaunchString", "Signer")
SQL = """
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
-- Compatibility table stays empty; schema 9 has no hash-based suppressions.
CREATE TABLE autoruns_known_good(hash_key TEXT PRIMARY KEY, image_path TEXT, launch_string TEXT,
    signer TEXT, description TEXT, modified_time TEXT);
CREATE TABLE autoruns_regex_rules(
    category_regex TEXT NOT NULL CHECK(category_regex='.'), image_path_regex TEXT NOT NULL,
    launch_string_regex TEXT NOT NULL, signer_regex TEXT NOT NULL,
    notes TEXT NOT NULL, modified_time TEXT NOT NULL,
    PRIMARY KEY(category_regex,image_path_regex,launch_string_regex,signer_regex)
) WITHOUT ROWID;
"""


def literal_pattern(value):
    # Quote only Go regexp metacharacters. Preserve all Unicode and whitespace.
    escaped = "".join("\\" + c if c in "\\.+*?()|[]{}^$" else c for c in value)
    return r"(?-i)\A" + escaped + r"\z"


def records(connection):
    if connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] == "10":
        from vraptor.autoruns.csv_store import records as csv_records
        return csv_records(connection)
    connection.row_factory = sqlite3.Row
    return [dict(r) for r in connection.execute("SELECT * FROM autoruns_regex_rules ORDER BY category_regex,image_path_regex,launch_string_regex,signer_regex")]


def load(path, *, rmm_reference=None, allow_legacy=False):
    from vraptor.autoruns import golden
    path = Path(path).expanduser().resolve()
    golden._require_standalone_database(path)
    before = path.read_bytes()
    with closing(sqlite3.connect(path.as_uri()+"?mode=ro",uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Regex-only GoldenDB integrity check failed.")
        meta = dict(db.execute("SELECT key,value FROM metadata"))
        if meta.get("schema_version") == "10":
            from vraptor.autoruns.csv_store import load_connection
            result = load_connection(db, meta, max_rows=golden.MAX_LOOKUP_ROWS)
            if path.read_bytes() != before:
                raise RuntimeError("GoldenDB changed while loading.")
            return {**result, "database_sha256": hashlib.sha256(before).hexdigest()}
        if meta.get("schema_version") not in ({SCHEMA, *LEGACY_SCHEMAS} if allow_legacy else {SCHEMA}) or meta.get("canonicalization_version") != str(autoruns.CANONICALIZATION_VERSION):
            raise RuntimeError("Incompatible regex-only GoldenDB schema/canonicalization; migrate to schema 9 with autoruns regex-migrate.")
        if meta.get("matching") != "regex-only-four-field" or meta.get("hash_algorithm") != "none":
            raise RuntimeError("Invalid regex-only GoldenDB matching metadata.")
        if db.execute("SELECT count(*) FROM autoruns_known_good").fetchone()[0]:
            raise RuntimeError("Regex-only GoldenDB contains exact/hash entries.")
        columns = list(db.execute("PRAGMA table_info(autoruns_regex_rules)"))
        if meta["schema_version"] in {SCHEMA, "8"}:
            expected_columns = COLUMNS if meta["schema_version"] == SCHEMA else LEGACY_COLUMNS
            if tuple(r[1] for r in columns) != expected_columns:
                raise RuntimeError(f"Invalid schema-{meta['schema_version']} rule columns.")
            if tuple(r[1] for r in sorted(columns, key=lambda r:r[5]) if r[5]) != COLUMNS[:4]:
                raise RuntimeError("Invalid regex-only rule key.")
            expected_policy = autoruns_regex.MATCHING_POLICY if meta["schema_version"] == SCHEMA else "goldendb-reviewed-rules-v1"
            if meta.get("approval_policy") != expected_policy:
                raise RuntimeError("Invalid GoldenDB approval policy.")
        if meta["schema_version"] == SCHEMA and meta.get("category_matching") != "any":
            raise RuntimeError("Schema 9 requires category-independent matching.")
        stored = records(db)
    if not stored or len(stored) > golden.MAX_LOOKUP_ROWS:
        raise RuntimeError("Regex-only GoldenDB rule limit exceeded.")
    rules = []
    for row in stored:
        if not row["modified_time"]:
            raise RuntimeError("Invalid regex-only rule metadata.")
        rule = dict(zip(FIELDS, (row[k] for k in ("category_regex","image_path_regex","launch_string_regex","signer_regex"))))
        for pattern in rule.values():
            if not isinstance(pattern,str): raise RuntimeError("Regex-only patterns must be strings.")
            autoruns_regex.compile_pattern(pattern)
        if meta["schema_version"] == SCHEMA:
            if row["category_regex"] != ".":
                raise RuntimeError("Schema 9 CategoryRegex must be '.' for all categories.")
            rule["Category"] = autoruns_regex.category_pattern(rule["Category"])
        rule = {field:autoruns_regex.full_pattern(pattern) for field,pattern in rule.items()}
        rules.append(rule)
    if meta.get("rule_count") != str(len(rules)):
        raise RuntimeError("Regex-only GoldenDB rule count mismatch.")
    if path.read_bytes() != before:
        raise RuntimeError("Regex-only GoldenDB changed while loading.")
    return dict(rules=rules, metadata=meta, database_sha256=hashlib.sha256(before).hexdigest(),
                records=stored, matching_policy=autoruns_regex.MATCHING_POLICY)


def report(path, *, rmm_reference=None, allow_legacy=False):
    cfg = load(path, rmm_reference=rmm_reference, allow_legacy=allow_legacy)
    return dict(database=str(Path(path).resolve()),identity_count=0,record_count=len(cfg["rules"]),
                regex_rule_count=len(cfg["rules"]),notes_count=sum(bool(r.get("Notes", r.get("notes", r.get("description")))) for r in cfg["records"]),
                metadata=cfg["metadata"],sha256=cfg["database_sha256"],regex_only=True,
                matching_policy=cfg["matching_policy"])


def _migrate_locked(source, output, *, backup_dir, exclude_exact=False):
    from vraptor.autoruns import golden
    source, output = Path(source).resolve(), Path(output).resolve()
    golden._require_standalone_database(source)
    with closing(sqlite3.connect(source.as_uri()+"?mode=ro", uri=True)) as probe:
        version = dict(probe.execute("SELECT key,value FROM metadata")).get("schema_version")
    if version == "10":
        if source == output:
            return {**report(source), "already_current": True, "remote_uploaded": False}
        raise RuntimeError("GoldenDB already uses schema 10; use regex-build for CSV maintenance.")
    checked = report(source, allow_legacy=True) if version in {SCHEMA, *LEGACY_SCHEMAS} else golden.validate_database(source)
    if checked["metadata"]["schema_version"] == SCHEMA:
        if output == source:
            return {**checked, "already_current": True, "remote_uploaded": False}
        raise RuntimeError("GoldenDB already uses schema 9 category-independent matching.")
    if output != source and output.exists():
        raise RuntimeError("Migration output already exists.")
    golden._require_standalone_database(source)
    before = source.read_bytes()
    if hashlib.sha256(before).hexdigest() != checked["sha256"]:
        raise RuntimeError("Migration source changed after validation.")
    backup_dir = Path(backup_dir).expanduser().resolve()
    backup_dir.mkdir(parents=True,exist_ok=True)
    backup = backup_dir/(source.name+"."+checked["sha256"]+".bak")
    if backup.exists():
        if backup.read_bytes() != before: raise RuntimeError("Existing migration backup differs.")
    else:
        with backup.open("xb") as f: f.write(before)
        backup.chmod(0o600)
    with closing(golden.connect_database(source,readonly=True)) as db:
        exact = golden.exact_records(db)
        legacy = golden.regex_records(db)
    removed_exact_count = len(exact) if exclude_exact else 0
    if exclude_exact:
        exact = []
    converted=[]
    for row in exact:
        converted.append((".", literal_pattern(row["image_path"]), literal_pattern(row["launch_string"]),
            literal_pattern(row["signer"]), row["description"], row["modified_time"]))
    for row in legacy:
        if version in LEGACY_SCHEMAS:
            converted.append((".", row["image_path_regex"], row["launch_string_regex"],
                row["signer_regex"], row["description"], row["modified_time"]))
        else:
            # Legacy signer_regex was descriptive, never a matching condition.
            converted.append((".", autoruns_regex.full_pattern(row["image_path_regex"]),
                autoruns_regex.full_pattern(row["launch_string_regex"]), "(?s).*",
                row["description"], row["modified_time"]))
    # Category broadening can merge matching identities; retain every distinct note.
    unique={}
    for rule in converted:
        unique.setdefault(rule[:4], []).append(rule)
    collapsed=len(converted)-len(unique)
    converted=[(*key, "\n".join(sorted({r[4] for r in rules if r[4]})),
                max(r[5] for r in rules)) for key, rules in sorted(unique.items())]
    output.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp = tempfile.mkstemp(prefix=".regex-migration-",suffix=".sqlite",dir=output.parent);os.close(fd)
    temp=Path(tmp)
    try:
        meta={"schema_version":SCHEMA,"canonicalization_version":str(autoruns.CANONICALIZATION_VERSION),
              "hash_algorithm":"none","transform_key":autoruns.PATH_TRANSFORM_CACHE_KEY,
              "matching":"regex-only-four-field","category_matching":"any","approval_policy":autoruns_regex.MATCHING_POLICY,"rule_count":str(len(converted)),
              "migrated_from_sha256":checked["sha256"],"migrated_exact_count":str(len(exact)),
              "migrated_regex_count":str(len(legacy)),"removed_exact_count":str(removed_exact_count),"built_at":datetime.now(timezone.utc).isoformat()}
        with closing(sqlite3.connect(temp)) as db:
            db.executescript(SQL)
            db.executemany("INSERT INTO metadata VALUES (?,?)",sorted(meta.items()))
            db.executemany("INSERT INTO autoruns_regex_rules VALUES (?,?,?,?,?,?)",converted)
            db.commit()
        result=report(temp)
        # Every exact source identity must still match its own converted rule.
        if exact:
            matcher = autoruns_regex.RegexIndex(load(temp)["records"])
            for row in exact:
                if not matcher.matches(row):
                    raise RuntimeError("Exact-to-regex conversion changed an identity.")
        if source.read_bytes()!=before or backup.read_bytes()!=before:
            raise RuntimeError("Migration source/backup changed before publication.")
        os.replace(temp,output)
        return {**result,"database":str(output),"backup":str(backup),"source_sha256":checked["sha256"],
                "converted_exact_count":len(exact),"removed_exact_count":removed_exact_count,"retained_regex_count":len(legacy),"collapsed_duplicate_rules":collapsed,"remote_uploaded":False}
    finally:
        temp.unlink(missing_ok=True)


def migrate(source, output, *, backup_dir, exclude_exact=False):
    source = Path(source).expanduser().resolve()
    with source.with_name("."+source.name+".lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _migrate_locked(source, output, backup_dir=backup_dir, exclude_exact=exclude_exact)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def import_rules(target, input_path, *, backup_dir, dry_run=False):
    """Import current CSV rules, or legacy schema-9 JSON rules."""
    if Path(input_path).suffix.lower() == ".csv":
        from vraptor.autoruns.csv_store import write_csv
        return write_csv(target, input_path, backup_dir=backup_dir, dry_run=dry_run)
    target = Path(target).expanduser().resolve()
    if target.exists():
        with closing(sqlite3.connect(target.as_uri() + "?mode=ro", uri=True)) as probe:
            if dict(probe.execute("SELECT key,value FROM metadata")).get("schema_version") == "10":
                raise RuntimeError("Schema-10 GoldenDB imports require CSV input.")
    proposed = json.loads(Path(input_path).read_text())
    if not isinstance(proposed,list) or not proposed:
        raise RuntimeError("Regex import requires a nonempty JSON array of reviewed rules.")
    stamp = datetime.now(timezone.utc).isoformat()
    new = []
    for row in proposed:
        if set(row) != {*FIELDS, "Notes"} or any(not isinstance(v,str) or not v for v in row.values()):
            raise RuntimeError("Each rule requires Category, ImagePath, LaunchString, Signer and Notes strings.")
        if row["Category"] != ".":
            raise RuntimeError("Category must be '.' for category-independent matching.")
        for field in FIELDS: autoruns_regex.compile_pattern(row[field])
        new.append((".", *(autoruns_regex.full_pattern(row[f]) for f in FIELDS[1:]),
            row["Notes"], stamp))
    with target.with_name("."+target.name+".lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        try:
            if load(target)["metadata"]["schema_version"] == "10":
                raise RuntimeError("Schema-10 GoldenDB imports require CSV input.")
            before=target.read_bytes()
            fd,name=tempfile.mkstemp(prefix=".regex-import-",suffix=".sqlite",dir=target.parent)
            os.close(fd); temp=Path(name)
            try:
                temp.write_bytes(before)
                with closing(sqlite3.connect(temp)) as db:
                    initial=db.total_changes
                    db.executemany("INSERT OR IGNORE INTO autoruns_regex_rules VALUES (?,?,?,?,?,?)",new)
                    added=db.total_changes-initial
                    count=db.execute("SELECT count(*) FROM autoruns_regex_rules").fetchone()[0]
                    db.execute("UPDATE metadata SET value=? WHERE key='rule_count'",(str(count),))
                    db.commit()
                checked=report(temp)
                result=dict(database=str(target),added_rules=added,rule_count=count,dry_run=dry_run,remote_uploaded=False)
                if dry_run or not added: return result
                directory=Path(backup_dir).expanduser().resolve();directory.mkdir(parents=True,exist_ok=True)
                backup=directory/(target.name+"."+hashlib.sha256(before).hexdigest()+".bak")
                if not backup.exists():
                    with backup.open("xb") as f: f.write(before)
                    backup.chmod(0o600)
                if target.read_bytes()!=before or backup.read_bytes()!=before:
                    raise RuntimeError("Regex import source/backup changed.")
                os.replace(temp,target)
                return {**result,"backup":str(backup),"sha256":checked["sha256"]}
            finally:
                temp.unlink(missing_ok=True)
        finally:
            fcntl.flock(lock.fileno(),fcntl.LOCK_UN)
