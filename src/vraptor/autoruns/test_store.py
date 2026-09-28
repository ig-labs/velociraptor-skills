"""Isolated, locally built GoldenDB experiments; never production inventory.

The finite exact expressions encode entire canonical tuples. Paired regex
rules follow the same approved-rule matching contract as production.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable

import re2

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import golden
from vraptor.autoruns import regex as autoruns_regex


SCHEMA_VERSION = "autoruns_test_v2"
LEGACY_SCHEMA_VERSION = "autoruns_test_v1"
MAX_PATTERN_BYTES = 32 * 1024
# Limit recursive radix factoring independently of expression byte size.
MAX_IDENTITIES_PER_PATTERN = 256
REQUIRED_METADATA = {
    "schema_version": SCHEMA_VERSION,
    "purpose": "autoruns_test_only",
    "canonicalization_version": str(autoruns.CANONICALIZATION_VERSION),
    "hash_algorithm": autoruns.TRUSTED_KEY_HASH,
    "transform_key": autoruns.PATH_TRANSFORM_CACHE_KEY,
    "source_schema_version": golden.SCHEMA_VERSION,
    "signer_rules_status": "runtime_artifact_verification_required",
    "signer_rules_policy": "intentionally_broader_cross_system_directory",
}
SCHEMA_SQL = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE test_exact_identities (
    hash_key TEXT PRIMARY KEY, payload TEXT NOT NULL UNIQUE
);
CREATE TABLE test_exact_patterns (
    position INTEGER PRIMARY KEY, pattern TEXT NOT NULL
);
CREATE TABLE test_regex_rules (
    image_path_regex TEXT NOT NULL, launch_string_regex TEXT NOT NULL,
    PRIMARY KEY (image_path_regex, launch_string_regex)
) WITHOUT ROWID;
CREATE TABLE test_signer_rules (
    position INTEGER PRIMARY KEY, rule_json TEXT NOT NULL
);
CREATE TABLE test_identity_categories (
    hash_key TEXT NOT NULL, category TEXT NOT NULL,
    PRIMARY KEY (hash_key, category)
);
CREATE TABLE test_exact_pattern_groups (
    position INTEGER PRIMARY KEY, group_json TEXT NOT NULL
);
CREATE TABLE test_identity_notes (
    hash_key TEXT PRIMARY KEY, description TEXT NOT NULL
);
CREATE TABLE test_regex_rule_notes (
    image_path_regex TEXT NOT NULL, launch_string_regex TEXT NOT NULL,
    description TEXT NOT NULL, PRIMARY KEY (image_path_regex, launch_string_regex)
);
"""


def _compile(pattern: str) -> Any:
    options = re2.Options()
    options.log_errors = False
    try:
        return re2.compile(pattern, options=options)
    except re2.error as exc:
        raise RuntimeError(f"Invalid autoruns_test RE2 expression: {exc}") from exc


def _literal(value: str) -> str:
    # Only JSON formatting introduces raw newlines; evidence controls are
    # already JSON escaped. Avoid Python re.escape's escaped literal newline.
    return re.sub(r"[\\.^$|?*+()\[\]{}\n]",
                  lambda match: r"\n" if match[0] == "\n" else "\\" + match[0], value)


def _factor(values: list[str]) -> str:
    """Radix-factor sorted literals without introducing any new tuple."""
    if len(values) == 1:
        return _literal(values[0])
    prefix = os.path.commonprefix((values[0], values[-1]))
    tails = [value[len(prefix):] for value in values]
    buckets: dict[str, list[str]] = {}
    for tail in tails:
        buckets.setdefault(tail[:1], []).append(tail)
    arms = [_factor(group) if key else "" for key, group in buckets.items()]
    return _literal(prefix) + "(?:" + "|".join(arms) + ")"


def exact_patterns(
    payloads: Iterable[str], *, max_pattern_bytes: int = MAX_PATTERN_BYTES,
) -> list[str]:
    """Return deterministic, bounded, case-sensitive finite tuple expressions."""
    if not isinstance(max_pattern_bytes, int) or not 64 <= max_pattern_bytes <= MAX_PATTERN_BYTES:
        raise RuntimeError(f"autoruns_test pattern budget must be 64..{MAX_PATTERN_BYTES} bytes.")
    values = sorted(set(payloads))
    patterns: list[str] = []
    start = 0
    while start < len(values):
        end = min(start + MAX_IDENTITIES_PER_PATTERN, len(values))
        # Binary search reduces build work for long tuples. Factoring a larger
        # finite set cannot shorten the rendered expression for this grammar.
        low, high, accepted = start + 1, end, None
        while low <= high:
            middle = (low + high) // 2
            pattern = r"(?-i)\A(?:" + _factor(values[start:middle]) + r")\z"
            if len(pattern.encode("utf-8")) <= max_pattern_bytes:
                accepted = (middle, pattern)
                low = middle + 1
            else:
                high = middle - 1
        if accepted is None:
            raise RuntimeError("An exact autoruns_test tuple exceeds the pattern byte budget.")
        end, pattern = accepted
        compiled = _compile(pattern)
        if not all(compiled.search(value) is not None for value in values[start:end]):
            raise RuntimeError("autoruns_test finite expression failed positive tuple validation.")
        patterns.append(pattern)
        start = end
    return patterns


def _reject_pending_wal(path: Path) -> None:
    wal = path.with_name(path.name + "-wal")
    if wal.exists() and wal.stat().st_size:
        raise RuntimeError("autoruns_test requires a stable SQLite file without pending WAL data.")


def signer_rules(
    exacts: list[tuple[str, str]], *, max_pattern_bytes: int = MAX_PATTERN_BYTES,
) -> list[dict[str, Any]]:
    """Propose finite DLL counterpart paths; runtime must attest verification.

    Only the system32/syswow64 directory varies. Filenames originate in exact
    source identities, and launch equality remains a separate runtime condition.
    This is intentionally broader and never participates in baseline modes.
    """
    subject = "(verified) microsoft windows"
    eligible: dict[str, dict[str, set[str]]] = {"same_image": {}, "empty": {}}
    for key, payload in exacts:
        item = json.loads(payload)
        match = re.fullmatch(r"c:\\windows\\(?:system32|syswow64)\\([a-z0-9_][a-z0-9_.-]{0,126}\.dll)",
                             item["ImagePath"])
        if item["Signer"] != subject or not match:
            continue
        if item["LaunchString"] == item["ImagePath"]:
            mode = "same_image"
        elif not item["LaunchString"]:
            mode = "empty"
        else:
            continue
        eligible[mode].setdefault(match[1], set()).add(key)
    result = []
    for mode, names in sorted(eligible.items()):
        paths = sorted(f"c:\\windows\\{directory}\\{name}"
                       for name in names for directory in ("system32", "syswow64"))
        for pattern in exact_patterns(paths, max_pattern_bytes=max_pattern_bytes):
            compiled = _compile(pattern)
            source_keys = sorted({key for name, keys in names.items()
                if any(compiled.search(f"c:\\windows\\{directory}\\{name}") is not None
                       for directory in ("system32", "syswow64")) for key in keys})
            result.append({"ImagePathRegex": pattern, "LaunchMode": mode,
                           "Signer": subject, "SourceExactHashes": source_keys})
    return result


def _content_hash(exacts: list[tuple[str, str]], rules: list[tuple[str, str]]) -> str:
    return hashlib.sha256(golden.stable_json({
        "exact_identities": exacts, "regex_rules": rules, "matching_policy": autoruns_regex.MATCHING_POLICY,
    }).encode("utf-8")).hexdigest()


def _category_hash(categories: dict[str, list[str]]) -> str:
    return hashlib.sha256(golden.stable_json(categories).encode("utf-8")).hexdigest()


def _load_category_map(path: Path | None, source_sha256: str, exacts: list[tuple[str, str]]) -> tuple[dict[str, list[str]], str]:
    if path is None:
        return {}, ""
    raw = Path(path).expanduser().read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("schema_version") != "autoruns_test_categories_v1" or data.get("source_database_sha256") != source_sha256:
        raise RuntimeError("Category map must identify the exact source GoldenDB and autoruns_test_categories_v1 schema.")
    categories = data.get("identity_categories")
    keys = {key for key, _ in exacts}
    if not isinstance(categories, dict) or set(categories) - keys:
        raise RuntimeError("Category map contains unknown identity hashes.")
    normalized = {}
    for key, values in categories.items():
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() or value != value.strip() for value in values):
            raise RuntimeError("Category map requires lists of nonempty observed category labels.")
        if values:
            normalized[key] = sorted(set(values))
    return normalized, hashlib.sha256(raw).hexdigest()


def _publish_new(path: Path, data: bytes) -> None:
    path = Path(path).expanduser().absolute()
    if os.path.lexists(path):
        raise RuntimeError(f"autoruns_test output already exists: {path}")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".building", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise RuntimeError(f"autoruns_test output already exists: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def recover_categories(source: Path, category_sources: list[Path], output: Path) -> dict[str, Any]:
    """Join observed legacy categories to current identities; never infer labels."""
    source = Path(source).expanduser().resolve()
    _reject_pending_wal(source)
    source_hash = golden.file_sha256(source)
    with contextlib.closing(golden.connect_database(source, readonly=True)) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok" or golden.metadata(connection).get("schema_version") != golden.SCHEMA_VERSION:
            raise RuntimeError("Category recovery requires a valid schema-6 source GoldenDB.")
        records = golden.exact_records(connection)
    current = {row["hash_key"]: autoruns.trusted_key_serialized(image_path=row["image_path"],
        launch_string=row["launch_string"], signer=row["signer"]) for row in records}
    if any(key != hashlib.sha1(payload.encode()).hexdigest() for key, payload in current.items()):
        raise RuntimeError("Source GoldenDB identity hash mismatch.")
    categories: dict[str, set[str]] = {}
    provenance = []
    for category_source in category_sources:
        path = Path(category_source).expanduser().resolve()
        _reject_pending_wal(path)
        digest = golden.file_sha256(path)
        with contextlib.closing(golden.connect_database(path, readonly=True)) as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("Category source SQLite quick_check failed.")
            rows = list(connection.execute("SELECT hash_key, category, image_path, launch_string, signer FROM autoruns_known_good"))
        matched = 0
        for key, category, image, launch, signer in rows:
            payload = autoruns.trusted_key_serialized(image_path=image, launch_string=launch, signer=signer)
            if key != hashlib.sha1(payload.encode()).hexdigest():
                raise RuntimeError("Category source identity does not match current canonical hashing.")
            if key not in current:
                continue
            if current[key] != payload:
                raise RuntimeError("Category source canonical identity differs from current GoldenDB.")
            if category in (None, ""):
                continue
            if not isinstance(category, str) or category != category.strip():
                raise RuntimeError("Category source contains an invalid category label.")
            categories.setdefault(key, set()).add(category)
            matched += 1
        _reject_pending_wal(path)
        if golden.file_sha256(path) != digest:
            raise RuntimeError("Category source changed during recovery.")
        provenance.append({"path": str(path), "sha256": digest, "rows_read": len(rows), "matched_category_rows": matched})
    _reject_pending_wal(source)
    if golden.file_sha256(source) != source_hash:
        raise RuntimeError("Source GoldenDB changed during category recovery.")
    result = {"schema_version": "autoruns_test_categories_v1", "source_database": str(source),
              "source_database_sha256": source_hash, "sources": provenance,
              "identity_categories": {key: sorted(values) for key, values in sorted(categories.items())},
              "covered_identities": len(categories), "unknown_identities": len(current) - len(categories),
              "category_associations": sum(map(len, categories.values())),
              "method": "Exact canonical identity and SHA1 join; no inferred categories."}
    _publish_new(output, (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode())
    return {key: value for key, value in result.items() if key != "identity_categories"}


def export_grouped_review(database: Path, output: Path) -> dict[str, Any]:
    from vraptor.autoruns.test_groups import render_grouped_review
    loaded = load_database(database)
    if loaded["metadata"]["schema_version"] != SCHEMA_VERSION:
        raise RuntimeError("Grouped review requires a rebuilt autoruns_test_v2 database.")
    with contextlib.closing(golden.connect_database(database, readonly=True)) as connection:
        exacts = [tuple(row) for row in connection.execute("SELECT hash_key, payload FROM test_exact_identities ORDER BY hash_key")]
    if golden.file_sha256(database) != loaded["database_sha256"]:
        raise RuntimeError("autoruns_test database changed during review export.")
    header = (f"<!-- Database SHA256: {loaded['database_sha256']} -->\n"
              f"<!-- Category map SHA256: {loaded['metadata']['category_map_sha256']} -->\n\n")
    rendered = header + render_grouped_review(exacts, loaded["exact_groups"], notes=loaded["identity_notes"],
                                               paired_rules=loaded["regex_review_rules"])
    _publish_new(output, rendered.encode())
    return {"output": str(Path(output).absolute()), "groups": len(loaded["exact_groups"]),
            "identities": len(exacts), "database_sha256": loaded["database_sha256"]}


def build_database(
    source: Path, output: Path, *, max_pattern_bytes: int = MAX_PATTERN_BYTES,
    rmm_reference: Path | None = None,
    category_map: Path | None = None,
) -> dict[str, Any]:
    """Create a private new sibling-validated database; never replace a path."""
    source = Path(source).expanduser().resolve()
    output = Path(output).expanduser().absolute()
    if os.path.lexists(output):
        raise RuntimeError(f"autoruns_test output already exists: {output}")
    if not output.parent.is_dir():
        raise RuntimeError(f"autoruns_test output directory does not exist: {output.parent}")
    _reject_pending_wal(source)
    source_sha256 = golden.file_sha256(source)
    report = golden.validate_database(source, rmm_reference=rmm_reference)
    if report["metadata"]["schema_version"] != golden.SCHEMA_VERSION:
        raise RuntimeError("autoruns_test build requires a validated schema 6 source GoldenDB.")
    connection = golden.connect_database(source, readonly=True)
    try:
        records = golden.exact_records(connection)
        exacts = [(record["hash_key"], autoruns.trusted_key_serialized(
            image_path=record["image_path"], launch_string=record["launch_string"],
            signer=record["signer"],
        )) for record in records]
        notes = {record["hash_key"]: str(record.get("description") or "") for record in records}
        regex_records = golden.regex_records(connection)
        rules = [(record["image_path_regex"], record["launch_string_regex"])
                 for record in regex_records]
        regex_notes = sorted((record["image_path_regex"], record["launch_string_regex"], str(record.get("description") or ""))
                             for record in regex_records)
    finally:
        connection.close()
    if (len(exacts) != report["identity_count"] or len(rules) != report["regex_rule_count"]
            or source_sha256 != report["sha256"]):
        raise RuntimeError("Source GoldenDB changed during autoruns_test build.")
    classifier = golden.RmmClassifier(rmm_reference)
    if classifier.reference_hash != report["rmm_reference_hash"]:
        raise RuntimeError("RMM reference changed during autoruns_test build.")
    from vraptor.autoruns.test_groups import grouped_patterns
    categories, category_map_sha256 = _load_category_map(category_map, source_sha256, exacts)
    groups = grouped_patterns(exacts, categories, max_pattern_bytes=max_pattern_bytes)
    patterns = [group["IdentityRegex"] for group in groups]
    broader_rules = signer_rules(exacts, max_pattern_bytes=max_pattern_bytes)
    metadata = {
        **REQUIRED_METADATA, "built_at": golden.now_utc(),
        "source_database": str(source), "source_sha256": source_sha256,
        "source_rmm_reference_sha256": report["rmm_reference_hash"],
        "exact_identity_count": str(len(exacts)),
        "exact_pattern_count": str(len(patterns)), "regex_rule_count": str(len(rules)),
        "signer_rule_count": str(len(broader_rules)),
        "signer_source_identity_count": str(len({key for rule in broader_rules
                                                for key in rule["SourceExactHashes"]})),
        "max_pattern_bytes": str(max_pattern_bytes),
        "max_identities_per_pattern": str(MAX_IDENTITIES_PER_PATTERN),
        "matching_policy": autoruns_regex.MATCHING_POLICY, "content_sha256": _content_hash(exacts, rules),
        "exact_pattern_grouping": "category-directory-launch-v1",
        "category_content_sha256": _category_hash(categories),
        "category_map_sha256": category_map_sha256,
        "category_identity_count": str(len(categories)),
        "notes_content_sha256": hashlib.sha256(golden.stable_json(notes).encode("utf-8")).hexdigest(),
        "regex_notes_content_sha256": hashlib.sha256(golden.stable_json(regex_notes).encode("utf-8")).hexdigest(),
    }
    descriptor, name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".building", dir=output.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.executescript(SCHEMA_SQL)
            connection.executemany("INSERT INTO metadata VALUES (?, ?)", sorted(metadata.items()))
            connection.executemany("INSERT INTO test_exact_identities VALUES (?, ?)", exacts)
            connection.executemany("INSERT INTO test_exact_patterns VALUES (?, ?)", enumerate(patterns))
            connection.executemany("INSERT INTO test_identity_categories VALUES (?, ?)",
                                   ((key, category) for key, values in sorted(categories.items()) for category in values))
            connection.executemany("INSERT INTO test_exact_pattern_groups VALUES (?, ?)",
                                   ((index, golden.stable_json(group)) for index, group in enumerate(groups)))
            connection.executemany("INSERT INTO test_identity_notes VALUES (?, ?)", sorted(notes.items()))
            connection.executemany("INSERT INTO test_regex_rule_notes VALUES (?, ?, ?)", regex_notes)
            connection.executemany("INSERT INTO test_regex_rules VALUES (?, ?)", rules)
            connection.executemany("INSERT INTO test_signer_rules VALUES (?, ?)",
                                   ((index, golden.stable_json(rule))
                                    for index, rule in enumerate(broader_rules)))
            connection.commit()
        finally:
            connection.close()
        loaded = load_database(temporary)
        _reject_pending_wal(source)
        if source_sha256 != golden.file_sha256(source):
            raise RuntimeError("Source GoldenDB changed during autoruns_test build.")
        # Atomic no-replace publication, including a destination created after
        # the initial existence check. Both paths are on the same filesystem.
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise RuntimeError(f"autoruns_test output already exists: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return {"database": str(output), "database_sha256": loaded["database_sha256"],
            "metadata": dict(metadata),
            "production_compatible": False}


def load_database(path: Path) -> dict[str, Any]:
    """Read and fail closed on format, identity, pattern, count or hash drift."""
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"autoruns_test database not found: {path}")
    _reject_pending_wal(path)
    database_sha256 = golden.file_sha256(path)
    connection = golden.connect_database(path, readonly=True)
    try:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("autoruns_test SQLite quick_check failed.")
        metadata = golden.metadata(connection)
        schema = metadata.get("schema_version")
        if schema not in (SCHEMA_VERSION, LEGACY_SCHEMA_VERSION):
            raise RuntimeError("autoruns_test incompatible metadata 'schema_version'.")
        for key, expected in REQUIRED_METADATA.items():
            if key == "schema_version":
                continue
            if metadata.get(key) != expected:
                raise RuntimeError(f"autoruns_test incompatible metadata {key!r}; expected {expected!r}.")
        if metadata.get("max_identities_per_pattern") != str(MAX_IDENTITIES_PER_PATTERN):
            raise RuntimeError("autoruns_test incompatible finite-pattern grouping.")
        for key in ("source_sha256", "source_rmm_reference_sha256", "content_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", metadata.get(key, "")):
                raise RuntimeError(f"autoruns_test invalid metadata {key!r}.")
        exacts = [tuple(row) for row in connection.execute(
            "SELECT hash_key, payload FROM test_exact_identities ORDER BY hash_key")]
        rules = [tuple(row) for row in connection.execute(
            "SELECT image_path_regex, launch_string_regex FROM test_regex_rules "
            "ORDER BY image_path_regex, launch_string_regex")]
        patterns = [row[0] for row in connection.execute(
            "SELECT pattern FROM test_exact_patterns ORDER BY position")]
        broader_rules = [json.loads(row[0]) for row in connection.execute(
            "SELECT rule_json FROM test_signer_rules ORDER BY position")]
        if metadata.get("matching_policy") != autoruns_regex.MATCHING_POLICY:
            raise RuntimeError("autoruns_test incompatible matching policy; rebuild the experiment.")
        for key, count in (("exact_identity_count", len(exacts)),
                           ("exact_pattern_count", len(patterns)), ("regex_rule_count", len(rules)),
                           ("signer_rule_count", len(broader_rules))):
            if metadata.get(key) != str(count):
                raise RuntimeError(f"autoruns_test {key} accounting mismatch.")
        if len(exacts) > golden.MAX_LOOKUP_ROWS or len(rules) > golden.MAX_LOOKUP_ROWS:
            raise RuntimeError("autoruns_test database exceeds the source lookup limit.")
        for key, payload in exacts:
            item = json.loads(payload)
            if not isinstance(item, dict) or list(item) != ["ImagePath", "LaunchString", "Signer"]:
                raise RuntimeError("autoruns_test invalid canonical tuple fields.")
            if any(not isinstance(value, str) for value in item.values()):
                raise RuntimeError("autoruns_test invalid canonical tuple values.")
            expected = autoruns.trusted_key_serialized(image_path=item["ImagePath"],
                launch_string=item["LaunchString"], signer=item["Signer"])
            if payload != expected or key != hashlib.sha1(payload.encode("utf-8")).hexdigest():
                raise RuntimeError("autoruns_test exact tuple/hash verification failed.")
        if metadata["content_sha256"] != _content_hash(exacts, rules):
            raise RuntimeError("autoruns_test content hash verification failed.")
        groups = []
        categories: dict[str, list[str]] = {}
        notes: dict[str, str] = {}
        regex_notes_by_pair: dict[tuple[str, str], str] = {}
        if schema == SCHEMA_VERSION:
            if metadata.get("exact_pattern_grouping") != "category-directory-launch-v1":
                raise RuntimeError("autoruns_test incompatible pattern grouping.")
            keys = {key for key, _ in exacts}
            notes = dict(connection.execute("SELECT hash_key, description FROM test_identity_notes ORDER BY hash_key"))
            if set(notes) != keys or any(not isinstance(value, str) for value in notes.values()) or metadata.get("notes_content_sha256") != hashlib.sha256(golden.stable_json(notes).encode("utf-8")).hexdigest():
                raise RuntimeError("autoruns_test notes accounting/hash mismatch.")
            if "regex_notes_content_sha256" in metadata:
                regex_notes = [tuple(row) for row in connection.execute("SELECT image_path_regex, launch_string_regex, description FROM test_regex_rule_notes ORDER BY image_path_regex, launch_string_regex")]
                if [(image, launch) for image, launch, _ in regex_notes] != rules or any(not isinstance(note, str) for _, _, note in regex_notes) or metadata["regex_notes_content_sha256"] != hashlib.sha256(golden.stable_json(regex_notes).encode("utf-8")).hexdigest():
                    raise RuntimeError("autoruns_test regex notes accounting/hash mismatch.")
                regex_notes_by_pair = {(image, launch): note for image, launch, note in regex_notes}
            for key, category in connection.execute("SELECT hash_key, category FROM test_identity_categories ORDER BY hash_key, category"):
                if key not in keys or not isinstance(category, str) or not category.strip() or category != category.strip():
                    raise RuntimeError("autoruns_test invalid category association.")
                categories.setdefault(key, []).append(category)
            if metadata.get("category_content_sha256") != _category_hash(categories) or metadata.get("category_identity_count") != str(len(categories)):
                raise RuntimeError("autoruns_test category accounting/hash mismatch.")
            if not re.fullmatch(r"(?:[0-9a-f]{64})?", metadata.get("category_map_sha256", "invalid")):
                raise RuntimeError("autoruns_test invalid category map provenance.")
            from vraptor.autoruns.test_groups import grouped_patterns
            expected_groups = grouped_patterns(exacts, categories, max_pattern_bytes=int(metadata["max_pattern_bytes"]))
            groups = [json.loads(row[0]) for row in connection.execute("SELECT group_json FROM test_exact_pattern_groups ORDER BY position")]
            if groups != expected_groups:
                raise RuntimeError("autoruns_test pattern groups differ from source identities/categories.")
            expected_patterns = [group["IdentityRegex"] for group in expected_groups]
        else:
            expected_patterns = exact_patterns((payload for _, payload in exacts),
                max_pattern_bytes=int(metadata["max_pattern_bytes"]))
        if patterns != expected_patterns:
            raise RuntimeError("autoruns_test patterns differ from the finite source tuples.")
        if broader_rules != signer_rules(exacts, max_pattern_bytes=int(metadata["max_pattern_bytes"])):
            raise RuntimeError("autoruns_test signer rules differ from finite approved source identities.")
        source_count = len({key for rule in broader_rules for key in rule["SourceExactHashes"]})
        if metadata.get("signer_source_identity_count") != str(source_count):
            raise RuntimeError("autoruns_test signer source identity accounting mismatch.")
        regex_rules = []
        regex_review_rules = []
        for image, launch in rules:
            autoruns_regex.compile_pattern(image)
            autoruns_regex.compile_pattern(launch)
            regex_rules.append({"ImagePathRegex": autoruns_regex.full_pattern(image),
                                "LaunchStringRegex": autoruns_regex.full_pattern(launch)})
            regex_review_rules.append({**regex_rules[-1], "Description": regex_notes_by_pair.get((image, launch), "")})
    except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        raise RuntimeError(f"Invalid autoruns_test database {path}: {exc}") from exc
    finally:
        connection.close()
    _reject_pending_wal(path)
    if database_sha256 != golden.file_sha256(path):
        raise RuntimeError("autoruns_test database changed during validation.")
    return {"metadata": metadata, "database_sha256": database_sha256,
            "exact_hashes": [key for key, _ in exacts], "exact_patterns": patterns,
            "regex_rules": regex_rules, "matching_policy": autoruns_regex.MATCHING_POLICY, "signer_rules": broader_rules,
            "exact_groups": groups, "identity_categories": categories, "identity_notes": notes,
            "regex_review_rules": regex_review_rules}
