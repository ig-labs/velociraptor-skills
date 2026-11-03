"""Four-field regex review exports and complete-stream accounting."""
from __future__ import annotations

import base64
import csv
from contextlib import closing
import gzip
import hashlib
from importlib import resources
import json
import re
from dataclasses import dataclass
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

from vraptor.autoruns import regex as autoruns_regex
from vraptor.analyze import source as review_source
from vraptor.logging import operations as operation_log

SCHEMA = "autoruns_four_field_regex_v1"
FIELDS = ("Category", "ImagePath", "LaunchString", "Signer")
CSV_FIELDS = (*FIELDS, "TotalRows", "ExampleHosts")
SOURCE_CONTRACT = "autoruns-pre-golden-count-v1"
GOLDEN_FIRST_SOURCE_CONTRACT = "autoruns-golden-first-count-v1"
COUNT_FIELDS = ("SourceRows", "EligibleRows", "MatchedRows", "ResidualRows", "GroupCount")
CUTOFF_COUNT_FIELDS = ("EligibleGroups", "HighCountExcludedRows", "HighCountExcludedGroups", "MatchedGroups")
DEFAULT_MAX_HOSTNAMES = 10
MAX_REQUEST_BYTES = 1024 * 1024
TRANSPORT_ROWS = 1000


def load_database(path):
    path = Path(path).resolve()
    before = path.read_bytes()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise RuntimeError("Regex GoldenDB integrity check failed.")
        metadata = dict(db.execute("SELECT key,value FROM metadata"))
        if metadata.get("schema_version") in {"7", "8", "9", "10"}:
            from vraptor.autoruns.regex_store import load
            return load(path)
        if metadata.get("schema_version") != SCHEMA:
            raise RuntimeError("regex-review requires autoruns_four_field_regex_v1.")
        columns = {row[1] for row in db.execute("PRAGMA table_info(GoldenRules)")}
        order_by = "RuleId" if "RuleId" in columns else "rowid"
        rules = [dict(zip(FIELDS, row)) for row in db.execute(
            f"SELECT Category,ImagePath,LaunchString,Signer FROM GoldenRules ORDER BY {order_by}")]
    if not rules or len(rules) != int(metadata.get("rule_count", "-1")):
        raise RuntimeError("Regex GoldenDB rule count mismatch or empty database.")
    for rule in rules:
        for pattern in rule.values():
            if not isinstance(pattern, str):
                raise RuntimeError("Regex fields must be strings.")
            autoruns_regex.compile_pattern(pattern)
    if path.read_bytes() != before:
        raise RuntimeError("Regex GoldenDB changed while loading.")
    return {"rules": rules, "metadata": metadata,
            "database_sha256": hashlib.sha256(before).hexdigest()}

@dataclass(frozen=True)
class VQLFile:
    path: str
    text: str
    sha256: str


def load_vql_file(path):
    """Snapshot an operator-selected VQL template once, before any API work."""
    path = Path(path).expanduser().resolve()
    try:
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError("Autoruns VQL file exceeds 1 MiB.")
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise RuntimeError(f"Cannot read Autoruns VQL file {path}: {error}") from error
    for placeholder in ("SOURCE_QUERY", "RULE_COUNT", "HOST_LIMIT"):
        if not re.search(r"\b" + placeholder + r"\b", text):
            raise RuntimeError(f"Autoruns VQL file must contain {placeholder}.")
    return VQLFile(str(path), text, hashlib.sha256(raw).hexdigest())


def _encode(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(gzip.compress(payload, mtime=0)).decode("ascii")


def _query_environment_sha256(query: str, env: dict[str, str]) -> str:
    identity = json.dumps({"query": query, "env": env}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def _stream_rows(api: Any, query: str, env: dict[str, str], timeout: int, *,
                 query_name: str = "autoruns_test.accounted_stack",
                 purpose: str = "autoruns_test-first-pass") -> Iterator[dict[str, Any]]:
    batches = iter(api.query_batches(
        query, env, timeout=timeout, max_wait=30, max_row=TRANSPORT_ROWS,
        query_name=query_name,
    ))
    try:
        while True:
            with operation_log.query_context(
                purpose=purpose, hunt_id=env.get("HuntId"),
                artifact=env.get("ArtifactName"),
            ):
                try:
                    batch = next(batches)
                except StopIteration:
                    return
            if not isinstance(batch, list):
                raise RuntimeError("Autoruns query returned a malformed row batch.")
            for row in batch:
                if not isinstance(row, dict):
                    raise RuntimeError("Autoruns query returned a malformed row.")
                yield row
    finally:
        close = getattr(batches, "close", None)
        if close is not None:
            close()


def build_query(configuration, *, source, vql_file, max_hostnames=DEFAULT_MAX_HOSTNAMES, max_total_rows=None):
    if type(max_hostnames) is not int or not 0 <= max_hostnames <= 1000:
        raise RuntimeError("Example hostname limit must be between 0 and 1000.")
    if max_total_rows is not None and (type(max_total_rows) is not int or max_total_rows <= 0):
        raise ValueError("max_total_rows must be a positive integer or None.")
    env = source.query_environment()
    env["AutorunsTestReviewGzip"] = _encode(configuration["rules"])
    template = vql_file.text
    if configuration["metadata"].get("schema_version") in {"9", "10"}:
        pinned = resources.files("vraptor").joinpath(
            "resources", "autoruns", "regex-review-dedup-first.vql").read_text()
        if template != pinned:
            raise RuntimeError("Schema 9/10 requires the pinned production dedup VQL with canonicalization and approved-rule matching.")
    if "NORMALIZATION_FUNCTIONS" in template:
        from vraptor.autoruns import pipeline as autoruns
        if configuration["metadata"].get("schema_version") not in {"9", "10"}:
            raise RuntimeError("Production dedup requires regex-only schema 9 or 10.")
        template = template.replace("NORMALIZATION_FUNCTIONS",
            "LET NormalizeText(Value) = " + autoruns.ascii_lower_vql('if(condition=Value, then=Value, else="")') + "\n"
            + "LET NormalizePath(Value) = " + autoruns.user_path_vql('if(condition=Value, then=Value, else="")'))
    if max_total_rows is not None and "TOTAL_ROWS_LIMIT" not in template:
        raise RuntimeError("This VQL template does not support a residual count cutoff.")
    query = (template.replace("SOURCE_QUERY", source.vql)
             .replace("HOST_LIMIT", str(max_hostnames))
             .replace("TOTAL_ROWS_LIMIT", str(max_total_rows or 0))
             .replace("RULE_COUNT", str(len(configuration["rules"]))))
    query = "// Autoruns VQL file SHA-256: " + vql_file.sha256 + "\n" + query
    return query, env, {"Regex": len(configuration["rules"])}


def consume(rows, writer, *, rule_count, max_hostnames, pre_golden_cutoff=False, max_total_rows=None):
    header = next(rows, None)
    if header != {"_Review": "ready", "Rules": rule_count, "Ready": True}:
        raise RuntimeError("Regex review rule materialization failed.")
    groups = residual = 0
    previous = None
    summary = None
    for row in rows:
        if summary is not None:
            raise RuntimeError("Rows after regex review completion.")
        if row.get("_Review") == "summary":
            summary = row
            continue
        if row.get("_Review") != "stack":
            raise RuntimeError("Unexpected regex review stream row.")
        if any(not isinstance(row.get(f), str) for f in FIELDS):
            raise RuntimeError("Malformed stack fields.")
        total = row.get("TotalRows")
        hosts = row.get("ExampleHosts")
        if type(total) is not int or total <= 0:
            raise RuntimeError("Malformed stack count.")
        if max_total_rows is not None and total > max_total_rows:
            raise RuntimeError("Returned stack exceeds the residual count cutoff.")
        if (not isinstance(hosts, list) or len(hosts) > max_hostnames
                or any(not isinstance(h, str) or not h for h in hosts)
                or len(set(hosts)) != len(hosts) or len(hosts) > total):
            raise RuntimeError("Malformed hostname sample.")
        if pre_golden_cutoff and previous is not None and total > previous:
            raise RuntimeError("Restored uncached stack order is not descending.")
        previous = total
        writer.writerow({**{f: row[f] for f in FIELDS}, "TotalRows": total,
                         "ExampleHosts": json.dumps(hosts, ensure_ascii=False)})
        groups += 1
        residual += total
    keys = COUNT_FIELDS + (CUTOFF_COUNT_FIELDS if pre_golden_cutoff else ())
    if summary is None or any(type(summary.get(k)) is not int or summary[k] < 0 for k in keys):
        raise RuntimeError("Missing or invalid regex review completion.")
    counts = {k: summary[k] for k in keys}
    if (counts["SourceRows"] < counts["EligibleRows"]
            or counts["EligibleRows"] != counts["MatchedRows"] + residual + counts.get("HighCountExcludedRows", 0)
            or counts["ResidualRows"] != residual or counts["GroupCount"] != groups):
        raise RuntimeError("Regex review accounting mismatch.")
    if pre_golden_cutoff:
        validate_cutoff_counts(counts, max_total_rows)
    if set(summary) != {"_Review", *keys}:
        raise RuntimeError("Uncached summary does not match its expected schema.")
    counts["ExcludedRows"] = counts["SourceRows"] - counts["EligibleRows"]
    return counts


def validate_cutoff_counts(counts, max_total_rows, *, golden_first=False):
    """Validate weighted rows and complete-group partitions, including excluded groups."""
    keys = (*COUNT_FIELDS, *CUTOFF_COUNT_FIELDS)
    numeric_keys = [k for k in keys if not (golden_first and k in {"EligibleGroups", "MatchedGroups"})]
    if (any(type(counts.get(k)) is not int or counts[k] < 0 for k in numeric_keys)
            or counts["SourceRows"] < counts["EligibleRows"]
            or counts["EligibleRows"] != counts["HighCountExcludedRows"] + counts["MatchedRows"] + counts["ResidualRows"]):
        raise RuntimeError("Residual cutoff accounting mismatch.")
    if golden_first:
        if any(k not in counts or counts[k] is not None for k in ("EligibleGroups", "MatchedGroups")):
            raise RuntimeError("GoldenDB-first matched and eligible group counts must be unavailable.")
    elif counts["EligibleGroups"] != counts["HighCountExcludedGroups"] + counts["MatchedGroups"] + counts["GroupCount"]:
        raise RuntimeError("Pre-GoldenDB group accounting mismatch.")
    pairs = [("HighCountExcludedGroups", "HighCountExcludedRows"), ("GroupCount", "ResidualRows")]
    if not golden_first:
        pairs.append(("MatchedGroups", "MatchedRows"))
    for group_key, row_key in pairs:
        groups, rows = counts[group_key], counts[row_key]
        if groups > rows or bool(groups) != bool(rows):
            raise RuntimeError("Residual group/row accounting mismatch.")
    if max_total_rows is None:
        if counts["HighCountExcludedRows"]:
            raise RuntimeError("Unlimited review cannot exclude high-count groups.")
    elif (type(max_total_rows) is not int or max_total_rows <= 0
            or counts["HighCountExcludedRows"] < counts["HighCountExcludedGroups"] * (max_total_rows + 1)
            or (not golden_first and counts["MatchedRows"] > counts["MatchedGroups"] * max_total_rows)
            or counts["ResidualRows"] > counts["GroupCount"] * max_total_rows):
        raise RuntimeError("Residual counts violate the configured cutoff.")


def run(api, *, hunt_id, artifact, database, output_dir, vql_file, max_hostnames=DEFAULT_MAX_HOSTNAMES,
        query_timeout_seconds=0, workflow="autoruns", max_total_rows=None):
    from vraptor.api import build_vql_request
    from vraptor.api import org_id_candidates
    if workflow != "autoruns":
        raise RuntimeError("Unknown Autoruns export workflow.")
    started = time.monotonic()
    configuration = load_database(database)
    source = review_source.hunt_source(hunt_id, artifact)
    query, env, expected = build_query(configuration, source=source, max_hostnames=max_hostnames,
                                       vql_file=vql_file, max_total_rows=max_total_rows)
    pre_golden_cutoff = "TOTAL_ROWS_LIMIT" in vql_file.text
    request_bytes = max(build_vql_request(
        query, env, org_id=org, timeout=query_timeout_seconds, max_wait=30,
        max_row=TRANSPORT_ROWS).ByteSize()
        for org in org_id_candidates(getattr(api, "org_id", "root")))
    if request_bytes > MAX_REQUEST_BYTES:
        raise RuntimeError("Regex review request exceeds the 1 MiB limit.")
    if output_dir is None:
        raise RuntimeError("regex-review requires --autoruns-test-output-dir.")
    target = Path(output_dir).expanduser().resolve()
    if target.exists():
        raise RuntimeError(f"Review output directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".autoruns-review-", dir=target.parent))
    prepared = time.monotonic()
    try:
        rows = _stream_rows(api, query, env, query_timeout_seconds,
                            query_name="autoruns.accounted_stack", purpose="autoruns-source-export")
        try:
            with (staging / "review.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                counts = consume(rows, writer, rule_count=expected["Regex"],
                                 max_hostnames=max_hostnames,
                                 pre_golden_cutoff=pre_golden_cutoff, max_total_rows=max_total_rows)
        finally:
            rows.close()
        finished = time.monotonic()
        csv_sha256 = hashlib.sha256((staging / "review.csv").read_bytes()).hexdigest()
        result = {
            "action": workflow, "status": "complete", "mode": "regex-review",
            "hunt_id": hunt_id, "artifact": artifact, "source": source.identity(),
            "database": str(Path(database).resolve()),
            "database_sha256": configuration["database_sha256"],
            "database_metadata": configuration["metadata"],
            "counts": counts, "rule_counts": expected, "max_example_hosts": max_hostnames,
            "decision_cache": {"mode": "custom-vql", "metrics_available": False},
            "request_bytes": request_bytes, "stream_complete": True,
            "duration_seconds": round(finished-started, 6),
            "preparation_seconds": round(prepared-started, 6),
            "stream_seconds": round(finished-prepared, 6),
            "query_environment_sha256": _query_environment_sha256(query, env),
            "review_csv": str(target / "review.csv"), "stats_json": str(target / "stats.json"),
            "review_csv_sha256": csv_sha256,
            "stack_rows_saved": counts["GroupCount"], "review_status": "not_performed",
            "target_execution": "not_assessed", "canonical_analysis_written": False,
            "inventory_mutated": False,
            "signature_validation": {"status": "source_signer_values_not_independently_verified"},
        }
        result["vql_file"] = {"path": vql_file.path, "sha256": vql_file.sha256}
        if pre_golden_cutoff:
            result.update(source_contract=SOURCE_CONTRACT, max_total_rows=max_total_rows)
        result.update(stage="source_export", review_status_scope="source_export_only",
            review_status_detail="This file records the source export only; AI review status is recorded in canonical hunt state.")
        result["chat_summary"] = (
            f"autoruns source export: {counts['SourceRows']:,} source rows; "
            f"{counts['EligibleRows']:,} eligible; {counts['MatchedRows']:,} matched; "
            f"{counts['ResidualRows']:,} retained in {counts['GroupCount']:,} stacks.\n"
            f"Up to {max_hostnames} example hosts per stack. CSV: {result['review_csv']}\n"
            f"Stats: {result['stats_json']}; elapsed: {result['duration_seconds']}s.")
        if pre_golden_cutoff:
            result["chat_summary"] += (
                f"\nExcluded before GoldenDB: {counts['HighCountExcludedGroups']:,} identities / "
                f"{counts['HighCountExcludedRows']:,} records; GoldenDB not evaluated, absent from CSV.")
        (staging / "stats.json").write_text(json.dumps(result, indent=2) + "\n")
        # Reserve the destination without replacing an existing review.
        target.mkdir()
        try:
            for name in ("review.csv", "stats.json"):
                os.replace(staging / name, target / name)
        except BaseException:
            shutil.rmtree(target)
            raise
        return result
    finally:
        shutil.rmtree(staging)
