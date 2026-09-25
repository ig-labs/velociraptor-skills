"""Four-field regex review exports and complete-stream accounting."""
from __future__ import annotations

import csv
from contextlib import closing
import hashlib
from importlib import resources
import json
import re
from dataclasses import dataclass
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from vraptor.autoruns import regex as autoruns_regex
from vraptor.analyze import source as review_source

SCHEMA = "autoruns_four_field_regex_v1"
FIELDS = ("Category", "ImagePath", "LaunchString", "Signer")
CSV_FIELDS = (*FIELDS, "TotalRows", "ExampleHosts")
SOURCE_CONTRACT = "autoruns-pre-golden-count-v1"
GOLDEN_FIRST_SOURCE_CONTRACT = "autoruns-golden-first-count-v1"
COUNT_FIELDS = ("SourceRows", "EligibleRows", "MatchedRows", "ResidualRows", "GroupCount")
CUTOFF_COUNT_FIELDS = ("EligibleGroups", "HighCountExcludedRows", "HighCountExcludedGroups", "MatchedGroups")
DEFAULT_MAX_HOSTNAMES = 10
CACHE_MAX_ENTRIES = 500  # Per category, including the shared overflow LRU.
SINGLE_LRU_MAX_ENTRIES = 1000
CACHE_DEDICATED_CATEGORIES = 19
CACHE_MAX_KEY_BYTES = 4096
METRIC_MAX_CATEGORIES = 128
METRIC_MAX_CATEGORY_BYTES = 256


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

def build_query(configuration, *, source, max_hostnames=DEFAULT_MAX_HOSTNAMES, max_total_rows=None,
                cache_max_entries=None, cache_max_key_bytes=CACHE_MAX_KEY_BYTES,
                single_lru=False, vql_file=None):
    from vraptor.autoruns.testing import _encode
    if type(max_hostnames) is not int or not 0 <= max_hostnames <= 1000:
        raise RuntimeError("Example hostname limit must be between 0 and 1000.")
    if max_total_rows is not None and (type(max_total_rows) is not int or max_total_rows <= 0):
        raise ValueError("max_total_rows must be a positive integer or None.")
    if type(single_lru) is not bool:
        raise RuntimeError("single_lru must be a boolean.")
    if vql_file is not None and (single_lru or cache_max_entries is not None):
        raise RuntimeError("VQL files cannot be combined with built-in cache options.")
    # Explicit cache options select the retained experimental template.
    cached_template = single_lru or cache_max_entries is not None
    entry_limit = SINGLE_LRU_MAX_ENTRIES if single_lru else CACHE_MAX_ENTRIES
    if cache_max_entries is None:
        cache_max_entries = entry_limit
    # Zero entries is an internal benchmark/reference mode, not a second CLI workflow.
    if type(cache_max_entries) is not int or not 0 <= cache_max_entries <= entry_limit:
        raise RuntimeError("Invalid review cache entry bound.")
    if type(cache_max_key_bytes) is not int or not 1 <= cache_max_key_bytes <= CACHE_MAX_KEY_BYTES:
        raise RuntimeError("Invalid review cache key bound.")
    cache_name = ('"autoruns-regex-review-single-lru"' if single_lru else
                  'ReviewCategoryCache(CategoryKey=serialize(item=Category, format="json"))')
    env = source.query_environment()
    env["AutorunsTestReviewGzip"] = _encode(configuration["rules"])
    template = (vql_file.text if vql_file is not None else
        resources.files("vraptor").joinpath(
            "resources", "autoruns",
            "regex-review-cached.vql" if cached_template else "regex-review.vql").read_text())
    match = ("ReviewCachedMatch(Key=serialize(item=dict(Category=Category, "
             "ImagePath=ImagePath, LaunchString=LaunchString, Signer=Signer), format=\"json\"))"
             if cache_max_entries else "ReviewFullMatch()")
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
             .replace("RULE_COUNT", str(len(configuration["rules"])))
             .replace("CACHE_ENTRIES", str(max(1, cache_max_entries)))
             .replace("CACHE_NAME", cache_name)
             .replace("CACHE_DEDICATED_CATEGORIES", str(CACHE_DEDICATED_CATEGORIES))
             .replace("CACHE_KEY_BYTES", str(cache_max_key_bytes))
             .replace("MATCH_EXPRESSION", match)
             .replace("METRIC_MAX_CATEGORIES", str(METRIC_MAX_CATEGORIES))
             .replace("METRIC_MAX_CATEGORY_BYTES", str(METRIC_MAX_CATEGORY_BYTES)))
    if vql_file is not None:
        query = "// Autoruns VQL file SHA-256: " + vql_file.sha256 + "\n" + query
    return query, env, {"Regex": len(configuration["rules"])}


def category_cache_statistics(summary, counts, evaluations, bypasses):
    """Validate bounded outcome metrics against the same-pass source totals."""
    rows = summary.get("CacheCategoryMetrics")
    overflow = summary.get("CacheCategoryMetricsOverflow")
    if not isinstance(rows, list) or len(rows) > METRIC_MAX_CATEGORIES:
        raise RuntimeError("Invalid regex review category metrics.")
    raw_fields = tuple(prefix + suffix for prefix in ("Matched", "Residual")
                       for suffix in ("Rows", "Evaluations", "Bypasses"))
    totals = dict.fromkeys(raw_fields, 0)
    categories = set()
    result = []
    for index, row in enumerate([*rows, overflow]):
        if not isinstance(row, dict) or set(row) != {"Category", *raw_fields}:
            raise RuntimeError("Malformed regex review category metrics.")
        category = row["Category"]
        if index == len(rows):
            if category is not None:
                raise RuntimeError("Invalid regex review overflow category.")
        else:
            if (not isinstance(category, str) or category in categories
                    or len(category.encode("utf-8")) > METRIC_MAX_CATEGORY_BYTES):
                raise RuntimeError("Invalid or duplicated regex review metric category.")
            categories.add(category)
        if any(type(row[k]) is not int or row[k] < 0 for k in raw_fields):
            raise RuntimeError("Invalid regex review category counters.")
        item = {"category": category}
        for label, prefix in (("matched", "Matched"), ("residual", "Residual")):
            total, executed, bypassed = (row[prefix + suffix]
                                        for suffix in ("Rows", "Evaluations", "Bypasses"))
            if not 0 <= bypassed <= executed <= total:
                raise RuntimeError("Inconsistent regex review category counters.")
            item[label] = dict(rows=total, hits=total-executed, misses=executed-bypassed,
                               bypasses=bypassed, matching_evaluations=executed)
        for key in totals:
            totals[key] += row[key]
        result.append(item)
    if (totals["MatchedRows"] != counts["MatchedRows"]
            or totals["ResidualRows"] != counts["ResidualRows"]
            or totals["MatchedEvaluations"] + totals["ResidualEvaluations"] != evaluations
            or totals["MatchedBypasses"] + totals["ResidualBypasses"] != bypasses):
        raise RuntimeError("Regex review category totals do not reconcile.")
    global_outcomes = {
        label: {key: sum(item[label][key] for item in result)
                for key in ("rows", "hits", "misses", "bypasses", "matching_evaluations")}
        for label in ("matched", "residual")
    }
    return {"category_metrics_version": 1,
            "max_metric_categories": METRIC_MAX_CATEGORIES,
            "max_metric_category_bytes": METRIC_MAX_CATEGORY_BYTES,
            "by_category": sorted(result[:-1], key=lambda item: item["category"]),
            "category_overflow": result[-1], **global_outcomes}


def consume(rows, writer, *, rule_count, max_hostnames, cache_stats=None, single_lru=False,
            expect_cache_metrics=True, pre_golden_cutoff=False, max_total_rows=None):
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
        if (pre_golden_cutoff or expect_cache_metrics is False) and previous is not None and total > previous:
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
        expect_cache_metrics = False
    if expect_cache_metrics is None:
        # Complete experimental templates may return either supported summary.
        # Partial or malformed cache telemetry still fails the cached validator.
        expect_cache_metrics = bool(set(summary) - {"_Review", *keys})
    if not expect_cache_metrics:
        if single_lru or set(summary) != {"_Review", *keys}:
            raise RuntimeError("Uncached summary does not match its expected schema.")
        counts["ExcludedRows"] = counts["SourceRows"] - counts["EligibleRows"]
        return counts
    evaluations, bypasses = (summary.get(k) for k in ("MatchingEvaluations", "CacheBypasses"))
    if (type(summary.get("CacheCategories")) is not int
            or not 0 <= summary["CacheCategories"] <= CACHE_DEDICATED_CATEGORIES
            or type(summary.get("CacheOverflowUsed")) is not bool
            or type(summary.get("CacheErrors")) is not int or summary["CacheErrors"] != 0
            or type(evaluations) is not int or type(bypasses) is not int
            or not 0 <= bypasses <= evaluations <= counts["EligibleRows"]
            or (counts["EligibleRows"] and not evaluations)):
        raise RuntimeError("Invalid regex review cache accounting.")
    if single_lru and (summary["CacheCategories"] != 0 or summary["CacheOverflowUsed"]):
        raise RuntimeError("Single-LRU review unexpectedly allocated category caches.")
    category_stats = category_cache_statistics(summary, counts, evaluations, bypasses)
    if cache_stats is not None:
        cache_stats.update(category_stats)
        cache_stats.update(matching_evaluations=evaluations, bypasses=bypasses,
                           hits=counts["EligibleRows"] - evaluations,
                           misses=evaluations - bypasses,
                           dedicated_categories=summary["CacheCategories"],
                           overflow_cache_used=summary["CacheOverflowUsed"])
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


def run(api, *, hunt_id, artifact, database, output_dir, max_hostnames=DEFAULT_MAX_HOSTNAMES,
        query_timeout_seconds=0, show_vql=False, single_lru=False, vql_file=None,
        workflow="autoruns_test", max_total_rows=None):
    from vraptor.autoruns import testing as parent
    from vraptor.api import build_vql_request
    from vraptor.api import org_id_candidates
    if workflow not in {"autoruns_test", "autoruns"}:
        raise RuntimeError("Unknown Autoruns export workflow.")
    started = time.monotonic()
    configuration = load_database(database)
    source = review_source.hunt_source(hunt_id, artifact)
    query, env, expected = build_query(configuration, source=source, max_hostnames=max_hostnames,
                                       single_lru=single_lru, vql_file=vql_file, max_total_rows=max_total_rows)
    pre_golden_cutoff = vql_file is not None and "TOTAL_ROWS_LIMIT" in vql_file.text
    request_bytes = max(build_vql_request(
        query, env, org_id=org, timeout=query_timeout_seconds, max_wait=30,
        max_row=parent.TRANSPORT_ROWS).ByteSize()
        for org in org_id_candidates(getattr(api, "org_id", "root")))
    if request_bytes > parent.MAX_REQUEST_BYTES:
        raise RuntimeError("Regex review request exceeds the 1 MiB limit.")
    if output_dir is None:
        raise RuntimeError("regex-review requires --autoruns-test-output-dir.")
    target = Path(output_dir).expanduser().resolve()
    if target.exists():
        raise RuntimeError(f"Review output directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".autoruns-review-", dir=target.parent))
    if show_vql:
        print(parent.render_vql(query, env, mode="regex-review",
              database_sha256=configuration["database_sha256"]), file=sys.stderr, flush=True)
    prepared = time.monotonic()
    try:
        cache_stats = {}
        labels = ({"query_name": "autoruns.accounted_stack",
                   "purpose": "autoruns-source-export"}
                  if workflow == "autoruns" else {})
        rows = parent._stream_rows(api, query, env, query_timeout_seconds, **labels)
        try:
            with (staging / "review.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                counts = consume(rows, writer, rule_count=expected["Regex"],
                                 max_hostnames=max_hostnames, cache_stats=cache_stats,
                                 single_lru=single_lru,
                                 pre_golden_cutoff=pre_golden_cutoff, max_total_rows=max_total_rows,
                                 expect_cache_metrics=None if vql_file is not None else single_lru)
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
            "decision_cache": ({"mode": "single-lru",
                               "max_caches": 1 if single_lru else CACHE_DEDICATED_CATEGORIES + 1,
                               "max_entries_per_cache": SINGLE_LRU_MAX_ENTRIES if single_lru else CACHE_MAX_ENTRIES,
                               "max_entries_per_category": None if single_lru else CACHE_MAX_ENTRIES,
                               "max_dedicated_categories": 0 if single_lru else CACHE_DEDICATED_CATEGORIES,
                               "max_total_entries": SINGLE_LRU_MAX_ENTRIES if single_lru else CACHE_MAX_ENTRIES * (CACHE_DEDICATED_CATEGORIES + 1),
                               "max_key_bytes": CACHE_MAX_KEY_BYTES, **cache_stats}
                               if single_lru else {"mode": "uncached-restored",
                                                   "enabled": False, "metrics_available": False}),
            "request_bytes": request_bytes, "stream_complete": True,
            "duration_seconds": round(finished-started, 6),
            "preparation_seconds": round(prepared-started, 6),
            "stream_seconds": round(finished-prepared, 6),
            "query_environment_sha256": parent._query_environment_sha256(query, env),
            "review_csv": str(target / "review.csv"), "stats_json": str(target / "stats.json"),
            "review_csv_sha256": csv_sha256,
            "stack_rows_saved": counts["GroupCount"], "review_status": "not_performed",
            "target_execution": "not_assessed", "canonical_analysis_written": False,
            "inventory_mutated": False,
            "signature_validation": {"status": "source_signer_values_not_independently_verified"},
        }
        if vql_file is not None:
            result["vql_file"] = {"path": vql_file.path, "sha256": vql_file.sha256}
            result["decision_cache"] = {"mode": "custom-vql", "metrics_available": bool(cache_stats),
                                        **cache_stats}
        if pre_golden_cutoff:
            result.update(source_contract=SOURCE_CONTRACT, max_total_rows=max_total_rows)
        if workflow == "autoruns":
            result.update(stage="source_export", review_status_scope="source_export_only",
                review_status_detail="This file records the source export only; AI review status is recorded in canonical hunt state.")
        label = "autoruns source export" if workflow == "autoruns" else "autoruns_test (regex-review)"
        result["chat_summary"] = (
            f"{label}: {counts['SourceRows']:,} source rows; "
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
