"""GoldenDB experiments over a complete Autoruns hunt.

The existing accounted-stack query and validator own grouping and completion.
Legacy modes return counts only. regex-review exports local residual CSV and stats.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Iterator

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import test_store as autoruns_test_db
from vraptor.hunt import live
from vraptor.logging import operations as operation_log
from vraptor.analyze import source as review_source
from vraptor.api import build_vql_request
from vraptor.api import org_id_candidates

MODES = ("hash-baseline", "regex-equivalent", "regex-grouped", "signer-experimental", "regex-review")
MAX_REQUEST_BYTES = 1024 * 1024
TRANSPORT_ROWS = 1000


def validate_request(*, database: Path, mode: str) -> dict[str, Any]:
    if mode == "regex-review":
        from vraptor.autoruns.review import load_database
        return load_database(database)
    if mode not in MODES:
        raise RuntimeError(f"Unknown autoruns_test mode: {mode!r}.")
    result = autoruns_test_db.load_database(database)
    if mode == "regex-grouped" and result["metadata"]["schema_version"] != autoruns_test_db.SCHEMA_VERSION:
        raise RuntimeError("regex-grouped requires a rebuilt autoruns_test_v2 database.")
    if mode == "signer-experimental" and not result["signer_rules"]:
        raise RuntimeError("The test database has no eligible signer experiment rules.")
    return result


def _encode(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(gzip.compress(payload, mtime=0)).decode("ascii")


def build_query(
    configuration: dict[str, Any], *, mode: str, source: review_source.ReviewSource,
    max_hostnames: int = 20, single_lru: bool = False, vql_file=None,
) -> tuple[str, dict[str, str], dict[str, int]]:
    """Bind local rules as scalar arrays; stored SELECT queries break any()."""
    if mode == "regex-review":
        from vraptor.autoruns.review import build_query as build_review
        return build_review(configuration, source=source, max_hostnames=max_hostnames,
                            single_lru=single_lru, vql_file=vql_file)
    if vql_file is not None:
        raise RuntimeError("VQL files require regex-review mode.")
    if single_lru:
        raise RuntimeError("Single-LRU caching requires regex-review mode.")
    if mode not in MODES:
        raise RuntimeError(f"Unknown autoruns_test mode: {mode!r}.")
    payloads = {
        "Hashes": configuration["exact_hashes"] if mode == "hash-baseline" else [],
        "Exact": configuration["exact_patterns"] if mode != "hash-baseline" else [],
        "Regex": configuration["regex_rules"],
        "Signer": configuration["signer_rules"] if mode == "signer-experimental" else [],
    }
    if mode == "regex-grouped":
        # The loader verifies that these finite expressions accept exactly the
        # same correlated ImagePath/LaunchString/Signer rows shown in the review.
        # Evaluate one compiled tuple expression per group instead of three
        # separate field expressions for every identity.
        payloads["Exact"] = [{"CategoryRegex": group["CategoryRegex"], "IdentityRegex": group["IdentityRegex"]}
                             for group in configuration["exact_groups"]]
    env = source.query_environment()
    counts = {name: len(rows) for name, rows in payloads.items()}
    statements = []
    for name, rows in payloads.items():
        env[f"AutorunsTest{name}Gzip"] = _encode(rows)
        statements.append(
            f"LET AutorunsTest{name} <= parse_json_array(data=gunzip(string="
            f"base64decode(string=AutorunsTest{name}Gzip)))"
        )
    checks = " AND ".join(f"len(list=AutorunsTest{name}) = {count}" for name, count in counts.items())
    statements.append(f"LET AutorunsTestReady <= {checks}")
    if mode == "hash-baseline":
        statements.append(
            'LET AutorunsTestKeys <= memoize(key="Key", period=1000000, query={ '
            'SELECT _value AS Key FROM foreach(row=AutorunsTestHashes) })'
        )
        exact = f"get(item=AutorunsTestKeys, field={autoruns.trusted_key_vql()})"
    elif mode == "regex-grouped":
        statements.append(
            'LET AutorunsTestFieldMatch(GoldenCategory, Identity) = '
            'any(items=AutorunsTestExact, filter=\'rule=>(rule.CategoryRegex = ".*" OR GoldenCategory =~ rule.CategoryRegex) '
            'AND Identity =~ rule.IdentityRegex\')'
        )
        category_value = 'if(condition=Category, then=Category, else="")'
        exact = (
            f"AutorunsTestFieldMatch(GoldenCategory={autoruns.ascii_lower_vql(category_value)}, "
            f"Identity={autoruns.trusted_key_serialized_vql()})"
        )
    else:
        statements.append(
            'LET AutorunsTestExactMatch(Identity) = any(items=AutorunsTestExact, '
            'filter="rule=>Identity =~ rule")'
        )
        exact = f"AutorunsTestExactMatch(Identity={autoruns.trusted_key_serialized_vql()})"
    # The baseline paired regex remains signer-independent.
    statements.append(
        'LET AutorunsTestRegexMatch(GoldenImage, GoldenLaunch, GoldenSigner) = '
        'any(items=AutorunsTestRegex, '
        'filter="rule=>GoldenImage =~ rule.ImagePathRegex AND GoldenLaunch =~ rule.LaunchStringRegex") '
        'OR any(items=AutorunsTestSigner, filter=\'rule=>GoldenSigner = rule.Signer '
        'AND GoldenImage =~ rule.ImagePathRegex AND '
        '((rule.LaunchMode = "empty" AND NOT GoldenLaunch) OR '
        '(rule.LaunchMode = "same_image" AND GoldenImage = GoldenLaunch))\')'
    )
    fallback = (
        f"AutorunsTestRegexMatch(GoldenImage={autoruns.user_path_vql('`Image Path`')}, "
        f"GoldenLaunch={autoruns.user_path_vql('`Launch String`')}, "
        f"GoldenSigner={autoruns.ascii_lower_vql('Signer')})"
    )
    # An exact match avoids redundant paired-regex evaluation.
    where = f"NOT if(condition={exact}, then=TRUE, else={fallback})"
    statements.append(
        'SELECT "rules_ready" AS _AutorunsTest, AutorunsTestReady AS Ready, '
        + ", ".join(f"len(list=AutorunsTest{name}) AS {name}" for name in counts)
        + " FROM scope()"
    )
    guarded_source = review_source.ReviewSource(
        source.source_type, source.source_id, source.artifact,
        'if(condition=AutorunsTestReady, then={ SELECT *, get(item=scope(), field="Category") AS Category'
        + f" FROM {source.vql} }})",
        source.environment,
    )
    return (
        "\n".join(statements) + "\n" + live.autoruns_accounted_stack_vql(where, source=guarded_source),
        env,
        counts,
    )


def _query_environment_sha256(query: str, env: dict[str, str]) -> str:
    identity = json.dumps({"query": query, "env": env}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def render_vql(
    query: str, env: dict[str, str], *, mode: str, database_sha256: str,
) -> str:
    """Display the exact query with safe metadata, without bound rule contents."""
    comments = [
        f"-- autoruns_test mode={json.dumps(mode)}",
        f"-- HuntId={json.dumps(env.get('HuntId', ''))}",
        f"-- ArtifactName={json.dumps(env.get('ArtifactName', ''))}",
        f"-- database_sha256={json.dumps(database_sha256)}",
        f"-- query_sha256={hashlib.sha256(query.encode('utf-8')).hexdigest()}",
        f"-- query_environment_sha256={_query_environment_sha256(query, env)}",
        "-- Gzip rule payloads are separately bound API environment parameters; values omitted.",
        "-- This rendering does not establish live signature-source verification.",
    ]
    for name in sorted(env):
        if name.startswith("AutorunsTest"):
            value = env[name].encode("utf-8")
            comments.append(
                f"-- env {json.dumps(name)}: utf8_bytes={len(value)} sha256={hashlib.sha256(value).hexdigest()}"
            )
    return "\n".join(comments) + "\n\n" + query


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


def consume_stream(rows: Iterator[dict[str, Any]], expected: dict[str, int]) -> dict[str, int]:
    header = next(rows, None)
    if not isinstance(header, dict) or header.get("_AutorunsTest") != "rules_ready" or header.get("Ready") is not True:
        raise RuntimeError("Autoruns test rule materialization was not verified.")
    if any(type(header.get(name)) is not int or header[name] != value for name, value in expected.items()):
        raise RuntimeError("Autoruns test rule materialization counts differ.")
    stack = live.AutorunsAccountedStack(rows)
    for _ in stack:
        pass  # All groups are validated and discarded; no review or persistence.
    if not stack.complete:
        raise RuntimeError("Autoruns test did not complete its accounted stream.")
    return dict(stack.counts)


def run(
    api: Any, *, hunt_id: str, artifact: str, database: Path,
    mode: str = "hash-baseline", query_timeout_seconds: int = 0,
    hunt_row: dict[str, Any] | None = None,
    show_vql: bool = False,
    output_dir: Path | None = None, max_hostnames: int = 20, single_lru: bool = False, vql_file=None,
) -> dict[str, Any]:
    started = time.monotonic()
    if artifact not in live.AUTORUNS_ARTIFACTS or not hunt_id:
        raise RuntimeError("autoruns_test requires one exact Autoruns hunt artifact.")
    if mode == "regex-review":
        from vraptor.autoruns.review import run as run_review
        return run_review(api, hunt_id=hunt_id, artifact=artifact, database=database,
                          output_dir=output_dir, max_hostnames=max_hostnames,
                          query_timeout_seconds=query_timeout_seconds, show_vql=show_vql,
                          single_lru=single_lru, vql_file=vql_file)
    if vql_file is not None:
        raise RuntimeError("VQL files require regex-review mode.")
    if single_lru:
        raise RuntimeError("Single-LRU caching requires regex-review mode.")
    configuration = validate_request(database=database, mode=mode)
    attestation: dict[str, Any] = {"status": "not_required"}
    if mode == "signer-experimental":
        from vraptor.autoruns.signature import validate_signature_source
        attestation = validate_signature_source(api, hunt_row or {}, artifact)
    source = review_source.hunt_source(hunt_id, artifact)
    query, env, expected = build_query(configuration, mode=mode, source=source)
    request_bytes = max(
        build_vql_request(query, env, org_id=org_id, timeout=query_timeout_seconds,
                          max_wait=30, max_row=TRANSPORT_ROWS).ByteSize()
        for org_id in org_id_candidates(getattr(api, "org_id", "root"))
    )
    if request_bytes > MAX_REQUEST_BYTES:
        raise RuntimeError(f"Autoruns test request is {request_bytes} bytes; limit is {MAX_REQUEST_BYTES}.")
    if show_vql:
        print(render_vql(query, env, mode=mode, database_sha256=configuration["database_sha256"]),
              file=sys.stderr, flush=True)
    prepared = time.monotonic()
    rows = _stream_rows(api, query, env, query_timeout_seconds)
    try:
        counts = consume_stream(rows, expected)
    finally:
        rows.close()
    finished = time.monotonic()
    query_environment_sha256 = _query_environment_sha256(query, env)
    return {
        "action": "autoruns_test", "status": "complete", "mode": mode,
        "hunt_id": hunt_id, "artifact": artifact,
        "source": source.identity(), "database": str(database.resolve()),
        "database_sha256": configuration["database_sha256"],
        "database_metadata": dict(configuration["metadata"]),
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "query_environment_sha256": query_environment_sha256,
        "request_bytes": request_bytes, "counts": counts, "rule_counts": expected,
        "category_matching": "observed_categories_or_wildcard" if mode == "regex-grouped" else "not_required",
        "duration_seconds": round(finished - started, 6),
        "preparation_seconds": round(prepared - started, 6),
        "stream_seconds": round(finished - prepared, 6),
        "stream_complete": True, "review_status": "not_performed",
        "target_execution": "not_assessed", "stack_rows_saved": 0,
        "canonical_analysis_written": False, "inventory_mutated": False,
        "signature_validation": attestation,
        "chat_summary": (
            f"Source: {hunt_id} / {artifact}\n"
            f"autoruns_test ({mode}): {counts['SourceRows']:,} source rows; "
            f"{counts['MatchedRows']:,} matched; {counts['ResidualRows']:,} residual; "
            f"{counts['PopulatedRows']:,} populated; {counts['GroupCount']:,} groups.\n"
            f"Complete stream: {finished - prepared:.3f}s; total: {finished - started:.3f}s. "
            "AI review: not performed. Stack rows saved: 0. Target execution: not assessed.\n"
            f"Database SHA256: {configuration['database_sha256']}\n"
            f"Source GoldenDB SHA256: {configuration['metadata'].get('source_sha256', '')}\n"
            f"Query/environment SHA256: {query_environment_sha256}"
        ),
    }
