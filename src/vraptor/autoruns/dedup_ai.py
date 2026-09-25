"""Complete-stack Autoruns preparation and optional AI review."""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import time
from importlib import resources
from itertools import chain
from vraptor.common import token_budget
from pathlib import Path

from vraptor.autoruns import ai_review as ai
from vraptor.autoruns import review
from vraptor.autoruns import regex_store as autoruns_regex_db
from vraptor.autoruns import testing as autoruns_test
from vraptor.analyze import source as review_source
from vraptor.autoruns import publication

CONTRACT = "autoruns-dedup-ai-v2"
FIELDS = (*review.FIELDS, "TotalRows")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()


def identity(row):
    return tuple(row[f] for f in review.FIELDS)


def template():
    path = resources.files("vraptor").joinpath(
        "resources", "autoruns", "regex-review-dedup-first.vql")
    return review.load_vql_file(path)


def prompt(**kwargs):
    text = ai._prompt(**kwargs)
    return text.replace(
        "Known\nRMM/remote-admin software has already been removed by deterministic policy and is reviewed\nthrough a separate focused use case.",
        "RMM/remote-admin software may be present; assess its command and path context.") + (
        "\nCategory is persistence context, not a trust signal. TotalRows counts source records, "
        "not distinct hosts. Signer is source evidence, not independent signature verification. "
        "These are normalized identities; host samples and original entry metadata are unavailable. "
        "Do not infer execution or compromise from presence alone.\n")


def load_source(stats_path, *, database, hunt_id, artifact, max_total_rows=None):
    """Accept only a completed, unchanged export of the pinned matching query."""
    stats_path = Path(stats_path).resolve()
    stats = json.loads(stats_path.read_text())
    cfg = autoruns_regex_db.load(database)
    selected = template()
    if (stats.get("status") != "complete" or stats.get("stream_complete") is not True
        or stats.get("mode") != "regex-review" or stats.get("hunt_id") != hunt_id
        or stats.get("artifact") != artifact
        or stats.get("source_contract") != review.SOURCE_CONTRACT
        or "max_total_rows" not in stats or stats["max_total_rows"] != max_total_rows
        or stats.get("database_sha256") != cfg["database_sha256"]
        or stats.get("vql_file", {}).get("sha256") != selected.sha256):
        raise RuntimeError("Saved review does not match the completed production dedup contract/database/scope.")
    cap = stats.get("max_example_hosts")
    query, env, _ = review.build_query(cfg, source=review_source.hunt_source(hunt_id, artifact),
        max_hostnames=cap, vql_file=selected, max_total_rows=max_total_rows)
    if autoruns_test._query_environment_sha256(query, env) != stats.get("query_environment_sha256"):
        raise RuntimeError("Saved review query/rule fingerprint differs.")
    csv_path = stats_path.parent / "review.csv"
    raw = csv_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != stats.get("review_csv_sha256"):
        raise RuntimeError("Saved review CSV checksum differs or is missing.")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8")))
    if reader.fieldnames != list(review.CSV_FIELDS):
        raise RuntimeError("Saved review CSV contract differs.")
    rows = []
    seen = set()
    for row in reader:
        if set(row) != set(review.CSV_FIELDS) or any(row[f] is None for f in review.CSV_FIELDS):
            raise RuntimeError("Malformed saved stack row.")
        row["TotalRows"] = int(row["TotalRows"])
        row["ExampleHosts"] = json.loads(row["ExampleHosts"])
        key = identity(row)
        if key in seen: raise RuntimeError("Duplicate saved stack identity.")
        seen.add(key)
        rows.append(row)
    # Reuse the stream validator for field types, sample bounds and weighted totals.
    stream = chain([{ "_Review":"ready", "Rules":len(cfg["rules"]), "Ready":True}],
        ({"_Review":"stack", **r} for r in rows),
        [{"_Review":"summary", **{k:stats["counts"][k] for k in
            (*review.COUNT_FIELDS, *review.CUTOFF_COUNT_FIELDS)}}])
    class ValidationSink:
        def writerow(self, row):
            pass
    validated_counts = review.consume(stream, ValidationSink(),
        rule_count=len(cfg["rules"]), max_hostnames=cap, expect_cache_metrics=False,
        pre_golden_cutoff=True, max_total_rows=max_total_rows)
    if validated_counts != stats["counts"]:
        raise RuntimeError("Saved review counts differ from validated source accounting.")
    return stats, rows, cfg


def validate_result(result, rows):
    """Bind completed classifications and full-review accounting to the source."""
    model_rows = sorted(rows, key=identity)
    allowed = {identity(r): r for r in model_rows}
    selected = set()
    for kind in ("suspicious_rows", "potential_golden_rows"):
        for row in result[kind]:
            ident = identity(row)
            expected = {*FIELDS, "Reason"} | ({"Severity"} if kind == "suspicious_rows" else set())
            if (set(row) != expected or ident not in allowed or ident in selected
                    or row["TotalRows"] != allowed[ident]["TotalRows"]
                    or not isinstance(row["Reason"], str) or not row["Reason"].strip()
                    or (kind == "suspicious_rows" and row["Severity"] not in {"low", "medium", "high", "critical"})):
                raise RuntimeError("Classification does not belong to the immutable input.")
            selected.add(ident)
    # Match the streaming review's ordered, length-prefixed normalized rows.
    stack_hash = hashlib.sha256()
    for index, row in enumerate(model_rows, 1):
        normalized = {f: str(row[f]) for f in FIELDS}
        normalized["RowId"] = str(index)
        raw = json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode()
        stack_hash.update(len(raw).to_bytes(8, "big"))
        stack_hash.update(raw)
    manifest = result["manifest"]
    if (manifest.get("review_mode") != CONTRACT
            or manifest.get("source_stack_sha256") != stack_hash.hexdigest()
            or manifest.get("reviewed_group_count") != len(rows)
            or manifest.get("model_reviewed_group_count") != len(rows)
            or manifest.get("script_excluded_group_count") != 0
            or manifest.get("represented_row_count") != sum(r["TotalRows"] for r in rows)
            or manifest.get("suspicious_count") != len(result["suspicious_rows"])
            or manifest.get("potential_golden_count") != len(result["potential_golden_rows"])):
        raise RuntimeError("AI completion accounting does not match the residual source.")


def review_saved(stats_path, *, database, hunt_id, artifact, hunt_root,
                 execution=None, executor=None, maximum_evidence_tokens=6000, progress=None,
                 skip_ai=False, max_total_rows=None, started_at=None):
    """Run under hunt_lock, using only canonical state for completed AI reuse."""
    def emit(phase, status="running", **fields):
        if progress is not None:
            progress(dict(phase=phase, status=status, mode="autoruns", **fields))

    started_at = time.monotonic() if started_at is None else started_at
    if max_total_rows is not None and (type(max_total_rows) is not int or max_total_rows <= 0):
        raise ValueError("max_total_rows must be a positive integer.")
    emit("source_validation")
    stats, rows, cfg = load_source(stats_path, database=database, hunt_id=hunt_id, artifact=artifact,
                                  max_total_rows=max_total_rows)
    selection = dict(stage="before_golden", max_total_rows=max_total_rows,
        excluded_group_count=stats["counts"]["HighCountExcludedGroups"],
        excluded_row_count=stats["counts"]["HighCountExcludedRows"])
    previous = publication.saved_review(publication.load_state(hunt_root))
    prepared = dict(action="autoruns", status="prepared", ai_review_status="skipped" if skip_ai else "pending",
        review_complete=False, contract=CONTRACT, hunt_id=hunt_id, artifact=artifact,
        source_stream_complete=True, database_sha256=cfg["database_sha256"], counts=stats["counts"],
        context_queries=0, target_execution="not_assessed", max_example_hosts=stats["max_example_hosts"],
        source_selection=selection, elapsed_seconds=round(time.monotonic()-started_at, 3))
    published = publication.publish(hunt_root, stats_path, stats, prepared)
    emit("residual_csv_published", groups=len(rows), rows=stats["counts"]["ResidualRows"])
    if skip_ai:
        emit("prepared", status="complete", ai_review_status="skipped", groups=len(rows))
        return published
    model_rows = sorted(({f: r[f] for f in FIELDS} for r in rows), key=identity)
    hosts = {identity(r): r["ExampleHosts"] for r in rows}
    route = execution.route.identity() if execution is not None else "test-executor"
    encoding = token_budget.token_encoding_name()
    key = digest(dict(contract=CONTRACT, prompt=prompt(csv_text="", part_number=1,
        part_count=0, row_count=0), database=cfg["database_sha256"],
        matching_policy=cfg["matching_policy"], route=route, token_encoding=encoding, rows=model_rows,
        maximum_evidence_tokens=maximum_evidence_tokens, max_total_rows=max_total_rows))
    hit = previous.get("review_complete") is True and previous.get("cache_key") == key
    try:
        emit("classification_cache", status="hit" if hit else "miss", groups=len(rows))
        if hit:
            expanded = publication.expand_classifications(previous, rows)
            result = {kind: [{f: r[f] for f in (*FIELDS, "Reason", *(("Severity",) if kind == "suspicious_rows" else ()))}
                            for r in expanded[kind]]
                      for kind in ("suspicious_rows", "potential_golden_rows")}
            result["manifest"] = previous["manifest"]
        elif not rows:
            result = dict(suspicious_rows=[], potential_golden_rows=[], manifest=dict(
                review_mode=CONTRACT, source_stack_sha256=hashlib.sha256(b"").hexdigest(),
                reviewed_group_count=0, model_reviewed_group_count=0,
                script_excluded_group_count=0, represented_row_count=0,
                suspicious_count=0, potential_golden_count=0))
        else:
            emit("ai_review", groups=len(rows), rows=stats["counts"]["ResidualRows"])
            result = asyncio.run(ai.classify_streaming_rows_async(iter(model_rows), workdir=Path(stats_path).parent,
                execution=execution, executor=executor, maximum_evidence_tokens=maximum_evidence_tokens,
                review_mode=CONTRACT, dedup_contract=True, prompt_builder=prompt, token_encoding=encoding))
        validate_result(result, rows)
        report = dict(prepared, status="complete", ai_review_status="complete", review_complete=True,
            cache_hit=bool(hit), manifest=result["manifest"],
            elapsed_seconds=round(time.monotonic()-started_at, 3),
            **{kind: [{**r, "IdentityId": digest(identity(r)),
                **({"ExampleHosts": hosts[identity(r)]} if kind == "suspicious_rows" else {})}
                for r in sorted(result[kind], key=identity)]
                for kind in ("suspicious_rows", "potential_golden_rows")})
        emit("reporting", groups=len(rows), rows=stats["counts"]["ResidualRows"])
        return publication.publish(hunt_root, stats_path, stats, report, cache_key=key)
    except BaseException:
        publication.publish(hunt_root, stats_path, stats,
                            dict(prepared, status="failed", ai_review_status="failed"))
        raise
