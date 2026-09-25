"""Canonical Autoruns outputs and state-backed classification reuse."""

from __future__ import annotations

import copy
import csv
import fcntl
import hashlib
import io
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

from vraptor.common import atomic_io

from vraptor.analyze import flow as flow_analysis
from vraptor.hunt import live as live_hunt_analysis
from vraptor.artifacts import persistence as persistence_policy
from vraptor.analyze import coordinator

CANDIDATE_FIELDS = (
    "Category",
    "ImagePath",
    "LaunchString",
    "Signer",
    "TotalRows",
    "Reason",
    "IdentityId",
)


@contextmanager
def hunt_lock(hunt_root):
    """Serialize Autoruns writers using the directory inode, without a lock file."""
    hunt_root = Path(hunt_root)
    hunt_root.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(hunt_root, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                "Another Autoruns publisher is using this hunt."
            ) from exc
        yield
    finally:
        os.close(descriptor)


def load_state(hunt_root):
    path = live_hunt_analysis.analysis_paths(Path(hunt_root))["state"]
    for candidate in (
        Path(hunt_root),
        path.parent,
        path,
        Path(hunt_root) / "analysis-hunt.md",
    ):
        if candidate.is_symlink():
            raise RuntimeError("Refusing symlink in canonical Autoruns output paths.")
    if not path.exists():
        return flow_analysis.initial_state(
            scope_type="hunt", scope_id=Path(hunt_root).name, analysis_id=""
        )
    state = json.loads(path.read_text())
    if (
        state.get("schema_version") != flow_analysis.SCHEMA_VERSION
        or state.get("scope_type") != "hunt"
        or state.get("scope_id") != Path(hunt_root).name
    ):
        raise RuntimeError(
            "Existing hunt state has an incompatible schema or scope; preserve it for explicit migration."
        )
    if (state.get("active_analysis") or {}).get("status") == "running":
        raise RuntimeError(
            "An active hunt analysis must finish before Autoruns publication."
        )
    return state


def saved_review(state):
    return (state.get("specialized_analysis") or {}).get("autoruns_review") or {}


def compact_classifications(report):
    return {
        kind: [
            {
                key: row[key]
                for key in ("IdentityId", "Reason", "Severity")
                if key in row
            }
            for row in report.get(kind, [])
        ]
        for kind in ("suspicious_rows", "potential_golden_rows")
    }


def expand_classifications(record, rows):
    from vraptor.autoruns import dedup_ai as dedup

    expected_hash = hashlib.sha256(
        json.dumps(record["classifications"], sort_keys=True).encode()
    ).hexdigest()
    if expected_hash != record.get("classification_sha256"):
        raise RuntimeError("Classification cache integrity check failed.")
    by_id = {dedup.digest(dedup.identity(row)): row for row in rows}
    result = {}
    seen = set()
    for kind in ("suspicious_rows", "potential_golden_rows"):
        result[kind] = []
        for selected in record.get("classifications", {}).get(kind, []):
            identity_id = selected["IdentityId"]
            if identity_id not in by_id or identity_id in seen:
                raise RuntimeError(
                    "Saved classification is not unique in the current residual CSV."
                )
            seen.add(identity_id)
            row = by_id[identity_id]
            result[kind].append(
                {
                    **{f: row[f] for f in dedup.FIELDS},
                    **selected,
                    **(
                        {"ExampleHosts": row["ExampleHosts"]}
                        if kind == "suspicious_rows"
                        else {}
                    ),
                }
            )
    return result


def read_review_rows(path, record):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != record["review_csv_sha256"]:
        raise RuntimeError(
            "Autoruns CSV and canonical state belong to different publications."
        )
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
    for row in rows:
        row["TotalRows"] = int(row["TotalRows"])
        row["ExampleHosts"] = json.loads(row["ExampleHosts"])
    return rows


def render_summary(record, results):
    """Summarize completed work with bounded, terminal-safe finding examples."""
    counts = record["counts"]
    selection = record.get("ai_selection") or {}
    source_selection = record.get("source_selection") or {}
    complete = record["review_complete"]
    suspicious = results.get("suspicious_rows", [])
    candidates = results.get("potential_golden_rows", [])
    lines = [
        f"Source records: {counts['SourceRows']:,}; GoldenDB matched: {counts['MatchedRows']:,}.",
        f"Residual identities: {counts['GroupCount']:,}, representing {counts['ResidualRows']:,} records.",
        f"AI-reviewed identities: {record.get('manifest', {}).get('model_reviewed_group_count', 0):,}; result review: {record['result_review']}.",
    ]
    if source_selection.get("max_total_rows") is not None:
        golden_first = source_selection.get("stage") == "after_golden"
        stage = "after" if golden_first else "before"
        outcome = "GoldenDB non-matches" if golden_first else "GoldenDB not evaluated"
        lines.append(f"Stack threshold: TotalRows > {source_selection['max_total_rows']:,}; "
                     f"excluded {stage} GoldenDB: {source_selection['excluded_group_count']:,} identities / "
                     f"{source_selection['excluded_row_count']:,} records "
                     f"({outcome}; absent from review CSV and AI review).")
    elif selection.get("max_total_rows") is not None:
        lines.append(f"Stack threshold: TotalRows > {selection['max_total_rows']:,}; "
                     f"excluded from AI: {selection['excluded_group_count']:,} identities / "
                     f"{selection['excluded_row_count']:,} records (retained in review CSV).")
    if record.get("elapsed_seconds") is not None:
        lines.append(f"Elapsed: {record['elapsed_seconds']:,.1f}s; classification cache: "
                     + ("hit" if record.get("cache_hit") else "not reused"))
    if complete:
        severity = ", ".join(f"{sum(r['Severity'] == level for r in suspicious)} {level}"
                             for level in ("critical", "high", "medium", "low"))
        lines.append(f"Suspicious identities: {len(suspicious):,} ({severity}).")
        lines.append(f"GoldenDB prospects: {len(candidates):,} (require review).")
        ordered = sorted(suspicious, key=lambda r: (
            ("critical", "high", "medium", "low").index(r["Severity"]),
            -r["TotalRows"], r["Category"], r["ImagePath"], r["LaunchString"]))
        if ordered:
            lines.append("Representative findings (up to 5):")
        for row in ordered[:5]:
            text = f"{row['Severity'].upper()} | {row['Category']} | {row['ImagePath']} | {row['Reason']}"
            text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
            lines.append("- " + (text[:497] + "..." if len(text) > 500 else text))
    else:
        lines.append("AI review is incomplete or skipped; no clean conclusion is available.")
    if selection.get("excluded_group_count") or source_selection.get("excluded_group_count"):
        lines.append("High-count entries were not assessed by AI; frequency is not a benign classification.")
    lines.append("Findings are review leads; presence and signer labels do not prove execution or compromise.")
    return "\n".join(lines)


def render_section(record, csv_path):
    rows = read_review_rows(csv_path, record)
    results = expand_classifications(record, rows)
    lines = [
        "## Autoruns review",
        "",
        f"- AI review: `{record['ai_review_status']}`; result review: `{record['result_review']}`.",
        "- Target execution: `not_assessed`.",
        f"- Residual identities: {record['counts']['GroupCount']:,}; represented residual records: {record['counts']['ResidualRows']:,}.",
        "- Review CSV: `analysis/autoruns_review.csv`.",
        "- Candidate CSV: `analysis/autoruns_potential_golden.csv` (proposals, not approved GoldenDB rules).",
        "- TotalRows counts source records; ExampleHosts contains bounded samples.",
        "- Normalized paths and source signer labels do not prove execution or independently verify signatures.",
        "",
    ]
    lines += ["### Summary", "", render_summary(record, results), ""]
    if not record["review_complete"]:
        lines += [
            "AI review is incomplete. Empty candidate output is not a clean finding.",
            "",
        ]
    for kind, selected in results.items():
        lines += ["### " + kind.replace("_", " "), ""]
        for row in selected:
            lines += [
                "````json",
                json.dumps(row, ensure_ascii=False, indent=2).replace("`", "\\u0060"),
                "````",
                "",
            ]
        if not selected:
            lines += ["None recorded.", ""]
    return "\n".join(lines)


def publish(hunt_root, stats_path, stats, report, *, cache_key=None):
    """Publish under hunt_lock; state hashes detect interrupted multi-file writes.

    Each replacement is atomic, with state committed last. Ordinary failures roll
    back the preceding files; abrupt process termination fails hash validation.
    """
    hunt_root = Path(hunt_root)
    paths = live_hunt_analysis.analysis_paths(hunt_root)
    state = load_state(hunt_root)
    if stats["hunt_id"] != hunt_root.name:
        raise RuntimeError("Source hunt does not match the output directory.")
    payload = Path(stats_path).with_name("review.csv").read_bytes().decode("utf-8")
    if (
        stats.get("stream_complete") is not True
        or stats.get("status") != "complete"
        or hashlib.sha256(payload.encode()).hexdigest() != stats["review_csv_sha256"]
    ):
        raise RuntimeError("Incomplete or changed source cannot be published.")
    complete = report["status"] == "complete"
    record = {
        name: copy.deepcopy(stats[name])
        for name in (
            "hunt_id",
            "artifact",
            "counts",
            "max_example_hosts",
            "database_sha256",
            "query_environment_sha256",
            "review_csv_sha256",
            "vql_file",
        )
    }
    record.update(
        schema="autoruns-review-v4" if "source_selection" in report else "autoruns-review-v3",
        source_complete=True,
        content="count_filtered_residual_stacks" if "source_selection" in report else "complete_residual_stacks",
        contract=report["contract"],
        status=report["status"],
        ai_review_status=report.get("ai_review_status", "complete"),
        result_review=("partial" if (report.get("source_selection", {}).get("excluded_group_count")
            or report.get("ai_selection", {}).get("excluded_group_count")) else "complete") if complete else "not_reviewed",
        review_complete=complete,
        target_execution="not_assessed",
        updated_at=flow_analysis.now_utc(),
        classifications=compact_classifications(report),
        manifest=copy.deepcopy(report.get("manifest", {})),
        ai_selection=copy.deepcopy(report.get("ai_selection", {})),
        elapsed_seconds=report.get("elapsed_seconds"),
        cache_hit=bool(report.get("cache_hit")),
    )
    if "source_selection" in report:
        record.update(source_selection=copy.deepcopy(report["source_selection"]),
                      source_contract=stats["source_contract"], max_total_rows=stats["max_total_rows"])
    if cache_key and complete:
        record["cache_key"] = cache_key
    record["classification_sha256"] = hashlib.sha256(
        json.dumps(record["classifications"], sort_keys=True).encode()
    ).hexdigest()
    candidate = io.StringIO(newline="")
    writer = csv.DictWriter(candidate, fieldnames=CANDIDATE_FIELDS)
    writer.writeheader()
    writer.writerows(report.get("potential_golden_rows", []))
    record["candidate_csv_sha256"] = hashlib.sha256(
        candidate.getvalue().encode()
    ).hexdigest()
    if not state.get("specialized_analysis"):
        state["specialized_analysis"] = live_hunt_analysis.initial_state(
            investigation_id=hunt_root.parent.parent.name,
            hunt_id=hunt_root.name,
            group="",
            hunt_state="unknown",
        )
    specialized = state["specialized_analysis"]
    specialized["analysis_version"] = live_hunt_analysis.ANALYSIS_VERSION
    specialized["updated_at"] = record["updated_at"]
    if not specialized.get("artifacts"):
        specialized.update(
            status=record["status"],
            result_review_coverage=record["result_review"],
            target_execution_coverage="not_assessed",
            coverage="partial",
        )
    specialized["autoruns_review"] = record
    if not state.get("checkpoint") and not state.get("runs"):
        state["analysis_method"] = "specialized"
        state["coverage"] = {
            "result_review": record["result_review"],
            "target_execution": "not_assessed",
            "overall": "partial",
        }
    state["updated_at"] = record["updated_at"]
    paths["root"].mkdir(parents=True, exist_ok=True)
    # Keep the source copy transient. Rendering uses it before any public writes.
    markdown = coordinator.render_canonical_hunt_report(
        hunt_root=hunt_root,
        question="Review Autoruns persistence",
        flow_state=state,
        specialized_state=specialized,
        autoruns_csv=Path(stats_path).with_name("review.csv"),
    )
    outputs = {
        paths["autoruns_review"]: payload,
        paths["autoruns_potential_golden"]: candidate.getvalue(),
        paths["analysis_memory"]: markdown,
        paths["state"]: json.dumps(state, ensure_ascii=False, indent=2) + "\n",
    }
    previous = {path: path.read_bytes() if path.exists() else None for path in outputs}
    written = []
    try:
        for path, text in outputs.items():
            atomic_io.write_text_atomic(path, text, newline="")
            written.append(path)
        for path in (
            paths["autoruns_review"],
            paths["autoruns_potential_golden"],
            paths["state"],
        ):
            persistence_policy.classify_analysis_file(
                path, analysis_root=paths["root"], source_ids=[f"hunt:{hunt_root.name}"]
            )
    except BaseException:
        for path in reversed(written):
            if previous[path] is None:
                path.unlink(missing_ok=True)
            else:
                atomic_io.write_text_atomic(
                    path, previous[path].decode("utf-8"), newline=""
                )
        raise
    return {
        **report,
        "result_review": record["result_review"],
        "canonical_analysis_written": True,
        "analysis_review_csv": str(paths["autoruns_review"]),
        "potential_golden_csv": str(paths["autoruns_potential_golden"]),
        "report_json": str(paths["state"]),
        "report_markdown": str(paths["analysis_memory"]),
        "report_file": str(paths["analysis_memory"]),
        "state_file": str(paths["state"]),
        "chat_summary": render_summary(record, report),
    }
