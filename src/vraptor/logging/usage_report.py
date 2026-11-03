"""Read-only reconciliation of retained vraptor token and progress records."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path

from vraptor.logging import operations
from vraptor.logging.command import LINE_FIELDS_RE, _line_fields
from vraptor.logging.token_usage import LOG_FILENAME, RETRY_FIELDS, TOKEN_FIELDS


def _counts(record: dict) -> dict:
    counts = {key: record.get(key) for key in TOKEN_FIELDS}
    for value in counts.values():
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("invalid_token_counter")
    if (all(counts[key] is not None for key in TOKEN_FIELDS[:3])
            and counts["input_tokens"] + counts["output_tokens"] != counts["total_tokens"]):
        raise ValueError("inconsistent_token_total")
    if (counts["cached_input_tokens"] is not None and counts["input_tokens"] is not None
            and counts["cached_input_tokens"] > counts["input_tokens"]):
        raise ValueError("invalid_cached_input")
    return counts


def _total(records: list[dict]) -> dict:
    return {key: sum(record.get(key) or 0 for record in records) for key in TOKEN_FIELDS}


def _read(path: Path) -> list[str]:
    """Bound reads and reject symlinks, partial writes and concurrent changes."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise ValueError("unsafe_log_file")
        if before.st_size > operations.MAX_FILE_BYTES:
            raise ValueError("log_size_limit")
        data = handle.read(operations.MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    current = path.lstat()
    def identity(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError("log_changed_during_read")
    if data and not data.endswith(b"\n"):
        raise ValueError("incomplete_log_line")
    return data.decode("utf-8").splitlines()


def summarize(directory: Path, *, ledger_only: bool = False) -> dict:
    """Use each operation summary once; recover unsummarized progress requests."""
    buckets: dict[str, dict] = {}
    issues: list[dict] = []
    files: list[str] = []
    request_owners: dict[str, str] = {}
    started: set[tuple] = set()
    completed: set[tuple] = set()
    ledger_requests = progress_added = 0

    def issue(code: str, file: str = "", line: int = 0, operation: str = "") -> None:
        issues.append({"code": code, "file": file, "line": line, "operation": operation})

    names = [LOG_FILENAME] + ([] if ledger_only else [operations.LOG_FILENAME])
    for name in names:
        for index in range(operations.MAX_LOG_FILES - 1, -1, -1):
            path = directory / (f"{name}.{index}" if index else name)
            try:
                lines = _read(path)
            except FileNotFoundError:
                if path.is_symlink():
                    issue("unsafe_log_file", path.name)
                continue
            except (OSError, ValueError) as exc:
                issue(type(exc).__name__ if isinstance(exc, OSError) else str(exc), path.name)
                continue
            files.append(path.name)
            for number, line in enumerate(lines, 1):
                op = ""
                try:
                    if name == LOG_FILENAME:
                        row = json.loads(line)
                        if not isinstance(row, dict) or row.get("schema_version") != 1:
                            raise ValueError("unsupported_usage_record")
                        event = row.get("event")
                        if event not in {"operation_started", "request_usage", "operation_summary"}:
                            raise ValueError("unsupported_usage_event")
                    else:
                        match = LINE_FIELDS_RE.match(line)
                        if not match:
                            continue
                        message = line[match.end():].partition(" | ")[0]
                        fields = _line_fields(line)
                        task = (match["operation"], fields.get("task_id"), fields.get("attempt"))
                        if message == "Model request started":
                            started.add(task)
                        if message != "Model request completed":
                            continue
                        completed.add(task)
                        if not fields.get("request_id"):
                            raise ValueError("progress_request_without_identity")
                        row = {key: int(fields[key]) if key in fields else None for key in TOKEN_FIELDS}
                        row.update(operation_id=match["operation"], timestamp=match["timestamp"],
                                   request_id=fields["request_id"], usage_status="reported")
                        event = "request_usage"
                    op = row.get("operation_id", "")
                    if not isinstance(op, str) or not operations.OPERATION_ID_RE.fullmatch(op):
                        op = ""
                        raise ValueError("invalid_operation_identity")
                    if not isinstance(row.get("timestamp"), str):
                        raise TypeError("invalid_timestamp")
                    timestamp = datetime.fromisoformat(row["timestamp"])
                    if timestamp.tzinfo is None:
                        raise ValueError("timestamp_without_timezone")
                    bucket = buckets.setdefault(op, {"requests": {}, "summary": None, "timestamp": timestamp,
                                                      "conflict": False, "progress_added": 0, "started": False})
                    bucket["timestamp"] = max(bucket["timestamp"], timestamp)
                    if event == "operation_started":
                        bucket["started"] = True
                        continue
                    counts = _counts(row)
                    if event == "operation_summary":
                        attempts = row.get("attempts")
                        if (type(attempts) is not int or attempts < 0 or any(v is None for v in counts.values())
                                or attempts == 0 and any(counts.values())):
                            raise ValueError("invalid_operation_summary")
                        retries = {key: row.get(key) for key in RETRY_FIELDS}
                        if any(v is not None and (type(v) is not int or not 0 <= v <= attempts)
                               for v in retries.values()):
                            raise ValueError("invalid_retry_counter")
                        summary = {**counts, "attempts": attempts,
                                   **retries,
                                   "status": row.get("status") if row.get("status") in {
                                       "complete", "failed", "interrupted", "cancelled"} else "unknown",
                                   "usage_complete": row.get("usage_complete") is True,
                                   "log_complete": row.get("log_complete") is True}
                        if bucket["summary"] is not None and bucket["summary"] != summary:
                            bucket["conflict"] = True
                            issue("conflicting_operation_summaries", path.name, number, op)
                        bucket["summary"] = summary
                        continue
                    request = row.get("request_id")
                    if not request:
                        invocation, attempt = row.get("invocation_id"), row.get("attempt")
                        if not isinstance(invocation, str) or not invocation or type(attempt) is not int or attempt < 1:
                            raise ValueError("request_without_identity")
                        request = (invocation, attempt)
                    elif not isinstance(request, str):
                        raise ValueError("invalid_request_identity")
                    else:
                        owner = request_owners.setdefault(request, op)
                        if owner != op:
                            bucket["conflict"] = buckets[owner]["conflict"] = True
                            issue("request_identity_in_multiple_operations", path.name, number, op)
                    existing = bucket["requests"].get(request)
                    if existing is not None:
                        if existing != counts:
                            bucket["conflict"] = True
                            issue("conflicting_request_counters", path.name, number, op)
                        continue
                    bucket["requests"][request] = counts
                    if name == LOG_FILENAME:
                        ledger_requests += 1
                    else:
                        progress_added += 1
                        bucket["progress_added"] += 1
                    if row.get("usage_status") != "reported" or any(v is None for v in counts.values()):
                        issue("partial_or_unavailable_usage", path.name, number, op)
                except (ValueError, TypeError, KeyError) as exc:
                    code = str(exc) if type(exc) is ValueError and str(exc).isidentifier() else "invalid_usage_record"
                    issue(code, path.name, number, op)
                    if op in buckets:
                        buckets[op]["conflict"] = True

    for op in sorted({task[0] for task in started - completed}):
        issue("progress_requests_without_terminal_usage", operation=op)
    result = []
    for op, bucket in sorted(buckets.items(), key=lambda pair: pair[1]["timestamp"]):
        observed = _total(list(bucket["requests"].values()))
        summary = bucket["summary"]
        n = len(bucket["requests"])
        if summary:
            if (n > summary["attempts"] or any(observed[k] > summary[k] for k in TOKEN_FIELDS)
                    or (n == summary["attempts"] and any(observed[k] != summary[k] for k in TOKEN_FIELDS))):
                bucket["conflict"] = True
                issue("summary_request_mismatch", operation=op)
            if not summary["usage_complete"] or not summary["log_complete"]:
                issue("incomplete_operation_summary", operation=op)
        else:
            issue("operation_without_terminal_summary" if bucket["started"] else "operation_summary_unavailable",
                  operation=op)
        if bucket["conflict"]:
            issue("operation_excluded_due_to_conflict", operation=op)
            continue
        result.append({"operation_id": op, "timestamp": bucket["timestamp"].isoformat(),
                       "status": summary["status"] if summary else "unfinished" if bucket["started"] else "unknown",
                       "operation_complete": summary is not None,
                       "usage_complete": bool(summary and summary["usage_complete"]),
                       "log_complete": bool(summary and summary["log_complete"]),
                       **{key: summary[key] if summary else None for key in RETRY_FIELDS},
                       "requests": summary["attempts"] if summary else n,
                       "basis": "operation_summary" if summary else "request_records",
                       "progress_requests_added": bucket["progress_added"],
                       "requests_covered_only_by_summary": max(0, summary["attempts"] - n) if summary else 0,
                       **({k: summary[k] for k in TOKEN_FIELDS} if summary else observed)})
    if not result:
        issue("no_usage_records")
    return {"schema_version": 1, "scope": "retained_vraptor_usage", "lifetime_complete": False,
            "codex_session_usage_included": False, "totals": _total(result),
            "requests": sum(r["requests"] for r in result), "operation_count": len(result),
            "retry_totals": {key: sum(r[key] for r in result) if result and all(r[key] is not None for r in result)
                             else None for key in RETRY_FIELDS},
            "latest_operation": result[-1] if result else None, "operations": result,
            "coverage": {"files": files, "ledger_requests": ledger_requests,
                         "progress_requests_added": progress_added, "issues": issues,
                         "retained_records_consistent": not issues,
                         "retention_files_per_log": operations.MAX_LOG_FILES,
                         "retention_bytes_per_file": operations.MAX_FILE_BYTES}}


def render(report: dict) -> str:
    totals, latest = report["totals"], report["latest_operation"]
    lines = ["Vraptor AI usage (retained logs; Codex conversation excluded)",
             f"Retained total: {totals['total_tokens']:,} known tokens across {report['requests']} requests / {report['operation_count']} operations",
             f"Input: {totals['input_tokens']:,}; cached input (included): {totals['cached_input_tokens']:,}; output: {totals['output_tokens']:,}"]
    if latest:
        lines.append(f"Latest operation: {latest['total_tokens']:,} known tokens ({latest['operation_id']}; {latest['status']})")
    retries = report["retry_totals"]
    if all(value is not None for value in retries.values()):
        lines.append(f"Retry requests: {retries['retry_attempts']}; transport retries: {retries['transport_retry_attempts']}; correction attempts: {retries['correction_attempts']}")
    lines.append(f"Additional progress-log requests: {report['coverage']['progress_requests_added']}")
    lines.append("Totals count operation summaries OR request records, never both. Not a lifetime or billed-cost total.")
    for code in sorted({i["code"] for i in report["coverage"]["issues"]}):
        lines.append(f"Coverage warning: {code}")
    return "\n".join(lines)
