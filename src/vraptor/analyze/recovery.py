"""Reference-only accepted chunk checkpoints and bounded failure diagnostics."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from vraptor.common import atomic_io

VALIDATION_MESSAGES = frozenset(
    {
        "final review requires one DISPOSITIONS section before END",
        "final review disposition record is invalid",
        "final review candidate is unknown or duplicated",
        "final review disposition or rationale is invalid",
        "final review finding mapping disagrees with disposition",
        "final review cannot declare no candidates alongside dispositions",
        "final review supported candidate must cite its mapped finding evidence",
        "final review contains an unaccounted output finding",
        "final review finding uses evidence from an unsupported candidate",
        "synthesis story content appears before ANSWER",
        "synthesis story is missing a required section",
        "synthesis story ANSWER is required",
        "synthesis FINDING id is invalid or duplicated",
        "synthesis FINDING confidence or text is invalid",
        "synthesis FINDING tactics are invalid",
        "synthesis EVIDENCE references an unknown finding",
        "synthesis EVIDENCE is not present in accepted worker results",
    }
)


def validation_defects(error: Exception) -> list[dict]:
    defects = list(getattr(error, "diagnostics", []) or [])
    if defects:
        return defects
    message = str(error)
    return [
        {
            "code": "invalid_output_contract",
            "message": message
            if message in VALIDATION_MESSAGES
            else "Response must satisfy the required sections, record grammar, references and final END marker.",
        }
    ]


def fingerprint(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode()
    ).hexdigest()


def reference_only(value: Any) -> Any:
    if isinstance(value, list):
        return [reference_only(item) for item in value]
    if isinstance(value, dict):
        return {
            key: reference_only(item)
            for key, item in value.items()
            if key not in {"fields", "_full_fields", "source", "_origin"}
        }
    return value


def worker_text(worker: dict) -> str:
    """Serialize accepted decisions for revalidation against freshly queried rows."""
    lines = ["RESULT\t" + worker["result"]]
    for finding in worker.get("findings", []):
        lines.append(
            "\t".join(
                [
                    "FINDING",
                    finding["id"],
                    finding["confidence"],
                    ",".join(finding["domains"]),
                    finding["summary"],
                ]
            )
        )
        lines.extend(
            f"EVIDENCE\t{finding['id']}\t{row['ref']}" for row in finding["rows"]
        )
    for row in worker.get("relevant_context", []):
        lines.append(
            "\t".join(
                [
                    "CONTEXT",
                    row.get("finding_id") or "-",
                    row["ref"],
                    row["context_type"],
                    row["summary"],
                ]
            )
        )
    for row in worker.get("uplift_candidates", []):
        lines.append("\t".join(["UPLIFT", row["ref"], row["scope"], row["summary"]]))
    for key, tag in (("limitations", "LIMITATION"), ("bounded_follow_up", "FOLLOW_UP")):
        lines.extend(tag + "\t" + value for value in worker.get(key, []))
    return "\n".join([*lines, "END"])


class ChunkRecovery:
    """Keep only the current artifact generation; source/prompt changes invalidate it."""

    def __init__(self, path: Path, identity: str, *, reuse: bool):
        self.path = path
        self.payload = {"schema_version": 1, "identity": identity, "accepted": {}}
        if reuse and path.is_file() and not path.is_symlink():
            try:
                saved = json.loads(path.read_text())
                if (
                    saved.get("schema_version") == 1
                    and saved.get("identity") == identity
                    and isinstance(saved.get("accepted"), dict)
                ):
                    self.payload = saved
            except (OSError, ValueError, AttributeError):
                pass

    def get(self, task: Any) -> dict | None:
        item = self.payload["accepted"].get(task.task_id, {})
        if (
            isinstance(item, dict)
            and item.get("input_sha256") == fingerprint(task.prompt)
            and isinstance(item.get("result"), dict)
            and item.get("result_sha256") == fingerprint(item["result"])
        ):
            return copy.deepcopy(item["result"])
        return None

    def accept(self, task: Any, result: dict) -> None:
        compact = reference_only(result)
        self.payload["accepted"][task.task_id] = {
            "input_sha256": fingerprint(task.prompt),
            "result": compact,
            "result_sha256": fingerprint(compact),
        }
        atomic_io.write_json_atomic(self.path, self.payload, sort_keys=True)


def task_diagnostics(record: dict) -> dict:
    """No provider bodies, model text, source values, or arbitrary error messages."""
    attempts = []
    for item in record.get("attempt_history", []):
        run = item.get("run") or {}
        defects = []
        for raw in item.get("diagnostics") or []:
            defect = {}
            if raw.get("message") in VALIDATION_MESSAGES:
                defect["message"] = raw["message"]
            for key in (
                "code",
                "record",
                "ref",
                "candidate_id",
                "finding_id",
                "line",
                "allowed",
                "received", "reason",
            ):
                value = raw.get(key)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    or isinstance(value, str)
                    and re.fullmatch(r"[A-Za-z0-9_. :+-]{1,100}", value)
                ):
                    defect[key] = value
                elif key in {"allowed", "received"} and isinstance(value, list):
                    defect[key] = [
                        v
                        for v in value[:50]
                        if isinstance(v, str)
                        and re.fullmatch(r"[A-Za-z0-9_. :+-]{1,100}", v)
                    ]
            if defect:
                defects.append(defect)
        provider_status = str(run.get("status") or "")
        category = (
            "validation_failed"
            if item.get("status") != "accepted" and provider_status == "succeeded"
            else str(
                run.get("error_classification") or provider_status or "analysis_error"
            )
        )
        if not re.fullmatch(r"[a-z_]{1,80}", category):
            category = "analysis_error"
        messages = {
            "validation_failed": "The provider returned text, but it failed the analysis output contract. Inspect defect codes, record types, line numbers and allowed references.",
            "timeout": "The configured provider deadline expired. Inspect provider health and input size before changing the timeout.",
            "rate_limit": "The provider rate limit was exhausted. Inspect its quota and the configured concurrency.",
            "authentication": "Provider authentication failed. Check credential availability without logging credentials.",
            "output_too_large": "The response exceeded the output budget. Reduce the requested detail or adjust the model-compatible output budget.",
            "output_limit_reached": "The provider stopped at the output-token limit. Reduce the requested detail or increase the model-compatible output budget.",
            "cancelled": "The analysis was cancelled. Confirm the stop reason before resuming the same request.",
            "succeeded": "The response passed validation.",
        }
        attempts.append(
            {
                "attempt": item.get("attempt"),
                "status": item.get("status"),
                "category": category,
                "defects": defects,
                "message": messages.get(
                    category,
                    "Inspect provider status and configured capabilities. Use metadata-only --debug for further detail.",
                ),
                "provider_attempts": run.get("attempts", 0),
                "elapsed_seconds": run.get("elapsed_seconds", 0),
                "response_sha256": hashlib.sha256(
                    str(run.get("output") or "").encode()
                ).hexdigest(),
            }
        )
    return {
        "task_id": record.get("task_id"),
        "stage": record.get("stage"),
        "status": record.get("status"),
        "attempts": record.get("attempts", 0),
        "coverage": record.get("coverage", {}),
        "attempt_history": attempts,
        "action": (
            "Correct the cited validation defects or check provider configuration; then use --retry-failed with the same request and question."
            if record.get("status") == "failed"
            else "none"
        ),
    }
