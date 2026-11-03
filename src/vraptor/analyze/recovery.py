"""Reference-only accepted chunk checkpoints and bounded failure diagnostics."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any

from vraptor.analyze import report_priority
from vraptor.common import atomic_io
from vraptor.common import clock

FAILED_CHUNK_ENTRY_LIMIT = 500
WAIVER_REASON_LIMIT = 500
_CHUNK_POSITION_KEYS = (
    "row_start", "row_end", "row_count", "task_chunk_index", "task_chunk_count",
    "ordinal", "input_tokens",
)
_IDENTITY_PATTERNS = {
    "artifact": r"[A-Za-z0-9_.:/ -]{1,200}",
    "flow_id": r"F\.[A-Za-z0-9]{1,64}",
    "hunt_id": r"H\.[A-Za-z0-9]{1,64}",
    "chunk_id": r"(?:[a-z]+(?:-[a-z]+)*-v[0-9]+-)?[0-9a-f]{16,64}",
}

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
        priority = report_priority.priority_metadata(finding)
        if priority["priority_rationale"]:
            lines.append(
                f"PRIORITY\t{finding['id']}\t{priority['report_priority']}\t"
                + priority["priority_rationale"]
            )
        elif priority["report_priority"] != "unranked":
            # Old saved explicit labels may lack a rationale. Preserve the label
            # without inventing an impact assessment during revalidation.
            lines.append(
                f"PRIORITY\t{finding['id']}\t{priority['report_priority']}\t"
                "Retained saved priority; original rationale unavailable."
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

    def mark_repaired(self, task: Any, repair: Any) -> None:
        """Keep the repair label with the checkpoint so a resumed run still reports it."""
        item = self.payload["accepted"].get(task.task_id)
        if isinstance(item, dict) and item.get("input_sha256") == fingerprint(task.prompt):
            item["repair"] = safe_repair(repair)
            atomic_io.write_json_atomic(self.path, self.payload, sort_keys=True)

    def repair(self, task: Any) -> dict:
        item = self.payload["accepted"].get(task.task_id)
        if isinstance(item, dict) and item.get("input_sha256") == fingerprint(task.prompt):
            return safe_repair(item.get("repair"))
        return {}


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _safe_timestamp(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ) is not None


def _safe_inputs(value: Any) -> dict:
    """Locate a chunk's inputs by position, reference and hash, never by value."""
    if not isinstance(value, dict):
        return {}
    inputs = {key: value[key] for key in _CHUNK_POSITION_KEYS if _non_negative_int(value.get(key))}
    for key in ("first_reference", "last_reference"):
        if _safe_diagnostic_value("ref", value.get(key)):
            inputs[key] = value[key]
    if isinstance(value.get("input_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", value["input_sha256"]):
        inputs["input_sha256"] = value["input_sha256"]
    if isinstance(value.get("flow_id"), str) and re.fullmatch(_IDENTITY_PATTERNS["flow_id"], value["flow_id"]):
        inputs["flow_id"] = value["flow_id"]
    return inputs


def _safe_diagnostic_value(key: str, value: Any) -> bool:
    """Retain protocol vocabulary and references, never arbitrary model identifiers."""
    from vraptor.analyze.host import ATTACK_TACTICS

    if key == "line":
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if not isinstance(value, str) or len(value) > 100:
        return False
    if key in {"code", "reason"}:
        return re.fullmatch(r"[a-z][a-z0-9_]{0,99}", value) is not None
    records = {
        "RESULT", "FINDING", "FINDINGS", "PRIORITY", "EVIDENCE", "CONTEXT",
        "RELEVANT_CONTEXT", "LIMITATION", "LIMITATIONS", "FOLLOW_UP", "UPLIFT",
        "DISPOSITION", "DISPOSITIONS", "ANSWER", "TEXT", "END",
    }
    if key == "record":
        return value in records
    if key == "ref":
        return re.fullmatch(r"S[0-9]{1,20}-R[0-9]{1,20}", value) is not None
    identifier = re.fullmatch(r"(?:A[0-9]{1,20}:)?[FM][0-9]{1,20}", value)
    if key in {"finding_id", "candidate_id"}:
        return identifier is not None
    return bool(
        identifier
        or re.fullmatch(r"S[0-9]{1,20}-R[0-9]{1,20}", value)
        or value in records
        or value in ATTACK_TACTICS
        or value in report_priority.RETAINED_PRIORITIES
    )


def safe_defects(raw_defects: list) -> list[dict]:
    """Project validator diagnostics onto protocol vocabulary; model-supplied values are dropped."""
    defects = []
    for raw in raw_defects[:50]:
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
            "received", "missing", "reason",
        ):
            value = raw.get(key)
            if _safe_diagnostic_value(key, value):
                defect[key] = value
            elif key in {"allowed", "received", "missing"} and isinstance(value, list):
                defect[key] = [
                    v
                    for v in value[:50]
                    if _safe_diagnostic_value(key, v)
                ]
        if defect:
            defects.append(defect)
    return defects


_REPAIR_OUTCOMES = frozenset({"pending", "repaired", "failed", "unrepairable", "skipped"})


def safe_repair(value: Any) -> dict:
    """Keep a repair record's outcome, cause codes, locations and counts only."""
    if not isinstance(value, dict) or value.get("outcome") not in _REPAIR_OUTCOMES:
        return {}
    result: dict[str, Any] = {"outcome": value["outcome"]}
    for key in ("attempt", "findings_before", "findings_after"):
        if _non_negative_int(value.get(key)):
            result[key] = value[key]
    for key in ("reason", "unrepairable_cause", "category"):
        if _safe_diagnostic_value("code", value.get(key)):
            result[key] = value[key]
    if value.get("diagnosis_status") in {"valid", "invalid", "absent"}:
        result["diagnosis_status"] = value["diagnosis_status"]
    if isinstance(value.get("explanation_sha256"), str) and re.fullmatch(
        r"[0-9a-f]{64}", value["explanation_sha256"]
    ):
        result["explanation_sha256"] = value["explanation_sha256"]
    causes = []
    for item in list(value.get("causes") or [])[:5]:
        if not isinstance(item, dict) or not _safe_diagnostic_value("code", item.get("cause")):
            continue
        location = str(item.get("location") or "-")
        if not (location == "-" or re.fullmatch(r"L[0-9]{1,6}", location)
                or _safe_diagnostic_value("ref", location)):
            location = "-"
        causes.append({"cause": item["cause"], "location": location})
    if causes:
        result["causes"] = causes
    return result


def task_diagnostics(record: dict) -> dict:
    """No provider bodies, model text, source values, or arbitrary error messages."""
    attempts = []
    history = list(record.get("attempt_history", []))
    for item in history[:7]:
        run = item.get("run") or {}
        raw_defects = list(item.get("diagnostics") or [])
        defects = safe_defects(raw_defects)
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
            "context_window_exceeded": "Input plus output reached the model context window. Lower the input or output budget; the provider counts more tokens than the local estimate.",
            "refusal": "The model declined the request. Review the submitted evidence; repeating the same request is unlikely to change the result.",
            "input_limit": "The rendered prompt exceeds the input budget. Lower max_analysis_item_tokens or raise the model-compatible input budget.",
            "cancelled": "The analysis was cancelled. Confirm the stop reason before resuming the same request.",
            "succeeded": "The response passed validation.",
        }
        attempts.append(
            {
                "attempt": item.get("attempt"),
                "status": item.get("status"),
                **({"repair": True} if item.get("repair") else {}),
                "category": category,
                "defects": defects,
                "message": messages.get(
                    category,
                    "Inspect provider status and configured capabilities. Use metadata-only --debug for further detail.",
                ),
                "provider_attempts": run.get("attempt_count", run.get("attempts", 0)),
                "elapsed_seconds": run.get("elapsed_seconds", 0),
                **{key: item[key] for key in ("started_at", "completed_at") if _safe_timestamp(item.get(key))},
                "response_sha256": hashlib.sha256(
                    str(run.get("output") or "").encode()
                ).hexdigest(),
                **({"omitted_defect_count": len(raw_defects) - 50} if len(raw_defects) > 50 else {}),
            }
        )
    inputs = _safe_inputs(record.get("inputs"))
    repair = safe_repair(record.get("repair"))
    return {
        "task_id": record.get("task_id"),
        "stage": record.get("stage"),
        "status": record.get("status"),
        "attempts": record.get("attempts", 0),
        "coverage": record.get("coverage", {}),
        **({"inputs": inputs} if inputs else {}),
        "attempt_history": attempts,
        **({"repair": repair} if repair else {}),
        **({"omitted_attempt_count": len(history) - 7} if len(history) > 7 else {}),
        "action": (
            "Correct the cited validation defects or check provider configuration; then use --retry-failed with the same request and question."
            if record.get("status") == "failed"
            else "none"
        ),
    }


class FailedChunkLedger:
    """Durable, value-free review records for chunks that exhausted every attempt.

    Ordinary reruns keep entries; a later acceptance marks one resolved, a re-plan
    that drops the chunk marks it superseded, and only an explicit operator waiver
    marks one waived.
    """

    def __init__(self, path: Path, scope: dict[str, str]):
        self.path = path
        self.payload: dict[str, Any] = {
            "schema_version": 1,
            "retention": "value_free_failed_chunk_review",
            "scope": dict(scope),
            "chunks": {},
        }
        self._lock = threading.Lock()
        if path.is_file() and not path.is_symlink():
            try:
                saved = json.loads(path.read_text(encoding="utf-8"))
                if (
                    saved.get("schema_version") == 1
                    and saved.get("scope") == self.payload["scope"]
                    and isinstance(saved.get("chunks"), dict)
                ):
                    self.payload = saved
            except (OSError, ValueError, AttributeError):
                pass

    def entries(self, *statuses: str) -> dict[str, dict]:
        return {
            key: copy.deepcopy(entry)
            for key, entry in sorted(self.payload["chunks"].items())
            if not statuses or entry.get("status") in statuses
        }

    def find(self, value: str) -> str | None:
        """Resolve an operator-supplied key or unique task id to a recorded chunk."""
        chunks = self.payload["chunks"]
        if value in chunks:
            return value
        matches = [key for key, entry in chunks.items() if entry.get("task_id") == value]
        return matches[0] if len(matches) == 1 else None

    def record_failure(
        self,
        key: str,
        diagnostics: dict,
        *,
        identity: dict[str, str],
        budget: dict[str, int],
        next_steps: dict[str, str],
        evidence: dict | None = None,
    ) -> None:
        """Store one task_diagnostics() record; never pass a raw task record."""
        history = list(diagnostics.get("attempt_history") or [])
        # The failure is the last rejected answer; an optional repair call's own
        # category stays in the repair record.
        last = next(
            (dict(item) for item in reversed(history)
             if item.get("status") != "accepted" and not item.get("repair")),
            {},
        )
        repair = safe_repair(diagnostics.get("repair"))
        repair_call = next((item for item in reversed(history) if item.get("repair")), {})
        if repair and repair_call.get("status") != "accepted" and repair_call.get("category"):
            repair = safe_repair({**repair, "category": repair_call["category"]})
        with self._lock:
            prior = dict(self.payload["chunks"].get(key) or {})
            # Only a repair call's own result continues the pending record written
            # just before it; any other record is a new failure.
            same_event = (
                dict(prior.get("repair") or {}).get("outcome") == "pending"
                and repair.get("outcome") in {"failed", "unrepairable"}
            )
            now = clock.now_utc()
            failure_count = int(prior.get("failure_count") or 0) + (0 if same_event else 1)
            inputs = _safe_inputs(
                {**dict(diagnostics.get("coverage") or {}), **dict(diagnostics.get("inputs") or {})}
            )
            decision = dict(prior.get("decision") or {})
            if prior.get("status") == "waived" and decision.get("input_sha256") != inputs.get(
                "input_sha256"
            ):
                # A waived chunk is sent again only after its rendered input changed.
                decision["lapsed_at"] = now
            self.payload["chunks"][key] = {
                **{
                    name: value
                    for name, value in identity.items()
                    if name in _IDENTITY_PATTERNS
                    and re.fullmatch(_IDENTITY_PATTERNS[name], str(value))
                },
                "task_id": diagnostics.get("task_id"),
                "stage": diagnostics.get("stage"),
                "status": "failed",
                "attempts": diagnostics.get("attempts", 0),
                "budget": dict(budget),
                "inputs": inputs,
                "first_failed_at": prior.get("first_failed_at") or now,
                "last_failed_at": prior["last_failed_at"] if same_event else now,
                "failure_count": failure_count,
                "final": {
                    "category": last.get("category", "analysis_error"),
                    "defect_codes": sorted(
                        {
                            str(defect["code"])
                            for item in history
                            if not item.get("repair")
                            for defect in item.get("defects") or []
                            if defect.get("code")
                        }
                    ),
                    "message": last.get("message", ""),
                },
                "attempt_history": history,
                **({"repair": repair} if repair else {}),
                # An export stays referenced until a later one replaces it; ``failure``
                # names the failure_count it belongs to.
                "evidence": prior.get("evidence") if evidence is None else {**evidence, "failure": failure_count},
                "decision": decision or None,
                "next": dict(next_steps),
            }
            self._prune()
            self._save()

    def resolve(self, key: str, repair: dict | None = None, evidence: dict | None = None) -> None:
        """Mark a later acceptance; ``repair`` records an in-run AI repair."""
        with self._lock:
            entry = self.payload["chunks"].get(key)
            if entry and entry.get("status") != "resolved":
                entry["status"] = "resolved"
                entry["resolved_at"] = clock.now_utc()
                resolution = safe_repair(repair)
                entry["resolution"] = {"by": "repair", **resolution} if resolution else {"by": "acceptance"}
                if resolution:
                    entry["repair"] = resolution
                elif dict(entry.get("repair") or {}).get("outcome") == "pending":
                    entry.pop("repair")
                if evidence is not None:
                    entry["evidence"] = {**evidence, "failure": entry.get("failure_count", 0)}
                self._save()

    def supersede(self, artifact: str, current: set[str]) -> None:
        """Retire an artifact's open entries for chunks its current plan no longer has."""
        with self._lock:
            stale = [
                entry
                for key, entry in self.payload["chunks"].items()
                if entry.get("artifact") == artifact
                and key not in current
                and entry.get("status") in {"failed", "waived"}
            ]
            for entry in stale:
                entry["status"] = "superseded"
                entry["superseded_at"] = clock.now_utc()
            if stale:
                self._save()

    def waive(self, key: str, reason: str) -> None:
        reason = " ".join(str(reason or "").split())
        if not reason or len(reason) > WAIVER_REASON_LIMIT:
            raise ValueError(
                f"--waive-reason must be 1-{WAIVER_REASON_LIMIT} characters"
            )
        with self._lock:
            entry = self.payload["chunks"][key]
            if entry.get("status") != "failed":
                raise ValueError(
                    f"{key} is {entry.get('status')}; only failed chunks can be waived"
                )
            entry["status"] = "waived"
            entry["decision"] = {
                "action": "waived",
                "reason": reason,
                "decided_at": clock.now_utc(),
                "input_sha256": dict(entry.get("inputs") or {}).get("input_sha256", ""),
            }
            self._save()

    def waiver(self, key: str, input_sha256: str) -> str | None:
        """Return the waiver reason while the chunk's rendered input is unchanged."""
        entry = self.payload["chunks"].get(key) or {}
        decision = dict(entry.get("decision") or {})
        if entry.get("status") == "waived" and decision.get("input_sha256") == input_sha256:
            return str(decision.get("reason") or "")
        return None

    def revoke_waivers(self) -> None:
        with self._lock:
            for entry in self.payload["chunks"].values():
                if entry.get("status") == "waived":
                    entry["status"] = "failed"
                    entry["decision"] = {**dict(entry["decision"]), "revoked_at": clock.now_utc()}
            self._save()

    def _prune(self) -> None:
        chunks = self.payload["chunks"]
        excess = len(chunks) - FAILED_CHUNK_ENTRY_LIMIT
        if excess > 0:
            oldest_closed_first = sorted(
                chunks,
                key=lambda key: (
                    chunks[key].get("status") not in {"resolved", "superseded"},
                    str(chunks[key].get("last_failed_at") or ""),
                ),
            )
            for key in oldest_closed_first[:excess]:
                del chunks[key]
            self.payload["omitted_chunk_count"] = (
                int(self.payload.get("omitted_chunk_count") or 0) + excess
            )

    def _save(self) -> None:
        atomic_io.write_json_atomic(self.path, self.payload, sort_keys=True)


def failed_chunk_summary(key: str, entry: dict) -> dict:
    """One compact line of review context for results and chat summaries."""
    final = dict(entry.get("final") or {})
    inputs = dict(entry.get("inputs") or {})
    return {
        "key": key,
        "artifact": entry.get("artifact", ""),
        "status": entry.get("status", ""),
        "attempts": entry.get("attempts", 0),
        "category": final.get("category", "analysis_error"),
        "defect_codes": list(final.get("defect_codes") or [])[:10],
        **{
            name: inputs[name]
            for name in (
                "row_start", "row_end", "task_chunk_index", "task_chunk_count",
                "first_reference", "last_reference",
            )
            if name in inputs
        },
        **(
            {"reason": dict(entry.get("decision") or {}).get("reason", "")}
            if entry.get("status") == "waived"
            else {}
        ),
        **(
            {"waiver": "lapsed"}
            if entry.get("status") == "failed" and dict(entry.get("decision") or {}).get("lapsed_at")
            else {}
        ),
        **({"repair": dict(entry["repair"])} if entry.get("repair") else {}),
    }
