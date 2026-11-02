"""Explicit, bounded export of chunk prompts and responses for inspection."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from vraptor.artifacts.persistence import authorize_persistence
from vraptor.analyze.limits import MAX_CORRECTION_ATTEMPTS

_active: ContextVar[PromptDump | None] = ContextVar("chunk_prompt_dump", default=None)
_failed: ContextVar[FailedChunkEvidence | None] = ContextVar(
    "failed_chunk_evidence", default=None
)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _new_debug_directory(case_dir: Path, name: str) -> Path:
    root = case_dir.resolve()
    for part in ("debug", name):
        root = root / part
        if root.is_symlink():
            raise ValueError("Chunk debug output directories must not be symlinks")
        root.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    return Path(mkdtemp(prefix=stamp, dir=root))


class PromptDump:
    """One shared limit across all artifacts and asynchronous tasks in a command."""

    def __init__(self, case_dir: Path, limit: int):
        if limit < 0:
            raise ValueError("chunk prompt limit must not be negative")
        self.case_dir = case_dir
        self.limit = limit
        self.directory: Path | None = None
        self.records: list[dict[str, Any]] = []
        self._unbound_count = 0
        self._lock = threading.Lock()

    def capture(self, prompt: str, plan: dict, chunk: dict, csv_evidence: str) -> None:
        with self._lock:
            if len(self.records) >= self.limit:
                return
            # Resolve only the sources present in this chunk, not the entire run.
            refs = [
                row["_SourceRef"] for row in csv.DictReader(io.StringIO(csv_evidence))
            ]
            aliases = {ref.split("-R", 1)[0] for ref in refs}
            sources = {
                key: value
                for key, value in (plan.get("source_aliases") or {}).items()
                if value.get("alias") in aliases
            }
            authorization = authorize_persistence(
                "interoperability_export",
                source_ids=sources,
                raw_rows=True,
                explicit_export=True,
                bounded=True,
            )
            if self.directory is None:
                self.directory = _new_debug_directory(self.case_dir, "chunk-prompts")
            name = f"chunk-{len(self.records) + 1:03d}.prompt.txt"
            data = prompt.encode("utf-8")
            record = {
                "file": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "artifact": chunk["artifact"],
                "request_id": plan["request_id"],
                "chunk_index": chunk["task_chunk_index"],
                "chunk_count": chunk["task_chunk_count"],
                "row_count": len(refs),
                "first_reference": refs[0] if refs else "",
                "last_reference": refs[-1] if refs else "",
                "source_aliases": sources,
                "persistence": authorization,
                "attempts": [],
            }
            _write_new(self.directory / name, data)
            self.records.append(record)
            self._unbound_count += 1

    def track_task(self, task: Any) -> int | None:
        with self._lock:
            if not self._unbound_count:
                return None
            fingerprint = hashlib.sha256(task.prompt.encode("utf-8")).hexdigest()
            for index, record in enumerate(self.records):
                if record["sha256"] == fingerprint and "task_id" not in record:
                    record["task_id"] = task.task_id
                    self._unbound_count -= 1
                    return index
        return None

    def response(
        self,
        index: int,
        attempt: int,
        prompt: str,
        output: str | None,
        status: str,
    ) -> None:
        with self._lock:
            record = self.records[index]
            # One first attempt, the correction ceiling and one repair call.
            if not 1 <= attempt <= MAX_CORRECTION_ATTEMPTS + 2 or any(
                item["attempt"] == attempt for item in record["attempts"]
            ):
                raise ValueError(
                    "Chunk debug attempt must be unique and within the correction attempt ceiling"
                )
            prefix = f"chunk-{index + 1:03d}.attempt-{attempt:03d}"
            prompt_data = prompt.encode("utf-8")
            prompt_hash = hashlib.sha256(prompt_data).hexdigest()
            prompt_file = record["file"]
            if prompt_hash != record["sha256"]:
                prompt_file = f"{prefix}.prompt.txt"
                _write_new(self.directory / prompt_file, prompt_data)
            response_file = ""
            response_data = output.encode("utf-8") if output is not None else None
            if response_data is not None:
                response_file = f"{prefix}.response.txt"
                _write_new(self.directory / response_file, response_data)
            record["attempts"].append(
                {
                    "attempt": attempt,
                    "runner_status": status,
                    "validation_status": "not_run",
                    "prompt_file": prompt_file,
                    "prompt_sha256": prompt_hash,
                    "response_file": response_file,
                    "response_bytes": len(response_data)
                    if response_data is not None
                    else None,
                    "response_sha256": hashlib.sha256(response_data).hexdigest()
                    if response_data is not None
                    else "",
                }
            )

    def validation(self, index: int, attempt: int, status: str) -> None:
        with self._lock:
            for record in self.records[index]["attempts"]:
                if record["attempt"] == attempt:
                    record["validation_status"] = status
                    return

    def summary(self) -> dict[str, Any]:
        return {
            "requested_limit": self.limit,
            "saved_count": len(self.records),
            "response_count": sum(
                bool(attempt["response_file"])
                for record in self.records
                for attempt in record["attempts"]
            ),
            "directory": str(self.directory) if self.directory else "",
        }

    def finish(self) -> None:
        if self.directory is not None:
            manifest = {
                "schema_version": 2,
                **self.summary(),
                "capture_stage": "rendered_chunk_prompt",
                "note": "Raw responses are untrusted model output. Rendering or response capture does not prove completed review.",
                "prompts": self.records,
            }
            _write_new(
                self.directory / "manifest.json",
                (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
            )
        if self.limit:
            print(
                f"Chunk prompt debug: saved {len(self.records)}/{self.limit} prompts, "
                f"{self.summary()['response_count']} responses"
                + (
                    f" in {self.directory}"
                    if self.directory
                    else " (no chunk prompts rendered)"
                ),
                file=sys.stderr,
                flush=True,
            )


class FailedChunkEvidence:
    """Explicit export of prompts, raw responses and validator messages for failed chunks only."""

    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.directory: Path | None = None
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def save(
        self,
        *,
        key: str,
        prompts: list[str],
        record: dict[str, Any],
        source_ids: list[str],
    ) -> dict[str, Any]:
        authorization = authorize_persistence(
            "interoperability_export",
            source_ids=source_ids,
            raw_rows=True,
            explicit_export=True,
            bounded=True,
        )
        with self._lock:
            if self.directory is None:
                self.directory = _new_debug_directory(self.case_dir, "failed-chunks")
            prefix = f"failed-{len(self.records) + 1:03d}"
            files: list[dict[str, Any]] = []
            history = list(record.get("attempt_history") or [])
            for attempt, prompt in enumerate(prompts, start=1):
                item = dict(history[attempt - 1]) if attempt <= len(history) else {}
                for kind, text in (
                    ("prompt", prompt),
                    ("response", str(dict(item.get("run") or {}).get("output") or "")),
                    ("error", str(item.get("error") or "")),
                ):
                    if not text:
                        continue
                    name = f"{prefix}.attempt-{attempt:03d}.{kind}.txt"
                    data = text.encode("utf-8")
                    _write_new(self.directory / name, data)
                    files.append(
                        {
                            "attempt": attempt,
                            "kind": kind,
                            "file": name,
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": len(data),
                        }
                    )
            reference = {"directory": str(self.directory), "files": files}
            self.records.append({"key": key, **reference, "persistence": authorization})
            return reference

    def finish(self) -> None:
        if self.directory is not None:
            manifest = {
                "schema_version": 1,
                "capture_stage": "failed_chunk",
                "note": "Raw responses are untrusted model output. Prompts contain evidence rows.",
                "chunks": self.records,
            }
            _write_new(
                self.directory / "manifest.json",
                (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
            )
            print(
                f"Failed chunk evidence: saved {len(self.records)} chunks in {self.directory}",
                file=sys.stderr,
                flush=True,
            )


@contextmanager
def session(
    case_dir: Path, limit: int = 0, *, keep_failed: bool = False,
) -> Iterator[PromptDump]:
    dump = PromptDump(case_dir, limit)
    evidence = FailedChunkEvidence(case_dir) if keep_failed else None
    token = _active.set(dump if limit else None)
    failed_token = _failed.set(evidence)
    try:
        yield dump
    finally:
        _active.reset(token)
        _failed.reset(failed_token)
        dump.finish()
        if evidence is not None:
            evidence.finish()


def capture_failed_chunk(
    *, key: str, prompts: list[str], record: dict[str, Any], source_ids: list[str],
) -> dict[str, Any] | None:
    """Save one failed chunk's raw inputs and outputs only when explicitly requested."""
    evidence = _failed.get()
    if evidence is None:
        return None
    return evidence.save(key=key, prompts=prompts, record=record, source_ids=source_ids)


def capture(prompt: str, *, plan: dict, chunk: dict, csv_evidence: str) -> None:
    dump = _active.get()
    if dump is not None:
        dump.capture(prompt, plan, chunk, csv_evidence)


def track_task(task: Any) -> int | None:
    dump = _active.get()
    if dump is not None and task.metadata.get("stage") == "chunk":
        return dump.track_task(task)
    return None


def response(
    index: int | None,
    *,
    attempt: int,
    prompt: str,
    output: str | None,
    status: str,
) -> None:
    dump = _active.get()
    if dump is not None and index is not None:
        dump.response(index, attempt, prompt, output, status)


def validation(index: int | None, attempt: int, status: str) -> None:
    dump = _active.get()
    if dump is not None and index is not None:
        dump.validation(index, attempt, status)
