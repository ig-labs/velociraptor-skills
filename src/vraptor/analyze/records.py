"""Canonical, reversible evidence records for token-bounded model review."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict, defaultdict
from typing import Any

from vraptor.common import token_budget


EVIDENCE_RECORD_VERSION = 1
TIMESTAMP_FIELDS = (
    "EventTime",
    "Timestamp",
    "TimeCreated",
    "Created",
    "LastModified",
    "Mtime",
    "Atime",
)


def compact_value(value: Any) -> Any:
    """Remove empty structure while preserving non-empty evidential values."""
    if value is None:
        return None
    if isinstance(value, dict):
        compacted = {
            str(key): item
            for key, child in value.items()
            if (item := compact_value(child)) not in (None, "", [], {})
        }
        return compacted or None
    if isinstance(value, (list, tuple)):
        compacted_items = [
            item
            for child in value
            if (item := compact_value(child)) not in (None, "", [], {})
        ]
        return compacted_items or None
    if isinstance(value, str):
        return value if value.strip() else None
    return value


def normalized_values(row: dict[str, Any]) -> dict[str, Any]:
    compacted = compact_value(row)
    if not isinstance(compacted, dict):
        return {}
    return compacted


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def record_content_hash(artifact: str, partition: str, values: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(str(artifact).encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(partition).encode("utf-8"))
    digest.update(b"\0")
    digest.update(canonical_json_bytes(values))
    return digest.hexdigest()


def evidence_id(content_hash: str) -> str:
    return f"ev-{content_hash[:24]}"


def first_timestamp(values: dict[str, Any]) -> str:
    for field in TIMESTAMP_FIELDS:
        value = values.get(field)
        if value not in (None, ""):
            return str(value)
    return ""


def compress_line_numbers(lines: list[int]) -> list[str]:
    ordered = sorted(set(int(line) for line in lines if int(line) > 0))
    if not ordered:
        return []
    ranges: list[str] = []
    start = previous = ordered[0]
    for line in ordered[1:]:
        if line == previous + 1:
            previous = line
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = line
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ranges


class EvidenceAccumulator:
    """Deduplicate exact normalized rows while retaining complete provenance."""

    def __init__(self, artifact: str):
        self.artifact = str(artifact)
        self.raw_row_count = 0
        self.raw_tokens = 0
        self.normalized_tokens = 0
        self._records: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._source_lines: dict[str, dict[str, list[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add(
        self,
        row: dict[str, Any],
        *,
        partition: str,
        source_file: str,
        source_line: int,
    ) -> str:
        values = normalized_values(row)
        raw_encoded = canonical_json_bytes(row)
        normalized_encoded = canonical_json_bytes(values)
        content_hash = record_content_hash(self.artifact, partition, values)
        record_id = evidence_id(content_hash)
        timestamp = first_timestamp(values)

        self.raw_row_count += 1
        self.raw_tokens += token_budget.estimate_tokens(raw_encoded.decode("utf-8"))
        self.normalized_tokens += token_budget.estimate_tokens(
            normalized_encoded.decode("utf-8")
        )
        record = self._records.get(record_id)
        if record is None:
            record = {
                "record_version": EVIDENCE_RECORD_VERSION,
                "evidence_id": record_id,
                "content_hash": content_hash,
                "artifact": self.artifact,
                "partition": partition,
                "occurrence_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "values": values,
            }
            self._records[record_id] = record
        record["occurrence_count"] += 1
        if timestamp:
            if not record["first_seen"] or timestamp < record["first_seen"]:
                record["first_seen"] = timestamp
            if not record["last_seen"] or timestamp > record["last_seen"]:
                record["last_seen"] = timestamp
        self._source_lines[record_id][str(source_file)].append(int(source_line))
        return record_id

    def records(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for record_id, record in self._records.items():
            item = dict(record)
            item["provenance"] = [
                {
                    "source_file": source_file,
                    "line_ranges": compress_line_numbers(lines),
                }
                for source_file, lines in sorted(self._source_lines[record_id].items())
            ]
            output.append(item)
        return output

    def model_records(self) -> list[dict[str, Any]]:
        return [
            {
                "evidence_id": record["evidence_id"],
                "occurrence_count": record["occurrence_count"],
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "values": record["values"],
            }
            for record in self._records.values()
        ]

    def metrics(self) -> dict[str, Any]:
        model_records = self.model_records()
        deduplicated_tokens = sum(
            token_budget.estimate_tokens(canonical_json_bytes(record).decode("utf-8"))
            for record in model_records
        )
        duplicate_rows = self.raw_row_count - len(model_records)
        reduction = (
            0.0
            if self.raw_tokens == 0
            else round((1 - (deduplicated_tokens / self.raw_tokens)) * 100, 2)
        )
        return {
            "raw_row_count": self.raw_row_count,
            "unique_evidence_count": len(model_records),
            "duplicate_row_count": duplicate_rows,
            "raw_tokens": self.raw_tokens,
            "normalized_tokens": self.normalized_tokens,
            "deduplicated_tokens": deduplicated_tokens,
            "token_reduction_percent": reduction,
            "token_estimator": token_budget.token_estimator_name(),
        }
