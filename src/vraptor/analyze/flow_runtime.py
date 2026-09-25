"""Authoritative, bounded acquisition for server-resident flow results."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping, Sequence

import grpc

from vraptor.analyze import flow as flow_analysis


HUNT_FLOW_PAGE_ROWS = 5_000
MULTI_FLOW_WORKERS = 8
UPDATE_SOURCE_BATCH_SIZE = 250
TRANSPORT_RETRY_ROWS = (5_000, 2_500, 1_000, 500, 100, 10, 1)
DETECTRAPTOR_TRANSPORT_BACKOFF_SECONDS = (2.0, 5.0, 15.0)
DETECTRAPTOR_TRANSPORT_ATTEMPTS = len(DETECTRAPTOR_TRANSPORT_BACKOFF_SECONDS) + 1
DETECTRAPTOR_QUERY_TIMEOUT_ENV = "AI_SKILLS_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS"
DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS = 900
DETECTRAPTOR_EVTX_ARTIFACT = "DetectRaptor.Windows.Detection.Evtx"
DETECTRAPTOR_EVTX_STACK_KEY_VERSION = "scriptblock-v2"
DETECTRAPTOR_EVTX_EVIDENCE_EXPRESSION = (
    "if(condition=EventData.ScriptBlockText, "
    "then=EventData.ScriptBlockText, "
    "else=serialize(item=if(condition=Message, then=Message, else=EventData), "
    'format="json"))'
)


def _positive_operational_setting(name: str, default: int) -> int:
    raw = str(os.environ.get(name, default) or "").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def detectraptor_query_timeout_seconds() -> int:
    """Return the absolute deadline for one DetectRaptor server query."""
    return _positive_operational_setting(
        DETECTRAPTOR_QUERY_TIMEOUT_ENV,
        DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
    )


def detectraptor_retry_delay(attempt: int) -> float | None:
    """Return the delay after a failed attempt, or None after the final attempt."""
    index = int(attempt) - 1
    if 0 <= index < len(DETECTRAPTOR_TRANSPORT_BACKOFF_SECONDS):
        return DETECTRAPTOR_TRANSPORT_BACKOFF_SECONDS[index]
    return None

EXACT_FLOW_SOURCE_VQL = """
SELECT *
FROM source(
  client_id=ClientId,
  flow_id=FlowId,
  artifact=ArtifactName)
""".strip()

EXACT_FLOW_NUMBERED_SOURCE_VQL = """
LET NumberedRows = SELECT _key + 1 AS _AnalysisSourceRowNumber,
       _value
FROM items(item={{
  SELECT *
  FROM source(
    client_id=ClientId,
    flow_id=FlowId,
    artifact=ArtifactName)
}})
LET ScopedRows = SELECT *,
       _AnalysisSourceRowNumber
FROM foreach(
  row=NumberedRows,
  query={{
    SELECT *,
           _AnalysisSourceRowNumber
    FROM _value
  }})
WHERE {predicate}
{select_query}
""".strip()

HUNT_RESULTS_VQL = """
SELECT *
FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
""".strip()

DETECTRAPTOR_EVTX_DETECTION_DISCOVERY_VQL = """
LET ScopedRows = SELECT *,
       {evidence_expression} AS EvidencePayload
FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
{where_clause}
SELECT Detection.Name AS Detection,
       count() AS RowCount,
       sum(item=len(list=EvidencePayload)) AS TotalEvidenceChars,
       max(item=len(list=EvidencePayload)) AS MaxEvidenceChars,
       sum(item=if(condition=len(list=EvidencePayload) > 4096, then=1, else=0)) AS RowsOverPreview
FROM ScopedRows
GROUP BY Detection
ORDER BY RowCount
""".strip()

DETECTRAPTOR_EVTX_STACK_CENSUS_VQL = """
LET StackRows = SELECT {evidence_expression} AS StackEvidence
FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
WHERE {predicate}
LET StackGroups = SELECT count() AS GroupRows
FROM StackRows
GROUP BY StackEvidence
SELECT count() AS GroupCount,
       sum(item=GroupRows) AS RowCount,
       sum(item=if(condition=GroupRows = 1, then=1, else=0)) AS SingletonGroupCount,
       max(item=GroupRows) AS LargestGroupRows
FROM StackGroups
GROUP BY True
""".strip()

DETECTRAPTOR_EVTX_STACK_GROUPS_VQL = """
LET StackRows = SELECT *,
       {evidence_expression} AS StackEvidence,
       if(condition=EventData.ScriptBlockText,
          then="EventData.ScriptBlockText",
          else=if(condition=Message, then="Message", else="EventData")) AS EvidenceField
FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
WHERE {predicate}
SELECT StackEvidence,
       EvidenceField,
       count() AS GroupRows,
       min(item=EventTime) AS FirstSeen,
       max(item=EventTime) AS LastSeen
FROM StackRows
GROUP BY StackEvidence
ORDER BY GroupRows
""".strip()

DETECTRAPTOR_EVTX_STACK_CONTEXT_VQL = """
LET SelectedStackEvidence <= parse_json_array(data=SelectedStackEvidenceJson)
LET ScopedRows = SELECT *
FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)
WHERE {predicate}
LET StackRows = SELECT *,
       {evidence_expression} AS StackEvidence
FROM ScopedRows
SELECT EventTime,
       Detection.Name AS Detection,
       Channel,
       EventID,
       Username,
       Computer,
       ClientId,
       Fqdn,
       EventData.Path AS EvidencePath,
       StackEvidence
FROM StackRows
WHERE StackEvidence IN SelectedStackEvidence
ORDER BY EventTime
""".strip()

DETECTRAPTOR_CONTEXT_REQUEST_MAX_CHARS = 256_000

BATCHED_FLOW_SOURCE_VQL = """
SELECT *
FROM foreach(
  row=parse_json_array(data=SourcesJson),
  query={
    SELECT *,
           ClientId AS _SourceClientId,
           FlowId AS _SourceFlowId,
           ArtifactName AS _SourceArtifact
    FROM source(
      client_id=ClientId,
      flow_id=FlowId,
      artifact=ArtifactName)
  })
""".strip()

SERVER_CUTOFF_VQL = """
SELECT timestamp(epoch=now()) AS ServerCutoff
FROM scope()
""".strip()


def _projected_query(base_vql: str, expressions: Sequence[str] | None) -> str:
    selected = [str(value).strip() for value in expressions or () if str(value).strip()]
    if not selected:
        return base_vql
    select_clause = ",\n       ".join(selected)
    marker = "SELECT *"
    if marker not in base_vql:
        raise ValueError("projection requires a SELECT * query template")
    return base_vql.replace(marker, f"SELECT {select_clause}", 1)


def _exact_flow_query(
    expressions: Sequence[str] | None,
    predicate: str = "",
) -> str:
    """Build one exact-source query, preserving source ordinals when filtered."""
    selected = [str(value).strip() for value in expressions or () if str(value).strip()]
    where = str(predicate or "").strip()
    if not where:
        return _projected_query(EXACT_FLOW_SOURCE_VQL, selected)
    if selected:
        select_clause = ",\n       ".join(
            [*selected, "_AnalysisSourceRowNumber"]
        )
        select_query = f"SELECT {select_clause}\nFROM ScopedRows"
    else:
        select_query = "SELECT *\nFROM ScopedRows"
    return EXACT_FLOW_NUMBERED_SOURCE_VQL.format(
        predicate=where,
        select_query=select_query,
    )


def _hunt_result_query(
    expressions: Sequence[str] | None,
    predicate: str = "",
) -> str:
    selected = [str(value).strip() for value in expressions or () if str(value).strip()]
    where = str(predicate or "").strip()
    if selected and where:
        # VQL SELECT aliases are visible to WHERE. Apply the predicate while
        # source fields are still intact, then project aliases in the outer
        # query (notably Detection.Name AS Detection for DetectRaptor EVTX).
        select_clause = ",\n       ".join(selected)
        return (
            "LET ScopedRows = SELECT *\n"
            "FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)\n"
            f"WHERE {where}\n"
            f"SELECT {select_clause}\n"
            "FROM ScopedRows"
        )
    query = _projected_query(HUNT_RESULTS_VQL, selected)
    return f"{query}\nWHERE {where}" if where else query


def _batched_projected_query(
    expressions: Sequence[str] | None,
    predicate: str = "",
) -> str:
    selected = [str(value).strip() for value in expressions or () if str(value).strip()]
    query = BATCHED_FLOW_SOURCE_VQL
    if selected:
        select_clause = ",\n           ".join(selected)
        query = query.replace(
            "SELECT *,\n           ClientId AS _SourceClientId,",
            f"SELECT {select_clause},\n           ClientId AS _SourceClientId,",
            1,
        )
    where = str(predicate or "").strip()
    if where:
        marker = "\n  })"
        if marker not in query:
            raise ValueError("time predicate requires a batched source query template")
        query = query.replace(marker, f"\n    WHERE {where}{marker}", 1)
    return query


@dataclass(frozen=True)
class AcquiredSegment:
    source: flow_analysis.FlowSource
    segment_id: str
    row_start: int
    row_end: int
    rows: list[dict[str, Any]]
    flow_state: str
    provisional: bool = False

    @property
    def row_count(self) -> int:
        return len(self.rows)


@dataclass(frozen=True)
class DetectionPartition:
    detection: str | None
    row_count: int
    partition_id: str
    total_evidence_chars: int = 0
    max_evidence_chars: int = 0
    rows_over_preview: int = 0


@dataclass(frozen=True)
class DetectionStackCensus:
    partition_id: str
    row_count: int
    group_count: int
    singleton_group_count: int
    largest_group_rows: int
    query_sha256: str = ""

    @property
    def reduced_row_count(self) -> int:
        return max(0, self.row_count - self.group_count)

    @property
    def reduction_percent(self) -> float:
        if self.row_count <= 0:
            return 0.0
        return self.reduced_row_count * 100.0 / self.row_count


def _combined_predicate(*predicates: str) -> str:
    selected = [str(value).strip() for value in predicates if str(value).strip()]
    return " AND ".join(f"({value})" for value in selected)


def detectraptor_evtx_partition_source(
    *,
    org_id: str,
    hunt_id: str,
    partition: DetectionPartition,
    watermark: str,
) -> flow_analysis.FlowSource:
    return flow_analysis.FlowSource(
        org_id=org_id,
        client_id="",
        flow_id=hunt_id,
        artifact=DETECTRAPTOR_EVTX_ARTIFACT,
        source=f"hunt_results:detection:{partition.partition_id}",
        hunt_id=hunt_id,
        state="aggregate",
        watermark=watermark,
    )


def discover_detectraptor_evtx_partitions(
    api: Any,
    *,
    hunt_id: str,
    time_predicate: str = "",
    time_environment: Mapping[str, str] | None = None,
    detection_regex: str = "",
    stats: dict[str, Any] | None = None,
    query_timeout_seconds: int = DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
) -> list[DetectionPartition]:
    """Return every in-scope Detection.Name group, ordered rare-first."""
    requested_regex = str(detection_regex or "").strip()
    where = _combined_predicate(
        str(time_predicate or "").strip(),
        "Detection.Name =~ RequestedDetection" if requested_regex else "",
    )
    query = DETECTRAPTOR_EVTX_DETECTION_DISCOVERY_VQL.format(
        where_clause=f"WHERE {where}" if where else "",
        evidence_expression=DETECTRAPTOR_EVTX_EVIDENCE_EXPRESSION,
    )
    environment = {
        **(dict(time_environment or {}) if where else {}),
        "HuntId": hunt_id,
        "ArtifactName": DETECTRAPTOR_EVTX_ARTIFACT,
        **({"RequestedDetection": requested_regex} if requested_regex else {}),
    }
    if stats is not None:
        stats.update(
            {
                "query_sha256": flow_analysis.sha256_identity(
                    "detectraptor-evtx-detection-discovery-query",
                    {"vql": query, "environment": environment},
                ),
                "time_predicate": str(time_predicate or ""),
                "detection_regex": requested_regex,
            }
        )
    counts: dict[str | None, dict[str, int]] = {}
    for batch in api.query_batches_with_metadata(
        query,
        environment,
        timeout=query_timeout_seconds,
        max_wait=30,
        max_row=flow_analysis.DEFAULT_TRANSPORT_ROWS,
    ):
        for raw in batch.rows:
            row = dict(raw)
            detection_value = row.get("Detection")
            detection = (
                str(detection_value)
                if detection_value is not None and str(detection_value)
                else None
            )
            try:
                row_count = int(row.get("RowCount") or 0)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "DetectRaptor EVTX detection discovery returned an invalid row count."
                ) from exc
            if row_count <= 0:
                raise RuntimeError(
                    "DetectRaptor EVTX detection discovery returned a non-positive row count."
                )
            metrics = counts.setdefault(
                detection,
                {
                    "row_count": 0,
                    "total_evidence_chars": 0,
                    "max_evidence_chars": 0,
                    "rows_over_preview": 0,
                },
            )
            metrics["row_count"] += row_count
            for source_key, target_key in (
                ("TotalEvidenceChars", "total_evidence_chars"),
                ("RowsOverPreview", "rows_over_preview"),
            ):
                try:
                    metrics[target_key] += max(0, int(row.get(source_key) or 0))
                except (TypeError, ValueError) as exc:
                    raise RuntimeError(
                        "DetectRaptor EVTX detection discovery returned invalid "
                        "evidence-size metadata."
                    ) from exc
            try:
                metrics["max_evidence_chars"] = max(
                    metrics["max_evidence_chars"],
                    max(0, int(row.get("MaxEvidenceChars") or 0)),
                )
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "DetectRaptor EVTX detection discovery returned invalid "
                    "maximum evidence-size metadata."
                ) from exc
    return [
        DetectionPartition(
            detection=detection,
            row_count=metrics["row_count"],
            partition_id=flow_analysis.sha256_identity(
                "detectraptor-evtx-detection-partition",
                {"detection": detection},
            ),
            total_evidence_chars=metrics["total_evidence_chars"],
            max_evidence_chars=metrics["max_evidence_chars"],
            rows_over_preview=metrics["rows_over_preview"],
        )
        for detection, metrics in sorted(
            counts.items(),
            key=lambda item: (
                item[1]["row_count"],
                item[0] is None,
                item[0] or "",
            ),
        )
    ]


def _detectraptor_partition_predicate(
    partition: DetectionPartition,
    *,
    time_predicate: str,
    environment: dict[str, str],
    detection_regex: str = "",
) -> str:
    detection_predicate = (
        "NOT Detection.Name"
        if partition.detection is None
        else "Detection.Name = PartitionDetection"
    )
    if partition.detection is not None:
        environment["PartitionDetection"] = partition.detection
    requested_regex = str(detection_regex or "").strip()
    if requested_regex:
        environment["RequestedDetection"] = requested_regex
    predicates = [
        time_predicate,
        "Detection.Name =~ RequestedDetection" if requested_regex else "",
        detection_predicate,
    ]
    return _combined_predicate(*predicates)


def query_detectraptor_evtx_stack_census(
    api: Any,
    *,
    hunt_id: str,
    partition: DetectionPartition,
    time_predicate: str = "",
    time_environment: Mapping[str, str] | None = None,
    detection_regex: str = "",
    query_timeout_seconds: int = DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
) -> DetectionStackCensus:
    """Measure exact-evidence consolidation without returning evidence values."""
    environment = {
        **(dict(time_environment or {}) if time_predicate else {}),
        "HuntId": hunt_id,
        "ArtifactName": DETECTRAPTOR_EVTX_ARTIFACT,
    }
    predicate = _detectraptor_partition_predicate(
        partition,
        time_predicate=time_predicate,
        environment=environment,
        detection_regex=detection_regex,
    )
    query = DETECTRAPTOR_EVTX_STACK_CENSUS_VQL.format(
        predicate=predicate,
        evidence_expression=DETECTRAPTOR_EVTX_EVIDENCE_EXPRESSION,
    )
    query_sha256 = flow_analysis.sha256_identity(
        "detectraptor-evtx-exact-census-query",
        {"vql": query, "environment": environment},
    )
    result: dict[str, int] | None = None
    for batch in api.query_batches_with_metadata(
        query,
        environment,
        timeout=query_timeout_seconds,
        max_wait=30,
        max_row=1,
    ):
        for raw in batch.rows:
            row = dict(raw)
            result = {
                "row_count": max(0, int(row.get("RowCount") or 0)),
                "group_count": max(0, int(row.get("GroupCount") or 0)),
                "singleton_group_count": max(
                    0, int(row.get("SingletonGroupCount") or 0)
                ),
                "largest_group_rows": max(
                    0, int(row.get("LargestGroupRows") or 0)
                ),
            }
    if result is None or result["row_count"] <= 0 or result["group_count"] <= 0:
        raise RuntimeError(
            "DetectRaptor EVTX stack census returned no accountable groups for "
            f"{partition.detection!r}."
        )
    if result["group_count"] > result["row_count"]:
        raise RuntimeError(
            "DetectRaptor EVTX stack census returned more groups than rows."
        )
    return DetectionStackCensus(
        partition_id=partition.partition_id,
        query_sha256=query_sha256,
        **result,
    )


def iter_detectraptor_evtx_stack_segments(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    cutoff: str,
    partition: DetectionPartition,
    census: DetectionStackCensus,
    time_predicate: str = "",
    time_environment: Mapping[str, str] | None = None,
    detection_regex: str = "",
    segment_rows: int = flow_analysis.DEFAULT_SEGMENT_ROWS,
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    stats: dict[str, Any] | None = None,
    query_timeout_seconds: int = DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
) -> Iterator[AcquiredSegment]:
    """Stream one full-payload summary per exact evidence group."""
    environment = {
        **(dict(time_environment or {}) if time_predicate else {}),
        "HuntId": hunt_id,
        "ArtifactName": DETECTRAPTOR_EVTX_ARTIFACT,
    }
    predicate = _detectraptor_partition_predicate(
        partition,
        time_predicate=time_predicate,
        environment=environment,
        detection_regex=detection_regex,
    )
    query = DETECTRAPTOR_EVTX_STACK_GROUPS_VQL.format(
        predicate=predicate,
        evidence_expression=DETECTRAPTOR_EVTX_EVIDENCE_EXPRESSION,
    )
    query_sha256 = flow_analysis.sha256_identity(
        "detectraptor-evtx-exact-groups-query",
        {"vql": query, "environment": environment},
    )
    source = detectraptor_evtx_partition_source(
        org_id=org_id,
        hunt_id=hunt_id,
        partition=partition,
        watermark=cutoff,
    )
    source_rows = 0
    group_rows = 0
    summary = stats if stats is not None else {}
    summary.update(
        {
            "partition_id": partition.partition_id,
            "detection": partition.detection,
            "discovered_row_count": partition.row_count,
            "census_row_count": census.row_count,
            "census_group_count": census.group_count,
            "group_count": census.group_count,
            "singleton_group_count": census.singleton_group_count,
            "largest_group_rows": census.largest_group_rows,
            "reduction_percent": round(census.reduction_percent, 4),
            "reviewed_row_count": 0,
            "model_group_count": 0,
            "query_sha256": query_sha256,
        }
    )
    for segment in _iter_query_segments(
        api,
        vql=query,
        env=environment,
        source=source,
        segment_rows=segment_rows,
        segment_bytes=segment_bytes,
        query_timeout_seconds=query_timeout_seconds,
    ):
        transformed: list[dict[str, Any]] = []
        for raw in segment.rows:
            row = dict(raw)
            evidence = str(row.pop("StackEvidence", "") or "")
            count = max(1, int(row.get("GroupRows") or 1))
            transformed.append(
                {
                    "Detection": partition.detection or "",
                    "OccurrenceCount": count,
                    "FirstSeen": row.get("FirstSeen"),
                    "LastSeen": row.get("LastSeen"),
                    "PayloadField": row.get("EvidenceField") or "EventData",
                    "Payload": evidence,
                }
            )
            group_rows += 1
            source_rows += count
        yield AcquiredSegment(
            source=segment.source,
            segment_id=segment.segment_id + "-exact-stack",
            row_start=segment.row_start,
            row_end=segment.row_end,
            rows=transformed,
            flow_state=segment.flow_state,
            provisional=segment.provisional,
        )
    summary["reviewed_row_count"] = source_rows
    summary["model_group_count"] = group_rows
    summary["group_count"] = group_rows
    if group_rows < census.group_count or source_rows < census.row_count:
        raise RuntimeError(
            "DetectRaptor EVTX exact stack returned less than its census for "
            f"{partition.detection!r}: census rows/groups "
            f"{census.row_count}/{census.group_count}, streamed "
            f"{source_rows}/{group_rows}."
        )


def _detectraptor_context_batches(
    evidence_by_group: Mapping[str, str],
) -> Iterator[dict[str, str]]:
    """Bound request payload size while preserving deterministic group order."""
    batch: dict[str, str] = {}
    batch_chars = 0
    for group_id, evidence in sorted(evidence_by_group.items()):
        value_chars = len(group_id) + len(evidence)
        if batch and batch_chars + value_chars > DETECTRAPTOR_CONTEXT_REQUEST_MAX_CHARS:
            yield batch
            batch = {}
            batch_chars = 0
        batch[str(group_id)] = str(evidence)
        batch_chars += value_chars
    if batch:
        yield batch


def query_detectraptor_evtx_stack_context(
    api: Any,
    *,
    hunt_id: str,
    partition: DetectionPartition,
    evidence_by_group: Mapping[str, str],
    time_predicate: str = "",
    time_environment: Mapping[str, str] | None = None,
    detection_regex: str = "",
    query_timeout_seconds: int = DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Retrieve timestamp and machine context for already-classified groups."""
    requested = {
        str(group_id): str(evidence)
        for group_id, evidence in evidence_by_group.items()
        if str(group_id) and str(evidence)
    }
    if not requested:
        return {}, []
    group_by_evidence = {evidence: group_id for group_id, evidence in requested.items()}
    if len(group_by_evidence) != len(requested):
        raise RuntimeError("DetectRaptor selected group evidence is not unique.")
    rows_by_group: dict[str, list[dict[str, Any]]] = {
        group_id: [] for group_id in requested
    }
    query_hashes: list[str] = []
    for selected in _detectraptor_context_batches(requested):
        environment = {
            **(dict(time_environment or {}) if time_predicate else {}),
            "HuntId": hunt_id,
            "ArtifactName": DETECTRAPTOR_EVTX_ARTIFACT,
            "SelectedStackEvidenceJson": json.dumps(
                list(selected.values()), ensure_ascii=False, separators=(",", ":")
            ),
        }
        predicate = _detectraptor_partition_predicate(
            partition,
            time_predicate=time_predicate,
            environment=environment,
            detection_regex=detection_regex,
        )
        query = DETECTRAPTOR_EVTX_STACK_CONTEXT_VQL.format(
            predicate=predicate,
            evidence_expression=DETECTRAPTOR_EVTX_EVIDENCE_EXPRESSION,
        )
        query_sha256 = flow_analysis.sha256_identity(
            "detectraptor-evtx-exact-context-query",
            {"vql": query, "environment": environment},
        )
        query_hashes.append(query_sha256)
        for result_batch in api.query_batches_with_metadata(
            query,
            environment,
            timeout=query_timeout_seconds,
            max_wait=30,
            max_row=HUNT_FLOW_PAGE_ROWS,
        ):
            for raw in result_batch.rows:
                row = dict(raw)
                evidence = str(row.pop("StackEvidence", "") or "")
                group_id = group_by_evidence.get(evidence)
                if group_id in selected:
                    rows_by_group[group_id].append(row)
    missing = [group_id for group_id, rows in rows_by_group.items() if not rows]
    if missing:
        raise RuntimeError(
            "DetectRaptor EVTX context lookup returned no rows for "
            f"{len(missing)} selected group(s)."
        )
    return rows_by_group, query_hashes


def iter_detectraptor_evtx_detection_segments(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    cutoff: str,
    partitions: Sequence[DetectionPartition],
    projection: Sequence[str] | None = None,
    time_predicate: str = "",
    time_environment: Mapping[str, str] | None = None,
    segment_rows: int = flow_analysis.DEFAULT_SEGMENT_ROWS,
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    stats: dict[str, Any] | None = None,
    detection_regex: str = "",
    query_timeout_seconds: int = DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS,
) -> Iterator[AcquiredSegment]:
    """Stream full EVTX rows once per discovered Detection.Name value."""
    summary = stats if stats is not None else {}
    summary.clear()
    summary.update(
        {
            "artifact": DETECTRAPTOR_EVTX_ARTIFACT,
            "discovery_query_count": 1,
            "partition_query_count": 0,
            "partition_count": len(partitions),
            "discovered_row_count": sum(item.row_count for item in partitions),
            "reviewed_row_count": 0,
            "partitions": [
                {
                    "partition_id": item.partition_id,
                    "detection": item.detection,
                    "discovered_row_count": item.row_count,
                    "reviewed_row_count": 0,
                }
                for item in partitions
            ],
        }
    )
    partition_stats = {
        str(item["partition_id"]): item for item in summary["partitions"]
    }
    for partition in partitions:
        environment = {
            **(dict(time_environment or {}) if time_predicate else {}),
            "HuntId": hunt_id,
            "ArtifactName": DETECTRAPTOR_EVTX_ARTIFACT,
        }
        predicate = _detectraptor_partition_predicate(
            partition,
            time_predicate=time_predicate,
            environment=environment,
            detection_regex=detection_regex,
        )
        source = detectraptor_evtx_partition_source(
            org_id=org_id,
            hunt_id=hunt_id,
            partition=partition,
            watermark=cutoff,
        )
        reviewed = 0
        summary["partition_query_count"] += 1
        query = _hunt_result_query(projection, predicate)
        partition_stats[partition.partition_id]["query_sha256"] = (
            flow_analysis.sha256_identity(
                "detectraptor-evtx-direct-partition-query",
                {"vql": query, "environment": environment},
            )
        )
        for segment in _iter_query_segments(
            api,
            vql=query,
            env=environment,
            source=source,
            segment_rows=segment_rows,
            segment_bytes=segment_bytes,
            query_timeout_seconds=query_timeout_seconds,
        ):
            reviewed += segment.row_count
            summary["reviewed_row_count"] += segment.row_count
            partition_stats[partition.partition_id]["reviewed_row_count"] = reviewed
            yield segment
        if reviewed < partition.row_count:
            raise RuntimeError(
                "DetectRaptor EVTX detection partition returned fewer rows than "
                f"its discovery baseline for {partition.detection!r}: "
                f"discovered {partition.row_count}, reviewed {reviewed}."
            )


def _serialized_row_bytes(row: Mapping[str, Any]) -> int:
    return len(
        json.dumps(row, ensure_ascii=False, default=str).encode("utf-8")
    )


def query_server_cutoff(api: Any) -> str:
    rows = api.query(SERVER_CUTOFF_VQL, max_wait=30, max_row=1)
    if not rows:
        raise RuntimeError("Velociraptor did not return a server cutoff time.")
    cutoff = str(dict(rows[0]).get("ServerCutoff") or "").strip()
    if not cutoff:
        raise RuntimeError("Velociraptor returned an empty server cutoff time.")
    return cutoff


def aggregate_hunt_source(
    *, org_id: str, hunt_id: str, artifact: str, watermark: str
) -> flow_analysis.FlowSource:
    """Return the stable logical source used by full hunt_results() review."""
    return flow_analysis.FlowSource(
        org_id=org_id,
        client_id="",
        flow_id=hunt_id,
        artifact=artifact,
        source="hunt_results",
        hunt_id=hunt_id,
        state="aggregate",
        watermark=watermark,
    )


def _iter_query_segments(
    api: Any,
    *,
    vql: str,
    env: dict[str, str],
    source: flow_analysis.FlowSource,
    segment_rows: int,
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    query_timeout_seconds: int = 0,
) -> Iterator[AcquiredSegment]:
    """Stream one logical query result with bounded transport recovery."""
    if segment_rows <= 0 or segment_bytes <= 0:
        raise ValueError("segment row and byte limits must be positive")
    completed_rows = 0
    for candidate_index, max_row in enumerate(
        _transport_candidates(flow_analysis.DEFAULT_TRANSPORT_ROWS)
    ):
        buffered: list[dict[str, Any]] = []
        buffered_bytes = 0
        observed_rows = 0
        try:
            for batch in api.query_batches_with_metadata(
                vql,
                env,
                timeout=query_timeout_seconds,
                max_wait=30,
                max_row=max_row,
            ):
                for raw in batch.rows:
                    if observed_rows < completed_rows:
                        observed_rows += 1
                        continue
                    observed_rows += 1
                    row = dict(raw)
                    row_bytes = _serialized_row_bytes(row)
                    if buffered and buffered_bytes + row_bytes > segment_bytes:
                        start = completed_rows
                        completed_rows += len(buffered)
                        yield AcquiredSegment(
                            source=source,
                            segment_id=flow_analysis.segment_identifier(
                                source.source_id, start, completed_rows
                            ),
                            row_start=start,
                            row_end=completed_rows,
                            rows=buffered,
                            flow_state=source.state,
                        )
                        buffered = []
                        buffered_bytes = 0
                    buffered.append(row)
                    buffered_bytes += row_bytes
                    if len(buffered) == segment_rows:
                        start = completed_rows
                        completed_rows += len(buffered)
                        yield AcquiredSegment(
                            source=source,
                            segment_id=flow_analysis.segment_identifier(
                                source.source_id, start, completed_rows
                            ),
                            row_start=start,
                            row_end=completed_rows,
                            rows=buffered,
                            flow_state=source.state,
                        )
                        buffered = []
                        buffered_bytes = 0
            if buffered:
                start = completed_rows
                completed_rows += len(buffered)
                yield AcquiredSegment(
                    source=source,
                    segment_id=flow_analysis.segment_identifier(
                        source.source_id, start, completed_rows
                    ),
                    row_start=start,
                    row_end=completed_rows,
                    rows=buffered,
                    flow_state=source.state,
                )
            return
        except Exception as exc:
            if not is_resource_exhausted_error(exc):
                raise
            if candidate_index == len(
                _transport_candidates(flow_analysis.DEFAULT_TRANSPORT_ROWS)
            ) - 1:
                raise RuntimeError(
                    "A single Velociraptor result row exceeds the configured "
                    "gRPC message limit."
                ) from exc


def iter_hunt_result_segments(
    api: Any,
    *,
    org_id: str,
    hunt_id: str,
    artifacts: Sequence[str],
    cutoff: str,
    segment_rows: int = flow_analysis.DEFAULT_SEGMENT_ROWS,
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    projections: Mapping[str, Sequence[str]] | None = None,
    time_predicates: Mapping[str, str] | None = None,
    time_environment: Mapping[str, str] | None = None,
) -> Iterator[AcquiredSegment]:
    """Stream hunt_results() once per selected artifact."""
    selected_projections = dict(projections or {})
    selected_predicates = dict(time_predicates or {})
    shared_time_environment = dict(time_environment or {})
    for artifact in sorted({str(value) for value in artifacts if str(value)}):
        time_predicate = selected_predicates.get(artifact, "")
        source = aggregate_hunt_source(
            org_id=org_id,
            hunt_id=hunt_id,
            artifact=artifact,
            watermark=cutoff,
        )
        yield from _iter_query_segments(
            api,
            vql=_hunt_result_query(
                selected_projections.get(artifact),
                time_predicate,
            ),
            env={
                **(shared_time_environment if time_predicate else {}),
                "HuntId": hunt_id,
                "ArtifactName": artifact,
            },
            source=source,
            segment_rows=segment_rows,
            segment_bytes=segment_bytes,
        )


def iter_batched_flow_segments(
    api: Any,
    sources: Sequence[flow_analysis.FlowSource],
    *,
    batch_size: int = UPDATE_SOURCE_BATCH_SIZE,
    segment_rows: int = flow_analysis.DEFAULT_SEGMENT_ROWS,
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    projections: Mapping[str, Sequence[str]] | None = None,
    time_predicates: Mapping[str, str] | None = None,
    time_environment: Mapping[str, str] | None = None,
) -> Iterator[AcquiredSegment]:
    """Read update sources with one server-side foreach query per 250 flows."""
    if batch_size <= 0:
        raise ValueError("source batch size must be positive")
    selected_projections = dict(projections or {})
    selected_predicates = dict(time_predicates or {})
    shared_time_environment = dict(time_environment or {})
    for batch_source, batch in batched_source_groups(
        sources, batch_size=batch_size
    ):
        time_predicate = selected_predicates.get(batch[0].artifact, "")
        descriptors = [
            {
                "ClientId": source.client_id,
                "FlowId": source.flow_id,
                "ArtifactName": source.artifact,
            }
            for source in batch
        ]
        yield from _iter_query_segments(
            api,
            vql=_batched_projected_query(
                selected_projections.get(batch[0].artifact),
                time_predicate,
            ),
            env={
                **(shared_time_environment if time_predicate else {}),
                "SourcesJson": json.dumps(
                    descriptors, sort_keys=True, separators=(",", ":")
                )
            },
            source=batch_source,
            segment_rows=segment_rows,
            segment_bytes=segment_bytes,
        )


def batched_source_groups(
    sources: Sequence[flow_analysis.FlowSource],
    *,
    batch_size: int = UPDATE_SOURCE_BATCH_SIZE,
) -> list[tuple[flow_analysis.FlowSource, list[flow_analysis.FlowSource]]]:
    """Return deterministic, artifact-homogeneous update batches."""
    if batch_size <= 0:
        raise ValueError("source batch size must be positive")
    by_artifact: dict[str, list[flow_analysis.FlowSource]] = {}
    for source in sorted(
        sources, key=lambda item: (item.artifact, item.client_id, item.flow_id)
    ):
        by_artifact.setdefault(source.artifact, []).append(source)
    groups: list[tuple[flow_analysis.FlowSource, list[flow_analysis.FlowSource]]] = []
    for artifact, values in sorted(by_artifact.items()):
        for start in range(0, len(values), batch_size):
            batch = values[start : start + batch_size]
            identity = [
                (source.client_id, source.flow_id, source.artifact)
                for source in batch
            ]
            groups.append(
                (
                    flow_analysis.FlowSource(
                        org_id=batch[0].org_id,
                        client_id="",
                        flow_id=flow_analysis.sha256_identity(
                            "update-batch", identity, length=16
                        ),
                        artifact=artifact,
                        source="source",
                        hunt_id=batch[0].hunt_id,
                        state="terminal",
                        watermark=flow_analysis.sha256_identity(
                            "batchmark", [source.watermark for source in batch]
                        ),
                    ),
                    batch,
                )
            )
    return groups


def is_resource_exhausted_error(exc: Exception) -> bool:
    code_method = getattr(exc, "code", None)
    if callable(code_method):
        try:
            code = code_method()
            if code == grpc.StatusCode.RESOURCE_EXHAUSTED:
                return True
            if str(getattr(code, "name", "")) == "RESOURCE_EXHAUSTED":
                return True
        except Exception:
            pass
    text = str(exc).lower()
    return "resource exhausted" in text or "received message larger than max" in text


def grpc_status_name(exc: Exception) -> str:
    """Return a value-free gRPC status name when one is available."""
    code_method = getattr(exc, "code", None)
    if not callable(code_method):
        return ""
    try:
        code = code_method()
    except Exception:
        return ""
    return str(getattr(code, "name", "") or code or "").split(".")[-1].upper()


def is_retryable_read_only_transport_error(
    exc: Exception,
    *,
    rows_received: int = 0,
) -> bool:
    """Classify only replay-safe transport loss for caller-scoped read queries.

    UNAVAILABLE can interrupt a streamed response and is safe only because the
    caller discards the complete semantic unit. DEADLINE_EXCEEDED is narrower:
    retry it only before the query has returned rows so a server-side timeout is
    not silently treated as an ordering-stable continuation.
    """
    status = grpc_status_name(exc)
    if status == "UNAVAILABLE":
        return True
    if status == "DEADLINE_EXCEEDED" and int(rows_received) == 0:
        return True
    return False


def reconnect_query_client(api: Any) -> bool:
    """Reopen a query client's channel when it exposes the supported hook."""
    reconnect = getattr(api, "reconnect", None)
    if not callable(reconnect):
        return False
    reconnect()
    return True


def _transport_candidates(preferred: int) -> tuple[int, ...]:
    candidates = [preferred, *TRANSPORT_RETRY_ROWS]
    return tuple(dict.fromkeys(value for value in candidates if value <= preferred))


def enumerate_hunt_flows(
    api: Any,
    hunt_id: str,
    *,
    page_rows: int = HUNT_FLOW_PAGE_ROWS,
) -> list[dict[str, Any]]:
    """Enumerate the complete server inventory with nested flow metadata."""
    if page_rows <= 0:
        raise ValueError("hunt flow page size must be positive")
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    start_row = 0
    while True:
        # Older supported Velociraptor servers accept start_row on hunt_flows()
        # but reject a limit plugin argument. VQL LIMIT requires a numeric
        # literal, so interpolate only the already validated integer.
        inventory_vql = f"""
            SELECT *
            FROM hunt_flows(
              hunt_id=HuntId,
              start_row=int(int=StartRow),
              basic_info=FALSE)
            LIMIT {page_rows}
            """.strip()
        page = api.query(
            inventory_vql,
            {
                "HuntId": hunt_id,
                "StartRow": str(start_row),
            },
            max_wait=30,
            max_row=min(page_rows, flow_analysis.DEFAULT_TRANSPORT_ROWS),
        )
        for raw in page:
            row = dict(raw)
            identity = flow_analysis.flow_identifiers(row)
            if not all(identity) or identity in seen:
                continue
            seen.add(identity)
            rows.append(row)
        if len(page) < page_rows:
            break
        start_row += len(page)
    return rows


def classify_hunt_inventory(
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    classified = {
        flow_analysis.FLOW_OPEN: [],
        flow_analysis.FLOW_SUCCESSFUL_TERMINAL: [],
        flow_analysis.FLOW_FAILED_TERMINAL: [],
        flow_analysis.FLOW_UNKNOWN: [],
    }
    for raw in rows:
        row = dict(raw)
        classified[flow_analysis.classify_flow(row)].append(row)
    for values in classified.values():
        values.sort(key=flow_analysis.flow_identifiers)
    return classified


def query_client_identity_map(
    api: Any,
    client_ids: Iterable[str],
) -> dict[str, dict[str, str]]:
    """Best-effort hostname enrichment; client ids remain authoritative."""
    requested = {str(value) for value in client_ids if str(value).strip()}
    if not requested:
        return {}
    try:
        rows = api.query(
            """
            SELECT client_id, os_info.fqdn AS Fqdn,
                   os_info.hostname AS Hostname
            FROM clients()
            """.strip(),
            max_wait=30,
            max_row=max(1000, len(requested)),
        )
    except Exception:
        return {}
    identities: dict[str, dict[str, str]] = {}
    for raw in rows:
        row = dict(raw)
        client_id = str(row.get("client_id") or row.get("ClientId") or "").strip()
        if client_id not in requested:
            continue
        identities[client_id] = {
            "hostname": str(row.get("Hostname") or "").strip(),
            "fqdn": str(row.get("Fqdn") or "").strip(),
        }
    return identities


def iter_flow_segments(
    api: Any,
    sources: Sequence[flow_analysis.FlowSource],
    *,
    acquisition_window_rows: int = flow_analysis.DEFAULT_ACQUISITION_WINDOW_ROWS,
    segment_rows: int = flow_analysis.DEFAULT_SEGMENT_ROWS,
    source_page_rows: int | None = None,
    workers: int = MULTI_FLOW_WORKERS,
    variable_large_artifacts: Iterable[str] = (),
    segment_bytes: int = flow_analysis.DEFAULT_SEGMENT_BYTES,
    projections: Mapping[str, Sequence[str]] | None = None,
    time_predicates: Mapping[str, str] | None = None,
    time_environment: Mapping[str, str] | None = None,
) -> Iterator[AcquiredSegment]:
    """Stream exact flow sources and yield bounded, fixed logical segments.

    ``source()`` does not expose row paging on all supported Velociraptor
    servers. Stream one immutable terminal source at a time instead, using the
    gRPC ``max_row`` control only to bound transport packets and segmenting the
    result locally. This avoids silently treating an unsupported paging query
    as an empty source.
    """
    if acquisition_window_rows < segment_rows:
        raise ValueError("acquisition window cannot be smaller than one segment")
    page_rows = int(source_page_rows or segment_rows)
    if page_rows < segment_rows or page_rows > acquisition_window_rows:
        raise ValueError(
            "source page rows must be between one segment and the acquisition window"
        )
    if segment_bytes <= 0:
        raise ValueError("segment byte limit must be positive")
    del workers  # Exact-source streaming is intentionally deterministic.
    variable_large = {str(value) for value in variable_large_artifacts}
    selected_predicates = dict(time_predicates or {})
    shared_time_environment = dict(time_environment or {})
    transport_rows = flow_analysis.DEFAULT_TRANSPORT_ROWS
    observations: list[dict[str, int]] = []
    for source in sorted(
        sources,
        key=lambda item: (item.artifact, item.client_id, item.flow_id),
    ):
        preferred_rows = min(
            transport_rows,
            100 if source.artifact in variable_large else transport_rows,
        )
        time_predicate = selected_predicates.get(source.artifact, "")
        completed_rows = 0
        candidate_rows = _transport_candidates(preferred_rows)
        for candidate_index, max_row in enumerate(candidate_rows):
            buffered: list[dict[str, Any]] = []
            buffered_bytes = 0
            observed_rows = 0
            try:
                batches = api.query_batches_with_metadata(
                    _exact_flow_query(
                        dict(projections or {}).get(source.artifact),
                        time_predicate,
                    ),
                    {
                        **(shared_time_environment if time_predicate else {}),
                        "ClientId": source.client_id,
                        "FlowId": source.flow_id,
                        "ArtifactName": source.artifact,
                    },
                    max_wait=30,
                    max_row=max_row,
                )
                for batch in batches:
                    observations.append(
                        {
                            "row_count": int(batch.row_count),
                            "payload_bytes": int(batch.payload_bytes),
                            "max_row_bytes": int(batch.max_row_bytes),
                        }
                    )
                    for raw in batch.rows:
                        if observed_rows < completed_rows:
                            observed_rows += 1
                            continue
                        observed_rows += 1
                        row = dict(raw)
                        row_bytes = _serialized_row_bytes(row)
                        if buffered and buffered_bytes + row_bytes > segment_bytes:
                            segment_start = completed_rows
                            completed_rows += len(buffered)
                            yield AcquiredSegment(
                                source=source,
                                segment_id=flow_analysis.segment_identifier(
                                    source.source_id,
                                    segment_start,
                                    completed_rows,
                                ),
                                row_start=segment_start,
                                row_end=completed_rows,
                                rows=buffered,
                                flow_state=source.state,
                            )
                            buffered = []
                            buffered_bytes = 0
                        buffered.append(row)
                        buffered_bytes += row_bytes
                        if len(buffered) == segment_rows:
                            segment_start = completed_rows
                            completed_rows += len(buffered)
                            yield AcquiredSegment(
                                source=source,
                                segment_id=flow_analysis.segment_identifier(
                                    source.source_id,
                                    segment_start,
                                    completed_rows,
                                ),
                                row_start=segment_start,
                                row_end=completed_rows,
                                rows=buffered,
                                flow_state=source.state,
                            )
                            buffered = []
                            buffered_bytes = 0
                if buffered:
                    segment_start = completed_rows
                    completed_rows += len(buffered)
                    yield AcquiredSegment(
                        source=source,
                        segment_id=flow_analysis.segment_identifier(
                            source.source_id,
                            segment_start,
                            completed_rows,
                        ),
                        row_start=segment_start,
                        row_end=completed_rows,
                        rows=buffered,
                        flow_state=source.state,
                    )
                transport_rows = flow_analysis.transport_rows_after_observations(
                    observations,
                    current_rows=max_row,
                    variable_large_rows=source.artifact in variable_large,
                )
                break
            except Exception as exc:
                if not is_resource_exhausted_error(exc):
                    raise
                if candidate_index == len(candidate_rows) - 1:
                    raise RuntimeError(
                        "A single Velociraptor result row exceeds the configured "
                        "gRPC message limit; exact-source streaming cannot recover "
                        f"{source.source_id}."
                    ) from exc
