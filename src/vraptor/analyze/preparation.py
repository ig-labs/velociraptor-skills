"""Bounded live-hunt preparation without model execution or review checkpoints."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from vraptor.analyze import limits as analysis_limits
from vraptor.common import atomic_io
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.analyze import coordinator
from vraptor.analyze import flow_runtime as runtime


def prepare_hunt(
    api: Any, *, org_id: str, hunt_id: str, hunt_root: Path,
    selected_artifacts: Iterable[str], policy: artifact_policy.ArtifactPolicySnapshot,
    limits: analysis_limits.AnalysisLimits, time_scope: analysis_time_scope.TimeScope,
    detection_regex: str = "", reported_result_rows: int = 0,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Exhaust projected streams, count planned chunks, and publish only metadata.

    Reuse the normal acquisition, time filtering, projection and token chunking
    primitives. No model route, cached classification, or reviewed cursor is used.
    Memory is bounded by the acquisition segment and one pending token chunk.
    """
    limits.validate()
    cutoff = runtime.query_server_cutoff(api)
    inventory = runtime.enumerate_hunt_flows(api, hunt_id)
    if reported_result_rows and not inventory:
        raise RuntimeError(f"Hunt {hunt_id} reports results but returned no flow inventory")
    artifacts = coordinator._inventory_artifacts(inventory, set(selected_artifacts))
    if reported_result_rows and not artifacts:
        raise RuntimeError(f"Hunt {hunt_id} reports results but has no result artifacts")
    if detection_regex and (
        len(detection_regex) > 512 or set(artifacts) != {runtime.DETECTRAPTOR_EVTX_ARTIFACT}
    ):
        raise RuntimeError("--detection-regex requires only DetectRaptor EVTX and at most 512 characters")
    profiles = policy.profiles
    scopes = analysis_time_scope.resolve_all(
        artifacts, profiles, time_scope, profile_resolver=artifact_profiles.resolve_profile)
    provenance = analysis_time_scope.provenance(
        artifacts, profiles, time_scope, scopes, profile_resolver=artifact_profiles.resolve_profile)
    projections = coordinator._live_projections(artifacts, profiles, scopes)
    predicates = {name: scope.predicate() for name, scope in scopes.items() if scope.scope.bounded}
    environment = time_scope.environment()
    evtx = runtime.DETECTRAPTOR_EVTX_ARTIFACT
    partitions = []
    sources = [runtime.aggregate_hunt_source(
        org_id=org_id, hunt_id=hunt_id, artifact=name, watermark=cutoff)
        for name in artifacts if name != evtx]
    if evtx in artifacts:
        partitions = runtime.discover_detectraptor_evtx_partitions(
            api, hunt_id=hunt_id, time_predicate=predicates.get(evtx, ""),
            time_environment=environment, detection_regex=detection_regex)
        sources.extend(runtime.detectraptor_evtx_partition_source(
            org_id=org_id, hunt_id=hunt_id, partition=partition, watermark=cutoff)
            for partition in partitions)
    aliases: dict[str, Any] = {}
    references = coordinator.ensure_analysis_source_aliases(
        aliases, sources, scope_type="hunt", scope_id=hunt_id)

    def segments():
        yield from runtime.iter_hunt_result_segments(
            api, org_id=org_id, hunt_id=hunt_id,
            artifacts=[name for name in artifacts if name != evtx], cutoff=cutoff,
            projections=projections, time_predicates=predicates, time_environment=environment)
        if evtx in artifacts:
            yield from runtime.iter_detectraptor_evtx_detection_segments(
                api, org_id=org_id, hunt_id=hunt_id, cutoff=cutoff, partitions=partitions,
                projection=projections.get(evtx), time_predicate=predicates.get(evtx, ""),
                time_environment=environment, detection_regex=detection_regex)

    counts = {name: dict(row_count=0, chunk_count=0, input_tokens=0) for name in artifacts}
    acquired = 0

    def acquired_segment(rows: int) -> None:
        nonlocal acquired
        acquired += rows
        if progress_callback:
            progress_callback(dict(phase="preparing", status="running", rows=acquired,
                                   ai_review_status="skipped"))

    for chunk in coordinator.iter_streaming_chunks(
        coordinator._time_filter_segments(segments(), scopes), profiles=profiles,
        source_references=references,
        maximum_tokens=limits.maximum_evidence_tokens_per_item,
        encoding_name=limits.token_encoding, analysis_id="preparation",
        on_segment=acquired_segment,
    ):
        item = counts[chunk["artifact"]]
        item["row_count"] += chunk["row_count"]
        item["chunk_count"] += 1
        item["input_tokens"] += chunk["input_tokens"]
    # Publication happens only after the iterator and its terminal checks finish.
    destination = hunt_root / "analysis" / "analysis-preparation.json"
    result = dict(
        schema_version=1, action="hunt_prepared", status="prepared",
        hunt_id=hunt_id, ai_review_status="skipped", review_complete=False,
        result_review_coverage="not_reviewed", reviewed_row_count=0,
        source_stream_complete=True, server_cutoff=cutoff,
        acquired_row_count=acquired, row_count=sum(x["row_count"] for x in counts.values()),
        chunk_count=sum(x["chunk_count"] for x in counts.values()), artifacts=counts,
        artifact_policy=policy.metadata(), time_filter=provenance,
        source_aliases=aliases.get("source_aliases", {}), detection_regex=detection_regex,
        raw_evidence_persisted=False, analysis_plan_file=str(destination),
        chat_summary=f"Hunt {hunt_id}: {acquired:,} rows prepared; AI review skipped. "
                     f"Plan: {destination}",
    )
    atomic_io.write_json_atomic(destination, result, sort_keys=True)
    return result
