from __future__ import annotations

import asyncio
import csv
import copy
import io
import json
import os
import re
import tempfile
import threading
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import grpc

from vraptor.analyze import limits as analysis_limits
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentResult
from vraptor.agent.runtime import AgentRuntimeLimits
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import flow as flow_analysis
from vraptor.analyze import coordinator as flow_analysis_coordinator
from vraptor.analyze import flow_runtime as flow_analysis_runtime


TEST_LIMITS = analysis_limits.resolve_analysis_limits({})


def execute_streaming_chunk_work(*args, **kwargs):
    return asyncio.run(
        flow_analysis_coordinator._execute_streaming_chunk_work_async(*args, **kwargs)
    )


def execute_streaming_chunks(**kwargs):
    return asyncio.run(
        flow_analysis_coordinator.execute_streaming_chunks_async(**kwargs)
    )


def flow_row(
    client_id: str,
    flow_id: str,
    *,
    state: str = "FINISHED",
    active_time: str = "2026-08-13T09:00:00Z",
    artifact: str = "Artifact.Test",
) -> dict:
    return {
        "ClientId": client_id,
        "Flow": {
            "session_id": flow_id,
            "state": state,
            "active_time": active_time,
            "total_collected_rows": 1,
            "artifacts_with_results": [artifact],
        },
    }


class FakeFlowApi:
    org_id = "root"
    server_identity = "fake-flow-api-server"

    def __init__(
        self,
        inventory: list[dict],
        rows: dict[tuple[str, str], list[dict]],
        *,
        cutoff: str = "2026-08-13T10:00:00Z",
    ):
        self.inventory = inventory
        self.rows = rows
        self.cutoff = cutoff
        self.flow_queries: list[dict] = []
        self.result_queries: list[dict] = []

    def query(self, vql, env=None, **_kwargs):
        env = dict(env or {})
        if "ServerCutoff" in vql:
            return [{"ServerCutoff": self.cutoff}]
        if "FROM clients()" in vql:
            return []
        if "hunt_flows(" not in vql:
            raise AssertionError(vql)
        match = re.search(r"\bLIMIT\s+(\d+)\s*$", vql)
        if not match:
            raise AssertionError(vql)
        self.flow_queries.append({**env, "VQL": vql})
        start = int(env["StartRow"])
        return self.inventory[start : start + int(match.group(1))]

    def query_batches_with_metadata(self, vql, env=None, **kwargs):
        env = dict(env or {})
        if "hunt_results(" in vql:
            artifact = str(env["ArtifactName"])
            values = []
            for inventory_row in self.inventory:
                client_id, flow_id = flow_analysis.flow_identifiers(inventory_row)
                if artifact not in flow_analysis.flow_result_sources(inventory_row):
                    continue
                for raw in self.rows.get((client_id, flow_id), []):
                    values.append(
                        {"ClientId": client_id, "FlowId": flow_id, **dict(raw)}
                    )
            def evidence_text(row):
                event_data = row.get("EventData")
                value = (
                    event_data.get("ScriptBlockText")
                    if isinstance(event_data, dict)
                    else None
                )
                if value in (None, ""):
                    value = row.get("Message")
                if value in (None, ""):
                    value = event_data
                if isinstance(value, str):
                    return value
                return json.dumps(value, sort_keys=True, default=str)

            def detection_name(row):
                raw = row.get("Detection")
                return str(
                    (raw.get("Name") if isinstance(raw, dict) else raw) or ""
                )

            if (
                "Detection.Name =~ RequestedDetection" in vql
                and env.get("RequestedDetection")
            ):
                values = [
                    row
                    for row in values
                    if re.search(str(env["RequestedDetection"]), detection_name(row))
                ]

            if env.get("SelectedStackEvidenceJson") is not None:
                selected_evidence = {
                    str(value)
                    for value in json.loads(env["SelectedStackEvidenceJson"])
                }
                values = [
                    row for row in values if evidence_text(row) in selected_evidence
                ]
            if "LET StackGroups" in vql:
                groups = Counter(evidence_text(row) for row in values)
                values = [
                    {
                        "RowCount": sum(groups.values()),
                        "GroupCount": len(groups),
                        "SingletonGroupCount": sum(
                            1 for count in groups.values() if count == 1
                        ),
                        "LargestGroupRows": max(groups.values(), default=0),
                    }
                ]
                query_type = "detectraptor_stack_census"
            elif "GROUP BY StackEvidence" in vql:
                grouped = {}
                for row in values:
                    evidence = evidence_text(row)
                    record = grouped.setdefault(
                        evidence,
                        {
                            "StackEvidence": evidence,
                            "EvidenceField": (
                                "EventData.ScriptBlockText"
                                if isinstance(row.get("EventData"), dict)
                                and row["EventData"].get("ScriptBlockText")
                                else "Message"
                                if row.get("Message")
                                else "EventData"
                            ),
                            "GroupRows": 0,
                            "FirstSeen": str(row.get("EventTime") or ""),
                            "LastSeen": str(row.get("EventTime") or ""),
                            **row,
                        },
                    )
                    record["GroupRows"] += 1
                    record["FirstSeen"] = min(
                        str(record.get("FirstSeen") or ""),
                        str(row.get("EventTime") or ""),
                    )
                    record["LastSeen"] = max(
                        str(record.get("LastSeen") or ""),
                        str(row.get("EventTime") or ""),
                    )
                values = sorted(grouped.values(), key=lambda row: row["GroupRows"])
                query_type = "detectraptor_stack_groups"
            elif "GROUP BY Detection" in vql:
                counts = {}
                for row in values:
                    detection = detection_name(row) or None
                    metrics = counts.setdefault(
                        detection,
                        {"count": 0, "total": 0, "maximum": 0, "over": 0},
                    )
                    length = len(evidence_text(row))
                    metrics["count"] += 1
                    metrics["total"] += length
                    metrics["maximum"] = max(metrics["maximum"], length)
                    metrics["over"] += int(length > 4096)
                values = [
                    {
                        "Detection": detection,
                        "RowCount": metrics["count"],
                        "TotalEvidenceChars": metrics["total"],
                        "MaxEvidenceChars": metrics["maximum"],
                        "RowsOverPreview": metrics["over"],
                    }
                    for detection, metrics in sorted(
                        counts.items(),
                        key=lambda item: (
                            item[1]["count"], item[0] is None, item[0] or ""
                        ),
                    )
                ]
                query_type = "detectraptor_detection_discovery"
            else:
                if "Detection.Name = PartitionDetection" in vql:
                    requested = str(env["PartitionDetection"])
                    values = [
                        row
                        for row in values
                        if str(
                            (
                                detection_name(row)
                            )
                        )
                        == requested
                    ]
                elif "NOT Detection.Name" in vql:
                    values = [
                        row
                        for row in values
                        if not str(
                            (
                                row.get("Detection", {}).get("Name")
                                if isinstance(row.get("Detection"), dict)
                                else row.get("Detection")
                            )
                            or ""
                        )
                    ]
                if env.get("SelectedStackEvidenceJson") is not None:
                    values = [
                        {**row, "StackEvidence": evidence_text(row)}
                        for row in values
                    ]
                query_type = "hunt_results"
        elif "parse_json_array(data=SourcesJson)" in vql:
            descriptors = json.loads(env["SourcesJson"])
            values = []
            for descriptor in descriptors:
                client_id = str(descriptor["ClientId"])
                flow_id = str(descriptor["FlowId"])
                artifact = str(descriptor["ArtifactName"])
                for raw in self.rows.get((client_id, flow_id), []):
                    values.append(
                        {
                            "_SourceClientId": client_id,
                            "_SourceFlowId": flow_id,
                            "_SourceArtifact": artifact,
                            **dict(raw),
                        }
                    )
            query_type = "batched_source"
            artifact = ",".join(sorted({item["ArtifactName"] for item in descriptors}))
        elif "FROM source(" in vql:
            client_id = str(env["ClientId"])
            flow_id = str(env["FlowId"])
            artifact = str(env["ArtifactName"])
            values = list(self.rows.get((client_id, flow_id), []))
            query_type = "source"
        else:
            raise AssertionError(vql)
        self.result_queries.append(
            {
                "type": query_type,
                "artifact": artifact,
                "max_row": kwargs["max_row"],
                "timeout": kwargs.get("timeout", 0),
                "source_count": len(descriptors) if query_type == "batched_source" else 0,
                "VQL": vql,
                "env": env,
            }
        )
        for offset in range(0, len(values), kwargs["max_row"]):
            batch = values[offset : offset + kwargs["max_row"]]
            encoded = [len(json.dumps(row).encode()) for row in batch]
            yield SimpleNamespace(
                rows=batch,
                row_count=len(batch),
                payload_bytes=sum(encoded),
                max_row_bytes=max(encoded, default=0),
            )


class FakeTransportError(grpc.RpcError):
    def __init__(self, status: grpc.StatusCode):
        super().__init__()
        self.status = status

    def code(self):
        return self.status

    def details(self):
        return self.status.name


class FlakyDetectionApi(FakeFlowApi):
    """Inject deterministic transport resets into exact EVTX read queries."""

    def __init__(self, *args, failures=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.failures = {
            str(key): list(values) for key, values in dict(failures or {}).items()
        }
        self.attempts = Counter()
        self.reconnect_count = 0

    def reconnect(self):
        self.reconnect_count += 1

    @staticmethod
    def _failure_key(vql, env):
        if env.get("SelectedStackEvidenceJson") is not None:
            return f"context:{env.get('PartitionDetection', '')}"
        if "LET StackGroups" in vql:
            return f"census:{env.get('PartitionDetection', '')}"
        if "GROUP BY StackEvidence" in vql:
            return f"groups:{env.get('PartitionDetection', '')}"
        if "Detection.Name = PartitionDetection" in vql:
            return f"direct:{env.get('PartitionDetection', '')}"
        return ""

    def query_batches_with_metadata(self, vql, env=None, **kwargs):
        env = dict(env or {})
        key = self._failure_key(vql, env)
        if key:
            self.attempts[key] += 1
        mode = self.failures.get(key, []).pop(0) if self.failures.get(key) else ""
        if mode == "before":
            raise FakeTransportError(grpc.StatusCode.UNAVAILABLE)
        for batch in super().query_batches_with_metadata(vql, env, **kwargs):
            if mode == "mid" and batch.rows:
                first = [dict(batch.rows[0])]
                encoded = len(json.dumps(first[0]).encode())
                yield SimpleNamespace(
                    rows=first,
                    row_count=1,
                    payload_bytes=encoded,
                    max_row_bytes=encoded,
                )
                raise FakeTransportError(grpc.StatusCode.UNAVAILABLE)
            yield batch


class FlowAnalysisTest(unittest.TestCase):
    def test_exact_flow_time_query_filters_before_projection_and_keeps_ordinals(self):
        query = flow_analysis_runtime._exact_flow_query(
            ["EventTime", "Detection.Name AS Detection"],
            "((EventTime > AnalysisTimeAfter AND EventTime < AnalysisTimeBefore))",
        )

        self.assertIn("FROM items(item={", query)
        self.assertIn(
            "_key + 1 AS _AnalysisSourceRowNumber",
            query,
        )
        self.assertLess(query.index("WHERE ((EventTime"), query.index("SELECT EventTime"))
        self.assertIn("_AnalysisSourceRowNumber\nFROM ScopedRows", query)

    def test_exact_flow_time_query_binds_bounds_only_when_predicate_exists(self):
        artifact = "Artifact.Test"
        api = FakeFlowApi(
            [],
            {("C.1", "F.1"): [{"EventTime": "2026-08-13T09:30:00Z"}]},
        )
        source = flow_analysis.FlowSource(
            org_id="root",
            client_id="C.1",
            flow_id="F.1",
            artifact=artifact,
        )

        list(
            flow_analysis_runtime.iter_flow_segments(
                api,
                [source],
                projections={artifact: ["EventTime"]},
                time_predicates={
                    artifact: "((EventTime > AnalysisTimeAfter))"
                },
                time_environment={
                    "AnalysisTimeAfter": "2026-08-13T09:00:00Z"
                },
            )
        )
        bounded_query = api.result_queries[-1]
        self.assertIn("FROM items(item={", bounded_query["VQL"])
        self.assertEqual(
            bounded_query["env"]["AnalysisTimeAfter"],
            "2026-08-13T09:00:00Z",
        )

        api.result_queries.clear()
        list(
            flow_analysis_runtime.iter_flow_segments(
                api,
                [source],
                projections={artifact: ["EventTime"]},
                time_environment={
                    "AnalysisTimeAfter": "2026-08-13T09:00:00Z"
                },
            )
        )
        unbounded_query = api.result_queries[-1]
        self.assertNotIn("FROM items(item={", unbounded_query["VQL"])
        self.assertNotIn("WHERE", unbounded_query["VQL"])
        self.assertNotIn("AnalysisTimeAfter", unbounded_query["env"])

    def test_detectraptor_family_guidance_is_detection_scoped(self):
        bits = "\n".join(
            flow_analysis_coordinator._detectraptor_analysis_guidance(
                "T1197-Suspicious BitsTransfer Activity"
            )
        )
        powershell = "\n".join(
            flow_analysis_coordinator._detectraptor_analysis_guidance(
                "PowerShell long script"
            )
        )
        unrelated = "\n".join(
            flow_analysis_coordinator._detectraptor_analysis_guidance(
                "Suspicious service creation"
            )
        )

        self.assertIn("BITS triage:", bits)
        self.assertNotIn("PowerShell triage:", bits)
        self.assertIn("PowerShell triage:", powershell)
        self.assertNotIn("BITS triage:", powershell)
        self.assertNotIn("BITS triage:", unrelated)
        self.assertNotIn("PowerShell triage:", unrelated)
        self.assertIn("detection as a lead, not a finding", unrelated)

    def test_read_only_transport_retry_classification_is_narrow(self):
        self.assertTrue(
            flow_analysis_runtime.is_retryable_read_only_transport_error(
                FakeTransportError(grpc.StatusCode.UNAVAILABLE),
                rows_received=10,
            )
        )
        self.assertTrue(
            flow_analysis_runtime.is_retryable_read_only_transport_error(
                FakeTransportError(grpc.StatusCode.DEADLINE_EXCEEDED),
                rows_received=0,
            )
        )
        self.assertFalse(
            flow_analysis_runtime.is_retryable_read_only_transport_error(
                FakeTransportError(grpc.StatusCode.DEADLINE_EXCEEDED),
                rows_received=1,
            )
        )
        self.assertFalse(
            flow_analysis_runtime.is_retryable_read_only_transport_error(
                FakeTransportError(grpc.StatusCode.CANCELLED),
                rows_received=0,
            )
        )

    def test_detectraptor_transport_backoff_is_bounded_and_reconnects(self):
        api = SimpleNamespace(reconnect=mock.Mock())

        async def scenario():
            with mock.patch.object(
                flow_analysis_coordinator.asyncio,
                "sleep",
                new=mock.AsyncMock(),
            ) as sleep:
                observed = [
                    await flow_analysis_coordinator._detectraptor_transport_retry_wait(
                        api, attempt=attempt
                    )
                    for attempt in (1, 2, 3)
                ]
            return observed, sleep.await_args_list

        observed, sleep_calls = asyncio.run(scenario())

        self.assertEqual(observed, [2.0, 5.0, 15.0])
        self.assertEqual(
            [call.args[0] for call in sleep_calls],
            [2.0, 5.0, 15.0],
        )
        self.assertEqual(api.reconnect.call_count, 3)

    def test_detectraptor_query_timeout_setting_is_positive(self):
        with mock.patch.dict(
            os.environ,
            {
                flow_analysis_runtime.DETECTRAPTOR_QUERY_TIMEOUT_ENV: "45",
            },
        ):
            self.assertEqual(
                flow_analysis_runtime.detectraptor_query_timeout_seconds(), 45
            )

        with mock.patch.dict(
            os.environ,
            {flow_analysis_runtime.DETECTRAPTOR_QUERY_TIMEOUT_ENV: "0"},
        ), self.assertRaisesRegex(ValueError, "greater than zero"):
            flow_analysis_runtime.detectraptor_query_timeout_seconds()

    def test_retire_specialized_analysis_removes_fully_superseded_state(self):
        state = {
            "specialized_analysis": {
                "artifacts": {
                    "DetectRaptor.Windows.Detection.MFT": {
                        "mode": "generic-stack-streaming"
                    }
                }
            }
        }

        retired = flow_analysis_coordinator.retire_specialized_analysis(
            state,
            ["DetectRaptor.Windows.Detection.MFT"],
        )

        self.assertEqual(
            retired,
            ["DetectRaptor.Windows.Detection.MFT"],
        )
        self.assertNotIn("specialized_analysis", state)

    def test_retire_specialized_analysis_preserves_mixed_state(self):
        state = {
            "specialized_analysis": {
                "artifacts": {
                    "DetectRaptor.Windows.Detection.MFT": {},
                    "Windows.System.Pslist": {},
                }
            }
        }

        retired = flow_analysis_coordinator.retire_specialized_analysis(
            state,
            ["DetectRaptor.Windows.Detection.MFT"],
        )

        self.assertEqual(retired, [])
        self.assertIn("specialized_analysis", state)

    def spec(self, model: str = "test") -> ResolvedAgentExecution:
        route = ResolvedAgentRoute(
            provider="openai",
            model=model,
            protocol="responses",
            reasoning_effort="",
            timeout_seconds=60,
            max_retries=2,
            max_concurrency=2,
        )
        return ResolvedAgentExecution(route=route)

    def test_hunt_analysis_identity_changes_with_resolved_route(self):
        policy = {"maximum_input_tokens": 10_000}
        first = flow_analysis_coordinator.analysis_id_for(
            scope_type="hunt",
            question="What is suspicious?",
            profile_hash="profile",
            policy_limits=policy,
            spec=self.spec("model-one"),
        )
        second = flow_analysis_coordinator.analysis_id_for(
            scope_type="hunt",
            question="What is suspicious?",
            profile_hash="profile",
            policy_limits=policy,
            spec=self.spec("model-two"),
        )

        self.assertNotEqual(first, second)

    def test_hunt_analysis_identity_changes_with_task_output_contract(self):
        policy = {"maximum_input_tokens": 10_000}
        targeted = flow_analysis_coordinator.analysis_id_for(
            scope_type="hunt",
            question="What is suspicious?",
            profile_hash="profile",
            policy_limits=policy,
            spec=self.spec(),
            task_mode="targeted_hunt",
            response_depth="standard",
        )
        assessment = flow_analysis_coordinator.analysis_id_for(
            scope_type="hunt",
            question="What is suspicious?",
            profile_hash="profile",
            policy_limits=policy,
            spec=self.spec(),
            task_mode="compromise_assessment",
            response_depth="rapid",
        )

        self.assertNotEqual(targeted, assessment)

    @staticmethod
    def accepted_chunks(*, plan, provenance, **_kwargs):
        outcomes = {}
        for chunk in plan["chunks"]:
            ref = sorted(provenance[chunk["chunk_id"]])[0]
            outcomes[chunk["chunk_id"]] = {
                "status": "accepted",
                "accepted_at": "2026-08-13T10:00:00Z",
                "attempts": 1,
                "result": {
                    "task_id": chunk["task_id"],
                    "artifact": chunk["artifact"],
                    "status": "complete",
                    "coverage": {
                        "planned_rows": chunk["row_count"],
                        "reviewed_rows": chunk["row_count"],
                    },
                    "answer": "Grounded chunk result.",
                    "findings": [
                        {
                            "id": "F1",
                            "summary": "Suspicious event.",
                            "confidence": "high",
                            "domains": ["execution"],
                            "evidence": [
                                {
                                    "artifact": chunk["artifact"],
                                    "ref": ref,
                                    "fields": {"Value": "representative"},
                                }
                            ],
                        }
                    ],
                    "relevant_context": [],
                    "limitations": [],
                    "bounded_follow_up": [],
                },
            }
        return {"status": "complete"}, outcomes

    @staticmethod
    def accepted_streaming_chunks(
        *, work_items, progress_callback=None, active_callback=None, **_kwargs
    ):
        for work in work_items:
            chunk = dict(work["chunk"])
            chunk_id = str(dict(work["manifest"])["chunk_id"])
            ref = sorted(dict(work["provenance"]))[0]
            if active_callback is not None:
                active_callback(1)
            if progress_callback is not None:
                progress_callback(
                    {
                        "phase": "chunk",
                        "task_id": str(work["task"].task_id),
                        "chunk_id": chunk_id,
                        "status": "accepted",
                    }
                )
            yield {
                "status": "accepted",
                "chunk_id": chunk_id,
                "attempts": 1,
                "result": {
                    "task_id": chunk["task_id"],
                    "artifact": chunk["artifact"],
                    "status": "complete",
                    "coverage": {
                        "planned_rows": chunk["row_count"],
                        "reviewed_rows": chunk["row_count"],
                    },
                    "answer": "Grounded chunk result.",
                    "findings": [
                        {
                            "id": "F1",
                            "summary": "Suspicious event.",
                            "confidence": "high",
                            "domains": ["execution"],
                            "evidence": [
                                {
                                    "artifact": chunk["artifact"],
                                    "ref": ref,
                                    "fields": {"Value": "representative"},
                                }
                            ],
                        }
                    ],
                    "relevant_context": [],
                    "limitations": [],
                    "bounded_follow_up": [],
                },
            }
        if active_callback is not None:
            active_callback(0)

    @staticmethod
    def accepted_synthesis(*, results, **_kwargs):
        findings = [
            copy.deepcopy(finding)
            for result in results
            for finding in result.get("findings") or []
        ]
        relevant_context = [
            copy.deepcopy(item)
            for result in results
            for item in result.get("relevant_context") or []
        ]
        reviewed = sum(
            int(dict(result.get("coverage") or {}).get("reviewed_rows") or 0)
            for result in results
        )
        return {
            "status": "complete",
            "host_result": {
                "status": "complete",
                "coverage": {"planned_rows": reviewed, "reviewed_rows": reviewed},
                "answer": "Grounded cumulative result.",
                "findings": findings,
                "relevant_context": relevant_context,
                "limitations": [],
                "bounded_follow_up": [],
            },
        }

    @staticmethod
    def fallback_synthesis(*, results, **_kwargs):
        findings = [
            copy.deepcopy(finding)
            for result in results
            for finding in result.get("findings") or []
        ]
        reviewed = sum(
            int(dict(result.get("coverage") or {}).get("reviewed_rows") or 0)
            for result in results
        )
        return {
            "status": "complete_with_failures",
            "host_result": {
                "status": "complete_with_failures",
                "coverage": {
                    "planned_rows": reviewed,
                    "reviewed_rows": reviewed,
                },
                "answer": (
                    "Automated hunt synthesis could not be accepted. "
                    "Deterministic fallback retained grounded findings."
                ),
                "findings": findings,
                "relevant_context": [],
                "limitations": ["Unprojected field was rejected."],
                "bounded_follow_up": ["Rerun the full analysis for synthesis retry."],
            },
            "tasks": [
                {
                    "task_id": "hunt-analysis-synthesis",
                    "stage": "hunt-synthesis",
                    "status": "failed",
                    "error": "invalid evidence field: Channel" + ("x" * 4_096),
                }
            ],
        }

    def run_analysis(
        self,
        api,
        root: Path,
        *,
        update=False,
        targeted=0,
        target_coverage="partial",
        synthesis=None,
        streaming=None,
        debug_validation=False,
        artifact="Artifact.Test",
        time_scope=None,
        detection_regex="",
    ):
        with mock.patch.object(
            flow_analysis_coordinator,
            "execute_streaming_chunks_async",
            side_effect=streaming or self.accepted_streaming_chunks,
        ), mock.patch.object(
            flow_analysis_coordinator,
            "_synthesize_transient_results",
            side_effect=synthesis or self.accepted_synthesis,
        ), mock.patch.object(
            flow_analysis_coordinator.asyncio,
            "sleep",
            new=mock.AsyncMock(),
        ):
            return flow_analysis_coordinator.analyze_hunt_flows(
                api,
                org_id="root",
                hunt_id="H.1",
                hunt_state="RUNNING",
                reported_result_rows=sum(len(value) for value in api.rows.values()),
                target_execution_coverage=target_coverage,
                targeted_client_count=targeted,
                question="What is suspicious?",
                hunt_root=root,
                update=update,
                selected_artifacts=(
                    [artifact] if isinstance(artifact, str) else list(artifact)
                ),
                limits=replace(
                    TEST_LIMITS,
                    maximum_evidence_tokens_per_item=1_000,
                ),
                debug_validation=debug_validation,
                spec=self.spec(),
                time_scope=time_scope,
                detection_regex=detection_regex,
            )

    def test_hunt_flow_inventory_is_exhaustively_paged(self):
        api = FakeFlowApi(
            [flow_row(f"C.{index}", f"F.{index}") for index in range(5)], {}
        )
        observed = flow_analysis_runtime.enumerate_hunt_flows(api, "H.1", page_rows=2)
        self.assertEqual(len(observed), 5)
        self.assertEqual([int(item["StartRow"]) for item in api.flow_queries], [0, 2, 4])

    def test_full_analysis_uses_one_hunt_results_query_per_artifact(self):
        inventory = [
            flow_row("C.1", "F.1", artifact="Artifact.One"),
            flow_row("C.2", "F.2", artifact="Artifact.Two"),
        ]
        api = FakeFlowApi(inventory, {("C.1", "F.1"): [{"V": 1}], ("C.2", "F.2"): [{"V": 2}]})
        segments = list(
            flow_analysis_runtime.iter_hunt_result_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                artifacts=["Artifact.One", "Artifact.Two"],
                cutoff=api.cutoff,
            )
        )
        self.assertEqual(sum(item.row_count for item in segments), 2)
        self.assertEqual([item["type"] for item in api.result_queries], ["hunt_results", "hunt_results"])

    def test_hunt_segments_respect_byte_ceiling_before_row_ceiling(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "x" * 80}, {"Value": "y" * 80}]},
        )
        segments = list(
            flow_analysis_runtime.iter_hunt_result_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                artifacts=["Artifact.Test"],
                cutoff=api.cutoff,
                segment_rows=5_000,
                segment_bytes=120,
            )
        )
        self.assertEqual([segment.row_count for segment in segments], [1, 1])

    def test_hunt_query_applies_trusted_projection_without_filtering_rows(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one", "Unused": "large"}]},
        )
        segments = list(
            flow_analysis_runtime.iter_hunt_result_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                artifacts=["Artifact.Test"],
                cutoff=api.cutoff,
                projections={"Artifact.Test": ["Value"]},
            )
        )
        self.assertEqual(sum(segment.row_count for segment in segments), 1)
        self.assertIn("SELECT Value", api.result_queries[0]["VQL"])
        self.assertNotIn("WHERE", api.result_queries[0]["VQL"])
        self.assertNotIn("AnalysisTimeAfter", api.result_queries[0]["env"])
        self.assertNotIn("AnalysisTimeBefore", api.result_queries[0]["env"])

    def test_hunt_query_applies_time_filter_before_transport(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"EventTime": "2026-08-13T09:30:00Z"}]},
        )
        segments = list(
            flow_analysis_runtime.iter_hunt_result_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                artifacts=["Artifact.Test"],
                cutoff=api.cutoff,
                time_predicates={
                    "Artifact.Test": (
                        "(EventTime > AnalysisTimeAfter AND "
                        "EventTime < AnalysisTimeBefore)"
                    )
                },
                time_environment={
                    "AnalysisTimeAfter": "2026-08-13T09:00:00Z",
                    "AnalysisTimeBefore": "2026-08-13T10:00:00Z",
                },
            )
        )
        self.assertEqual(sum(segment.row_count for segment in segments), 1)
        query = api.result_queries[0]
        self.assertIn("FROM hunt_results", query["VQL"])
        self.assertIn("\nWHERE (EventTime > AnalysisTimeAfter", query["VQL"])
        self.assertEqual(
            query["env"]["AnalysisTimeAfter"], "2026-08-13T09:00:00Z"
        )
        self.assertEqual(
            query["env"]["AnalysisTimeBefore"], "2026-08-13T10:00:00Z"
        )

    def test_detectraptor_evtx_discovers_and_streams_each_detection(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:20:00Z"},
                    {"Detection": {"Name": "Rare"}, "EventTime": "2026-08-13T09:30:00Z"},
                    {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:40:00Z"},
                ]
            },
        )
        predicate = (
            "EventTime > AnalysisTimeAfter AND EventTime < AnalysisTimeBefore"
        )
        environment = {
            "AnalysisTimeAfter": "2026-08-13T09:00:00Z",
            "AnalysisTimeBefore": "2026-08-13T10:00:00Z",
        }

        partitions = flow_analysis_runtime.discover_detectraptor_evtx_partitions(
            api,
            hunt_id="H.1",
            time_predicate=predicate,
            time_environment=environment,
        )
        stats = {}
        segments = list(
            flow_analysis_runtime.iter_detectraptor_evtx_detection_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                cutoff=api.cutoff,
                partitions=partitions,
                projection=["EventTime", "Detection.Name AS Detection"],
                time_predicate=predicate,
                time_environment=environment,
                stats=stats,
            )
        )

        self.assertEqual(
            [(item.detection, item.row_count) for item in partitions],
            [("Rare", 1), ("Common", 2)],
        )
        self.assertEqual(sum(segment.row_count for segment in segments), 3)
        self.assertEqual(stats["partition_count"], 2)
        self.assertEqual(stats["discovered_row_count"], 3)
        self.assertEqual(stats["reviewed_row_count"], 3)
        self.assertEqual(
            [item["type"] for item in api.result_queries],
            [
                "detectraptor_detection_discovery",
                "hunt_results",
                "hunt_results",
            ],
        )
        discovery_query = api.result_queries[0]["VQL"]
        self.assertTrue(discovery_query.endswith("ORDER BY RowCount"))
        self.assertNotIn("ORDER BY RowCount,", discovery_query)
        for query in api.result_queries:
            self.assertNotIn("EvidenceSHA256", query["VQL"])
        for query in api.result_queries[1:]:
            self.assertIn("AnalysisTimeAfter", query["VQL"])
            self.assertIn("Detection.Name", query["VQL"])
            self.assertIn("LET ScopedRows = SELECT *", query["VQL"])
            self.assertEqual(query["VQL"].count("\nWHERE "), 1)

    def test_detectraptor_evtx_partition_accounting_fails_closed(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): [{"Detection": {"Name": "Rule"}}]},
        )
        partitions = [
            flow_analysis_runtime.DetectionPartition(
                detection="Rule",
                row_count=2,
                partition_id="partition",
            )
        ]

        with self.assertRaisesRegex(RuntimeError, "fewer rows than"):
            list(
                flow_analysis_runtime.iter_detectraptor_evtx_detection_segments(
                    api,
                    org_id="root",
                    hunt_id="H.1",
                    cutoff=api.cutoff,
                    partitions=partitions,
                )
            )

    def test_detectraptor_regex_scope_and_exact_stack_census(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        selected = "Powershell Suspicious CommandLet - IN DEVELOPMENT"
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {
                        "Detection": {"Name": selected},
                        "Message": "same-script wrapper id=1",
                        "EventData": {"ScriptBlockText": "same-script"},
                        "EventTime": "2026-08-13T09:20:00Z",
                    },
                    {
                        "Detection": {"Name": selected},
                        "Message": "same-script wrapper id=2",
                        "EventData": {"ScriptBlockText": "same-script"},
                        "EventTime": "2026-08-13T09:21:00Z",
                    },
                    {
                        "Detection": {"Name": selected},
                        "Message": "unique-script",
                        "EventTime": "2026-08-13T09:22:00Z",
                    },
                    {
                        "Detection": {"Name": "Other detection"},
                        "Message": "other",
                    },
                ]
            },
        )
        pattern = r"^Powershell Suspicious CommandLet - IN DEVELOPMENT$"
        time_predicate = (
            "EventTime > AnalysisTimeAfter AND EventTime < AnalysisTimeBefore"
        )
        time_environment = {
            "AnalysisTimeAfter": "2026-08-13T09:00:00Z",
            "AnalysisTimeBefore": "2026-08-13T10:00:00Z",
        }

        partitions = flow_analysis_runtime.discover_detectraptor_evtx_partitions(
            api,
            hunt_id="H.1",
            time_predicate=time_predicate,
            time_environment=time_environment,
            detection_regex=pattern,
        )
        census = flow_analysis_runtime.query_detectraptor_evtx_stack_census(
            api,
            hunt_id="H.1",
            partition=partitions[0],
            time_predicate=time_predicate,
            time_environment=time_environment,
            detection_regex=pattern,
        )
        stats = {}
        segments = list(
            flow_analysis_runtime.iter_detectraptor_evtx_stack_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                cutoff=api.cutoff,
                partition=partitions[0],
                census=census,
                time_predicate=time_predicate,
                time_environment=time_environment,
                detection_regex=pattern,
                stats=stats,
            )
        )
        same_group_row = next(
            dict(row)
            for segment in segments
            for row in segment.rows
            if int(row["OccurrenceCount"]) == 2
        )
        same_group = "S0001-R1"
        context, context_hashes = (
            flow_analysis_runtime.query_detectraptor_evtx_stack_context(
                api,
                hunt_id="H.1",
                partition=partitions[0],
                evidence_by_group={same_group: str(same_group_row["Payload"])},
                time_predicate=time_predicate,
                time_environment=time_environment,
                detection_regex=pattern,
            )
        )

        self.assertEqual([(item.detection, item.row_count) for item in partitions], [(selected, 3)])
        self.assertEqual(census.row_count, 3)
        self.assertEqual(census.group_count, 2)
        self.assertEqual(census.singleton_group_count, 1)
        self.assertEqual(census.largest_group_rows, 2)
        self.assertEqual(sum(segment.row_count for segment in segments), 2)
        self.assertEqual(stats["reviewed_row_count"], 3)
        self.assertEqual(same_group_row["Payload"], "same-script")
        self.assertEqual(
            list(same_group_row),
            [
                "Detection",
                "OccurrenceCount",
                "FirstSeen",
                "LastSeen",
                "PayloadField",
                "Payload",
            ],
        )
        self.assertEqual(len(context[same_group]), 2)
        self.assertEqual(len(context_hashes), 1)
        for query in api.result_queries:
            self.assertIn("Detection.Name =~ RequestedDetection", query["VQL"])
            self.assertIn("AnalysisTimeAfter", query["VQL"])
            self.assertIn("AnalysisTimeBefore", query["VQL"])
            self.assertEqual(query["env"]["RequestedDetection"], pattern)
            self.assertEqual(
                query["env"]["AnalysisTimeAfter"],
                time_environment["AnalysisTimeAfter"],
            )
            self.assertEqual(
                query["env"]["AnalysisTimeBefore"],
                time_environment["AnalysisTimeBefore"],
            )
        census_query = next(
            item for item in api.result_queries if item["type"] == "detectraptor_stack_census"
        )
        self.assertEqual(
            census.query_sha256,
            flow_analysis.sha256_identity(
                "detectraptor-evtx-exact-census-query",
                {"vql": census_query["VQL"], "environment": census_query["env"]},
            ),
        )
        group_query = next(
            item for item in api.result_queries if item["type"] == "detectraptor_stack_groups"
        )
        self.assertEqual(
            stats["query_sha256"],
            flow_analysis.sha256_identity(
                "detectraptor-evtx-exact-groups-query",
                {"vql": group_query["VQL"], "environment": group_query["env"]},
            ),
        )
        self.assertIn("Detection.Name = PartitionDetection", api.result_queries[-1]["VQL"])
        self.assertIn("ORDER BY EventTime", api.result_queries[-1]["VQL"])
        self.assertNotIn("ORDER BY Fqdn,", api.result_queries[-1]["VQL"])

    def test_detectraptor_stack_accounts_source_rows_without_filters(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        selected = "Powershell Suspicious CommandLet - IN DEVELOPMENT"
        rows = [
            {
                "Detection": {"Name": selected},
                "Message": "common-script",
                "EventTime": "2026-08-13T09:20:00Z",
            }
            for _index in range(1_100)
        ] + [
            {
                "Detection": {"Name": selected},
                "Message": "rare-script",
                "EventTime": "2026-08-13T09:21:00Z",
            }
        ]
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                detection_regex=(
                    r"^Powershell Suspicious CommandLet - IN DEVELOPMENT$"
                ),
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        self.assertEqual(result["analysis_method"], "full")
        self.assertEqual(result["accounted_row_count"], 1_101)
        self.assertEqual(result["reviewed_row_count"], 2)
        self.assertEqual(state["checkpoint"]["row_count"], 1_101)
        self.assertEqual(
            state["detectraptor_stack"]["partitions"][0]["mode"],
            "exact_stack",
        )
        self.assertEqual(
            state["detectraptor_stack"]["partitions"][0]["exact_group_count"],
            2,
        )

    def test_large_unique_detectraptor_detection_falls_back_to_direct(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        rows = [
            {
                "Detection": {"Name": "Mostly unique"},
                "Message": f"unique-script-{index}",
            }
            for index in range(1_001)
        ]
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(api, Path(directory), artifact=artifact)
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        partition = state["detectraptor_stack"]["partitions"][0]
        self.assertEqual(partition["mode"], "direct_fallback")
        self.assertEqual(partition["fallback_reason"], "insufficient_consolidation")
        self.assertEqual(result["accounted_row_count"], 1_001)
        self.assertEqual(result["model_input_row_count"], 1_001)
        direct_query = next(
            item
            for item in api.result_queries
            if item["type"] == "hunt_results"
            and "RequestedStackEvidence" not in item["env"]
        )
        self.assertIn(" AS Evidence", direct_query["VQL"])
        self.assertIn("EventData.ScriptBlockText", direct_query["VQL"])
        self.assertTrue(
            all(
                set(item["env"]).issubset(
                    {"HuntId", "ArtifactName", "PartitionDetection"}
                )
                for item in api.result_queries
            )
        )

    def test_detectraptor_census_failure_falls_back_to_direct(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        rows = [
            {"Detection": {"Name": "Census failure"}, "Message": "repeat"}
            for _index in range(1_001)
        ]
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
        )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis_runtime,
            "query_detectraptor_evtx_stack_census",
            side_effect=RuntimeError("census unavailable"),
        ):
            result = self.run_analysis(api, Path(directory), artifact=artifact)
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        partition = state["detectraptor_stack"]["partitions"][0]
        self.assertEqual(partition["mode"], "direct_fallback")
        self.assertEqual(
            partition["fallback_reason"], "census_failed_runtimeerror"
        )
        self.assertEqual(result["accounted_row_count"], 1_001)

    def test_mixed_artifact_accounting_preserves_generic_and_evtx_rows(self):
        evtx = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        generic = "Artifact.Generic"
        api = FakeFlowApi(
            [
                flow_row("C.1", "F.1", artifact=evtx),
                flow_row("C.2", "F.2", artifact=generic),
            ],
            {
                ("C.1", "F.1"): [
                    {
                        "Detection": {"Name": "Repeated"},
                        "Message": "same-script",
                    }
                    for _index in range(1_100)
                ],
                ("C.2", "F.2"): [{"Value": 1}, {"Value": 2}],
            },
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=[evtx, generic],
            )

        self.assertEqual(result["model_input_row_count"], 3)
        self.assertEqual(result["accounted_row_count"], 1_102)
        self.assertEqual(
            result["detectraptor_evtx_detection_partitions"][
                "reviewed_row_count"
            ],
            1_100,
        )

    def test_character_volume_triggers_census_below_row_threshold(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        rows = [
            {
                "Detection": {"Name": "Large payloads"},
                "Message": ("repeat" + "x" * 4_994),
            }
            for _index in range(200)
        ]
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
        )

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(api, Path(directory), artifact=artifact)
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        partition = state["detectraptor_stack"]["partitions"][0]
        self.assertGreaterEqual(partition["estimated_direct_chunks"], 10)
        self.assertEqual(partition["average_evidence_chars"], 5_000.0)
        self.assertEqual(partition["estimated_evidence_tokens"], 250_000)
        self.assertEqual(partition["mode"], "exact_stack")
        self.assertIn(
            "detectraptor_stack_census",
            [item["type"] for item in api.result_queries],
        )

    def test_exact_stack_uses_normal_csv_and_hydrates_reportable_groups(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        expected_script = "signed vendor health check,\tsecond\nline" + ("A" * 6_000)
        suspicious_script = 'powershell -enc "malicious,part"\tsecond\nline'
        rows = [
            {
                "Detection": {"Name": "PowerShell long script"},
                "EventData": {"ScriptBlockText": expected_script},
                "EventTime": "2026-08-13T09:20:00Z",
                "Fqdn": "host.example",
            }
            for _index in range(1_100)
        ] + [
            {
                "Detection": {"Name": "PowerShell long script"},
                "EventData": {"ScriptBlockText": suspicious_script},
                "EventTime": "2026-08-13T09:21:00Z",
                "Fqdn": "evil.example",
            }
        ]
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
        )
        reviewed_payloads = []
        captured_prompts = []

        def review_normal_chunks(*, work_items, **_kwargs):
            for work in work_items:
                prompt = work["task"].prompt
                captured_prompts.append(prompt)
                csv_text = prompt.split(
                    "--- CSV EVIDENCE START ---\n", 1
                )[1].split("\n--- CSV EVIDENCE END ---", 1)[0]
                csv_rows = list(csv.DictReader(io.StringIO(csv_text)))
                reviewed_payloads.extend(row["Payload"] for row in csv_rows)
                suspicious = next(
                    (row for row in csv_rows if row["Payload"] == suspicious_script),
                    None,
                )
                expected = next(
                    (row for row in csv_rows if row["Payload"] == expected_script),
                    None,
                )
                chunk = dict(work["chunk"])
                findings = []
                if suspicious is not None:
                    ref = suspicious["_SourceRef"]
                    findings.append(
                        {
                            "id": "F1",
                            "summary": "Malicious encoded command.",
                            "confidence": "high",
                            "domains": ["execution"],
                            "evidence": [
                                {
                                    "artifact": chunk["artifact"],
                                    "ref": ref,
                                    "fields": dict(work["source_rows"][ref]),
                                }
                            ],
                        }
                    )
                yield {
                    "status": "accepted",
                    "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                    "attempts": 1,
                    "result": {
                        "task_id": chunk["task_id"],
                        "artifact": chunk["artifact"],
                        "status": "complete",
                        "coverage": {
                            "planned_rows": chunk["row_count"],
                            "reviewed_rows": chunk["row_count"],
                        },
                        "answer": "Question-relevant exact-group review.",
                        "findings": findings,
                        "uplift_candidates": (
                            [
                                {
                                    "ref": expected["_SourceRef"],
                                    "scope": "global",
                                    "summary": "Stable signed vendor health-check script.",
                                    "fields": dict(
                                        work["source_rows"][expected["_SourceRef"]]
                                    ),
                                }
                            ]
                            if expected is not None
                            else []
                        ),
                        "relevant_context": [],
                        "limitations": [],
                        "bounded_follow_up": [],
                    },
                }

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                streaming=review_normal_chunks,
            )
            state_text = Path(result["analysis_state_file"]).read_text()
            state = json.loads(state_text)
            context = json.loads(
                Path(result["detectraptor_interesting_context_file"]).read_text()
            )
            uplift_path = Path(result["detectraptor_whitelist_candidates_file"])
            uplift_text = uplift_path.read_text()
            uplift_lines = uplift_text.splitlines(keepends=True)
            uplift_header = next(
                index
                for index, line in enumerate(uplift_lines)
                if not line.startswith("#")
            )
            uplift_rows = list(
                csv.DictReader(io.StringIO("".join(uplift_lines[uplift_header:])))
            )
            uplift_summary = (
                flow_analysis_coordinator._summarize_detectraptor_uplift_csv(
                    uplift_path
                )
            )
            report = Path(result["analysis_memory_file"]).read_text()

        self.assertCountEqual(reviewed_payloads, [expected_script, suspicious_script])
        self.assertTrue(captured_prompts)
        prompt = "\n".join(captured_prompts)
        self.assertIn("--- CSV EVIDENCE START ---", prompt)
        self.assertIn("RESULT\tfindings", prompt)
        self.assertIn("no_reportable_findings", prompt)
        self.assertIn("PowerShell triage:", prompt)
        self.assertIn("UPLIFT<TAB>SourceRef<TAB>global|site<TAB>reason", prompt)
        self.assertNotIn("ASSESSMENT\t", prompt)
        self.assertNotIn("GROUP\t", prompt)
        csv_text = captured_prompts[0].split(
            "--- CSV EVIDENCE START ---\n", 1
        )[1].split("\n--- CSV EVIDENCE END ---", 1)[0]
        headers = next(csv.reader(io.StringIO(csv_text)))
        self.assertEqual(
            headers,
            [
                "_SourceRef",
                "Detection",
                "OccurrenceCount",
                "FirstSeen",
                "LastSeen",
                "PayloadField",
                "Payload",
            ],
        )
        self.assertNotIn("GroupId", headers)
        self.assertNotIn("EvidenceLength", headers)
        self.assertNotIn("EvidencePreview", headers)
        partition_state = state["detectraptor_stack"]["partitions"][0]
        self.assertEqual(
            partition_state["group_review"]["protocol"],
            "reference-line-v3",
        )
        self.assertEqual(partition_state["group_review"]["reviewed_group_count"], 2)
        self.assertEqual(partition_state["group_review"]["reportable_group_count"], 1)
        self.assertEqual(partition_state["context_hydration"]["semantic_ai_passes"], 0)
        self.assertEqual(context["group_count"], 1)
        self.assertEqual(context["event_count"], 1)
        self.assertEqual(context["groups"][0]["events"][0]["fqdn"], "evil.example")
        self.assertEqual(len(uplift_rows), 1)
        self.assertEqual(uplift_rows[0]["Scope"], "global")
        self.assertEqual(uplift_rows[0]["OccurrenceCount"], "1100")
        self.assertEqual(uplift_rows[0]["Payload"], expected_script)
        self.assertEqual(uplift_summary["candidate_count"], 1)
        self.assertEqual(uplift_summary["global_count"], 1)
        self.assertNotIn(suspicious_script, uplift_text)
        self.assertIn("AI-selected findings - analyst review required", report)
        self.assertIn("DetectRaptor interesting event notes", report)
        self.assertIn("Potential whitelist opportunities", report)
        self.assertIn("Event context hydrated: 1/1", report)
        self.assertIn("Representative events:", report)
        self.assertIn("evil.example", report)
        self.assertTrue(result["candidate_payloads_persisted"])
        self.assertTrue(result["raw_evidence_persisted"])
        self.assertNotIn(suspicious_script, json.dumps(context))
        self.assertNotIn("detectraptor_stack_candidate_file", result)
        self.assertNotIn(expected_script, state_text)
        self.assertNotIn("evil.example", state_text)
        self.assertLess(len(state_text.encode("utf-8")), 64 * 1024)
        query_types = [item["type"] for item in api.result_queries]
        self.assertEqual(query_types.count("detectraptor_stack_groups"), 1)
        self.assertEqual(
            sum("SelectedStackEvidenceJson" in item["env"] for item in api.result_queries),
            1,
        )

    def test_detectraptor_evtx_partition_accepts_at_least_discovered_rows(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule"}, "Value": "initial"},
                    {"Detection": {"Name": "Rule"}, "Value": "added"},
                ]
            },
        )
        partitions = [
            flow_analysis_runtime.DetectionPartition(
                detection="Rule",
                row_count=1,
                partition_id="partition",
            )
        ]
        stats = {}

        segments = list(
            flow_analysis_runtime.iter_detectraptor_evtx_detection_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                cutoff=api.cutoff,
                partitions=partitions,
                stats=stats,
            )
        )

        self.assertEqual(sum(segment.row_count for segment in segments), 2)

    def test_detectraptor_exact_stack_accepts_growth_after_census(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule"}, "Message": "initial"},
                    {"Detection": {"Name": "Rule"}, "Message": "added"},
                ]
            },
        )
        partition = flow_analysis_runtime.DetectionPartition(
            detection="Rule",
            row_count=1,
            partition_id="partition",
        )
        census = flow_analysis_runtime.DetectionStackCensus(
            partition_id="partition",
            row_count=1,
            group_count=1,
            singleton_group_count=1,
            largest_group_rows=1,
        )
        stats = {}

        segments = list(
            flow_analysis_runtime.iter_detectraptor_evtx_stack_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                cutoff=api.cutoff,
                partition=partition,
                census=census,
                stats=stats,
            )
        )

        self.assertEqual(sum(segment.row_count for segment in segments), 2)
        self.assertEqual(stats["reviewed_row_count"], 2)
        self.assertEqual(stats["model_group_count"], 2)
        self.assertEqual(stats["discovered_row_count"], 1)

    def test_detectraptor_evtx_preserves_rows_without_detection_name(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": ""}, "Value": "empty"},
                    {"Detection": None, "Value": "missing"},
                ]
            },
        )
        partitions = flow_analysis_runtime.discover_detectraptor_evtx_partitions(
            api,
            hunt_id="H.1",
        )

        segments = list(
            flow_analysis_runtime.iter_detectraptor_evtx_detection_segments(
                api,
                org_id="root",
                hunt_id="H.1",
                cutoff=api.cutoff,
                partitions=partitions,
            )
        )

        self.assertEqual(len(partitions), 1)
        self.assertIsNone(partitions[0].detection)
        self.assertEqual(partitions[0].row_count, 2)
        self.assertEqual(sum(segment.row_count for segment in segments), 2)
        self.assertIn("NOT Detection.Name", api.result_queries[-1]["VQL"])

    def test_full_detectraptor_evtx_analysis_persists_partition_accounting(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:20:00Z"},
                    {"Detection": {"Name": "Rare"}, "EventTime": "2026-08-13T09:30:00Z"},
                    {"Detection": {"Name": "Common"}, "EventTime": "2026-08-13T09:40:00Z"},
                ]
            },
        )
        scope = analysis_time_scope.TimeScope.from_values(
            after="2026-08-13T09:00:00Z",
            before="2026-08-13T10:00:00Z",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_analysis(
                api,
                root,
                artifact=artifact,
                time_scope=scope,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())
            run_outputs = result["detectraptor_stack"]["run_outputs"]
            run_root = root / run_outputs["root"]
            self.assertEqual(
                (run_root / "detectraptor-interesting-context.json").read_text(),
                (root / "analysis" / "detectraptor-interesting-context.json").read_text(),
            )
            self.assertEqual(
                (run_root / "detectraptor_whitelist_candidates.csv").read_text(),
                (root / "analysis" / "detectraptor_whitelist_candidates.csv").read_text(),
            )
            self.assertEqual(
                (run_root / "analysis-hunt.md").read_text(),
                (root / "analysis-hunt.md").read_text(),
            )

        accounting = result["detectraptor_evtx_detection_partitions"]
        self.assertEqual(result["reviewed_row_count"], 3)
        self.assertEqual(result["planned_chunk_count"], 2)
        self.assertEqual(accounting["partition_count"], 2)
        self.assertEqual(accounting["discovered_row_count"], 3)
        self.assertEqual(accounting["reviewed_row_count"], 3)
        self.assertEqual(
            state["runs"][-1]["detectraptor_evtx_detection_partitions"],
            accounting,
        )
        self.assertEqual(len(state["source_aliases"]), 2)
        self.assertEqual(len(api.result_queries), 3)
        self.assertTrue(
            all(
                item["timeout"]
                == flow_analysis_runtime.DEFAULT_DETECTRAPTOR_QUERY_TIMEOUT_SECONDS
                for item in api.result_queries
            )
        )
        self.assertNotIn("EvidenceSHA256", "\n".join(
            query["VQL"] for query in api.result_queries
        ))

    def test_detectraptor_evtx_update_requires_full_rerun(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): [{"Detection": {"Name": "Rule"}}]},
        )

        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            RuntimeError,
            "--update is not supported for detection-partitioned",
        ):
            self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                update=True,
            )

    def test_detectraptor_evtx_acquisition_failure_is_terminal_in_state(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): [{"Detection": {"Name": "Rule"}}]},
        )
        bad_partition = flow_analysis_runtime.DetectionPartition(
            detection="Rule",
            row_count=2,
            partition_id="partition",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                flow_analysis_runtime,
                "discover_detectraptor_evtx_partitions",
                return_value=[bad_partition],
            ), self.assertRaisesRegex(RuntimeError, "fewer rows than"):
                self.run_analysis(api, root, artifact=artifact)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(state["active_analysis"]["phase"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"],
            "detectraptor_partition",
        )
        self.assertEqual(state["active_analysis"]["active_detection"], "Rule")
        self.assertEqual(state["active_analysis"]["partition_id"], "partition")
        self.assertEqual(
            state["active_analysis"]["detection_stage"],
            "initial_analysis",
        )
        self.assertEqual(state["runs"][-1]["status"], "failed")

    def test_detectraptor_transport_reset_discards_partial_detection_attempt(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FlakyDetectionApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule"}, "Message": "one"},
                    {"Detection": {"Name": "Rule"}, "Message": "two"},
                ]
            },
            failures={"direct:Rule": ["mid"]},
        )
        model_rows = []

        def counting_stream(*, work_items, **kwargs):
            for work in work_items:
                model_rows.extend(dict(work["source_rows"]).values())
                yield from self.accepted_streaming_chunks(
                    work_items=[work], **kwargs
                )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis,
            "DEFAULT_SEGMENT_ROWS",
            1,
        ):
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                streaming=counting_stream,
            )

        self.assertEqual(api.attempts["direct:Rule"], 2)
        self.assertEqual(api.reconnect_count, 1)
        self.assertEqual(result["reviewed_row_count"], 2)
        self.assertEqual(result["accounted_row_count"], 2)
        self.assertEqual(len(model_rows), 2)
        self.assertEqual(
            result["analysis_result"]["coverage"]["reviewed_rows"],
            2,
        )

    def test_detectraptor_single_chunk_skips_redundant_partition_synthesis(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule"}, "Message": "one"},
                    {"Detection": {"Name": "Rule"}, "Message": "two"},
                ]
            },
        )
        synthesis_scopes = []

        def record_synthesis(*, scope_id, results, **kwargs):
            synthesis_scopes.append(scope_id)
            return self.accepted_synthesis(results=results, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                synthesis=record_synthesis,
            )

        self.assertEqual(synthesis_scopes, ["H.1"])
        self.assertEqual(result["accounted_row_count"], 2)

    def test_detectraptor_multichunk_partition_restores_artifact_for_cumulative_synthesis(
        self,
    ):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {
                        "Detection": {"Name": "Large rule"},
                        "Message": f"row-{index}-" + ("x" * 2_500),
                    }
                    for index in range(20)
                ]
            },
        )
        synthesis_scopes = []

        def record_synthesis(*, scope_id, results, **kwargs):
            synthesis_scopes.append(scope_id)
            return self.accepted_synthesis(results=results, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                synthesis=record_synthesis,
            )

        self.assertEqual(len(synthesis_scopes), 2)
        self.assertTrue(synthesis_scopes[0].startswith("H.1:"))
        self.assertEqual(synthesis_scopes[1], "H.1")
        self.assertEqual(result["accounted_row_count"], 20)

    def test_detectraptor_cumulative_exception_terminalizes_partial_outputs(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule"}, "Message": "one"}
                ]
            },
        )

        def raise_cumulative(*, scope_id, results, **kwargs):
            if scope_id == "H.1":
                raise KeyError("artifact")
            return self.accepted_synthesis(results=results, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "synthesis failed closed"):
                self.run_analysis(
                    api,
                    root,
                    artifact=artifact,
                    synthesis=raise_cumulative,
                )
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            context = json.loads(
                (
                    root
                    / "analysis"
                    / "detectraptor-interesting-context.json"
                ).read_text()
            )
            report = (root / "analysis-hunt.md").read_text()

        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"], "cumulative_synthesis"
        )
        self.assertEqual(state["active_analysis"]["acquired_row_count"], 1)
        self.assertEqual(state["active_analysis"]["accepted_chunk_count"], 1)
        self.assertEqual(state["active_analysis"]["submitted_chunk_count"], 1)
        self.assertEqual(state["active_analysis"]["completed_chunk_count"], 1)
        self.assertEqual(context["status"], "failed")
        self.assertIn("Status: `failed`", report)
        self.assertIn("Report mode: progressive atomic checkpoint", report)

    def test_detectraptor_degraded_synthesis_preserves_partition_recovery(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        inventory = [flow_row("C.1", "F.1", artifact=artifact)]
        rows = {
            ("C.1", "F.1"): [
                {"Detection": {"Name": "Rule"}, "Message": "one"}
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_api = FlakyDetectionApi(inventory, rows)
            first = self.run_analysis(
                first_api,
                root,
                artifact=artifact,
                synthesis=self.fallback_synthesis,
            )
            degraded_state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

            second_api = FlakyDetectionApi(inventory, rows)
            second = self.run_analysis(second_api, root, artifact=artifact)
            completed_state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(first["synthesis_status"], "complete_with_failures")
        self.assertIn("detectraptor_recovery", degraded_state)
        self.assertEqual(
            degraded_state["detectraptor_recovery"]["partitions"][0]["status"],
            "completed",
        )
        self.assertEqual(second_api.attempts["direct:Rule"], 0)
        self.assertEqual(second["synthesis_status"], "complete")
        self.assertNotIn("detectraptor_recovery", completed_state)

    def test_detectraptor_report_consolidates_equivalent_exact_payload_notes(self):
        groups = [
            {
                "detection": "T1197-Suspicious BitsTransfer Activity",
                "confidence": "medium",
                "summary": "Unvalidated executable delivery.",
                "count": count,
                "payload_sha256": str(index),
                "first_seen": f"2026-08-{10 + index:02d}T00:00:00Z",
                "last_seen": f"2026-08-{11 + index:02d}T00:00:00Z",
                "events": [
                    {
                        "event_time": f"2026-08-{10 + index:02d}T00:00:00Z",
                        "fqdn": f"host{index}.example",
                        "client_id": f"C.{index}",
                        "username": "SYSTEM",
                        "channel": "Bits-Client/Operational",
                        "event_id": 59,
                        "source_ref": f"S1:R{index}",
                    }
                ],
            }
            for index, count in enumerate((590, 1, 1), start=1)
        ]

        report = "\n".join(
            flow_analysis_coordinator._render_detectraptor_report_notes(
                groups,
                context_ledger="analysis/detectraptor-interesting-context.json",
            )
        )

        self.assertEqual(report.count("### MEDIUM — T1197"), 1)
        self.assertIn("Occurrences: 592 across 3 endpoint(s)", report)
        self.assertIn("Exact payload variants: 3", report)
        self.assertEqual(report.count("Bits-Client/Operational"), 3)

    def test_detectraptor_restart_reuses_completed_detection_only(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        inventory = [flow_row("C.1", "F.1", artifact=artifact)]
        rows = {
            ("C.1", "F.1"): [
                {"Detection": {"Name": "Rare"}, "Message": "rare"},
                {"Detection": {"Name": "Common"}, "Message": "common-1"},
                {"Detection": {"Name": "Common"}, "Message": "common-2"},
            ]
        }
        first_api = FlakyDetectionApi(
            inventory,
            rows,
            failures={"direct:Common": ["before", "before", "before", "before"]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FakeTransportError):
                self.run_analysis(first_api, root, artifact=artifact)
            failed_state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            recovery = failed_state["detectraptor_recovery"]
            by_detection = {
                item["detection"]: item for item in recovery["partitions"]
            }
            self.assertEqual(by_detection["Rare"]["status"], "completed")
            self.assertEqual(by_detection["Common"]["status"], "failed")
            self.assertEqual(failed_state["checkpoint"], {})
            partial_report = (root / "analysis-hunt.md").read_text()
            self.assertIn("Status: `failed`", partial_report)
            self.assertIn("Rare", partial_report)
            self.assertIn("Common", partial_report)

            second_api = FlakyDetectionApi(inventory, rows)
            result = self.run_analysis(second_api, root, artifact=artifact)
            published_state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(second_api.attempts["direct:Rare"], 0)
        self.assertEqual(second_api.attempts["direct:Common"], 1)
        self.assertEqual(result["accounted_row_count"], 3)
        self.assertNotIn("detectraptor_recovery", published_state)

    def test_detectraptor_incompatible_resume_rebuilds_all_detections(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        inventory = [flow_row("C.1", "F.1", artifact=artifact)]
        rows = {
            ("C.1", "F.1"): [
                {"Detection": {"Name": "Rare"}, "Message": "rare"},
                {"Detection": {"Name": "Common"}, "Message": "common-1"},
                {"Detection": {"Name": "Common"}, "Message": "common-2"},
            ]
        }
        first_api = FlakyDetectionApi(
            inventory,
            rows,
            failures={"direct:Common": ["before", "before", "before", "before"]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FakeTransportError):
                self.run_analysis(first_api, root, artifact=artifact)
            first_state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            first_analysis_id = first_state["analysis_id"]
            first_run_id = first_state["active_analysis"]["run_id"]
            second_api = FlakyDetectionApi(inventory, rows)
            self.run_analysis(
                second_api,
                root,
                artifact=artifact,
                detection_regex=".*",
            )
            archived_state = json.loads(
                (
                    root
                    / "analysis"
                    / "runs"
                    / first_analysis_id
                    / first_run_id
                    / "hunt-analysis-state.json"
                ).read_text()
            )

        self.assertEqual(second_api.attempts["direct:Rare"], 1)
        self.assertEqual(second_api.attempts["direct:Common"], 1)
        archived_by_detection = {
            item["detection"]: item
            for item in archived_state["detectraptor_recovery"]["partitions"]
        }
        self.assertEqual(archived_by_detection["Rare"]["status"], "completed")
        self.assertEqual(archived_by_detection["Common"]["status"], "failed")

    def test_detectraptor_nonretryable_transport_error_fails_without_reconnect(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FlakyDetectionApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): [{"Detection": {"Name": "Rule"}}]},
        )

        def cancelled(vql, env=None, **kwargs):
            if "Detection.Name = PartitionDetection" in vql:
                raise FakeTransportError(grpc.StatusCode.CANCELLED)
            yield from FakeFlowApi.query_batches_with_metadata(
                api, vql, env, **kwargs
            )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            api,
            "query_batches_with_metadata",
            side_effect=cancelled,
        ), self.assertRaises(FakeTransportError):
            self.run_analysis(api, Path(directory), artifact=artifact)

        self.assertEqual(api.reconnect_count, 0)

    def test_detectraptor_recovery_state_contains_no_raw_evidence_or_prompts(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        secret = "RAW-EVIDENCE-MUST-NOT-PERSIST"
        api = FlakyDetectionApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rare"}, "Message": secret},
                    {"Detection": {"Name": "Common"}, "Message": "one"},
                    {"Detection": {"Name": "Common"}, "Message": "two"},
                ]
            },
            failures={"direct:Common": ["before", "before", "before", "before"]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FakeTransportError):
                self.run_analysis(api, root, artifact=artifact)
            state_text = (
                root / "analysis" / "hunt-analysis-state.json"
            ).read_text()

        self.assertNotIn(secret, state_text)
        self.assertNotIn('"Evidence"', state_text)
        self.assertNotIn('"prompt"', state_text.casefold())
        self.assertNotIn('"transcript"', state_text.casefold())

        compact = flow_analysis_coordinator._compact_detectraptor_recovery_result(
            {
                "findings": [
                    {
                        "evidence": [
                            {
                                "fields": {
                                    "EvidencePreview": secret,
                                    "StackEvidence": secret,
                                    "EvidenceLength": len(secret),
                                }
                            }
                        ]
                    }
                ]
            }
        )
        compact_text = json.dumps(compact)
        self.assertNotIn(secret, compact_text)
        self.assertNotIn("EvidenceLength", compact_text)

    def test_detectraptor_batched_context_transport_retry_is_detection_scoped(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        rows = [
            {"Detection": {"Name": "Rule"}, "Message": "common"}
            for _index in range(1_100)
        ] + [{"Detection": {"Name": "Rule"}, "Message": "rare"}]
        api = FlakyDetectionApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
            failures={"context:Rule": ["before"]},
        )

        def select_every_group(*, work_items, **_kwargs):
            for work in work_items:
                chunk = dict(work["chunk"])
                source_rows = dict(work["source_rows"])
                refs = sorted(source_rows)
                yield {
                    "status": "accepted",
                    "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                    "attempts": 1,
                    "result": {
                        "task_id": chunk["task_id"],
                        "artifact": chunk["artifact"],
                        "status": "complete",
                        "coverage": {
                            "planned_rows": chunk["row_count"],
                            "reviewed_rows": chunk["row_count"],
                        },
                        "answer": "Selected all exact groups.",
                        "findings": [
                            {
                                "id": f"F{index}",
                                "summary": f"Selected group {index}.",
                                "confidence": "medium",
                                "domains": ["execution"],
                                "evidence": [
                                    {
                                        "artifact": chunk["artifact"],
                                        "ref": ref,
                                        "fields": dict(source_rows[ref]),
                                    }
                                ],
                            }
                            for index, ref in enumerate(refs, start=1)
                        ],
                        "relevant_context": [],
                        "limitations": [],
                        "bounded_follow_up": [],
                    },
                }

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                streaming=select_every_group,
            )

        self.assertEqual(api.attempts["context:Rule"], 2)
        self.assertEqual(api.reconnect_count, 1)
        self.assertEqual(result["detectraptor_stack"]["partitions"][0]["group_review"]["reviewed_group_count"], 2)
        self.assertEqual(result["accounted_row_count"], 1_101)

    def test_detectraptor_context_failure_keeps_compact_recovery_checkpoint(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        inventory = [flow_row("C.1", "F.1", artifact=artifact)]
        rows = {
            ("C.1", "F.1"): [
                {"Detection": {"Name": "Rule"}, "Message": "common"}
                for _index in range(1_100)
            ]
        }
        first_api = FlakyDetectionApi(
            inventory,
            rows,
            failures={
                "context:Rule": ["before", "before", "before", "before"]
            },
        )

        def select_group(*, work_items, **_kwargs):
            for work in work_items:
                chunk = dict(work["chunk"])
                source_rows = dict(work["source_rows"])
                ref = sorted(source_rows)[0]
                yield {
                    "status": "accepted",
                    "chunk_id": str(dict(work["manifest"])["chunk_id"]),
                    "attempts": 1,
                    "result": {
                        "task_id": chunk["task_id"],
                        "artifact": chunk["artifact"],
                        "status": "complete",
                        "coverage": {
                            "planned_rows": chunk["row_count"],
                            "reviewed_rows": chunk["row_count"],
                        },
                        "answer": "Selected exact group.",
                        "findings": [
                            {
                                "id": "F1",
                                "summary": "Requires validation.",
                                "confidence": "medium",
                                "domains": ["execution"],
                                "evidence": [
                                    {
                                        "artifact": chunk["artifact"],
                                        "ref": ref,
                                        "fields": dict(source_rows[ref]),
                                    }
                                ],
                            }
                        ],
                        "relevant_context": [],
                        "limitations": [],
                        "bounded_follow_up": [],
                    },
                }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FakeTransportError):
                self.run_analysis(
                    first_api,
                    root,
                    artifact=artifact,
                    streaming=select_group,
                )
            interrupted = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            record = interrupted["detectraptor_recovery"]["partitions"][0]
            self.assertEqual(record["stage"], "context_hydration")
            self.assertNotIn("initial_result", record)
            self.assertNotIn("group_assessments", record)
            self.assertEqual(len(record["selected_source_refs"]), 1)
            self.assertEqual(len(record["transport_errors"]), 4)
            self.assertEqual(record["transport_errors"][-1]["attempt"], 4)
            self.assertEqual(
                record["transport_errors"][-1]["status"], "UNAVAILABLE"
            )
            self.assertEqual(
                [
                    item.get("retry_delay_seconds")
                    for item in record["transport_errors"]
                ],
                [2.0, 5.0, 15.0, None],
            )
            self.assertTrue(
                all("elapsed_seconds" in item for item in record["transport_errors"])
            )
            self.assertTrue(
                all("rows_received" in item for item in record["transport_errors"])
            )

            second_api = FlakyDetectionApi(inventory, rows)
            result = self.run_analysis(
                second_api,
                root,
                artifact=artifact,
                streaming=select_group,
            )

        self.assertEqual(second_api.attempts["groups:Rule"], 1)
        self.assertEqual(second_api.attempts["context:Rule"], 1)
        self.assertEqual(result["accounted_row_count"], 1_100)

    def test_detectraptor_group_query_failure_preserves_progress_report(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        rows = [
            {"Detection": {"Name": "Rule"}, "Message": "common"}
            for _index in range(1_100)
        ]
        api = FlakyDetectionApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): rows},
            failures={"groups:Rule": ["before", "before", "before", "before"]},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FakeTransportError):
                self.run_analysis(api, root, artifact=artifact)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            report = (root / "analysis-hunt.md").read_text()

        record = state["detectraptor_recovery"]["partitions"][0]
        self.assertEqual(record["stage"], "initial_analysis")
        self.assertEqual(record["status"], "failed")
        self.assertIn("Status: `failed`", report)
        self.assertEqual(api.attempts["groups:Rule"], 4)

    def test_detectraptor_evtx_discovery_failure_is_terminal_in_state(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {("C.1", "F.1"): [{"Detection": {"Name": "Rule"}}]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                flow_analysis_runtime,
                "discover_detectraptor_evtx_partitions",
                side_effect=RuntimeError("discovery failed"),
            ), self.assertRaisesRegex(RuntimeError, "discovery failed"):
                self.run_analysis(api, root, artifact=artifact)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"],
            "detection_discovery",
        )
        self.assertEqual(state["runs"][-1]["status"], "failed")

    def test_unhandled_source_setup_failure_is_terminal_in_state(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            successful = self.run_analysis(api, root)
            previous_state = json.loads(
                Path(successful["analysis_state_file"]).read_text()
            )
            with mock.patch.object(
                flow_analysis_runtime,
                "query_client_identity_map",
                side_effect=RuntimeError("identity lookup failed"),
            ), self.assertRaisesRegex(RuntimeError, "identity lookup failed"):
                self.run_analysis(api, root)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(state["active_analysis"]["phase"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"],
            "source_setup",
        )
        self.assertEqual(
            state["active_analysis"]["failure_reason"],
            "Unhandled RuntimeError",
        )
        self.assertEqual(state["runs"][-1]["status"], "failed")
        self.assertEqual(state["checkpoint"], previous_state["checkpoint"])
        self.assertEqual(
            state["inventory"]["last_successful_check_at"],
            previous_state["inventory"]["last_successful_check_at"],
        )

    def test_post_acquisition_accounting_failure_is_terminal_in_state(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                flow_analysis_runtime,
                "iter_hunt_result_segments",
                return_value=iter(()),
            ), self.assertRaisesRegex(RuntimeError, "returned zero rows"):
                self.run_analysis(api, root)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )

        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(state["active_analysis"]["phase"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"],
            "row_accounting",
        )
        self.assertEqual(state["runs"][-1]["status"], "failed")

    def test_preflight_failure_does_not_relabel_preexisting_running_state(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )
        previous = {
            "active_analysis": {
                "run_id": "previous-run",
                "status": "running",
                "phase": "acquiring_results",
                "started_at": "2026-08-13T08:00:00Z",
            }
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "analysis" / "hunt-analysis-state.json"
            state_path.parent.mkdir(parents=True)
            state_path.write_text(json.dumps(previous), encoding="utf-8")
            with mock.patch.object(
                flow_analysis_runtime,
                "query_server_cutoff",
                side_effect=RuntimeError("cutoff unavailable"),
            ), self.assertRaisesRegex(RuntimeError, "cutoff unavailable"):
                self.run_analysis(api, root)
            state = json.loads(state_path.read_text())

        self.assertEqual(state, previous)

    def test_terminalizer_distinguishes_retry_with_same_run_id(self):
        state = {
            "active_analysis": {
                "run_id": "same-run",
                "status": "running",
                "phase": "acquiring_results",
                "started_at": "2026-08-13T09:00:00Z",
            }
        }

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "hunt-analysis-state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            changed = (
                flow_analysis_coordinator._terminalize_unhandled_active_analysis(
                    state_path,
                    RuntimeError("failure"),
                    preexisting_running_run_id="same-run",
                    preexisting_running_started_at="2026-08-13T08:00:00Z",
                )
            )
            persisted = json.loads(state_path.read_text())

        self.assertTrue(changed)
        self.assertEqual(persisted["active_analysis"]["status"], "failed")

    def test_full_analysis_passes_resolved_time_filter_to_hunt_query(self):
        artifact = "Windows.NTFS.MFT"
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {
                        "Name": "inside.txt",
                        "LastModified0x10": "2026-08-13T09:30:00Z",
                        "Created0x10": "2026-08-12T09:30:00Z",
                    },
                    {
                        "Name": "boundary.txt",
                        "LastModified0x10": "2026-08-13T09:00:00Z",
                        "Created0x10": "2026-08-12T09:00:00Z",
                    },
                ]
            },
        )
        scope = analysis_time_scope.TimeScope.from_values(
            after="2026-08-13T09:00:00Z",
            before="2026-08-13T10:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                time_scope=scope,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        query = api.result_queries[0]
        self.assertIn("LastModified0x10 > AnalysisTimeAfter", query["VQL"])
        self.assertIn("Created0x10 > AnalysisTimeAfter", query["VQL"])
        self.assertIn(" OR ", query["VQL"])
        self.assertEqual(query["env"]["AnalysisTimeAfter"], scope.after)
        self.assertEqual(query["env"]["AnalysisTimeBefore"], scope.before)
        self.assertEqual(state["checkpoint"]["row_count"], 1)

    def test_full_analysis_keeps_unknown_time_fields_unfiltered(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "normal-unfiltered-row"}]},
        )
        scope = analysis_time_scope.TimeScope.from_values(
            after="2026-08-13T09:00:00Z",
            before="2026-08-13T10:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                time_scope=scope,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        query = api.result_queries[0]
        self.assertNotIn("WHERE", query["VQL"])
        self.assertNotIn("AnalysisTimeAfter", query["env"])
        self.assertNotIn("AnalysisTimeBefore", query["env"])
        self.assertEqual(state["checkpoint"]["row_count"], 1)

    def test_mixed_time_filter_persists_partial_coverage_and_exact_resolution(self):
        supported = "Windows.EventLogs.RDPAuth"
        unsupported = "IG.Windows.Registry.HiddenTasks"
        api = FakeFlowApi(
            [
                flow_row("C.1", "F.1", artifact=supported),
                flow_row("C.2", "F.2", artifact=unsupported),
            ],
            {
                ("C.1", "F.1"): [
                    {"EventTime": "2026-08-13T09:30:00Z", "EventID": 4624}
                ],
                ("C.2", "F.2"): [{"TaskID": "state-row"}],
            },
        )
        scope = analysis_time_scope.TimeScope.from_values(
            after="2026-08-13T09:00:00Z",
            before="2026-08-13T10:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=[supported, unsupported],
                target_coverage="not_assessed",
                time_scope=scope,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())
            report = Path(result["analysis_memory_file"]).read_text()

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["time_filter"]["coverage"], "partial")
        self.assertEqual(state["coverage"]["time_filter"], "partial")
        self.assertEqual(state["coverage"]["overall"], "partial")
        self.assertEqual(
            state["time_filter"]["filtered_artifacts"], [supported]
        )
        self.assertEqual(
            state["time_filter"]["unsupported_artifacts"], [unsupported]
        )
        self.assertEqual(
            state["time_filter"]["resolved_artifacts"][supported]["expressions"],
            {"event": ["EventTime"]},
        )
        queries = {item["artifact"]: item for item in api.result_queries}
        self.assertIn("WHERE", queries[supported]["VQL"])
        self.assertNotIn("WHERE", queries[unsupported]["VQL"])
        self.assertIn("Analysis time filter: `partial`", report)
        self.assertIn("EventTime", report)
        self.assertIn(unsupported, report)

    def test_full_analysis_reviews_rows_exposed_by_open_flows(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", state="RUNNING")],
            {("C.1", "F.1"): [{"Value": "available-before-terminal"}]},
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(api, Path(directory))
            state = json.loads(
                Path(result["analysis_state_file"]).read_text()
            )

        self.assertEqual(state["checkpoint"]["row_count"], 1)
        self.assertEqual(state["inventory"]["flow_counts"]["open"], 1)
        self.assertEqual(state["coverage"]["result_review"], "complete")
        self.assertEqual(state["coverage"]["target_execution"], "partial")

    def test_update_source_reads_are_server_side_batched(self):
        sources = [
            flow_analysis.FlowSource(
                org_id="root",
                client_id=f"C.{index}",
                flow_id=f"F.{index}",
                artifact="Artifact.Test",
                hunt_id="H.1",
                state="FINISHED",
                watermark=f"revision-{index}",
            )
            for index in range(10_000)
        ]
        api = FakeFlowApi([], {})
        list(flow_analysis_runtime.iter_batched_flow_segments(api, sources))
        self.assertEqual(len(api.result_queries), 40)
        self.assertTrue(all(item["type"] == "batched_source" for item in api.result_queries))
        self.assertTrue(all(item["source_count"] == 250 for item in api.result_queries))

    def test_update_query_applies_time_filter_inside_each_source_read(self):
        sources = [
            flow_analysis.FlowSource(
                org_id="root",
                client_id="C.1",
                flow_id="F.1",
                artifact="Artifact.Test",
                hunt_id="H.1",
                state="FINISHED",
                watermark="revision-1",
            )
        ]
        api = FakeFlowApi([], {("C.1", "F.1"): [{"EventTime": "2026-08-13T09:30:00Z"}]})
        list(
            flow_analysis_runtime.iter_batched_flow_segments(
                api,
                sources,
                time_predicates={
                    "Artifact.Test": "(EventTime > AnalysisTimeAfter)"
                },
                time_environment={
                    "AnalysisTimeAfter": "2026-08-13T09:00:00Z"
                },
            )
        )
        query = api.result_queries[0]
        self.assertIn(
            "artifact=ArtifactName)\n    WHERE (EventTime > AnalysisTimeAfter)",
            query["VQL"],
        )
        self.assertLess(query["VQL"].index("WHERE"), query["VQL"].index("  })"))
        self.assertEqual(
            query["env"]["AnalysisTimeAfter"], "2026-08-13T09:00:00Z"
        )

    def test_unchanged_full_rerun_has_stable_bounded_state(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "raw-secret"}]})
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis, "now_utc", return_value="2026-08-13T00:00:00Z"
        ):
            root = Path(directory)
            first = self.run_analysis(api, root)
            path = Path(first["analysis_state_file"])
            first_payload = json.loads(path.read_text())
            first_size = path.stat().st_size
            first_ref = first_payload["checkpoint"]["result"]["findings"][0]["evidence"][0]["ref"]
            second = self.run_analysis(api, root)
            second_payload = json.loads(path.read_text())
            second_size = path.stat().st_size
            second_ref = second_payload["checkpoint"]["result"]["findings"][0]["evidence"][0]["ref"]
        self.assertLessEqual(second_size - first_size, 256)
        self.assertEqual(first_ref, second_ref)
        self.assertEqual(first_ref, "S0001-R1")
        self.assertNotIn("raw-secret", json.dumps(second_payload))
        for key in ("sources", "segments", "chunks", "hunt_result", "findings", "analysis_summary"):
            self.assertNotIn(key, second_payload)
        self.assertEqual(second["analysis_method"], "full")
        self.assertEqual(
            len(second["analysis_result"]["findings"]),
            len(second_payload["checkpoint"]["result"]["findings"]),
        )
        self.assertIn("## Hunt H.1 analysis summary", second["chat_summary"])
        self.assertIn("### Findings", second["chat_summary"])
        self.assertEqual(
            second_payload["checkpoint"]["result"]["coverage"]["reviewed_rows"],
            1,
        )

    def test_active_analysis_is_visible_during_chunks_and_removed_on_success(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )
        observed: list[dict] = []

        def execute(*, work_items, progress_callback, **kwargs):
            work = list(work_items)
            state_path = (
                Path(directory) / "analysis" / "hunt-analysis-state.json"
            )
            observed.append(json.loads(state_path.read_text())["active_analysis"])
            progress_callback(
                {
                    "phase": "chunk",
                    "task_id": "task-1",
                    "status": "accepted",
                }
            )
            return self.accepted_streaming_chunks(
                work_items=work,
                progress_callback=progress_callback,
                **kwargs,
            )

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis_coordinator,
            "execute_streaming_chunks_async",
            side_effect=execute,
        ), mock.patch.object(
            flow_analysis_coordinator,
            "_synthesize_transient_results",
            side_effect=self.accepted_synthesis,
        ):
            result = flow_analysis_coordinator.analyze_hunt_flows(
                api,
                org_id="root",
                hunt_id="H.1",
                hunt_state="RUNNING",
                question="What is suspicious?",
                hunt_root=Path(directory),
                selected_artifacts=["Artifact.Test"],
                limits=replace(
                    TEST_LIMITS,
                    maximum_evidence_tokens_per_item=1_000,
                ),
                spec=self.spec(),
            )
            final_state = json.loads(Path(result["analysis_state_file"]).read_text())
            debug_exists = (
                Path(directory)
                / "analysis"
                / "hunt-analysis-validation-debug.json"
            ).exists()

        self.assertEqual(observed[0]["status"], "running")
        self.assertEqual(observed[0]["phase"], "chunk_analysis")
        self.assertEqual(observed[0]["planned_chunk_count"], 1)
        self.assertNotIn("active_analysis", final_state)
        self.assertNotIn("last_validation_debug", final_state)
        self.assertFalse(debug_exists)
        self.assertTrue(result["analysis_state_file"].endswith("hunt-analysis-state.json"))

    def test_full_aggregate_recovers_unique_client_and_flow_provenance(self):
        source = flow_analysis_runtime.aggregate_hunt_source(
            org_id="root",
            hunt_id="H.1",
            artifact="Artifact.Test",
            watermark="cutoff",
        )
        segment = flow_analysis_runtime.AcquiredSegment(
            source=source,
            segment_id=flow_analysis.segment_identifier(source.source_id, 0, 1),
            row_start=0,
            row_end=1,
            rows=[{"Fqdn": "host.example.test", "Value": "one"}],
            flow_state="aggregate",
        )
        projected, _fields, _fingerprint = flow_analysis_coordinator._project_segment(
            segment,
            {},
            {"alias": "S0001"},
            {"C.1": {"hostname": "host", "fqdn": "host.example.test"}},
            {"C.1": "F.1"},
        )
        self.assertEqual(projected[0]["_ClientId"], "C.1")
        self.assertEqual(projected[0]["_FlowId"], "F.1")
        self.assertEqual(projected[0]["_HuntId"], "H.1")

    def test_streaming_chunker_crosses_segments_and_flushes_final_partial_chunk(self):
        def unit(identifier: str, tokens: int, segment_id: str) -> dict:
            return {
                "unit_id": identifier,
                "revision": f"revision-{identifier}",
                "source_id": "source-1",
                "segment_id": segment_id,
                "artifact": "Artifact.Test",
                "compatibility_key": "Artifact.Test/profile",
                "row_start": 0,
                "row_end": 1,
                "row_count": 1,
                "input_tokens": tokens,
                "rows": [{"_SourceRef": f"S0001-R{identifier[-1]}", "Value": identifier}],
            }

        first = SimpleNamespace(segment_id="segment-1", row_count=1)
        second = SimpleNamespace(segment_id="segment-2", row_count=2)
        by_segment = {
            "segment-1": [unit("unit-1", 60, "segment-1")],
            "segment-2": [
                unit("unit-2", 30, "segment-2"),
                unit("unit-3", 60, "segment-2"),
            ],
        }

        def planned(segment, **_kwargs):
            return {}, copy.deepcopy(by_segment[segment.segment_id])

        acquired: list[int] = []
        with mock.patch.object(
            flow_analysis_coordinator, "segment_units", side_effect=planned
        ):
            chunks = list(
                flow_analysis_coordinator.iter_streaming_chunks(
                    [first, second],
                    profiles={},
                    source_references={},
                    maximum_tokens=100,
                    encoding_name="cl100k_base",
                    analysis_id="analysis-1",
                    on_segment=acquired.append,
                )
            )

        self.assertEqual(
            [chunk["unit_ids"] for chunk in chunks],
            [["unit-1", "unit-2"], ["unit-3"]],
        )
        self.assertEqual([chunk["input_tokens"] for chunk in chunks], [90, 60])
        self.assertEqual(acquired, [1, 2])

    def test_streaming_chunk_retries_then_accepts_and_releases_payload(self):
        chunk = flow_analysis_coordinator._streaming_chunk(
            [
                {
                    "unit_id": "unit-1",
                    "revision": "revision-1",
                    "source_id": "source-1",
                    "segment_id": "segment-1",
                    "artifact": "Artifact.Test",
                    "compatibility_key": "Artifact.Test/profile",
                    "row_count": 1,
                    "input_tokens": 10,
                    "rows": [{"_SourceRef": "S0001-R1", "Value": "one"}],
                }
            ],
            analysis_id="analysis-1",
        )
        limits = {
            "model_context_tokens": 16_000,
            "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000,
            "maximum_output_tokens": 2_000,
            "instruction_reserve_tokens": 1_000,
            "prior_context_reserve_tokens": 0,
            "safety_reserve_tokens": 1_000,
            "maximum_evidence_tokens_per_item": 8_000,
        }
        work = next(
            iter(
                flow_analysis_coordinator.iter_streaming_chunk_work(
                    [chunk],
                    source_aliases={
                        "source-1": {
                            "alias": "S0001",
                            "scope_type": "hunt",
                            "scope_id": "H.1",
                            "hunt_id": "H.1",
                            "org_id": "root",
                            "artifact": "Artifact.Test",
                            "source": "hunt_results",
                        }
                    },
                    scope_type="hunt",
                    scope_id="H.1",
                    analysis_id="analysis-1",
                    question="What is suspicious?",
                    limits=limits,
                    encoding_name="cl100k_base",
                )
            )
        )
        invalid_work = copy.deepcopy(work)
        limit_work = copy.deepcopy(work)
        valid_output = "\n".join(
            [
                "RESULT\tfindings",
                "FINDING\tF1\thigh\tExecution\tSuspicious event.",
                "EVIDENCE\tF1\tS0001-R1",
                "END",
            ]
        )

        class RetryRunner:
            def __init__(self):
                self.calls = 0

            def run(self, task, **_kwargs):
                self.calls += 1
                return AgentResult(
                    task_id=task.task_id,
                    status="failed" if self.calls == 1 else "succeeded",
                    output="" if self.calls == 1 else valid_output,
                    output_file="",
                    events_file="",
                    manifest_file="",
                    elapsed_seconds=0.0,
                    error="temporary failure" if self.calls == 1 else "",
                )

        runner = RetryRunner()
        outcome = execute_streaming_chunk_work(
            work,
            runner=runner,
            workdir=Path("."),
            runtime_dir=Path(".api-runtime-test"),
        )

        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["attempts"], 1)
        self.assertEqual(
            outcome["attempt_failures"],
            [
                {
                    "attempt": 1,
                    "status": "failed",
                    "failure_type": "agent_failed",
                    "error": "temporary failure",
                    "diagnostic_codes": [],
                }
            ],
        )
        self.assertEqual(runner.calls, 1)
        self.assertNotIn("task", work)
        self.assertNotIn("source_rows", work)
        self.assertNotIn("provenance", work)

        invalid_output = valid_output.replace(
            "EVIDENCE\tF1\tS0001-R1",
            "EVIDENCE\tF1\tS0001-R1\tValue",
        )

        class RepairRunner:
            def __init__(self):
                self.calls = 0

            def run(self, task, **_kwargs):
                self.calls += 1
                return AgentResult(
                    task_id=task.task_id,
                    status="succeeded",
                    output=invalid_output,
                    output_file="",
                    events_file="",
                    manifest_file="",
                    elapsed_seconds=0.0,
                )

        invalid_runner = RepairRunner()
        rejected = execute_streaming_chunk_work(
            invalid_work,
            runner=invalid_runner,
            workdir=Path("."),
            runtime_dir=Path(".api-runtime-test"),
        )

        self.assertEqual(rejected["status"], "failed")
        self.assertEqual(rejected["attempts"], 3)
        self.assertEqual(invalid_runner.calls, 3)
        self.assertEqual(
            [item["status"] for item in rejected["attempt_failures"]],
            ["retrying", "retrying", "failed"],
        )
        self.assertEqual(
            rejected["attempt_failures"][0]["diagnostic_codes"],
            ["invalid_evidence_record"],
        )

        class OutputLimitRunner:
            def __init__(self):
                self.calls = 0

            def run(self, task, **_kwargs):
                self.calls += 1
                return AgentResult(
                    task_id=task.task_id,
                    status="failed",
                    output="",
                    output_file="",
                    events_file="",
                    manifest_file="",
                    elapsed_seconds=0.0,
                    error="Agent output exceeds maximum output tokens",
                    error_classification="output_too_large",
                )

        output_limit_runner = OutputLimitRunner()
        limited = execute_streaming_chunk_work(
            limit_work,
            runner=output_limit_runner,
            workdir=Path("."),
            runtime_dir=Path(".api-runtime-test"),
        )

        self.assertEqual(limited["status"], "failed")
        self.assertEqual(limited["attempts"], 1)
        self.assertEqual(output_limit_runner.calls, 1)
        self.assertEqual(
            [item["status"] for item in limited["attempt_failures"]],
            ["failed"],
        )

    def test_empty_stream_does_not_start_an_analyst_runner(self):
        limits = {
            "model_context_tokens": 16_000,
            "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000,
            "maximum_output_tokens": 2_000,
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis_coordinator, "create_agent_runner"
        ) as runner:
            outcomes = list(
                execute_streaming_chunks(
                    work_items=[],
                    limits=limits,
                    encoding_name="cl100k_base",
                    spec=self.spec(),
                    workdir=Path(directory),
                    runtime_dir=Path(directory) / ".api-runtime",
                )
            )

        self.assertEqual(outcomes, [])
        runner.assert_not_called()

    def test_external_streaming_queue_restores_status_callback(self):
        limits = {
            "model_context_tokens": 16_000,
            "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000,
            "maximum_output_tokens": 2_000,
        }
        prior_statuses = []

        async def execute(_work, **_kwargs):
            return {
                "status": "accepted",
                "chunk_id": "chunk-1",
                "attempts": 1,
                "result": {},
            }

        async def scenario(directory: str):
            queue = flow_analysis_coordinator.DynamicAnalysisQueue(
                max_concurrency=1,
                prefetch=1,
                lane_queue_size=1,
            )
            previous_callback = prior_statuses.append
            queue.on_status_change = previous_callback
            await queue.start()
            try:
                with mock.patch.object(
                    flow_analysis_coordinator,
                    "_execute_streaming_chunk_work_async",
                    side_effect=execute,
                ):
                    outcomes = await (
                        flow_analysis_coordinator.execute_streaming_chunks_async(
                            work_items=[
                                {
                                    "manifest": {
                                        "artifact": "Artifact.Test",
                                        "input_tokens": 1,
                                    },
                                    "chunk": {"artifact": "Artifact.Test"},
                                }
                            ],
                            limits=limits,
                            encoding_name="cl100k_base",
                            spec=self.spec(),
                            workdir=Path(directory),
                            runtime_dir=Path(directory) / ".api-runtime",
                            analysis_queue=queue,
                            shared_execute=lambda *_args, **_kwargs: None,
                        )
                    )
                self.assertIs(queue.on_status_change, previous_callback)
                self.assertEqual(len(outcomes), 1)
                queue.request_stop()
                self.assertTrue(prior_statuses)
            finally:
                await queue.close()

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(directory))

    def test_external_streaming_call_waits_only_for_owned_futures(self):
        limits = {
            "model_context_tokens": 16_000,
            "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000,
            "maximum_output_tokens": 2_000,
        }

        async def scenario(directory: str):
            release_unrelated = asyncio.Event()
            unrelated_started = asyncio.Event()

            async def unrelated(_item):
                unrelated_started.set()
                await release_unrelated.wait()
                return {"status": "accepted"}

            async def execute(_work, **_kwargs):
                return {
                    "status": "accepted",
                    "chunk_id": "owned",
                    "attempts": 1,
                    "result": {},
                }

            queue = flow_analysis_coordinator.DynamicAnalysisQueue(
                max_concurrency=2,
                prefetch=1,
                lane_queue_size=1,
            )
            await queue.start()
            unrelated_future = await queue.enqueue(
                "unrelated", {}, execute=unrelated
            )
            await unrelated_started.wait()
            try:
                with mock.patch.object(
                    flow_analysis_coordinator,
                    "_execute_streaming_chunk_work_async",
                    side_effect=execute,
                ):
                    outcomes = await asyncio.wait_for(
                        flow_analysis_coordinator.execute_streaming_chunks_async(
                            work_items=[
                                {
                                    "manifest": {
                                        "artifact": "Artifact.Test",
                                        "input_tokens": 1,
                                    },
                                    "chunk": {"artifact": "Artifact.Test"},
                                }
                            ],
                            limits=limits,
                            encoding_name="cl100k_base",
                            spec=self.spec(),
                            workdir=Path(directory),
                            runtime_dir=Path(directory) / ".api-runtime",
                            analysis_queue=queue,
                            shared_execute=lambda *_args, **_kwargs: None,
                            lane_id="owned",
                        ),
                        timeout=1,
                    )
                self.assertEqual([item["chunk_id"] for item in outcomes], ["owned"])
                self.assertFalse(unrelated_future.done())
            finally:
                release_unrelated.set()
                await unrelated_future
                await queue.close()

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(directory))

    def test_cancelled_streaming_producer_unblocks_enqueue_and_closes_iterator(self):
        limits = {
            "model_context_tokens": 16_000,
            "operational_context_tokens": 12_000,
            "maximum_input_tokens": 10_000,
            "maximum_output_tokens": 2_000,
        }

        class ClosingIterator:
            def __init__(self):
                self.yielded = threading.Event()
                self.closed = threading.Event()

            def __iter__(self):
                return self

            def __next__(self):
                if self.yielded.is_set():
                    raise StopIteration
                self.yielded.set()
                return {
                    "manifest": {
                        "artifact": "Artifact.Test",
                        "input_tokens": 1,
                    },
                    "chunk": {"artifact": "Artifact.Test"},
                }

            def close(self):
                self.closed.set()

        async def scenario(directory: str):
            release = asyncio.Event()
            active = asyncio.Event()

            async def unrelated(_item):
                active.set()
                await release.wait()
                return {"status": "accepted"}

            queue = flow_analysis_coordinator.DynamicAnalysisQueue(
                max_concurrency=1,
                prefetch=0,
                lane_queue_size=1,
            )
            await queue.start()
            unrelated_future = await queue.enqueue(
                "unrelated", {}, execute=unrelated
            )
            await active.wait()
            iterator = ClosingIterator()
            task = asyncio.create_task(
                flow_analysis_coordinator.execute_streaming_chunks_async(
                    work_items=iterator,
                    limits=limits,
                    encoding_name="cl100k_base",
                    spec=self.spec(),
                    workdir=Path(directory),
                    runtime_dir=Path(directory) / ".api-runtime",
                    analysis_queue=queue,
                    shared_execute=lambda *_args, **_kwargs: None,
                    lane_id="cancelled",
                )
            )
            await asyncio.to_thread(iterator.yielded.wait, 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(iterator.closed.wait(1))
            release.set()
            await unrelated_future
            await queue.close()

        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(scenario(directory))

    def test_detectraptor_detection_partitions_use_independent_concurrency_limit(self):
        artifact = flow_analysis_runtime.DETECTRAPTOR_EVTX_ARTIFACT
        api = FakeFlowApi(
            [flow_row("C.1", "F.1", artifact=artifact)],
            {
                ("C.1", "F.1"): [
                    {"Detection": {"Name": "Rule A"}, "Message": "one"},
                    {"Detection": {"Name": "Rule B"}, "Message": "two"},
                    {"Detection": {"Name": "Rule C"}, "Message": "three"},
                ]
            },
        )
        started: set[str] = set()
        both_started = asyncio.Event()
        active = 0
        peak_active = 0

        async def overlapping_streaming(*, work_items, **kwargs):
            nonlocal active, peak_active
            work = list(work_items)
            if not work:
                return []
            prompt = work[0]["task"].prompt
            detection = next(
                rule for rule in ("Rule A", "Rule B", "Rule C") if rule in prompt
            )
            started.add(detection)
            active += 1
            peak_active = max(peak_active, active)
            if len(started) == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=1)
            try:
                return list(
                    self.accepted_streaming_chunks(work_items=work, **kwargs)
                )
            finally:
                active -= 1

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                artifact=artifact,
                streaming=overlapping_streaming,
            )

        self.assertEqual(started, {"Rule A", "Rule B", "Rule C"})
        self.assertEqual(peak_active, 2)
        operations = result["detectraptor_stack"]["operations"]
        self.assertEqual(operations["analysis_concurrency_limit"], 2)
        self.assertEqual(operations["peak_active_partition_count"], 2)
        self.assertEqual(operations["reanalyzed_partition_count"], 3)

    def test_hunt_scope_reuses_one_runner_for_chunks_and_synthesis(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )

        class SharedRunner:
            def __init__(self):
                self.calls = 0
                self.closed = 0

            async def run(self, task, **_kwargs):
                self.calls += 1
                return AgentResult(
                    task_id=task.task_id,
                    status="succeeded",
                    output=(
                        "RESULT\tfindings\n"
                        "FINDING\tF1\thigh\tExecution\tSuspicious event.\n"
                        "EVIDENCE\tF1\tS0001-R1\n"
                        "END"
                    ),
                    output_file="",
                    events_file="",
                    manifest_file="",
                    elapsed_seconds=0.0,
                )

            async def close(self):
                self.closed += 1

        shared_runner = SharedRunner()
        real_streaming = flow_analysis_coordinator.execute_streaming_chunks_async

        def runtime_limits(limits, encoding_name):
            return AgentRuntimeLimits(
                model_context_tokens=int(limits["model_context_tokens"]),
                operational_context_tokens=int(limits["operational_context_tokens"]),
                maximum_input_tokens=int(limits["maximum_input_tokens"]),
                maximum_output_tokens=int(limits["maximum_output_tokens"]),
                token_encoding=encoding_name,
            )

        async def streaming(**kwargs):
            return await real_streaming(**kwargs)

        async def synthesis(
            *,
            results,
            limits,
            encoding_name,
            shared_execute,
            schedule,
            **_kwargs,
        ):
            resolved = runtime_limits(limits, encoding_name)
            task = AgentRequest(
                task_id="hunt-analysis-synthesis",
                prompt="synthesize",
                output_name="hunt-analysis-synthesis.txt",
                metadata={"stage": "hunt-synthesis"},
            )
            future = await schedule(
                task,
                lambda item: shared_execute(
                    item,
                    limits=resolved,
                    progress_callback=None,
                ),
            )
            await future
            return self.accepted_synthesis(results=results)

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis_coordinator,
            "create_agent_runner",
            return_value=shared_runner,
        ) as runner_factory:
            result = self.run_analysis(
                api,
                Path(directory),
                streaming=streaming,
                synthesis=synthesis,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())

        runner_factory.assert_called_once()
        self.assertEqual(shared_runner.calls, 2)
        self.assertEqual(shared_runner.closed, 1)
        self.assertNotIn("active_analysis", state)
        self.assertEqual(state["checkpoint"]["generation"], 1)
        self.assertEqual(state["checkpoint"]["row_count"], 1)
        self.assertEqual(state["runs"][-1]["status"], "complete")

    def test_next_run_records_stale_active_analysis_as_interrupted(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.run_analysis(api, root)
            state_path = Path(first["analysis_state_file"])
            state = json.loads(state_path.read_text())
            state["active_analysis"] = {
                "run_id": "interrupted-run",
                "status": "running",
                "method": "full",
                "phase": "chunk_analysis",
                "started_at": "2026-08-13T09:00:00Z",
                "heartbeat_at": "2026-08-13T09:01:00Z",
                "planned_chunk_count": 3,
                "accepted_chunk_count": 1,
                "failed_chunk_count": 0,
            }
            state_path.write_text(json.dumps(state))
            api.cutoff = "2026-08-13T11:00:00Z"
            second = self.run_analysis(api, root)
            final_state = json.loads(Path(second["analysis_state_file"]).read_text())

        interrupted = [
            run
            for run in final_state["runs"]
            if run.get("run_id") == "interrupted-run"
        ]
        self.assertEqual(len(interrupted), 1)
        self.assertEqual(interrupted[0]["status"], "interrupted")
        self.assertEqual(interrupted[0]["last_phase"], "chunk_analysis")

    def test_changed_source_revision_is_merged_by_explicit_update(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "one"}]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_analysis(api, root)
            api.cutoff = "2026-08-13T11:00:00Z"
            api.inventory.append(
                flow_row("C.2", "F.2", active_time="2026-08-13T10:30:00Z")
            )
            api.rows[("C.2", "F.2")] = [{"Value": "two"}]
            result = self.run_analysis(api, root, update=True)
            state = json.loads(Path(result["analysis_state_file"]).read_text())
        self.assertEqual(result["analysis_method"], "update")
        self.assertEqual(result["candidate_flow_count"], 1)
        self.assertEqual(state["checkpoint"]["generation"], 2)
        self.assertEqual(state["checkpoint"]["row_count"], 2)
        self.assertEqual(state["inventory"]["last_successful_check_at"], api.cutoff)
        self.assertTrue(any(item["type"] == "batched_source" for item in api.result_queries))

    def test_full_rebuild_prunes_superseded_update_aliases(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "one"}]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_analysis(api, root)
            api.cutoff = "2026-08-13T11:00:00Z"
            api.inventory.append(flow_row("C.2", "F.2", active_time="2026-08-13T10:30:00Z"))
            api.rows[("C.2", "F.2")] = [{"Value": "two"}]
            updated = self.run_analysis(api, root, update=True)
            update_state = json.loads(Path(updated["analysis_state_file"]).read_text())
            rebuilt = self.run_analysis(api, root)
            rebuilt_state = json.loads(Path(rebuilt["analysis_state_file"]).read_text())
        self.assertGreater(len(update_state["source_aliases"]), 1)
        self.assertEqual(len(rebuilt_state["source_aliases"]), 1)

    def test_obvious_duplicate_findings_are_merged_on_update(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "one"}]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_analysis(api, root)
            api.cutoff = "2026-08-13T11:00:00Z"
            api.inventory.append(flow_row("C.2", "F.2", active_time="2026-08-13T10:30:00Z"))
            api.rows[("C.2", "F.2")] = [{"Value": "same finding"}]
            updated = self.run_analysis(api, root, update=True)
            state = json.loads(Path(updated["analysis_state_file"]).read_text())
        findings = state["checkpoint"]["result"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "F1")
        self.assertEqual(len(findings[0]["evidence"]), 2)

    def test_update_requires_successful_full_checkpoint(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"V": 1}]})
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            RuntimeError, "successful full hunt analysis checkpoint"
        ):
            self.run_analysis(api, Path(directory), update=True)

    def test_failed_update_retains_cursor_then_accepts_on_rerun(self):
        api = FakeFlowApi([flow_row("C.1", "F.1")], {("C.1", "F.1"): [{"Value": "one"}]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.run_analysis(api, root)
            state_path = Path(first["analysis_state_file"])
            before = json.loads(state_path.read_text())
            api.cutoff = "2026-08-13T11:00:00Z"
            api.inventory.append(flow_row("C.2", "F.2", active_time="2026-08-13T10:30:00Z"))
            api.rows[("C.2", "F.2")] = [{"Value": "two"}]
            observed_active_failures = []

            def failed_chunks(*, work_items, progress_callback=None, **_kwargs):
                for work in work_items:
                    chunk_id = str(dict(work["manifest"])["chunk_id"])
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "phase": "chunk",
                                "task_id": str(work["task"].task_id),
                                "chunk_id": chunk_id,
                                "attempt": 1,
                                "status": "retrying",
                                "failure_type": "agent_failed",
                                "error": "temporary model failure",
                                "diagnostics": [],
                            }
                        )
                        observed_active_failures.append(
                            json.loads(state_path.read_text())["active_analysis"][
                                "chunk_attempt_failures"
                            ]
                        )
                        progress_callback(
                            {
                                "phase": "chunk",
                                "task_id": str(work["task"].task_id),
                                "chunk_id": chunk_id,
                                "attempt": 2,
                                "status": "failed",
                                "failure_type": "validation_failed",
                                "error": "worker output containing evidence",
                                "diagnostics": [
                                    {"code": "invalid_source_reference"},
                                    {"code": "unknown_field"},
                                ],
                            }
                        )
                    yield {
                        "chunk_id": chunk_id,
                        "status": "failed",
                        "attempts": 2,
                        "error": "model failed",
                        "attempt_failures": [
                            {
                                "attempt": 1,
                                "status": "retrying",
                                "failure_type": "agent_failed",
                                "error": "temporary model failure",
                                "diagnostic_codes": [],
                            },
                            {
                                "attempt": 2,
                                "status": "failed",
                                "failure_type": "validation_failed",
                                "error": "worker output containing evidence",
                                "diagnostic_codes": [
                                    "invalid_source_reference",
                                    "unknown_field",
                                ],
                            },
                        ],
                    }

            with mock.patch.object(
                flow_analysis_coordinator,
                "execute_streaming_chunks_async",
                side_effect=failed_chunks,
            ), self.assertRaisesRegex(RuntimeError, "failed closed"):
                flow_analysis_coordinator.analyze_hunt_flows(
                    api,
                    org_id="root",
                    hunt_id="H.1",
                    hunt_state="RUNNING",
                    question="What is suspicious?",
                    hunt_root=root,
                    update=True,
                    selected_artifacts=["Artifact.Test"],
                    limits=replace(
                        TEST_LIMITS,
                        maximum_evidence_tokens_per_item=1_000,
                    ),
                    spec=self.spec(),
                )
            failed_state = json.loads(state_path.read_text())
            self.assertEqual(
                observed_active_failures[0][0]["error"],
                "temporary model failure",
            )
            self.assertEqual(failed_state["checkpoint"]["generation"], before["checkpoint"]["generation"])
            self.assertEqual(failed_state["inventory"]["last_successful_check_at"], before["inventory"]["last_successful_check_at"])
            self.assertNotIn("chunks", failed_state)
            failed_run = failed_state["runs"][-1]
            self.assertEqual(failed_run["chunk_attempt_failure_count"], 2)
            self.assertEqual(failed_run["chunk_attempt_failures_truncated"], 0)
            self.assertEqual(len(failed_run["chunk_attempt_failures"]), 2)
            self.assertEqual(
                failed_run["chunk_attempt_failures"][0]["error"],
                "temporary model failure",
            )
            final_attempt = failed_run["chunk_attempt_failures"][1]
            self.assertEqual(final_attempt["failure_type"], "validation_failed")
            self.assertEqual(
                final_attempt["diagnostic_codes"],
                ["invalid_source_reference", "unknown_field"],
            )
            self.assertNotIn(
                "worker output containing evidence", json.dumps(failed_state)
            )
            accepted = self.run_analysis(api, root, update=True)
            accepted_state = json.loads(Path(accepted["analysis_state_file"]).read_text())
        self.assertEqual(accepted_state["checkpoint"]["generation"], 2)
        self.assertEqual(accepted_state["inventory"]["last_successful_check_at"], api.cutoff)

    def test_debug_validation_persists_recovered_errors_without_values(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )

        def retried_chunks(
            *, work_items, progress_callback=None, active_callback=None, **kwargs
        ):
            for work in work_items:
                chunk_id = str(dict(work["manifest"])["chunk_id"])
                if progress_callback is not None:
                    progress_callback(
                        {
                            "phase": "chunk",
                            "task_id": str(work["task"].task_id),
                            "chunk_id": chunk_id,
                            "attempt": 1,
                            "status": "retrying",
                            "failure_type": "validation_failed",
                            "error": "diagnostic contained SECRET-EVIDENCE-VALUE",
                            "diagnostics": [
                                {
                                    "code": "invalid_source_reference",
                                    "record": "EVIDENCE",
                                    "line": 8,
                                    "ref": "S0001-R1",
                                },
                                {
                                    "code": "unsupported_tactic",
                                    "record": "FINDING",
                                    "line": 7,
                                    "value": "SECRET-EVIDENCE-VALUE",
                                },
                                {
                                    "allowed": ["Execution"],
                                    "code": "unsupported_evidence_tactic",
                                    "finding_id": "M1",
                                    "record": "FINDING",
                                    "value": "Credential Access",
                                },
                            ],
                            "response_sha256": "a" * 64,
                        }
                    )
                for outcome in self.accepted_streaming_chunks(
                    work_items=[work],
                    progress_callback=progress_callback,
                    active_callback=active_callback,
                    **kwargs,
                ):
                    outcome["attempt_failures"] = [
                        {
                            "attempt": 1,
                            "status": "retrying",
                            "failure_type": "validation_failed",
                            "error": "worker result failed deterministic validation",
                            "diagnostic_codes": [
                                "invalid_source_reference",
                                "unsupported_tactic",
                            ],
                        }
                    ]
                    yield outcome

        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(
                api,
                Path(directory),
                streaming=retried_chunks,
                debug_validation=True,
            )
            debug_path = Path(result["validation_debug_file"])
            debug_text = debug_path.read_text()
            debug = json.loads(debug_text)
            debug_sha256 = flow_analysis_coordinator._sha256_bytes(
                debug_path.read_bytes()
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())
            debug_bytes = debug_path.read_bytes()
            non_debug_result = self.run_analysis(
                api,
                Path(directory),
                streaming=retried_chunks,
            )
            non_debug_state = json.loads(
                Path(non_debug_result["analysis_state_file"]).read_text()
            )
            debug_after_non_debug = debug_path.read_bytes()

        self.assertEqual(debug["status"], "complete")
        self.assertEqual(debug["attempt_failure_count"], 1)
        attempt = debug["attempt_failures"][0]
        self.assertEqual(attempt["diagnostics"][0]["ref"], "S0001-R1")
        self.assertIn("value_sha256", attempt["diagnostics"][1])
        self.assertEqual(
            attempt["diagnostics"][1]["allowed"],
            list(collection_analysis.ATTACK_TACTICS),
        )
        self.assertEqual(attempt["diagnostics"][2]["finding_id"], "M1")
        self.assertEqual(attempt["diagnostics"][2]["allowed"], ["Execution"])
        self.assertIn("value_sha256", attempt["diagnostics"][2])
        self.assertNotIn("SECRET-EVIDENCE-VALUE", debug_text)
        self.assertFalse(debug["raw_rows_persisted"])
        self.assertFalse(debug["model_output_persisted"])
        self.assertEqual(
            state["last_validation_debug"]["sha256"],
            debug_sha256,
        )
        self.assertEqual(debug_after_non_debug, debug_bytes)
        self.assertEqual(
            non_debug_state["last_validation_debug"]["sha256"],
            state["last_validation_debug"]["sha256"],
        )
        self.assertEqual(
            non_debug_state["last_validation_debug"]["run_id"],
            state["last_validation_debug"]["run_id"],
        )
        self.assertTrue(state["last_validation_debug"]["current_run"])
        self.assertFalse(
            non_debug_state["last_validation_debug"]["current_run"]
        )
        self.assertEqual(
            non_debug_state["persistence_manifest"]["validation_debug"],
            "bounded_validation_debug",
        )

    def test_grounded_synthesis_fallback_publishes_provisional_report(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_analysis(
                api,
                root,
                target_coverage="not_assessed",
                synthesis=self.fallback_synthesis,
                debug_validation=True,
            )
            state = json.loads(Path(result["analysis_state_file"]).read_text())
            debug_text = Path(result["validation_debug_file"]).read_text()
            debug = json.loads(debug_text)
            report = (root / "analysis-hunt.md").read_text()

        self.assertEqual(result["synthesis_status"], "complete_with_failures")
        self.assertEqual(result["synthesis_failure_count"], 1)
        self.assertEqual(result["result_review_coverage"], "partial")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(state["checkpoint"]["result"]["status"], "complete_with_failures")
        self.assertEqual(state["synthesis"]["status"], "complete_with_failures")
        self.assertEqual(state["coverage"]["result_review"], "partial")
        self.assertEqual(state["coverage"]["target_execution"], "not_assessed")
        self.assertEqual(state["coverage"]["overall"], "partial")
        self.assertEqual(
            state["inventory"]["last_successful_check_at"],
            api.cutoff,
        )
        self.assertEqual(state["runs"][-1]["status"], "complete_with_failures")
        self.assertEqual(
            state["runs"][-1]["synthesis_status"],
            "complete_with_failures",
        )
        failures = state["runs"][-1]["synthesis_failures"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["task_id"], "hunt-analysis-synthesis")
        self.assertLessEqual(
            len(failures[0]["error"]),
            flow_analysis_coordinator.MAX_FAILED_CHUNK_ERROR_CHARS,
        )
        self.assertIn("Deterministic fallback retained grounded findings.", report)
        self.assertIn("- Synthesis: `complete_with_failures`", report)
        self.assertIn("- Result review: `partial`", report)
        self.assertIn("Suspicious event.", report)
        self.assertIn("Unprojected field was rejected.", report)
        self.assertEqual(debug["status"], "complete_with_failures")
        synthesis_attempts = [
            item
            for item in debug["attempt_failures"]
            if item["stage"] == "hunt-synthesis"
        ]
        self.assertEqual(len(synthesis_attempts), 1)
        self.assertEqual(
            synthesis_attempts[0]["error"],
            "synthesis result failed deterministic validation",
        )
        self.assertNotIn("Unprojected field was rejected.", debug_text)
        self.assertEqual(
            state["persistence_manifest"]["validation_debug"],
            "bounded_validation_debug",
        )

    def test_failed_synthesis_retains_bounded_diagnostic_without_report(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1")],
            {("C.1", "F.1"): [{"Value": "one"}]},
        )

        def failed_synthesis(**_kwargs):
            return {
                "status": "failed",
                "tasks": [
                    {
                        "task_id": f"hunt-analysis-synthesis-{index}",
                        "stage": "hunt-synthesis",
                        "status": "failed",
                        "error": "agent unavailable" + ("x" * 4_096),
                    }
                    for index in range(7)
                ],
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "synthesis failed closed"):
                self.run_analysis(api, root, synthesis=failed_synthesis)
            state = json.loads(
                (root / "analysis" / "hunt-analysis-state.json").read_text()
            )
            report_exists = (root / "analysis-hunt.md").exists()

        self.assertFalse(report_exists)
        self.assertEqual(state["checkpoint"], {})
        self.assertEqual(state["coverage"]["result_review"], "incomplete")
        self.assertEqual(state["runs"][-1]["status"], "failed")
        self.assertEqual(state["runs"][-1]["synthesis_status"], "failed")
        self.assertEqual(state["active_analysis"]["status"], "failed")
        self.assertEqual(state["active_analysis"]["phase"], "failed")
        self.assertEqual(
            state["active_analysis"]["failure_stage"],
            "cumulative_synthesis",
        )
        failures = state["runs"][-1]["synthesis_failures"]
        self.assertEqual(
            len(failures),
            flow_analysis_coordinator.MAX_SYNTHESIS_FAILURES,
        )
        self.assertLessEqual(
            len(failures[0]["error"]),
            flow_analysis_coordinator.MAX_FAILED_CHUNK_ERROR_CHARS,
        )

    def test_less_than_seventy_percent_completion_is_warned(self):
        api = FakeFlowApi(
            [flow_row("C.1", "F.1"), flow_row("C.2", "F.2")],
            {("C.1", "F.1"): [{"V": 1}], ("C.2", "F.2"): [{"V": 2}]},
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_analysis(api, Path(directory), targeted=10)
            state = json.loads(Path(result["analysis_state_file"]).read_text())
        self.assertIn("20.0%", result["completion_warning"])
        self.assertEqual(state["inventory"]["completion_ratio"], 0.2)

    def test_unsupported_state_is_discarded(self):
        unsupported = {
            "schema_version": 999,
            "scope_type": "hunt",
            "scope_id": "H.1",
            "analysis_id": "A.1",
            "chunks": {"old": {"result": {"raw": "secret"}}},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(unsupported))
            state = flow_analysis_coordinator.load_state(
                path, scope_type="hunt", scope_id="H.1", analysis_id="A.1"
            )
            self.assertEqual(state["schema_version"], 7)
        self.assertEqual(state["checkpoint"], {})
        self.assertNotIn("chunks", state)

    def test_state_write_is_atomic_and_deterministically_sorted(self):
        state = flow_analysis.initial_state(
            scope_type="hunt", scope_id="H.1", analysis_id="A.1"
        )
        state["source_aliases"] = {
            "z": {"alias": "S0002"},
            "a": {"alias": "S0001"},
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis, "now_utc", return_value="2026-08-13T00:00:00Z"
        ):
            path = Path(directory) / "state.json"
            flow_analysis_coordinator.write_state(path, state)
            first = path.read_bytes()
            flow_analysis_coordinator.write_state(path, state)
            second = path.read_bytes()
            temp_files = list(Path(directory).glob(".state.json.*.tmp"))
            self.assertEqual(first, second)
            self.assertLess(first.index(b'"a"'), first.index(b'"z"'))
            self.assertEqual(temp_files, [])

    def test_validation_debug_uses_independent_attempt_bound(self):
        attempts = [
            {
                "chunk_id": f"chunk-{index:03d}",
                "ordinal": index,
                "artifact": "Artifact.Test",
                "row_count": 1,
                "input_tokens": 10,
                "attempt": 1,
                "status": "retrying",
                "failure_type": "validation_failed",
                "error": "worker result failed deterministic validation",
                "diagnostics": [
                    {
                        "code": "internal_field",
                        "field": "_FlowId",
                        "ref": f"S0001-R{index + 1}",
                    }
                ],
            }
            for index in range(25)
        ]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            flow_analysis, "now_utc", return_value="2026-08-13T00:00:00Z"
        ):
            path = Path(directory) / "hunt-analysis-validation-debug.json"
            flow_analysis_coordinator.write_validation_debug(
                path,
                {
                    "schema_version": 1,
                    "scope_id": "H.1",
                    "analysis_id": "analysis-1",
                    "run_id": "run-1",
                },
                reversed(attempts),
                status="complete",
            )
            first = path.read_bytes()
            flow_analysis_coordinator.write_validation_debug(
                path,
                {
                    "schema_version": 1,
                    "scope_id": "H.1",
                    "analysis_id": "analysis-1",
                    "run_id": "run-1",
                },
                attempts,
                status="complete",
            )
            second = path.read_bytes()
            payload = json.loads(path.read_text())
            temp_files = list(
                Path(directory).glob(
                    ".hunt-analysis-validation-debug.json.*.tmp"
                )
            )

        self.assertEqual(payload["attempt_failure_count"], 25)
        self.assertEqual(len(payload["attempt_failures"]), 25)
        self.assertEqual(payload["attempt_failures_truncated"], 0)
        first_payload = json.loads(first)
        second_payload = json.loads(second)
        self.assertEqual(
            first_payload["attempt_failures"],
            second_payload["attempt_failures"],
        )
        self.assertEqual(temp_files, [])

    def test_report_uses_checkpoint_and_documents_update_cursor(self):
        state = flow_analysis.initial_state(
            scope_type="hunt", scope_id="H.1", analysis_id="A.1"
        )
        state["analysis_method"] = "update"
        state["checkpoint"] = {
            "row_count": 12,
            "result": {
                "answer": "Grounded result.",
                "findings": [],
                "limitations": [],
                "bounded_follow_up": [],
            },
        }
        state["inventory"]["last_successful_check_at"] = "2026-08-13T11:00:00Z"
        report = flow_analysis_coordinator.render_hunt_report(
            state, question="What is suspicious?"
        )
        self.assertIn("Analysis method: `update`", report)
        self.assertIn("Cumulative reviewed rows: 12", report)
        self.assertIn("2026-08-13T11:00:00Z", report)

    def test_canonical_report_omits_uninitialized_flow_section(self):
        flow_state = flow_analysis.initial_state(
            scope_type="hunt", scope_id="H.specialized", analysis_id=""
        )
        specialized_state = {
            "hunt_id": "H.specialized",
            "status": "complete",
            "coverage": "complete",
            "result_review_coverage": "complete",
            "target_execution_coverage": "not_assessed",
            "artifacts": {},
        }

        report = flow_analysis_coordinator.render_canonical_hunt_report(
            hunt_root=Path("/tmp/H.specialized"),
            question="What is suspicious?",
            flow_state=flow_state,
            specialized_state=specialized_state,
        )

        self.assertIn("The specialized analyzer has refreshed", report)
        self.assertIn("Result review: `complete`", report)
        self.assertNotIn("Result review: `incomplete`", report)
        self.assertNotIn("No completed result rows were available", report)

    def test_canonical_report_renders_compact_specialized_detail(self):
        specialized_state = {
            "hunt_id": "H.autoruns",
            "status": "complete",
            "coverage": "complete",
            "result_review_coverage": "complete",
            "target_execution_coverage": "not_assessed",
            "artifacts": {
                "IG.Windows.Sysinternals.Autoruns": {
                    "status": "complete",
                    "current_total": 100,
                    "autoruns_golden": {
                        "source_rows": 100,
                        "matched_rows": 60,
                        "residual_rows": 40,
                    },
                    "autoruns_residual_workflow": {
                        "mode": "general-golden-residual",
                        "stage": "complete",
                        "stack": {
                            "group_count": 8,
                            "represented_rows": 40,
                            "persisted": False,
                        },
                        "classification": {
                            "suspicious_count": 1,
                            "potential_golden_count": 2,
                            "potential_golden": {
                                "path": "analysis/autoruns_potential_golden.csv",
                                "sha256": "a" * 64,
                            },
                        },
                        "suspicious_context": {
                            "row_count": 1,
                            "host_count": 1,
                            "persisted": False,
                            "representative_items": [
                                {
                                    "identity_sha256": "b" * 64,
                                    "ImagePath": "example.exe",
                                    "Reason": "Unexpected persistence.",
                                    "row_count": 1,
                                    "host_count": 1,
                                    "endpoints": [{
                                        "fqdn": "host-one.example.test",
                                        "client_id": "C.1",
                                        "row_count": 1,
                                    }],
                                    "persistence": [{
                                        "category": "Logon",
                                        "entry_location": r"HKCU\Software\Vendor\Run",
                                        "entry": "Example",
                                    }],
                                    "source": {
                                        "hunt_id": "H.autoruns",
                                        "artifact": "IG.Windows.Sysinternals.Autoruns",
                                        "query_sha256": "c" * 64,
                                    },
                                }
                            ],
                        },
                    },
                }
            },
        }

        report = flow_analysis_coordinator.render_canonical_hunt_report(
            hunt_root=Path("/tmp/H.autoruns"),
            question="Review persistence",
            specialized_state=specialized_state,
        )

        self.assertIn("### Autoruns GoldenDB reduction", report)
        self.assertIn("### Streaming review", report)
        self.assertIn("example.exe", report)
        self.assertIn("host-one.example.test", report)
        self.assertIn("C.1", report)
        self.assertIn(r"HKCU\Software\Vendor\Run", report)
        self.assertIn("Source query", report)
        self.assertIn(
            "[analysis/autoruns_potential_golden.csv]", report
        )


if __name__ == "__main__":
    unittest.main()
