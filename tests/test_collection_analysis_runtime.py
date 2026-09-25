from __future__ import annotations

import asyncio
import csv
import io
import re
import unittest
from dataclasses import replace
from pathlib import Path

from vraptor.analyze import limits as analysis_limits
from vraptor.common import token_budget
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentResult
from vraptor.analyze import summary as analysis_summary
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import runtime as collection_analysis_runtime


TEST_LIMITS = analysis_limits.resolve_analysis_limits({})


def execution_spec(
    enabled: bool = True,
    provider: str = "openai",
    model: str = "gpt-5.6-luna",
    reasoning_effort: str = "high",
    timeout_seconds: int = 600,
    max_retries: int = 2,
    max_concurrency: int = 20,
) -> ResolvedAgentExecution:
    route = ResolvedAgentRoute(
        provider=provider,
        model=model,
        protocol="responses",
        enabled=enabled,
        reasoning_effort=reasoning_effort,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        max_concurrency=max_concurrency,
    )
    return ResolvedAgentExecution(route=route)


def spec() -> ResolvedAgentExecution:
    return execution_spec()


def execute_host_synthesis(**kwargs):
    return asyncio.run(
        collection_analysis_runtime.execute_host_synthesis_from_artifact_results_async(
            **kwargs
        )
    )


def execute_analysis_workload(**kwargs):
    return asyncio.run(
        collection_analysis_runtime.execute_analysis_workload_async(**kwargs)
    )


def validated_pool(*args, **kwargs):
    return asyncio.run(
        collection_analysis_runtime._validated_pool_async(*args, **kwargs)
    )


def payload(artifacts: int = 1, rows: int = 2) -> dict:
    return {
        "investigation_id": "IR1",
        "hostname": "host01",
        "client_id": "C.1",
        "request_id": "request-1",
        "requested_artifacts": [f"Artifact.{index}" for index in range(artifacts)],
        "artifact_flows": [
            {
                "artifact": f"Artifact.{index}",
                "artifact_name": f"Artifact.{index}",
                "flow_id": f"F.{index}",
                "flow_state": "FINISHED",
                "total_rows": rows,
                "available_result_components": [f"Artifact.{index}"],
                "matching_flow_found": True,
                "is_finished": True,
            }
            for index in range(artifacts)
        ],
    }


def profiles(artifacts: int) -> dict:
    return {
        f"Artifact.{index}": {
            "enabled": True,
            "review": {"analysis_fields": ["When", "Command"]},
        }
        for index in range(artifacts)
    }


def successful(task: AgentRequest, output: str) -> AgentResult:
    return AgentResult(
        task_id=task.task_id,
        status="succeeded",
        output=output,
        output_file="",
        events_file="",
        manifest_file="",
        elapsed_seconds=0.01,
    )


def chunk_output(task: AgentRequest) -> str:
    return "\n".join(
        [
            "RESULT\tno_reportable_findings",
            "END",
        ]
    )


def synthesis_output(task: AgentRequest) -> str:
    return "\n".join(
        [
            "ANSWER",
            "No reportable findings were identified.",
            "FINDINGS",
            "None.",
            "RELEVANT_CONTEXT",
            "None.",
            "LIMITATIONS",
            "None.",
            "FOLLOW_UP",
            "None.",
            *(["DISPOSITIONS", "None."] if task.metadata["stage"] == "host-synthesis" else []),
            "END",
        ]
    )


def artifact_result(
    index: int,
    *,
    artifact: str | None = None,
    status: str = "complete",
) -> dict:
    return {
        "format": "artifact-analysis-v2",
        "task_id": f"artifact-task-{index}",
        "artifact": artifact or f"Artifact.{index}",
        "question": "What is security relevant?",
        "status": status,
        "coverage": {
            "planned_chunks": 1,
            "accepted_chunks": 1 if status != "failed" else 0,
            "planned_rows": 2,
            "reviewed_rows": 2 if status != "failed" else 0,
        },
        "answer": "No reportable findings were identified.",
        "findings": [],
        "relevant_context": [],
        "limitations": [],
        "bounded_follow_up": [],
    }


class CollectionAnalysisRuntimeTest(unittest.TestCase):
    def test_flat_legacy_limit_fields_are_rejected(self):
        legacy_plan = {
            "model_context_tokens": 400_000,
            "operational_context_tokens": 360_000,
            "maximum_input_tokens": 272_000,
            "maximum_output_tokens": 64_000,
            "token_encoding": "o200k_base",
        }

        with self.assertRaisesRegex(ValueError, "missing analysis_limits"):
            collection_analysis_runtime.limits_from_plan(legacy_plan)

    def test_model_visible_csv_requires_source_reference(self):
        with self.assertRaisesRegex(ValueError, "required _SourceRef"):
            collection_analysis_runtime.model_visible_csv("Value\nexample\n")

    def test_model_visible_csv_hides_internal_metadata_and_lists_fields(self):
        visible, selectable = collection_analysis_runtime.model_visible_csv(
            "_Artifact,_Component,_FlowId,_RowNumber,_SourceRef,EventID,Command\n"
            "Artifact.Test,Result,F.1,7,S0001-R7,4688,whoami\n"
        )

        self.assertEqual(selectable, ["EventID", "Command"])
        self.assertEqual(
            next(csv.DictReader(io.StringIO(visible))),
            {"_SourceRef": "S0001-R7", "EventID": "4688", "Command": "whoami"},
        )
        self.assertNotIn("_FlowId", visible)
        self.assertNotIn("_RowNumber", visible)

    def test_report_reference_ranges_remain_source_qualified(self):
        self.assertEqual(
            analysis_summary.compress_refs(
                [
                    "S0002-R3",
                    "S0001-R1004",
                    "S0001-R1005",
                    "S0002-R1",
                ]
            ),
            "S0001-R1004–R1005, S0002-R1, S0002-R3",
        )
        with self.assertRaises(ValueError):
            analysis_summary.compress_refs(["R1"])

    def test_artifact_report_names_are_readable_and_collision_resistant(self):
        slash = analysis_summary.safe_artifact_name("Artifact/A")
        dash = analysis_summary.safe_artifact_name("Artifact-A")
        case_variant = analysis_summary.safe_artifact_name("artifact-a")

        self.assertNotEqual(slash, dash)
        self.assertNotEqual(dash.casefold(), case_variant.casefold())
        self.assertTrue(slash.startswith("Artifact-A--"))
        self.assertRegex(slash, r"--[0-9a-f]{10}$")
        self.assertEqual(
            analysis_summary.artifact_report_path("Artifact/A").parent.name,
            "artifact-analysis",
        )

    def build(self, *, artifact_count: int, rows: list[dict], limit: int):
        return collection_analysis.build_analysis_workload(
            object(),
            payload(artifact_count, len(rows)),
            limits=replace(
                TEST_LIMITS,
                maximum_evidence_tokens_per_item=limit,
            ),
            collection_type="triage",
            profiles=profiles(artifact_count),
            query_rows=lambda *_args: rows,
        )

    def test_compact_evidence_without_fields_remains_synthesis_compatible(self):
        worker = collection_analysis_runtime._artifact_as_host_worker(
            {
                "artifact": "Artifact.Test",
                "coverage": {"reviewed_rows": 1},
                "findings": [
                    {
                        "id": "F1",
                        "confidence": "high",
                        "domains": ["Execution"],
                        "summary": "Grounded compact finding.",
                        "evidence": [
                            {
                                "artifact": "Artifact.Test",
                                "ref": "S0001-R1",
                                "source": {
                                    "client_id": "C.1",
                                    "flow_id": "F.1",
                                    "source_row_number": 1,
                                },
                            }
                        ],
                    }
                ],
            },
            index=0,
            count=1,
        )

        self.assertEqual(worker["findings"][0]["rows"][0]["fields"], {})
        self.assertEqual(worker["findings"][0]["rows"][0]["ref"], "S0001-R1")

    def test_synthesis_prompt_excludes_large_hydrated_evidence_values(self):
        marker = "POWERSHELL-EVIDENCE-" + ("X" * 1_500_000)
        accepted = {
            "chunk-0": {
                "artifact": "Windows.EventLogs.EvtxHunter",
                "chunk_index": 0,
                "chunk_count": 1,
                "row_start": 0,
                "row_end": 1,
                "row_count": 1,
                "result": "findings",
                "findings": [
                    {
                        "id": "F1",
                        "confidence": "high",
                        "domains": ["Execution"],
                        "summary": "Suspicious PowerShell execution.",
                        "rows": [
                            {
                                "ref": "S0001-R1",
                                "fields": {
                                    "Message": marker,
                                    "Provider": "PowerShell",
                                },
                            }
                        ],
                    }
                ],
                "relevant_context": [],
                "explained": [],
                "limitations": [],
                "bounded_follow_up": [],
            }
        }

        prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="Windows.EventLogs.EvtxHunter",
            question="Was malicious execution observed?",
            accepted_chunks=accepted,
            failures={},
        )

        self.assertNotIn(marker, prompt)
        self.assertIn("EVIDENCE\tF1\tS0001-R1", prompt)
        self.assertIn(
            "Inside FINDINGS, emit only FINDING and EVIDENCE records",
            prompt,
        )
        self.assertIn(
            "tactic set must be a subset of the union of those cited records' tactics",
            prompt,
        )
        self.assertLess(len(prompt), 10_000)

    def test_synthesis_validation_rejects_reference_omitted_from_compact_input(self):
        worker = {
            "artifact": "Artifact.Test",
            "chunk_index": 0,
            "chunk_count": 1,
            "row_start": 0,
            "row_end": 4,
            "row_count": 4,
            "result": "findings",
            "findings": [
                {
                    "id": "F1",
                    "confidence": "high",
                    "domains": ["Execution"],
                    "summary": "Four related executions.",
                    "rows": [
                        {
                            "ref": f"S0001-R{index}",
                            "fields": {"Command": f"command-{index}"},
                        }
                        for index in range(1, 5)
                    ],
                }
            ],
            "relevant_context": [],
            "explained": [],
            "limitations": [],
            "bounded_follow_up": [],
        }
        visible = collection_analysis_runtime.bounded_synthesis_chunks(
            {"chunk-0": worker}
        )
        prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="Artifact.Test",
            question="What executed?",
            accepted_chunks=visible,
            failures={},
        )
        story = "\n".join(
            [
                "ANSWER",
                "One execution.",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution\tExecution.",
                "EVIDENCE\tM1\tS0001-R4",
                "RELEVANT_CONTEXT",
                "None.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        self.assertIn("OMITTED_EVIDENCE_ROWS\tF1\t1", prompt)
        self.assertNotIn("EVIDENCE\tF1\tS0001-R4", prompt)
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            'code="unavailable_source".*ref="S0001-R4"',
        ):
            collection_analysis.validate_analysis_story(
                story,
                task="Artifact.Test",
                question="What executed?",
                expected_chunks=[{"row_count": 4}],
                accepted_chunks=visible,
            )

    def test_synthesis_output_policy_changes_by_intent_and_depth(self):
        base = {
            "task": "host-analysis",
            "question": "What happened?",
            "accepted_chunks": {},
            "failures": {},
        }

        host = collection_analysis_runtime.render_synthesis_prompt(
            **base,
            task_mode="host_forensics",
            response_depth="deep",
        )
        rapid = collection_analysis_runtime.render_synthesis_prompt(
            **base,
            task_mode="incident_response",
            response_depth="rapid",
        )
        assessment = collection_analysis_runtime.render_synthesis_prompt(
            **base,
            task_mode="compromise_assessment",
            response_depth="standard",
        )

        self.assertIn("timestamp | host | user/session", host)
        self.assertIn("label incomplete review provisional", rapid)
        self.assertIn("baseline and prevalence observations", assessment)

        mode_markers = {
            "incident_response": "bounded incident question",
            "targeted_hunt": "exact hunt seed and filters",
            "host_forensics": "direct host assessment",
            "compromise_assessment": "environment and coverage",
        }
        depth_markers = {
            "rapid": "highest-signal conclusions",
            "standard": "prioritized findings",
            "deep": "full bounded chronology",
        }
        for mode, mode_marker in mode_markers.items():
            for depth, depth_marker in depth_markers.items():
                with self.subTest(mode=mode, depth=depth):
                    policy = collection_analysis_runtime.synthesis_output_policy(
                        task_mode=mode,
                        response_depth=depth,
                    )
                    self.assertIn(mode_marker, policy)
                    if mode == "host_forensics" and depth == "deep":
                        self.assertIn("timestamp | host | user/session", policy)
                    else:
                        self.assertIn(depth_marker, policy)

    def test_public_host_synthesis_handles_zero_artifact_results_without_executor(self):
        artifact_results = []
        events = []

        final = (
            execute_host_synthesis(
                plan={"artifact_tasks": [], "collection_failures": []},
                artifact_results=artifact_results,
                question="What is security relevant?",
                progress_callback=events.append,
            )
        )

        self.assertEqual(set(final), {"status", "host_result", "tasks"})
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["tasks"], [])
        self.assertEqual(final["host_result"]["final_review"]["status"], "failed")
        self.assertEqual(events[-1]["phase"], "host")

    def test_public_host_synthesis_handles_one_result_and_collection_failure(self):
        artifact_results = [
            artifact_result(
                0,
                artifact="Windows.Forensics.Prefetch",
            )
        ]
        plan = {
            "artifact_tasks": [
                {
                    "task_id": "artifact-task-0",
                    "artifact": "Windows.Forensics.Prefetch",
                }
            ],
            "collection_failures": [
                {
                    "artifact": "Windows.Forensics.Prefetch",
                    "state": "partial",
                }
            ],
        }

        final = (
            execute_host_synthesis(
                plan=plan,
                artifact_results=artifact_results,
                question="What is security relevant?",
            )
        )

        self.assertEqual(final["status"], "complete_with_failures")
        self.assertEqual(final["tasks"][0]["attempts"], 0)
        self.assertEqual(artifact_results[0]["status"], "complete_with_failures")
        self.assertIn(
            "Windows.Forensics.Prefetch: partial",
            final["host_result"]["limitations"],
        )
        self.assertEqual(
            final["host_result"]["domain_assessments"]["execution"]["status"],
            "unknown_due_to_coverage",
        )

    def test_public_host_synthesis_handles_many_results_with_one_validated_task(self):
        artifact_results = [artifact_result(0), artifact_result(1)]
        stages = []
        events = []

        def execute(task: AgentRequest) -> AgentResult:
            stages.append(task.metadata["stage"])
            return successful(task, synthesis_output(task))

        final = (
            execute_host_synthesis(
                plan={
                    "artifact_tasks": [
                        {
                            "task_id": f"artifact-task-{index}",
                            "artifact": f"Artifact.{index}",
                        }
                        for index in range(2)
                    ],
                    "collection_failures": [],
                },
                artifact_results=artifact_results,
                question="What is security relevant?",
                execute=execute,
                progress_callback=events.append,
            )
        )

        self.assertEqual(final["status"], "complete")
        self.assertEqual(stages, ["host-synthesis"])
        self.assertEqual(len(final["tasks"]), 1)
        self.assertEqual(final["tasks"][0]["status"], "accepted")
        self.assertEqual(events[-1]["phase"], "host")

    def test_multi_artifact_host_synthesis_preserves_context_and_source_provenance(self):
        artifact_results = [artifact_result(0), artifact_result(1)]
        artifact_results[0].update(
            {
                "answer": "Artifact answer retained.",
                "findings": [
                    {
                        "id": "F7",
                        "confidence": "high",
                        "domains": ["Execution"],
                        "summary": "Suspicious command execution.",
                        "evidence": [
                            {
                                "artifact": "Artifact.0",
                                "chunk_index": 3,
                                "chunk_count": 7,
                                "ref": "S0001-R9",
                                "fields": {"Command": "powershell.exe -enc AAA"},
                            }
                        ],
                    }
                ],
                "relevant_context": [
                    {
                        "artifact": "Artifact.0",
                        "chunk_index": 2,
                        "chunk_count": 7,
                        "ref": "S0001-R7",
                        "finding_id": "F7",
                        "context_type": "identity",
                        "summary": "Retained artifact context.",
                        "fields": {"When": "2026-08-10T00:00:00Z"},
                    }
                ],
            }
        )
        prompts = []

        def execute(task: AgentRequest) -> AgentResult:
            prompts.append(task.prompt)
            return successful(
                task,
                "\n".join(
                    [
                        "ANSWER",
                        "Suspicious execution was retained.",
                        "FINDINGS",
                        "FINDING\tM1\thigh\tExecution\tSuspicious command execution.",
                        "EVIDENCE\tM1\tS0001-R9",
                        "RELEVANT_CONTEXT",
                        "CONTEXT\tS0001-R7\tRetained artifact context.",
                        "LIMITATIONS",
                        "None.",
                        "FOLLOW_UP",
                        "None.",
                        "DISPOSITIONS",
                        "DISPOSITION\tA0001:F7\tsupported_finding\tM1\tS0001-R9\tCorroborated execution relevant to chronology.",
                        "END",
                    ]
                ),
            )

        final = (
            execute_host_synthesis(
                plan={
                    "artifact_tasks": [
                        {
                            "task_id": f"artifact-task-{index}",
                            "artifact": f"Artifact.{index}",
                        }
                        for index in range(2)
                    ],
                    "collection_failures": [],
                },
                artifact_results=artifact_results,
                question="What is security relevant?",
                execute=execute,
            )
        )

        self.assertIn("ANSWER\tArtifact answer retained.", prompts[0])
        self.assertIn(
            "CONTEXT\tA0001:F7\tS0001-R7\tidentity\tRetained artifact context.",
            prompts[0],
        )
        self.assertIn("powershell.exe -enc AAA", prompts[0])
        self.assertIn("2026-08-10T00:00:00Z", prompts[0])
        evidence = final["host_result"]["findings"][0]["evidence"][0]
        self.assertEqual(evidence["chunk_index"], 3)
        self.assertEqual(evidence["chunk_count"], 7)
        self.assertEqual(evidence["ref"], "S0001-R9")
        self.assertEqual(evidence["fields"], {"Command": "powershell.exe -enc AAA"})
        context = final["host_result"]["relevant_context"][0]
        self.assertEqual(context["artifact"], "Artifact.0")
        self.assertEqual(context["chunk_index"], 2)
        self.assertEqual(context["chunk_count"], 7)
        self.assertEqual(context["ref"], "S0001-R7")
        self.assertEqual(context["fields"], {"When": "2026-08-10T00:00:00Z"})

    def test_host_synthesis_disambiguates_same_artifact_sources_without_renumbering(self):
        artifact_results = [
            artifact_result(0, artifact="Artifact.Same"),
            artifact_result(1, artifact="Artifact.Same"),
        ]
        for index, result in enumerate(artifact_results, start=1):
            result["findings"] = [
                {
                    "id": "F1",
                    "confidence": "high",
                    "domains": ["Execution"],
                    "summary": f"Source {index} execution.",
                    "evidence": [
                        {
                            "artifact": "Artifact.Same",
                            "chunk_index": index + 10,
                            "chunk_count": 20,
                            "ref": f"S{index:04d}-R1004",
                            "fields": {"Command": f"command-{index}"},
                            "source": {
                                "flow_id": f"F.{index}",
                                "source_alias": f"S{index:04d}",
                                "source_row_number": 1004,
                            },
                        }
                    ],
                }
            ]

        prompts = []

        def execute(task: AgentRequest) -> AgentResult:
            prompts.append(task.prompt)
            return successful(
                task,
                "\n".join(
                    [
                        "ANSWER",
                        "The second source executed a command.",
                        "FINDINGS",
                        "FINDING\tM1\thigh\tExecution\tSecond source execution.",
                        "EVIDENCE\tM1\tS0002-R1004",
                        "RELEVANT_CONTEXT",
                        "None.",
                        "LIMITATIONS",
                        "None.",
                        "FOLLOW_UP",
                        "None.",
                        "DISPOSITIONS",
                        "DISPOSITION\tA0001:F1\tomit\t-\tS0001-R1004\tOutside the question.",
                        "DISPOSITION\tA0002:F1\tsupported_finding\tM1\tS0002-R1004\tRelevant execution.",
                        "END",
                    ]
                ),
            )

        final = execute_host_synthesis(
            plan={
                "scope_type": "host",
                "artifact_tasks": [
                    {"task_id": "artifact-task-0", "artifact": "Artifact.Same"},
                    {"task_id": "artifact-task-1", "artifact": "Artifact.Same"},
                ],
                "collection_failures": [],
            },
            artifact_results=artifact_results,
            question="What is security relevant?",
            execute=execute,
        )

        self.assertIn("EVIDENCE\tA0001:F1\tS0001-R1004", prompts[0])
        self.assertIn("EVIDENCE\tA0002:F1\tS0002-R1004", prompts[0])
        evidence = final["host_result"]["findings"][0]["evidence"][0]
        self.assertEqual(evidence["ref"], "S0002-R1004")
        self.assertEqual(evidence["chunk_index"], 12)
        self.assertEqual(evidence["source"]["flow_id"], "F.2")

    def test_aggregate_host_fan_in_over_limit_uses_complete_fallback(self):
        artifact_results = []
        for index in range(4):
            result = artifact_result(index)
            result.update(
                {
                    "answer": f"Artifact {index} answer " + ("A" * 400),
                    "findings": [
                        {
                            "id": f"F{index}",
                            "confidence": "high",
                            "domains": ["Execution"],
                            "summary": f"Finding {index} " + ("S" * 400),
                            "evidence": [
                                {
                                    "artifact": f"Artifact.{index}",
                                    "chunk_index": index + 2,
                                    "chunk_count": 9,
                                    "ref": f"S{index + 1:04d}-R{index + 10}",
                                    "fields": {"Command": f"command-{index}"},
                                }
                            ],
                        }
                    ],
                    "relevant_context": [
                        {
                            "artifact": f"Artifact.{index}",
                            "chunk_index": index + 3,
                            "chunk_count": 9,
                            "ref": f"S{index + 1:04d}-R{index + 20}",
                            "summary": f"Context {index} " + ("C" * 400),
                            "fields": {"When": f"time-{index}"},
                        }
                    ],
                }
            )
            artifact_results.append(result)
        host_workers = {
            f"artifact-{index}": collection_analysis_runtime._artifact_as_host_worker(
                result,
                index=index,
                count=len(artifact_results),
            )
            for index, result in enumerate(artifact_results)
        }
        host_expected = [
            {
                "chunk_index": index,
                "chunk_count": len(artifact_results),
                "row_count": 2,
            }
            for index in range(len(artifact_results))
        ]
        single_prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="host-analysis",
            question="What is security relevant?",
            accepted_chunks={"artifact-0": host_workers["artifact-0"]},
            failures={},
        )
        aggregate_prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="host-analysis",
            question="What is security relevant?",
            accepted_chunks=host_workers,
            failures={},
        )
        encoding = "o200k_base"
        maximum = token_budget.estimate_tokens(single_prompt, encoding)
        self.assertGreater(
            token_budget.estimate_tokens(aggregate_prompt, encoding),
            maximum,
        )
        calls = 0

        def execute(_task: AgentRequest) -> AgentResult:
            nonlocal calls
            calls += 1
            raise AssertionError("oversized host synthesis must not execute")

        final = (
            execute_host_synthesis(
                plan={
                    "artifact_tasks": [
                        {
                            "task_id": f"artifact-task-{index}",
                            "artifact": f"Artifact.{index}",
                        }
                        for index in range(len(artifact_results))
                    ],
                    "collection_failures": [],
                    "analysis_limits": {
                        "maximum_input_tokens": maximum,
                        "token_encoding": encoding,
                    },
                },
                artifact_results=artifact_results,
                question="What is security relevant?",
                execute=execute,
            )
        )

        self.assertEqual(calls, 0)
        self.assertEqual(final["status"], "complete_with_failures")
        self.assertEqual(final["host_result"]["findings"], [])
        self.assertEqual(final["host_result"]["final_review"]["status"], "failed")
        self.assertEqual(len(artifact_results), 4)
        self.assertEqual(artifact_results[3]["findings"][0]["evidence"][0]["ref"], "S0004-R13")
        self.assertEqual(final["tasks"][0]["attempts"], 0)

    def test_public_host_synthesis_fails_closed_for_unanalyzed_collection_failure(self):
        final = (
            execute_host_synthesis(
                plan={
                    "artifact_tasks": [
                        {
                            "task_id": "artifact-task-0",
                            "artifact": "Windows.EventLogs.RDPAuth",
                        }
                    ],
                    "collection_failures": [
                        {
                            "artifact": "Windows.EventLogs.RDPAuth",
                            "error": "collection did not finish",
                        }
                    ],
                },
                artifact_results=[],
                question="Was lateral movement observed?",
            )
        )

        self.assertEqual(final["status"], "failed")
        self.assertIn(
            "Windows.EventLogs.RDPAuth: collection did not finish",
            final["host_result"]["limitations"],
        )
        self.assertEqual(
            final["host_result"]["domain_assessments"]["authentication"]["status"],
            "unknown_due_to_coverage",
        )
        self.assertEqual(
            final["host_result"]["domain_assessments"]["lateral_movement"]["status"],
            "unknown_due_to_coverage",
        )

    def test_parallel_direct_artifacts_then_one_host_synthesis(self):
        plan, chunks = self.build(
            artifact_count=2,
            rows=[
                {"When": "2026-08-10T00:00:00Z", "Command": "one"},
                {"When": "2026-08-10T00:01:00Z", "Command": "two"},
            ],
            limit=9_900,
        )
        stages = []

        def execute(task: AgentRequest) -> AgentResult:
            stages.append(task.metadata["stage"])
            output = chunk_output(task) if task.metadata["stage"] == "chunk" else synthesis_output(task)
            return successful(task, output)

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="Was malicious execution observed?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=execute,
        )

        self.assertEqual(stages.count("chunk"), 2)
        self.assertNotIn("artifact-synthesis", stages)
        self.assertEqual(stages.count("host-synthesis"), 1)
        self.assertEqual(run["status"], "complete")
        self.assertFalse(run["evidence_persisted"])

    def test_empty_plan_needs_no_agent_runtime(self):
        plan, chunks = self.build(artifact_count=1, rows=[], limit=9_900)
        disabled = execution_spec(
            enabled=False,
            provider="openai",
            model="",
            reasoning_effort="",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=20,
        )

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="What is security relevant?",
            spec=disabled,
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
        )

        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["host_result"]["final_review"]["status"], "failed")

    def test_partial_collection_evidence_cannot_close_as_complete(self):
        source = payload(1, 2)
        source["artifact_flows"][0]["flow_state"] = "ERROR"
        plan, chunks = collection_analysis.build_analysis_workload(
            object(),
            source,
            limits=replace(
                TEST_LIMITS,
                maximum_evidence_tokens_per_item=9_900,
            ),
            collection_type="triage",
            profiles=profiles(1),
            query_rows=lambda *_args: [
                {"When": "2026-08-10T00:00:00Z", "Command": "one"},
                {"When": "2026-08-10T00:01:00Z", "Command": "two"},
            ],
        )

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="What is security relevant?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=lambda task: successful(task, chunk_output(task)),
        )

        self.assertEqual(run["status"], "complete_with_failures")
        self.assertIn("Artifact.0: partial", run["host_result"]["limitations"])

    def test_deterministic_input_limit_failure_is_not_retried(self):
        plan, chunks = self.build(
            artifact_count=1,
            rows=[{"When": "2026-08-10T00:00:00Z", "Command": "one"}],
            limit=9_900,
        )
        calls = 0

        def execute(task: AgentRequest) -> AgentResult:
            nonlocal calls
            calls += 1
            return AgentResult(
                task_id=task.task_id,
                status="failed",
                output="",
                output_file="",
                events_file="",
                manifest_file="",
                elapsed_seconds=0.0,
                error="Agent prompt exceeds maximum input tokens (273000 > 272000).",
            )

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="What is security relevant?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=execute,
        )

        self.assertEqual(calls, 1)
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["tasks"][0]["attempts"], 1)

    def test_chunked_artifact_retries_invalid_chunk_then_synthesizes_once(self):
        rows = [
            {"When": f"2026-08-10T00:{index:02d}:00Z", "Command": "x " * 80}
            for index in range(8)
        ]
        plan, chunks = self.build(artifact_count=1, rows=rows, limit=150)
        attempts: dict[str, int] = {}
        stages = []

        def execute(task: AgentRequest) -> AgentResult:
            stages.append(task.metadata["stage"])
            attempts[task.task_id] = attempts.get(task.task_id, 0) + 1
            if task.metadata["stage"] == "chunk":
                output = (
                    "invalid"
                    if attempts[task.task_id] == 1 and task.task_id.endswith("chunk-0")
                    else chunk_output(task)
                )
            else:
                output = synthesis_output(task)
            return successful(task, output)

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="What is security relevant?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=execute,
        )

        self.assertGreater(plan["chunk_count"], 1)
        self.assertEqual(attempts[next(key for key in attempts if key.endswith("chunk-0"))], 2)
        self.assertEqual(stages.count("artifact-synthesis"), 1)
        self.assertEqual(stages.count("host-synthesis"), 1)
        self.assertEqual(run["status"], "complete")

    def test_artifact_synthesis_over_limit_preserves_all_accepted_chunks(self):
        rows = [
            {"When": f"2026-08-10T00:{index:02d}:00Z", "Command": "x " * 80}
            for index in range(8)
        ]
        plan, chunks = self.build(artifact_count=1, rows=rows, limit=150)
        self.assertGreater(plan["chunk_count"], 1)
        expected = [
            {
                **chunk,
                "chunk_index": int(chunk["task_chunk_index"]),
                "chunk_count": int(chunk["task_chunk_count"]),
            }
            for chunk in plan["chunks"]
        ]
        compact_workers = {}
        for chunk in plan["chunks"]:
            source = next(
                csv.DictReader(
                    io.StringIO(chunks[int(chunk["chunk_index"])])
                )
            )
            compact_workers[f"chunk-{chunk['task_chunk_index']}"] = {
                "artifact": chunk["artifact"],
                "chunk_index": int(chunk["task_chunk_index"]),
                "chunk_count": int(chunk["task_chunk_count"]),
                "row_start": int(chunk["row_start"]),
                "row_end": int(chunk["row_end"]),
                "row_count": int(chunk["row_count"]),
                "result": "findings",
                "findings": [
                    {
                        "id": "F1",
                        "confidence": "high",
                        "domains": ["Execution"],
                        "summary": "Accepted chunk finding.",
                        "rows": [
                            {
                                "ref": source["_SourceRef"],
                                "fields": {"Command": source["Command"]},
                            }
                        ],
                    }
                ],
                "relevant_context": [
                    {
                        "ref": source["_SourceRef"],
                        "summary": "Accepted chunk context.",
                        "fields": {"When": source["When"]},
                    }
                ],
                "explained": [],
                "limitations": [],
                "bounded_follow_up": [],
            }
        single_prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="Artifact.0",
            question="Was malicious execution observed?",
            accepted_chunks={"chunk-0": compact_workers["chunk-0"]},
            failures={},
        )
        aggregate_prompt = collection_analysis_runtime.render_synthesis_prompt(
            task="Artifact.0",
            question="Was malicious execution observed?",
            accepted_chunks=compact_workers,
            failures={},
        )
        encoding = str(plan["analysis_limits"]["token_encoding"])
        plan["analysis_limits"]["maximum_input_tokens"] = token_budget.estimate_tokens(
            single_prompt,
            encoding,
        )
        self.assertGreater(
            token_budget.estimate_tokens(aggregate_prompt, encoding),
            plan["analysis_limits"]["maximum_input_tokens"],
        )
        stages = []

        def execute(task: AgentRequest) -> AgentResult:
            stages.append(task.metadata["stage"])
            self.assertEqual(task.metadata["stage"], "chunk")
            chunk = dict(task.metadata["chunk"])
            source = next(
                csv.DictReader(
                    io.StringIO(chunks[int(chunk["chunk_index"])])
                )
            )
            ref = source["_SourceRef"]
            return successful(
                task,
                "\n".join(
                    [
                        "RESULT\tfindings",
                        "FINDING\tF1\thigh\tExecution\tAccepted chunk finding.",
                        f"EVIDENCE\tF1\t{ref}",
                        f"CONTEXT\t{ref}\tAccepted chunk context.",
                        "END",
                    ]
                ),
            )

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="Was malicious execution observed?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=execute,
        )

        artifact = run["artifact_results"][0]
        self.assertEqual(set(stages), {"chunk"})
        self.assertEqual(run["status"], "complete_with_failures")
        self.assertEqual(artifact["status"], "complete_with_failures")
        self.assertEqual(len(artifact["findings"]), 1)
        self.assertEqual(
            len(artifact["findings"][0]["evidence"]),
            plan["chunk_count"],
        )
        self.assertEqual(len(artifact["relevant_context"]), plan["chunk_count"])
        self.assertEqual(
            {
                item["chunk_index"]
                for item in artifact["findings"][0]["evidence"]
            },
            set(range(plan["chunk_count"])),
        )
        synthesis_record = next(
            item for item in run["tasks"] if item["stage"] == "artifact-synthesis"
        )
        self.assertEqual(synthesis_record["attempts"], 0)

    def test_retry_prompt_contains_all_structured_defects_without_values(self):
        rendered = collection_analysis_runtime.render_retry_prompt(
            "ORIGINAL PROMPT",
            error="invalid",
            diagnostics=[
                {
                    "code": "unsupported_tactic",
                    "line": 7,
                    "value": "authentiction",
                    "allowed": ["Credential Access", "Execution"],
                },
                {
                    "code": "invalid_source_reference",
                    "line": 8,
                    "ref": "S0001-R99",
                },
            ],
        )

        self.assertIn("RETRY CORRECTION", rendered)
        self.assertEqual(rendered.count("DEFECT\t"), 2)
        self.assertIn('"value":"authentiction"', rendered)
        self.assertIn('"ref":"S0001-R99"', rendered)
        self.assertNotIn("whoami", rendered)

    def test_retry_prompt_limit_stops_before_second_execution(self):
        task = AgentRequest(
            task_id="retry-limit",
            prompt="ORIGINAL",
            output_name="retry-limit.txt",
            metadata={"stage": "host-synthesis"},
        )
        calls = []

        def execute(current: AgentRequest) -> AgentResult:
            calls.append(current.prompt)
            return successful(current, "bad")

        accepted, records = validated_pool(
            [task],
            max_concurrency=1,
            execute=execute,
            validate=lambda _task, _output: (_ for _ in ()).throw(
                ValueError("invalid synthesis")
            ),
            retry_prompt_error=lambda _prompt: "Synthesis prompt exceeds limit",
        )

        self.assertEqual(accepted, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(records["retry-limit"]["error"], "Synthesis prompt exceeds limit")

    def test_successful_retry_preserves_first_attempt_diagnostics(self):
        task = AgentRequest(
            task_id="retry-test",
            prompt="ORIGINAL",
            output_name="retry-test.txt",
            metadata={"stage": "chunk"},
            output_schema={"type": "object"},
            required_capabilities=frozenset({"stateless_operation"}),
            stream=False,
            max_output_tokens=17,
        )
        attempts = []

        def execute(current: AgentRequest) -> AgentResult:
            attempts.append(current)
            return successful(current, "bad" if len(attempts) == 1 else "good")

        def validate(_task: AgentRequest, output: str) -> dict:
            if output == "bad":
                raise collection_analysis.WorkerResultError(
                    "bad tactic",
                    diagnostics=[
                        {
                            "code": "unsupported_tactic",
                            "value": "authentiction",
                            "allowed": ["Credential Access"],
                        }
                    ],
                )
            return {"status": "complete"}

        accepted, records = validated_pool(
            [task],
            max_concurrency=1,
            execute=execute,
            validate=validate,
        )

        self.assertIn("retry-test", accepted)
        self.assertEqual(records["retry-test"]["attempts"], 2)
        self.assertEqual(len(records["retry-test"]["attempt_history"]), 2)
        self.assertEqual(
            records["retry-test"]["attempt_history"][0]["diagnostics"][0]["code"],
            "unsupported_tactic",
        )
        self.assertIn("RETRY CORRECTION", attempts[1].prompt)
        self.assertEqual(attempts[1].max_output_tokens, 17)
        self.assertEqual(attempts[1].output_schema, {"type": "object"})
        self.assertEqual(
            attempts[1].required_capabilities,
            frozenset({"stateless_operation"}),
        )
        self.assertFalse(attempts[1].stream)

    def test_output_limit_failure_does_not_receive_correction_retry(self):
        task = AgentRequest(
            task_id="output-limit",
            prompt="ORIGINAL",
            output_name="output-limit.txt",
            metadata={"stage": "chunk"},
            max_output_tokens=17,
        )
        calls = []

        def execute(current: AgentRequest) -> AgentResult:
            calls.append(current)
            return AgentResult(
                task_id=current.task_id,
                status="failed",
                output="",
                output_file="",
                events_file="",
                manifest_file="",
                elapsed_seconds=0.01,
                error="Agent output exceeds maximum output tokens",
                error_classification="output_too_large",
                max_output_tokens_requested=17,
                local_output_tokens=18,
            )

        accepted, records = validated_pool(
            [task],
            max_concurrency=1,
            execute=execute,
            validate=lambda _task, _output: {"status": "complete"},
        )

        self.assertEqual(accepted, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(records["output-limit"]["attempts"], 1)
        self.assertEqual(
            records["output-limit"]["run"]["error_classification"],
            "output_too_large",
        )

    def test_external_scheduler_owns_validation_retry_as_one_work_item(self):
        task = AgentRequest(
            task_id="scheduled-retry",
            prompt="ORIGINAL",
            output_name="scheduled-retry.txt",
            metadata={"stage": "chunk"},
        )
        prompts = []
        scheduled = []

        def execute(current: AgentRequest) -> AgentResult:
            prompts.append(current.prompt)
            return successful(current, "bad" if len(prompts) == 1 else "good")

        def validate(_task: AgentRequest, output: str) -> dict:
            if output == "bad":
                raise ValueError("retry required")
            return {"status": "complete"}

        async def schedule(current, worker):
            scheduled.append(current.task_id)
            return await worker(current)

        accepted, records = validated_pool(
            [task],
            max_concurrency=4,
            execute=execute,
            validate=validate,
            schedule=schedule,
        )

        self.assertEqual(scheduled, ["scheduled-retry"])
        self.assertEqual(len(prompts), 2)
        self.assertEqual(records["scheduled-retry"]["attempts"], 2)
        self.assertIn("scheduled-retry", accepted)

    def test_partial_artifact_propagates_to_multi_artifact_host_status(self):
        rows = [
            {"When": f"2026-08-10T00:{index:02d}:00Z", "Command": "x " * 80}
            for index in range(8)
        ]
        plan, chunks = self.build(artifact_count=2, rows=rows, limit=150)

        def execute(task: AgentRequest) -> AgentResult:
            if (
                task.metadata["stage"] == "chunk"
                and task.metadata["chunk"]["artifact"] == "Artifact.0"
                and task.metadata["chunk"]["task_chunk_index"] == 0
            ):
                return AgentResult(
                    task_id=task.task_id,
                    status="failed",
                    output="",
                    output_file="",
                    events_file="",
                    manifest_file="",
                    elapsed_seconds=0.01,
                    error="simulated failure",
                )
            output = (
                chunk_output(task)
                if task.metadata["stage"] == "chunk"
                else synthesis_output(task)
            )
            return successful(task, output)

        run = execute_analysis_workload(
            plan=plan,
            chunk_csv=chunks,
            question="What is security relevant?",
            spec=spec(),
            workdir=Path("/case"),
            output_dir=Path("/case/agents"),
            execute=execute,
        )

        self.assertEqual(run["artifact_results"][0]["status"], "complete_with_failures")
        self.assertEqual(run["status"], "complete_with_failures")

    def test_artifact_report_disambiguates_source_qualified_evidence_references(self):
        rendered = analysis_summary.render_artifact_report(
            {
                "artifact": "Artifact.A",
                "status": "complete",
                "coverage": {"reviewed_rows": 2, "planned_rows": 2},
                "answer": "Two chunks contain distinct rows.",
                "findings": [
                    {
                        "id": "F1",
                        "confidence": "medium",
                        "domains": ["Execution"],
                        "summary": "Distinct chunk-local rows.",
                        "evidence": [
                            {
                                "artifact": "Artifact.A",
                                "chunk_index": 0,
                                "chunk_count": 2,
                                "ref": "S0001-R1",
                                "fields": {"Command": "one"},
                                "source": {
                                    "client_id": "C.1",
                                    "flow_id": "F.A",
                                    "artifact": "Artifact.A",
                                    "source": "Component.One",
                                    "source_alias": "S0001",
                                    "source_row_number": 1,
                                },
                            },
                            {
                                "artifact": "Artifact.A",
                                "chunk_index": 1,
                                "chunk_count": 2,
                                "ref": "S0002-R1",
                                "fields": {"Command": "two"},
                                "source": {
                                    "client_id": "C.1",
                                    "flow_id": "F.A",
                                    "artifact": "Artifact.A",
                                    "source": "Component.Two",
                                    "source_alias": "S0002",
                                    "source_row_number": 1,
                                },
                            },
                        ],
                    }
                ],
                "limitations": [],
                "bounded_follow_up": [],
            }
        )

        self.assertIn(
            "`C.1 / F.A / Artifact.A / Component.One / S0001-R1`",
            rendered,
        )
        self.assertIn(
            "`C.1 / F.A / Artifact.A / Component.Two / S0002-R1`",
            rendered,
        )
        self.assertIn("`Artifact.A:S0001-R1` Command=one", rendered)
        self.assertIn("`Artifact.A:S0002-R1` Command=two", rendered)

    def test_artifact_report_deduplicates_selected_full_values(self):
        result = artifact_result(0, artifact="Windows.EventLogs.EvtxHunter")
        result["findings"] = [
            {
                "id": "F1",
                "confidence": "high",
                "domains": ["Execution"],
                "summary": "Repeated suspicious script block.",
                "evidence": [
                    {
                        "artifact": "Windows.EventLogs.EvtxHunter",
                        "chunk_index": index,
                        "chunk_count": 2,
                        "ref": f"S0001-R{index + 1}",
                        "fields": {
                            "ScriptBlockText": "Invoke-Example -Argument value",
                            "Evidence SHA-256": "internal-dedup-value",
                        },
                        "_full_fields": {
                            "ScriptBlockText": "Invoke-Example -Argument value",
                            "ParentProcess": "services.exe",
                            "EventTime": f"2026-08-13T00:00:0{index}Z",
                            "Evidence SHA-256": "internal-dedup-value",
                        },
                    }
                    for index in range(2)
                ],
            }
        ]

        rendered = analysis_summary.render_artifact_report(result)

        self.assertIn("Repeated selected rows represented: 2", rendered)
        self.assertEqual(rendered.count("### Evidence "), 1)
        self.assertEqual(rendered.count("Invoke-Example -Argument value"), 2)
        self.assertIn('"ParentProcess": "services.exe"', rendered)
        self.assertNotIn("internal-dedup-value", rendered)

    def test_compact_result_limits_representative_examples(self):
        result = artifact_result(0)
        result["findings"] = [
            {
                "id": "F1",
                "confidence": "medium",
                "domains": ["Execution"],
                "summary": "Grouped executions.",
                "evidence": [
                    {
                        "artifact": "Artifact.0",
                        "chunk_index": 0,
                        "chunk_count": 1,
                        "ref": f"S0001-R{index + 1}",
                        "fields": {"Command": f"command-{index}"},
                    }
                    for index in range(6)
                ],
            }
        ]
        result["relevant_context"] = [
            {
                "finding_id": "F1",
                "context_type": "identity",
                "artifact": "Artifact.0",
                "ref": "S0001-R1",
                "summary": "Execution was attributed to the svc-backup account.",
                "fields": {"User": "svc-backup"},
            }
        ]

        compact = analysis_summary.compact_result(result)

        self.assertEqual(compact["findings"][0]["occurrence_count"], 6)
        self.assertEqual(len(compact["findings"][0]["examples"]), 3)

        chat_summary = analysis_summary.render_chat_summary(
            compact,
            title="Host host01 analysis summary",
            status="complete",
        )
        self.assertIn("## Host host01 analysis summary", chat_summary)
        self.assertIn("Grouped executions.", chat_summary)
        self.assertIn("### Relevant context", chat_summary)
        self.assertIn("`F1` `identity`", chat_summary)
        self.assertIn("User=svc-backup", chat_summary)
        self.assertIn("### Limitations", chat_summary)
        self.assertIn("### Next action", chat_summary)
        self.assertLessEqual(
            len(chat_summary),
            analysis_summary.MAX_CHAT_SUMMARY_CHARS,
        )

    def test_compact_result_keeps_all_findings_and_indexes_after_twenty(self):
        result = artifact_result(0)
        result["findings"] = [
            {
                "id": f"F{index + 1}",
                "confidence": "high" if index == 24 else "medium",
                "domains": ["Execution"],
                "summary": f"Finding summary {index + 1}.",
                "evidence": [
                    {
                        "artifact": "Artifact.0",
                        "chunk_index": 0,
                        "chunk_count": 1,
                        "ref": f"S0001-R{index + 1}",
                        "fields": {"Command": f"command-{index + 1}"},
                    }
                ],
            }
            for index in range(25)
        ]

        compact = analysis_summary.compact_result(result)

        self.assertEqual(compact["finding_count"], 25)
        self.assertEqual(compact["primary_finding_count"], 20)
        self.assertEqual(compact["indexed_finding_count"], 5)
        self.assertEqual(compact["findings_omitted_from_summary"], 0)
        self.assertEqual(len(compact["findings"]), 25)
        self.assertEqual(len(compact["findings"][19]["examples"]), 1)
        self.assertEqual(compact["findings"][20]["examples"], [])
        self.assertEqual(len(compact["findings"][20]["sources"]), 1)

        rendered = "\n".join(analysis_summary.render_compact_findings(compact))
        self.assertIn("### F20: Finding summary 20.", rendered)
        self.assertNotIn("### F21: Finding summary 21.", rendered)
        self.assertIn("### Additional findings index", rendered)
        self.assertIn("`F21` [medium] Finding summary 21.", rendered)
        self.assertIn("`F25` [high] Finding summary 25.", rendered)
        self.assertIn(
            "Finding representation: 20 detailed, 5 indexed, 0 unavailable.",
            rendered,
        )

        recompact = analysis_summary.compact_result(compact)
        self.assertEqual(len(recompact["findings"]), 25)
        self.assertEqual(recompact["findings"][20]["occurrence_count"], 1)
        self.assertEqual(len(recompact["findings"][20]["sources"]), 1)

    def test_failed_authentication_artifact_prevents_negative_domain_conclusion(self):
        guarded = collection_analysis_runtime.apply_domain_guard(
            plan={
                "artifact_tasks": [
                    {
                        "artifact": "Windows.EventLogs.RDPAuth",
                    }
                ]
            },
            artifact_results=[
                {
                    "artifact": "Windows.EventLogs.RDPAuth",
                    "status": "failed",
                }
            ],
            host_result={
                "findings": [],
                "limitations": [],
            },
        )

        self.assertEqual(
            guarded["domain_assessments"]["authentication"]["status"],
            "unknown_due_to_coverage",
        )
        self.assertEqual(
            guarded["domain_assessments"]["lateral_movement"]["status"],
            "unknown_due_to_coverage",
        )
        self.assertEqual(
            guarded["domain_assessments"]["network"]["status"],
            "unknown_due_to_coverage",
        )
        self.assertIn("accepted evidence only", guarded["limitations"][0])

    def test_observed_domain_is_derived_from_validated_finding(self):
        assessments = collection_analysis_runtime.derive_domain_assessments(
            plan={
                "artifact_tasks": [
                    {
                        "artifact": "Windows.Network.NetstatEnriched",
                    }
                ]
            },
            artifact_results=[
                {
                    "artifact": "Windows.Network.NetstatEnriched",
                    "status": "complete",
                }
            ],
            host_findings=[
                {
                    "domains": ["Command and Control"],
                }
            ],
        )

        self.assertEqual(assessments["network"]["status"], "observed")
        self.assertEqual(
            assessments["lateral_movement"]["status"],
            "not_observed_in_accepted_evidence",
        )

    def test_failed_host_synthesis_cannot_emit_negative_domain_assessment(self):
        guarded = collection_analysis_runtime.apply_domain_guard(
            plan={
                "artifact_tasks": [
                    {
                        "artifact": "Windows.Forensics.Prefetch",
                    }
                ]
            },
            artifact_results=[
                {
                    "artifact": "Windows.Forensics.Prefetch",
                    "status": "complete",
                }
            ],
            host_result={
                "status": "failed",
                "findings": [],
                "limitations": ["host synthesis failed"],
            },
        )

        self.assertEqual(
            guarded["domain_assessments"]["execution"]["status"],
            "unknown_due_to_coverage",
        )
        self.assertIn(
            "host-analysis-synthesis",
            guarded["domain_assessments"]["execution"]["failed_artifacts"],
        )


if __name__ == "__main__":
    unittest.main()
