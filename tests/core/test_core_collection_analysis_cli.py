from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import command as collection_analysis_cli
from vraptor.analyze import profiles as collection_analysis_profiles
from vraptor.analyze import checkpoints as host_analysis_state


TEST_LIMITS = analysis_limits.resolve_analysis_limits({})
TEST_POLICY = collection_analysis_cli.artifact_policy.load_artifact_policy()


def execution_spec(
    enabled: bool,
    provider: str,
    model: str,
    reasoning_effort: str,
    timeout_seconds: int,
    max_retries: int,
    max_concurrency: int,
    route: ResolvedAgentRoute | None = None,
) -> ResolvedAgentExecution:
    resolved_route = route or ResolvedAgentRoute(
        provider=provider,
        model=model,
        protocol="responses",
        enabled=enabled,
        reasoning_effort=reasoning_effort,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        max_concurrency=max_concurrency,
    )
    return ResolvedAgentExecution(route=resolved_route)


def args(**overrides):
    values = {
        "investigation_id": "IR1",
        "case_root": None,
        "client_id": "C.1",
        "host": None,
        "api_client": None,
        "org_id": None,
        "collection_type": "triage",
        "artifact": [],
        "supersedes_request_id": None,
        "unavailable_artifact": [],
        "env": [],
        "analysis_input": [],
        "flow_timeout_seconds": None,
        "date_after": None,
        "date_before": None,
        "mft_drive": None,
        "mft_path_regex": None,
        "mft_file_regex": None,
        "mft_size_min": None,
        "mft_size_max": None,
        "evtx_glob": None,
        "evtx_ioc_regex": None,
        "evtx_whitelist_regex": None,
        "evtx_path_regex": None,
        "evtx_channel_regex": None,
        "evtx_provider_regex": None,
        "evtx_id_regex": None,
        "evtx_vss_analysis_age": None,
        "request_id": None,
        "question": "Was malicious execution observed?",
        "timeout_seconds": 60,
        "poll_interval_seconds": 15,
        "poll_timeout_seconds": 3600,
        "force_run": False,
        "reset_artifact": [],
        "reset_analysis": False,
        "rebuild_host_summary": False,
        "debug": False,
        "readiness_manifest": None,
        "autoruns_golden_db": None,
        "no_autoruns_golden": True,
        "plan_only": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def execute_incremental_analysis(**kwargs):
    kwargs.setdefault("limits", TEST_LIMITS)
    kwargs.setdefault("policy", TEST_POLICY)
    return asyncio.run(collection_analysis_cli.execute_incremental_analysis_async(**kwargs))


def run_analysis(api, namespace):
    return asyncio.run(
        collection_analysis_cli.run_analysis_async(
            api,
            namespace,
            policy=TEST_POLICY,
            limits=TEST_LIMITS,
        )
    )


def collection_payload(*, complete: bool = True) -> dict:
    return {
        "action": "reused_existing_flows",
        "hostname": "host01",
        "client_id": "C.1",
        "request_id": "request-1",
        "target_collection_type": "triage",
        "requested_artifacts": ["Artifact.Test"],
        "all_artifacts_expected_complete": complete,
        "artifact_flows": [],
    }


def plan() -> dict:
    return {
        "schema_version": collection_analysis.ANALYSIS_PLAN_SCHEMA_VERSION,
        "reference_protocol": "source-row-v1",
        "source_aliases": {},
        "analysis_mode": "direct",
        "artifact_task_count": 1,
        "chunk_count": 1,
        "plan_fingerprint": "plan",
        "source_fingerprint": "source",
        "hostname": "host01",
        "client_id": "C.1",
        "request_id": "request-1",
        "collection_type": "triage",
        "analysis_limits": TEST_LIMITS.as_dict(),
        "analysis_limits_identity": TEST_LIMITS.identity(),
        "total_rows": 1,
        "artifact_tasks": [
            {
                "task_id": "artifact-task-1",
                "artifact": "Artifact.Test",
            }
        ],
    }


def runtime_state(*, status: str = "complete") -> dict:
    state = host_analysis_state.new_state(
        hostname="host01",
        client_id="C.1",
        request_id="request-1",
        analysis_identity="analysis",
    )
    state["status"] = status
    state["synthesis"] = {"status": status}
    return state


class CollectionAnalysisCliTest(unittest.TestCase):
    def test_host_analysis_defaults_and_explicit_assessment_mode(self):
        defaults = collection_analysis_cli.build_parser().parse_args(
            ["--id", "IR1", "--client-id", "C.1"]
        )
        assessment = collection_analysis_cli.build_parser().parse_args(
            [
                "--id",
                "IR1",
                "--client-id",
                "C.1",
                "--task-mode",
                "compromise-assessment",
                "--response-depth",
                "rapid",
            ]
        )

        self.assertEqual(defaults.task_mode, "host-forensics")
        self.assertEqual(defaults.response_depth, "")
        self.assertEqual(
            collection_analysis_profiles.response_depth_policy(
                defaults.response_depth,
                task_mode=defaults.task_mode,
            )["depth"],
            "deep",
        )
        self.assertEqual(assessment.task_mode, "compromise-assessment")
        self.assertEqual(assessment.response_depth, "rapid")

    def test_removed_limit_flags_are_rejected(self):
        for flag, value in (
            ("--max-analysis-item-tokens", "1000"),
            ("--token-encoding", "o200k_base"),
        ):
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                collection_analysis_cli.build_parser().parse_args(
                    ["--id", "IR1", "--client-id", "C.1", flag, value]
                )

    def test_time_filter_result_marks_unmapped_artifact_partial(self):
        result = collection_analysis_cli.apply_time_filter_result(
            {
                "status": "complete",
                "coverage": {"planned_rows": 2, "reviewed_rows": 2},
                "limitations": [],
            },
            {
                "time_filter": {
                    "coverage": "unsupported",
                    "unsupported_artifacts": ["Artifact.Test"],
                    "application_stage": "not_applied",
                }
            },
        )

        self.assertEqual(result["status"], "complete_with_failures")
        self.assertEqual(result["coverage"]["time_filter"], "unsupported")
        self.assertEqual(result["coverage"]["overall"], "partial")
        self.assertIn("analyzed unfiltered", result["limitations"][0])

    def test_empty_artifact_result_preserves_zero_row_coverage(self):
        result = collection_analysis_cli.empty_artifact_result(
            artifact="Artifact.Empty",
            question="Was execution observed?",
            plan={
                "total_rows": 0,
                "chunk_count": 0,
            },
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            result["coverage"],
            {
                "planned_rows": 0,
                "reviewed_rows": 0,
                "planned_chunks": 0,
                "accepted_chunks": 0,
            },
        )
        self.assertEqual(result["findings"], [])
        self.assertIn("zero rows", result["answer"])
        self.assertIn(
            "not evidence of absence",
            result["limitations"][0],
        )

    def test_combined_incremental_plan_preserves_request_wide_source_aliases(self):
        first = {
            **plan(),
            "source_aliases": {
                "source-a": {"alias": "S0001", "artifact": "Artifact.A"}
            },
            "chunks": [],
            "expected_chunk_headers": [],
            "artifacts": [],
            "artifact_tasks": [],
            "collection_failures": [],
        }
        second = {
            **plan(),
            "source_aliases": {
                "source-b": {"alias": "S0002", "artifact": "Artifact.B"}
            },
            "chunks": [],
            "expected_chunk_headers": [],
            "artifacts": [],
            "artifact_tasks": [],
            "collection_failures": [],
        }

        combined = collection_analysis_cli.combine_incremental_plans(
            [first, second],
            collection_payload(),
        )

        self.assertEqual(
            {
                source_id: metadata["alias"]
                for source_id, metadata in combined["source_aliases"].items()
            },
            {"source-a": "S0001", "source-b": "S0002"},
        )

    def test_combined_incremental_plan_rejects_alias_collision(self):
        first = {
            **plan(),
            "source_aliases": {"source-a": {"alias": "S0001"}},
            "chunks": [],
            "expected_chunk_headers": [],
            "artifacts": [],
            "artifact_tasks": [],
            "collection_failures": [],
        }
        second = {
            **plan(),
            "source_aliases": {"source-b": {"alias": "S0001"}},
            "chunks": [],
            "expected_chunk_headers": [],
            "artifacts": [],
            "artifact_tasks": [],
            "collection_failures": [],
        }

        with self.assertRaisesRegex(RuntimeError, "multiple sources"):
            collection_analysis_cli.combine_incremental_plans(
                [first, second],
                collection_payload(),
            )

    def test_current_reports_preserve_request_history_and_rebuild_links(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = "IG.Windows.Sysinternals.Autoruns"
            filename = collection_analysis_cli.analysis_summary.safe_artifact_name(artifact) + ".md"
            history = []
            for index in (1, 2):
                paths = collection_analysis_cli.analysis_paths(case_root=Path(directory),
                    investigation_id="IR1", hostname="host01", request_id=f"request-{index}")
                report = paths["artifact_reports_dir"] / filename
                report.parent.mkdir(parents=True)
                report.write_text(f"# Assessment {index}\n", encoding="utf-8")
                state = host_analysis_state.new_state(hostname="host01", client_id="C.1",
                    request_id=f"request-{index}", analysis_identity="test")
                entry = dict(artifact=artifact, analysis_status="complete", report_file=str(report),
                    report_sha256=hashlib.sha256(report.read_bytes()).hexdigest())
                state["artifacts"] = {artifact: entry}
                checkpoint = host_analysis_state.write_request_checkpoint(paths["request_checkpoint"],
                    state=state, question=f"Question {index}", host_result={"answer": "Reviewed.", "findings": []},
                    status="complete")
                # Completion time is excluded from the content fingerprint.
                checkpoint["completed_at"] = f"2026-09-0{index}T00:00:00Z"
                paths["request_checkpoint"].write_text(json.dumps(checkpoint), encoding="utf-8")
                host_analysis_state.persist(paths["host_state"], state)
                history.append((report, report.read_bytes(), paths["request_checkpoint"], paths["request_checkpoint"].read_bytes()))
            published = collection_analysis_cli.publish_host_artifact_reports(paths=paths)
            current = Path(published[artifact])
            self.assertEqual(current, Path(directory)/"IR1/systems/host01/analysis"/filename)
            self.assertEqual(current.read_bytes(), history[1][1])
            before_mtime = current.stat().st_mtime_ns
            collection_analysis_cli.publish_host_artifact_reports(paths=paths)
            self.assertEqual(current.stat().st_mtime_ns, before_mtime)
            summary = collection_analysis_cli.render_cumulative_host_memory(paths=paths)
            self.assertIn(f"]({current})", summary)
            self.assertIn(f"]({history[0][0]})", summary)
            self.assertIn("Completed analysis requests: 2", summary)
            self.assertNotIn(f"]({history[1][0]})", summary)
            for report, content, checkpoint, checkpoint_content in history:
                self.assertEqual(report.read_bytes(), content)
                self.assertEqual(checkpoint.read_bytes(), checkpoint_content)
            # A rebuild restores a damaged convenience copy from attested history.
            current.write_text("damaged current copy", encoding="utf-8")
            collection_analysis_cli.publish_host_artifact_reports(paths=paths)
            self.assertEqual(current.read_bytes(), history[1][1])
            history[1][0].write_text("damaged history", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity"):
                collection_analysis_cli.publish_host_artifact_reports(paths=paths, entries=[entry])
            self.assertEqual(current.read_bytes(), history[1][1])

    def test_host_memory_is_cumulative_across_request_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_paths = collection_analysis_cli.analysis_paths(
                case_root=root,
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            first_state = runtime_state()
            host_analysis_state.write_request_checkpoint(
                first_paths["request_checkpoint"],
                state=first_state,
                question="First question?",
                host_result={
                    "status": "complete",
                    "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                    "answer": "Complete.",
                    "findings": [],
                    "limitations": [],
                },
                status="complete",
                task_mode="host_forensics",
                response_depth="deep",
            )
            second_paths = collection_analysis_cli.analysis_paths(
                case_root=root,
                investigation_id="IR1",
                hostname="host01",
                request_id="request-2",
            )
            second_state = host_analysis_state.new_state(
                hostname="host01",
                client_id="C.1",
                request_id="request-2",
                analysis_identity="analysis",
            )
            host_analysis_state.write_request_checkpoint(
                second_paths["request_checkpoint"],
                state=second_state,
                question="Second question?",
                host_result={
                    "status": "complete",
                    "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                    "answer": "Complete.",
                    "findings": [],
                    "limitations": [],
                },
                status="complete",
            )
            host_analysis_state.persist(second_paths["host_state"], second_state)
            report = collection_analysis_cli.render_cumulative_host_memory(
                paths=second_paths
            )

            self.assertIn("## Request request-1", report)
            self.assertIn("## Request request-2", report)

    def test_deep_host_memory_renders_only_unambiguous_utc_timeline_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            state = runtime_state()
            host_analysis_state.write_request_checkpoint(
                paths["request_checkpoint"],
                state=state,
                question="What happened?",
                host_result={
                    "status": "complete",
                    "coverage": {"planned_rows": 2, "reviewed_rows": 2},
                    "answer": "One material execution was observed.",
                    "findings": [
                        {
                            "id": "F1",
                            "confidence": "high",
                            "summary": "Encoded PowerShell execution",
                            "examples": [
                                {
                                    "label": "Windows.Events:S0001-R7",
                                    "fields": {
                                        "EventTime": "2026-01-02T13:04:05+11:00",
                                        "Username": "DOMAIN\\analyst",
                                        "CommandLine": "powershell.exe -enc AAAA",
                                    },
                                },
                                {
                                    "label": "Windows.Events:S0001-R8",
                                    "fields": {
                                        "EventTime": "2026-01-02 13:05:00",
                                        "Username": "DOMAIN\\analyst",
                                    },
                                },
                            ],
                        }
                    ],
                    "relevant_context": [],
                    "limitations": [],
                },
                status="complete",
                task_mode="host_forensics",
                response_depth="deep",
            )
            host_analysis_state.persist(paths["host_state"], state)

            report = collection_analysis_cli.render_cumulative_host_memory(paths=paths)

            self.assertIn("### UTC timeline", report)
            self.assertIn("2026-01-02T02:04:05Z", report)
            self.assertIn("DOMAIN\\analyst", report)
            self.assertIn("Windows.Events:S0001-R7", report)
            self.assertNotIn("| 2026-01-02 13:05:00 |", report)

    def test_rapid_host_memory_omits_deep_timeline_section(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            state = runtime_state()
            host_analysis_state.write_request_checkpoint(
                paths["request_checkpoint"],
                state=state,
                question="What is highest priority?",
                host_result={
                    "status": "complete",
                    "coverage": {},
                    "answer": "One high-signal finding.",
                    "findings": [],
                    "relevant_context": [],
                    "limitations": [],
                },
                status="complete",
                task_mode="host_forensics",
                response_depth="rapid",
            )
            host_analysis_state.persist(paths["host_state"], state)

            report = collection_analysis_cli.render_cumulative_host_memory(paths=paths)

            self.assertIn("- Response depth: `rapid`", report)
            self.assertNotIn("### UTC timeline", report)

    def test_host_memory_does_not_load_legacy_reference_state(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-new",
            )
            paths["host_state"].parent.mkdir(parents=True)
            paths["host_state"].write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "hostname": "host01",
                        "client_id": "C.1",
                        "requests": {
                            "legacy": {
                                "result": {
                                    "findings": [
                                        {
                                            "evidence": [{"ref": "R1"}],
                                        }
                                    ]
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = collection_analysis_cli.render_cumulative_host_memory(paths=paths)

            self.assertIn("Completed analysis requests: 0", report)
            self.assertNotIn("R1", report)

    def test_ensure_reuse_then_poll_before_analysis(self):
        initial = collection_payload(complete=False)
        terminal = collection_payload(complete=True)
        with mock.patch.object(
            collection_analysis_cli.collection,
            "resolve_cli_collection_target",
            return_value=("host01", object()),
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "build_request_from_args",
            return_value=object(),
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "ensure_collection",
            return_value=initial,
        ) as ensure, mock.patch.object(
            collection_analysis_cli.collection,
            "poll_collection",
            return_value=terminal,
        ) as poll:
            hostname, payload, action = collection_analysis_cli.resolve_collection(
                object(), args(), policy=TEST_POLICY
            )

        self.assertEqual(hostname, "host01")
        self.assertIs(payload, terminal)
        self.assertEqual(action, "reused_existing_flows")
        ensure.assert_called_once()
        poll.assert_called_once()

    def test_new_request_validates_supersession_before_ensure(self):
        request = mock.Mock()
        initial = collection_payload()
        with mock.patch.object(
            collection_analysis_cli.collection,
            "resolve_cli_collection_target",
            return_value=("host01", object()),
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "build_request_from_args",
            return_value=request,
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "validate_request_supersession",
        ) as validate, mock.patch.object(
            collection_analysis_cli.collection,
            "ensure_collection",
            return_value=initial,
        ):
            collection_analysis_cli.resolve_collection(
                object(), args(), policy=TEST_POLICY
            )

        validate.assert_called_once_with(
            "IR1",
            "host01",
            request,
            api=mock.ANY,
            client=mock.ANY,
        )

    def test_incremental_manager_starts_first_terminal_artifact_before_poll_finishes(self):
        first_started = threading.Event()
        first_finished = threading.Event()
        observed_source_aliases = {}
        initial = {
            **collection_payload(complete=False),
            "requested_artifacts": ["Artifact.A", "Artifact.B"],
            "artifact_flows": [
                {
                    "artifact": "Artifact.A",
                    "flow_id": "F.A",
                    "is_finished": True,
                    "total_rows": 1,
                },
                {
                    "artifact": "Artifact.B",
                    "flow_id": "F.B",
                    "is_finished": False,
                    "total_rows": 0,
                },
            ],
        }
        terminal = {
            **initial,
            "all_artifacts_expected_complete": True,
            "artifact_flows": [
                initial["artifact_flows"][0],
                {
                    **initial["artifact_flows"][1],
                    "is_finished": True,
                    "total_rows": 1,
                },
            ],
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="model-one",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=2,
        )

        def build(_api, _args, payload_value, **kwargs):
            artifact = payload_value["requested_artifacts"][0]
            observed_source_aliases[artifact] = {
                source_id: metadata["alias"]
                for source_id, metadata in kwargs["source_aliases"].items()
            }
            if artifact == "Artifact.A":
                first_started.set()
            return (
                {
                    **plan(),
                    "source_fingerprint": artifact,
                    "plan_fingerprint": artifact,
                    "total_rows": 1,
                    "chunk_count": 1,
                    "artifacts": [{"artifact": artifact}],
                    "artifact_tasks": [
                        {"task_id": f"task-{artifact}", "artifact": artifact}
                    ],
                    "artifact_task_count": 1,
                    "collection_failures": [],
                },
                {0: "csv"},
            )

        def execute_workload(**kwargs):
            artifact = kwargs["plan"]["artifact_tasks"][0]["artifact"]
            if artifact == "Artifact.A":
                first_finished.set()
            return {
                "status": "complete",
                "artifact_results": [
                    {
                        "artifact": artifact,
                        "status": "complete",
                        "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                        "findings": [],
                        "limitations": [],
                        "bounded_follow_up": [],
                    }
                ],
                "tasks": (
                    [
                        {
                            "task_id": "artifact-a-chunk-0",
                            "stage": "chunk",
                            "attempt_history": [
                                {
                                    "attempt": 1,
                                    "status": "retrying",
                                    "error": "SECRET-EVIDENCE-VALUE",
                                    "diagnostics": [
                                        {
                                            "code": "unsupported_tactic",
                                            "record": "FINDING",
                                            "line": 7,
                                            "value": "SECRET-EVIDENCE-VALUE",
                                        }
                                    ],
                                    "run": {
                                        "output": "SECRET-EVIDENCE-VALUE",
                                    },
                                }
                            ],
                        }
                    ]
                    if artifact == "Artifact.A"
                    else []
                ),
            }

        def poll(*_args, **kwargs):
            self.assertTrue(first_started.wait(1))
            self.assertTrue(first_finished.wait(1))
            persisted_complete = False
            for _attempt in range(100):
                if paths["host_state"].is_file():
                    saved = collection_analysis_cli.json.loads(
                        paths["host_state"].read_text(encoding="utf-8")
                    )
                    persisted_complete = any(
                        item.get("artifact") == "Artifact.A"
                        and item.get("analysis_status") == "complete"
                        for item in saved.get("artifacts", {}).values()
                    )
                    if persisted_complete:
                        break
                threading.Event().wait(0.01)
            self.assertTrue(persisted_complete)
            kwargs["progress_callback"](terminal)
            return terminal

        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            with mock.patch.object(
                collection_analysis_cli,
                "build_workload",
                side_effect=build,
            ), mock.patch.object(
                collection_analysis_cli.collection,
                "poll_collection",
                side_effect=poll,
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "limits_from_plan",
                return_value=mock.Mock(),
            ), mock.patch.object(
                collection_analysis_cli,
                "create_agent_runner",
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "execute_analysis_workload_async",
                side_effect=execute_workload,
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "execute_host_synthesis_from_artifact_results_async",
                return_value={
                    "status": "complete",
                    "host_result": {
                        "status": "complete",
                        "coverage": {"planned_rows": 2, "reviewed_rows": 2},
                        "findings": [],
                        "limitations": [],
                    },
                    "tasks": [],
                },
                create=True,
            ):
                combined_plan, final_run, final_state = (
                    execute_incremental_analysis(
                        api=object(),
                        args=args(debug=True),
                        hostname="host01",
                        initial_payload=initial,
                        selected_client=object(),
                        question="Was malicious execution observed?",
                        spec=analyst,
                        paths=paths,
                        update_progress=lambda _event: None,
                    )
                )
                debug_payload = json.loads(
                    Path(final_run["validation_debug"]["path"]).read_text(
                        encoding="utf-8"
                    )
                )

        self.assertTrue(first_started.is_set())
        self.assertEqual(combined_plan["artifact_task_count"], 2)
        self.assertEqual(len(final_run["artifact_results"]), 2)
        self.assertEqual(final_state["status"], "complete")
        self.assertIn("validation_debug", final_run)
        self.assertEqual(debug_payload["scope_type"], "host")
        self.assertEqual(debug_payload["attempt_failure_count"], 1)
        self.assertIn(
            "value_sha256",
            debug_payload["attempt_failures"][0]["diagnostics"][0],
        )
        self.assertNotIn("SECRET-EVIDENCE-VALUE", json.dumps(debug_payload))
        self.assertEqual(len(observed_source_aliases["Artifact.A"]), 2)
        self.assertEqual(len(observed_source_aliases["Artifact.B"]), 2)
        self.assertEqual(
            set(observed_source_aliases["Artifact.A"].values()),
            {"S0001", "S0002"},
        )
        self.assertEqual(
            set(observed_source_aliases["Artifact.B"].values()),
            {"S0001", "S0002"},
        )

    def test_artifact_failure_is_terminal_and_does_not_block_siblings(self):
        terminal = {
            **collection_payload(),
            "requested_artifacts": ["Artifact.A", "Artifact.B"],
            "artifact_flows": [
                {
                    "artifact": "Artifact.A",
                    "flow_id": "F.A",
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 1,
                },
                {
                    "artifact": "Artifact.B",
                    "flow_id": "F.B",
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 0,
                },
            ],
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="test-model",
            reasoning_effort="",
            timeout_seconds=60,
            max_retries=0,
            max_concurrency=2,
        )

        def build(_api, _args, payload_value, **_kwargs):
            artifact = payload_value["requested_artifacts"][0]
            if artifact == "Artifact.A":
                raise RuntimeError("bounded test failure")
            return (
                {
                    **plan(),
                    "source_fingerprint": artifact,
                    "plan_fingerprint": artifact,
                    "total_rows": 0,
                    "chunk_count": 0,
                    "chunks": [],
                    "expected_chunk_headers": [],
                    "artifacts": [{"artifact": artifact}],
                    "artifact_tasks": [
                        {"task_id": f"task-{artifact}", "artifact": artifact}
                    ],
                    "artifact_task_count": 1,
                    "collection_failures": [],
                },
                {},
            )

        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            with mock.patch.object(
                collection_analysis_cli,
                "build_workload",
                side_effect=build,
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "limits_from_plan",
                return_value=mock.Mock(),
            ):
                combined, final_run, final_state = execute_incremental_analysis(
                    api=object(),
                    args=args(),
                    hostname="host01",
                    initial_payload=terminal,
                    selected_client=object(),
                    question="What happened?",
                    spec=analyst,
                    paths=paths,
                    update_progress=lambda _event: None,
                )
            persisted = json.loads(paths["host_state"].read_text(encoding="utf-8"))

        self.assertEqual(final_run["status"], "complete_with_failures")
        self.assertEqual(final_state["artifacts"]["Artifact.A"]["analysis_status"], "failed")
        self.assertEqual(final_state["artifacts"]["Artifact.B"]["analysis_status"], "complete")
        self.assertEqual(persisted["artifacts"]["Artifact.A"]["result"]["status"], "failed")
        self.assertEqual(len(combined["collection_failures"]), 1)
        self.assertTrue(persisted["artifacts"]["Artifact.A"]["report_sha256"])

    def test_all_artifact_failures_publish_failed_terminal_state(self):
        terminal = {
            **collection_payload(),
            "requested_artifacts": ["Artifact.A"],
            "artifact_flows": [
                {
                    "artifact": "Artifact.A",
                    "flow_id": "F.A",
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 1,
                }
            ],
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="test-model",
            reasoning_effort="",
            timeout_seconds=60,
            max_retries=0,
            max_concurrency=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            with mock.patch.object(
                collection_analysis_cli,
                "build_workload",
                side_effect=RuntimeError("bounded test failure"),
            ):
                combined, final_run, final_state = execute_incremental_analysis(
                    api=object(),
                    args=args(),
                    hostname="host01",
                    initial_payload=terminal,
                    selected_client=object(),
                    question="What happened?",
                    spec=analyst,
                    paths=paths,
                    update_progress=lambda _event: None,
                )

        self.assertEqual(final_run["status"], "failed")
        self.assertEqual(final_state["status"], "failed")
        self.assertEqual(final_state["artifacts"]["Artifact.A"]["analysis_status"], "failed")
        self.assertEqual(len(combined["collection_failures"]), 1)

    def test_analysis_cache_identity_changes_with_question_and_execution_route(self):
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=2,
        )
        first = collection_analysis_cli.analysis_cache_identity(
            args(),
            question="Question one?",
            spec=analyst,
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )
        second = collection_analysis_cli.analysis_cache_identity(
            args(),
            question="Question two?",
            spec=analyst,
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )
        third = collection_analysis_cli.analysis_cache_identity(
            args(),
            question="Question one?",
            spec=execution_spec(
                True, "openai", "model-two", "high", 600, 2, 2
            ),
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )

        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)

    def test_analysis_cache_identity_excludes_route_source_paths(self):
        first_execution = execution_spec(
            True,
            "openai",
            "model",
            "",
            60,
            1,
            2,
            route=ResolvedAgentRoute(
                "openai",
                "model",
                "responses",
                harness_config_path="/first/config.toml",
                credential_variable="FIRST_SECRET",
            ),
        )
        second_execution = execution_spec(
            True,
            "openai",
            "model",
            "",
            60,
            1,
            2,
            route=ResolvedAgentRoute(
                "openai",
                "model",
                "responses",
                harness_config_path="/second/config.toml",
                credential_variable="SECOND_SECRET",
            ),
        )
        first = collection_analysis_cli.analysis_cache_identity(
            args(),
            question="Question?",
            spec=first_execution,
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )
        second = collection_analysis_cli.analysis_cache_identity(
            args(),
            question="Question?",
            spec=second_execution,
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )

        self.assertEqual(first, second)

    def test_semantic_file_identity_ignores_location(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.json"
            second = root / "nested" / "second.json"
            second.parent.mkdir()
            first.write_bytes(b"same-content")
            second.write_bytes(b"same-content")

            self.assertEqual(
                collection_analysis_cli.semantic_file_identity(first),
                collection_analysis_cli.semantic_file_identity(second),
            )

            second.write_bytes(b"changed-content")
            self.assertNotEqual(
                collection_analysis_cli.semantic_file_identity(first),
                collection_analysis_cli.semantic_file_identity(second),
            )

    def test_semantic_file_identity_distinguishes_missing_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"

            self.assertEqual(
                collection_analysis_cli.semantic_file_identity(missing),
                {"state": "missing", "sha256": ""},
            )

    def test_degraded_cache_reuse_requires_no_failed_analysis_tasks(self):
        base = {
            "status": "complete_with_failures",
            "artifact_results": [{"status": "complete_with_failures"}],
            "tasks": [{"status": "accepted"}],
        }
        self.assertTrue(
            collection_analysis_cli.artifact_analysis_run_is_cacheable(base)
        )
        self.assertFalse(
            collection_analysis_cli.artifact_analysis_run_is_cacheable(
                {
                    **base,
                    "tasks": [{"status": "failed"}],
                }
            )
        )
        self.assertFalse(
            collection_analysis_cli.artifact_analysis_run_is_cacheable(
                {
                    **base,
                    "artifact_results": [{"status": "failed"}],
                }
            )
        )

    def test_incremental_manager_explicitly_resets_failed_artifact(self):
        terminal = {
            **collection_payload(),
            "requested_artifacts": ["Artifact.A"],
            "artifact_flows": [
                {
                    "artifact": "Artifact.A",
                    "flow_id": "F.A",
                    "is_finished": True,
                    "total_rows": 1,
                }
            ],
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=1,
        )
        selected_args = args(
            request_id="request-1",
            reset_artifact=["Artifact.A"],
        )
        identity = collection_analysis_cli.analysis_cache_identity(
            selected_args,
            question="Was execution observed?",
            spec=analyst,
            limits=TEST_LIMITS,
            policy=TEST_POLICY,
        )
        child_plan = {
            **plan(),
            "source_fingerprint": "source",
            "plan_fingerprint": "plan",
            "total_rows": 1,
            "chunk_count": 1,
            "chunks": [],
            "expected_chunk_headers": [],
            "artifacts": [{"artifact": "Artifact.A"}],
            "artifact_tasks": [
                {"task_id": "task-a", "artifact": "Artifact.A", "chunk_indices": []}
            ],
            "artifact_task_count": 1,
            "collection_failures": [],
        }
        completed_run = {
            "status": "complete",
            "plan_fingerprint": "plan",
            "source_fingerprint": "source",
            "artifact_results": [
                {
                    "artifact": "Artifact.A",
                    "status": "complete",
                    "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                    "findings": [],
                    "limitations": [],
                    "bounded_follow_up": [],
                }
            ],
            "tasks": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            saved_state = host_analysis_state.new_state(
                hostname="host01",
                client_id="C.1",
                request_id="request-1",
                analysis_identity=identity,
            )
            saved_state["artifacts"] = {
                "Artifact.A": {
                    "artifact": "Artifact.A",
                    "flow_id": "F.A",
                    "source_fingerprint": host_analysis_state.artifact_source_fingerprint(
                        terminal["artifact_flows"][0],
                        analysis_identity=identity,
                    ),
                    "analysis_status": "failed",
                    "attempts": 1,
                }
            }
            host_analysis_state.persist(paths["host_state"], saved_state)
            with mock.patch.object(
                collection_analysis_cli,
                "build_workload",
                return_value=(child_plan, {}),
            ) as build, mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "limits_from_plan",
                return_value=mock.Mock(),
            ), mock.patch.object(
                collection_analysis_cli,
                "create_agent_runner",
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "execute_analysis_workload_async",
                return_value=completed_run,
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "execute_host_synthesis_from_artifact_results_async",
                return_value={
                    "status": "complete_with_failures",
                    "host_result": {
                        "status": "complete_with_failures",
                        "coverage": {"planned_rows": 0, "reviewed_rows": 0},
                        "findings": [],
                        "limitations": ["test limitation"],
                    },
                    "tasks": [],
                },
            ):
                _combined, final_run, final_state = (
                    execute_incremental_analysis(
                        api=object(),
                        args=selected_args,
                        hostname="host01",
                        initial_payload=terminal,
                        selected_client=object(),
                        question="Was execution observed?",
                        spec=analyst,
                        paths=paths,
                        update_progress=lambda _event: None,
                    )
                )

            persisted = collection_analysis_cli.json.loads(
                paths["host_state"].read_text(encoding="utf-8")
            )

        build.assert_called_once()
        self.assertEqual(final_run["status"], "complete_with_failures")
        self.assertEqual(persisted["status"], "complete_with_failures")
        self.assertEqual(final_state["artifacts"]["Artifact.A"]["attempts"], 2)

    def test_saved_request_rejects_collection_target_arguments(self):
        with mock.patch.object(
            collection_analysis_cli.collection,
            "resolve_cli_collection_target",
            return_value=("host01", object()),
        ):
            with self.assertRaisesRegex(RuntimeError, "cannot be combined"):
                collection_analysis_cli.resolve_collection(
                    object(), args(request_id="request-1"), policy=TEST_POLICY
                )

    def test_saved_request_without_flow_ids_fails_before_polling(self):
        saved = {
            **collection_payload(complete=False),
            "artifact_flows": [
                {
                    "artifact": "Artifact.Missing",
                    "flow_id": "",
                    "state": "MISSING",
                }
            ],
            "queue_progress": {
                "status": "failed",
                "error": "server artifact definition was unavailable",
            },
        }
        with mock.patch.object(
            collection_analysis_cli.collection,
            "resolve_cli_collection_target",
            return_value=("host01", object()),
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "status_payload",
            return_value=saved,
        ), mock.patch.object(
            collection_analysis_cli.collection,
            "poll_collection",
        ) as poll:
            with self.assertRaisesRegex(
                RuntimeError,
                "cannot be resumed or polled.*Artifact.Missing",
            ):
                collection_analysis_cli.resolve_collection(
                    object(),
                    args(
                        request_id="request-1",
                        collection_type=None,
                    ),
                    policy=TEST_POLICY,
                )

        poll.assert_not_called()

    def test_plan_only_persists_public_plan_without_agent_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            collection_analysis_cli.collection.CASE_ROOT = Path(directory)
            with mock.patch.object(
                collection_analysis_cli,
                "resolve_collection",
                return_value=("host01", collection_payload(), "reused_existing_flows"),
            ), mock.patch.object(
                collection_analysis_cli,
                "build_workload",
                return_value=(plan(), {0: "csv"}),
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_runtime,
                "execute_analysis_workload_async",
            ) as execute:
                result = run_analysis(
                    object(), args(plan_only=True)
                )

            self.assertEqual(result["status"], "planned")
            self.assertTrue(Path(result["analysis_plan_file"]).is_file())
            execute.assert_not_called()

    def test_rebuild_host_summary_does_not_launch_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            collection_analysis_cli.collection.CASE_ROOT = Path(directory)
            with mock.patch.object(
                collection_analysis_cli,
                "resolve_collection",
                return_value=("host01", collection_payload(), "reused_existing_flows"),
            ), mock.patch.object(
                collection_analysis_cli,
                "execute_incremental_analysis_async",
            ) as execute:
                result = run_analysis(
                    object(), args(rebuild_host_summary=True)
                )

            self.assertEqual(result["status"], "rebuilt")
            self.assertTrue(Path(result["host_report_file"]).is_file())
            execute.assert_not_called()

    def test_analysis_reset_requires_exact_request_id(self):
        with self.assertRaisesRegex(RuntimeError, "require --request-id"):
            run_analysis(
                object(), args(reset_artifact=["Artifact.Test"])
            )

    def test_full_run_persists_request_and_current_host_reports(self):
        run = {
            "status": "complete",
            "host_result": {
                "status": "complete",
                "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                "answer": "No reportable findings.",
                "findings": [],
                "relevant_context": [],
                "limitations": [],
                "bounded_follow_up": [],
            },
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            collection_analysis_cli.collection.CASE_ROOT = Path(directory)

            def execute(**kwargs):
                kwargs["paths"]["runtime_dir"].mkdir(parents=True)
                (kwargs["paths"]["runtime_dir"] / "transient.json").write_text(
                    "{}", encoding="utf-8"
                )
                return plan(), run, runtime_state()

            with mock.patch.object(
                collection_analysis_cli,
                "start_collection",
                return_value=(
                    "host01",
                    collection_payload(),
                    "reused_existing_flows",
                    object(),
                ),
            ), mock.patch.object(
                collection_analysis_cli,
                "resolve_agent_execution",
                return_value=analyst,
            ), mock.patch.object(
                collection_analysis_cli,
                "execute_incremental_analysis_async",
                side_effect=execute,
            ):
                result = run_analysis(object(), args())

            self.assertEqual(result["status"], "complete")
            self.assertTrue(Path(result["request_checkpoint_file"]).is_file())
            self.assertIn(
                "## Request request-1",
                Path(result["host_report_file"]).read_text(),
            )
            self.assertEqual(
                Path(result["host_report_file"]),
                Path(directory) / "IR1" / "systems" / "host01" / "analysis-host.md",
            )
            self.assertTrue(Path(result["host_state_file"]).is_file())
            self.assertEqual(result["analysis_result"]["status"], "complete")
            self.assertIn("## Host host01 analysis summary", result["chat_summary"])
            self.assertIn("No reportable findings", result["chat_summary"])
            self.assertFalse(
                Path(result["request_checkpoint_file"]).parent.joinpath(
                    ".api-runtime"
                ).exists()
            )

    def test_degraded_supersession_cannot_report_complete_baseline(self):
        run = {
            "status": "complete",
            "host_result": {
                "status": "complete",
                "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                "answer": "No reportable findings.",
                "findings": [],
                "relevant_context": [],
                "limitations": [],
                "bounded_follow_up": [],
            },
        }
        degraded_plan = {
            **plan(),
            "supersedes_request_id": "all-failed",
            "unavailable_artifacts": ["Artifact.Missing"],
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            collection_analysis_cli.collection.CASE_ROOT = Path(directory)
            with mock.patch.object(
                collection_analysis_cli,
                "start_collection",
                return_value=(
                    "host01",
                    collection_payload(),
                    "queued_new_flows",
                    object(),
                ),
            ), mock.patch.object(
                collection_analysis_cli,
                "resolve_agent_execution",
                return_value=analyst,
            ), mock.patch.object(
                collection_analysis_cli,
                "execute_incremental_analysis_async",
                return_value=(degraded_plan, run, runtime_state()),
            ):
                result = run_analysis(object(), args())

            persisted = collection_analysis_cli.json.loads(
                Path(result["request_checkpoint_file"]).read_text(encoding="utf-8")
            )
            self.assertEqual(result["status"], "complete_with_failures")
            self.assertEqual(
                persisted["result"]["status"],
                "complete_with_failures",
            )
            self.assertIn(
                "Full baseline coverage is not claimed",
                persisted["result"]["limitations"][0],
            )

    def test_running_host_report_is_updated_before_final_publication(self):
        run = {
            "status": "complete",
            "host_result": {
                "status": "complete",
                "coverage": {"planned_rows": 1, "reviewed_rows": 1},
                "answer": "One finding.",
                "findings": [],
                "relevant_context": [],
                "limitations": [],
                "bounded_follow_up": [],
            },
        }
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection_analysis_cli.collection.CASE_ROOT = root
            observed = []

            def execute(**kwargs):
                host_report = root / "IR1" / "systems" / "host01" / "analysis-host.md"
                observed.append(host_report.read_text())
                kwargs["update_progress"](
                    {
                        "phase": "chunk",
                        "task_id": "artifact-task-1-chunk-0",
                        "attempt": 1,
                        "status": "accepted",
                        "error": "",
                        "normalized": {
                            "row_count": 1,
                            "findings": [
                                {
                                    "confidence": "high",
                                    "domains": ["execution"],
                                    "summary": "Suspicious PowerShell execution.",
                                }
                            ],
                        },
                    }
                )
                observed.append(host_report.read_text())
                return plan(), run, runtime_state()

            with mock.patch.object(
                collection_analysis_cli,
                "start_collection",
                return_value=(
                    "host01",
                    collection_payload(),
                    "reused_existing_flows",
                    object(),
                ),
            ), mock.patch.object(
                collection_analysis_cli,
                "resolve_agent_execution",
                return_value=analyst,
            ), mock.patch.object(
                collection_analysis_cli,
                "execute_incremental_analysis_async",
                side_effect=execute,
            ):
                result = run_analysis(object(), args())

            self.assertIn("Provisional running report", observed[0])
            self.assertIn("Suspicious PowerShell execution.", observed[1])
            self.assertIn(
                "## Request request-1",
                Path(result["host_report_file"]).read_text(),
            )
            self.assertTrue(Path(result["request_checkpoint_file"]).is_file())

    def test_runtime_failure_leaves_failed_running_report(self):
        analyst = execution_spec(
            enabled=True,
            provider="openai",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            timeout_seconds=600,
            max_retries=2,
            max_concurrency=20,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection_analysis_cli.collection.CASE_ROOT = root

            def fail(**kwargs):
                kwargs["paths"]["runtime_dir"].mkdir(parents=True)
                (kwargs["paths"]["runtime_dir"] / "transient.json").write_text(
                    "{}", encoding="utf-8"
                )
                raise RuntimeError("simulated runtime failure")

            with mock.patch.object(
                collection_analysis_cli,
                "start_collection",
                return_value=(
                    "host01",
                    collection_payload(),
                    "reused_existing_flows",
                    object(),
                ),
            ), mock.patch.object(
                collection_analysis_cli,
                "resolve_agent_execution",
                return_value=analyst,
            ), mock.patch.object(
                collection_analysis_cli,
                "execute_incremental_analysis_async",
                side_effect=fail,
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated runtime failure"):
                    run_analysis(object(), args(debug=True))

            report = (
                root / "IR1" / "systems" / "host01" / "analysis-host.md"
            ).read_text()
            self.assertIn("- Status: `failed`", report)
            self.assertIn("simulated runtime failure", report)
            debug = json.loads(
                (
                    root
                    / "IR1"
                    / "systems"
                    / "host01"
                    / "collection"
                    / "requests"
                    / "request-1"
                    / "analysis"
                    / "host-analysis-validation-debug.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(debug["status"], "failed")
            self.assertEqual(debug["attempt_failure_count"], 1)
            self.assertNotIn("simulated runtime failure", json.dumps(debug))
            self.assertFalse(
                root.joinpath(
                    "IR1",
                    "systems",
                    "host01",
                    "collection",
                    "requests",
                    "request-1",
                    "analysis",
                    ".api-runtime",
                ).exists()
            )

    def test_transient_cleanup_rejects_output_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            request_dir = Path(directory) / "request" / "analysis"
            escaped = Path(directory) / "unrelated"
            escaped.mkdir()
            paths = {"request_dir": request_dir, "runtime_dir": escaped}

            with self.assertRaisesRegex(RuntimeError, "unexpected runtime path"):
                collection_analysis_cli.cleanup_transient_runtime(paths)

            self.assertTrue(escaped.is_dir())

    def test_analysis_invocation_does_not_create_or_wait_on_filesystem_lock(self):
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        call_count = 0
        call_lock = threading.Lock()

        def execute(**_kwargs):
            nonlocal call_count
            with call_lock:
                call_count += 1
                ordinal = call_count
            if ordinal == 1:
                first_entered.set()
                self.assertTrue(release_first.wait(2))
            else:
                second_entered.set()
            return plan(), {}, runtime_state()

        with tempfile.TemporaryDirectory() as directory:
            collection_analysis_cli.collection.CASE_ROOT = Path(directory)
            selected_args = args()
            selected_paths = collection_analysis_cli.analysis_paths(
                case_root=Path(directory),
                investigation_id="IR1",
                hostname="host01",
                request_id="request-1",
            )
            kwargs = {
                "api": object(),
                "args": selected_args,
                "hostname": "host01",
                "initial_payload": collection_payload(),
                "selected_client": object(),
                "question": "Question?",
                "spec": execution_spec(
                    enabled=True,
                    provider="openai",
                    model="test-model",
                    reasoning_effort="",
                    timeout_seconds=60,
                    max_retries=0,
                    max_concurrency=2,
                ),
                "paths": selected_paths,
                "update_progress": lambda _event: None,
            }
            with mock.patch.object(
                collection_analysis_cli,
                "_execute_incremental_analysis",
                side_effect=execute,
            ):
                first = threading.Thread(
                    target=execute_incremental_analysis,
                    kwargs=kwargs,
                )
                second = threading.Thread(
                    target=execute_incremental_analysis,
                    kwargs=kwargs,
                )
                first.start()
                self.assertTrue(first_entered.wait(1))
                second.start()
                self.assertTrue(second_entered.wait(1))
                release_first.set()
                first.join(2)
                second.join(2)

        self.assertTrue(second_entered.is_set())
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse((selected_paths["host_state"].parent / ".analysis.lock").exists())


if __name__ == "__main__":
    unittest.main()
