from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.agent.runtime import AgentRequest
from vraptor.agent.runtime import AgentResult
from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import host as collection_analysis
from vraptor.analyze import command as collection_analysis_cli
from vraptor.analyze import runtime as collection_analysis_runtime


TEST_LIMITS = analysis_limits.resolve_analysis_limits({})
TEST_POLICY = collection_analysis_cli.artifact_policy.load_artifact_policy()


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "velociraptor"
    / "paginated-multicomponent.json"
)


class PaginatedFixtureApi:
    def __init__(
        self,
        fixture: dict[str, Any],
        *,
        page_size: int,
        failed_components: set[str] | None = None,
    ):
        self.page_size = page_size
        self.failed_components = failed_components or set()
        self.rows = {
            str(component["name"]): list(component["rows"])
            for artifact in fixture["artifacts"]
            for component in artifact["components"]
        }
        self.calls: list[str] = []
        self.page_counts: dict[str, int] = {}

    def query_file(
        self,
        _filename: str,
        env: dict[str, str],
        **_kwargs: Any,
    ) -> list[dict[str, Any]]:
        component = str(env["ArtifactName"])
        self.calls.append(component)
        if component in self.failed_components:
            raise RuntimeError("fixture component failure")
        rows = self.rows[component]
        pages = [
            rows[index : index + self.page_size]
            for index in range(0, len(rows), self.page_size)
        ]
        self.page_counts[component] = len(pages)
        return [row for page in pages for row in page]


class CollectionAnalysisIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def payload(self) -> dict[str, Any]:
        return {
            "investigation_id": self.fixture["investigation_id"],
            "hostname": self.fixture["hostname"],
            "client_id": self.fixture["client_id"],
            "request_id": self.fixture["request_id"],
            "requested_artifacts": [
                artifact["artifact"] for artifact in self.fixture["artifacts"]
            ],
            "artifact_flows": [
                {
                    "artifact": artifact["artifact"],
                    "artifact_name": artifact["artifact"],
                    "flow_id": artifact["flow_id"],
                    "flow_state": "FINISHED",
                    "total_rows": sum(
                        len(component["rows"])
                        for component in artifact["components"]
                    ),
                    "available_result_components": [
                        component["name"] for component in artifact["components"]
                    ],
                    "matching_flow_found": True,
                    "is_finished": True,
                }
                for artifact in self.fixture["artifacts"]
            ],
        }

    def profiles(self) -> dict[str, Any]:
        return {
            artifact["artifact"]: {
                "enabled": True,
                "review": {
                    "analysis_fields": ["When", "Command", "User"],
                },
            }
            for artifact in self.fixture["artifacts"]
        }

    def cli_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            synthesis="full",  # This fixture exercises explicit final-review recovery.
            investigation_id=self.fixture["investigation_id"],
            case_root=None,
            client_id=self.fixture["client_id"],
            host=None,
            api_client=None,
            org_id=None,
            collection_type=None,
            artifact=[],
            env=[],
            analysis_input=[],
            flow_timeout_seconds=None,
            date_after=None,
            date_before=None,
            mft_drive=None,
            mft_path_regex=None,
            mft_file_regex=None,
            mft_size_min=None,
            mft_size_max=None,
            evtx_glob=None,
            evtx_ioc_regex=None,
            evtx_whitelist_regex=None,
            evtx_path_regex=None,
            evtx_channel_regex=None,
            evtx_provider_regex=None,
            evtx_id_regex=None,
            evtx_vss_analysis_age=None,
            request_id=self.fixture["request_id"],
            question="What activity is security relevant?",
            timeout_seconds=60,
            poll_interval_seconds=1,
            poll_timeout_seconds=60,
            force_run=False,
            token_encoding=None,
            autoruns_golden_db=None,
            no_autoruns_golden=True,
            plan_only=False,
        )

    def build(
        self,
        *,
        page_size: int,
        failed_components: set[str] | None = None,
    ) -> tuple[dict[str, Any], dict[int, str], PaginatedFixtureApi]:
        api = PaginatedFixtureApi(
            self.fixture,
            page_size=page_size,
            failed_components=failed_components,
        )
        plan, chunks = collection_analysis.build_analysis_workload(
            api,
            self.payload(),
            limits=TEST_LIMITS,
            collection_type="triage",
            profiles=self.profiles(),
        )
        return plan, chunks, api

    def test_pagination_is_fingerprint_and_reference_stable(self):
        baseline_plan, baseline_chunks, baseline_api = self.build(page_size=1)
        expected_components = [
            component["name"]
            for artifact in self.fixture["artifacts"]
            for component in artifact["components"]
        ]
        self.assertEqual(baseline_api.calls, expected_components)
        self.assertTrue(all(count >= 2 for count in baseline_api.page_counts.values()))

        for page_size in (2, 3, 100):
            with self.subTest(page_size=page_size):
                plan, chunks, api = self.build(page_size=page_size)
                self.assertEqual(api.calls, expected_components)
                self.assertEqual(
                    plan["source_fingerprint"],
                    baseline_plan["source_fingerprint"],
                )
                self.assertEqual(
                    plan["plan_fingerprint"],
                    baseline_plan["plan_fingerprint"],
                )
                self.assertEqual(chunks, baseline_chunks)

        multi_rows = [
            row
            for index in sorted(baseline_chunks)
            for row in csv.DictReader(io.StringIO(baseline_chunks[index]))
            if row["_Artifact"] == "Artifact.Multi"
        ]
        self.assertEqual(
            [row["_SourceRef"] for row in multi_rows],
            [
                "S0001-R1",
                "S0001-R2",
                "S0001-R3",
                "S0001-R4",
                "S0003-R1",
                "S0003-R2",
                "S0003-R3",
            ],
        )
        self.assertIn("Invoke-Expression $t", multi_rows[1]["Command"])
        self.assertIn('"nested":"a=b;c"', multi_rows[2]["Command"])

    def test_failed_component_preserves_successful_component_rows(self):
        plan, chunks, api = self.build(
            page_size=2,
            failed_components={"Artifact.Multi/Network"},
        )

        self.assertEqual(
            api.calls,
            [
                "Artifact.Multi/Events",
                "Artifact.Multi/Network",
                "Artifact.Second",
            ],
        )
        multi = next(
            item for item in plan["artifacts"] if item["artifact"] == "Artifact.Multi"
        )
        self.assertEqual(multi["artifact_state"], "partial")
        self.assertEqual(multi["row_count"], 4)
        self.assertEqual(
            [component["state"] for component in multi["components"]],
            ["success", "failed"],
        )
        self.assertIn("fixture component failure", multi["query_error"])
        self.assertEqual(
            [failure["artifact"] for failure in plan["collection_failures"]],
            ["Artifact.Multi"],
        )
        combined_rows = [
            row
            for index in sorted(chunks)
            for row in csv.DictReader(io.StringIO(chunks[index]))
        ]
        multi_refs = [
            row["_SourceRef"]
            for row in combined_rows
            if row["_Artifact"] == "Artifact.Multi"
        ]
        self.assertEqual(
            multi_refs,
            ["S0001-R1", "S0001-R2", "S0001-R3", "S0001-R4"],
        )

    def test_full_mocked_collect_analyze_workflow_retries_and_publishes(self):
        api = PaginatedFixtureApi(self.fixture, page_size=2)
        payload = self.payload()
        payload.update(
            {
                "target_collection_type": "triage",
                "all_artifacts_expected_complete": True,
            }
        )
        route = ResolvedAgentRoute(
            provider="openai",
            model="fixture-model",
            protocol="responses",
            reasoning_effort="high",
            timeout_seconds=60,
            max_retries=2,
            max_concurrency=4,
        )
        spec = ResolvedAgentExecution(route=route)
        attempts: dict[str, int] = {}
        fail_final_review = True

        def succeeded(task: AgentRequest, output: str) -> AgentResult:
            return AgentResult(
                task_id=task.task_id,
                status="succeeded",
                output=output,
                output_file="",
                events_file="",
                manifest_file="",
                elapsed_seconds=0.01,
            )

        def chunk_output(task: AgentRequest, *, invalid: bool = False) -> str:
            chunk = dict(task.metadata["chunk"])
            lines = [
            ]
            if invalid:
                lines.extend(
                    [
                        "RESULT\tfindings",
                        "FINDING\tF1\tmedium\tauthentiction\tInvalid first attempt.",
                        f"ROW\tF1\tR{int(chunk['row_start']) + 1}\tCommand",
                    ]
                )
            elif chunk["artifact"] == "Artifact.Multi":
                lines.extend([
                    "RESULT\tfindings",
                    "FINDING\tF1\tmedium\tExecution\tOverstated routine PowerShell finding.",
                    "EVIDENCE\tF1\tS0001-R1",
                ])
            else:
                lines.append("RESULT\tno_reportable_findings")
            lines.append("END")
            return "\n".join(lines)

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
                    *(["DISPOSITIONS",
                       "DISPOSITION\tA0001:F1\tomit\t-\tS0001-R1\tThis isolated command has no established incident linkage."]
                      if task.metadata["stage"] == "host-synthesis" else []),
                    "END",
                ]
            )

        def execute(task: AgentRequest) -> AgentResult:
            attempts[task.task_id] = attempts.get(task.task_id, 0) + 1
            if task.metadata["stage"] == "chunk":
                first_multi = (
                    task.metadata["chunk"]["artifact"] == "Artifact.Multi"
                    and attempts[task.task_id] == 1
                )
                return succeeded(task, chunk_output(task, invalid=first_multi))
            if task.metadata["stage"] == "host-synthesis" and fail_final_review:
                return succeeded(task, "invalid final review")
            return succeeded(task, synthesis_output(task))

        real_write = collection_analysis_cli.atomic_io.write_text_atomic
        writes: list[tuple[Path, str]] = []
        runner = mock.Mock()
        runner.run.side_effect = lambda task, **_kwargs: execute(task)

        def tracked_write(path: Path, text: str, **kwargs) -> None:
            writes.append((Path(path), text))
            real_write(path, text, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection_analysis_cli.collection.CASE_ROOT = root
            with mock.patch.object(
                collection_analysis_cli,
                "start_collection",
                return_value=(
                    self.fixture["hostname"],
                    payload,
                    "resumed_saved_request",
                    None,
                ),
            ), mock.patch.object(
                collection_analysis_cli.collection_analysis_profiles,
                "profile_contract",
                return_value={
                    "analysis_profile": "fixture",
                    "analysis_objectives": [
                        "Answer the investigation question from accepted rows."
                    ],
                    "artifact_strategies": {},
                },
            ), mock.patch.object(
                collection_analysis_cli,
                "resolve_agent_execution",
                return_value=spec,
            ), mock.patch.object(
                collection_analysis_cli,
                "create_agent_runner",
                return_value=runner,
            ) as create_runner, mock.patch.object(
                collection_analysis_cli.atomic_io,
                "write_text_atomic",
                side_effect=tracked_write,
            ):
                result = asyncio.run(
                    collection_analysis_cli.run_analysis_async(
                        api,
                        self.cli_args(),
                        policy=collection_analysis_cli.artifact_policy.build_artifact_policy(
                            profiles=self.profiles(),
                        ),
                        limits=TEST_LIMITS,
                    )
                )

                self.assertEqual(result["status"], "complete_with_failures")
                self.assertEqual(result["analysis_result"]["final_review"]["status"], "failed")
                troubleshooting = result["analysis_result"]["troubleshooting"]
                self.assertIn("--retry-failed", troubleshooting["resume_command"])
                diagnostic_payload = json.loads(Path(troubleshooting["diagnostics_file"]).read_text())
                failed_records = [item for item in diagnostic_payload["tasks"] if item["status"] == "failed"]
                self.assertEqual(failed_records[-1]["attempts"], 3)
                self.assertEqual(len(failed_records[-1]["attempt_history"]), 3)
                provisional_state = json.loads(Path(result["host_state_file"]).read_text())
                self.assertTrue(all(e["analysis_status"] == "complete" for e in provisional_state["artifacts"].values()))
                self.assertTrue(all(e["accepted_result_role"] == "provisional_candidates" for e in provisional_state["artifacts"].values()))
                previous_reports = {e["report_file"]: e["report_sha256"]
                                    for e in provisional_state["artifacts"].values()}
                source_calls = list(api.calls)
                chunk_attempts = {k: v for k, v in attempts.items() if "chunk" in k}
                fail_final_review = False
                # The host pointer may now belong to another request. Recover accepted
                # artifacts from this request's immutable reports and checkpoint.
                Path(result["host_state_file"]).write_text('{"schema_version": 999}')
                retry_args = self.cli_args()
                retry_args.retry_failed = True
                retry_args.request_id = payload["request_id"]
                result = asyncio.run(collection_analysis_cli.run_analysis_async(
                    api, retry_args,
                    policy=collection_analysis_cli.artifact_policy.build_artifact_policy(profiles=self.profiles()),
                    limits=TEST_LIMITS,
                ))
                for filename, expected_hash in previous_reports.items():
                    self.assertEqual(collection_analysis_cli.sha256_file(Path(filename)), expected_hash)
                self.assertEqual(api.calls, source_calls)
                self.assertEqual({k: v for k, v in attempts.items() if "chunk" in k}, chunk_attempts)
                self.assertEqual(attempts["host-analysis-synthesis"], 4)
                self.assertFalse((Path(result["host_state_file"]).parent / "previous-analysis").exists())

            self.assertEqual(create_runner.call_count, 2)

            checkpoint = json.loads(
                Path(result["request_checkpoint_file"]).read_text(encoding="utf-8")
            )
            state = json.loads(
                Path(result["host_state_file"]).read_text(encoding="utf-8")
            )
            self.assertEqual(result["status"], "complete", checkpoint)
            self.assertEqual(checkpoint["result"]["final_review"]["status"], "complete")
            for entry in state["artifacts"].values():
                self.assertEqual(entry["result"]["final_review"]["status"], "complete")
                self.assertEqual(entry["result"]["finding_count"], checkpoint["result"]["finding_count"])
                self.assertEqual(entry["result_role"], "final_publication")

            self.assertEqual(len(state["artifacts"]["Artifact.Multi"]["accepted_result"]["findings"]), 1)
            self.assertEqual(state["artifacts"]["Artifact.Multi"]["result"]["findings"], [])
            self.assertEqual(checkpoint["result"]["final_review"]["candidate_count"], 1)
            self.assertNotIn("Overstated routine PowerShell finding", Path(result["host_report_file"]).read_text())
            self.assertNotIn("Overstated routine PowerShell finding", Path(result["artifact_report_files"]["Artifact.Multi"]).read_text())
            retried = [
                artifact
                for artifact, item in state["artifacts"].items()
                if int(item.get("retry_count") or 0) > 0
            ]
            self.assertEqual(retried, ["Artifact.Multi"])
            self.assertNotIn(
                "Provisional running report",
                Path(result["host_report_file"]).read_text(encoding="utf-8"),
            )
            self.assertTrue(
                any("Provisional running report" in text for _path, text in writes)
            )
            self.assertEqual(
                set(result["artifact_report_files"]),
                {
                    str(item["artifact"])
                    for item in checkpoint["artifact_summaries"]
                },
            )
            self.assertTrue(
                all(
                    Path(path).is_file()
                    for path in result["artifact_report_files"].values()
                )
            )
            self.assertEqual(
                result["analysis_result"]["artifact_reports"],
                result["artifact_report_files"],
            )
            for item in checkpoint["artifact_summaries"]:
                current = Path(result["artifact_report_files"][item["artifact"]])
                self.assertEqual(current.parent, Path(result["host_report_file"]).parent / "analysis")
                self.assertEqual(current.read_bytes(), Path(item["report_file"]).read_bytes())
                self.assertIn(str(current), Path(result["host_report_file"]).read_text())
            durable = (
                Path(result["request_checkpoint_file"]).read_text(encoding="utf-8")
                + Path(result["host_state_file"]).read_text(encoding="utf-8")
            )
            self.assertNotIn("--- CSV EVIDENCE START ---", durable)
            self.assertNotIn("Invoke-Expression $t", durable)
            request_analysis = Path(result["request_checkpoint_file"]).parent
            self.assertFalse((request_analysis / "plan.json").exists())
            self.assertFalse((request_analysis / "run.json").exists())
            self.assertFalse((request_analysis / ".api-runtime").exists())


if __name__ == "__main__":
    unittest.main()
