from __future__ import annotations

import csv
import io
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import time_scope as analysis_time_scope
from vraptor.autoruns import golden as autoruns_golden
from vraptor.analyze import host as collection_analysis


TEST_LIMITS = analysis_limits.resolve_analysis_limits({})


def finished_payload(*, rows: int = 2, state: str = "FINISHED") -> dict:
    return {
        "investigation_id": "IR1",
        "hostname": "host01",
        "client_id": "C.1",
        "request_id": "triage-1",
        "artifact_flows": [
            {
                "artifact": "Artifact.Test",
                "artifact_name": "Artifact.Test",
                "flow_id": "F.1",
                "flow_state": state,
                "total_rows": rows,
                "available_result_components": ["Artifact.Test"] if rows else [],
                "matching_flow_found": True,
                "is_finished": True,
            }
        ],
    }


class CollectionAnalysisTest(unittest.TestCase):
    class ExactSourceApi:
        org_id = "root"

        def __init__(self, rows):
            self.rows = list(rows)
            self.queries = []

        def query(self, *_args, **_kwargs):
            return []

        def query_batches_with_metadata(self, vql, env=None, **kwargs):
            self.queries.append({"vql": vql, "env": dict(env or {})})
            encoded = [len(str(row).encode()) for row in self.rows]
            yield SimpleNamespace(
                rows=self.rows,
                row_count=len(self.rows),
                payload_bytes=sum(encoded),
                max_row_bytes=max(encoded, default=0),
            )

    def profiles(self) -> dict:
        return {
            "Artifact.Test": {
                "enabled": True,
                "review": {"analysis_fields": ["When", "Command"]},
            }
        }

    def rows(self, *_args) -> list[dict]:
        return [
            {"When": "2026-08-08T01:00:00Z", "Command": "one", "Noise": "x"},
            {"When": "2026-08-08T02:00:00Z", "Command": "two", "Noise": "y"},
        ]

    def worker_result(
        self,
        *,
        row_start: int = 0,
        row_count: int = 2,
        chunk_index: int = 0,
        chunk_count: int = 1,
        finding: bool = True,
    ) -> str:
        result = "findings" if finding else "no_reportable_findings"
        lines = [
            f"RESULT\t{result}",
        ]
        if finding:
            lines.extend(
                [
                    "FINDING\tF1\tmedium\tExecution\tSYSTEM command execution observed.",
                    f"EVIDENCE\tF1\tS0001-R{row_start + 1}",
                ]
            )
        lines.append("END")
        return "\n".join(lines)

    def validate_worker(
        self,
        result: object,
        *,
        row_start: int = 0,
        row_count: int = 2,
        chunk_index: int = 0,
        chunk_count: int = 1,
    ) -> dict:
        return collection_analysis.validate_context_worker_result(
            result,
            artifact="Artifact.Test",
            chunk_index=chunk_index,
            chunk_count=chunk_count,
            row_start=row_start,
            row_end=row_start + row_count,
            expected_row_count=row_count,
            source_rows={
                f"S0001-R{number}": {
                    "Command": "whoami",
                    "User": "SYSTEM",
                }
                for number in range(row_start + 1, row_start + row_count + 1)
            },
        )

    def test_preferred_fields_and_direct_analysis_plan(self):
        plan = collection_analysis.build_analysis_plan(
            object(),
            finished_payload(),
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=9_900),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=self.rows,
        )

        self.assertEqual(plan["analysis_mode"], "direct")
        self.assertEqual(plan["chunk_count"], 1)
        self.assertEqual(plan["artifacts"][0]["preferred_fields"], ["When", "Command"])
        self.assertGreater(plan["direct_input_tokens"], 0)
        self.assertFalse(plan["evidence_persisted"])

    def test_host_time_filter_runs_in_exact_source_query_and_keeps_source_row(self):
        profile = {
            "Artifact.Test": {
                "enabled": True,
                "review": {
                    "analysis_fields": ["When", "Command"],
                    "live_vql_select": ["When", "Command"],
                    "time_filter": {
                        "default_roles": ["event"],
                        "roles": {
                            "event": {
                                "semantics": "event time",
                                "expressions": ["When"],
                            }
                        },
                    },
                },
            }
        }
        requested = analysis_time_scope.TimeScope.from_values(
            after="2026-01-01T00:00:00Z",
            before="2027-01-01T00:00:00Z",
        )
        resolved = analysis_time_scope.resolve_for_profile(
            "Artifact.Test",
            profile["Artifact.Test"],
            requested,
        )
        api = self.ExactSourceApi(
            [
                {
                    "When": "2026-08-08T02:00:00Z",
                    "Command": "inside",
                    collection_analysis.SOURCE_ROW_NUMBER_FIELD: 2,
                }
            ]
        )

        plan, chunks = collection_analysis.build_analysis_workload(
            api,
            finished_payload(rows=2),
            limits=TEST_LIMITS,
            collection_type="triage",
            profiles=profile,
            time_scopes={"Artifact.Test": resolved},
        )

        rows = list(csv.DictReader(io.StringIO(chunks[0])))
        self.assertEqual(rows[0]["_SourceRef"], "S0001-R2")
        self.assertEqual(rows[0]["_RowNumber"], "2")
        self.assertIn("WHERE ((When > AnalysisTimeAfter", api.queries[0]["vql"])
        self.assertLess(
            api.queries[0]["vql"].index("WHERE ((When"),
            api.queries[0]["vql"].index("SELECT When"),
        )
        self.assertEqual(
            api.queries[0]["env"]["AnalysisTimeBefore"],
            "2027-01-01T00:00:00Z",
        )
        self.assertEqual(
            plan["artifacts"][0]["time_filter_validation"],
            "passed",
        )

    def test_host_projection_omits_hunt_identity_but_keeps_event_computer(self):
        profile = {
            "Artifact.Test": {
                "enabled": True,
                "review": {
                    "analysis_fields": ["When", "Computer", "ClientId"],
                    "live_vql_select": [
                        "When",
                        "Computer",
                        "ClientId",
                        "Fqdn",
                        "Hostname",
                    ],
                },
            }
        }
        api = self.ExactSourceApi(
            [
                {
                    "When": "2026-08-08T02:00:00Z",
                    "Computer": "event-origin.example.test",
                    "ClientId": "C.1",
                }
            ]
        )

        plan, _chunks = collection_analysis.build_analysis_workload(
            api,
            finished_payload(rows=1),
            limits=TEST_LIMITS,
            collection_type="triage",
            profiles=profile,
        )

        query = api.queries[0]["vql"]
        self.assertIn("SELECT When,\n       Computer,\n       ClientId", query)
        self.assertNotIn("Fqdn", query)
        self.assertNotIn("Hostname", query)
        self.assertEqual(
            plan["artifacts"][0]["preferred_fields"],
            ["When", "Computer", "ClientId"],
        )

    def test_host_time_filter_rejects_out_of_window_server_row(self):
        profile = {
            "Artifact.Test": {
                "enabled": True,
                "review": {
                    "analysis_fields": ["When", "Command"],
                    "live_vql_select": ["When", "Command"],
                    "time_filter": {
                        "default_roles": ["event"],
                        "roles": {
                            "event": {
                                "semantics": "event time",
                                "expressions": ["When"],
                            }
                        },
                    },
                },
            }
        }
        requested = analysis_time_scope.TimeScope.from_values(
            after="2026-01-01T00:00:00Z",
            before="2027-01-01T00:00:00Z",
        )
        resolved = analysis_time_scope.resolve_for_profile(
            "Artifact.Test",
            profile["Artifact.Test"],
            requested,
        )
        api = self.ExactSourceApi(
            [
                {
                    "When": "2025-12-31T23:59:59Z",
                    "Command": "outside",
                    collection_analysis.SOURCE_ROW_NUMBER_FIELD: 1,
                }
            ]
        )

        plan, chunks = collection_analysis.build_analysis_workload(
            api,
            finished_payload(rows=1),
            limits=TEST_LIMITS,
            collection_type="triage",
            profiles=profile,
            time_scopes={"Artifact.Test": resolved},
            analysis_profile_contract={
                "time_filter": {
                    "coverage": "complete",
                    "filtered_artifacts": ["Artifact.Test"],
                    "unsupported_artifacts": [],
                }
            },
        )

        self.assertEqual(chunks, {})
        self.assertEqual(plan["analysis_mode"], "empty")
        self.assertEqual(plan["time_filter"]["coverage"], "failed")
        self.assertEqual(plan["artifacts"][0]["time_filter_validation"], "failed")
        self.assertIn(
            "server-side time filter validation failed",
            plan["collection_failures"][0]["error"],
        )

    def test_host_time_filter_keeps_all_fields_without_live_projection(self):
        profile = {
            "Artifact.Test": {
                "enabled": True,
                "review": {
                    "analysis_fields": ["When", "Command"],
                    "time_filter": {
                        "default_roles": ["event"],
                        "roles": {
                            "event": {
                                "semantics": "event time",
                                "expressions": ["When"],
                            }
                        },
                    },
                },
            }
        }
        requested = analysis_time_scope.TimeScope.from_values(
            after="2026-01-01T00:00:00Z",
        )
        resolved = analysis_time_scope.resolve_for_profile(
            "Artifact.Test",
            profile["Artifact.Test"],
            requested,
        )
        api = self.ExactSourceApi(
            [
                {
                    "When": "2026-08-08T02:00:00Z",
                    "Command": "kept",
                    "AdditionalField": "available",
                    collection_analysis.SOURCE_ROW_NUMBER_FIELD: 2,
                }
            ]
        )

        _plan, chunks = collection_analysis.build_analysis_workload(
            api,
            finished_payload(rows=2),
            limits=TEST_LIMITS,
            collection_type="triage",
            profiles=profile,
            time_scopes={"Artifact.Test": resolved},
        )

        self.assertIn("SELECT *\nFROM ScopedRows", api.queries[0]["vql"])
        self.assertIn("kept", chunks[0])

    def test_direct_workload_returns_ephemeral_evidence_without_second_query(self):
        query = mock.Mock(side_effect=self.rows)
        plan, chunks = collection_analysis.build_analysis_workload(
            object(),
            finished_payload(),
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=9_900),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=query,
        )

        self.assertEqual(query.call_count, 1)
        self.assertIn("Command", chunks[0])
        self.assertEqual(plan["analysis_profile"], "detectraptor-host")

    def test_partial_flow_with_results_is_analyzed_and_retains_failure_state(self):
        payload = finished_payload(state="ERROR")
        query = mock.Mock(side_effect=self.rows)

        plan, chunks = collection_analysis.build_analysis_workload(
            object(),
            payload,
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=9_900),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=query,
        )

        self.assertEqual(query.call_count, 1)
        self.assertEqual(plan["analysis_mode"], "direct")
        self.assertEqual(plan["artifacts"][0]["artifact_state"], "partial")
        self.assertEqual(plan["collection_failures"][0]["state"], "partial")
        self.assertIn("Command", chunks[0])

    def test_multiple_artifacts_emit_parallel_artifact_tasks_not_all_context(self):
        payload = finished_payload()
        payload["artifact_flows"].append(
            {
                **payload["artifact_flows"][0],
                "artifact": "Artifact.Second",
                "artifact_name": "Artifact.Second",
                "flow_id": "F.2",
                "available_result_components": ["Artifact.Second"],
            }
        )
        query = mock.Mock(side_effect=self.rows)

        plan = collection_analysis.build_analysis_plan(
            object(),
            payload,
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=9_900),
            collection_type="triage",
            profiles={
                **self.profiles(),
                "Artifact.Second": self.profiles()["Artifact.Test"],
            },
            query_rows=query,
        )

        self.assertEqual(plan["analysis_mode"], "parallel_direct")
        self.assertEqual(plan["artifact_task_count"], 2)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(
            {task["artifact"] for task in plan["artifact_tasks"]},
            {"Artifact.Test", "Artifact.Second"},
        )
        self.assertNotIn("all", {chunk["artifact"] for chunk in plan["chunks"]})

    def test_token_limit_triggers_context_safe_row_chunks(self):
        rows = [
            {"When": f"2026-08-08T{i:02d}:00:00Z", "Command": "x " * 60}
            for i in range(8)
        ]
        plan = collection_analysis.build_analysis_plan(
            object(),
            finished_payload(rows=len(rows)),
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=110),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=lambda *_args: rows,
        )

        self.assertEqual(plan["analysis_mode"], "chunked")
        self.assertGreater(plan["chunk_count"], 1)
        self.assertEqual(sum(item["row_count"] for item in plan["chunks"]), len(rows))
        self.assertTrue(
            all(
                item["input_tokens"]
                <= plan["analysis_limits"]["maximum_evidence_tokens_per_item"]
                for item in plan["chunks"]
            )
        )
        self.assertTrue(all(item["component"] == "Artifact.Test" for item in plan["chunks"]))

    def test_workload_queries_components_once_and_chunks_artifact_rows(self):
        payload = finished_payload(rows=4)
        payload["artifact_flows"][0]["available_result_components"] = [
            "Artifact.Test/First",
            "Artifact.Test/Second",
        ]

        query_calls = []

        def query(_api, _client, _flow, component):
            query_calls.append(component)
            prefix = "first" if component.endswith("First") else "second"
            return [
                {"When": f"2026-08-08T0{i}:00:00Z", "Command": f"{prefix}-{i} " * 60}
                for i in range(2)
            ]

        plan, chunks = collection_analysis.build_analysis_workload(
            object(),
            payload,
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=280),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=query,
        )
        self.assertEqual(
            query_calls,
            ["Artifact.Test/First", "Artifact.Test/Second"],
        )
        self.assertEqual(plan["artifact_task_count"], 1)
        self.assertEqual(len(chunks), plan["chunk_count"])
        combined = "\n".join(chunks[index] for index in sorted(chunks))
        self.assertIn("first-", combined)
        self.assertIn("second-", combined)
        references = [
            row["_SourceRef"]
            for chunk in chunks.values()
            for row in csv.DictReader(io.StringIO(chunk))
        ]
        self.assertEqual(
            references,
            ["S0001-R1", "S0001-R2", "S0002-R1", "S0002-R2"],
        )

    def test_autoruns_strategy_fails_closed_without_database(self):
        autoruns_payload = finished_payload()
        autoruns_payload["requested_artifacts"] = ["Windows.Sysinternals.Autoruns"]
        autoruns_payload["artifact_flows"][0]["artifact"] = "Windows.Sysinternals.Autoruns"
        autoruns_payload["artifact_flows"][0]["artifact_name"] = "Windows.Sysinternals.Autoruns"

        plan = collection_analysis.build_analysis_plan(
            object(),
            autoruns_payload,
            limits=TEST_LIMITS,
            collection_type="persistence",
            artifact_strategies={
                "Windows.Sysinternals.Autoruns": "autoruns-goldendb"
            },
            autoruns_golden_db=Path("/definitely/missing/golden.sqlite"),
            profiles={
                "Windows.Sysinternals.Autoruns": {
                    "enabled": True,
                    "review": {"analysis_fields": ["Category", "ImagePath"]},
                }
            },
            query_rows=lambda *_args: [
                {"Category": "Logon", "ImagePath": r"C:\\a.exe", "Signer": "A"}
            ],
        )

        self.assertEqual(plan["analysis_mode"], "empty")
        self.assertEqual(plan["artifacts"][0]["artifact_state"], "failed")
        self.assertIn("GoldenDB", plan["collection_failures"][0]["error"])

    def test_autoruns_strategy_matches_identity_across_categories(self):
        row = {
            "Category": "Logon",
            "ImagePath": r"C:\\Windows\\example.exe",
            "LaunchString": r"C:\\Windows\\example.exe -run",
        }
        identity = autoruns_golden.normalized_record(row)["hash_key"]

        residual, metadata = collection_analysis.reduce_autoruns_with_golden_db(
            [row],
            database=Path("/unused.sqlite"),
            keys={identity},
            base_metadata={"strategy": "autoruns-goldendb"},
        )

        self.assertEqual(residual, [])
        self.assertEqual(metadata["known_good_filtered_rows"], 1)

    def test_autoruns_strategy_preserves_alias_context_and_golden_status(self):
        artifact = "Windows.Sysinternals.Autoruns"
        payload = finished_payload(rows=1)
        payload["requested_artifacts"] = [artifact]
        payload["artifact_flows"][0]["artifact"] = artifact
        payload["artifact_flows"][0]["artifact_name"] = artifact
        payload["artifact_flows"][0]["available_result_components"] = [artifact]
        raw_row = {
            "Entry Location": r"HKLM\\Software\\Vendor\\Run",
            "Entry": "VendorAgent",
            "Category": "Logon",
            "Signer": "(Verified) Vendor Inc.",
            "Image Path": r"C:\\Program Files\\Vendor\\agent.exe",
            "Launch String": r'"C:\\Program Files\\Vendor\\agent.exe" --startup',
            "Profile": "System-wide",
            "Description": "Vendor Agent",
            "Version": "1.2.3",
            "SHA-256": "a" * 64,
            "Fqdn": "host01.example.test",
            "ClientId": "C.1",
        }
        profile = {
            artifact: {
                "enabled": True,
                "review": {
                    "sample_fields": [
                        "EntryLocation",
                        "Entry",
                        "Category",
                        "Signer",
                        "ImagePath",
                        "LaunchString",
                        "Profile",
                        "Description",
                        "Version",
                        "SHA256",
                        "HashKey",
                        "GoldenDBStatus",
                        "Fqdn",
                        "ClientId",
                    ],
                    "live_vql_select": [
                        "`Entry Location` AS EntryLocation",
                        "Entry",
                        "Category",
                        "Signer",
                        "`Image Path` AS ImagePath",
                        "`Launch String` AS LaunchString",
                        "Profile",
                        "Description",
                        "Version",
                        "`SHA-256` AS SHA256",
                        "Fqdn",
                        "ClientId",
                    ],
                    "filter_fields": {
                        "EntryLocation": "`Entry Location`",
                        "ImagePath": "`Image Path`",
                        "LaunchString": "`Launch String`",
                        "SHA256": "`SHA-256`",
                    },
                },
            }
        }

        with mock.patch.object(
            collection_analysis,
            "_autoruns_golden_keys",
            return_value=(
                set(),
                {
                    "strategy": "autoruns-goldendb",
                    "database": "/unused.sqlite",
                    "database_mode": "read_only",
                },
                collection_analysis.autoruns_regex.RegexIndex(),
            ),
        ):
            plan, chunks = collection_analysis.build_analysis_workload(
                object(),
                payload,
                limits=TEST_LIMITS,
                collection_type="persistence",
                artifact_strategies={artifact: "autoruns-goldendb"},
                autoruns_golden_db=Path("/unused.sqlite"),
                profiles=profile,
                query_rows=lambda *_args: [raw_row],
            )

        rows = list(csv.DictReader(io.StringIO(chunks[0])))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["EntryLocation"], raw_row["Entry Location"])
        self.assertEqual(rows[0]["ImagePath"], raw_row["Image Path"])
        self.assertEqual(rows[0]["LaunchString"], raw_row["Launch String"])
        self.assertEqual(rows[0]["SHA256"], raw_row["SHA-256"])
        self.assertEqual(rows[0]["GoldenDBStatus"], "not_known_good")
        self.assertEqual(
            rows[0]["HashKey"],
            autoruns_golden.normalized_record(raw_row)["hash_key"],
        )
        self.assertEqual(
            plan["artifacts"][0]["preferred_fields"],
            profile[artifact]["review"]["sample_fields"],
        )

    def test_autoruns_reduction_preserves_pre_filter_source_row_number(self):
        artifact = "Windows.Sysinternals.Autoruns"
        payload = finished_payload(rows=2)
        payload["requested_artifacts"] = [artifact]
        payload["artifact_flows"][0]["artifact"] = artifact
        payload["artifact_flows"][0]["artifact_name"] = artifact
        payload["artifact_flows"][0]["available_result_components"] = [artifact]
        known = {
            "Category": "Logon",
            "ImagePath": r"C:\Known\known.exe",
            "LaunchString": r"C:\Known\known.exe",
        }
        residual = {
            "Category": "Logon",
            "ImagePath": r"C:\Review\review.exe",
            "LaunchString": r"C:\Review\review.exe",
        }
        known_key = autoruns_golden.normalized_record(known)["hash_key"]
        profile = {
            artifact: {
                "enabled": True,
                "review": {
                    "sample_fields": ["Category", "ImagePath", "LaunchString"],
                },
            }
        }

        with mock.patch.object(
            collection_analysis,
            "_autoruns_golden_keys",
            return_value=(
                {known_key},
                {"strategy": "autoruns-goldendb"},
                collection_analysis.autoruns_regex.RegexIndex(),
            ),
        ):
            _plan, chunks = collection_analysis.build_analysis_workload(
                object(),
                payload,
                limits=TEST_LIMITS,
                collection_type="persistence",
                artifact_strategies={artifact: "autoruns-goldendb"},
                autoruns_golden_db=Path("/unused.sqlite"),
                profiles=profile,
                query_rows=lambda *_args: [known, residual],
            )

        rows = list(csv.DictReader(io.StringIO(chunks[0])))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["_SourceRef"], "S0001-R2")
        self.assertEqual(rows[0]["_RowNumber"], "2")

    def test_workload_returns_projected_csv_without_persisting_evidence(self):
        plan, chunks = collection_analysis.build_analysis_workload(
            object(),
            finished_payload(),
            limits=replace(TEST_LIMITS, maximum_evidence_tokens_per_item=9_900),
            collection_type="triage",
            profiles=self.profiles(),
            query_rows=self.rows,
        )

        self.assertIn("_RowNumber", chunks[0])
        self.assertIn("Command", chunks[0])
        self.assertNotIn("Noise", chunks[0])
        self.assertFalse(plan["evidence_persisted"])

    def test_empty_and_failed_flows_are_not_queried(self):
        empty = finished_payload(rows=0)
        failed = finished_payload(rows=0, state="ERROR")
        query = unittest.mock.Mock(side_effect=AssertionError("must not query"))

        empty_plan = collection_analysis.build_analysis_plan(
            object(), empty, limits=TEST_LIMITS, collection_type="triage", profiles=self.profiles(), query_rows=query
        )
        failed_plan = collection_analysis.build_analysis_plan(
            object(), failed, limits=TEST_LIMITS, collection_type="triage", profiles=self.profiles(), query_rows=query
        )

        self.assertEqual(empty_plan["analysis_mode"], "empty")
        self.assertEqual(empty_plan["artifacts"][0]["artifact_state"], "empty")
        self.assertEqual(failed_plan["artifacts"][0]["artifact_state"], "failed")
        self.assertEqual(len(failed_plan["collection_failures"]), 1)
        query.assert_not_called()

    def test_line_worker_protocol_preserves_only_relevant_components(self):
        result = self.validate_worker(self.worker_result())

        self.assertEqual(result["protocol"], "reference-line-v3")
        self.assertEqual(result["findings"][0]["domains"], ["Execution"])
        self.assertEqual(result["findings"][0]["rows"][0]["ref"], "S0001-R1")
        self.assertEqual(
            result["findings"][0]["rows"][0]["fields"],
            {"Command": "whoami", "User": "SYSTEM"},
        )
        self.assertNotIn("evidence", result)
        self.assertNotIn("review_accounting", result)

    def test_finding_without_evidence_is_rejected(self):
        current = self.worker_result(row_count=1).replace(
            "EVIDENCE\tF1\tS0001-R1\n", ""
        )
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "requires at least one EVIDENCE",
        ):
            self.validate_worker(current, row_count=1)

    def test_legacy_json_worker_output_is_rejected(self):
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "model-generated JSON",
        ):
            self.validate_worker('{"schema_version":3,"status":"complete"}')

    def test_worker_missing_end_marker_is_rejected(self):
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "missing the END marker",
        ):
            self.validate_worker(self.worker_result().removesuffix("\nEND"))

    def test_worker_rejects_model_echoed_coordinator_headers(self):
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "line 1 must be RESULT",
        ):
            self.validate_worker("CHUNK\t1/1\n" + self.worker_result())

    def test_worker_evidence_reference_outside_chunk_is_rejected(self):
        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(
                self.worker_result().replace(
                    "EVIDENCE\tF1\tS0001-R1",
                    "EVIDENCE\tF1\tS0001-R3",
                )
            )
        self.assertEqual(
            captured.exception.diagnostics[0]["code"],
            "invalid_source_reference",
        )

    def test_worker_hydrates_arbitrary_source_values_without_parsing_them(self):
        value = (
            '$l = $p.Read($b, 0, 8); if ($l -gt 0) { Invoke-Expression $t }\n'
            '{"nested":"a=b;c"}\tUnicode=✓'
        )
        result = collection_analysis.validate_context_worker_result(
            self.worker_result(row_count=1),
            artifact="Artifact.Test",
            chunk_index=0,
            chunk_count=1,
            row_start=0,
            row_end=1,
            expected_row_count=1,
            source_rows={"S0001-R1": {"Command": value}},
        )

        self.assertEqual(result["findings"][0]["rows"][0]["fields"]["Command"], value)

    def test_worker_requires_one_reference_per_context_record(self):
        output = "\n".join(
            [
                "RESULT\tfindings",
                "FINDING\tF1\tmedium\tExecution\tRepeated SYSTEM execution.",
                "EVIDENCE\tF1\tS0001-R1",
                "CONTEXT\tS0001-R1|S0001-R2\tRepeated context.",
                "END",
            ]
        )
        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output)
        self.assertEqual(
            captured.exception.diagnostics[0]["code"],
            "invalid_source_reference",
        )

    def test_worker_hydrates_context_without_model_selected_fields(self):
        output = self.worker_result(row_count=1).replace(
            "\nEND",
            "\nCONTEXT\tS0001-R1\tExecutable context.\nEND",
        )
        result = collection_analysis.validate_context_worker_result(
            output,
            artifact="Artifact.Test",
            chunk_index=0,
            chunk_count=1,
            row_start=0,
            row_end=1,
            expected_row_count=1,
            source_rows={
                "S0001-R1": {
                    "Command": "whoami",
                    "User": "SYSTEM",
                    "ImagePath": r"C:\\Windows\\System32\\cmd.exe",
                    "Signer": "",
                }
            },
        )

        self.assertEqual(
            result["relevant_context"][0]["fields"],
            {
                "Command": "whoami",
                "User": "SYSTEM",
                "ImagePath": r"C:\\Windows\\System32\\cmd.exe",
            },
        )

    def test_worker_links_typed_identity_context_to_finding(self):
        output = self.worker_result(row_count=1).replace(
            "\nEND",
            "\nCONTEXT\tF1\tS0001-R1\tidentity\tUsername SYSTEM executed the command.\nEND",
        )

        result = self.validate_worker(output, row_count=1)

        context = result["relevant_context"][0]
        self.assertEqual(context["finding_id"], "F1")
        self.assertEqual(context["context_type"], "identity")
        self.assertEqual(context["fields"]["User"], "SYSTEM")

    def test_worker_rejects_unknown_context_type(self):
        output = self.worker_result(row_count=1).replace(
            "\nEND",
            "\nCONTEXT\tF1\tS0001-R1\tunsupported\tContext.\nEND",
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output, row_count=1)

        self.assertEqual(captured.exception.diagnostics[0]["code"], "invalid_context_type")

    def test_worker_rejects_unlinked_non_environment_context(self):
        output = self.worker_result(row_count=1).replace(
            "\nEND",
            "\nCONTEXT\t-\tS0001-R1\tidentity\tUnlinked identity context.\nEND",
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output, row_count=1)

        self.assertEqual(
            captured.exception.diagnostics[0]["code"],
            "unlinked_context_type",
        )

    def test_worker_preserves_tabs_in_trailing_prose_fields(self):
        output = "\n".join(
            [
                "RESULT\tfindings",
                "FINDING\tF1\tmedium\tExecution\tSYSTEM command\texecution observed.",
                "EVIDENCE\tF1\tS0001-R1",
                "CONTEXT\tS0001-R1\tExecutable\tcontext.",
                "LIMITATION\tMissing\thash.",
                "FOLLOW_UP\tReview\texecutable.",
                "END",
            ]
        )

        result = self.validate_worker(output, row_count=1)

        self.assertEqual(
            result["findings"][0]["summary"],
            "SYSTEM command\texecution observed.",
        )
        self.assertEqual(
            result["relevant_context"][0]["summary"],
            "Executable\tcontext.",
        )
        self.assertEqual(result["limitations"], ["Missing\thash."])
        self.assertEqual(result["bounded_follow_up"], ["Review\texecutable."])

    def test_worker_rejects_legacy_records_and_field_names(self):
        output = self.worker_result(row_count=1).replace(
            "EVIDENCE\tF1\tS0001-R1",
            "ROW\tF1\tS0001-R1\tCommand",
        )
        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output, row_count=1)
        self.assertEqual(captured.exception.diagnostics[0]["code"], "unsupported_record")

        output = self.worker_result(row_count=1).replace(
            "EVIDENCE\tF1\tS0001-R1",
            "EVIDENCE\tF1\tS0001-R1\tCommand",
        )
        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output, row_count=1)
        self.assertEqual(captured.exception.diagnostics[0]["code"], "invalid_evidence_record")

    def test_worker_rejects_usage_footer(self):
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "forbidden agent metadata",
        ):
            self.validate_worker(
                self.worker_result(row_count=1).replace(
                    "\nEND",
                    "\nSkills used: none\nEND",
                ),
                row_count=1,
            )

    def test_worker_normalizes_tactics_and_rejects_unknown_tactics(self):
        normalized = self.validate_worker(
            self.worker_result(row_count=1).replace(
                "Execution", "credential_access,LATERAL-MOVEMENT"
            ),
            row_count=1,
        )
        self.assertEqual(
            normalized["findings"][0]["domains"],
            ["Credential Access", "Lateral Movement"],
        )
        output = self.worker_result(row_count=1).replace(
            "FINDING\tF1\tmedium\tExecution",
            "FINDING\tF1\tmedium\tauthentiction",
        )
        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            collection_analysis.validate_context_worker_result(
                output,
                artifact="Artifact.Test",
                chunk_index=0,
                chunk_count=1,
                row_start=0,
                row_end=1,
                expected_row_count=1,
                source_rows={
                    "S0001-R1": {
                        "Command": "whoami",
                        "User": "",
                    }
                },
            )

        self.assertEqual(captured.exception.diagnostics[0]["code"], "unsupported_tactic")
        self.assertNotIn("whoami", str(captured.exception))

    def test_no_reportable_findings_completes_chunk(self):
        result = self.validate_worker(self.worker_result(finding=False))

        self.assertEqual(result["result"], "no_reportable_findings")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["row_count"], 2)

    def test_worker_accepts_sparse_uplift_with_trailing_tabs_when_enabled(self):
        output = "\n".join(
            [
                "RESULT\tno_reportable_findings",
                "UPLIFT\tS0001-R1\tsite\tExpected vendor\tmaintenance script.",
                "END",
            ]
        )

        result = collection_analysis.validate_context_worker_result(
            output,
            artifact="Artifact.Test",
            chunk_index=0,
            chunk_count=1,
            row_start=0,
            row_end=1,
            expected_row_count=1,
            source_rows={
                "S0001-R1": {
                    "Detection": "PowerShell long script",
                    "PayloadField": "EventData.ScriptBlockText",
                    "Payload": "Get-WindowsUpdate\nWrite-Output 'complete'",
                }
            },
            allow_uplift_candidates=True,
        )

        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["uplift_candidates"][0]["summary"],
            "Expected vendor\tmaintenance script.",
        )
        self.assertEqual(
            result["uplift_candidates"][0]["fields"]["Payload"],
            "Get-WindowsUpdate\nWrite-Output 'complete'",
        )

    def test_worker_rejects_uplift_unless_enabled(self):
        output = "\n".join(
            [
                "RESULT\tno_reportable_findings",
                "UPLIFT\tS0001-R1\tglobal\tExpected Windows script.",
                "END",
            ]
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            self.validate_worker(output, row_count=1)

        self.assertEqual(captured.exception.diagnostics[0]["code"], "unsupported_record")

    def test_worker_rejects_finding_and_uplift_for_same_reference(self):
        output = "\n".join(
            [
                "RESULT\tfindings",
                "FINDING\tF1\tmedium\tExecution\tPotential malicious execution.",
                "EVIDENCE\tF1\tS0001-R1",
                "UPLIFT\tS0001-R1\tglobal\tExpected Windows script.",
                "END",
            ]
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            collection_analysis.validate_context_worker_result(
                output,
                artifact="Artifact.Test",
                chunk_index=0,
                chunk_count=1,
                row_start=0,
                row_end=1,
                expected_row_count=1,
                source_rows={"S0001-R1": {"Payload": "payload"}},
                allow_uplift_candidates=True,
            )

        self.assertEqual(
            captured.exception.diagnostics[0]["code"],
            "conflicting_source_classification",
        )

    def test_empty_worker_output_is_rejected(self):
        with self.assertRaisesRegex(
            collection_analysis.WorkerResultError,
            "worker result is empty",
        ):
            self.validate_worker("")

    def test_chunk_results_merge_without_evidence_catalogue(self):
        first = self.validate_worker(
            self.worker_result(row_count=1, chunk_count=2),
            row_count=1,
            chunk_count=2,
        )
        second = self.validate_worker(
            self.worker_result(
                row_start=1,
                row_count=1,
                chunk_index=1,
                chunk_count=2,
                finding=False,
            ),
            row_start=1,
            row_count=1,
            chunk_index=1,
            chunk_count=2,
        )

        merged = collection_analysis.merge_context_worker_results([second, first])

        self.assertEqual(merged["reviewed_rows"], 2)
        self.assertEqual(len(merged["findings"]), 1)
        self.assertNotIn("evidence", merged)
        self.assertNotIn("review_accounting", merged)
        self.assertEqual(merged["chunk_count"], 2)

    def test_synthesis_story_preserves_accepted_worker_evidence_components(self):
        worker = self.validate_worker(self.worker_result())
        expected = [
            {
                "artifact": "Artifact.Test",
                "chunk_index": 0,
                "chunk_count": 1,
                "row_start": 0,
                "row_end": 2,
                "row_count": 2,
            }
        ]
        story = "\n".join(
            [
                "ANSWER",
                "Suspicious SYSTEM execution requires validation.",
                "",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution\tSYSTEM command execution requires validation.",
                "EVIDENCE\tM1\tS0001-R1",
                "",
                "RELEVANT_CONTEXT",
                "None.",
                "",
                "LIMITATIONS",
                "Binary hash was unavailable.",
                "",
                "FOLLOW_UP",
                "Review the exact executable.",
                "END",
            ]
        )

        result = collection_analysis.validate_analysis_story(
            story,
            task="execution",
            question="Is anything malicious or suspicious?",
            expected_chunks=expected,
            accepted_chunks={"chunk-1": worker},
        )

        self.assertEqual(result["format"], "analysis-story-v2")
        self.assertEqual(
            result["question"],
            "Is anything malicious or suspicious?",
        )
        self.assertEqual(
            result["findings"][0]["evidence"][0]["fields"],
            {"Command": "whoami", "User": "SYSTEM"},
        )
        self.assertEqual(
            result["findings"][0]["evidence"][0]["_full_fields"],
            {"Command": "whoami", "User": "SYSTEM"},
        )
        self.assertEqual(result["coverage"]["reviewed_rows"], 2)

        abbreviated = story
        normalized = collection_analysis.validate_analysis_story(
            abbreviated,
            task="execution",
            question="Is anything malicious or suspicious?",
            expected_chunks=expected,
            accepted_chunks={"chunk-1": worker},
        )
        self.assertEqual(
            normalized["question"],
            "Is anything malicious or suspicious?",
        )

    def test_synthesis_rejects_unsupported_findings_record_with_retry_diagnostic(self):
        worker = self.validate_worker(self.worker_result())
        story = "\n".join(
            [
                "ANSWER",
                "One finding.",
                "FINDINGS",
                "- Suspicious execution.",
                "RELEVANT_CONTEXT",
                "None.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            collection_analysis.validate_analysis_story(
                story,
                task="execution",
                question="What happened?",
                expected_chunks=[{"row_count": 2}],
                accepted_chunks={"chunk-1": worker},
            )

        self.assertEqual(
            captured.exception.diagnostics,
            [
                {
                    "allowed": ["FINDING", "EVIDENCE"],
                    "code": "unsupported_record",
                    "line": 1,
                    "record": "FINDINGS",
                }
            ],
        )

    def test_synthesis_rejects_tactic_not_supported_by_cited_evidence(self):
        worker = self.validate_worker(self.worker_result())
        story = "\n".join(
            [
                "ANSWER",
                "One finding.",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution,Credential Access\tSuspicious execution.",
                "EVIDENCE\tM1\tS0001-R1",
                "RELEVANT_CONTEXT",
                "None.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        with self.assertRaises(collection_analysis.WorkerResultError) as captured:
            collection_analysis.validate_analysis_story(
                story,
                task="execution",
                question="What happened?",
                expected_chunks=[{"row_count": 2}],
                accepted_chunks={"chunk-1": worker},
            )

        self.assertEqual(
            captured.exception.diagnostics,
            [
                {
                    "allowed": ["Execution"],
                    "code": "unsupported_evidence_tactic",
                    "finding_id": "M1",
                    "record": "FINDING",
                    "value": "Credential Access",
                }
            ],
        )

    def test_synthesis_context_requires_and_hydrates_worker_provenance(self):
        worker = self.validate_worker(
            self.worker_result().replace(
                "\nEND",
                "\nCONTEXT\tS0001-R1\tExecution context.\nEND",
            )
        )
        expected = [{"row_count": 2}]
        story = "\n".join(
            [
                "ANSWER",
                "One contextual item was retained.",
                "FINDINGS",
                "None.",
                "RELEVANT_CONTEXT",
                "CONTEXT\tS0001-R1\tExecution context.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        result = collection_analysis.validate_analysis_story(
            story,
            task="execution",
            question="What context matters?",
            expected_chunks=expected,
            accepted_chunks={"chunk-1": worker},
        )

        context = result["relevant_context"][0]
        self.assertEqual(context["artifact"], "Artifact.Test")
        self.assertEqual(context["chunk_index"], 0)
        self.assertEqual(context["chunk_count"], 1)
        self.assertEqual(context["ref"], "S0001-R1")
        self.assertEqual(context["summary"], "Execution context.")
        self.assertEqual(
            context["fields"],
            {"Command": "whoami", "User": "SYSTEM"},
        )
        self.assertEqual(context["source"]["source_alias"], "S0001")
        self.assertEqual(context["source"]["source_row_number"], 1)
        with self.assertRaisesRegex(ValueError, "requires CONTEXT"):
            collection_analysis.validate_analysis_story(
                story.replace(
                    "CONTEXT\tS0001-R1\tExecution context.",
                    "Ungrounded model-authored context.",
                ),
                task="execution",
                question="What context matters?",
                expected_chunks=expected,
                accepted_chunks={"chunk-1": worker},
            )

    def test_synthesis_retains_finding_link_and_context_type(self):
        worker = self.validate_worker(
            self.worker_result().replace(
                "\nEND",
                "\nCONTEXT\tF1\tS0001-R1\tidentity\tSYSTEM account context.\nEND",
            )
        )
        story = "\n".join(
            [
                "ANSWER",
                "One finding with account context.",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution\tSuspicious execution.",
                "EVIDENCE\tM1\tS0001-R1",
                "RELEVANT_CONTEXT",
                "CONTEXT\tM1\tS0001-R1\tidentity\tSYSTEM account context.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        result = collection_analysis.validate_analysis_story(
            story,
            task="execution",
            question="What happened?",
            expected_chunks=[{"row_count": 2}],
            accepted_chunks={"chunk-1": worker},
        )

        context = result["relevant_context"][0]
        self.assertEqual(context["finding_id"], "M1")
        self.assertEqual(context["context_type"], "identity")
        self.assertEqual(context["fields"]["User"], "SYSTEM")

    def test_synthesis_hydrates_context_without_field_selection(self):
        worker = self.validate_worker(
            self.worker_result().replace(
                "\nEND",
                "\nCONTEXT\tS0001-R1\tCommand context."
                "\nCONTEXT\tS0001-R1\tAccount context.\nEND",
            )
        )
        story = "\n".join(
            [
                "ANSWER",
                "One grounded contextual item was retained.",
                "FINDINGS",
                "None.",
                "RELEVANT_CONTEXT",
                "CONTEXT\tS0001-R1\tCombined execution context.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        result = collection_analysis.validate_analysis_story(
            story,
            task="execution",
            question="What context matters?",
            expected_chunks=[{"row_count": 2}],
            accepted_chunks={"chunk-1": worker},
        )

        self.assertEqual(
            result["relevant_context"][0]["fields"],
            {"Command": "whoami", "User": "SYSTEM"},
        )

    def test_synthesis_preserves_tabs_in_finding_and_context_text(self):
        worker = self.validate_worker(
            self.worker_result().replace(
                "\nEND",
                "\nCONTEXT\tS0001-R1\tCommand\tcontext.\nEND",
            )
        )
        story = "\n".join(
            [
                "ANSWER",
                "One finding.",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution\tSuspicious\texecution.",
                "EVIDENCE\tM1\tS0001-R1",
                "RELEVANT_CONTEXT",
                "CONTEXT\tS0001-R1\tCombined\texecution context.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )

        result = collection_analysis.validate_analysis_story(
            story,
            task="execution",
            question="What context matters?",
            expected_chunks=[{"row_count": 2}],
            accepted_chunks={"chunk-1": worker},
        )

        self.assertEqual(result["findings"][0]["summary"], "Suspicious\texecution.")
        self.assertEqual(
            result["relevant_context"][0]["summary"],
            "Combined\texecution context.",
        )

    def test_synthesis_story_rejects_invented_evidence_and_json(self):
        worker = self.validate_worker(self.worker_result())
        expected = [
            {
                "artifact": "Artifact.Test",
                "chunk_index": 0,
                "chunk_count": 1,
                "row_start": 0,
                "row_end": 2,
                "row_count": 2,
            }
        ]
        base = "\n".join(
            [
                "ANSWER",
                "One finding.",
                "FINDINGS",
                "FINDING\tM1\thigh\tExecution\tSuspicious execution.",
                "EVIDENCE\tM1\tS0001-R99",
                "RELEVANT_CONTEXT",
                "None.",
                "LIMITATIONS",
                "None.",
                "FOLLOW_UP",
                "None.",
                "END",
            ]
        )
        with self.assertRaisesRegex(
            ValueError,
            'code="unavailable_source"',
        ):
            collection_analysis.validate_analysis_story(
                base,
                task="execution",
                question="Is anything malicious or suspicious?",
                expected_chunks=expected,
                accepted_chunks={"chunk-1": worker},
            )
        with self.assertRaisesRegex(ValueError, "JSON synthesis story"):
            collection_analysis.validate_analysis_story(
                '{"status":"complete"}',
                task="execution",
                question="Is anything malicious or suspicious?",
                expected_chunks=expected,
                accepted_chunks={"chunk-1": worker},
            )

if __name__ == "__main__":
    unittest.main()
