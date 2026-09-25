import csv
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import ResolvedAgentRoute
from vraptor.analyze import stack_review as generic_stack_review
from vraptor.hunt import live


ARTIFACT = "DetectRaptor.Windows.Detection.Evtx"
GENERIC_STACK_ARTIFACT = "DetectRaptor.Windows.Detection.Applications"
PSLIST_ARTIFACT = "Custom.Windows.Pslist"
NETSTAT_ARTIFACT = "Custom.Windows.Netstat"


def _test_execution(*, max_concurrency: int = 1) -> ResolvedAgentExecution:
    return ResolvedAgentExecution(
        route=ResolvedAgentRoute(
            provider="openai",
            model="test-model",
            protocol="responses",
            timeout_seconds=60,
            max_retries=1,
            max_concurrency=max_concurrency,
        )
    )


def recommendation_response(payload):
    lines = []
    scope = payload.get("scope")
    if scope:
        lines.append(f"SCOPE\t{scope['field']}\t{scope['rationale']}")
    else:
        lines.append("SCOPE\tNONE\tNo safe scope field.")
    lines.extend(
        f"SIGNATURE\t{item['field']}\t{item['rationale']}"
        for item in payload.get("signatures") or []
    )
    lines.extend(
        f"REJECT\t{item['field']}\t{item['reason']}"
        for item in payload.get("rejected") or []
    )
    return "\n".join([*lines, "END"])


def flag_response(items=()):
    return "\n".join(
        [
            *(f"FLAG\t{item['row_id']}\t{item['disposition']}\t{item['severity']}\t{item['reason']}" for item in items),
            "END",
        ]
    )


def followup_response(items):
    return "\n".join(
        [
            *(f"ASSESSMENT\t{item['group_id']}\t{item['disposition']}\t{item['severity']}\t{item['summary']}\t{item['reason']}" for item in items),
            "END",
        ]
    )


def request():
    return SimpleNamespace(
        expected_specs=[SimpleNamespace(artifact=ARTIFACT)],
    )


def artifact_request(artifact):
    return SimpleNamespace(
        expected_specs=[SimpleNamespace(artifact=artifact)],
    )


class StreamingStackApi:
    def __init__(self, group_count=2600):
        self.group_count = group_count
        self.calls = []
        self.stream_calls = []

    def query(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        if "count() AS RowCount" in vql:
            return [{"RowCount": self.group_count}]
        return []

    def query_batches(self, vql, env=None, **kwargs):
        self.stream_calls.append((vql, dict(env or {}), kwargs))
        if "FROM ImpactRows" in vql:
            yield [
                {
                    "ClientId": "C.test",
                    "Fqdn": "test.example",
                    "RowCount": 1,
                }
            ]
            return
        if "FROM ReviewRows" in vql:
            limit_match = __import__("re").search(r"\bLIMIT\s+(\d+)", vql)
            limit = int(limit_match.group(1)) if limit_match else 1
            yield [
                {
                    "ClientId": "C.test",
                    "Fqdn": "test.example",
                    "Evidence": f"row-{index}",
                }
                for index in range(limit)
            ]
            return
        if "DisplayName AS Pivot1" in vql:
            yield [
                {
                    "Pivot1": "Example application",
                    "HostCount": 1,
                    "Count": self.group_count,
                }
            ]
            return
        if "Category AS Pivot1" in vql:
            for offset in range(0, self.group_count, 100):
                yield [
                    {
                        "Pivot1": f"family-{index:05d}",
                        "HostCount": 1,
                        "Count": 1,
                    }
                    for index in range(
                        offset,
                        min(offset + 100, self.group_count),
                    )
                ]
            return
        yield []


class DynamicStackApi:
    def __init__(self, sample_rows, aggregate_rows):
        self.sample_rows = list(sample_rows)
        self.aggregate_rows = list(aggregate_rows)
        self.total = sum(int(row["Count"]) for row in self.aggregate_rows)
        self.calls = []
        self.stream_calls = []

    def query(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        if "count() AS RowCount" in vql:
            return [{"RowCount": self.total}]
        limit_match = __import__("re").search(r"\bLIMIT\s+(\d+)", vql)
        limit = int(limit_match.group(1)) if limit_match else len(self.sample_rows)
        return self.sample_rows[:limit]

    def query_batches(self, vql, env=None, **kwargs):
        self.stream_calls.append((vql, dict(env or {}), kwargs))
        if "FROM ImpactRows" in vql:
            yield [
                {
                    "ClientId": "C.test",
                    "Fqdn": "test.example",
                    "RowCount": 1,
                }
            ]
            return
        if "FROM StackHostGroups" in vql:
            yield [
                {**row, "HostCount": int(row.get("HostCount") or 1)}
                for row in self.aggregate_rows
            ]
            return
        if "FROM ReviewRows" in vql:
            limit_match = __import__("re").search(r"\bLIMIT\s+(\d+)", vql)
            limit = int(limit_match.group(1)) if limit_match else len(self.sample_rows)
            yield self.sample_rows[:limit]
            return
        limit_match = __import__("re").search(r"\bLIMIT\s+(\d+)", vql)
        limit = int(limit_match.group(1)) if limit_match else len(self.sample_rows)
        yield self.sample_rows[:limit]


def pslist_rows():
    return [
        {
            "ClientId": f"C.{index % 4}",
            "Name": "svchost.exe" if index < 18 else "rare.exe",
            "Pid": 1000 + index,
            "Timestamp": f"2026-08-14T00:00:{index:02d}Z",
            "DiscoveryOnly": f"DISCOVERY_SECRET_{index}",
        }
        for index in range(20)
    ]


def pslist_identity_rows():
    return [
        {
            "ClientId": f"C.{index % 4}",
            "Name": f"process-{index}.exe",
            "Exe": f"C:\\Program Files\\Example\\process-{index}.exe",
            "CommandLine": (
                f'"C:\\Program Files\\Example\\process-{index}.exe" '
                f"--worker {index}"
            ),
            "Pid": 1000 + index,
        }
        for index in range(20)
    ]


def netstat_rows():
    return [
        {
            "ClientId": f"C.{index % 4}",
            "Protocol": "tcp" if index % 2 else "udp",
            "Name": "chrome.exe" if index % 3 else "svchost.exe",
            "Status": "ESTABLISHED" if index % 4 else "LISTEN",
            "Laddr": {"IP": "127.0.0.1", "Port": index},
        }
        for index in range(20)
    ]


def recommendation_executor(recommendation, *, flag_first=True):
    def execute(**kwargs):
        if "Recommend ephemeral stack fields" in kwargs["prompt"]:
            return recommendation_response(recommendation), {}
        supplied = list(
            csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1]))
        )
        if "second pass" in kwargs["prompt"]:
            return followup_response(
                [
                    {
                        "group_id": row["GroupId"],
                        "disposition": "notable",
                        "severity": "low",
                        "summary": "Follow-up source rows require analyst validation.",
                        "reason": "Original rows and impacted host were reviewed.",
                    }
                    for row in supplied
                ]
            ), {}
        flagged = []
        if flag_first and supplied:
            flagged.append(
                {
                    "row_id": int(supplied[0]["RowId"]),
                    "disposition": "notable",
                    "severity": "low",
                    "reason": "Rare aggregate requires original-row review.",
                }
            )
        return flag_response(flagged), {}

    return execute


class GenericStackReviewTest(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(
            os.environ,
            {
                "AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE": "application",
                "AI_SKILLS_ANALYST_AGENT_PROVIDER": "openai",
                "AI_SKILLS_ANALYST_AGENT_MODEL": "test-model",
                "OPENAI_API_KEY": "synthetic-test-key",
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

    def test_field_recommendation_line_protocol_parses_nullable_scope(self):
        payload = generic_stack_review._parse_field_recommendation(
            "SCOPE\tNONE\tNo safe\tscope field.\n"
            "SIGNATURE\tName\tStable\texecutable identity.\n"
            "REJECT\tTimestamp\tTime field\tis unsuitable.\nEND"
        )

        self.assertIsNone(payload["scope"])
        self.assertEqual(payload["signatures"][0]["field"], "Name")
        self.assertEqual(
            payload["signatures"][0]["rationale"],
            "Stable\texecutable identity.",
        )
        self.assertEqual(payload["rejected"][0]["field"], "Timestamp")

    def test_review_protocols_preserve_tabs_in_final_reason(self):
        flagged = generic_stack_review._validate(
            "FLAG\t1\tnotable\tlow\tRare\tgroup.\nEND",
            rows=[{"RowId": "1"}],
        )
        followed_up = generic_stack_review._validate_followup(
            "ASSESSMENT\tgroup-1\tnotable\tlow\tSummary.\tNeeds\treview.\nEND",
            rows=[{"GroupId": "group-1"}],
        )

        self.assertEqual(flagged[0]["reason"], "Rare\tgroup.")
        self.assertEqual(followed_up[0]["reason"], "Needs\treview.")

    def test_field_statistics_and_deterministic_rejections(self):
        rows = [
            {
                "Name": "a.exe" if index % 2 else "b.exe",
                "Timestamp": f"2026-08-14T00:00:{index:02d}Z",
                "Nested": {"value": index},
                "ArrayValue": [index],
                "Payload": "x" * (600 + index),
                "Constant": "same",
                "OpaqueToken": f"opaque-{index}",
            }
            for index in range(20)
        ]
        statistics = generic_stack_review.calculate_field_statistics(rows)
        by_field = {item["field"]: item for item in statistics}

        self.assertEqual(by_field["Name"]["presence_ratio"], 1.0)
        self.assertEqual(by_field["Name"]["distinct_count"], 2)
        self.assertEqual(by_field["Nested"]["nested_object_count"], 20)
        self.assertEqual(by_field["Payload"]["maximum_rendered_length"], 619)
        cases = {
            "Timestamp": "timestamp_field",
            "Nested": "nested_object",
            "ArrayValue": "array",
            "Payload": "raw_payload",
            "Constant": "constant",
            "OpaqueToken": "mostly_unique_identifier",
        }
        for field, expected_code in cases.items():
            validated = generic_stack_review.validate_field_recommendation(
                {
                    "scope": None,
                    "signatures": [
                        {"field": field, "rationale": "Test rejection."}
                    ],
                    "rejected": [],
                },
                statistics=statistics,
            )
            self.assertIn(
                expected_code,
                validated["rejected_recommendations"][0]["reason_codes"],
            )

    def test_invalid_ai_response_retries_once_and_returns_fallback(self):
        calls = 0

        def execute(**_kwargs):
            nonlocal calls
            calls += 1
            return "BROKEN\nEND", {}

        result = generic_stack_review.recommend_runtime_stack_fields(
            pslist_rows(),
            artifact=PSLIST_ARTIFACT,
            question="Review processes",
            workdir=Path("."),
            executor=execute,
            execution=_test_execution(),
        )

        self.assertEqual(calls, 2)
        self.assertEqual(result["signature_fields"], [])
        self.assertEqual(
            result["fallback_reason"],
            "invalid_ai_response_after_retry",
        )

    def test_unknown_unsafe_and_excess_dimension_recommendations_fail_closed(self):
        statistics = generic_stack_review.calculate_field_statistics(pslist_rows())
        validated = generic_stack_review.validate_field_recommendation(
            {
                "scope": None,
                "signatures": [
                    {
                        "field": "Name; FROM hunt_results()",
                        "rationale": "Untrusted expression-shaped name.",
                    }
                ],
                "rejected": [],
            },
            statistics=statistics,
        )
        codes = validated["rejected_recommendations"][0]["reason_codes"]
        self.assertIn("unknown_field", codes)
        self.assertIn("unsafe_identifier", codes)
        with self.assertRaisesRegex(
            generic_stack_review.GenericStackReviewError,
            "one to three signatures",
        ):
            generic_stack_review.validate_field_recommendation(
                {
                    "scope": None,
                    "signatures": [
                        {"field": "Name", "rationale": "One."},
                        {"field": "Pid", "rationale": "Two."},
                        {"field": "Timestamp", "rationale": "Three."},
                        {"field": "ClientId", "rationale": "Four."},
                    ],
                    "rejected": [],
                },
                statistics=statistics,
            )
        with self.assertRaisesRegex(
            generic_stack_review.GenericStackReviewError,
            "at most three total dimensions",
        ):
            generic_stack_review.validate_field_recommendation(
                {
                    "scope": {
                        "field": "Name",
                        "rationale": "Scope.",
                    },
                    "signatures": [
                        {"field": "Pid", "rationale": "One."},
                        {"field": "Timestamp", "rationale": "Two."},
                        {"field": "ClientId", "rationale": "Three."},
                    ],
                    "rejected": [],
                },
                statistics=statistics,
            )

    def test_operator_guidance_allows_three_field_pslist_identity(self):
        observed_prompt = []

        def execute(**kwargs):
            observed_prompt.append(kwargs["prompt"])
            return recommendation_response({
                "scope": None,
                "signatures": [
                    {"field": "Name", "rationale": "Process image name."},
                    {"field": "Exe", "rationale": "Executable path."},
                    {"field": "CommandLine", "rationale": "Invocation identity."},
                ],
                "rejected": [],
            }), {}

        result = generic_stack_review.recommend_runtime_stack_fields(
            pslist_identity_rows(),
            artifact="Windows.System.Pslist",
            question="Reduce process identities",
            workdir=Path("."),
            preferred_fields=["Name", "Exe", "CommandLine"],
            field_guidance=(
                "Use a cohesive process identity and retain command-line "
                "variants."
            ),
            executor=execute,
            execution=_test_execution(),
        )

        self.assertEqual(
            result["signature_fields"],
            ["Name", "Exe", "CommandLine"],
        )
        self.assertEqual(result["fallback_reason"], "")
        self.assertIn('"Name", "Exe", "CommandLine"', observed_prompt[0])
        self.assertIn("cohesive process identity", observed_prompt[0])

    def test_unprofiled_pslist_uses_global_one_field_rare_first_stack(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 2},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )
        recommendation = {
            "scope": None,
            "signatures": [
                {"field": "Name", "rationale": "Process image prevalence."}
            ],
            "rejected": [
                {"field": "Pid", "reason": "Per-process identifier."}
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=recommendation_executor(recommendation),
        ):
            hunt_root = Path(temp_dir) / "H.dynamic-pslist"
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.dynamic-pslist", "state": "FINISHED"},
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=hunt_root,
                direct_row_limit=1,
                autoruns_ai_review_enabled=True,
            )
            persisted = "\n".join(
                path.read_text(encoding="utf-8")
                for path in hunt_root.rglob("*")
                if path.is_file()
            )

        discovery = result["stack_discovery"][PSLIST_ARTIFACT]
        stack = result["streaming_stacks"][PSLIST_ARTIFACT]
        self.assertEqual(discovery["sample_row_count"], 20)
        self.assertEqual(discovery["validated_scope_field"], "")
        self.assertEqual(discovery["validated_signature_fields"], ["Name"])
        self.assertEqual(discovery["represented_rows"], 20)
        self.assertEqual(discovery["represented_groups"], 2)
        self.assertEqual(stack["scope_stack_id"], "global")
        self.assertTrue(stack["runtime_profile_ephemeral"])
        aggregate = next(
            vql for vql, _env, _kwargs in api.stream_calls
            if "`Name` AS Pivot1" in vql
        )
        self.assertIn("ORDER BY Count", aggregate)
        self.assertNotIn("ORDER BY Count ASC", aggregate)
        self.assertNotIn("LIMIT", aggregate)
        self.assertNotIn("DISCOVERY_SECRET", persisted)

    def test_unprofiled_netstat_uses_scope_and_two_field_signature(self):
        api = DynamicStackApi(
            netstat_rows(),
            [
                {
                    "Pivot1": "tcp",
                    "Pivot2": "svchost.exe",
                    "Pivot3": "LISTEN",
                    "Count": 4,
                },
                {
                    "Pivot1": "tcp",
                    "Pivot2": "chrome.exe",
                    "Pivot3": "ESTABLISHED",
                    "Count": 16,
                },
            ],
        )
        recommendation = {
            "scope": {"field": "Protocol", "rationale": "Transport scope."},
            "signatures": [
                {"field": "Name", "rationale": "Owning process."},
                {"field": "Status", "rationale": "Connection state."},
            ],
            "rejected": [
                {"field": "Laddr", "reason": "Nested endpoint object."}
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=recommendation_executor(recommendation, flag_first=False),
        ):
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.dynamic-netstat", "state": "FINISHED"},
                request=artifact_request(NETSTAT_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.dynamic-netstat",
                direct_row_limit=1,
                stack_discovery_rows=10,
                autoruns_ai_review_enabled=True,
            )

        discovery = result["stack_discovery"][NETSTAT_ARTIFACT]
        self.assertEqual(discovery["sample_row_count"], 10)
        self.assertEqual(discovery["validated_scope_field"], "Protocol")
        self.assertEqual(
            discovery["validated_signature_fields"],
            ["Name", "Status"],
        )
        aggregate = next(vql for vql, _env, _kwargs in api.stream_calls)
        self.assertIn("`Protocol` AS Pivot1", aggregate)
        self.assertIn("`Name` AS Pivot2", aggregate)
        self.assertIn("`Status` AS Pivot3", aggregate)
        self.assertIn("ORDER BY Count", aggregate)
        self.assertNotIn("ORDER BY Count ASC", aggregate)
        self.assertEqual(
            result["streaming_stacks"][NETSTAT_ARTIFACT]["represented_row_count"],
            20,
        )

    def test_unprofiled_process_artifact_uses_three_operator_guided_fields(self):
        artifact = "Windows.System.Pslist/UnprofiledTest"
        api = DynamicStackApi(
            pslist_identity_rows(),
            [
                {
                    "Pivot1": "process-1.exe",
                    "Pivot2": "C:\\Program Files\\Example\\process-1.exe",
                    "Pivot3": (
                        '"C:\\Program Files\\Example\\process-1.exe" --worker 1'
                    ),
                    "Count": 1,
                },
                {
                    "Pivot1": "process-2.exe",
                    "Pivot2": "C:\\Program Files\\Example\\process-2.exe",
                    "Pivot3": (
                        '"C:\\Program Files\\Example\\process-2.exe" --worker 2'
                    ),
                    "Count": 19,
                },
            ],
        )
        recommendation = {
            "scope": None,
            "signatures": [
                {"field": "Name", "rationale": "Process image name."},
                {"field": "Exe", "rationale": "Executable path."},
                {"field": "CommandLine", "rationale": "Invocation identity."},
            ],
            "rejected": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=recommendation_executor(recommendation, flag_first=False),
        ):
            overlay = Path(temp_dir) / "disable-pslist-profile.json"
            overlay.write_text(
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "Windows.System.Pslist": {"enabled": False}
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.dynamic-pslist-three", "state": "FINISHED"},
                request=artifact_request(artifact),
                hunt_root=Path(temp_dir) / "H.dynamic-pslist-three",
                direct_row_limit=1,
                autoruns_ai_review_enabled=True,
                artifact_references=[overlay],
                stack_field_preferences=["Name", "Exe", "CommandLine"],
                stack_field_guidance="Use one process identity stack.",
            )

        discovery = result["stack_discovery"][artifact]
        self.assertEqual(
            discovery["validated_signature_fields"],
            ["Name", "Exe", "CommandLine"],
        )
        self.assertEqual(
            discovery["requested_field_preferences"],
            ["Name", "Exe", "CommandLine"],
        )
        aggregate = next(vql for vql, _env, _kwargs in api.stream_calls)
        self.assertIn("`Name` AS Pivot1", aggregate)
        self.assertIn("`Exe` AS Pivot2", aggregate)
        self.assertIn("`CommandLine` AS Pivot3", aggregate)

    def test_invalid_recommendation_retries_once_then_sample_first_fallback(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 2},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )
        calls = 0

        def execute(**kwargs):
            nonlocal calls
            calls += 1
            return recommendation_response({
                "scope": None,
                "signatures": [
                    {"field": "UnknownField", "rationale": "Invalid."}
                ],
                "rejected": [],
            }), {}

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=execute,
        ):
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.invalid-dynamic", "state": "FINISHED"},
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.invalid-dynamic",
                direct_row_limit=1,
                sample_rows=10,
                autoruns_ai_review_enabled=True,
            )

        self.assertEqual(calls, 2)
        self.assertEqual(result["status"], "awaiting_review")
        self.assertEqual(
            result["stack_discovery"][PSLIST_ARTIFACT]["fallback_reason"],
            "no_safe_fields_after_retry",
        )
        self.assertNotIn(PSLIST_ARTIFACT, result["streaming_stacks"])

    def test_small_no_safe_stack_falls_back_to_exhaustive_direct_review(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 2},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )

        def execute(**_kwargs):
            return recommendation_response({
                "scope": None,
                "signatures": [
                    {"field": "UnknownField", "rationale": "Invalid."}
                ],
                "rejected": [],
            }), {}

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=execute,
        ):
            hunt_root = Path(temp_dir) / "H.small-no-safe-stack"
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.small-no-safe-stack",
                    "state": "RUNNING",
                    "review_scope": "ad_hoc_review",
                },
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=hunt_root,
                sample_rows=10,
                autoruns_ai_review_enabled=True,
            )
            decision_path = Path(temp_dir) / "decisions.json"
            decision_path.write_text(
                __import__("json").dumps(
                    {
                        "reviews": [
                            {
                                "review_id": result["review_items"][0]["review_id"],
                                "complete": True,
                                "disposition": "expected",
                                "reason": "Reviewed all rows directly.",
                                "findings": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            completed = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={
                    "hunt_id": "H.small-no-safe-stack",
                    "state": "RUNNING",
                    "review_scope": "ad_hoc_review",
                },
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=hunt_root,
                sample_rows=10,
                decisions_path=decision_path,
                autoruns_ai_review_enabled=True,
            )

        item = result["review_items"][0]
        self.assertEqual(result["status"], "awaiting_review")
        self.assertEqual(item["kind"], "direct")
        self.assertTrue(item["exhaustive"])
        self.assertEqual(item["scope_row_count"], 20)
        self.assertEqual(item["returned_row_count"], 20)
        self.assertEqual(
            result["stack_discovery"][PSLIST_ARTIFACT]["fallback_reason"],
            "no_safe_fields_after_retry",
        )
        self.assertEqual(
            completed["status"],
            "review_complete_source_non_terminal",
        )
        self.assertEqual(completed["result_review_coverage"], "complete")
        self.assertEqual(completed["coverage"], "provisional")
        self.assertEqual(completed["review_item_count"], 0)

    def test_guided_invalid_recommendation_stops_for_operator_input(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 2},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )

        def execute(**_kwargs):
            return recommendation_response({
                "scope": None,
                "signatures": [
                    {"field": "UnknownField", "rationale": "Invalid."}
                ],
                "rejected": [],
            }), {}

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=execute,
        ):
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.guided-invalid", "state": "FINISHED"},
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.guided-invalid",
                direct_row_limit=1,
                autoruns_ai_review_enabled=True,
                stack_field_preferences=["Name"],
                stack_field_guidance="Use process identity.",
            )

        discovery = result["stack_discovery"][PSLIST_ARTIFACT]
        self.assertEqual(discovery["fallback_reason"], "no_safe_fields_after_retry")
        self.assertIn("preferred stack fields", discovery["operator_question"])
        self.assertEqual(result["review_item_count"], 0)

    def test_ai_disabled_retains_sample_first_with_explicit_reason(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 2},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.disabled-dynamic", "state": "FINISHED"},
                request=artifact_request(PSLIST_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.disabled-dynamic",
                direct_row_limit=1,
                sample_rows=10,
                autoruns_ai_review_enabled=False,
            )

        self.assertEqual(result["status"], "awaiting_review")
        self.assertEqual(
            result["stack_discovery"][PSLIST_ARTIFACT]["fallback_reason"],
            "ai_disabled",
        )
        self.assertEqual(result["review_items"][0]["kind"], "sample")

    def test_dynamic_stack_accounting_mismatch_fails_closed(self):
        api = DynamicStackApi(
            pslist_rows(),
            [
                {"Pivot1": "rare.exe", "Count": 1},
                {"Pivot1": "svchost.exe", "Count": 18},
            ],
        )
        api.total = 20
        recommendation = {
            "scope": None,
            "signatures": [
                {"field": "Name", "rationale": "Process prevalence."}
            ],
            "rejected": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=recommendation_executor(recommendation, flag_first=False),
        ):
            with self.assertRaisesRegex(RuntimeError, "accounting mismatch"):
                live.analyze_live_hunt(
                    api,
                    investigation_id="IR1",
                    hunt_row={"hunt_id": "H.bad-accounting", "state": "FINISHED"},
                    request=artifact_request(PSLIST_ARTIFACT),
                    hunt_root=Path(temp_dir) / "H.bad-accounting",
                    direct_row_limit=1,
                    autoruns_ai_review_enabled=True,
                )

    def test_dynamic_scoped_group_requeries_original_rows_before_disposition(self):
        api = DynamicStackApi(
            netstat_rows(),
            [
                {
                    "Pivot1": "tcp",
                    "Pivot2": "svchost.exe",
                    "Pivot3": "LISTEN",
                    "Count": 4,
                },
                {
                    "Pivot1": "tcp",
                    "Pivot2": "chrome.exe",
                    "Pivot3": "ESTABLISHED",
                    "Count": 16,
                },
            ],
        )
        recommendation = {
            "scope": {"field": "Protocol", "rationale": "Transport scope."},
            "signatures": [
                {"field": "Name", "rationale": "Owning process."},
                {"field": "Status", "rationale": "Connection state."},
            ],
            "rejected": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=recommendation_executor(recommendation),
        ):
            hunt_root = Path(temp_dir) / "H.dynamic-drilldown"
            first = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.dynamic-drilldown", "state": "FINISHED"},
                request=artifact_request(NETSTAT_ARTIFACT),
                hunt_root=hunt_root,
                direct_row_limit=1,
                autoruns_ai_review_enabled=True,
            )
            decisions = Path(temp_dir) / "decisions.json"
            decisions.write_text(
                __import__("json").dumps(
                    {
                        "reviews": [
                            {
                                "review_id": first["review_items"][0]["review_id"],
                                "complete": True,
                                "disposition": "suspicious",
                                "reason": "Requires original network rows.",
                                "drilldown": {
                                    "reason": "Retrieve original process and endpoint context."
                                },
                                "findings": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            second = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.dynamic-drilldown", "state": "FINISHED"},
                request=artifact_request(NETSTAT_ARTIFACT),
                hunt_root=hunt_root,
                direct_row_limit=1,
                decisions_path=decisions,
                autoruns_ai_review_enabled=True,
            )

        self.assertEqual(second["review_items"][0]["kind"], "drilldown")
        drilldown_queries = [
            vql
            for vql, env, _kwargs in api.stream_calls
            if any(key.startswith("DrilldownScope") for key in env)
        ]
        self.assertTrue(drilldown_queries)
        self.assertIn("`Protocol`", drilldown_queries[-1])
        self.assertIn("`Name`", drilldown_queries[-1])
        self.assertIn("`Status`", drilldown_queries[-1])

    def test_stack_threshold_boundary_and_all_excluded(self):
        groups = [dict(artifact=ARTIFACT, scope={}, stack_id="family",
                       logical_dimensions=["EvidenceFamily"], values=[f"family-{count}"],
                       count=count, query="SELECT * FROM source()", env={})
                  for count in (99, 100, 101)]
        seen = []
        def execute(**kwargs):
            seen.extend(csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1])))
            return flag_response(), {}
        with tempfile.TemporaryDirectory() as temp_dir:
            result = generic_stack_review.review_streaming_groups(iter(groups),
                workdir=Path(temp_dir), question="Review", maximum_evidence_tokens=2000,
                token_encoding="cl100k_base", max_flagged_groups=10, executor=execute,
                execution=_test_execution(), max_total_rows=100)
            manifest = result["manifest"]
            self.assertEqual([int(row["Count"]) for row in seen], [99, 100])
            self.assertEqual(manifest["represented_row_count"], 300)
            self.assertEqual(manifest["reviewed_group_count"], 2)
            self.assertEqual(manifest["excluded_group_count"], 1)
            self.assertEqual(manifest["excluded_row_count"], 101)
            seen.clear()
            result = generic_stack_review.review_streaming_groups(iter(groups),
                workdir=Path(temp_dir), question="Review", maximum_evidence_tokens=2000,
                token_encoding="cl100k_base", max_flagged_groups=10, executor=execute,
                execution=_test_execution(), max_total_rows=1)
            self.assertEqual(seen, [])
            self.assertEqual(result["manifest"]["part_count"], 0)
            self.assertEqual(result["manifest"]["excluded_row_count"], 300)

    def test_live_threshold_keeps_coverage_incomplete_and_invalidates_completed_state(self):
        class RepeatedStackApi(StreamingStackApi):
            def query(self, vql, env=None, **kwargs):
                rows = super().query(vql, env, **kwargs)
                return [{"RowCount": 300}] if "count() AS RowCount" in vql else rows

            def query_batches(self, vql, env=None, **kwargs):
                if "Category AS Pivot1" in vql:
                    yield [{"Pivot1": f"family-{count}", "HostCount": 1, "Count": count}
                           for count in (99, 100, 101)]
                else:
                    yield from super().query_batches(vql, env, **kwargs)

        api = RepeatedStackApi(group_count=300)
        seen = []
        def execute(**kwargs):
            seen.extend(csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1])))
            return flag_response(), {}
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review, "run_agent_text_async", side_effect=execute):
            params = dict(investigation_id="IR1", hunt_row={"hunt_id": "H.threshold", "state": "FINISHED"},
                          request=artifact_request(GENERIC_STACK_ARTIFACT),
                          hunt_root=Path(temp_dir)/"H.threshold", autoruns_ai_review_enabled=True)
            complete = live.analyze_live_hunt(api, **params)
            self.assertEqual(complete["result_review_coverage"], "complete")
            seen.clear()
            result = live.analyze_live_hunt(api, **params, stack_max_total_rows=100)
            self.assertEqual(result["result_review_coverage"], "incomplete")
            self.assertFalse(result["stack_analysis_complete"])
            self.assertEqual([int(row["Count"]) for row in seen], [99, 100])
            self.assertEqual(result["streaming_stacks"][GENERIC_STACK_ARTIFACT]["excluded_row_count"], 101)
            self.assertIn("101 records excluded", result["chat_summary"])
            self.assertIn("101 records excluded", Path(result["analysis_file"]).read_text())
            self.assertEqual(result["review_item_count"], 0)
            with mock.patch.object(live, "analyze_generic_streaming_stack_workflow", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "no usable stack"):
                    live.analyze_live_hunt(api, **params, stack_max_total_rows=99)

    def test_review_is_lazy_bounded_and_retains_only_flagged_limit(self):
        yielded = 0
        observed_at_first_execute = []

        def groups():
            nonlocal yielded
            for index in range(100):
                yielded += 1
                yield {
                    "artifact": ARTIFACT,
                    "scope": {"Detection": "PowerShell"},
                    "stack_id": "family",
                    "logical_dimensions": ["EvidenceFamily"],
                    "values": [f"family-{index:04d}"],
                    "count": 1,
                    "query": "SELECT * FROM source()",
                    "env": {},
                }

        def execute(**kwargs):
            if not observed_at_first_execute:
                observed_at_first_execute.append(yielded)
            supplied = list(
                csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1]))
            )
            return flag_response(
                [
                    {
                        "row_id": int(row["RowId"]),
                        "disposition": "notable",
                        "severity": "low",
                        "reason": "Opaque family requires original-row context.",
                    }
                    for row in supplied
                ]
            ), {"input_tokens": len(supplied)}

        with tempfile.TemporaryDirectory() as temp_dir:
            result = generic_stack_review.review_streaming_groups(
                groups(),
                workdir=Path(temp_dir),
                question="Find suspicious activity",
                maximum_evidence_tokens=220,
                token_encoding="cl100k_base",
                max_flagged_groups=7,
                executor=execute,
                execution=_test_execution(),
            )

        manifest = result["manifest"]
        self.assertEqual(manifest["reviewed_group_count"], 100)
        self.assertEqual(manifest["represented_row_count"], 100)
        self.assertEqual(manifest["flagged_group_count"], 100)
        self.assertEqual(manifest["retained_flagged_group_count"], 7)
        self.assertEqual(manifest["omitted_flagged_group_count"], 93)
        self.assertGreater(manifest["part_count"], 1)
        self.assertLess(observed_at_first_execute[0], 100)
        self.assertEqual(len(result["flagged_groups"]), 7)

    def test_live_generic_stack_streams_all_groups_without_total_limit(self):
        api = StreamingStackApi()
        aggregate_rows_seen = []
        followup_rows_seen = []

        def execute(**kwargs):
            supplied = list(
                csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1]))
            )
            if "second pass" in kwargs["prompt"]:
                followup_rows_seen.extend(supplied)
                return followup_response(
                    [
                        {
                            "group_id": row["GroupId"],
                            "disposition": "notable",
                            "severity": "medium",
                            "summary": "Original row remains notable.",
                            "reason": "Follow-up row and impacted host require validation.",
                        }
                        for row in supplied
                    ]
                ), {}
            aggregate_rows_seen.extend(supplied)
            flagged = []
            if supplied and int(supplied[0]["RowId"]) == 1:
                flagged.append(
                    {
                        "row_id": 1,
                        "disposition": "notable",
                        "severity": "medium",
                        "reason": "First streamed family requires raw context.",
                    }
                )
            return flag_response(flagged), {}

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=execute,
        ):
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.streaming-stack", "state": "FINISHED"},
                request=artifact_request(GENERIC_STACK_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.streaming-stack",
                autoruns_ai_review_enabled=True,
                max_review_tokens=2_000,
            )
            report = Path(result["analysis_file"]).read_text(encoding="utf-8")

        self.assertEqual(result["review_item_count"], 1)
        self.assertEqual(result["review_items"][0]["kind"], "normalized_stack")
        self.assertEqual(
            result["review_items"][0]["ai_review"]["disposition"],
            "notable",
        )
        streaming = result["streaming_stacks"][GENERIC_STACK_ARTIFACT]
        self.assertTrue(streaming["streaming"])
        self.assertEqual(streaming["reviewed_group_count"], 2600)
        self.assertEqual(streaming["represented_row_count"], 2600)
        self.assertEqual(streaming["followup_source_row_count"], 1)
        self.assertEqual(streaming["followup_exhaustive_group_count"], 1)
        self.assertEqual(aggregate_rows_seen[0]["HostCount"], "1")
        self.assertIn("HostDenominator", aggregate_rows_seen[0])
        self.assertEqual(followup_rows_seen[0]["ImpactedMachines"], (
            '[{"fqdn":"test.example","client_id":"C.test","row_count":1}]'
        ))
        self.assertEqual(followup_rows_seen[0]["RowsExhaustive"], "true")
        self.assertIn("generic stack", report)
        self.assertIn("2600 rows", report)
        self.assertIn("test.example", report)
        aggregate_queries = [
            vql for vql, _env, _kwargs in api.stream_calls
            if "FROM StackHostGroups" in vql
        ]
        self.assertTrue(aggregate_queries)
        self.assertTrue(all("LIMIT" not in vql for vql in aggregate_queries))
        self.assertTrue(
            all("ORDER BY Count" in vql for vql in aggregate_queries)
        )
        self.assertTrue(
            all("GROUP BY Pivot1, ClientId" in vql for vql in aggregate_queries)
        )
        self.assertTrue(
            all("sum(item=HostRows) AS Count" in vql for vql in aggregate_queries)
        )
        self.assertFalse(
            any(
                "ORDER BY ClientId, FlowId" in vql
                for vql, _env, _kwargs in api.calls
            )
        )

    def test_small_ai_enabled_hunt_still_runs_complete_stack_analysis(self):
        api = StreamingStackApi(group_count=20)
        aggregate_rows_seen = []

        def execute(**kwargs):
            supplied = list(
                csv.DictReader(io.StringIO(kwargs["prompt"].rsplit("CSV:\n", 1)[1]))
            )
            aggregate_rows_seen.extend(supplied)
            return flag_response(), {}

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            generic_stack_review.autoruns_ai_review,
            "run_agent_text_async",
            side_effect=execute,
        ):
            result = live.analyze_live_hunt(
                api,
                investigation_id="IR1",
                hunt_row={"hunt_id": "H.small-stack", "state": "FINISHED"},
                request=artifact_request(GENERIC_STACK_ARTIFACT),
                hunt_root=Path(temp_dir) / "H.small-stack",
                autoruns_ai_review_enabled=True,
            )

        self.assertEqual(live.DEFAULT_DIRECT_ROW_LIMIT, 1000)
        self.assertEqual(result["status"], "review_complete_coverage_unknown")
        self.assertEqual(result["result_review_coverage"], "complete")
        self.assertEqual(result["target_execution_coverage"], "unknown")
        self.assertEqual(result["review_item_count"], 0)
        streaming = result["streaming_stacks"][GENERIC_STACK_ARTIFACT]
        self.assertEqual(streaming["reviewed_group_count"], 20)
        self.assertEqual(streaming["represented_row_count"], 20)
        self.assertEqual(len(aggregate_rows_seen), 20)
        self.assertFalse(
            any(
                "FROM hunt_results" in vql and "LIMIT 20" in vql
                for vql, _env, _kwargs in api.calls
            )
        )


if __name__ == "__main__":
    unittest.main()
