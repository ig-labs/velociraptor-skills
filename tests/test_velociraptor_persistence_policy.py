from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vraptor.artifacts import persistence as persistence_policy


def complete_hunt_state() -> dict:
    return {
        "source_type": "hunt",
        "hunt_id": "H.1234",
        "hunt_state": "FINISHED",
        "status": "complete",
        "coverage": "complete",
        "target_execution_coverage": "complete",
        "result_review_coverage": "complete",
        "artifacts": {
            "Artifact.Test": {
                "status": "complete",
                "budget_stop": {},
                "pending_reviews": [],
            }
        },
    }


def complete_collection_state() -> dict:
    return {
        "source_type": "collection",
        "client_id": "C.1234",
        "request_id": "request-1",
        "status": "complete",
        "coverage": "complete",
        "flow_execution_coverage": "complete",
        "result_review_coverage": "complete",
        "collection_sources": {
            "Artifact.Test": {
                "flow_id": "F.1234",
                "flow_state": "FINISHED",
                "result_component": "Artifact.Test/Results",
            }
        },
        "artifacts": {
            "Artifact.Test": {
                "status": "complete",
                "budget_stop": {},
                "pending_reviews": [],
            }
        },
    }


class VelociraptorPersistencePolicyTest(unittest.TestCase):
    def test_machine_readable_policy_defines_required_classes(self):
        policy = persistence_policy.load_policy()
        self.assertEqual(policy["version"], 5)
        self.assertEqual(policy["default_raw_result_action"], "deny")
        self.assertEqual(
            set(policy["persistence_classes"]),
            {
                "compact_state",
                "complete_required_aggregate",
                "bounded_review_queue",
                "bounded_validation_debug",
                "bounded_agent_runtime_events",
                "bounded_velociraptor_operation_log",
                "exact_suspicious_context",
                "immutable_evidence_export",
                "interoperability_export",
                "raw_result_export",
            },
        )
        debug_policy = policy["persistence_classes"]["bounded_validation_debug"]
        self.assertTrue(debug_policy["safe_provider_metadata"])
        self.assertTrue(debug_policy["safe_configuration_provenance"])
        self.assertEqual(debug_policy["maximum_attempt_records"], 512)
        self.assertEqual(debug_policy["maximum_bytes"], 1_048_576)

    def test_bounded_agent_event_logs_are_classified_without_raw_evidence(self):
        event = {
            "type": "request_completed",
            "task_id": "standalone-analysis",
            "provider": "openai",
            "model": "test-model",
            "protocol": "responses",
            "timestamp": "2026-08-23T14:25:00Z",
            "attempt": 1,
            "request_id": "req-1",
            "metadata": {
                "finish_reason": "completed",
                "local_output_tokens": 1,
                "max_output_tokens_requested": 30,
                "max_output_tokens_sent": True,
                "total_tokens": 3,
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = (
                root
                / "previous-analysis"
                / "20260823T142500Z-a1b2c3d4e5f6"
            )
            archive.mkdir(parents=True)
            path = archive / "review.md.events.jsonl"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            classified = persistence_policy.classify_analysis_file(
                path,
                analysis_root=root,
                source_ids=["hunt:H.1:Artifact.Test"],
            )

        self.assertEqual(
            classified["classification"],
            "bounded_agent_runtime_events",
        )
        self.assertEqual(
            classified["content_profile"],
            "bounded_agent_runtime_events",
        )

    def test_agent_event_log_rejects_unbounded_or_evidence_metadata(self):
        event = {
            "type": "request_completed",
            "task_id": "standalone-analysis",
            "provider": "openai",
            "model": "test-model",
            "protocol": "responses",
            "timestamp": "2026-08-23T14:25:00Z",
            "attempt": 1,
            "request_id": "req-1",
            "metadata": {"evidence": "raw row"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "review.md.events.jsonl"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "unsupported metadata",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_agent_event_log_rejects_malformed_archive_paths_and_event_types(self):
        event = {
            "type": "request_completed",
            "task_id": "standalone-analysis",
            "provider": "openai",
            "model": "test-model",
            "protocol": "responses",
            "timestamp": "2026-08-23T14:25:00Z",
            "attempt": 1,
            "request_id": "req-1",
            "metadata": {},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            invalid_paths = (
                root / "previous-analysis" / "manual" / "review.md.events.jsonl",
                root
                / "previous-analysis"
                / "20260823T142500Z-a1b2c3d4e5f6"
                / "nested"
                / "review.md.events.jsonl",
            )
            for path in invalid_paths:
                with self.subTest(path=path.relative_to(root)):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(
                        persistence_policy.PersistencePolicyError,
                        "Previous analysis files must use",
                    ):
                        persistence_policy.classify_analysis_file(
                            path,
                            analysis_root=root,
                            source_ids=["hunt:H.1:Artifact.Test"],
                        )

            event["type"] = "evidence_recorded"
            path = root / "review.md.events.jsonl"
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "unsupported event type",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_raw_result_persistence_is_denied_in_live_analysis(self):
        with self.assertRaisesRegex(
            persistence_policy.PersistencePolicyError,
            "denied during live analysis",
        ):
            persistence_policy.authorize_persistence(
                "raw_result_export",
                source_ids=["hunt:H.1:Artifact.Test"],
                raw_rows=True,
            )

    def test_operation_log_is_bounded_and_evidence_free(self):
        authorized = persistence_policy.authorize_persistence(
            "bounded_velociraptor_operation_log",
            source_ids=["op-v1-0123456789abcdef"],
            bounded=True,
        )
        self.assertFalse(authorized["raw_rows"])
        self.assertTrue(authorized["bounded"])

    def test_detectraptor_stack_candidate_is_compact_canonical_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "detectraptor-stack-candidates.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "hunt_id": "H.1",
                        "artifact": "DetectRaptor.Windows.Detection.Evtx",
                        "analysis_id": "analysis",
                        "detection_regex": "^Rule$",
                        "candidate_count": 1,
                        "candidates": [
                            {
                                "candidate_id": "candidate",
                                "detection": "Rule",
                                "group_id": "group",
                                "group_rows": 20,
                                "source_ref": "S0001-R1",
                                "reason": "Expected system activity.",
                                "status": "uplift-review-required",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            classified = persistence_policy.classify_analysis_file(
                path,
                analysis_root=root,
                source_ids=["hunt:H.1:DetectRaptor.Windows.Detection.Evtx"],
            )

        self.assertEqual(classified["classification"], "compact_state")
        self.assertFalse(classified["raw_rows"])

    def test_validation_debug_manifest_is_bounded_value_free_state(self):
        for filename in (
            "hunt-analysis-validation-debug.json",
            "host-analysis-validation-debug.json",
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                path = root / filename
                path.write_text(
                    json.dumps(
                        {
                            "attempt_failure_count": 1,
                            "attempt_failures": [
                                {
                                    "chunk_id": "chunk-1",
                                    "failure_type": "validation_failed",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                classified = persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

            self.assertEqual(
                classified["classification"],
                "bounded_validation_debug",
            )
            self.assertTrue(classified["bounded"])
            self.assertFalse(classified["raw_rows"])

    def test_explicit_raw_export_exceptions_require_operator_intent(self):
        for classification in (
            "immutable_evidence_export",
            "interoperability_export",
        ):
            with self.subTest(classification=classification):
                with self.assertRaisesRegex(
                    persistence_policy.PersistencePolicyError,
                    "explicit export request",
                ):
                    persistence_policy.authorize_persistence(
                        classification,
                        source_ids=["hunt:H.1:Artifact.Test"],
                        raw_rows=True,
                    )
                authorized = persistence_policy.authorize_persistence(
                    classification,
                    source_ids=["hunt:H.1:Artifact.Test"],
                    raw_rows=True,
                    explicit_export=True,
                )
                self.assertTrue(authorized["explicit_export"])

    def test_exact_context_requires_source_and_finding_identity(self):
        with self.assertRaisesRegex(
            persistence_policy.PersistencePolicyError,
            "finding identifiers",
        ):
            persistence_policy.authorize_persistence(
                "exact_suspicious_context",
                source_ids=["flow:C.1:F.1:Artifact.Test"],
                raw_rows=True,
                exact=True,
            )
        authorized = persistence_policy.authorize_persistence(
            "exact_suspicious_context",
            source_ids=["flow:C.1:F.1:Artifact.Test"],
            raw_rows=True,
            exact=True,
            finding_ids=["finding-1"],
        )
        self.assertEqual(authorized["finding_ids"], ["finding-1"])

    def test_manager_selected_markdown_is_exact_finding_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "finding-evidence.md"
            path.write_text(
                "# Finding evidence\n\n- Supports: M1, M2\n",
                encoding="utf-8",
            )
            classified = persistence_policy.classify_analysis_file(
                path,
                analysis_root=root,
                source_ids=["hunt:H.1:Artifact.Test"],
            )

        self.assertEqual(classified["classification"], "exact_suspicious_context")
        self.assertEqual(classified["finding_ids"], ["M1", "M2"])
        self.assertEqual(
            classified["content_profile"],
            "manager_selected_exact_context",
        )

    def test_compact_markdown_rejects_row_shaped_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "analysis-hunt.md"
            path.write_text(
                "# Analysis\n\n"
                "#### Suspicious host and persistence context\n\n"
                "- Launch: `powershell.exe one`\n"
                "- Endpoint: `host-one`\n"
                "- Launch: `powershell.exe two`\n"
                "- Endpoint: `host-two`\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "exact row-shaped evidence",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_compact_markdown_enforces_content_size_guard(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "analysis-hunt.md"
            path.write_text(
                "# Analysis\n" + ("bounded summary line\n" * 30_000),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "content guard",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_compact_json_rejects_inline_row_payloads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "hunt-analysis-state.json"
            path.write_text(
                json.dumps({"rows": [{"CommandLine": "secret"}]}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "inline row payloads",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_legacy_specialized_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "state.json"
            path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "Legacy Autoruns live-analysis output",
            ):
                persistence_policy.classify_analysis_file(
                    path,
                    analysis_root=root,
                    source_ids=["hunt:H.1:Artifact.Test"],
                )

    def test_terminal_complete_hunt_and_collection_can_close(self):
        for state in (complete_hunt_state(), complete_collection_state()):
            with self.subTest(source_type=state["source_type"]):
                coverage = persistence_policy.enforce_closure(state)
                self.assertTrue(coverage["complete_claim_allowed"])
                self.assertTrue(coverage["source_ids"])
                self.assertEqual(coverage["closure_blockers"], [])

    def test_ad_hoc_result_set_review_can_close_without_target_assessment(self):
        state = complete_hunt_state()
        state.update(
            {
                "review_scope": "ad_hoc_review",
                "target_execution_coverage": "not_assessed",
            }
        )

        coverage = persistence_policy.enforce_closure(state)

        self.assertTrue(coverage["complete_claim_allowed"])
        self.assertEqual(coverage["execution_coverage"], "not_assessed")
        self.assertNotIn("target_scope_incomplete", coverage["closure_blockers"])

    def test_managed_hunt_cannot_use_not_assessed_target_coverage(self):
        state = complete_hunt_state()
        state["target_execution_coverage"] = "not_assessed"

        with self.assertRaisesRegex(
            persistence_policy.PersistencePolicyError,
            "target_scope_incomplete",
        ):
            persistence_policy.enforce_closure(state)

    def test_non_terminal_sampled_truncated_and_token_limited_fail_closed(self):
        cases = {
            "source_non_terminal": {"hunt_state": "RUNNING"},
            "sampled": {"artifacts": {"Artifact.Test": {"sampled": True}}},
            "sample_review": {
                "artifacts": {
                    "Artifact.Test": {
                        "pending_reviews": [
                            {
                                "kind": "sample",
                                "exhaustive": False,
                                "query": {"truncated": False},
                            }
                        ]
                    }
                }
            },
            "truncated": {"artifacts": {"Artifact.Test": {"truncated": True}}},
            "token_limited": {
                "artifacts": {
                    "Artifact.Test": {
                        "budget_stop": {"outcome": "token_limit_reached"}
                    }
                }
            },
            "group_truncated": {
                "artifacts": {"Artifact.Test": {"group_truncated": True}}
            },
        }
        for blocker, updates in cases.items():
            state = complete_hunt_state()
            state.update(updates)
            with self.subTest(blocker=blocker):
                with self.assertRaisesRegex(
                    persistence_policy.PersistencePolicyError,
                    "sampled" if blocker == "sample_review" else blocker,
                ):
                    persistence_policy.enforce_closure(state)

    def test_audit_records_compact_outputs_and_permitted_reductions(self):
        state = complete_hunt_state()
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "H.1234"
            root = hunt_root / "analysis"
            root.mkdir(parents=True)
            (root / "hunt-analysis-state.json").write_text("{}", encoding="utf-8")
            analysis_memory = hunt_root / "analysis-hunt.md"
            analysis_memory.write_text("# Analysis\n", encoding="utf-8")
            (root / "autoruns_potential_golden.csv").write_text(
                "# SchemaVersion: 2\n"
                f"# SourceStackSHA256: {'a' * 64}\n"
                "# ReviewedGroupCount: 1\n"
                "# ReviewComplete: true\n"
                "ImagePath,LaunchString,Signer,Total,Reason\n"
                "example.exe,example.exe,,2,reviewed\n",
                encoding="utf-8",
            )
            manifest = persistence_policy.audit_analysis_tree(
                root,
                state,
                extra_files=[analysis_memory],
            )

        classes = {
            record["path"]: record["classification"]
            for record in manifest["files"]
        }
        self.assertEqual(manifest["raw_result_export_count"], 0)
        self.assertEqual(classes["analysis-hunt.md"], "compact_state")
        self.assertEqual(classes["hunt-analysis-state.json"], "compact_state")
        self.assertEqual(
            classes["autoruns_potential_golden.csv"],
            "complete_required_aggregate",
        )
        profiles = {
            record["path"]: record.get("content_profile")
            for record in manifest["files"]
        }
        self.assertEqual(
            profiles["analysis-hunt.md"],
            "compact_human_summary",
        )
        self.assertEqual(
            profiles["hunt-analysis-state.json"],
            "compact_structured_state",
        )

    def test_unclassified_csv_is_preserved_and_rejected(self):
        state = complete_hunt_state()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            unauthorized = root / "all_hunt_results.csv"
            unauthorized.write_text("secret\nraw-row\n", encoding="utf-8")
            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError,
                "Unclassified raw-result-like",
            ):
                persistence_policy.audit_analysis_tree(root, state)
            self.assertTrue(unauthorized.exists())

    def test_preflight_preserves_and_explains_all_incompatible_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = [root / "old.csv", root / "old.sqlite"]
            for path in paths:
                path.write_text("old data\n")
            with self.assertRaises(persistence_policy.PersistencePolicyError) as caught:
                persistence_policy.preflight_analysis_tree(root, ["hunt:H.1234"])
            message = str(caught.exception)
            self.assertIn("output_preflight", message)
            self.assertIn("No files were removed", message)
            self.assertIn("rerun the same command", message)
            for path in paths:
                self.assertIn(str(path), message)
                self.assertEqual(path.read_text(), "old data\n")

    def test_final_audit_rechecks_new_outputs_after_preflight(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "analysis"
            persistence_policy.preflight_analysis_tree(root, ["hunt:H.1234"])
            self.assertFalse(root.exists())
            root.mkdir()
            bad = root / "new.sqlite"
            bad.write_text("new data")
            with self.assertRaisesRegex(
                persistence_policy.PersistencePolicyError, "during publishing",
            ):
                persistence_policy.audit_analysis_tree(root, complete_hunt_state())
            self.assertTrue(bad.exists())

if __name__ == "__main__":
    unittest.main()
