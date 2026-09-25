import importlib.util
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = REPO_ROOT / "src/vraptor"


def load_module(filename):
    name = f"hunt_metadata_{Path(filename).stem}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, MODULE_ROOT / {"hunting.py": "hunt/operations.py", "hunt_workflow.py": "hunt/command.py"}[filename])
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class HuntMetadataLookupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("hunting.py")

    def test_partial_specs_keep_parameters_and_include_other_declared_artifacts(self):
        row = {
            "start_request": {
                "artifacts": ["Artifact.Files", "Artifact.Remote", "Artifact.Logs"],
                "specs": [{
                    "artifact": "Artifact.Files",
                    "parameters": {"env": [{"key": "Path", "value": "*.log"}]},
                    "timeout": 120,
                }],
            },
        }

        specs = self.module.hunt_requested_specs(row)

        self.assertEqual([spec.artifact for spec in specs], row["start_request"]["artifacts"])
        self.assertEqual(specs[0].env, {"Path": "*.log"})
        self.assertEqual(specs[0].timeout_seconds, 120)
        self.assertEqual(specs[1].env, {})
        self.assertIsNone(specs[1].timeout_seconds)
        self.assertEqual(self.module.hunt_artifact_names(row), row["start_request"]["artifacts"])
        self.assertEqual(
            self.module.artifact_filters_match(row, ["Artifact.Remote"], None),
            (True, ["Artifact.Remote"]),
        )

    def test_spec_artifact_matching_is_case_insensitive(self):
        row = {"start_request": {
            "artifacts": ["Artifact.Files", "Artifact.Remote"],
            "specs": [{"artifact": "artifact.files"}],
        }}

        specs = self.module.hunt_requested_specs(row)

        self.assertEqual([spec.artifact for spec in specs], ["artifact.files", "Artifact.Remote"])

    def test_declared_artifacts_survive_unusable_specs(self):
        row = {"start_request": {
            "artifacts": ["Artifact.Remote"],
            "specs": [{"parameters": {}}],
        }}

        self.assertEqual(
            [spec.artifact for spec in self.module.hunt_requested_specs(row)],
            ["Artifact.Remote"],
        )

    def test_modern_complete_row_needs_one_query_and_is_copied(self):
        row = {
            "hunt_id": "H.test",
            "start_request": {"artifacts": ["Artifact.One"]},
            "artifacts": ["Artifact.One"],
            "artifact_sources": ["Artifact.One/Source"],
        }
        api = mock.Mock()
        api.query.return_value = [row]

        result = self.module.query_single_hunt(api, "H.test")

        self.assertEqual(result, row)
        self.assertIsNot(result, row)
        api.query.assert_called_once_with(
            "SELECT * FROM hunts(hunt_id=HuntId)", {"HuntId": "H.test"}
        )

    def test_complete_legacy_request_needs_one_query(self):
        row = {
            "hunt_id": "H.test",
            "Request": {"artifact_sources": ["Artifact.One/Source"]},
            "start_request": {"artifacts": ["Artifact.One"]},
        }
        api = mock.Mock()
        api.query.return_value = [row]

        self.assertEqual(self.module.query_single_hunt(api, "H.test"), row)
        self.assertEqual(api.query.call_count, 1)

    def test_sparse_row_merges_both_requests_without_overwriting_other_fields(self):
        row = {"hunt_id": "H.test", "state": "RUNNING", "Request": None}
        info = {
            "hunt_id": "H.test",
            "state": "STOPPED",
            "Request": {"artifact_sources": ["Artifact.One/Source"]},
            "start_request": {"artifacts": ["Artifact.One"]},
        }
        api = mock.Mock()
        api.query.side_effect = [[row], [{"Hunt": info}]]

        result = self.module.query_single_hunt(api, "H.test")

        self.assertEqual(result["state"], "RUNNING")
        self.assertEqual(result["Request"], info["Request"])
        self.assertEqual(result["start_request"], info["start_request"])
        self.assertEqual(row, {"hunt_id": "H.test", "state": "RUNNING", "Request": None})
        self.assertEqual(
            api.query.call_args_list,
            [
                mock.call("SELECT * FROM hunts(hunt_id=HuntId)", {"HuntId": "H.test"}),
                mock.call(
                    "SELECT hunt_info(hunt_id=HuntId) AS Hunt FROM scope()",
                    {"HuntId": "H.test"},
                ),
            ],
        )

    def test_sparse_row_preserves_each_existing_request(self):
        for existing_key, missing_key in (
            ("Request", "start_request"),
            ("start_request", "Request"),
        ):
            with self.subTest(existing_key=existing_key):
                original_request = {"preserve": True}
                row = {"hunt_id": "H.test", existing_key: original_request}
                info = {existing_key: {"overwrite": False}, missing_key: {"fill": True}}
                api = mock.Mock()
                api.query.side_effect = [[row], [{"Hunt": info}]]

                result = self.module.query_single_hunt(api, "H.test")

                self.assertEqual(result[existing_key], original_request)
                self.assertEqual(result[missing_key], {"fill": True})
                self.assertNotIn(missing_key, row)
                self.assertEqual(api.query.call_count, 2)

    def test_empty_modern_sources_still_enrich_named_sources_from_request(self):
        for sources in ([], [""], ["  "]):
            with self.subTest(sources=sources):
                row = {
                    "hunt_id": "H.test",
                    "start_request": {"artifacts": ["Artifact.One"]},
                    "artifacts": ["Artifact.One"],
                    "artifact_sources": sources,
                }
                legacy_request = {"artifact_sources": ["Artifact.One/NamedSource"]}
                api = mock.Mock()
                api.query.side_effect = [[row], [{"Hunt": {"Request": legacy_request}}]]

                result = self.module.query_single_hunt(api, "H.test")

                self.assertEqual(result["Request"], legacy_request)
                self.assertIn(
                    "Artifact.One/NamedSource",
                    self.module.hunt_result_artifact_sources(result),
                )
                self.assertEqual(api.query.call_count, 2)

    def test_partial_modern_shapes_keep_fallback(self):
        complete = {
            "hunt_id": "H.test",
            "start_request": {},
            "artifacts": ["Artifact.One"],
            "artifact_sources": ["Artifact.One/Source"],
        }
        for key in ("start_request", "artifacts", "artifact_sources"):
            for invalid in (None, "unexpected-shape"):
                with self.subTest(key=key, invalid=invalid):
                    row = {**complete, key: invalid}
                    api = mock.Mock()
                    api.query.side_effect = [[row], []]
                    self.assertEqual(self.module.query_single_hunt(api, "H.test"), row)
                    self.assertEqual(api.query.call_count, 2)

    def test_empty_primary_uses_copied_info_record(self):
        info = {"hunt_id": "H.test", "start_request": {}}
        api = mock.Mock()
        api.query.side_effect = [[], [{"Hunt": info}]]

        result = self.module.query_single_hunt(api, "H.test")

        self.assertEqual(result, info)
        self.assertIsNot(result, info)
        self.assertEqual(api.query.call_count, 2)

    def test_missing_or_malformed_info_does_not_invent_hunt(self):
        for info_rows in ([], [{}], [{"Hunt": None}], [{"Hunt": "invalid"}]):
            with self.subTest(info_rows=info_rows):
                api = mock.Mock()
                api.query.side_effect = [[], info_rows]
                self.assertIsNone(self.module.query_single_hunt(api, "H.test"))
                self.assertEqual(api.query.call_count, 2)

    def test_sparse_primary_survives_missing_info(self):
        row = {"hunt_id": "H.test", "state": "RUNNING"}
        api = mock.Mock()
        api.query.side_effect = [[row], []]
        self.assertEqual(self.module.query_single_hunt(api, "H.test"), row)
        self.assertEqual(api.query.call_count, 2)

    def test_primary_api_error_propagates_without_fallback(self):
        api = mock.Mock()
        api.query.side_effect = RuntimeError("primary transport failed")
        with self.assertRaisesRegex(RuntimeError, "primary transport failed"):
            self.module.query_single_hunt(api, "H.test")
        self.assertEqual(api.query.call_count, 1)

    def test_required_fallback_api_error_propagates(self):
        api = mock.Mock()
        api.query.side_effect = [[{"hunt_id": "H.test"}], RuntimeError("info failed")]
        with self.assertRaisesRegex(RuntimeError, "info failed"):
            self.module.query_single_hunt(api, "H.test")
        self.assertEqual(api.query.call_count, 2)


class HuntStatusMetadataReuseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("hunting.py")

    def test_supplied_row_is_copied_but_flow_inventory_is_always_fresh(self):
        row = {"hunt_id": "H.test", "state": "RUNNING"}
        baseline = {"targets": [{"client_id": "C.one"}]}
        api = object()

        def summarize(metadata):
            self.assertIsNot(metadata, row)
            metadata["local_summary_marker"] = True
            return {"hunt_id": "H.test", "state": "RUNNING"}

        with (
            mock.patch.object(self.module, "query_single_hunt") as metadata_query,
            mock.patch.object(self.module, "hunt_summary_from_row", side_effect=summarize),
            mock.patch.object(
                self.module, "query_hunt_flows", side_effect=[[{"row": 1}], [{"row": 2}]]
            ) as flow_query,
            mock.patch.object(self.module, "summary_from_hunt_flows", return_value={}) as flow_summary,
        ):
            first = self.module.refresh_hunt_status(
                api, "H.test", hunt_row=row, baseline_snapshot=baseline
            )
            second = self.module.refresh_hunt_status(
                api, "H.test", hunt_row=row, baseline_snapshot=baseline
            )

        metadata_query.assert_not_called()
        self.assertEqual(flow_query.call_args_list, [mock.call(api, "H.test")] * 2)
        self.assertEqual(first["flows_sample"], [{"row": 1}])
        self.assertEqual(second["flows_sample"], [{"row": 2}])
        self.assertEqual(flow_summary.call_args.kwargs["baseline_client_ids"], {"C.one"})
        self.assertNotIn("local_summary_marker", row)

    def test_supplied_wrong_or_missing_hunt_id_fails_before_queries(self):
        for row in ({"hunt_id": "H.other"}, {"HuntId": "H.other"}, {}):
            with self.subTest(row=row):
                api = mock.Mock()
                with self.assertRaises(ValueError):
                    self.module.refresh_hunt_status(api, "H.test", hunt_row=row)
                api.query.assert_not_called()

    def test_default_refresh_still_queries_metadata_and_flows(self):
        api = object()
        row = {"hunt_id": "H.test", "state": "RUNNING"}
        with (
            mock.patch.object(self.module, "query_single_hunt", return_value=row) as metadata_query,
            mock.patch.object(self.module, "query_hunt_flows", return_value=[]) as flow_query,
        ):
            result = self.module.refresh_hunt_status(api, "H.test")
        metadata_query.assert_called_once_with(api, "H.test")
        flow_query.assert_called_once_with(api, "H.test")
        self.assertEqual(result["hunt_id"], "H.test")

    def test_default_refresh_missing_hunt_does_not_query_flows(self):
        with (
            mock.patch.object(self.module, "query_single_hunt", return_value=None),
            mock.patch.object(self.module, "query_hunt_flows") as flow_query,
        ):
            with self.assertRaisesRegex(RuntimeError, "Hunt H.test was not found"):
                self.module.refresh_hunt_status(object(), "H.test")
        flow_query.assert_not_called()

    def test_flow_query_errors_still_propagate_with_reused_metadata(self):
        with mock.patch.object(
            self.module, "query_hunt_flows", side_effect=RuntimeError("fresh flows failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "fresh flows failed"):
                self.module.refresh_hunt_status(
                    object(), "H.test", hunt_row={"hunt_id": "H.test", "state": "RUNNING"}
                )


class HuntAnalysisMetadataReuseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("hunt_workflow.py")

    def test_analysis_status_opt_in_preserves_baseline_and_selection_markers(self):
        module = self.module
        row = {
            "hunt_id": "H.test",
            module.SELECTED_ARTIFACTS_KEY: ["Artifact.One"],
            module.SELECTED_GROUP_KEY: "IR-test",
        }
        baseline = {"targets": [{"client_id": "C.one"}]}
        for reuse_metadata in (False, True):
            with self.subTest(reuse_metadata=reuse_metadata):
                api = object()
                with (
                    mock.patch.object(module, "load_cached_baseline", return_value=baseline),
                    mock.patch.object(module, "resolve_review_scope", return_value="managed_collection"),
                    mock.patch.object(module, "review_readiness_payload", return_value={"ready": True}),
                    mock.patch.object(
                        module.generic, "refresh_hunt_status", return_value={"hunt_id": "H.test"}
                    ) as refresh,
                ):
                    kwargs = {"reuse_metadata": True} if reuse_metadata else {}
                    result = module.analysis_status_for_row(
                        api, row, Path("/cases"), investigation_id="IR-test", **kwargs
                    )
                expected = {"baseline_snapshot": baseline}
                if reuse_metadata:
                    expected["hunt_row"] = row
                refresh.assert_called_once_with(api, "H.test", **expected)
                self.assertEqual(result[module.SELECTED_ARTIFACTS_KEY], ["Artifact.One"])
                self.assertEqual(result[module.SELECTED_GROUP_KEY], "IR-test")
                self.assertTrue(result["ready"])

    def test_command_reuses_only_explicit_hunt_without_retry_attempts(self):
        module = self.module
        scenarios = [
            (True, status, 0, True)
            for status in ("disabled", "baseline_unavailable", "not_due", "nothing_due")
        ] + [
            (False, "disabled", 0, False),
            (False, "nothing_due", 0, False),
            (True, "disabled", 1, False),
            (True, "nothing_due", 1, False),
            (True, "retried", 1, False),
            (True, "failed", 1, False),
            (True, "failed", 0, False),
            (True, "unknown", 0, False),
        ]

        class StatusReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as temp_dir:
            for explicit, status, requested_count, expected_reuse in scenarios:
                with self.subTest(explicit=explicit, status=status, requested_count=requested_count):
                    selector = ["--hunt-id", "H.test"] if explicit else ["--group", "IR-test"]
                    args = module.parse_args([
                        "analyze", "--id", "IR-test", *selector,
                        "--api-client", str(Path(__file__).resolve()),
                        "--case-root", temp_dir,
                    ])
                    row = {"hunt_id": "H.test", "state": "RUNNING"}
                    with (
                        mock.patch.object(module, "VeloApiClient"),
                        mock.patch.object(module, "discover_hunt_rows", return_value=[row]),
                        mock.patch.object(module, "preflight_hunt_outputs"),
                        mock.patch.object(module, "resolve_task_output", return_value=("targeted_hunt", "standard")),
                        mock.patch.object(module, "load_cached_baseline", return_value=None),
                        mock.patch.object(module, "request_for_selected_row", return_value=SimpleNamespace(expected_specs=[])),
                        mock.patch.object(module, "resolve_live_analysis_mode", return_value={"mode": "stream"}),
                        mock.patch.object(module.analysis_time_scope, "resolve_all"),
                        mock.patch.object(module.artifact_policy, "load_artifact_policy", return_value=SimpleNamespace(profiles={})),
                        mock.patch.object(module, "retry_missing_clients", return_value={
                            "hunt_id": "H.test", "status": status,
                            "requested_count": requested_count, "queued_count": 0,
                        }),
                        mock.patch.object(module, "analysis_status_for_row", side_effect=StatusReached) as status_for_row,
                    ):
                        with self.assertRaises(StatusReached):
                            module.command_analyze(args)
                    self.assertEqual(status_for_row.call_count, 1)
                    self.assertIs(status_for_row.call_args.kwargs["reuse_metadata"], expected_reuse)


if __name__ == "__main__":
    unittest.main()
