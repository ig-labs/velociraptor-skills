import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "src/vraptor/hunt/operations.py"
)


def load_run_velociraptor_hunting_module():
    module_name = f"test_run_velociraptor_hunting_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class RunVelociraptorHuntingOrgIdRegressionTest(unittest.TestCase):
    def test_native_lookup_binds_case_before_dispatch(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            args = module.argparse.Namespace(
                command="lookup", investigation_id="audit-case", case_root=temp_dir,
            )
            with (
                mock.patch.object(module, "parse_args", return_value=args),
                mock.patch.object(module.operation_log, "bind_case") as bind_case,
                mock.patch.object(module.operation_log, "correlation_metadata", return_value={}),
                mock.patch.object(module, "command_lookup") as lookup,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                def dispatch(actual_args):
                    bind_case.assert_called_once_with(Path(temp_dir).resolve(), "audit-case")
                    self.assertIs(actual_args, args)
                    return {"hunts": []}

                lookup.side_effect = dispatch
                self.assertEqual(module.main([]), 0)
                lookup.assert_called_once_with(args)
            self.assertEqual(json.loads(output.getvalue()), {"hunts": []})

    def test_finalize_args_normalizes_legacy_orgs_root_default(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("dummy\n", encoding="utf-8")
            args = module.argparse.Namespace(
                command="ensure",
                api_client=str(api_client),
                investigation_id="ir9005",
                server_profile="lab7",
                org_id="orgs/root",
                case_root=None,
                target=None,
                os=None,
            )

            context = mock.Mock(
                engagement_id="ir9005",
                server_profile="lab7",
                api_client=api_client,
                case_root=Path(temp_dir),
            )
            with mock.patch.object(
                module.engagement_context,
                "resolve",
                return_value=context,
            ):
                resolved = module.finalize_args(args)

        self.assertEqual(resolved.org_id, "root")

    def test_finalize_args_prefers_case_specific_api_client_cache(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            home_dir = Path(temp_dir)
            module.REPO_ROOT = home_dir / "repo"
            module.REPO_ROOT.mkdir()
            api_client = home_dir / ".config" / "velociraptor" / "ca264_api_client.yaml"
            api_client.parent.mkdir(parents=True, exist_ok=True)
            api_client.write_text("api-client: ca264\n", encoding="utf-8")

            args = module.argparse.Namespace(
                command="review-results",
                api_client=None,
                org_id=None,
                case_root=None,
                target=None,
                os=None,
                investigation_id="ca264",
                server_profile="ca264",
            )

            context = mock.Mock(
                engagement_id="ca264",
                server_profile="ca264",
                api_client=api_client.resolve(),
                case_root=home_dir / "cases",
            )
            with mock.patch.object(
                module.engagement_context,
                "resolve",
                return_value=context,
            ):
                resolved = module.finalize_args(args)

        self.assertEqual(resolved.api_client_path, api_client.resolve())
        self.assertEqual(resolved.org_id, "root")


class RunVelociraptorHuntingPathTest(unittest.TestCase):
    def test_hunt_storage_is_flat_and_target_independent(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            expected = Path(temp_dir) / "IR9002" / "hunts"

            self.assertEqual(module.target_hunt_root("IR9002", "windows"), expected)
            self.assertEqual(module.target_hunt_root("IR9002", "linux"), expected)
            self.assertEqual(
                module.hunt_state_path("IR9002", "H.1234", target_os="windows"),
                expected / "H.1234" / "state.json",
            )
            self.assertEqual(
                module.current_profile_path(
                    "IR9002",
                    "detectraptor",
                    target_os="windows",
                ),
                expected / "current-windows-detectraptor.json",
            )


class RunVelociraptorHuntingScopeRegressionTest(unittest.TestCase):
    def test_case_scope_requires_exact_engagement_marker(self):
        module = load_run_velociraptor_hunting_module()
        matching = {
            "hunt_description": "velociraptor-hunting dfir-engagement:ir9005 Artifact.Target"
        }
        adjacent = {
            "hunt_description": "velociraptor-hunting dfir-engagement:ir90050 Artifact.Target"
        }
        self.assertEqual(
            module.resolve_case_scope(
                matching,
                "ir9005",
                "Artifact.Target",
                "signature",
            ),
            (True, True),
        )
        self.assertEqual(
            module.resolve_case_scope(
                adjacent,
                "ir9005",
                "Artifact.Target",
                "signature",
            ),
            (False, True),
        )
    def make_request(self, module):
        return module.collection.CollectionRequest(
            target_collection_type="hunt",
            requested_groups=[],
            requested_artifacts=["Generic.Client.Info"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Generic.Client.Info",
                    artifact="Generic.Client.Info",
                    env={},
                )
            ],
        )

    def create_and_capture(self, module, *, target_os="", include_labels=None, exclude_labels=None):
        calls = []

        class FakeApi:
            def query(self, vql, env=None, **kwargs):
                calls.append((vql, env or {}, kwargs))
                return [{"HuntResult": {"HuntId": "H.scope"}}]

        result = module.create_hunt(
            FakeApi(),
            "ir9003",
            "generic-client-info",
            self.make_request(module),
            target_os,
            include_labels or [],
            exclude_labels or [],
            [],
            False,
        )
        return result, calls[0]

    def test_include_labels_omit_os_and_keep_exclusions(self):
        module = load_run_velociraptor_hunting_module()

        result, (vql, env, _) = self.create_and_capture(
            module,
            target_os="linux",
            include_labels=["IR9003"],
            exclude_labels=["maintenance"],
        )

        self.assertNotIn("os=", vql)
        self.assertIn("include_labels=IncludedLabels", vql)
        self.assertIn("exclude_labels=ExcludedLabels", vql)
        self.assertNotIn("TargetOS", env)
        self.assertEqual(json.loads(env["IncludeLabelsJson"]), ["IR9003"])
        self.assertEqual(json.loads(env["ExcludeLabelsJson"]), ["maintenance"])
        self.assertEqual(result["target_os"], "linux")
        self.assertEqual(result["server_target_os"], "")
        self.assertEqual(result["target_scope_mode"], "label")

    def test_os_scope_omits_empty_label_arguments(self):
        module = load_run_velociraptor_hunting_module()

        result, (vql, env, _) = self.create_and_capture(module, target_os="linux")

        self.assertIn("os=TargetOS", vql)
        self.assertNotIn("include_labels=", vql)
        self.assertNotIn("exclude_labels=", vql)
        self.assertEqual(env["TargetOS"], "linux")
        self.assertEqual(result["target_scope_mode"], "os")

    def test_unscoped_hunt_omits_os_and_labels(self):
        module = load_run_velociraptor_hunting_module()

        result, (vql, env, _) = self.create_and_capture(module)

        self.assertNotIn("os=", vql)
        self.assertNotIn("include_labels=", vql)
        self.assertNotIn("exclude_labels=", vql)
        self.assertNotIn("TargetOS", env)
        self.assertEqual(result["target_scope_mode"], "unscoped")
        self.assertEqual(result["target_os"], "")

    def test_exclusion_only_can_be_combined_with_os_or_unscoped(self):
        module = load_run_velociraptor_hunting_module()

        os_result, (os_vql, os_env, _) = self.create_and_capture(
            module,
            target_os="linux",
            exclude_labels=["maintenance"],
        )
        all_result, (all_vql, all_env, _) = self.create_and_capture(
            module,
            exclude_labels=["maintenance"],
        )

        self.assertIn("os=TargetOS", os_vql)
        self.assertIn("exclude_labels=ExcludedLabels", os_vql)
        self.assertEqual(os_env["TargetOS"], "linux")
        self.assertEqual(os_result["target_scope_mode"], "os")
        self.assertNotIn("os=", all_vql)
        self.assertIn("exclude_labels=ExcludedLabels", all_vql)
        self.assertNotIn("TargetOS", all_env)
        self.assertEqual(all_result["target_scope_mode"], "unscoped")

    def test_label_baseline_uses_labels_instead_of_local_os_metadata(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def query(self, *args, **kwargs):
                return [
                    {
                        "client_id": "C.windows-labelled",
                        "Hostname": "labelled",
                        "Labels": ["IR9003"],
                        "OSType": "windows",
                    },
                    {
                        "client_id": "C.linux-unlabelled",
                        "Hostname": "unlabelled",
                        "Labels": [],
                        "OSType": "linux",
                    },
                ]

        targets = module.query_scope_clients(
            FakeApi(),
            "linux",
            ["IR9003"],
            [],
        )

        self.assertEqual([row["client_id"] for row in targets], ["C.windows-labelled"])

    def test_scope_readback_rejects_server_os_when_include_labels_were_requested(self):
        module = load_run_velociraptor_hunting_module()
        expected = module.resolve_hunt_target_scope("linux", ["IR9003"], [])
        server_row = {
            "start_request": {
                "os": "linux",
                "include_labels": ["IR9003"],
                "exclude_labels": [],
            }
        }

        with self.assertRaisesRegex(RuntimeError, "server target scope differs"):
            module.raise_for_hunt_scope_validation_errors(server_row, expected)

    def test_scope_readback_uses_server_condition_fields(self):
        module = load_run_velociraptor_hunting_module()
        expected = module.resolve_hunt_target_scope("", ["ir9003"], ["maintenance"])
        server_row = {
            "condition": {
                "labels": {"label": ["ir9003"]},
                "excluded_labels": {"label": ["maintenance"]},
                "os": {"os": "ALL"},
            }
        }

        self.assertEqual(module.hunt_scope_validation_errors(server_row, expected), [])
        self.assertEqual(module.hunt_scope_mode_from_row(server_row), "label")
        self.assertEqual(module.hunt_target_os(server_row), "")

        summary = module.hunt_summary_from_row(
            {
                "hunt_id": "H.scope",
                "condition": server_row["condition"],
            }
        )
        self.assertEqual(summary["target_scope_mode"], "label")
        self.assertEqual(summary["host_include_labels"], ["ir9003"])
        self.assertEqual(summary["host_exclude_labels"], ["maintenance"])
        self.assertEqual(summary["condition"], server_row["condition"])

    def test_cli_without_target_uses_unscoped_namespace(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("dummy\n", encoding="utf-8")
            args = module.parse_args(
                [
                    "--api-client",
                    str(api_client),
                    "ensure",
                    "--investigation-id",
                    "ir9003",
                    "--artifact",
                    "Generic.Client.Info",
                ],
                finalize=False,
            )

        self.assertEqual(args.os, "")
        self.assertEqual(module.target_namespace(args.os), "all")

    def test_cli_parses_stop_command(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("dummy\n", encoding="utf-8")
            args = module.parse_args(
                [
                    "--api-client",
                    str(api_client),
                    "stop",
                    "--investigation-id",
                    "ir9003",
                    "--hunt-id",
                    "H.stop",
                ],
                finalize=False,
            )

        self.assertEqual(args.command, "stop")
        self.assertEqual(args.hunt_id, "H.stop")
        self.assertEqual(args.os, "")

    def test_stop_hunt_uses_native_stop_update(self):
        module = load_run_velociraptor_hunting_module()
        api = mock.MagicMock()

        module.stop_hunt(api, "H.stop")

        api.query.assert_called_once_with(
            "SELECT hunt_update(hunt_id=HuntId, stop=TRUE) AS Result FROM scope()",
            {"HuntId": "H.stop"},
            max_wait=30,
            max_row=10,
        )

    def test_command_stop_requests_and_verifies_stop(self):
        module = load_run_velociraptor_hunting_module()
        api_context = mock.MagicMock()
        api_context.__enter__.return_value = object()
        request = self.make_request(module)
        args = module.argparse.Namespace(
            investigation_id="ir9003",
            hunt_id="H.stop",
            api_client_path=Path("/tmp/api.yaml"),
            org_id="root",
        )
        initial_row = {
            "hunt_id": "H.stop",
            "hunt_description": "stop test",
            "state": "RUNNING",
            "artifacts": ["Generic.Client.Info"],
        }
        stopped_status = {
            "hunt_id": "H.stop",
            "hunt_description": "stop test",
            "state": "STOPPED",
            "is_open": False,
            "is_paused": False,
            "target_scope_mode": "unscoped",
            "host_include_labels": [],
            "host_exclude_labels": [],
        }

        with (
            mock.patch.object(module.collection, "VeloApiClient", return_value=api_context),
            mock.patch.object(module, "find_saved_state_by_hunt_id", return_value=None),
            mock.patch.object(module, "query_single_hunt", return_value=initial_row),
            mock.patch.object(module, "resolve_request_from_hunt_row", return_value=request),
            mock.patch.object(module, "load_baseline_snapshot", return_value=None),
            mock.patch.object(module, "stop_hunt") as stop_hunt,
            mock.patch.object(module, "refresh_hunt_status", return_value=stopped_status),
            mock.patch.object(module, "baseline_and_readiness_payload", return_value={}),
        ):
            result = module.command_stop(args)

        stop_hunt.assert_called_once_with(api_context.__enter__.return_value, "H.stop")
        self.assertEqual(result["action"], "stopped_hunt")
        self.assertTrue(result["stop_requested"])
        self.assertTrue(result["stop_verified"])
        self.assertEqual(result["state"], "STOPPED")
        self.assertFalse(result["saved_state_updated"])

    def make_ensure_args(self, module):
        return module.argparse.Namespace(
            profile=None,
            artifact=["Generic.Client.Info"],
            env=[],
            date_after=None,
            date_before=None,
            os="linux",
            include_label=["IR9003"],
            label=[],
            host_label=[],
            exclude_label=[],
            exclude_host_label=[],
            hunt_tag=[],
            hunt_label=[],
            activate_paused=False,
            force_run=True,
            start_paused=False,
            investigation_id="ir9003",
            group="",
            question="",
            verbose_output=False,
            api_client_path=Path("/tmp/api.yaml"),
            org_id="root",
        )

    def test_scope_mismatch_fails_before_baseline_or_start(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_request(module)
        api_context = mock.MagicMock()
        api_context.__enter__.return_value = object()
        invalid_status = {
            "hunt_id": "H.scope",
            "hunt_description": "scope test",
            "state": "PAUSED",
            "start_request": {
                "os": "linux",
                "include_labels": ["IR9003"],
                "exclude_labels": [],
            },
        }

        with (
            mock.patch.object(module.collection, "VeloApiClient", return_value=api_context),
            mock.patch.object(module, "build_request_from_args", return_value=request),
            mock.patch.object(
                module,
                "create_hunt",
                return_value={"hunt_id": "H.scope", "created_paused_for_validation": True},
            ),
            mock.patch.object(module, "find_matching_hunts", return_value=[]),
            mock.patch.object(module, "refresh_hunt_status", return_value=invalid_status),
            mock.patch.object(module, "prepare_baseline_snapshot") as prepare_baseline,
            mock.patch.object(module, "start_hunt") as start_hunt,
        ):
            with self.assertRaisesRegex(RuntimeError, "server target scope differs"):
                module.command_ensure(self.make_ensure_args(module))

        prepare_baseline.assert_not_called()
        start_hunt.assert_not_called()

    def test_baseline_is_captured_before_new_hunt_activation(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_request(module)
        api_context = mock.MagicMock()
        api_context.__enter__.return_value = object()
        events = []
        paused_status = {
            "hunt_id": "H.scope",
            "hunt_description": "scope test",
            "state": "PAUSED",
            "start_request": {
                "include_labels": ["IR9003"],
                "exclude_labels": [],
            },
        }
        running_status = {
            **paused_status,
            "state": "RUNNING",
        }

        def capture_baseline(*args, **kwargs):
            events.append("baseline")
            return {"targets": [], "target_count": 0}

        def start(*args, **kwargs):
            events.append("start")

        with (
            mock.patch.object(module.collection, "VeloApiClient", return_value=api_context),
            mock.patch.object(module, "build_request_from_args", return_value=request),
            mock.patch.object(
                module,
                "create_hunt",
                return_value={"hunt_id": "H.scope", "created_paused_for_validation": True},
            ),
            mock.patch.object(module, "find_matching_hunts", return_value=[]),
            mock.patch.object(
                module,
                "refresh_hunt_status",
                side_effect=[paused_status, running_status, running_status],
            ),
            mock.patch.object(module, "prepare_baseline_snapshot", side_effect=capture_baseline),
            mock.patch.object(module, "start_hunt", side_effect=start),
            mock.patch.object(module, "baseline_and_readiness_payload", return_value={}),
            mock.patch.object(module, "persist_state", side_effect=lambda *args, **kwargs: args[4]),
        ):
            result = module.command_ensure(self.make_ensure_args(module))

        self.assertEqual(events, ["baseline", "start"])
        self.assertEqual(result["action"], "forced_new_hunt")
        self.assertTrue(result["force_run_requested"])


class RunVelociraptorHuntingSearchStateRegressionTest(unittest.TestCase):
    def make_hunt_request(self, module, artifact, env=None, timeout_seconds=None):
        return module.collection.CollectionRequest(
            target_collection_type="hunt",
            requested_groups=[],
            requested_artifacts=[artifact],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label=artifact,
                    artifact=artifact,
                    env=env or {},
                    timeout_seconds=timeout_seconds,
                )
            ],
        )

    def test_discovery_accepts_requested_artifact_subset_of_multi_artifact_hunt(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(
            module,
            "Artifact.Target",
            {"Needle": "value"},
            timeout_seconds=600,
        )
        rows = [
            {
                "hunt_id": "H.multi",
                "hunt_description": "legacy multi-artifact hunt",
                "create_time": 10,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [
                        {
                            "artifact": "Artifact.Other",
                            "parameters": {"env": [{"key": "Other", "value": "1"}]},
                        },
                        {
                            "artifact": "Artifact.Target",
                            "parameters": {"env": [{"key": "Needle", "value": "value"}]},
                            "timeout": 600,
                        },
                    ],
                },
            }
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "case-test",
                "targeted-artifact",
                request,
                "windows",
                [],
                [],
                "DR-new",
            )

        self.assertEqual([item["hunt_id"] for item in matches], ["H.multi"])
        self.assertEqual(matches[0]["candidate_classification"], "generic_template")
        self.assertTrue(matches[0]["artifact_subset_match"])
        self.assertEqual(
            matches[0]["source_artifact_set"],
            ["Artifact.Other", "Artifact.Target"],
        )
        self.assertFalse(matches[0]["reuse_allowed"])

    def test_exact_case_multi_artifact_hunt_reuses_with_case_insensitive_label_and_artifact(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "IG.Windows.Sysinternals.Autoruns")
        rows = [
            {
                "hunt_id": "H.EXISTING",
                "hunt_description": "ir9005 - Autoruns/Persistence",
                "state": "FINISHED",
                "create_time": 10,
                "start_request": {
                    "include_labels": ["ir9005"],
                    "exclude_labels": [],
                    "specs": [
                        {"artifact": "ig.windows.sysinternals.autoruns"},
                        {"artifact": "Windows.Packs.Persistence"},
                        {"artifact": "IG.Windows.Persistence.Outlook"},
                    ],
                },
            }
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "IR9005",
                "IG.Windows.Sysinternals.Autoruns",
                request,
                "windows",
                ["IR9005"],
                [],
            )

        self.assertEqual([item["hunt_id"] for item in matches], ["H.EXISTING"])
        self.assertEqual(matches[0]["candidate_classification"], "exact_case")
        self.assertTrue(matches[0]["scope_compatible"])
        self.assertTrue(matches[0]["reuse_allowed"])
        self.assertEqual(matches[0]["hunt_spec_count"], 3)

    def test_generic_template_ranks_before_different_ir_and_requires_authorization(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target")
        rows = [
            {
                "hunt_id": "H.other-ir",
                "hunt_description": "IR1000 pre-run",
                "create_time": 20,
                "start_request": {
                    "include_labels": ["ir1000"],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
            {
                "hunt_id": "H.generic",
                "hunt_description": "generic persistence pre-run template",
                "create_time": 10,
                "start_request": {
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "IR9005",
                "Artifact.Target",
                request,
                "windows",
                ["IR9005"],
                [],
            )
        decision = module.hunt_selection_decision(matches)

        self.assertEqual(
            [item["candidate_classification"] for item in matches],
            ["generic_template", "different_ir_template"],
        )
        self.assertEqual(decision["selection_decision"], "template_authorization_required")
        self.assertEqual(decision["recommended_template"]["hunt_id"], "H.generic")
        self.assertIn("source_parameters", decision["recommended_template"])

    def test_ensure_returns_template_recommendation_without_mutation(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target")
        template = {
            "hunt_id": "H.other-ir",
            "hunt_description": "IR1000 template",
            "state": "FINISHED",
            "reuse_allowed": False,
            "reuse_classification": "terminal_success",
            "candidate_classification": "different_ir_template",
            "selection_compatible": True,
            "template_only": True,
            "source_artifact_set": ["Artifact.Target", "Artifact.Other"],
            "source_parameters": [{"artifact": "Artifact.Target", "env": {}}],
            "hunt_spec_count": 2,
        }
        args = module.argparse.Namespace(
            profile=None,
            artifact=["Artifact.Target"],
            env=[],
            date_after=None,
            date_before=None,
            os="windows",
            include_label=["IR9005"],
            label=[],
            host_label=[],
            exclude_label=[],
            exclude_host_label=[],
            hunt_tag=[],
            hunt_label=[],
            activate_paused=False,
            authorize_template_create=False,
            force_run=False,
            start_paused=False,
            investigation_id="IR9005",
            group="",
            question="",
            verbose_output=False,
            api_client_path=Path("/tmp/api.yaml"),
            org_id="root",
        )
        api_context = mock.MagicMock()
        api_context.__enter__.return_value = mock.sentinel.api

        with (
            mock.patch.object(module.collection, "VeloApiClient", return_value=api_context),
            mock.patch.object(module, "build_request_from_args", return_value=request),
            mock.patch.object(module, "find_matching_hunts", return_value=[template]),
            mock.patch.object(module, "create_hunt") as create_mock,
        ):
            result = module.command_ensure(args)

        self.assertEqual(result["action"], "template_authorization_required")
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["recommended_template"]["hunt_id"], "H.other-ir")
        self.assertIn("--authorize-template-create", result["human_summary"])
        create_mock.assert_not_called()

    def test_matching_hunt_rejects_same_artifact_with_different_parameters(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target", {"Needle": "wanted"})
        rows = [
            {
                "hunt_id": "H.wrong-params",
                "hunt_description": "previous hunt",
                "create_time": 10,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [
                        {
                            "artifact": "Artifact.Target",
                            "parameters": {"env": [{"key": "Needle", "value": "different"}]},
                        }
                    ],
                },
            }
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "case-test",
                "targeted-artifact",
                request,
                "windows",
                [],
                [],
            )

        self.assertEqual([item["hunt_id"] for item in matches], ["H.wrong-params"])
        self.assertEqual(matches[0]["candidate_classification"], "unrelated")
        self.assertFalse(matches[0]["parameters_compatible"])

    def test_matching_hunt_prefers_requested_group_but_allows_other_groups(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target")
        rows = [
            {
                "hunt_id": "H.newer-other-group",
                "hunt_description": "dfir-group=DR-other",
                "create_time": 20,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
            {
                "hunt_id": "H.requested-group",
                "hunt_description": "dfir-group=DR-requested",
                "create_time": 10,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "case-test",
                "targeted-artifact",
                request,
                "windows",
                [],
                [],
                "DR-requested",
            )

        self.assertEqual(
            [item["hunt_id"] for item in matches],
            ["H.requested-group", "H.newer-other-group"],
        )

    def test_matching_hunt_ranks_terminal_success_before_in_flight_and_failed(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target")
        rows = [
            {
                "hunt_id": "H.failed",
                "hunt_description": "case-test persistence",
                "state": "ERROR",
                "create_time": 30,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
            {
                "hunt_id": "H.running",
                "hunt_description": "CASE-TEST persistence",
                "state": "RUNNING",
                "create_time": 20,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
            {
                "hunt_id": "H.finished",
                "hunt_description": "case-test persistence",
                "state": "FINISHED",
                "create_time": 10,
                "start_request": {
                    "os": "windows",
                    "include_labels": [],
                    "exclude_labels": [],
                    "specs": [{"artifact": "Artifact.Target"}],
                },
            },
        ]

        with mock.patch.object(module, "query_hunts", return_value=rows):
            matches = module.find_matching_hunts(
                object(),
                "case-test",
                "targeted-artifact",
                request,
                "windows",
                [],
                [],
            )

        self.assertEqual(
            [item["hunt_id"] for item in matches],
            ["H.finished", "H.running", "H.failed"],
        )
        self.assertEqual(matches[0]["reuse_classification"], "terminal_success")
        self.assertEqual(matches[1]["reuse_classification"], "in_flight")
        self.assertFalse(matches[2]["reuse_allowed"])

    def test_ensure_requires_force_when_only_failed_exact_hunt_exists(self):
        module = load_run_velociraptor_hunting_module()
        request = self.make_hunt_request(module, "Artifact.Target")
        args = module.argparse.Namespace(
            profile=None,
            artifact=["Artifact.Target"],
            env=[],
            date_after=None,
            date_before=None,
            os="windows",
            include_label=[],
            label=[],
            host_label=[],
            exclude_label=[],
            exclude_host_label=[],
            hunt_tag=[],
            hunt_label=[],
            activate_paused=False,
            force_run=False,
            start_paused=False,
            investigation_id="case-test",
            group="",
            question="",
            verbose_output=False,
            api_client_path=Path("/tmp/api.yaml"),
            org_id="root",
        )
        api_context = mock.MagicMock()
        api_context.__enter__.return_value = mock.sentinel.api
        failed_match = {
            "hunt_id": "H.failed",
            "state": "ERROR",
            "reuse_allowed": False,
            "reuse_classification": "failed_or_cancelled",
            "candidate_classification": "exact_case",
            "selection_compatible": True,
        }

        with (
            mock.patch.object(
                module.collection,
                "VeloApiClient",
                return_value=api_context,
            ),
            mock.patch.object(
                module,
                "build_request_from_args",
                return_value=request,
            ),
            mock.patch.object(
                module,
                "find_matching_hunts",
                return_value=[failed_match],
            ),
            mock.patch.object(module, "create_hunt") as create_mock,
        ):
            with self.assertRaisesRegex(RuntimeError, "--force-run"):
                module.command_ensure(args)

        create_mock.assert_not_called()

    def test_high_volume_evtx_hunt_requires_artifact_filter(self):
        module = load_run_velociraptor_hunting_module()
        args = module.argparse.Namespace(
            profile=None,
            artifact=["Windows.EventLogs.EvtxHunter"],
            env=[],
            date_after=None,
            date_before=None,
        )

        with self.assertRaisesRegex(RuntimeError, "Refusing broad high-volume hunt"):
            module.build_request_from_args(args)

    def test_high_volume_evtx_hunt_accepts_narrow_glob(self):
        module = load_run_velociraptor_hunting_module()
        args = module.argparse.Namespace(
            profile=None,
            artifact=["Windows.EventLogs.EvtxHunter"],
            env=[r"EvtxGlob=%SystemRoot%\\System32\\Winevt\\Logs\\*security*.evtx"],
            date_after=None,
            date_before=None,
        )

        request = module.build_request_from_args(args)

        self.assertEqual(len(request.expected_specs), 1)
        self.assertIn("EvtxGlob", request.expected_specs[0].env)

    def test_review_sample_vql_defaults_to_1000_limit_and_field_profile(self):
        module = load_run_velociraptor_hunting_module()
        self.assertEqual(module.HUNT_REVIEW_DEFAULT_LIMIT, 1000)
        self.assertEqual(module.HUNT_REVIEW_LIMIT_PRESETS["explore"], 1000)
        vql = module.build_review_sample_vql(
            source=None,
            field_profile="minimal",
            fields=[],
            where="ClientId = 'C.123'",
            limit=module.HUNT_REVIEW_DEFAULT_LIMIT,
        )
        self.assertIn("SELECT ClientId, Fqdn, Hostname, Timestamp", vql)
        self.assertIn("FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)", vql)
        self.assertIn("WHERE ClientId = 'C.123'", vql)
        self.assertIn("LIMIT 1000", vql)

    def test_effective_review_limit_uses_depth_or_explicit_limit(self):
        module = load_run_velociraptor_hunting_module()
        self.assertEqual(
            module.effective_review_limit(module.argparse.Namespace(limit=None, review_depth="broad")),
            10000,
        )
        self.assertEqual(
            module.effective_review_limit(module.argparse.Namespace(limit=None, review_depth="deep")),
            100000,
        )
        self.assertEqual(
            module.effective_review_limit(module.argparse.Namespace(limit=None, review_depth="max")),
            1000000,
        )
        self.assertEqual(
            module.effective_review_limit(module.argparse.Namespace(limit=100000, review_depth="explore")),
            100000,
        )

    def test_review_hunt_results_uses_limit_as_vql_cap_and_max_row_as_batch_size(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(
                    {
                        "vql": vql,
                        "env": env,
                        "max_wait": max_wait,
                        "max_row": max_row,
                        "timeout": timeout,
                    }
                )
                return [{"ClientId": "C.123", "EventID": 4624}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )

            manifest = module.review_hunt_results(
                api,
                "case-review-limit",
                "H.1234",
                request,
                target_os="windows",
                operation="sample",
                field_profile="minimal",
                fields=["EventID"],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000000,
                output_format="csv",
                inventory_mode="",
                max_row=17,
                timeout=90,
            )

        self.assertEqual(manifest["limit"], 1000000)
        self.assertEqual(len(api.calls), 1)
        self.assertIn("LIMIT 1000000", api.calls[0]["vql"])
        self.assertEqual(api.calls[0]["max_row"], 17)
        self.assertEqual(api.calls[0]["timeout"], 90)

    def test_review_inventory_quick_skips_exact_count_and_caps_host_stack(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"ClientId": "C.123", "Count": 5}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-inventory-quick",
                "H.1234",
                request,
                target_os="windows",
                operation="inventory",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="quick",
                max_row=1000,
                timeout=0,
            )

        self.assertEqual(len(api.calls), 1)
        self.assertNotIn("count() AS RowCount", api.calls[0])
        self.assertIn("ClientId AS Group1", api.calls[0])
        self.assertIn("Fqdn AS Group2", api.calls[0])
        self.assertIn("Hostname AS Group3", api.calls[0])
        self.assertIn("GROUP BY Group1, Group2, Group3", api.calls[0])
        self.assertIn("LIMIT 1000", api.calls[0])
        self.assertEqual(manifest["inventory_mode"], "quick")
        self.assertTrue(manifest["exact_count_skipped"])
        self.assertEqual(manifest["skipped_review_steps"][0]["operation"], "inventory-count")
        self.assertEqual(manifest["inventory_group_by"], [])

    def test_review_inventory_quick_allows_custom_inventory_grouping(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"Group1": "Security", "Group2": "4624", "Count": 5}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-inventory-channel",
                "H.1234",
                request,
                target_os="windows",
                operation="inventory",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=["Channel", "EventID"],
                where="Channel =~ 'Security|PowerShell'",
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="quick",
                max_row=1000,
                timeout=0,
            )

        self.assertEqual(len(api.calls), 1)
        self.assertIn("Channel AS Group1", api.calls[0])
        self.assertIn("EventID AS Group2", api.calls[0])
        self.assertIn("WHERE Channel =~ 'Security|PowerShell'", api.calls[0])
        self.assertIn("GROUP BY Group1, Group2", api.calls[0])
        self.assertEqual(manifest["inventory_group_by"], ["Channel", "EventID"])
        self.assertIn("inventory-stack", manifest["reviewed_files"][0]["output_file"])

    def test_review_inventory_exact_runs_only_global_count(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"RowCount": 42}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-inventory-exact",
                "H.1234",
                request,
                target_os="windows",
                operation="inventory",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="exact",
                max_row=1000,
                timeout=0,
            )

        self.assertEqual(len(api.calls), 1)
        self.assertIn("count() AS RowCount", api.calls[0])
        self.assertNotIn("GROUP BY ClientId, Fqdn, Hostname", api.calls[0])
        self.assertEqual(manifest["inventory_mode"], "exact")
        self.assertFalse(manifest["exact_count_skipped"])
        self.assertEqual(manifest["skipped_review_steps"][0]["operation"], "inventory-by-host")

    def test_review_inventory_both_runs_count_and_host_stack(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"RowCount": 42}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-inventory-both",
                "H.1234",
                request,
                target_os="windows",
                operation="inventory",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="both",
                max_row=1000,
                timeout=0,
            )

        self.assertEqual(len(api.calls), 2)
        self.assertIn("count() AS RowCount", api.calls[0])
        self.assertIn("GROUP BY Group1, Group2, Group3", api.calls[1])
        self.assertEqual(manifest["inventory_mode"], "both")
        self.assertFalse(manifest["exact_count_skipped"])
        self.assertEqual(manifest["skipped_review_steps"], [])

    def test_review_request_signature_changes_with_limit(self):
        module = load_run_velociraptor_hunting_module()
        first = module.review_request_signature(
            operation="sample",
            field_profile="minimal",
            fields=["EventID"],
            group_by=[],
            inventory_group_by=[],
            where="EventID = 4624",
            source=None,
            limit=1000,
            output_format="jsonl",
        )
        second = module.review_request_signature(
            operation="sample",
            field_profile="minimal",
            fields=["EventID"],
            group_by=[],
            inventory_group_by=[],
            where="EventID = 4624",
            source=None,
            limit=10000,
            output_format="jsonl",
        )
        self.assertRegex(first, r"^[0-9a-f]{12}$")
        self.assertNotEqual(first, second)

    def test_review_stack_vql_uses_grouping_and_limit(self):
        module = load_run_velociraptor_hunting_module()
        vql = module.build_review_stack_vql(
            source="Results",
            group_by=["Detection", "Path"],
            where=None,
            limit=250,
        )
        self.assertIn("FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName, source=Source)", vql)
        self.assertIn("Detection AS Group1", vql)
        self.assertIn("Path AS Group2", vql)
        self.assertIn("GROUP BY Group1, Group2", vql)
        self.assertIn("ORDER BY Count DESC", vql)
        self.assertIn("LIMIT 250", vql)

    def test_review_stack_uses_artifact_profile_when_group_by_is_omitted(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"Group1": "PowerShell test", "Count": 3}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["DetectRaptor.Windows.Detection.Evtx"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="DetectRaptor.Windows.Detection.Evtx",
                        artifact="DetectRaptor.Windows.Detection.Evtx",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-profile-stack",
                "H.1234",
                request,
                target_os="windows",
                operation="stack",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="quick",
                max_row=1000,
                timeout=0,
            )

        self.assertEqual(len(api.calls), 1)
        self.assertIn("Detection.Name AS Group1", api.calls[0])
        self.assertEqual(
            manifest["effective_group_by"],
            {"DetectRaptor.Windows.Detection.Evtx": ["Detection.Name"]},
        )
        self.assertEqual(
            manifest["effective_stack_ids"],
            {"DetectRaptor.Windows.Detection.Evtx": "detection"},
        )
        self.assertEqual(len(manifest["artifact_profile_hashes"]), 1)
        self.assertTrue(manifest["artifact_policy"]["sources"])

    def test_review_stack_selects_named_windows_services_view(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env, *, max_wait, max_row, timeout):
                self.calls.append(vql)
                return [{"Group1": "C:\\Windows\\System32\\example.dll", "Count": 2}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.System.Services"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.System.Services",
                        artifact="Windows.System.Services",
                        env={},
                    )
                ],
            )
            manifest = module.review_hunt_results(
                api,
                "case-services-stack",
                "H.5678",
                request,
                target_os="windows",
                operation="stack",
                field_profile="stacking",
                fields=[],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                output_format="csv",
                inventory_mode="quick",
                max_row=1000,
                timeout=0,
                stack_id="service_dll",
            )

        self.assertEqual(len(api.calls), 1)
        self.assertIn("ServiceDll AS Group1", api.calls[0])
        self.assertEqual(
            manifest["effective_stack_ids"],
            {"Windows.System.Services": "service_dll"},
        )

    def test_review_stack_fails_when_named_view_requires_uncollected_fields(self):
        module = load_run_velociraptor_hunting_module()
        request = module.collection.CollectionRequest(
            target_collection_type="hunt",
            requested_groups=[],
            requested_artifacts=["Windows.System.Services"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Windows.System.Services",
                    artifact="Windows.System.Services",
                    env={},
                )
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            with self.assertRaisesRegex(RuntimeError, "requires collection parameters Calculate_hashes=Y"):
                module.review_hunt_results(
                    object(),
                    "case-services-hash-stack",
                    "H.6789",
                    request,
                    target_os="windows",
                    operation="stack",
                    field_profile="stacking",
                    fields=[],
                    group_by=[],
                    inventory_group_by=[],
                    where=None,
                    source=None,
                    limit=1000,
                    output_format="csv",
                    inventory_mode="quick",
                    max_row=1000,
                    timeout=0,
                    stack_id="executable_hash",
                )

    def test_review_stack_fails_closed_when_profile_has_no_safe_server_dimensions(self):
        module = load_run_velociraptor_hunting_module()
        request = module.collection.CollectionRequest(
            target_collection_type="hunt",
            requested_groups=[],
            requested_artifacts=["Windows.EventLogs.EvtxHunter"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Windows.EventLogs.EvtxHunter",
                    artifact="Windows.EventLogs.EvtxHunter",
                    env={},
                )
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            with self.assertRaisesRegex(RuntimeError, "does not define a safe server stack"):
                module.review_hunt_results(
                    object(),
                    "case-profile-stack",
                    "H.1234",
                    request,
                    target_os="windows",
                    operation="stack",
                    field_profile="stacking",
                    fields=[],
                    group_by=[],
                    inventory_group_by=[],
                    where=None,
                    source=None,
                    limit=1000,
                    output_format="csv",
                    inventory_mode="quick",
                    max_row=1000,
                    timeout=0,
                )

    def test_review_fields_allow_explicit_projection(self):
        module = load_run_velociraptor_hunting_module()
        self.assertEqual(
            module.review_fields_for_profile("stacking", ["Path", "Hash", "Path"]),
            ["Path", "Hash"],
        )
        self.assertEqual(module.review_fields_for_profile("full", []), ["*"])

    def test_export_hunt_retries_resource_exhausted_with_smaller_batches(self):
        module = load_run_velociraptor_hunting_module()

        class ResourceExhaustedError(Exception):
            def code(self):
                return module.collection.grpc.StatusCode.RESOURCE_EXHAUSTED

        class FakeApi:
            def __init__(self):
                self.max_rows = []

            def query(self, vql, env, *, max_wait, max_row):
                self.max_rows.append(max_row)
                if max_row == 10000:
                    raise ResourceExhaustedError("larger than max")
                return [{"ClientId": "C.123", "Message": "ok"}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            api = FakeApi()
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.export_hunt(api, "case-export-retry", "H.1234", request, target_os="windows")

            exported = manifest["exported_files"][0]
            self.assertEqual(api.max_rows, [10000, 5000])
            self.assertEqual(exported["status"], "ok")
            self.assertEqual(exported["query_max_row"], 5000)
            self.assertEqual(exported["row_count"], 1)
            self.assertEqual(exported["query_attempts"][0]["status"], "resource_exhausted")
            self.assertEqual(exported["query_attempts"][1]["status"], "ok")
            self.assertTrue(Path(exported["output_file"]).exists())
            self.assertEqual(
                manifest["persistence_authorization"]["classification"],
                "immutable_evidence_export",
            )
            self.assertTrue(
                manifest["persistence_authorization"]["explicit_export"]
            )

    def test_export_hunt_writes_error_manifest_when_resource_exhausted_persists(self):
        module = load_run_velociraptor_hunting_module()

        class ResourceExhaustedError(Exception):
            def code(self):
                return module.collection.grpc.StatusCode.RESOURCE_EXHAUSTED

        class FakeApi:
            def query(self, vql, env, *, max_wait, max_row):
                raise ResourceExhaustedError(f"max_row={max_row} still too large")

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            manifest = module.export_hunt(FakeApi(), "case-export-error", "H.1234", request, target_os="windows")

            exported = manifest["exported_files"][0]
            self.assertEqual(exported["status"], "resource_exhausted")
            self.assertEqual(exported["row_count"], 0)
            self.assertIn("create_hunt_download", exported["fallback_recommendation"])
            error_payload = json.loads(Path(exported["output_file"]).read_text(encoding="utf-8"))
            self.assertEqual(error_payload["query_status"], "resource_exhausted")
            self.assertEqual(len(error_payload["query_attempts"]), len(module.HUNT_RESULTS_RETRY_MAX_ROWS))

    def test_export_hunt_expands_multi_source_artifact(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def __init__(self):
                self.artifacts = []

            def query(self, vql, env, *, max_wait, max_row):
                artifact = env["ArtifactName"]
                self.artifacts.append(artifact)
                return [{"ArtifactSource": artifact}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Generic.Client.Info"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Generic.Client.Info",
                        artifact="Generic.Client.Info",
                        env={},
                    )
                ],
            )
            sources = [
                "Generic.Client.Info/BasicInformation",
                "Generic.Client.Info/DetailedInfo",
                "Generic.Client.Info/LinuxInfo",
            ]
            api = FakeApi()
            manifest = module.export_hunt(
                api,
                "case-multi-source",
                "H.1234",
                request,
                target_os="linux",
                artifact_sources=sources,
            )

            self.assertEqual(api.artifacts, sources)
            self.assertEqual(len(manifest["exported_files"]), 3)
            self.assertEqual(
                [item["artifact_source"] for item in manifest["exported_files"]],
                sources,
            )
            self.assertEqual(
                len({item["output_file"] for item in manifest["exported_files"]}),
                3,
            )
            self.assertTrue(
                all(Path(item["output_file"]).exists() for item in manifest["exported_files"])
            )

    def test_download_hunt_expands_multi_source_artifact(self):
        module = load_run_velociraptor_hunting_module()

        class FakeApi:
            def query(self, vql, env, *, max_wait, max_row):
                return [{"ArtifactSource": env["ArtifactName"]}]

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Generic.Client.Info"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Generic.Client.Info",
                        artifact="Generic.Client.Info",
                        env={},
                    )
                ],
            )
            sources = [
                "Generic.Client.Info/BasicInformation",
                "Generic.Client.Info/LinuxInfo",
            ]
            manifest = module.download_hunt_results(
                FakeApi(),
                "case-multi-source",
                "H.1234",
                request,
                target_os="linux",
                artifact_sources=sources,
            )

            self.assertEqual(len(manifest["downloaded_files"]), 2)
            self.assertEqual(
                [item["artifact_source"] for item in manifest["downloaded_files"]],
                sources,
            )
            self.assertTrue(
                all(Path(item["output_file"]).exists() for item in manifest["downloaded_files"])
            )
            self.assertEqual(
                manifest["persistence_authorization"]["classification"],
                "interoperability_export",
            )
            self.assertTrue(
                manifest["persistence_authorization"]["explicit_export"]
            )

    def test_slim_ensure_output_removes_heavy_hunt_request_fields(self):
        module = load_run_velociraptor_hunting_module()
        state = {
            "action": "created_new_hunt",
            "hunt_id": "H.TEST",
            "hunt_description": "unit test hunt",
            "state_file": "/tmp/state.json",
            "request_signature": "abc123",
            "target_os": "windows",
            "target_name": "detectraptor",
            "start_request": {"compiled_collector_args": ["large"]},
            "Request": {"start_request": {"compiled_collector_args": ["large"]}},
            "matching_hunts": [
                {
                    "hunt_id": "H.OLD",
                    "start_request": {"compiled_collector_args": ["old"]},
                    "Request": {"start_request": {"compiled_collector_args": ["old"]}},
                }
            ],
            "baseline_scope": {"expected_clients": 4},
        }

        slim = module.slim_ensure_output(state)

        self.assertEqual(slim["hunt_id"], "H.TEST")
        self.assertEqual(slim["state_file"], "/tmp/state.json")
        self.assertEqual(slim["full_state_file"], "/tmp/state.json")
        self.assertEqual(slim["output_mode"], "slim")
        self.assertEqual(slim["suppressed_output_fields"], ["Request", "start_request"])
        self.assertNotIn("start_request", slim)
        self.assertNotIn("Request", slim)
        self.assertNotIn("start_request", slim["matching_hunts"][0])
        self.assertNotIn("Request", slim["matching_hunts"][0])
        self.assertEqual(slim["baseline_scope"], {"expected_clients": 4})

    def test_review_results_updates_saved_state_with_latest_review_manifest(self):
        module = load_run_velociraptor_hunting_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            request = module.collection.CollectionRequest(
                target_collection_type="hunt",
                requested_groups=[],
                requested_artifacts=["Windows.EventLogs.EvtxHunter"],
                expected_specs=[
                    module.collection.ArtifactSpec(
                        label="Windows.EventLogs.EvtxHunter",
                        artifact="Windows.EventLogs.EvtxHunter",
                        env={},
                    )
                ],
            )
            saved_state = module.persist_state(
                "case-review-state",
                "evtx-review",
                request,
                {
                    "hunt_id": "H.REVIEW",
                    "hunt_description": "Review state test",
                    "target_os": "windows",
                },
                {
                    "action": "created_new_hunt",
                    "target_os": "windows",
                    "target_name": "evtx-review",
                },
            )
            manifest = {
                "manifest_file": str(Path(temp_dir) / "review.json"),
                "reviewed_files": [
                    {
                        "artifact": "Windows.EventLogs.EvtxHunter",
                        "operation": "sample",
                        "output_file": str(Path(temp_dir) / "sample.csv"),
                        "row_count": 0,
                        "status": "ok",
                    }
                ],
            }
            args = module.argparse.Namespace(
                investigation_id="case-review-state",
                hunt_id="H.REVIEW",
                profile=None,
                artifact=[],
                api_client_path=Path(temp_dir) / "api_client.yaml",
                org_id="root",
                os="windows",
                target="windows",
                review_operation="sample",
                field_profile="minimal",
                field=["ClientId"],
                group_by=[],
                inventory_group_by=[],
                where=None,
                source=None,
                limit=1000,
                review_depth="explore",
                format="csv",
                inventory_mode="quick",
                max_row=1000,
                timeout=0,
            )

            fake_api_context = mock.MagicMock()
            fake_api_context.__enter__.return_value = mock.sentinel.api
            fake_api_context.__exit__.return_value = False

            with (
                mock.patch.object(module.collection, "VeloApiClient", return_value=fake_api_context),
                mock.patch.object(
                    module,
                    "resolve_saved_or_explicit_hunt",
                    return_value={
                        "saved_state": saved_state,
                        "hunt_id": "H.REVIEW",
                        "request": request,
                        "profile": "evtx-review",
                        "hunt_row": {
                            "hunt_id": "H.REVIEW",
                            "hunt_description": "Review state test",
                            "target_os": "windows",
                        },
                    },
                ),
                mock.patch.object(module, "raise_for_hunt_validation_errors"),
                mock.patch.object(module, "review_hunt_results", return_value=manifest),
            ):
                result = module.command_review_results(args)

            refreshed_state = json.loads(Path(saved_state["state_file"]).read_text(encoding="utf-8"))
            self.assertTrue(result["reviewed_after_action"])
            self.assertTrue(result["saved_state_updated"])
            self.assertEqual(refreshed_state["latest_review_manifest_file"], manifest["manifest_file"])
            self.assertEqual(refreshed_state["latest_reviewed_files"], manifest["reviewed_files"])

    def test_search_refresh_preserves_latest_manifest_state_and_resets_current_action_flags(self):
        module = load_run_velociraptor_hunting_module()
        investigation_id = "case-phase3-regression"
        profile = "lateral-movement"
        hunt_id = "H.1234"
        preserved_saved_at = "2026-05-01T10:11:12Z"
        refreshed_at = "2026-06-02T12:34:56Z"

        with tempfile.TemporaryDirectory() as temp_dir:
            module.CASE_ROOT = Path(temp_dir)
            request = module.build_request_for_profile(profile)
            initial_state = module.persist_state(
                investigation_id,
                profile,
                request,
                {
                    "hunt_id": hunt_id,
                    "hunt_description": "Saved hunt for regression test",
                    "target_os": "windows",
                },
                {
                    "action": "downloaded_hunt_results",
                    "target_os": "windows",
                    "target_name": profile,
                    "exported_after_action": True,
                    "export_skipped_reason": "",
                    "export_manifest_file": "exports/current-export.json",
                    "exported_files": ["exports/current.csv"],
                    "downloaded_after_action": True,
                    "download_manifest_file": "downloads/current-download.json",
                    "downloaded_files": ["downloads/current.bin"],
                    "latest_export_manifest_file": "exports/latest-export.json",
                    "latest_exported_files": ["exports/previous-1.csv", "exports/previous-2.csv"],
                    "latest_download_manifest_file": "downloads/latest-download.json",
                    "latest_downloaded_files": ["downloads/previous-1.bin"],
                },
                existing_state={"saved_at": preserved_saved_at},
            )

            args = module.argparse.Namespace(
                hunt_id=None,
                profile=profile,
                artifact=[],
                investigation_id=investigation_id,
                api_client_path=Path(temp_dir) / "api_client.yaml",
                org_id="root",
                os="windows",
                pattern=["needle"],
                exact_path=[],
                case_sensitive=False,
                limit=50,
                env=[],
                date_after=None,
                date_before=None,
                label=[],
                host_label=[],
                include_label=[],
                exclude_label=[],
                exclude_host_label=[],
            )

            fake_api_context = mock.MagicMock()
            fake_api_context.__enter__.return_value = object()
            fake_api_context.__exit__.return_value = False

            search_payload = {
                "hunt_id": hunt_id,
                "searched_artifacts": [request.expected_specs[0].label],
                "pattern": ["needle"],
                "exact_path": [],
                "case_sensitive": False,
                "match_count": 1,
                "hosts_with_hits": ["host01.example"],
                "matches": [
                    {
                        "artifact": request.expected_specs[0].label,
                        "artifact_name": request.expected_specs[0].artifact,
                        "host": "host01.example",
                        "client_id": "C.0001",
                        "matched_literals": ["needle"],
                        "matched_exact_paths": [],
                        "row": {"Message": "needle"},
                    }
                ],
            }

            with (
                mock.patch.object(module.collection, "VeloApiClient", return_value=fake_api_context),
                mock.patch.object(
                    module,
                    "query_single_hunt",
                    return_value={
                        "hunt_id": hunt_id,
                        "hunt_description": "Saved hunt for regression test",
                        "target_os": "windows",
                    },
                ),
                mock.patch.object(module, "raise_for_hunt_validation_errors"),
                mock.patch.object(module, "search_hunt", return_value=search_payload),
                mock.patch.object(module, "now_utc", return_value=refreshed_at),
            ):
                result = module.command_search(args)

            state_path = Path(initial_state["state_file"])
            refreshed_state = module.read_json(state_path)
            expected_review_flags = module.explicit_extraction_required_payload()

            self.assertEqual(result["state_file"], str(state_path))
            self.assertEqual(refreshed_state["saved_at"], preserved_saved_at)
            self.assertEqual(refreshed_state["updated_at"], refreshed_at)
            self.assertEqual(refreshed_state["latest_export_manifest_file"], "exports/latest-export.json")
            self.assertEqual(
                refreshed_state["latest_exported_files"],
                ["exports/previous-1.csv", "exports/previous-2.csv"],
            )
            self.assertEqual(
                refreshed_state["latest_download_manifest_file"],
                "downloads/latest-download.json",
            )
            self.assertEqual(
                refreshed_state["latest_downloaded_files"],
                ["downloads/previous-1.bin"],
            )

            for key, value in expected_review_flags.items():
                self.assertEqual(refreshed_state[key], value, key)


if __name__ == "__main__":
    unittest.main()
