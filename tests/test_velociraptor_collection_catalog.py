import json
import unittest
from unittest import mock

from vraptor.artifacts import policy as artifact_policy
from vraptor.collect import requests as collection
from vraptor.collect import catalog as collection_catalog


class VelociraptorCollectionCatalogTest(unittest.TestCase):
    def test_plan_cli_accepts_capability_aware_bundle(self):
        args = collection.parse_args(
            [
                "plan",
                "--id",
                "IR1",
                "--client-id",
                "C.1234",
                "--bundle",
                "ir-standard-live",
            ]
        )

        self.assertEqual(args.command, "plan")
        self.assertEqual(args.bundle, "ir-standard-live")

    def test_policy_loads_with_expected_groups_and_bundles(self):
        policy = collection_catalog.load_collection_policy()

        self.assertEqual(policy["schema_version"], 1)
        self.assertEqual(
            collection_catalog.IR_COLLECTION_BUNDLES,
            ("ir-standard-live", "ir-standard-disk"),
        )

    def test_policy_targets_cannot_be_silently_mixed_with_legacy_scope(self):
        with self.assertRaisesRegex(RuntimeError, "cannot be combined"):
            collection.build_request(
                "triage",
                [],
                [],
                collection_bundle="ir-standard-live",
            )
        with self.assertRaisesRegex(RuntimeError, "require --target-mode"):
            collection.build_request(
                None,
                [],
                [],
                collection_groups=["identity-state"],
            )
        with self.assertRaisesRegex(RuntimeError, "requires target mode"):
            collection.build_request(
                None,
                [],
                [],
                collection_bundle="ir-standard-live",
                target_mode="mapped-disk",
            )
        self.assertEqual(
            set(collection_catalog.IR_COLLECTION_GROUPS),
            {
                "signal-triage",
                "volatile-state",
                "execution-history",
                "identity-state",
                "persistence-state",
                "authentication-lateral",
                "script-execution",
                "defense-evasion",
            },
        )

    def test_standard_bundles_exclude_prohibited_heavy_artifacts(self):
        policy = collection_catalog.load_collection_policy()
        prohibited = set(policy["prohibited_baseline_artifacts"])

        for bundle in collection_catalog.IR_COLLECTION_BUNDLES:
            resolution = collection_catalog.resolve_collection_policy(bundle=bundle)
            self.assertFalse(prohibited & set(resolution["candidate_artifacts"]))

    def test_every_policy_candidate_has_an_artifact_profile(self):
        policy = collection_catalog.load_collection_policy()
        candidates = {
            alternative
            for group in policy["groups"].values()
            for item in group["artifacts"]
            for alternative in item["alternatives"]
        }
        profiles = artifact_policy.load_artifact_policy().profiles

        self.assertEqual(candidates - set(profiles), set())

    def test_mapped_disk_marks_volatile_sources_not_applicable(self):
        resolution = collection_catalog.resolve_collection_policy(
            bundle="ir-standard-disk"
        )

        self.assertIn("volatile-state:process-list", resolution["not_applicable"])
        self.assertNotIn("Windows.System.Pslist", resolution["candidate_artifacts"])
        self.assertNotIn(
            "Windows.Network.NetstatEnriched",
            resolution["candidate_artifacts"],
        )

    def test_alternative_selection_falls_back_without_duplicate_collection(self):
        available = {
            "Windows.System.Services",
            "Windows.System.TaskScheduler",
            "Windows.Sys.StartupItems",
            "Windows.Registry.TaskCache.HiddenTasks",
        }
        resolution = collection_catalog.resolve_collection_policy(
            groups=["persistence-state"],
            target_mode="mapped-disk",
            available_artifacts=available,
        )

        self.assertEqual(resolution["status"], "ready")
        self.assertIn(
            "Windows.Registry.TaskCache.HiddenTasks",
            resolution["selected_artifacts"],
        )
        self.assertNotIn(
            "IG.Windows.Registry.HiddenTasks",
            resolution["selected_artifacts"],
        )

    def test_missing_core_blocks_only_affected_request(self):
        resolution = collection_catalog.resolve_collection_policy(
            groups=["identity-state"],
            target_mode="live",
            available_artifacts={"Windows.Registry.HiddenUsers"},
        )

        self.assertEqual(resolution["status"], "blocked")
        self.assertEqual(resolution["missing_core"], ["identity-state:local-users"])
        self.assertIn(
            "identity-state:local-administrators",
            resolution["unavailable_recommended"],
        )

    def test_bundle_degrades_instead_of_aborting_other_lanes(self):
        resolution = collection_catalog.resolve_collection_policy(
            bundle="ir-standard-live",
            available_artifacts={
                "Windows.System.Pslist",
                "Windows.Detection.Amcache",
                "Windows.Forensics.Prefetch",
                "Windows.Sys.AllUsers",
                "Windows.System.Services",
                "Windows.System.TaskScheduler",
                "Windows.EventLogs.RDPAuth",
                "Windows.EventLogs.ExplicitLogon",
                "Windows.EventLogs.PowershellScriptblock",
                "Windows.EventLogs.Cleared",
            },
        )

        self.assertEqual(resolution["status"], "degraded")
        self.assertIn("signal-triage:event-log-detections", resolution["missing_core"])
        signal_status = next(
            item
            for item in resolution["group_statuses"]
            if item["group"] == "signal-triage"
        )
        self.assertEqual(signal_status["status"], "core_missing")
        self.assertIn("Windows.System.Services", resolution["selected_artifacts"])

    def test_physical_deduplication_preserves_logical_membership(self):
        unchecked = collection_catalog.resolve_collection_policy(
            groups=["signal-triage", "script-execution"],
            target_mode="live",
        )
        resolution = collection_catalog.resolve_collection_policy(
            groups=["signal-triage", "script-execution"],
            target_mode="live",
            available_artifacts=unchecked["candidate_artifacts"],
        )

        artifact = "DetectRaptor.Windows.Detection.Powershell.PSReadline"
        self.assertEqual(resolution["selected_artifacts"].count(artifact), 1)
        physical = next(
            item for item in resolution["physical_sources"] if item["artifact"] == artifact
        )
        self.assertEqual(
            physical["groups"],
            ["signal-triage", "script-execution"],
        )

    def test_bundle_request_resolution_does_not_change_flow_identity_shape(self):
        request = collection.build_request(
            None,
            [],
            [],
            collection_bundle="ir-standard-disk",
        )
        initial_policy_hash = request.collection_policy["sha256"]
        api = mock.Mock()

        def query_file(_name, env, **_kwargs):
            return [{"name": item} for item in json.loads(env["Artifacts"])]

        api.query_file.side_effect = query_file
        collection.resolve_policy_request_for_api(api, request)

        self.assertEqual(request.collection_resolution["status"], "ready")
        self.assertEqual(request.collection_policy["sha256"], initial_policy_hash)
        self.assertTrue(request.expected_specs)
        run_identity = collection.collection_run_identity(
            "C.1234", request.expected_specs
        )
        request_id = collection.request_id_for_request(request)
        request.collection_policy = {
            **request.collection_policy,
            "sha256": "f" * 64,
        }
        self.assertEqual(
            collection.collection_run_identity("C.1234", request.expected_specs),
            run_identity,
        )
        self.assertNotEqual(collection.request_id_for_request(request), request_id)
        self.assertEqual(run_identity["identity"]["target"]["client_id"], "C.1234")

    def test_unused_available_fallback_does_not_change_request_id(self):
        first = collection.build_request(
            None,
            [],
            [],
            collection_groups=["persistence-state"],
            target_mode="live",
        )
        second = collection.build_request(
            None,
            [],
            [],
            collection_groups=["persistence-state"],
            target_mode="live",
        )
        all_candidates = set(first.candidate_artifacts)
        unused_fallbacks = {
            "Windows.Registry.TaskCache.HiddenTasks",
            "Windows.Sysinternals.Autoruns",
        }

        for request, available in (
            (first, all_candidates - unused_fallbacks),
            (second, all_candidates),
        ):
            api = mock.Mock()
            api.query_file.return_value = [
                {"name": artifact} for artifact in sorted(available)
            ]
            collection.resolve_policy_request_for_api(api, request)

        self.assertEqual(
            collection.request_id_for_request(first),
            collection.request_id_for_request(second),
        )

    def test_plan_collection_is_read_only_and_reports_policy_gaps(self):
        request = collection.build_request(
            None,
            [],
            [],
            collection_groups=["identity-state"],
            target_mode="live",
        )
        api = mock.Mock()
        api.api_config = None
        api.org_id = "root"
        api.query_file.return_value = [{"name": "Windows.Registry.HiddenUsers"}]
        client = collection.ClientRecord(
            client_id="C.1234",
            hostname="host01",
            last_seen="2026-09-03T00:00:00Z",
        )

        result = collection.plan_collection(
            api,
            "IR1",
            "host01",
            request,
            client=client,
        )

        self.assertEqual(result["action"], "planned_only")
        self.assertEqual(result["artifact_preflight"]["status"], "failed")
        self.assertFalse(result["flows_queried"])
        self.assertFalse(result["flows_queued"])
        self.assertFalse(result["state_persisted"])
        queried_files = [call.args[0] for call in api.query_file.call_args_list]
        self.assertEqual(
            queried_files,
            ["list_artifact_availability.vql", "list_artifact_availability.vql"],
        )

    def test_degraded_policy_cannot_claim_complete_host_coverage(self):
        manifest = collection.build_coverage_manifest(
            {
                "investigation_id": "IR1",
                "hostname": "host01",
                "request_id": "ir-standard-live-test",
                "requested_groups": ["signal-triage"],
                "requested_artifacts": [],
                "artifact_flows": [],
                "collection_resolution": {
                    "status": "degraded",
                    "missing_core": ["signal-triage:event-log-detections"],
                },
            }
        )

        self.assertIsNotNone(manifest)
        self.assertTrue(manifest["physical_collection_complete"])
        self.assertFalse(manifest["host_coverage_complete"])
        self.assertTrue(manifest["review_ready"])


if __name__ == "__main__":
    unittest.main()
