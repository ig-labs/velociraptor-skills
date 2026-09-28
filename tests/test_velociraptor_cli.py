import unittest
from unittest import mock

from vraptor import legacy_cli as cli


class VelociraptorCliTest(unittest.TestCase):
    def test_collection_registry_covers_public_commands(self):
        self.assertEqual(
            set(cli.COLLECT_COMMAND_ROUTES),
            {
                "analyze",
                "check",
                "ensure",
                "export",
                "export-registry-hunter",
                "hydrate",
                "plan",
                "poll",
                "queue",
                "status",
            },
        )

    def test_hunt_registry_covers_public_and_compatibility_commands(self):
        self.assertEqual(
            set(cli.HUNT_COMMAND_ROUTES),
            {
                "analyze",
                "analyze-saved",
                "check",
                "download-results",
                "ensure",
                "export-results",
                "lookup",
                "native",
                "profiles",
                "retry-missing",
                "review-results",
                "run",
                "search",
                "snapshot",
                "status",
                "stop",
            },
        )
        compatibility = {
            command
            for command, route in cli.HUNT_COMMAND_ROUTES.items()
            if route.lifecycle == "compatibility"
        }
        self.assertEqual(
            compatibility,
            {
                "check",
                "download-results",
                "ensure",
                "export-results",
                "lookup",
                "profiles",
                "review-results",
                "search",
                "stop",
            },
        )
        for command in compatibility:
            self.assertEqual(
                cli.HUNT_COMMAND_ROUTES[command].replacement, f"hunt native {command}"
            )
            self.assertIn(command, cli.NATIVE_HUNT_COMMANDS)

    def test_query_routes_to_client_query_service(self):
        with mock.patch.object(cli.client_query, "main", return_value=15) as main:
            result = cli.main(
                ["query", "--id", "lab7", "--vql", "SELECT 1 FROM scope()"]
            )

        self.assertEqual(result, 15)
        main.assert_called_once_with(
            ["query", "--id", "lab7", "--vql", "SELECT 1 FROM scope()"]
        )

    def test_clients_route_to_client_query_service(self):
        with mock.patch.object(cli.client_query, "main", return_value=16) as main:
            result = cli.main(
                ["clients", "list", "--id", "lab7", "--label", "ir9004"]
            )

        self.assertEqual(result, 16)
        main.assert_called_once_with(
            ["clients", "list", "--id", "lab7", "--label", "ir9004"]
        )

    def test_collection_routes_directly_to_package_service(self):
        with mock.patch.object(cli.collection, "main", return_value=7) as main:
            result = cli.main(["collect", "status", "--host", "host01"])

        self.assertEqual(result, 7)
        main.assert_called_once_with(["status", "--host", "host01"])

    def test_registry_hunter_export_routes_to_collection_service(self):
        with mock.patch.object(cli.collection, "main", return_value=19) as main:
            result = cli.main(
                ["collect", "export-registry-hunter", "--host", "host01"]
            )

        self.assertEqual(result, 19)
        main.assert_called_once_with(
            ["export-registry-hunter", "--host", "host01"]
        )

    def test_collection_analyze_routes_to_canonical_runtime(self):
        with mock.patch.object(
            cli.collection_analysis_cli, "main", return_value=18
        ) as main:
            result = cli.main(["collect", "analyze", "--id", "IR1"])

        self.assertEqual(result, 18)
        main.assert_called_once_with(["--id", "IR1"])

    def test_unknown_collection_command_is_rejected_before_dispatch(self):
        with mock.patch.object(cli.collection, "main") as collection_main:
            result = cli.main(["collect", "typo"])

        self.assertEqual(result, 1)
        collection_main.assert_not_called()

    def test_collection_help_shows_public_analysis_entry(self):
        with mock.patch("builtins.print") as output:
            result = cli.main(["collect", "--help"])

        self.assertEqual(result, 0)
        rendered = output.call_args.args[0]
        self.assertIn("analyze", rendered)
        self.assertNotIn("workflow", rendered)
        self.assertNotIn("analysis-read", rendered)

    def test_autoruns_routes_to_golden_database_service(self):
        with mock.patch.object(
            cli.autoruns_golden,
            "main",
            return_value=14,
        ) as main:
            result = cli.main(
                ["autoruns", "inspect", "--db", "/tmp/golden.sqlite"]
            )

        self.assertEqual(result, 14)
        main.assert_called_once_with(
            ["inspect", "--db", "/tmp/golden.sqlite"]
        )

    def test_grouped_hunt_commands_route_to_workflow(self):
        with mock.patch.object(cli.hunt_workflow, "main", return_value=8) as main:
            result = cli.main(["hunt", "analyze", "--hunt-id", "H.1234"])

        self.assertEqual(result, 8)
        main.assert_called_once_with(["analyze", "--hunt-id", "H.1234"])

    def test_hunt_help_shows_public_workflow(self):
        with mock.patch.object(cli.hunt_workflow, "main", return_value=0) as main:
            result = cli.main(["hunt", "--help"])

        self.assertEqual(result, 0)
        main.assert_called_once_with(["--help"])

    def test_retry_missing_routes_to_public_workflow(self):
        with mock.patch.object(cli.hunt_workflow, "main", return_value=8) as main:
            result = cli.main(
                [
                    "hunt",
                    "retry-missing",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                    "--after-hours",
                    "24",
                ]
            )

        self.assertEqual(result, 8)
        main.assert_called_once()

    def test_native_hunt_routes_to_generic_engine(self):
        with mock.patch.object(cli.hunting, "main", return_value=9) as main:
            result = cli.main(["hunt", "native", "ensure", "--target", "linux"])

        self.assertEqual(result, 9)
        main.assert_called_once_with(["ensure", "--target", "linux"])

    def test_compatibility_hunt_command_routes_explicitly(self):
        with mock.patch.object(cli.hunting, "main", return_value=21) as main:
            result = cli.main(["hunt", "check", "--profile", "persistence"])

        self.assertEqual(result, 21)
        main.assert_called_once_with(["check", "--profile", "persistence"])

    def test_unknown_hunt_commands_are_rejected_before_dispatch(self):
        with mock.patch.object(cli.hunting, "main") as hunting_main:
            result = cli.main(["hunt", "typo"])
            native_result = cli.main(["hunt", "native", "typo"])

        self.assertEqual(result, 1)
        self.assertEqual(native_result, 1)
        hunting_main.assert_not_called()

    def test_saved_hunt_analysis_routes_to_analysis_engine(self):
        with mock.patch.object(cli.hunt_analysis, "main", return_value=11) as main:
            result = cli.main(
                ["hunt", "analyze-saved", "--state-file", "/tmp/state.json"]
            )

        self.assertEqual(result, 11)
        main.assert_called_once_with(["--state-file", "/tmp/state.json"])

    def test_detection_scenarios_route_to_scenario_cli(self):
        with mock.patch.object(
            cli.detection_scenario_cli,
            "main",
            return_value=12,
        ) as main:
            result = cli.main(
                ["artifacts", "scenarios", "show", "--scenario", "wmi-persistence"]
            )

        self.assertEqual(result, 12)
        main.assert_called_once_with(
            ["show", "--scenario", "wmi-persistence"]
        )

    def test_artifact_policy_routes_to_policy_cli(self):
        with mock.patch.object(
            cli.artifact_policy_cli,
            "main",
            return_value=18,
        ) as main:
            result = cli.main(["artifacts", "policy", "validate"])

        self.assertEqual(result, 18)
        main.assert_called_once_with(["validate"])

    def test_linux_plan_routes_to_linux_profile_cli(self):
        with mock.patch.object(
            cli.linux_host_profile,
            "main",
            return_value=17,
        ) as main:
            result = cli.main(
                [
                    "artifacts",
                    "linux-plan",
                    "--inventory",
                    "/tmp/inventory.json",
                    "--mode",
                    "standard",
                ]
            )

        self.assertEqual(result, 17)
        main.assert_called_once_with(
            [
                "--inventory",
                "/tmp/inventory.json",
                "--mode",
                "standard",
            ]
        )

    def test_config_fetch_routes_to_shared_bootstrap(self):
        with mock.patch.object(cli, "run_bootstrap", return_value=10) as bootstrap:
            result = cli.main(["config", "fetch-api", "--engagement-code", "ir1234"])

        self.assertEqual(result, 10)
        bootstrap.assert_called_once_with(
            "fetch_live_api_client.sh",
            ["--engagement-code", "ir1234"],
        )

    def test_mapped_add_remote_routes_to_shared_bootstrap(self):
        with mock.patch.object(cli, "run_bootstrap", return_value=19) as bootstrap:
            result = cli.main(
                [
                    "mapped",
                    "add-remote",
                    "--api-client",
                    "/tmp/api.yaml",
                    "--client-config",
                    "/tmp/client.yaml",
                    "/tmp/disk.E01",
                ]
            )

        self.assertEqual(result, 19)
        bootstrap.assert_called_once_with(
            "add_remote_mapped_client.sh",
            [
                "--api-client",
                "/tmp/api.yaml",
                "--client-config",
                "/tmp/client.yaml",
                "/tmp/disk.E01",
            ],
        )

    def test_mapped_status_routes_to_shared_bootstrap(self):
        with mock.patch.object(cli, "run_bootstrap", return_value=20) as bootstrap:
            result = cli.main(["mapped", "status", "--client", "disk01", "--json"])

        self.assertEqual(result, 20)
        bootstrap.assert_called_once_with(
            "mapped_client_status.sh",
            ["--client", "disk01", "--json"],
        )


if __name__ == "__main__":
    unittest.main()
