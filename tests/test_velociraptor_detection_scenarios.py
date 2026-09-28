import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.artifacts import scenario_cli as detection_scenario_cli
from vraptor.artifacts import scenarios as detection_scenarios


class VelociraptorDetectionScenarioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = artifact_policy.load_artifact_policy()
        cls.profiles = cls.snapshot.profiles

    def test_builtin_catalog_loads_and_validates_profile_stack_ids(self):
        scenarios = self.snapshot.scenarios
        sources = self.snapshot.scenario_sources

        self.assertEqual(len(scenarios), 10)
        self.assertEqual(
            sources[0],
            detection_scenarios.BUILTIN_SCENARIO_PATH.resolve(),
        )
        service = scenarios["suspicious-service-creation"]
        services_binding = next(
            item
            for item in service["artifacts"]
            if item["artifact"] == "Windows.System.Services"
        )
        self.assertIn("service_dll", services_binding["stack_ids"])
        self.assertIn("executable_hash", services_binding["stack_ids"])
        self.assertTrue(service["_scenario_hash"])

    def test_builtin_scenarios_do_not_select_registry_hunter(self):
        scenarios = self.snapshot.scenarios

        matches = detection_scenarios.scenarios_for_artifact(
            "Windows.Registry.Hunter",
            scenarios,
        )
        wmi_artifacts = [
            item["artifact"]
            for item in scenarios["wmi-persistence"]["artifacts"]
        ]

        self.assertEqual(matches, [])
        self.assertEqual(
            wmi_artifacts,
            ["Windows.Persistence.PermanentWMIEvents"],
        )

    def test_overlay_updates_scenario_without_replacing_artifact_bindings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            overlay = Path(tmpdir) / "site-scenarios.json"
            overlay.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": {
                            "suspicious-service-creation": {
                                "selection_guidance": "Site-approved service review."
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            snapshot = artifact_policy.load_artifact_policy(
                scenario_references=[overlay],
                environ={},
            )
            scenarios = snapshot.scenarios
            sources = snapshot.scenario_sources

        scenario = scenarios["suspicious-service-creation"]
        self.assertEqual(
            scenario["selection_guidance"],
            "Site-approved service review.",
        )
        self.assertEqual(len(scenario["artifacts"]), 2)
        self.assertEqual(sources[-1], overlay.resolve())

    def test_validation_rejects_all_category_registry_hunter_binding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reference = Path(tmpdir) / "invalid-registry-hunter.json"
            reference.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": {
                            "invalid-registry-hunter": {
                                "title": "Invalid Registry Hunter scenario",
                                "objective": "Exercise heavy-artifact validation.",
                                "artifacts": [
                                    {
                                        "artifact": "Windows.Registry.Hunter[all]",
                                        "role": "primary",
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "must not use"):
                artifact_policy.load_artifact_policy(
                    builtin_scenario_path=reference,
                    environ={},
                )

    def test_validation_rejects_field_in_required_and_optional_lists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reference = Path(tmpdir) / "invalid-scenarios.json"
            reference.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": {
                            "invalid-scenario": {
                                "title": "Invalid",
                                "objective": "Exercise validation.",
                                "artifacts": [
                                    {
                                        "artifact": "Windows.System.Services",
                                        "role": "primary",
                                        "required_fields": ["Name"],
                                        "optional_fields": ["Name"],
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "both required and optional",
            ):
                artifact_policy.load_artifact_policy(
                    builtin_scenario_path=reference,
                    environ={},
                )

    def test_validation_rejects_unknown_stack_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reference = Path(tmpdir) / "invalid-stack.json"
            reference.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": {
                            "invalid-stack": {
                                "title": "Invalid stack",
                                "objective": "Exercise stack validation.",
                                "artifacts": [
                                    {
                                        "artifact": "Windows.System.Services",
                                        "role": "primary",
                                        "stack_ids": ["does-not-exist"],
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "unknown stacks"):
                artifact_policy.load_artifact_policy(
                    builtin_scenario_path=reference,
                    environ={},
                )

    def test_export_writes_resolved_json_and_csv(self):
        scenarios = self.snapshot.scenarios
        sources = self.snapshot.scenario_sources
        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = detection_scenarios.write_scenario_exports(
                tmpdir,
                scenarios,
                sources,
            )
            json_path = Path(outputs["detection_scenarios_json"])
            csv_path = Path(outputs["detection_scenarios_csv"])
            payload = json.loads(json_path.read_text(encoding="utf-8"))

            self.assertTrue(json_path.is_file())
            self.assertTrue(csv_path.is_file())
            self.assertEqual(payload["schema_version"], 1)
            self.assertIn(
                "encoded-powershell-execution",
                payload["scenarios"],
            )

    def test_cli_for_artifact_returns_matching_scenarios(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = detection_scenario_cli.main(
                [
                    "for-artifact",
                    "--artifact",
                    "Windows.System.Services",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["scenario_count"], 1)
        self.assertEqual(
            payload["scenarios"][0]["scenario_id"],
            "suspicious-service-creation",
        )

    def test_cli_validate_reports_detectraptor_contract_stack_validation(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = detection_scenario_cli.main(["validate"])

        payload = json.loads(stdout.getvalue())
        validation = payload["detectraptor_contract_validation"]
        self.assertEqual(exit_code, 0)
        self.assertEqual(validation["status"], "ok")
        self.assertEqual(validation["priority_artifact_count"], 11)
        self.assertEqual(validation["named_source_count"], 2)
        self.assertEqual(validation["validated_artifact_binding_count"], 13)
        self.assertEqual(validation["validated_stack_count"], 32)


if __name__ == "__main__":
    unittest.main()
