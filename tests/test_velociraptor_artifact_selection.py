import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "src/vraptor/artifacts/inventory.py"
)


def load_export_artifact_inventory_module():
    module_name = f"test_export_artifact_inventory_{uuid.uuid4().hex}"
    stub_names = (
        "grpc",
        "pyvelociraptor",
        "pyvelociraptor.api_pb2",
        "pyvelociraptor.api_pb2_grpc",
        "vraptor.api",
    )
    original_modules = {name: sys.modules.get(name) for name in stub_names}

    grpc_stub = types.ModuleType("grpc")
    pyvelociraptor_stub = types.ModuleType("pyvelociraptor")
    api_pb2_stub = types.ModuleType("api_pb2")
    api_pb2_grpc_stub = types.ModuleType("api_pb2_grpc")
    pyvelociraptor_stub.api_pb2 = api_pb2_stub
    pyvelociraptor_stub.api_pb2_grpc = api_pb2_grpc_stub

    sys.modules["grpc"] = grpc_stub
    sys.modules["pyvelociraptor"] = pyvelociraptor_stub
    sys.modules["pyvelociraptor.api_pb2"] = api_pb2_stub
    sys.modules["pyvelociraptor.api_pb2_grpc"] = api_pb2_grpc_stub

    try:
        spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load module from {SCRIPT_PATH}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original_module in original_modules.items():
            if original_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module


class ExportArtifactInventoryRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_export_artifact_inventory_module()

    def test_policy_cache_identity_ignores_overlay_location(self):
        args = self.make_main_args("/tmp/inventory-cache")
        profiles = {"Artifact.Test": {"enabled": True}}
        first = self.module.artifact_policy.build_artifact_policy(
            profiles=profiles,
            sources=(
                self.module.artifact_policy.PolicySource(
                    category="artifact_profiles",
                    role="overlay",
                    order=1,
                    path="/site/one/profiles.json",
                    content_sha256="a" * 64,
                ),
            ),
        )
        second = self.module.artifact_policy.build_artifact_policy(
            profiles=profiles,
            sources=(
                self.module.artifact_policy.PolicySource(
                    category="artifact_profiles",
                    role="overlay",
                    order=1,
                    path="/site/two/profiles.json",
                    content_sha256="a" * 64,
                ),
            ),
        )

        self.assertEqual(
            self.module.expected_cache_identity(args, first),
            self.module.expected_cache_identity(args, second),
        )

    def make_args(self, workflow=None, question_shape=None, windows_skill=None, top=10):
        return argparse.Namespace(
            workflow=workflow,
            question_shape=question_shape,
            windows_skill=windows_skill,
            top=top,
        )

    def make_main_args(self, output_dir, **overrides):
        values = {
            "api_client": "/tmp/api-client.yaml",
            "org_id": None,
            "output_dir": str(output_dir),
            "name_regex": None,
            "description_regex": None,
            "type_regex": None,
            "parameter_regex": None,
            "workflow": None,
            "question_shape": None,
            "windows_skill": None,
            "top": 10,
            "force_run": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def make_raw_row(self, name, description, parameters, artifact_type="CLIENT"):
        return {
            "name": name,
            "description": description,
            "type": artifact_type,
            "built_in": True,
            "compiled_in": True,
            "is_alias": False,
            "is_inherited": False,
            "parameters": parameters,
            "metadata": {},
        }

    def row_by_name(self, rows, name):
        return next(row for row in rows if row["name"] == name)

    def recommendation_by_artifact(self, rows, name):
        return next(row for row in rows if row["artifact"] == name)

    def write_text_file(self, path, content):
        path.write_text(content, encoding="utf-8")

    def read_recommendations_payload(self, output_dir):
        return self.module.read_json(
            Path(output_dir) / "artifact_definitions_inventory_recommendations.json"
        )

    def read_csv_rows(self, path):
        import csv

        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_recommendation_hints_cover_hunt_and_collection_artifacts(self):
        raw_rows = [
            self.make_raw_row(
                "DetectRaptor.Windows.Detection.Evtx",
                "Cross-host DetectRaptor EVTX detection artifact.",
                [{"name": "DateAfter"}, {"name": "DateBefore"}, {"name": "ChannelRegex"}],
            ),
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Host-scoped EVTX collection artifact.",
                [{"name": "EvtxGlob"}, {"name": "DateAfter"}, {"name": "DateBefore"}],
            ),
        ]
        bias_rows = {
            "DetectRaptor.Windows.Detection.Evtx": {
                "recommended_windows_skills": "velociraptor-hunting",
                "recommended_question_shapes": "cross-host|artifact-inventory",
                "preferred_use_case": "Cross-host detection scoping.",
            },
            "Windows.EventLogs.EvtxHunter": {
                "recommended_windows_skills": "velociraptor-host-analysis",
                "recommended_question_shapes": "single-host|bounded-time-window",
                "preferred_use_case": "Host-scoped event log collection.",
                "review_strategy": "detection_or_keyword",
                "preferred_sample_fields": "ClientId|Fqdn|Timestamp|Message",
                "avoid_stack_fields": "EventID|Channel|Provider",
                "recommended_filters": "IocRegex|EvtxGlob|DateAfter|DateBefore",
            },
        }

        normalized = self.module.normalize_rows(raw_rows)
        enriched = self.module.build_enriched_rows(normalized, bias_rows)

        hunt_row = self.row_by_name(enriched, "DetectRaptor.Windows.Detection.Evtx")
        collection_row = self.row_by_name(enriched, "Windows.EventLogs.EvtxHunter")

        self.assertEqual(hunt_row["recommended_workflows"], ["hunt"])
        self.assertEqual(hunt_row["recommended_windows_skills"], ["velociraptor-hunting"])
        self.assertEqual(
            hunt_row["recommended_collection_types"],
            ["triage", "detectraptor", "evtx"],
        )
        self.assertEqual(
            hunt_row["recommended_ir_collection_groups"],
            ["signal-triage"],
        )
        self.assertEqual(hunt_row["recommended_hunt_profiles"], ["detectraptor"])

        self.assertEqual(
            collection_row["recommended_workflows"],
            ["collection", "analysis"],
        )
        self.assertEqual(
            collection_row["recommended_windows_skills"],
            ["velociraptor-host-analysis"],
        )
        self.assertEqual(collection_row["recommended_collection_types"], ["exfiltration", "timeline"])
        self.assertEqual(collection_row["recommended_hunt_profiles"], [])

        recommendations = self.module.build_recommendation_rows(enriched, self.make_args())
        collection_recommendation = self.recommendation_by_artifact(
            recommendations,
            "Windows.EventLogs.EvtxHunter",
        )
        self.assertEqual(
            collection_recommendation["recommended_windows_skills"],
            ["velociraptor-host-analysis"],
        )
        self.assertEqual(collection_recommendation["review_strategy"], "detection_or_keyword")
        self.assertEqual(
            collection_recommendation["preferred_sample_fields"],
            ["ClientId", "Fqdn", "Timestamp", "Message"],
        )
        self.assertEqual(collection_recommendation["avoid_stack_fields_csv"], "EventID|Channel|Provider")
        self.assertEqual(
            collection_recommendation["recommended_filters_csv"],
            "IocRegex|EvtxGlob|DateAfter|DateBefore",
        )

    def test_curated_evtxhunter_bias_is_detection_or_keyword_oriented(self):
        bias_rows = self.module.load_bias_rows(
            self.module.artifact_policy.load_artifact_policy()
        )
        evtx_bias = bias_rows["Windows.EventLogs.EvtxHunter"]

        self.assertEqual(evtx_bias["review_strategy"], "detection_or_keyword")
        self.assertIn("EventID", self.module.split_multi_value_field(evtx_bias["avoid_stack_fields"]))
        self.assertIn("Channel", self.module.split_multi_value_field(evtx_bias["avoid_stack_fields"]))
        self.assertIn("IocRegex", self.module.split_multi_value_field(evtx_bias["recommended_filters"]))
        self.assertIn("EvtxGlob", self.module.split_multi_value_field(evtx_bias["recommended_filters"]))

    def test_network_artifacts_resolve_to_network_collection_type(self):
        for artifact in (
            "Windows.Network.NetstatEnriched",
            "Windows.System.DNSCache",
        ):
            self.assertIn(
                "network",
                self.module.derived_collection_types(artifact),
            )
            self.assertEqual(
                self.module.derived_ir_collection_groups(artifact),
                ["volatile-state"],
            )
        self.assertEqual(
            self.module.derived_collection_types("Windows.Detection.PublicIP"),
            ["triage", "evtx"],
        )
        self.assertEqual(
            self.module.derived_collection_types(
                "DetectRaptor.Windows.Detection.MFT"
            ),
            ["triage", "detectraptor", "mft"],
        )

    def test_registry_hunter_profile_supports_conditional_ioc_and_mtime_bounds(self):
        profiles = self.module.artifact_policy.load_artifact_policy().profiles
        profile = profiles["Windows.Registry.Hunter"]

        self.assertEqual(
            profile["time_bound_support"],
            "conditional-live-definition",
        )
        self.assertIn(
            "bounded-time-window",
            profile["selection"]["question_shapes"],
        )
        for parameter in ("IocRegex", "ModifiedAfter", "ModifiedBefore"):
            self.assertIn(parameter, profile["review"]["recommended_filters"])
        self.assertIn("Mtime", profile["review"]["timestamp_fields"])

    def test_registry_hunter_modified_bounds_are_recognized_as_narrowing(self):
        details = self.module.extract_parameter_details(
            [
                {"name": "Categories"},
                {"name": "IocRegex"},
                {"name": "ModifiedAfter"},
                {"name": "ModifiedBefore"},
            ]
        )

        self.assertEqual(
            details["narrowing"],
            ["IocRegex", "ModifiedAfter", "ModifiedBefore"],
        )
        self.assertEqual(
            details["time_bound"],
            ["ModifiedAfter", "ModifiedBefore"],
        )

    def test_registry_hunter_is_recommended_for_live_bounded_registry_search(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.Registry.Hunter",
                "Category-scoped registry hunting.",
                [
                    {"name": "Categories"},
                    {"name": "IocRegex"},
                    {"name": "ModifiedAfter"},
                    {"name": "ModifiedBefore"},
                ],
            )
        ]
        normalized = self.module.normalize_rows(raw_rows)
        enriched = self.module.build_enriched_rows(
            normalized,
            self.module.load_bias_rows(
                self.module.artifact_policy.load_artifact_policy()
            ),
        )
        recommendations = self.module.build_recommendation_rows(
            enriched,
            self.make_args(
                workflow="collection",
                question_shape="bounded-time-window",
            ),
        )

        registry = self.recommendation_by_artifact(
            recommendations,
            "Windows.Registry.Hunter",
        )
        self.assertEqual(
            registry["time_bound_parameter_names"],
            ["ModifiedAfter", "ModifiedBefore"],
        )
        self.assertIn("IocRegex", registry["narrowing_parameter_names"])
        self.assertIn("registry", registry["recommended_collection_types"])

    def test_detectraptor_profile_exposes_only_detection_scope_stack(self):
        snapshot = self.module.artifact_policy.load_artifact_policy()
        profiles = snapshot.profiles
        source_paths = snapshot.profile_sources
        profile = profiles["DetectRaptor.Windows.Detection.Evtx"]

        self.assertEqual(
            profile["review"]["stacks"]["detection"]["dimensions"],
            ["DetectionIdentity"],
        )
        self.assertEqual(set(profile["review"]["stacks"]), {"detection"})
        self.assertEqual(
            profile["review"]["strategy"], "automatic_exact_payload"
        )
        self.assertEqual(profile["review"]["default_stack"], "detection")

        self.assertEqual(
            profile["review"]["stacks"]["detection"]["server_dimensions"],
            ["Detection.Name"],
        )
        self.assertEqual(
            profile["review"]["stacks"]["detection"]["server_scope_aliases"],
            ["Detection"],
        )
        self.assertEqual(
            profile["review"]["stacks"]["detection"]["analysis_role"],
            "scope",
        )
        self.assertNotIn(
            "hash(accessor=",
            json.dumps(profile["review"], sort_keys=True),
        )
        self.assertNotIn("Detection", profile["review"]["filter_fields"])
        self.assertEqual(
            profile["review"]["filter_scope_fields"],
            {"Detection": "Detection.Name"},
        )
        normalizers = {
            item["output"]: item
            for item in profile["review"]["normalizers"]
        }
        self.assertEqual(normalizers["DetectionIdentity"]["kind"], "identity")
        self.assertEqual(set(normalizers), {"DetectionIdentity"})
        self.assertIn("EventTime", profile["review"]["avoid_stack_fields"])
        self.assertEqual(source_paths[0], self.module.REFERENCE_JSON_PATH.resolve())

    def test_detectraptor_live_hunt_projections_retain_fqdn(self):
        profiles = self.module.artifact_policy.load_artifact_policy().profiles

        for artifact in (
            "DetectRaptor.Windows.Detection.Evtx",
            "DetectRaptor.Windows.Detection.MFT",
        ):
            with self.subTest(artifact=artifact):
                self.assertIn(
                    "Fqdn",
                    profiles[artifact]["review"]["live_vql_select"],
                )

    def test_detectraptor_priority_profiles_match_emitted_artifact_fields(self):
        profiles = self.module.artifact_policy.load_artifact_policy().profiles

        mft = profiles["DetectRaptor.Windows.Detection.MFT"]["review"]
        self.assertEqual(mft["default_stack"], "criticality_detection")
        self.assertEqual(
            mft["stacks"]["criticality_detection"]["server_dimensions"],
            ["Detection.Criticality", "Detection.Name"],
        )
        self.assertEqual(
            mft["stacks"]["detection_path"]["dimensions"],
            ["NormalizedPath"],
        )
        self.assertIn("Detection.StringHit", mft["sample_fields"])
        self.assertIn("SITimestamps", mft["context_fields"])
        self.assertNotIn("Extension", mft["sample_fields"])
        self.assertEqual(
            profiles["DetectRaptor.Windows.Detection.MFT"][
                "time_bound_support"
            ],
            "yes",
        )

        psreadline = profiles[
            "DetectRaptor.Windows.Detection.Powershell.PSReadline"
        ]["review"]
        self.assertEqual(psreadline["default_stack"], "rule")
        self.assertEqual(
            psreadline["stacks"]["rule"]["server_dimensions"],
            ["RuleID"],
        )
        self.assertEqual(
            psreadline["stacks"]["command"]["server_dimensions"],
            ["Line"],
        )
        self.assertIn("RuleRegex", psreadline["context_fields"])
        self.assertIn("FileInfo", psreadline["context_fields"])
        self.assertNotIn("Command", psreadline["sample_fields"])

        expected_priority_profiles = {
            "DetectRaptor.Windows.Detection.Applications": "application",
            "DetectRaptor.Windows.Detection.LolRMM": "rmm_application",
            "DetectRaptor.Windows.Detection.LolRMM/Processes": "rmm_process",
            "DetectRaptor.Windows.Detection.LolRMM/ResolvedDomains": "rmm_domain",
            "DetectRaptor.Windows.Detection.Amcache": "criticality_detection",
            "DetectRaptor.Windows.Detection.BinaryRename": "rename_identity",
            "DetectRaptor.Windows.Detection.Webhistory": "category_domain",
            "DetectRaptor.Windows.Detection.YaraProcessWin": "rule_process",
            "DetectRaptor.Generic.Detection.YaraWebshell": "rule_path",
            "DetectRaptor.Generic.Detection.BrowserExtensions": "extension",
        }
        for artifact, default_stack in expected_priority_profiles.items():
            self.assertIn(artifact, profiles)
            self.assertEqual(
                profiles[artifact]["review"]["default_stack"],
                default_stack,
            )

    def test_detectraptor_triage_group_uses_priority_analysis_order(self):
        self.assertEqual(
            list(self.module.ARTIFACT_GROUPS["triage"]),
            [
                "DetectRaptor.Windows.Detection.Evtx",
                "Windows.Detection.PublicIP",
                "DetectRaptor.Windows.Detection.MFT",
                "DetectRaptor.Windows.Detection.Powershell.PSReadline",
                "DetectRaptor.Windows.Detection.Applications",
                "DetectRaptor.Windows.Detection.LolRMM",
                "DetectRaptor.Windows.Detection.Amcache",
                "DetectRaptor.Windows.Detection.BinaryRename",
                "DetectRaptor.Windows.Detection.Webhistory",
                "DetectRaptor.Windows.Detection.YaraProcessWin",
                "DetectRaptor.Generic.Detection.BrowserExtensions",
                "DetectRaptor.Windows.Detection.ZoneIdentifier",
            ],
        )
        self.assertEqual(
            list(self.module.ARTIFACT_GROUPS["detectraptor"]),
            [
                "DetectRaptor.Windows.Detection.Evtx",
                "DetectRaptor.Windows.Detection.MFT",
                "DetectRaptor.Windows.Detection.Powershell.PSReadline",
                "DetectRaptor.Windows.Detection.Applications",
                "DetectRaptor.Windows.Detection.LolRMM",
                "DetectRaptor.Windows.Detection.Amcache",
                "DetectRaptor.Windows.Detection.BinaryRename",
                "DetectRaptor.Windows.Detection.Webhistory",
                "DetectRaptor.Windows.Detection.YaraProcessWin",
                "DetectRaptor.Generic.Detection.YaraWebshell",
                "DetectRaptor.Generic.Detection.BrowserExtensions",
                "DetectRaptor.Windows.Detection.ZoneIdentifier",
            ],
        )
        self.assertNotIn(
            "Windows.Detection.PublicIP",
            self.module.ARTIFACT_GROUPS["detectraptor"],
        )
        self.assertNotIn(
            "DetectRaptor.Generic.Detection.YaraWebshell",
            self.module.ARTIFACT_GROUPS["triage"],
        )
        self.assertIn(
            "DetectRaptor.Generic.Detection.YaraWebshell",
            self.module.ARTIFACT_GROUPS["detectraptor"],
        )

    def test_windows_services_profile_has_independent_stack_use_cases(self):
        profiles = self.module.artifact_policy.load_artifact_policy().profiles
        profile = profiles["Windows.System.Services"]

        self.assertEqual(profile["review"]["default_stack"], "service_name")
        self.assertEqual(
            set(profile["review"]["stacks"]),
            {
                "service_name",
                "executable_path",
                "service_dll",
                "service_account",
                "executable_hash",
                "dll_hash",
                "failure_command",
                "start_mode",
                "name_path",
            },
        )
        selected = self.module.artifact_profiles.select_stack_view(
            profile,
            "service_dll",
            require_server=True,
        )
        self.assertIsNotNone(selected)
        self.assertEqual(selected[1]["server_dimensions"], ["ServiceDll"])
        self.assertEqual(
            profile["review"]["stacks"]["executable_hash"]["collection_parameters"],
            {"Calculate_hashes": "Y"},
        )

    def test_windows_pslist_profile_defaults_to_process_trust_stack(self):
        profiles = self.module.artifact_policy.load_artifact_policy().profiles
        profile = profiles["Windows.System.Pslist"]

        self.assertEqual(profile["review"]["default_stack"], "process_trust")
        selected = self.module.artifact_profiles.select_stack_view(
            profile,
            None,
            require_server=True,
        )
        self.assertIsNotNone(selected)
        stack_name, stack = selected
        self.assertEqual(stack_name, "process_trust")
        self.assertEqual(
            stack["dimensions"],
            ["Name", "Exe", "AuthenticodeTrusted"],
        )
        self.assertEqual(
            stack["server_dimensions"],
            ["Name", "Exe", "Authenticode.Trusted"],
        )
        self.assertEqual(stack["analysis_role"], "signature")
        identity_stack = profile["review"]["stacks"]["process_identity"]
        self.assertEqual(
            identity_stack["dimensions"],
            ["Name", "Exe", "CommandLine"],
        )
        self.assertEqual(
            identity_stack["server_dimensions"],
            ["Name", "Exe", "CommandLine"],
        )
        self.assertIn("CommandLine", profile["review"]["sample_fields"])
        self.assertIn(
            "Authenticode.Trusted AS AuthenticodeTrusted",
            profile["review"]["vql_select"],
        )
        self.assertEqual(
            self.module.artifact_profiles.analysis_fields(profile)[:3],
            ["Name", "Exe", "AuthenticodeTrusted"],
        )
        inventory_hints = self.module.artifact_profiles.profile_to_inventory_hints(profile)
        self.assertEqual(
            inventory_hints["preferred_stack_fields"],
            ["Name", "Exe", "AuthenticodeTrusted"],
        )
        self.assertEqual(
            inventory_hints["server_stack_fields"],
            ["Name", "Exe", "Authenticode.Trusted"],
        )
        self.assertEqual(
            set(inventory_hints["stack_view_ids"]),
            {"process_trust", "process_identity"},
        )
        self.assertEqual(
            set(inventory_hints["recommended_windows_skills"]),
            {
                "velociraptor-hunting",
                "velociraptor-host-analysis",
            },
        )

    def test_explicit_site_reference_overrides_environment_and_can_add_custom_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_reference = root / "env.json"
            explicit_reference = root / "explicit.json"
            self.write_text_file(
                env_reference,
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "DetectRaptor.Windows.Detection.Evtx": {
                                "row_volume_risk": "low"
                            }
                        },
                    }
                ),
            )
            self.write_text_file(
                explicit_reference,
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "DetectRaptor.Windows.Detection.Evtx": {
                                "row_volume_risk": "very-high"
                            },
                            "Custom.Windows.SiteArtifact": {
                                "signal_type": "site-custom",
                                "row_volume_risk": "medium",
                                "time_bound_support": "no",
                                "selection": {},
                                "review": {
                                    "strategy": "site_stack",
                                    "default_stack": "name",
                                    "stacks": {
                                        "name": {
                                            "purpose": "Which names are rare in this site artifact?",
                                            "dimensions": ["Name"],
                                            "server_dimensions": ["Name"],
                                            "metrics": ["count"],
                                            "max_groups": 100
                                        }
                                    },
                                    "normalizers": [],
                                    "sample_fields": ["Name"],
                                    "context_fields": [],
                                    "avoid_stack_fields": [],
                                    "recommended_filters": [],
                                    "host_fields": [],
                                    "timestamp_fields": []
                                },
                                "analysis_routes": {}
                            }
                        },
                    }
                ),
            )

            snapshot = self.module.artifact_policy.load_artifact_policy(
                artifact_references=[explicit_reference],
                environ={
                    self.module.artifact_profiles.REFERENCE_ENV_VAR: str(env_reference)
                },
            )
            profiles = snapshot.profiles
            source_paths = snapshot.profile_sources

        self.assertEqual(profiles["DetectRaptor.Windows.Detection.Evtx"]["row_volume_risk"], "very-high")
        self.assertEqual(
            set(profiles["DetectRaptor.Windows.Detection.Evtx"]["review"]["stacks"]),
            {"detection"},
        )
        self.assertIn("Custom.Windows.SiteArtifact", profiles)
        self.assertEqual(source_paths[-1], explicit_reference.resolve())
        self.assertNotIn(env_reference.resolve(), source_paths)

    def test_profile_validation_rejects_unresolved_normalized_dimension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reference = Path(tmpdir) / "invalid.json"
            self.write_text_file(
                reference,
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "Custom.Invalid": {
                                "review": {
                                    "default_stack": "missing",
                                    "stacks": {
                                        "missing": {
                                            "purpose": "Which unresolved normalized values are rare?",
                                            "dimensions": ["NormalizedMissing"]
                                        }
                                    }
                                }
                            }
                        },
                    }
                ),
            )

            with self.assertRaisesRegex(RuntimeError, "without normalizers"):
                self.module.artifact_policy.load_artifact_policy(
                    artifact_references=[reference],
                    environ={},
                )

    def test_profile_validation_requires_one_analytical_purpose_per_stack(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reference = Path(tmpdir) / "missing-purpose.json"
            self.write_text_file(
                reference,
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "Custom.Invalid": {
                                "review": {
                                    "default_stack": "name",
                                    "stacks": {
                                        "name": {
                                            "dimensions": ["Name"]
                                        }
                                    }
                                }
                            }
                        },
                    }
                ),
            )

            with self.assertRaisesRegex(RuntimeError, "requires one analytical purpose"):
                self.module.artifact_policy.load_artifact_policy(
                    artifact_references=[reference],
                    environ={},
                )

    def test_profile_validation_rejects_retired_schema_and_route_fields(self):
        source = Path("retired-profile.json")
        with self.assertRaisesRegex(RuntimeError, "requires schema_version 4"):
            self.module.artifact_profiles.validate_reference_document(
                {"schema_version": 3, "profiles": {}},
                source=source,
            )

    def test_profile_validation_rejects_retired_standalone_saved_hunt_overlay(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "retired standalone saved-hunt review profile structure",
        ):
            self.module.artifact_profiles.validate_reference_document(
                {
                    "profile_name": "old-site-profile",
                    "artifact_patterns": ["^Custom\\.Old$"],
                    "field_candidates": ["Name"],
                },
                source=Path("old-site-profile.json"),
            )

    def test_saved_hunt_projection_schema_is_narrow(self):
        source = Path("site-profile.json")
        profiles = self.module.artifact_profiles.validate_reference_document(
            {
                "schema_version": 4,
                "profiles": {
                    "Custom.Valid": {
                        "review": {
                            "saved_hunt_projection": {
                                "summary_fields": ["Name", "Path"],
                                "max_source_fields": 6,
                            }
                        }
                    }
                },
            },
            source=source,
        )
        self.assertEqual(
            profiles["Custom.Valid"]["review"]["saved_hunt_projection"],
            {"summary_fields": ["Name", "Path"], "max_source_fields": 6},
        )
        with self.assertRaisesRegex(RuntimeError, "unsupported keys: field_candidates"):
            self.module.artifact_profiles.validate_reference_document(
                {
                    "schema_version": 4,
                    "profiles": {
                        "Custom.Invalid": {
                            "review": {
                                "saved_hunt_projection": {
                                    "field_candidates": ["Name"]
                                }
                            }
                        }
                    },
                },
                source=source,
            )

    def test_profile_validation_rejects_retired_route_fields(self):
        source = Path("retired-route-profile.json")
        with self.assertRaisesRegex(RuntimeError, "unsupported keys: model_routes"):
            self.module.artifact_profiles.validate_reference_document(
                {
                    "schema_version": 4,
                    "profiles": {"Custom.Invalid": {"model_routes": {}}},
                },
                source=source,
            )
        with self.assertRaisesRegex(RuntimeError, "unsupported keys: model_route"):
            self.module.artifact_profiles.validate_reference_document(
                {
                    "schema_version": 4,
                    "profiles": {
                        "Custom.Invalid": {
                            "review": {
                                "stacks": {
                                    "name": {
                                        "purpose": "Which names are rare?",
                                        "model_route": "reasoning",
                                    }
                                }
                            }
                        }
                    },
                },
                source=source,
            )

    def test_profile_validation_rejects_unknown_analysis_route(self):
        with self.assertRaisesRegex(RuntimeError, "Unknown analysis route"):
            self.module.artifact_profiles.validate_reference_document(
                {
                    "schema_version": 4,
                    "profiles": {
                        "Custom.Invalid": {
                            "analysis_routes": {"final_reasoning": "compact-review"}
                        }
                    },
                },
                source=Path("invalid-route.json"),
            )

    def test_recommendation_filtering_returns_expected_shortlist(self):
        raw_rows = [
            self.make_raw_row(
                "DetectRaptor.Windows.Detection.Evtx",
                "Highest-signal hunt candidate.",
                [{"name": "ChannelRegex"}],
            ),
            self.make_raw_row(
                "Windows.EventLogs.ServiceCreationComspec",
                "Targeted lateral-movement hunt candidate.",
                [],
            ),
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Collection-only candidate.",
                [{"name": "EvtxGlob"}],
            ),
        ]
        bias_rows = {
            "DetectRaptor.Windows.Detection.Evtx": {
                "recommended_windows_skills": "velociraptor-hunting",
                "recommended_question_shapes": "cross-host",
                "preferred_use_case": "Broad detection scoping.",
            },
            "Windows.EventLogs.ServiceCreationComspec": {
                "recommended_windows_skills": "velociraptor-hunting",
                "recommended_question_shapes": "cross-host",
            },
            "Windows.EventLogs.EvtxHunter": {
                "recommended_windows_skills": "velociraptor-host-analysis",
                "recommended_question_shapes": "bounded-time-window",
                "preferred_use_case": "Collect narrowed log windows.",
            },
        }

        normalized = self.module.normalize_rows(raw_rows)
        enriched = self.module.build_enriched_rows(normalized, bias_rows)

        matching_args = self.make_args(
            workflow="hunt",
            question_shape="cross-host",
            windows_skill="velociraptor-hunting",
            top=10,
        )
        shortlist = self.module.build_recommendation_rows(enriched, matching_args)

        self.assertEqual(
            [row["artifact"] for row in shortlist],
            [
                "DetectRaptor.Windows.Detection.Evtx",
                "Windows.EventLogs.ServiceCreationComspec",
            ],
        )

        top_one_args = self.make_args(
            workflow="hunt",
            question_shape="cross-host",
            windows_skill="velociraptor-hunting",
            top=1,
        )
        top_one = self.module.build_recommendation_rows(enriched, top_one_args)

        self.assertEqual(len(top_one), 1)
        self.assertEqual(top_one[0]["artifact"], "DetectRaptor.Windows.Detection.Evtx")

    def test_live_only_bias_rows_recommend_velociraptor_collection(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.Sysinternals.Autoruns",
                "Live-only persistence sweep.",
                [{"name": "PathRegex"}],
            ),
            self.make_raw_row(
                "Windows.Persistence.PermanentWMIEvents",
                "Live-only WMI persistence follow-up.",
                [{"name": "DateAfter"}],
            ),
        ]

        normalized = self.module.normalize_rows(raw_rows)
        enriched = self.module.build_enriched_rows(
            normalized,
            self.module.load_bias_rows(
                self.module.artifact_policy.load_artifact_policy()
            ),
        )
        single_host_recommendations = self.module.build_recommendation_rows(
            enriched,
            self.make_args(
                workflow="collection",
                question_shape="single-host",
                windows_skill="velociraptor-host-analysis",
                top=10,
            ),
        )

        autoruns_recommendations = self.module.build_recommendation_rows(
            enriched,
            self.make_args(
                workflow="collection",
                question_shape="cross-host",
                windows_skill="velociraptor-host-analysis",
                top=10,
            ),
        )

        for artifact_name, recommendations in (
            ("Windows.Sysinternals.Autoruns", autoruns_recommendations),
            (
                "Windows.Persistence.PermanentWMIEvents",
                single_host_recommendations,
            ),
        ):
            enriched_row = self.row_by_name(enriched, artifact_name)
            recommendation = self.recommendation_by_artifact(
                recommendations,
                artifact_name,
            )

            self.assertIn(
                "velociraptor-host-analysis",
                enriched_row["recommended_windows_skills"],
            )
            self.assertIn(
                "velociraptor-host-analysis",
                recommendation["recommended_windows_skills"],
            )

    def test_parameter_detail_extraction_propagates_to_recommendation_rows(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Time-bounded log collector.",
                [
                    {"name": "DateAfter"},
                    {"name": "DateBefore"},
                    {"name": "EvtxGlob"},
                    {"name": "SearchRegex"},
                    {"name": "Limit"},
                ],
            )
        ]
        bias_rows = {
            "Windows.EventLogs.EvtxHunter": {
                "recommended_windows_skills": "velociraptor-host-analysis",
                "recommended_question_shapes": "bounded-time-window",
                "preferred_use_case": "Collect a narrow EVTX slice.",
            }
        }

        normalized = self.module.normalize_rows(raw_rows)
        enriched = self.module.build_enriched_rows(normalized, bias_rows)
        recommendations = self.module.build_recommendation_rows(enriched, self.make_args())
        recommendation = self.recommendation_by_artifact(recommendations, "Windows.EventLogs.EvtxHunter")

        self.assertEqual(
            recommendation["narrowing_parameter_names"],
            ["DateAfter", "DateBefore", "EvtxGlob", "SearchRegex"],
        )
        self.assertEqual(
            recommendation["time_bound_parameter_names"],
            ["DateAfter", "DateBefore"],
        )
        self.assertEqual(
            recommendation["narrowing_parameter_names_csv"],
            "DateAfter,DateBefore,EvtxGlob,SearchRegex",
        )
        self.assertEqual(
            recommendation["time_bound_parameter_names_csv"],
            "DateAfter,DateBefore",
        )

    def test_type_regex_filter_matches_normalized_artifact_type(self):
        normalized = self.module.normalize_rows(
            [
                self.make_raw_row("Windows.Client.Artifact", "Client artifact.", [], artifact_type="CLIENT"),
                self.make_raw_row("Server.Admin.Artifact", "Server artifact.", [], artifact_type="SERVER"),
            ]
        )

        type_pattern = self.module.compile_optional_regex("^client$")
        client_row = self.row_by_name(normalized, "Windows.Client.Artifact")
        server_row = self.row_by_name(normalized, "Server.Admin.Artifact")

        self.assertTrue(self.module.filter_row(client_row, None, None, type_pattern, None))
        self.assertFalse(self.module.filter_row(server_row, None, None, type_pattern, None))

    def test_required_parameter_metadata_propagates_to_normalized_and_recommendation_rows(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.Custom.LiveCollector",
                "Collector with live parameter metadata.",
                [
                    {"name": "LiveRequired", "optional": False},
                    {"name": "ExplicitRequired", "required": True},
                    {"name": "LegacyMandatory", "mandatory": True},
                    {"name": "OptionalValue", "optional": True},
                    {"name": "ImplicitOptional"},
                ],
            )
        ]
        bias_rows = {
            "Windows.Custom.LiveCollector": {
                "recommended_windows_skills": "velociraptor-host-analysis",
                "recommended_question_shapes": "single-host",
                "preferred_use_case": "Live single-host collection.",
            }
        }

        normalized = self.module.normalize_rows(raw_rows)
        normalized_row = self.row_by_name(normalized, "Windows.Custom.LiveCollector")
        self.assertEqual(
            normalized_row["required_parameter_names"],
            ["LiveRequired", "ExplicitRequired", "LegacyMandatory"],
        )
        self.assertEqual(
            normalized_row["optional_parameter_names"],
            ["OptionalValue", "ImplicitOptional"],
        )

        enriched = self.module.build_enriched_rows(normalized, bias_rows)
        recommendations = self.module.build_recommendation_rows(enriched, self.make_args())
        recommendation = self.recommendation_by_artifact(
            recommendations,
            "Windows.Custom.LiveCollector",
        )
        self.assertEqual(
            recommendation["required_parameter_names"],
            ["LiveRequired", "ExplicitRequired", "LegacyMandatory"],
        )
        self.assertEqual(
            recommendation["required_parameter_names_csv"],
            "LiveRequired,ExplicitRequired,LegacyMandatory",
        )

    def test_main_uses_velo_local_org_id_when_org_id_arg_is_absent(self):
        captured = {}
        raw_rows = [self.make_raw_row("Windows.Env.Test", "Env fallback artifact.", [])]

        class FakeVeloApiClient:
            def __init__(self, api_client, org_id):
                captured["api_client"] = api_client
                captured["org_id"] = org_id

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            args = self.make_main_args(tmpdir, org_id=None)
            with mock.patch.dict(os.environ, {"VELO_LOCAL_ORG_ID": "org-from-env"}, clear=False):
                with mock.patch.object(self.module, "parse_args", return_value=args), mock.patch.object(
                    self.module, "load_bias_rows", return_value={}
                ), mock.patch.object(self.module, "VeloApiClient", FakeVeloApiClient):
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = self.module.main()

            summary_path = Path(tmpdir) / "artifact_definitions_inventory_summary.json"
            summary_payload = self.module.read_json(summary_path)

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["api_client"], Path("/tmp/api-client.yaml").resolve())
        self.assertEqual(captured["org_id"], "org-from-env")
        self.assertEqual(summary_payload["org_id"], "org-from-env")

    def test_resolved_org_id_and_main_default_to_root_when_arg_and_env_are_absent(self):
        captured = {}
        raw_rows = [self.make_raw_row("Windows.Root.Default", "Root fallback artifact.", [])]

        class FakeVeloApiClient:
            def __init__(self, api_client, org_id):
                captured["api_client"] = api_client
                captured["org_id"] = org_id

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {}, clear=True):
            args = self.make_main_args(tmpdir, org_id=None)

            self.assertEqual(self.module.resolved_org_id(args), "root")

            with mock.patch.object(self.module, "parse_args", return_value=args), mock.patch.object(
                self.module, "load_bias_rows", return_value={}
            ), mock.patch.object(self.module, "VeloApiClient", FakeVeloApiClient):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = self.module.main()

            summary_path = Path(tmpdir) / "artifact_definitions_inventory_summary.json"
            summary_payload = self.module.read_json(summary_path)

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["api_client"], Path("/tmp/api-client.yaml").resolve())
        self.assertEqual(captured["org_id"], "root")
        self.assertEqual(summary_payload["org_id"], "root")
        self.assertEqual(summary_payload["cache_identity"]["org_id"], "root")

    def test_main_prints_recommendation_and_summary_paths_and_reuses_cache_stdout(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Collection artifact.",
                [{"name": "DateAfter", "required": True}, {"name": "EvtxGlob"}],
            )
        ]
        api_calls = {"count": 0}

        class FakeVeloApiClient:
            def __init__(self, _api_client, org_id):
                self.org_id = org_id

            def __enter__(self):
                api_calls["count"] += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            args = self.make_main_args(tmpdir, org_id="explicit-org")
            output_dir = Path(tmpdir).resolve()
            summary_path = output_dir / "artifact_definitions_inventory_summary.json"
            expected_stdout = [
                str(output_dir / "artifact_definitions_inventory.csv"),
                str(output_dir / "artifact_definitions_inventory_enriched.csv"),
                str(output_dir / "artifact_definitions_inventory_recommendations.csv"),
                str(output_dir / "artifact_definitions_inventory_recommendations.json"),
                str(summary_path),
            ]

            with mock.patch.object(self.module, "parse_args", return_value=args), mock.patch.object(
                self.module,
                "load_bias_rows",
                return_value={
                    "Windows.EventLogs.EvtxHunter": {
                        "recommended_windows_skills": "velociraptor-host-analysis",
                        "recommended_question_shapes": "bounded-time-window",
                        "preferred_use_case": "Collect narrowed EVTX windows.",
                    }
                },
            ), mock.patch.object(self.module, "VeloApiClient", FakeVeloApiClient):
                first_stdout = io.StringIO()
                with contextlib.redirect_stdout(first_stdout):
                    first_exit_code = self.module.main()

                second_stdout = io.StringIO()
                with contextlib.redirect_stdout(second_stdout):
                    second_exit_code = self.module.main()

            summary_payload = self.module.read_json(summary_path)

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(first_stdout.getvalue().splitlines(), expected_stdout)
        self.assertEqual(second_stdout.getvalue().splitlines(), expected_stdout)
        self.assertEqual(api_calls["count"], 1)
        self.assertEqual(summary_payload["storage_class"], "disposable_cache")
        self.assertEqual(summary_payload["source_of_truth"], "velociraptor")
        self.assertFalse(summary_payload["evidence"])
        self.assertEqual(summary_payload["output_files"]["recommendations_csv"], expected_stdout[2])
        self.assertEqual(summary_payload["output_files"]["recommendations_json"], expected_stdout[3])
        self.assertEqual(summary_payload["output_files"]["summary"], expected_stdout[4])
        self.assertTrue(summary_payload["output_files"]["artifact_profiles_json"].endswith("artifact_profiles_resolved.json"))
        self.assertTrue(summary_payload["output_files"]["artifact_profiles_csv"].endswith("artifact_profiles_resolved.csv"))

    def test_main_writes_review_metadata_to_enriched_and_recommendation_csvs(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Collection artifact.",
                [{"name": "DateAfter"}, {"name": "EvtxGlob"}],
            )
        ]

        class FakeVeloApiClient:
            def __init__(self, _api_client, org_id):
                self.org_id = org_id

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            args = self.make_main_args(tmpdir, org_id="explicit-org")
            with mock.patch.object(self.module, "parse_args", return_value=args), mock.patch.object(
                self.module,
                "load_bias_rows",
                return_value={
                    "Windows.EventLogs.EvtxHunter": {
                        "recommended_windows_skills": "velociraptor-host-analysis",
                        "recommended_question_shapes": "bounded-time-window",
                        "review_strategy": "detection_or_keyword",
                        "preferred_stack_fields": "",
                        "preferred_sample_fields": "ClientId|Fqdn|Timestamp|Message",
                        "avoid_stack_fields": "EventID|Channel|Provider",
                        "recommended_filters": "IocRegex|EvtxGlob|DateAfter|DateBefore",
                    }
                },
            ), mock.patch.object(self.module, "VeloApiClient", FakeVeloApiClient):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = self.module.main()

            output_dir = Path(tmpdir).resolve()
            enriched_row = self.read_csv_rows(output_dir / "artifact_definitions_inventory_enriched.csv")[0]
            recommendation_row = self.read_csv_rows(output_dir / "artifact_definitions_inventory_recommendations.csv")[0]

        self.assertEqual(exit_code, 0)
        for row in (enriched_row, recommendation_row):
            self.assertEqual(row["review_strategy"], "detection_or_keyword")
            self.assertEqual(row["preferred_stack_fields_csv"], "")
            self.assertEqual(row["preferred_sample_fields_csv"], "ClientId|Fqdn|Timestamp|Message")
            self.assertEqual(row["avoid_stack_fields_csv"], "EventID|Channel|Provider")
            self.assertEqual(row["recommended_filters_csv"], "IocRegex|EvtxGlob|DateAfter|DateBefore")
        self.assertIn("--review-operation sample", recommendation_row["review_sample_command"])
        self.assertIn("--field ClientId", recommendation_row["review_sample_command"])
        self.assertIn("--field Message", recommendation_row["review_sample_command"])
        self.assertIn("--where '$REVIEW_WHERE'", recommendation_row["review_sample_command"])
        self.assertEqual(recommendation_row["review_stack_command"], "")
        self.assertIn("--review-operation inventory", recommendation_row["review_inventory_command"])
        self.assertIn("IocRegex", recommendation_row["review_filter_hint"])

    def test_main_invalidates_cache_when_site_artifact_reference_changes_between_runs(self):
        raw_rows = [
            self.make_raw_row(
                "Windows.EventLogs.EvtxHunter",
                "Collection artifact.",
                [{"name": "DateAfter"}, {"name": "EvtxGlob"}],
            )
        ]
        api_calls = {"count": 0}

        class FakeVeloApiClient:
            def __init__(self, _api_client, org_id):
                self.org_id = org_id

            def __enter__(self):
                api_calls["count"] += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            output_dir = temp_root / "output"
            api_client = temp_root / "api-client.yaml"
            site_reference = temp_root / "site-artifacts.json"
            self.write_text_file(api_client, "api_client: first\n")
            self.write_text_file(
                site_reference,
                json.dumps(
                    {
                        "schema_version": 4,
                        "profiles": {
                            "Windows.EventLogs.EvtxHunter": {
                                "selection": {
                                    "windows_skills": ["velociraptor-host-analysis"],
                                    "question_shapes": ["bounded-time-window"],
                                    "preferred_use_case": "Collect narrowed EVTX windows.",
                                }
                            }
                        },
                    }
                ),
            )
            args = self.make_main_args(
                output_dir,
                api_client=str(api_client),
                artifact_reference=[str(site_reference)],
            )

            with mock.patch.object(self.module, "parse_args", return_value=args), mock.patch.object(
                self.module, "VeloApiClient", FakeVeloApiClient
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    first_exit_code = self.module.main()
                first_recommendations = self.read_recommendations_payload(output_dir)

                self.write_text_file(
                    site_reference,
                    json.dumps(
                        {
                            "schema_version": 4,
                            "profiles": {
                                "Windows.EventLogs.EvtxHunter": {
                                    "selection": {
                                        "windows_skills": ["velociraptor-host-analysis"],
                                        "question_shapes": ["artifact-inventory"],
                                        "preferred_use_case": "Investigate EVTX contents directly.",
                                    }
                                }
                            },
                        }
                    ),
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    second_exit_code = self.module.main()
                second_recommendations = self.read_recommendations_payload(output_dir)
                summary_payload = self.module.read_json(
                    output_dir / "artifact_definitions_inventory_summary.json"
                )

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(api_calls["count"], 2)
        self.assertEqual(
            first_recommendations["recommendations"][0]["recommended_windows_skills"],
            ["velociraptor-host-analysis"],
        )
        self.assertEqual(
            second_recommendations["recommendations"][0]["recommended_windows_skills"],
            ["velociraptor-host-analysis"],
        )
        self.assertEqual(
            second_recommendations["recommendations"][0]["preferred_use_case"],
            "Investigate EVTX contents directly.",
        )
        cache_policy = summary_payload["cache_identity"]["artifact_policy"]
        self.assertEqual(cache_policy["sha256"], second_recommendations["artifact_policy"]["sha256"])
        self.assertNotIn(str(site_reference.resolve()), json.dumps(cache_policy))

    def test_main_invalidates_cache_when_api_client_path_changes(self):
        raw_rows = [self.make_raw_row("Windows.Env.Test", "Env fallback artifact.", [])]
        init_calls = []

        class FakeVeloApiClient:
            def __init__(self, api_client, org_id):
                init_calls.append((Path(api_client), org_id))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            output_dir = temp_root / "output"
            api_client_one = temp_root / "api-client-one.yaml"
            api_client_two = temp_root / "api-client-two.yaml"
            self.write_text_file(api_client_one, "api_client: one\n")
            self.write_text_file(api_client_two, "api_client: two\n")
            first_args = self.make_main_args(
                output_dir,
                api_client=str(api_client_one),
                org_id="explicit-org",
            )
            second_args = self.make_main_args(
                output_dir,
                api_client=str(api_client_two),
                org_id="explicit-org",
            )

            with mock.patch.object(self.module, "load_bias_rows", return_value={}), mock.patch.object(
                self.module, "VeloApiClient", FakeVeloApiClient
            ):
                with mock.patch.object(self.module, "parse_args", return_value=first_args):
                    with contextlib.redirect_stdout(io.StringIO()):
                        first_exit_code = self.module.main()
                with mock.patch.object(self.module, "parse_args", return_value=second_args):
                    with contextlib.redirect_stdout(io.StringIO()):
                        second_exit_code = self.module.main()
                summary_payload = self.module.read_json(
                    output_dir / "artifact_definitions_inventory_summary.json"
                )

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(len(init_calls), 2)
        self.assertEqual(init_calls[0], (api_client_one.resolve(), "explicit-org"))
        self.assertEqual(init_calls[1], (api_client_two.resolve(), "explicit-org"))
        self.assertEqual(
            summary_payload["cache_identity"]["api_client_path"],
            str(api_client_two.resolve()),
        )

    def test_main_invalidates_cache_when_api_client_contents_change_at_same_path(self):
        raw_rows = [self.make_raw_row("Windows.Env.Test", "Env fallback artifact.", [])]
        init_calls = []

        class FakeVeloApiClient:
            def __init__(self, api_client, org_id):
                init_calls.append((Path(api_client), org_id))

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            output_dir = temp_root / "output"
            api_client = temp_root / "api-client.yaml"
            self.write_text_file(api_client, "api_client: one\n")
            args = self.make_main_args(
                output_dir,
                api_client=str(api_client),
                org_id="explicit-org",
            )

            with mock.patch.object(self.module, "load_bias_rows", return_value={}), mock.patch.object(
                self.module, "VeloApiClient", FakeVeloApiClient
            ), mock.patch.object(self.module, "parse_args", return_value=args):
                with contextlib.redirect_stdout(io.StringIO()):
                    first_exit_code = self.module.main()
                first_summary_payload = self.module.read_json(
                    output_dir / "artifact_definitions_inventory_summary.json"
                )

                self.write_text_file(api_client, "api_client: two\n")

                with contextlib.redirect_stdout(io.StringIO()):
                    second_exit_code = self.module.main()
                second_summary_payload = self.module.read_json(
                    output_dir / "artifact_definitions_inventory_summary.json"
                )

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(len(init_calls), 2)
        self.assertEqual(init_calls[0], (api_client.resolve(), "explicit-org"))
        self.assertEqual(init_calls[1], (api_client.resolve(), "explicit-org"))
        self.assertEqual(
            first_summary_payload["cache_identity"]["api_client_path"],
            str(api_client.resolve()),
        )
        self.assertEqual(
            second_summary_payload["cache_identity"]["api_client_path"],
            str(api_client.resolve()),
        )
        self.assertNotEqual(
            first_summary_payload["cache_identity"]["api_client_fingerprint"],
            second_summary_payload["cache_identity"]["api_client_fingerprint"],
        )

    def test_main_ignores_top_in_cache_identity_without_recommendation_filters(self):
        raw_rows = [
            self.make_raw_row("Windows.First.Artifact", "First artifact.", []),
            self.make_raw_row("Windows.Second.Artifact", "Second artifact.", []),
        ]
        api_calls = {"count": 0}

        class FakeVeloApiClient:
            def __init__(self, _api_client, org_id):
                pass

            def __enter__(self):
                api_calls["count"] += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def query(self, _query):
                return raw_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            output_dir = temp_root / "output"
            api_client = temp_root / "api-client.yaml"
            self.write_text_file(api_client, "api_client: stable\n")
            first_args = self.make_main_args(output_dir, api_client=str(api_client), top=10)
            second_args = self.make_main_args(output_dir, api_client=str(api_client), top=1)

            with mock.patch.object(self.module, "load_bias_rows", return_value={}), mock.patch.object(
                self.module, "VeloApiClient", FakeVeloApiClient
            ):
                with mock.patch.object(self.module, "parse_args", return_value=first_args):
                    with contextlib.redirect_stdout(io.StringIO()):
                        first_exit_code = self.module.main()
                first_recommendations = self.read_recommendations_payload(output_dir)

                with mock.patch.object(self.module, "parse_args", return_value=second_args):
                    with contextlib.redirect_stdout(io.StringIO()):
                        second_exit_code = self.module.main()
                second_recommendations = self.read_recommendations_payload(output_dir)
                summary_payload = self.module.read_json(
                    output_dir / "artifact_definitions_inventory_summary.json"
                )

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(api_calls["count"], 1)
        self.assertEqual(first_recommendations["recommendation_count"], 2)
        self.assertEqual(second_recommendations["recommendation_count"], 2)
        self.assertEqual(
            [row["artifact"] for row in second_recommendations["recommendations"]],
            ["Windows.First.Artifact", "Windows.Second.Artifact"],
        )
        self.assertEqual(summary_payload["filters"]["top"], "")


if __name__ == "__main__":
    unittest.main()
