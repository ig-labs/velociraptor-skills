from __future__ import annotations

import unittest

from vraptor.analyze import profiles as collection_analysis_profiles
from vraptor.collect.catalog import BASELINE_COLLECTION_TYPES
from vraptor.collect.catalog import IR_COLLECTION_BUNDLES
from vraptor.collect.catalog import IR_COLLECTION_GROUPS
from vraptor.collect.catalog import SUPPORTED_COLLECTION_TYPES


class CollectionAnalysisProfilesTest(unittest.TestCase):
    def test_registry_covers_every_supported_collection_type(self):
        registry = collection_analysis_profiles.load_registry()

        self.assertEqual(
            set(registry["collection_profiles"]),
            {
                *SUPPORTED_COLLECTION_TYPES,
                *IR_COLLECTION_GROUPS,
                *IR_COLLECTION_BUNDLES,
            },
        )
        self.assertEqual(
            BASELINE_COLLECTION_TYPES,
            (
                "triage",
                "network",
                "execution",
                "persistence-expanded",
                "lateral-movement",
            ),
        )

    def test_special_profiles_and_autoruns_strategy_are_resolved(self):
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("triage"),
            "detectraptor-host",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("detectraptor"),
            "detectraptor-host",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("evtx"),
            "detectraptor-host",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("mft"),
            "detectraptor-host",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile(
                "ir-standard-live"
            ),
            "ir-standard-host",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile(
                "persistence-state"
            ),
            "persistence-state",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("timeline"),
            "timeline",
        )
        self.assertEqual(
            collection_analysis_profiles.resolve_analysis_profile("network"),
            "generic",
        )
        contract = collection_analysis_profiles.profile_contract(
            "persistence-expanded",
            ["Windows.Sysinternals.Autoruns", "Windows.System.Services"],
        )
        self.assertEqual(
            contract["artifact_strategies"],
            {"Windows.Sysinternals.Autoruns": "autoruns-goldendb"},
        )
        self.assertGreaterEqual(len(contract["analysis_objectives"]), 3)

    def test_question_relevance_modes_are_distinct(self):
        cases = {
            "Is anything malicious or suspicious?": "maliciousness",
            "Describe the host landscape and any RMM software.": "landscape",
            "What persistence mechanisms are present?": "persistence",
            "What does Artifact.Test row R1 show about svc-backup?": "targeted",
        }
        for question, expected in cases.items():
            with self.subTest(question=question):
                policy = collection_analysis_profiles.question_relevance_policy(
                    question
                )
                self.assertEqual(policy["mode"], expected)

        default = collection_analysis_profiles.question_relevance_policy(
            "Is anything malicious or suspicious?"
        )
        self.assertIn("ordinary system components", default["exclude"])
        landscape = collection_analysis_profiles.question_relevance_policy(
            "Describe the host landscape and any RMM software."
        )
        self.assertIn("Retain useful management context", landscape["context"])

    def test_explicit_task_modes_override_ambiguous_question_language(self):
        question = "Find suspicious activity and determine whether the environment is compromised."
        incident = collection_analysis_profiles.question_relevance_policy(
            question,
            task_mode="incident-response",
        )
        targeted = collection_analysis_profiles.question_relevance_policy(
            question,
            task_mode="targeted-hunt",
        )
        host = collection_analysis_profiles.question_relevance_policy(
            question,
            task_mode="host-forensics",
        )
        assessment = collection_analysis_profiles.question_relevance_policy(
            question,
            task_mode="compromise-assessment",
        )

        self.assertEqual(incident["mode"], "incident_response")
        self.assertIn("bounded incident hypothesis", incident["include"])
        self.assertIn("Do not broaden", targeted["exclude"])
        self.assertIn("UTC chronological order", host["include"])
        self.assertIn("prevalence", assessment["include"])
        self.assertIn("useful host, user", assessment["context"])

    def test_response_depth_contracts_are_distinct(self):
        rapid = collection_analysis_profiles.response_depth_policy("rapid")
        standard = collection_analysis_profiles.response_depth_policy("standard")
        deep = collection_analysis_profiles.response_depth_policy("deep")
        host_default = collection_analysis_profiles.response_depth_policy(
            "", task_mode="host-forensics"
        )
        hunt_default = collection_analysis_profiles.response_depth_policy(
            "", task_mode="targeted-hunt"
        )

        self.assertIn("highest-signal", rapid["output"])
        self.assertIn("provisional", rapid["output"])
        self.assertIn("relevant chronology", standard["output"])
        self.assertIn("UTC chronological timeline", deep["output"])
        self.assertEqual(host_default["depth"], "deep")
        self.assertEqual(hunt_default["depth"], "standard")


if __name__ == "__main__":
    unittest.main()
