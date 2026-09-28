from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import detectraptor as detectraptor_contract


class DetectRaptorContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = artifact_policy.load_artifact_policy().profiles

    def test_contract_priority_is_ordered_and_complete(self):
        contract = detectraptor_contract.load_contract()
        artifacts = [entry["artifact"] for entry in contract["priority"]]
        self.assertEqual(
            artifacts,
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
            ],
        )
        self.assertEqual(
            contract["dispositions"],
            [
                "suspicious",
                "notable",
                "expected",
                "false_positive",
                "unresolved",
            ],
        )
        self.assertFalse(
            contract["evidence_boundaries"]["host"]["allows_prevalence"]
        )
        self.assertTrue(
            contract["evidence_boundaries"]["fleet"]["allows_prevalence"]
        )
        self.assertEqual(
            contract["evtx_review_output"]["candidate_file"],
            "analysis/detectraptor_whitelist_candidates.csv",
        )
        self.assertEqual(
            contract["evtx_review_output"]["payload_column"], "final"
        )
        self.assertFalse(
            contract["evtx_review_output"]["automatic_mutation"]
        )

    def test_every_contract_stack_resolves_against_profiles(self):
        report = detectraptor_contract.validate_contract_profiles(self.profiles)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["priority_artifact_count"], 11)
        self.assertEqual(report["named_source_count"], 2)
        self.assertEqual(report["validated_artifact_binding_count"], 13)
        self.assertEqual(report["validated_stack_count"], 32)
        self.assertTrue(
            all(binding["profile_hash"] for binding in report["bindings"])
        )

    def test_lolrmm_named_sources_are_validated_independently(self):
        contract = detectraptor_contract.load_contract()
        lolrmm = next(
            item
            for item in contract["priority"]
            if item["artifact"] == "DetectRaptor.Windows.Detection.LolRMM"
        )
        self.assertEqual(
            [item["artifact"] for item in lolrmm["named_sources"]],
            [
                "DetectRaptor.Windows.Detection.LolRMM/Processes",
                "DetectRaptor.Windows.Detection.LolRMM/ResolvedDomains",
            ],
        )

    def test_missing_contract_stack_fails_validation(self):
        contract = detectraptor_contract.load_contract()
        broken_profiles = copy.deepcopy(self.profiles)
        del broken_profiles[
            "DetectRaptor.Windows.Detection.Evtx"
        ]["review"]["stacks"]["detection"]
        with self.assertRaisesRegex(RuntimeError, "unknown stacks: detection"):
            detectraptor_contract.validate_contract_profiles(
                broken_profiles,
                contract=contract,
            )

    def test_contract_rejects_duplicate_named_source_stack(self):
        contract = detectraptor_contract.load_contract()
        lolrmm = next(
            item
            for item in contract["priority"]
            if item["artifact"] == "DetectRaptor.Windows.Detection.LolRMM"
        )
        lolrmm["named_sources"][0]["review_stacks"].append("rmm_process")
        with self.subTest("duplicate named-source stack"):
            path = self._write_contract(contract)
            with self.assertRaisesRegex(RuntimeError, "unique review_stacks"):
                detectraptor_contract.load_contract(path)

    def test_contract_rejects_host_prevalence_drift(self):
        contract = detectraptor_contract.load_contract()
        contract["evidence_boundaries"]["host"]["allows_prevalence"] = True
        path = self._write_contract(contract)
        with self.assertRaisesRegex(RuntimeError, "must be False"):
            detectraptor_contract.load_contract(path)

    def _write_contract(self, payload):
        path = Path(self._testMethodName + ".json")
        self.addCleanup(path.unlink, missing_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
