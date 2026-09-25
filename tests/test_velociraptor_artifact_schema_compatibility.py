from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from unittest import mock

from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import profiles as artifact_profiles
from vraptor.artifacts import schema as artifact_schema_compatibility
from vraptor import legacy_cli as cli


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_SCRIPT = (
    REPO_ROOT
    / "utils/validate_velociraptor_artifact_schemas.py"
)


def official_schema_snapshot() -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifacts": [
            {
                "name": "Windows.EventLogs.RDPAuth",
                "columns": [
                    {"name": "EventTime"},
                    {"name": "EventID"},
                    {"name": "UserName"},
                    {"name": "SourceIP"},
                ],
            },
            {
                "artifact": "Windows.EventLogs.ExplicitLogon",
                "fields": [
                    "EventTime",
                    "EventID",
                    "TargetUserName",
                    "TargetServerName",
                    "ProcessName",
                ],
            },
            {
                "name": "Windows.Forensics.Amcache",
                "sources": [
                    {
                        "name": "File",
                        "fields": [
                            "FullPath",
                            "SHA1",
                            "ModificationTime",
                        ],
                    },
                    {
                        "name": "InventoryApplicationFile",
                        "fields": ["Timestamp", "FullPath", "SHA1"],
                    },
                ],
            },
            {
                "name": "Windows.Forensics.Bam",
                "schema": {
                    "properties": {
                        "SID": {"type": "string"},
                        "UserName": {"type": "string"},
                        "Binary": {"type": "string"},
                        "Bam_time": {"type": "timestamp"},
                    }
                },
            },
            {
                "name": "Windows.Persistence.PermanentWMIEvents",
                "fields": [
                    "ConsumerDetails",
                    "FilterDetails",
                    "Namespace",
                ],
            },
        ],
    }


class VelociraptorArtifactSchemaCompatibilityTest(unittest.TestCase):
    def test_builtin_contract_requires_native_artifacts(self):
        contract = artifact_schema_compatibility.load_contract()

        self.assertEqual(contract["schema_version"], 1)
        self.assertIn("Windows.Forensics.Amcache", contract["artifacts"])
        self.assertIn("Windows.Forensics.Bam", contract["artifacts"])
        self.assertNotIn("Windows.Detection.Amcache", contract["artifacts"])

    def test_official_server_schema_snapshot_is_compatible(self):
        result = artifact_schema_compatibility.validate_snapshot(
            official_schema_snapshot()
        )

        self.assertTrue(result["compatible"])
        self.assertEqual(result["missing_artifacts"], [])
        self.assertEqual(result["missing_semantic_alias_groups"], [])
        self.assertEqual(result["summary"]["required_artifact_count"], 5)

    def test_review_field_aliases_are_compatible(self):
        snapshot = {
            "artifacts": {
                "Windows.EventLogs.RDPAuth": [
                    "Timestamp",
                    "EventId",
                    "User",
                    "SourceAddress",
                ],
                "Windows.EventLogs.ExplicitLogon": {
                    "output_fields": [
                        "Timestamp",
                        "EventId",
                        "AccountName",
                        "TargetServer",
                        "Process",
                    ]
                },
                "Windows.Forensics.Amcache": {
                    "fields": ["Path", "FileId", "InstallDate"]
                },
                "Windows.Forensics.Bam": {
                    "fields": ["FullPath", "User", "LastExecution"]
                },
                "Windows.Persistence.PermanentWMIEvents": {
                    "fields": ["Consumer", "Filter", "EventNamespace"]
                },
            }
        }

        result = artifact_schema_compatibility.validate_snapshot(snapshot)

        self.assertTrue(result["compatible"])
        rdp = next(
            item
            for item in result["artifacts"]
            if item["artifact"] == "Windows.EventLogs.RDPAuth"
        )
        matched = {
            group["semantic"]: group["matched_aliases"]
            for group in rdp["semantic_alias_groups"]
        }
        self.assertEqual(matched["event_time"], ["Timestamp"])
        self.assertEqual(matched["user"], ["User"])

    def test_live_profiles_use_validated_native_projection_fields(self):
        profiles = artifact_policy.load_artifact_policy().profiles

        rdp = profiles["Windows.EventLogs.RDPAuth"]["review"]
        self.assertIn("EventTime", rdp["sample_fields"])
        self.assertIn("UserName", rdp["sample_fields"])
        self.assertIn("Description", rdp["sample_fields"])
        self.assertEqual(rdp["timestamp_fields"], ["EventTime"])

        explicit = profiles["Windows.EventLogs.ExplicitLogon"]["review"]
        self.assertIn("TargetServerName", explicit["sample_fields"])
        self.assertEqual(
            explicit["stacks"]["primary"]["server_dimensions"],
            ["ProcessName", "TargetServerName"],
        )

        amcache = profiles["Windows.Forensics.Amcache"]["review"]
        self.assertIn("LowerCaseLongPath", amcache["sample_fields"])
        self.assertIn("FileId", amcache["sample_fields"])

        bam = profiles["Windows.Forensics.Bam"]["review"]
        self.assertIn("Bam_time", bam["timestamp_fields"])
        self.assertIn("SID", bam["sample_fields"])

        wmi = profiles["Windows.Persistence.PermanentWMIEvents"]["review"]
        self.assertEqual(wmi["default_stack"], "")
        self.assertEqual(wmi["stacks"], {})
        self.assertIn("ConsumerDetails", wmi["sample_fields"])
        self.assertIn("FilterDetails", wmi["sample_fields"])

    def test_missing_artifact_and_semantic_groups_are_reported(self):
        snapshot = official_schema_snapshot()
        artifacts = snapshot["artifacts"]
        assert isinstance(artifacts, list)
        artifacts[:] = [
            item
            for item in artifacts
            if (item.get("name") or item.get("artifact"))
            != "Windows.Forensics.Bam"
        ]
        rdp = artifacts[0]
        assert isinstance(rdp, dict)
        rdp["columns"] = [{"name": "EventTime"}, {"name": "EventID"}]

        result = artifact_schema_compatibility.validate_snapshot(snapshot)

        self.assertFalse(result["compatible"])
        self.assertEqual(
            result["missing_artifacts"],
            ["Windows.Forensics.Bam"],
        )
        missing_rdp_semantics = {
            item["semantic"]
            for item in result["missing_semantic_alias_groups"]
            if item["artifact"] == "Windows.EventLogs.RDPAuth"
        }
        self.assertEqual(missing_rdp_semantics, {"user", "source_ip"})

    def test_strict_cli_returns_one_for_incompatible_snapshot(self):
        snapshot = official_schema_snapshot()
        artifacts = snapshot["artifacts"]
        assert isinstance(artifacts, list)
        artifacts.pop()
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot_path = Path(tmpdir) / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            non_strict = subprocess.run(
                [sys.executable, str(VALIDATOR_SCRIPT), str(snapshot_path)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            strict = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR_SCRIPT),
                    "--snapshot",
                    str(snapshot_path),
                    "--strict",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(non_strict.returncode, 0, non_strict.stderr)
        self.assertFalse(json.loads(non_strict.stdout)["compatible"])
        self.assertEqual(strict.returncode, 1, strict.stderr)
        self.assertFalse(json.loads(strict.stdout)["compatible"])

    def test_strict_cli_returns_zero_for_compatible_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot_path = Path(tmpdir) / "snapshot.json"
            snapshot_path.write_text(
                json.dumps(official_schema_snapshot()),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR_SCRIPT),
                    str(snapshot_path),
                    "--strict",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["compatible"])

    def test_unified_cli_routes_schema_validation(self):
        with mock.patch.object(
            artifact_schema_compatibility,
            "main",
            return_value=0,
        ) as validator:
            result = cli.main(
                ["artifacts", "validate-schema", "--snapshot", "schema.json"]
            )
        self.assertEqual(result, 0)
        validator.assert_called_once_with(["--snapshot", "schema.json"])


if __name__ == "__main__":
    unittest.main()
