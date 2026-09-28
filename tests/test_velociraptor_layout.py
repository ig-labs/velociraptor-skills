from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vraptor import case_layout
from vraptor.collect import requests as collection
from vraptor.collect import layout


class VelociraptorLayoutTest(unittest.TestCase):
    def setUp(self):
        self.original_case_root = collection.CASE_ROOT

    def tearDown(self):
        collection.CASE_ROOT = self.original_case_root

    def test_host_and_hunt_resources_share_engagement_root(self):
        case_root = Path("/cases")

        self.assertEqual(
            case_layout.hunt_dir(case_root, "IR1234", "H.1234"),
            Path("/cases/IR1234/hunts/H.1234"),
        )
        self.assertEqual(
            layout.system_dir(case_root, "IR1234", "HOST01"),
            Path("/cases/IR1234/systems/HOST01"),
        )
        self.assertEqual(
            layout.request_state_path(case_root, "IR1234", "HOST01", "triage-123"),
            Path("/cases/IR1234/systems/HOST01/collection/requests/triage-123/state.json"),
        )

    def test_collection_state_lookup_uses_only_current_layout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            collection.CASE_ROOT = Path(tmpdir)
            unsupported_state = (
                Path(tmpdir)
                / "case-123"
                / "evidence"
                / "systems"
                / "host01"
                / "velociraptor"
                / "host-collection"
                / "requests"
                / "request-1"
                / "state.json"
            )
            unsupported_state.parent.mkdir(parents=True)
            unsupported_state.write_text("{}\n", encoding="utf-8")

            resolved = collection.get_state_path("case-123", "host01", "request-1")

            self.assertEqual(
                resolved,
                Path(tmpdir)
                / "case-123"
                / "systems"
                / "host01"
                / "collection"
                / "requests"
                / "request-1"
                / "state.json",
            )
            self.assertFalse(resolved.exists())

    def test_write_state_uses_layout_v3_and_engagement_relative_references(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            collection.CASE_ROOT = Path(tmpdir)
            payload = {
                "request_id": "request-1",
                "client_id": "C.1234",
                "updated_at": "2026-08-06T00:00:00Z",
                "artifact_flows": {"Artifact.Test": {"flow_id": "F.1"}},
            }

            collection.write_state("case-123", "host01", payload)

            state_path = layout.request_state_path(
                collection.CASE_ROOT,
                "case-123",
                "host01",
                "request-1",
            )
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            current = json.loads(
                layout.current_state_path(
                    collection.CASE_ROOT,
                    "case-123",
                    "host01",
                ).read_text(encoding="utf-8")
            )
            identity = json.loads(
                layout.system_identity_path(
                    collection.CASE_ROOT,
                    "case-123",
                    "host01",
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(persisted["layout_version"], 3)
            self.assertEqual(
                persisted["state_file"],
                "systems/host01/collection/requests/request-1/state.json",
            )
            self.assertEqual(current["state_file"], "requests/request-1/state.json")
            self.assertEqual(identity["velociraptor_client_ids"], ["C.1234"])

    def test_write_state_rejects_system_identity_collision(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            collection.CASE_ROOT = Path(tmpdir)
            identity_path = layout.system_identity_path(
                collection.CASE_ROOT,
                "case-123",
                "host01",
            )
            identity_path.parent.mkdir(parents=True)
            identity_path.write_text(
                json.dumps({"hostname": "different-host"}) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "identity collision"):
                collection.write_state(
                    "case-123",
                    "host01",
                    {
                        "request_id": "request-1",
                        "client_id": "C.1234",
                        "artifact_flows": {},
                    },
                )


if __name__ == "__main__":
    unittest.main()
