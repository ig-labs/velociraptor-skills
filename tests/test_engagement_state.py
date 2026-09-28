from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vraptor import readiness_state as engagement_state
from vraptor import readiness, setup
from vraptor.hunt import command as hunt_workflow


class EngagementStateTest(unittest.TestCase):
    def write_api(
        self,
        root: Path,
        *,
        private_key: str = "key-one",
        valid_from: timedelta = timedelta(minutes=-1),
        valid_for: timedelta = timedelta(days=365),
    ) -> Path:
        path = root / "api.yaml"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "analyst")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + valid_from)
            .not_valid_after(now + valid_from + valid_for)
            .sign(key, hashes.SHA256())
        )
        path.write_text(
            yaml.safe_dump(
                {
                    "name": "analyst",
                    "api_connection_string": "velo.example:8001",
                    "ca_certificate": "test-ca",
                    "client_private_key": private_key,
                    "client_cert": certificate.public_bytes(
                        serialization.Encoding.PEM
                    ).decode(),
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def live_state(self, api: Path) -> dict:
        return engagement_state.build_state(
            engagement_id="EXAMPLE38",
            engagement_id_source="explicit",
            server_profile="lab7",
            mode="live_remote",
            source_skill="velociraptor-live-api-client",
            api_client_path=api,
            verification={
                "server_reachable": True,
                "target_visible": True,
                "scope_type": "label_scope",
                "matched_client_count": 3_000,
                "targets": [
                    {"client_id": "C.1", "hostname": "host01"},
                    {"client_id": "C.2", "hostname": "host02"},
                ],
                "api_user_provisioning": {
                    "status": "verified",
                    "api_user": "analyst",
                    "roles": ["administrator", "api"],
                    "role_profile": "provisioning-admin",
                    "effective_permissions": ["ANY_QUERY", "SUPER_USER"],
                },
            },
            next_step_hint="hunt",
        )

    def test_live_state_is_compact_and_validates_from_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            state = self.live_state(api)
            path = engagement_state.state_path(root, "EXAMPLE38")
            engagement_state.publish(path, state)

            self.assertEqual(path, root / "EXAMPLE38" / "engagement.json")
            self.assertEqual(state["schema_version"], 5)
            self.assertEqual(state["readiness"]["matched_client_count"], 3_000)
            self.assertNotIn("targets", state["readiness"])
            self.assertFalse(state["persistence"]["raw_evidence"])
            self.assertNotIn("derived", str(path))
            self.assertEqual(
                engagement_state.validate(
                    path=path,
                    engagement_id="example38",
                    server_profile="lab7",
                    api_client=api,
                    expected_org_id="root",
                )["engagement_fingerprint"],
                state["engagement_fingerprint"],
            )

    def test_credential_change_invalidates_readiness_but_not_server_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            state = self.live_state(api)
            path = engagement_state.state_path(root, "EXAMPLE38")
            engagement_state.publish(path, state)
            old_server = state["server"]["fingerprint"]

            self.write_api(root, private_key="key-two")
            self.assertEqual(
                engagement_state.api_metadata(api)["server_fingerprint"],
                old_server,
            )
            with self.assertRaisesRegex(RuntimeError, "content hash"):
                engagement_state.validate(
                    path=path,
                    engagement_id="EXAMPLE38",
                    server_profile="lab7",
                    api_client=api,
                )

    def test_live_state_rejects_status_setup_and_provisioning_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            path = engagement_state.state_path(root, "EXAMPLE38")
            mutations = (
                ("status", lambda state: state.update(status="error"), "status=error"),
                (
                    "source skill",
                    lambda state: state.update(source_skill=""),
                    "source_skill",
                ),
                (
                    "provisioning",
                    lambda state: state["readiness"].update(
                        api_user_provisioning={"status": "not_attempted"}
                    ),
                    "provisioning provenance",
                ),
            )
            for label, mutate, expected in mutations:
                with self.subTest(label=label):
                    state = self.live_state(api)
                    mutate(state)
                    engagement_state.publish(path, state)
                    with self.assertRaisesRegex(RuntimeError, expected):
                        engagement_state.validate(
                            path=path,
                            engagement_id="EXAMPLE38",
                            server_profile="lab7",
                            api_client=api,
                        )

    def test_live_site_readiness_allows_a_different_requested_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            path = engagement_state.state_path(root, "EXAMPLE38")
            state = self.live_state(api)
            engagement_state.publish(path, state)

            actual = engagement_state.validate(
                path=path,
                engagement_id="EXAMPLE38",
                server_profile="lab7",
                api_client=api,
                requested_client_id="C.another",
                requested_hostname="another-host",
            )

            self.assertEqual(actual["engagement_fingerprint"], state["engagement_fingerprint"])

    def test_live_server_readiness_records_empty_or_visible_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            provisioning = self.live_state(api)["readiness"]["api_user_provisioning"]
            for flags in ([], ["--environment-only-ok"]):
                for rows in ([], [{"client_id": "C.1", "Hostname": "host1"}]):
                    with self.subTest(flags=flags, visible=bool(rows)):
                        args = setup.parser().parse_args([
                            "start", "--mode", "live-remote", "--id", "EXAMPLE38",
                            "--server-profile", "lab7", "--api-client", str(api), *flags])
                        with patch.object(readiness, "verify_api_reachable", return_value=True), \
                             patch.object(readiness, "verify_api_authorization", return_value=dict(provisioning)), \
                             patch.object(readiness, "remote_query", return_value=rows) as query:
                            state = readiness._command_live_remote(args, root / "leaf.json")
                        query.assert_called_once()
                        self.assertEqual(state["status"], "ready")
                        self.assertEqual(state["readiness"]["target_visible"], bool(rows))
                        self.assertEqual(state["readiness"]["matched_client_count"], len(rows))
                        path = engagement_state.state_path(root, "EXAMPLE38")
                        engagement_state.publish(path, state)
                        engagement_state.validate(path=path, engagement_id="EXAMPLE38",
                                                  server_profile="lab7", api_client=api)

    def test_server_only_readiness_keeps_fail_closed_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            path = engagement_state.state_path(root, "EXAMPLE38")
            mutations = [
                (lambda s: s["readiness"].update(server_reachable=False), "server verification"),
                (lambda s: s["readiness"]["scope"].update(verification_method="hostname"), "target verification"),
                (lambda s: s["readiness"]["api_user_provisioning"].update(effective_permissions=[]), "administrator capability"),
                (lambda s: s["server"].update(fingerprint="other"), "server fingerprint"),
            ]
            for mutate, error in mutations:
                with self.subTest(error=error):
                    state = self.live_state(api)
                    state["readiness"]["scope"] = {"type": "site", "verification_method": "environment_only"}
                    state["readiness"]["target_visible"] = False
                    mutate(state)
                    engagement_state.publish(path, state)
                    with self.assertRaisesRegex(RuntimeError, error):
                        engagement_state.validate(path=path, engagement_id="EXAMPLE38",
                                                  server_profile="lab7", api_client=api)

    def test_explicit_live_target_still_requires_visibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            provisioning = self.live_state(api)["readiness"]["api_user_provisioning"]
            for flags in (["--hostname", "missing"], ["--client-id", "C.missing"],
                          ["--host-label", "missing"], ["--exclude-host-label", "excluded"]):
                with self.subTest(flags=flags):
                    args = setup.parser().parse_args([
                        "start", "--mode", "live-remote", "--id", "EXAMPLE38",
                        "--server-profile", "lab7", "--api-client", str(api), *flags])
                    with patch.object(readiness, "verify_api_reachable", return_value=True), \
                         patch.object(readiness, "verify_api_authorization", return_value=dict(provisioning)), \
                         patch.object(readiness, "remote_query", return_value=[]), \
                         self.assertRaisesRegex(RuntimeError, "not visible|no clients were visible"):
                        readiness._command_live_remote(args, root / "leaf.json")
                    visible = [{"client_id": "C.present", "Hostname": "present", "Labels": ["missing"]}]
                    with patch.object(readiness, "verify_api_reachable", return_value=True), \
                         patch.object(readiness, "verify_api_authorization", return_value=dict(provisioning)), \
                         patch.object(readiness, "remote_query", return_value=visible):
                        state = readiness._command_live_remote(args, root / "leaf.json")
                    self.assertTrue(state["readiness"]["target_visible"])
                    self.assertNotEqual(state["readiness"]["scope"]["verification_method"], "environment_only")

    def test_default_live_setup_propagates_connection_and_inventory_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            provisioning = self.live_state(api)["readiness"]["api_user_provisioning"]
            args = setup.parser().parse_args([
                "start", "--mode", "live-remote", "--id", "EXAMPLE38",
                "--server-profile", "lab7", "--api-client", str(api)])
            for failed_check in ("validate_api_client_security", "verify_api_reachable",
                                 "verify_api_authorization", "remote_query"):
                with self.subTest(failed_check=failed_check), \
                     patch.object(readiness, "verify_api_reachable", return_value=True), \
                     patch.object(readiness, "verify_api_authorization", return_value=dict(provisioning)), \
                     patch.object(readiness, "remote_query", return_value=[]), \
                     patch.object(readiness, failed_check, side_effect=RuntimeError("check failed")), \
                     self.assertRaisesRegex(RuntimeError, "check failed"):
                    readiness._command_live_remote(args, root / "leaf.json")

    def test_readiness_age_and_legacy_expiry_do_not_invalidate_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            path = engagement_state.state_path(root, "EXAMPLE38")
            state = self.live_state(api)
            self.assertNotIn("expires_at", state)
            for verified_at in ("2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"):
                with self.subTest(verified_at=verified_at):
                    state["verified_at"] = verified_at
                    state["expires_at"] = "2000-01-02T00:00:00Z"
                    engagement_state.publish(path, state)
                    actual = engagement_state.validate(
                        path=path, engagement_id="EXAMPLE38", server_profile="lab7",
                        api_client=api,
                    )
                    self.assertEqual(actual, state)

    def test_insecure_api_file_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            state = self.live_state(api)
            path = engagement_state.state_path(root, "EXAMPLE38")
            engagement_state.publish(path, state)
            api.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "remove group/other access"):
                engagement_state.validate(
                    path=path,
                    engagement_id="EXAMPLE38",
                    server_profile="lab7",
                    api_client=api,
                )

    def test_expired_api_certificate_fails_before_state_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(
                root,
                valid_from=timedelta(days=-2),
                valid_for=timedelta(days=1),
            )
            with self.assertRaisesRegex(RuntimeError, "certificate status is expired"):
                self.live_state(api)

    def test_certificate_inside_rotation_window_is_marked_expiring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root, valid_for=timedelta(days=10))
            state = self.live_state(api)
            self.assertEqual(
                state["api"]["credential_security"]["certificate_status"],
                "expiring",
            )
            self.assertLess(
                state["api"]["credential_security"]["certificate_days_remaining"],
                engagement_state.CERTIFICATE_WARNING_DAYS,
            )

    def test_schema_v3_requires_setup_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            state = self.live_state(api)
            state["schema_version"] = 3
            path = engagement_state.state_path(root, "EXAMPLE38")
            engagement_state.publish(path, state)
            with self.assertRaisesRegex(RuntimeError, "rerun Velociraptor engagement setup"):
                engagement_state.validate(
                    path=path,
                    engagement_id="EXAMPLE38",
                    server_profile="lab7",
                    api_client=api,
                )

    def test_dead_disk_state_is_bound_to_one_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            state = engagement_state.build_state(
                engagement_id="LAB7",
                engagement_id_source="explicit",
                server_profile="lab7",
                mode="local_dead_disk",
                source_skill="velociraptor-engagement-setup",
                api_client_path=api,
                verification={
                    "server_reachable": True,
                    "target_visible": True,
                    "scope_type": "client_id",
                    "client_id": "C.7",
                    "hostname": "disk-host",
                },
                next_step_hint="host",
            )
            path = engagement_state.state_path(root, "LAB7")
            engagement_state.publish(path, state)
            engagement_state.validate(
                path=path,
                engagement_id="LAB7",
                server_profile="lab7",
                api_client=api,
                requested_client_id="C.7",
            )
            with self.assertRaisesRegex(RuntimeError, "do not include C.other"):
                engagement_state.validate(
                    path=path,
                    engagement_id="LAB7",
                    server_profile="lab7",
                    api_client=api,
                    requested_client_id="C.other",
                )

            durable = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(durable["readiness"]["targets"]), 1)

    def test_hunt_live_gate_reuses_canonical_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.write_api(root)
            path = engagement_state.state_path(root, "EXAMPLE38")
            engagement_state.publish(path, self.live_state(api))
            args = hunt_workflow.argparse.Namespace(
                command="status",
                investigation_id="EXAMPLE38",
                api_client=str(api),
                server_profile="lab7",
                org_id="root",
                case_root=str(root),
                snapshot=None,
            )
            self.assertEqual(
                hunt_workflow.validate_live_engagement(args), path.resolve()
            )

            args.investigation_id = "EXAMPLE39"
            with self.assertRaisesRegex(RuntimeError, "readiness is not proven"):
                hunt_workflow.validate_live_engagement(args)


if __name__ == "__main__":
    unittest.main()
