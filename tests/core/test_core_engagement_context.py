from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vraptor import context as engagement_context
from vraptor import readiness_state as engagement_state


class EngagementContextTest(unittest.TestCase):
    def publish_ready(
        self,
        root: Path,
        *,
        engagement_id: str,
        server_profile: str,
        source: str,
    ) -> Path:
        api = root / f"{server_profile}_api_client.yaml"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "analyst")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        api.write_text(
            yaml.safe_dump(
                {
                    "name": "analyst",
                    "api_connection_string": "velo.example:8001",
                    "ca_certificate": "test-ca",
                    "client_private_key": "test-key",
                    "client_cert": certificate.public_bytes(serialization.Encoding.PEM).decode(),
                }
            ),
            encoding="utf-8",
        )
        api.chmod(0o600)
        payload = engagement_state.build_state(
            engagement_id=engagement_id,
            engagement_id_source=source,
            server_profile=server_profile,
            mode="live_remote",
            source_skill="velociraptor-live-api-client",
            api_client_path=api,
            verification={
                "server_reachable": True,
                "target_visible": True,
                "scope_type": "site",
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
        engagement_state.publish(
            engagement_state.state_path(root, engagement_id),
            payload,
        )
        return api

    def test_explicit_engagement_is_independent_of_server_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.publish_ready(
                root,
                engagement_id="ir9005",
                server_profile="lab7",
                source="explicit",
            )
            state_path = engagement_state.state_path(root, "ir9005")
            state = engagement_state.load(state_path)
            state["verified_at"] = "2000-01-01T00:00:00Z"
            state["expires_at"] = "2000-01-02T00:00:00Z"
            engagement_state.publish(state_path, state)
            context = engagement_context.resolve(
                repo_root=root,
                engagement_id="ir9005",
                server_profile="lab7",
                api_client=str(api),
                case_root=str(root),
            )
            self.assertEqual(context.engagement_dir, root.resolve() / "ir9005")
            self.assertEqual(context.server_profile, "lab7")
            self.assertEqual(context.engagement_id_source, "explicit")

    def test_server_profile_falls_back_to_engagement_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.publish_ready(
                root,
                engagement_id="lab7",
                server_profile="lab7",
                source="server_profile_fallback",
            )
            context = engagement_context.resolve(
                repo_root=root,
                engagement_id=None,
                server_profile="lab7",
                api_client=str(api),
                case_root=str(root),
            )
            self.assertEqual(context.engagement_id, "lab7")
            self.assertEqual(context.engagement_dir, root.resolve() / "lab7")

    def test_profile_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = self.publish_ready(
                root,
                engagement_id="ir9005",
                server_profile="lab7",
                source="explicit",
            )
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                engagement_context.resolve(
                    repo_root=root,
                    engagement_id="ir9005",
                    server_profile="other",
                    api_client=str(api),
                    case_root=str(root),
                )

    def test_neither_identifier_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Provide --engagement-id"):
            engagement_context.effective_engagement_id(None, None)


if __name__ == "__main__":
    unittest.main()
