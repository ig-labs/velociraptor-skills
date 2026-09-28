from __future__ import annotations

import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.artifacts import policy as artifact_policy
from vraptor.artifacts import policy_cli as artifact_policy_cli


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def profile_document(*, bias: str = "builtin") -> dict[str, object]:
    return {
        "schema_version": 4,
        "profiles": {
            "Artifact.Test": {
                "signal_type": "test",
                "selection": {"bias": bias},
                "review": {
                    "strategy": "direct",
                    "sample_fields": ["Value"],
                },
            }
        },
    }


def profile_overlay(*, bias: str) -> dict[str, object]:
    return {
        "schema_version": 4,
        "profiles": {
            "Artifact.Test": {"selection": {"bias": bias}}
        },
    }


def scenario_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scenarios": {
            "test-scenario": {
                "title": "Test scenario",
                "objective": "Test immutable policy loading.",
                "artifacts": [
                    {"artifact": "Artifact.Test", "role": "primary"}
                ],
            }
        },
    }


class ArtifactPolicyTests(unittest.TestCase):
    def load_from(
        self,
        root: Path,
        *,
        overlays: list[Path] | None = None,
    ) -> artifact_policy.ArtifactPolicySnapshot:
        profile_path = write_json(root / "profiles.json", profile_document())
        scenario_path = write_json(root / "scenarios.json", scenario_document())
        return artifact_policy.load_artifact_policy(
            overlays or [],
            [],
            environ={},
            builtin_profile_path=profile_path,
            builtin_scenario_path=scenario_path,
        )

    def test_snapshot_is_recursively_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))

        with self.assertRaisesRegex(TypeError, "immutable"):
            snapshot.profiles["Artifact.Test"] = {}  # type: ignore[index]
        with self.assertRaisesRegex(TypeError, "immutable"):
            snapshot.profiles["Artifact.Test"]["selection"]["bias"] = "changed"
        with self.assertRaisesRegex(TypeError, "immutable"):
            snapshot.profiles["Artifact.Test"]["review"]["sample_fields"].append(
                "Other"
            )

    def test_overlay_order_changes_resolution_and_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = write_json(root / "first.json", profile_overlay(bias="first"))
            second = write_json(root / "second.json", profile_overlay(bias="second"))
            forward = self.load_from(root, overlays=[first, second])
            reverse = self.load_from(root, overlays=[second, first])

        self.assertEqual(
            forward.profiles["Artifact.Test"]["selection"]["bias"],
            "second",
        )
        self.assertEqual(
            reverse.profiles["Artifact.Test"]["selection"]["bias"],
            "first",
        )
        self.assertNotEqual(forward.policy_sha256, reverse.policy_sha256)
        self.assertNotEqual(forward.profile_sha256, reverse.profile_sha256)

    def test_source_change_does_not_mutate_running_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            overlay = write_json(root / "overlay.json", profile_overlay(bias="one"))
            first = self.load_from(root, overlays=[overlay])
            write_json(overlay, profile_overlay(bias="two"))
            second = self.load_from(root, overlays=[overlay])

        self.assertEqual(
            first.profiles["Artifact.Test"]["selection"]["bias"],
            "one",
        )
        self.assertEqual(
            second.profiles["Artifact.Test"]["selection"]["bias"],
            "two",
        )
        self.assertNotEqual(first.policy_sha256, second.policy_sha256)

    def test_portable_hash_excludes_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = self.load_from(Path(first_dir))
            second = self.load_from(Path(second_dir))

        self.assertEqual(first.policy_sha256, second.policy_sha256)
        self.assertNotEqual(first.metadata()["sources"], second.metadata()["sources"])

    def test_each_source_is_read_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = artifact_policy.policy_sources.read_document
            with mock.patch.object(
                artifact_policy.policy_sources,
                "read_document",
                wraps=original,
            ) as reader:
                snapshot = self.load_from(root)

        self.assertEqual(reader.call_count, 2)
        self.assertEqual(len(snapshot.profiles), 1)
        self.assertEqual(len(snapshot.scenarios), 1)

    def test_operation_policy_rejects_references_with_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            with self.assertRaisesRegex(ValueError, "cannot be combined"):
                artifact_policy.resolve_operation_policy(
                    artifact_references=["overlay.json"],
                    policy_snapshot=snapshot,
                )

    def test_operation_policy_returns_injected_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            self.assertIs(
                artifact_policy.resolve_operation_policy(
                    policy_snapshot=snapshot,
                ),
                snapshot,
            )

    def test_injected_policy_does_not_read_files(self) -> None:
        snapshot = artifact_policy.build_artifact_policy(
            profiles={"Artifact.Test": {"enabled": True}},
            scenarios={"test": {"enabled": True}},
        )

        self.assertEqual(snapshot.profile_sources, ())
        self.assertEqual(snapshot.scenario_sources, ())
        self.assertEqual(snapshot.metadata()["profile_count"], 1)

    def test_portable_export_excludes_local_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            document = snapshot.resolved_document()

        encoded = json.dumps(document)
        self.assertNotIn(directory, encoded)
        self.assertEqual(
            document["artifact_policy"]["sha256"],
            snapshot.policy_sha256,
        )

    def test_policy_cli_exports_one_resolved_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self.load_from(root)
            output = root / "exports" / "artifact-policy.json"
            with mock.patch.object(
                artifact_policy_cli.artifact_policy,
                "load_artifact_policy",
                return_value=snapshot,
            ), contextlib.redirect_stdout(io.StringIO()):
                exit_code = artifact_policy_cli.main(
                    ["export", "--output", str(output)]
                )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            payload["artifact_policy"]["sha256"],
            snapshot.policy_sha256,
        )

    def test_policy_cli_validate_is_compact_and_show_includes_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            with mock.patch.object(
                artifact_policy_cli.artifact_policy,
                "load_artifact_policy",
                return_value=snapshot,
            ):
                validate_output = io.StringIO()
                with contextlib.redirect_stdout(validate_output):
                    validate_code = artifact_policy_cli.main(["validate"])
                show_output = io.StringIO()
                with contextlib.redirect_stdout(show_output):
                    show_code = artifact_policy_cli.main(["show"])

        validate = json.loads(validate_output.getvalue())
        show = json.loads(show_output.getvalue())
        self.assertEqual(validate_code, 0)
        self.assertEqual(show_code, 0)
        self.assertNotIn("sources", validate["artifact_policy"])
        self.assertEqual(len(show["artifact_policy"]["sources"]), 2)

    def test_policy_cli_explains_artifact_and_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            with mock.patch.object(
                artifact_policy_cli.artifact_policy,
                "load_artifact_policy",
                return_value=snapshot,
            ):
                artifact_output = io.StringIO()
                with contextlib.redirect_stdout(artifact_output):
                    artifact_code = artifact_policy_cli.main(
                        ["explain", "--artifact", "Artifact.Test"]
                    )
                scenario_output = io.StringIO()
                with contextlib.redirect_stdout(scenario_output):
                    scenario_code = artifact_policy_cli.main(
                        ["explain", "--scenario", "test-scenario"]
                    )

        artifact_result = json.loads(artifact_output.getvalue())
        scenario_result = json.loads(scenario_output.getvalue())
        self.assertEqual(artifact_code, 0)
        self.assertEqual(scenario_code, 0)
        self.assertEqual(artifact_result["kind"], "artifact_profile")
        self.assertEqual(scenario_result["kind"], "detection_scenario")

    def test_policy_cli_diff_check_reports_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self.load_from(root)
            export_path = write_json(
                root / "export.json",
                snapshot.resolved_document(),
            )
            changed_profiles = {
                "Artifact.Test": artifact_policy.artifact_profiles.validate_profile(
                    "Artifact.Test",
                    profile_document(bias="previous")["profiles"]["Artifact.Test"],
                    source=root / "changed-profile.json",
                )
            }
            changed_scenarios = {
                "test-scenario": artifact_policy.detection_scenarios.validate_scenario(
                    "test-scenario",
                    scenario_document()["scenarios"]["test-scenario"],
                    source=root / "changed-scenario.json",
                    profiles=changed_profiles,
                )
            }
            changed_snapshot = artifact_policy.build_artifact_policy(
                profiles=changed_profiles,
                scenarios=changed_scenarios,
                sources=snapshot.sources,
            )
            changed_document = changed_snapshot.resolved_document()
            changed_path = write_json(root / "changed.json", changed_document)
            with mock.patch.object(
                artifact_policy_cli.artifact_policy,
                "load_artifact_policy",
                return_value=snapshot,
            ):
                identical_output = io.StringIO()
                with contextlib.redirect_stdout(identical_output):
                    identical_code = artifact_policy_cli.main(
                        ["diff", "--against", str(export_path), "--check"]
                    )
                changed_output = io.StringIO()
                with contextlib.redirect_stdout(changed_output):
                    changed_code = artifact_policy_cli.main(
                        ["diff", "--against", str(changed_path), "--check"]
                    )

        identical = json.loads(identical_output.getvalue())
        changed = json.loads(changed_output.getvalue())
        self.assertEqual(identical_code, 0)
        self.assertFalse(identical["different"])
        self.assertEqual(changed_code, artifact_policy_cli.DIFF_EXIT_CODE)
        self.assertEqual(changed["profiles"]["changed"], ["Artifact.Test"])

    def test_portable_export_rejects_tampered_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            document = snapshot.resolved_document()
            document["profiles"]["Artifact.Test"]["selection"]["bias"] = "tampered"

            with self.assertRaisesRegex(RuntimeError, "identity is inconsistent"):
                artifact_policy.validate_portable_document(
                    document,
                    source=Path(directory) / "tampered.json",
                )

    def test_portable_export_rejects_inconsistent_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            document = snapshot.resolved_document()
            document["artifact_policy"]["profile_count"] = 99

            with self.assertRaisesRegex(RuntimeError, "profile_count is inconsistent"):
                artifact_policy.validate_portable_document(
                    document,
                    source=Path(directory) / "counts.json",
                )

    def test_portable_export_rejects_local_paths_and_source_reordering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            document = snapshot.resolved_document()
            document["artifact_policy"]["sources"][0]["path"] = "/local/path"
            with self.assertRaisesRegex(RuntimeError, "must contain exactly"):
                artifact_policy.validate_portable_document(
                    document,
                    source=Path(directory) / "local-path.json",
                )

            reordered = snapshot.resolved_document()
            reordered["artifact_policy"]["sources"].reverse()
            with self.assertRaisesRegex(RuntimeError, "canonically ordered"):
                artifact_policy.validate_portable_document(
                    reordered,
                    source=Path(directory) / "reordered.json",
                )

    def test_policy_diff_detects_ordered_source_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot = self.load_from(Path(directory))
            previous = snapshot.resolved_document()
            previous["artifact_policy"]["sha256"] = "0" * 64
            result = artifact_policy_cli.diff_payload(
                snapshot,
                previous,
                source=Path(directory) / "previous.json",
            )

        self.assertTrue(result["different"])
        self.assertTrue(result["identity_changed"])
        self.assertEqual(result["profiles"]["changed"], [])
        self.assertEqual(result["scenarios"]["changed"], [])


if __name__ == "__main__":
    unittest.main()
