import base64
import contextlib
import csv
import gzip
import hashlib
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import golden
from vraptor.analyze import flow as flow_analysis
from vraptor.hunt import live


class FakeInventoryApi:
    def __init__(self, *, verified_hash=None):
        self.calls = []
        self.uploaded_bytes = b""
        self.uploaded_hash = ""
        self.verified_hash = verified_hash
        self.inventory = {}

    def query(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        if "inventory_add" in vql:
            self.uploaded_bytes = gzip.decompress(
                base64.b64decode(env["DatabaseGzipBase64"])
            )
            self.uploaded_hash = hashlib.sha256(
                self.uploaded_bytes
            ).hexdigest()
            self.inventory[(env["ToolName"], env["ToolVersion"])] = self.uploaded_hash
            return [
                {
                    "Published": {
                        "name": env["ToolName"],
                        "version": env["ToolVersion"],
                        "hash": self.uploaded_hash,
                    }
                }
            ]
        return [
            {
                "Definition": {
                    "name": env["ToolName"],
                    "version": env["ToolVersion"],
                    "filestore_path": "inventory/path",
                    "hash": self.verified_hash or self.uploaded_hash,
                }
            }
        ]


class FakeCandidateApi:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def query_batches(self, vql, env=None, **kwargs):
        self.calls.append((vql, dict(env or {}), kwargs))
        yield list(self.rows)


def write_rmm_reference(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "executables": ["anydesk.exe", "screenconnect*.exe"],
                "installation_paths": [r"*\anydesk\*"],
                "tools": [],
            }
        ),
        encoding="utf-8",
    )


def render_potential_csv(
    *,
    golden_sha256: str,
    rows: list[dict[str, object]],
    source_stack_sha256: str = "stack-sha256",
    source_query_sha256: str = "query-sha256",
    source_group_count: int = 10,
    engagement_id: str = "IR1",
    hunt_id: str = "H.1",
    artifact: str = "IG.Windows.Sysinternals.Autoruns",
) -> str:
    return live.render_csv_with_metadata(
        metadata={
            "SchemaVersion": 2,
            "CanonicalizationVersion": autoruns.CANONICALIZATION_VERSION,
            "EngagementId": engagement_id,
            "HuntId": hunt_id,
            "Artifact": artifact,
            "SourceStackSHA256": source_stack_sha256,
            "SourceQuerySHA256": source_query_sha256,
            "GoldenDBSHA256": golden_sha256,
            "GoldenDBVersion": "20260824-test",
            "SourceGroupCount": source_group_count,
            "ReviewedGroupCount": source_group_count,
            "ReviewComplete": "true",
        },
        fieldnames=live.AUTORUNS_POTENTIAL_GOLDEN_FIELDS,
        rows=rows,
    )


class AutorunsGoldenTest(unittest.TestCase):
    def test_context_normalization_is_idempotent_at_truncation_boundary(self):
        value = ("A" * 255) + " B"
        first = autoruns.normalize_context_value(value, max_length=256)
        second = autoruns.normalize_context_value(first, max_length=256)
        self.assertEqual(first, second)
        self.assertFalse(first.endswith(" "))

    def test_publish_defaults_to_canonical_tool_name(self):
        args = golden.parser().parse_args(
            [
                "publish",
                "--db",
                "golden.sqlite",
                "--api-client",
                "api.yaml",
            ]
        )

        self.assertEqual(args.tool_name, "Autoruns.GoldenDB")

    def test_simplified_commands_hide_publish_version(self):
        promote = golden.parser().parse_args(
            [
                "promote",
                "--id",
                "IR1",
                "--hunt-id",
                "H.1",
                "--input",
                "reviewed.csv",
                "--db",
                "golden.sqlite",
            ]
        )
        push = golden.parser().parse_args(
            [
                "push",
                "--db",
                "golden.sqlite",
                "--api-client",
                "api.yaml",
            ]
        )

        self.assertIsNone(promote.artifact)
        self.assertFalse(hasattr(push, "tool_version"))
        self.assertFalse(hasattr(push, "tool_name"))

    def test_publication_commands_use_current_unless_explicitly_pinned(self):
        for command, extra, expected in (
            ("push", [], "current"),
            ("publish", [], "current"),
            ("publish", ["--tool-version", "20260728-pinned"], "20260728-pinned"),
        ):
            with (
                self.subTest(command=command, version=expected),
                mock.patch.object(golden.velociraptor_api, "VeloApiClient"),
                mock.patch.object(golden.dfir_paths, "resolve_velociraptor_api_client_path",
                                  return_value=Path("/unused/api.yaml")),
                mock.patch.object(golden, "publish_database", return_value={}) as publish,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                golden.main([command, "--db", "/unused/golden.sqlite",
                             "--api-client", "/unused/api.yaml", *extra])
                self.assertEqual(publish.call_args.kwargs["tool_version"], expected)

    def test_simplified_commands_default_to_shared_database(self):
        promote = golden.parser().parse_args(
            [
                "promote",
                "--input",
                "reviewed.csv",
            ]
        )
        filter_args = golden.parser().parse_args(
            [
                "filter",
                "--input",
                "autoruns.csv",
            ]
        )

        self.assertIsNone(promote.db)
        self.assertIsNone(filter_args.db)

    def test_offline_import_applies_exact_and_regex_rules_without_api(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "golden.sqlite"
            exact_input = root / "reviewed-enriched.csv"
            regex_input = root / "reviewed-regex.csv"
            golden.promote_records(baseline, [])
            image_path = r"c:\program files\vendor\app\1.2\service.exe"
            launch_string = image_path + " --service"
            hash_key = autoruns.trusted_key(
                signer="(verified) vendor corporation",
                image_path=image_path,
                launch_string=launch_string,
            )
            exact_buffer = io.StringIO()
            exact_writer = csv.DictWriter(
                exact_buffer,
                fieldnames=(
                    "HashKey",
                    "ImagePath",
                    "LaunchString",
                    "Signer",
                    "Description",
                ),
                lineterminator="\n",
            )
            exact_writer.writeheader()
            exact_writer.writerow(
                {
                    "HashKey": hash_key,
                    "ImagePath": image_path,
                    "LaunchString": launch_string,
                    "Signer": "(verified) vendor corporation",
                    "Description": "Reviewed vendor service.",
                }
            )
            exact_input.write_text(
                "# OfflineReview: approved\n" + exact_buffer.getvalue(),
                encoding="utf-8",
            )
            regex_buffer = io.StringIO()
            regex_writer = csv.DictWriter(
                regex_buffer,
                fieldnames=(
                    "image_path_regex",
                    "launch_string_regex",
                    "description",
                ),
                lineterminator="\n",
            )
            regex_writer.writeheader()
            regex_writer.writerow(
                {
                    "image_path_regex": (
                        r"c:\\program files\\vendor\\app\\[0-9.]+\\service\.exe"
                    ),
                    "launch_string_regex": (
                        r"c:\\program files\\vendor\\app\\[0-9.]+\\service\.exe --service"
                    ),
                    "description": "Reviewed version-variable vendor service.",
                }
            )
            regex_input.write_text(
                regex_buffer.getvalue(),
                encoding="utf-8",
            )
            dry_args = golden.parser().parse_args(
                [
                    "import",
                    "--db",
                    str(baseline),
                    "--input",
                    str(exact_input),
                    "--regex-input",
                    str(regex_input),
                    "--dry-run",
                ]
            )
            before = golden.file_sha256(baseline)
            with mock.patch.object(
                golden.velociraptor_api,
                "VeloApiClient",
                side_effect=AssertionError("unexpected API access"),
            ):
                dry_run = golden.import_offline_rules(dry_args)
            self.assertEqual(golden.file_sha256(baseline), before)
            self.assertEqual(
                dry_run["application"]["changes"]["new_identity_count"],
                1,
            )
            self.assertEqual(
                dry_run["application"]["changes"]["new_regex_rule_count"],
                1,
            )

            apply_args = golden.parser().parse_args(
                [
                    "import",
                    "--db",
                    str(baseline),
                    "--input",
                    str(exact_input),
                    "--regex-input",
                    str(regex_input),
                ]
            )
            with mock.patch.object(
                golden.velociraptor_api,
                "VeloApiClient",
                side_effect=AssertionError("unexpected API access"),
            ):
                applied = golden.import_offline_rules(apply_args)
            report = golden.validate_database(baseline)
            backup = Path(applied["application"]["backup"])
            backup_exists = backup.is_file()

        self.assertTrue(applied["offline"])
        self.assertTrue(applied["application"]["installed"])
        self.assertTrue(applied["publication_required"])
        self.assertTrue(backup_exists)
        self.assertEqual(report["identity_count"], 1)
        self.assertEqual(report["regex_rule_count"], 1)

    def test_offline_import_rejects_mismatched_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "golden.sqlite"
            exact_input = root / "reviewed-enriched.csv"
            golden.promote_records(baseline, [])
            exact_input.write_text(
                "HashKey,Category,ImagePath,LaunchString,Signer\n"
                + "0" * 40
                + r",Services,c:\vendor\app.exe,c:\vendor\app.exe,(verified) vendor"
                + "\n",
                encoding="utf-8",
            )
            args = golden.parser().parse_args(
                [
                    "import",
                    "--db",
                    str(baseline),
                    "--input",
                    str(exact_input),
                ]
            )

            with self.assertRaisesRegex(RuntimeError, "HashKey does not match"):
                golden.import_offline_rules(args)

    def test_promote_infers_case_context_from_standard_candidate_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            case_root = Path(temp_dir) / "cases"
            selected = (
                case_root
                / "IR1"
                / "hunts"
                / "H.1"
                / "analysis"
                / "autoruns_potential_golden_reviewed.csv"
            )
            selected.parent.mkdir(parents=True)
            selected.write_text(
                render_potential_csv(golden_sha256="a" * 64, rows=[]),
                encoding="utf-8",
            )
            args = golden.parser().parse_args(
                ["promote", "--input", str(selected)]
            )

            golden.resolve_promotion_source_args(args)

        self.assertEqual(args.investigation_id, "IR1")
        self.assertEqual(args.hunt_id, "H.1")
        self.assertEqual(
            args.artifact,
            "IG.Windows.Sysinternals.Autoruns",
        )
        self.assertEqual(Path(args.case_root).resolve(), case_root.resolve())

    def test_promote_infers_source_from_moved_candidate_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            selected = Path(temp_dir) / "saved-reviewed.csv"
            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[],
                    engagement_id="IR77",
                    hunt_id="H.77",
                    artifact="Windows.Sysinternals.Autoruns",
                ),
                encoding="utf-8",
            )
            args = golden.parser().parse_args(
                ["promote", "--input", str(selected)]
            )

            golden.resolve_promotion_source_args(args)

        self.assertEqual(args.investigation_id, "IR77")
        self.assertEqual(args.hunt_id, "H.77")
        self.assertEqual(args.artifact, "Windows.Sysinternals.Autoruns")
        self.assertIsNone(args.case_root)

    def test_promote_rejects_candidate_path_provenance_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            selected = (
                Path(temp_dir)
                / "IR1"
                / "hunts"
                / "H.1"
                / "analysis"
                / "reviewed.csv"
            )
            selected.parent.mkdir(parents=True)
            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[],
                    engagement_id="IR2",
                ),
                encoding="utf-8",
            )
            args = golden.parser().parse_args(
                ["promote", "--input", str(selected)]
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "does not match path-derived provenance",
            ):
                golden.resolve_promotion_source_args(args)

    def test_promote_requires_explicit_reviewed_input(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
            SystemExit
        ):
            golden.parser().parse_args(
                [
                    "promote",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                ]
            )
        args = golden.parser().parse_args(
            [
                "promote",
                "--id",
                "IR1",
                "--hunt-id",
                "H.1",
                "--input",
                "reviewed.csv",
                "--dry-run",
            ]
        )
        self.assertEqual(args.input, "reviewed.csv")
        self.assertTrue(args.dry_run)
        for removed_command in ("create", "update"):
            with contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                golden.parser().parse_args([removed_command])

    def test_candidate_subset_accepts_deletions_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            canonical = root / "autoruns_potential_golden.csv"
            selected = root / "reviewed.csv"
            rows = [
                {
                    "ImagePath": r"c:\vendor\one.exe",
                    "LaunchString": "one.exe",
                    "Signer": "(verified) vendor",
                    "Total": 2,
                    "Reason": "Expected vendor software.",
                },
                {
                    "ImagePath": r"c:\vendor\two.exe",
                    "LaunchString": "two.exe",
                    "Signer": "(verified) vendor",
                    "Total": 1,
                    "Reason": "Expected vendor software.",
                },
            ]
            canonical.write_text(
                render_potential_csv(golden_sha256="a" * 64, rows=rows),
                encoding="utf-8",
            )
            selected.write_text(
                render_potential_csv(golden_sha256="a" * 64, rows=rows[:1]),
                encoding="utf-8",
            )

            result = golden.validate_candidate_subset(
                canonical,
                selected,
                live=live,
            )

            self.assertEqual(result["canonical_row_count"], 2)
            self.assertEqual(result["selected_row_count"], 1)
            self.assertEqual(result["removed_row_count"], 1)

            edited = dict(rows[0])
            edited["Reason"] = "Changed reason."
            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[edited],
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "added or edited"):
                golden.validate_candidate_subset(
                    canonical,
                    selected,
                    live=live,
                )

    def test_candidate_subset_rejects_metadata_edits_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            canonical = root / "autoruns_potential_golden.csv"
            selected = root / "reviewed.csv"
            row = {
                "ImagePath": r"c:\vendor\app.exe",
                "LaunchString": "app.exe",
                "Signer": "(verified) vendor",
                "Total": 2,
                "Reason": "Expected vendor software.",
            }
            canonical.write_text(
                render_potential_csv(golden_sha256="a" * 64, rows=[row]),
                encoding="utf-8",
            )
            selected.write_text(
                render_potential_csv(golden_sha256="b" * 64, rows=[row]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "comments and header"):
                golden.validate_candidate_subset(
                    canonical,
                    selected,
                    live=live,
                )

            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[row],
                ).replace("# SchemaVersion: 2", "# SchemaVersion:   2"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "comments and header"):
                golden.validate_candidate_subset(
                    canonical,
                    selected,
                    live=live,
                )

            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[row, row],
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "duplicate row"):
                golden.validate_candidate_subset(
                    canonical,
                    selected,
                    live=live,
                )

            second = dict(row)
            second["ImagePath"] = r"c:\vendor\second.exe"
            canonical.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[row, second],
                ),
                encoding="utf-8",
            )
            selected.write_text(
                render_potential_csv(
                    golden_sha256="a" * 64,
                    rows=[second, row],
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "row order"):
                golden.validate_candidate_subset(
                    canonical,
                    selected,
                    live=live,
                )

    def test_promote_running_ad_hoc_hunt_accepts_retained_unverified_row(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "golden.sqlite"
            golden.promote_records(baseline, [])
            baseline_sha256 = golden.file_sha256(baseline)
            paths = golden.autoruns_analysis_paths(
                case_root=root,
                investigation_id="IR1",
                hunt_id="H.1",
            )
            paths["root"].mkdir(parents=True)
            candidate = {
                "ImagePath": r"c:\vendor\app.exe",
                "LaunchString": r"c:\vendor\app.exe --service",
                "Signer": "(not verified) vendor corporation",
                "Total": 1,
                "Reason": "Expected signed vendor service.",
            }
            canonical_text = render_potential_csv(
                golden_sha256=baseline_sha256,
                rows=[candidate],
            )
            paths["potential_golden"].write_text(
                canonical_text,
                encoding="utf-8",
            )
            selected = root / "reviewed.csv"
            selected.write_text(canonical_text, encoding="utf-8")
            state = {
                "schema_version": flow_analysis.SCHEMA_VERSION,
                "specialized_analysis": {
                    "hunt_id": "H.1",
                    "hunt_state": "RUNNING",
                    "review_scope": "ad_hoc_review",
                    "target_execution_coverage": "not_assessed",
                    "artifacts": {
                        "IG.Windows.Sysinternals.Autoruns": {
                            "autoruns_residual_workflow": {
                                "stack": {
                                    "sha256": "stack-sha256",
                                    "query_hash": "query-sha256",
                                    "group_count": 10,
                                },
                                "classification": {
                                    "potential_golden": {
                                        "sha256": golden.file_sha256(
                                            paths["potential_golden"]
                                        ),
                                        "row_count": 1,
                                        "reviewed_group_count": 10,
                                    }
                                },
                            }
                        }
                    },
                },
            }
            state_path = paths["root"] / "hunt-analysis-state.json"
            state_path.write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            api_client = root / "api.yaml"
            api_client.touch()
            enriched = {
                "HashKey": autoruns.trusted_key(
                    signer=candidate["Signer"],
                    image_path=candidate["ImagePath"],
                    launch_string=candidate["LaunchString"],
                ),
                "Category": "Services",
                "ImagePath": candidate["ImagePath"],
                "LaunchString": candidate["LaunchString"],
                "Signer": candidate["Signer"],
                "EntryLocation": r"HKLM\System\Services\Vendor",
                "Entry": "Vendor Service",
                "Description": "Vendor service",
                "Company": "Vendor Corporation",
                "Total": 1,
            }
            fake_api = FakeCandidateApi([enriched])
            args = golden.parser().parse_args(
                [
                    "promote",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                    "--db",
                    str(baseline),
                    "--case-root",
                    str(root),
                    "--api-client",
                    str(api_client),
                    "--input",
                    str(selected),
                    "--dry-run",
                ]
            )
            before = golden.file_sha256(baseline)
            with (
                mock.patch.object(
                    golden.velociraptor_api,
                    "VeloApiClient",
                    return_value=fake_api,
                ),
                mock.patch(
                    "vraptor.hunt.command.resolve_api_client",
                    return_value=api_client,
                ),
            ):
                dry_run = golden.promote_analysis_candidates(args)
                state["specialized_analysis"][
                    "review_scope"
                ] = "managed_collection"
                state_path.write_text(json.dumps(state), encoding="utf-8")
                with self.assertRaisesRegex(
                    RuntimeError,
                    "requires complete target execution coverage for managed",
                ):
                    golden.promote_analysis_candidates(args)
                state["specialized_analysis"][
                    "review_scope"
                ] = "ad_hoc_review"
                state_path.write_text(json.dumps(state), encoding="utf-8")
                golden.promote_records(
                    baseline,
                    [
                        {
                            "Category": "Services",
                            "ImagePath": r"c:\vendor\unrelated.exe",
                            "LaunchString": r"c:\vendor\unrelated.exe",
                            "Signer": "(verified) unrelated vendor",
                            "Description": "Unrelated current baseline entry.",
                        }
                    ],
                )
                drifted_sha256 = golden.file_sha256(baseline)
                args.dry_run = False
                applied = golden.promote_analysis_candidates(args)
                applied_sha256 = golden.file_sha256(baseline)
                replay = golden.promote_analysis_candidates(args)
                replay_sha256 = golden.file_sha256(baseline)

            manifest = json.loads(
                paths["delta_manifest"].read_text(encoding="utf-8")
            )
            canonical_after = golden.file_sha256(paths["potential_golden"])
            after_sha256 = golden.file_sha256(baseline)
            backup_exists = Path(applied["application"]["backup"]).is_file()

        self.assertTrue(fake_api.calls)
        for query, _, _ in fake_api.calls:
            self.assertIn("SELECT HashKey, Category, ImagePath, LaunchString, Signer,", query)
            self.assertIn("GROUP BY HashKey, Category, ImagePath, LaunchString, Signer,", query)
        self.assertEqual(
            after_sha256,
            applied["application"]["after"]["sha256"],
        )
        self.assertEqual(dry_run["application"]["after"], {})
        self.assertEqual(dry_run["application"]["before"]["sha256"], before)
        self.assertEqual(applied["staging"]["canonical_candidate_count"], 1)
        self.assertEqual(applied["staging"]["removed_candidate_count"], 0)
        self.assertEqual(
            applied["staging"]["operator_approved_priority_rows"],
            [{"row_number": 1, "reasons": ["unverified-signer"]}],
        )
        self.assertEqual(
            canonical_after,
            hashlib.sha256(canonical_text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(applied["application"]["changes"]["new_identity_count"], 1)
        self.assertTrue(backup_exists)
        self.assertNotEqual(drifted_sha256, before)
        self.assertFalse(
            manifest["candidate_review"]["source_baseline_matches"]
        )
        self.assertEqual(replay_sha256, applied_sha256)
        self.assertTrue(replay["application"]["no_changes"])
        self.assertTrue(replay["application"]["idempotent_replay"])
        self.assertEqual(
            replay["reconciliation"]["counts"],
            {"already_applied": 1},
        )
        self.assertEqual(
            replay["reconciliation"]["rows"][0]["status"],
            "already_applied",
        )
        self.assertEqual(manifest["status"], "applied")
        self.assertEqual(
            manifest["candidate_review"]["selected_path"],
            str(selected.resolve()),
        )
        self.assertEqual(
            manifest["candidate_review"]["operator_approved_priority_rows"],
            [{"row_number": 1, "reasons": ["unverified-signer"]}],
        )

    def test_promote_does_not_replace_database_when_delta_has_no_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "golden.sqlite"
            delta = root / "delta.sqlite"
            manifest_path = root / "delta.json"
            golden.promote_records(baseline, [])
            golden.promote_records(delta, [], baseline_databases=[baseline])
            manifest_path.write_text("{}\n", encoding="utf-8")
            before = golden.file_sha256(baseline)
            args = SimpleNamespace(
                input=str(root / "reviewed.csv"),
                db=str(baseline),
                dry_run=False,
                backup_dir=None,
                rmm_reference=None,
            )
            staged = {
                "delta": str(delta),
                "delta_manifest": str(manifest_path),
            }

            with mock.patch.object(
                golden,
                "stage_analysis_candidates",
                return_value=staged,
            ):
                result = golden.promote_analysis_candidates(args)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            backups = list((root / "backups").glob("*.sqlite"))
            after = golden.file_sha256(baseline)

        self.assertEqual(after, before)
        self.assertFalse(result["publication_required"])
        self.assertFalse(result["application"]["dry_run"])
        self.assertFalse(result["application"]["installed"])
        self.assertTrue(result["application"]["no_changes"])
        self.assertEqual(manifest["status"], "no_changes")
        self.assertEqual(backups, [])

    def test_promote_empty_review_skips_live_query_and_database_replace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            baseline = root / "golden.sqlite"
            golden.promote_records(baseline, [])
            baseline_sha256 = golden.file_sha256(baseline)
            paths = golden.autoruns_analysis_paths(
                case_root=root,
                investigation_id="IR1",
                hunt_id="H.1",
            )
            paths["root"].mkdir(parents=True)
            canonical_text = render_potential_csv(
                golden_sha256=baseline_sha256,
                rows=[],
                source_group_count=0,
            )
            paths["potential_golden"].write_text(
                canonical_text,
                encoding="utf-8",
            )
            selected = root / "reviewed-empty.csv"
            selected.write_text(canonical_text, encoding="utf-8")
            state = {
                "schema_version": flow_analysis.SCHEMA_VERSION,
                "specialized_analysis": {
                    "hunt_id": "H.1",
                    "hunt_state": "FINISHED",
                    "target_execution_coverage": "complete",
                    "artifacts": {
                        "IG.Windows.Sysinternals.Autoruns": {
                            "autoruns_residual_workflow": {
                                "stack": {
                                    "sha256": "stack-sha256",
                                    "query_hash": "query-sha256",
                                    "group_count": 0,
                                },
                                "classification": {
                                    "potential_golden": {
                                        "sha256": golden.file_sha256(
                                            paths["potential_golden"]
                                        ),
                                        "row_count": 0,
                                        "reviewed_group_count": 0,
                                    }
                                },
                            }
                        }
                    },
                },
            }
            (paths["root"] / "hunt-analysis-state.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            args = golden.parser().parse_args(
                [
                    "promote",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                    "--db",
                    str(baseline),
                    "--case-root",
                    str(root),
                    "--input",
                    str(selected),
                ]
            )
            before = golden.file_sha256(baseline)

            with (
                mock.patch.object(
                    golden.velociraptor_api,
                    "VeloApiClient",
                    side_effect=AssertionError("unexpected live query"),
                ),
                mock.patch(
                    "vraptor.hunt.command.resolve_api_client",
                    side_effect=AssertionError("unexpected API resolution"),
                ),
            ):
                result = golden.promote_analysis_candidates(args)

            after = golden.file_sha256(baseline)

        self.assertEqual(after, before)
        self.assertEqual(result["staging"]["candidate_count"], 0)
        self.assertEqual(result["staging"]["enriched_row_count"], 0)
        self.assertTrue(result["application"]["no_changes"])
        self.assertFalse(result["publication_required"])

    def test_build_normalizes_deduplicates_and_excludes_non_promotable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "autoruns.json"
            rmm_path = root / "rmm.json"
            database = root / "golden.sqlite"
            write_rmm_reference(rmm_path)
            rows = [
                {
                    "Category": "Logon",
                    "EntryLocation": (
                        r"HKU\S-1-5-21-111-222-333-1001"
                        r"\Software\Vendor"
                    ),
                    "Entry": "Vendor App",
                    "Description": "D" * 300,
                    "Company": "Vendor Incorporated",
                    "Signer": "(Verified) Vendor",
                    "ImagePath": r"C:\Users\Alice\App.exe",
                    "LaunchString": r"C:\Users\Alice\App.exe /quiet",
                },
                {
                    "Category": "Scheduled Tasks",
                    "EntryLocation": (
                        r"HKU\S-1-5-21-444-555-666-1002"
                        r"\Software\Vendor"
                    ),
                    "Entry": "Vendor App",
                    "Description": "D" * 300,
                    "Company": "Vendor Incorporated",
                    "Signer": "(verified) vendor",
                    "ImagePath": r"C:\Users\Bob\App.exe",
                    "LaunchString": r"C:\Users\Bob\App.exe /QUIET",
                },
                {
                    "Category": "Services",
                    "Signer": "(Verified) AnyDesk",
                    "ImagePath": r"C:\Program Files\AnyDesk\AnyDesk.exe",
                    "LaunchString": r'"C:\Program Files\AnyDesk\AnyDesk.exe"',
                },
                {
                    "Category": "Drivers",
                    "Signer": "",
                    "ImagePath": "File not found: stale.sys",
                    "LaunchString": "",
                },
            ]
            input_path.write_text(json.dumps(rows), encoding="utf-8")

            result = golden.build_database(
                database,
                [input_path],
                rmm_reference=rmm_path,
            )
            report = golden.validate_database(
                database,
                rmm_reference=rmm_path,
            )

            self.assertEqual(result["inserted"], 1)
            self.assertEqual(result["existing"], 1)
            self.assertEqual(result["skipped_non_promotable"], 1)
            self.assertEqual(result["skipped_missing_file"], 1)
            self.assertEqual(report["identity_count"], 1)
            self.assertEqual(report["record_count"], 1)
            self.assertEqual(report["description_count"], 1)
            connection = sqlite3.connect(database)
            connection.row_factory = sqlite3.Row
            try:
                records = list(connection.execute(
                    """
                    SELECT description, modified_time
                    FROM autoruns_known_good
                    """
                ))
            finally:
                connection.close()
            self.assertEqual(len(records), 1)
            self.assertEqual(len(records[0]["description"]), 256)
            self.assertEqual(
                records[0]["description"],
                "D" * 256,
            )
            self.assertTrue(all(row["modified_time"] for row in records))

    def test_build_rejects_mismatched_supplied_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "autoruns.json"
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            input_path.write_text(
                json.dumps(
                    [
                        {
                            "HashKey": "a" * 40,
                            "Category": "Logon",
                            "Signer": "Vendor",
                            "ImagePath": r"C:\Vendor\App.exe",
                            "LaunchString": "app.exe",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "does not match"):
                golden.build_database(
                    root / "golden.sqlite",
                    [input_path],
                    rmm_reference=rmm_path,
                )

    def test_merge_unions_identities_ignoring_categories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            first = root / "first.sqlite"
            second = root / "second.sqlite"
            merged = root / "merged.sqlite"
            common = {
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe /service",
            }
            golden.promote_records(
                first,
                [{**common, "Category": "Logon"}],
                rmm_reference=rmm_path,
                modified_time="2026-01-01T00:00:00Z",
            )
            golden.promote_records(
                second,
                [
                    {**common, "Category": "Services"},
                    {
                        "Category": "Drivers",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\Driver.exe",
                        "LaunchString": "driver.exe",
                    },
                ],
                rmm_reference=rmm_path,
                modified_time="2026-02-01T00:00:00Z",
            )

            result = golden.merge_databases(
                merged,
                [second, first],
                rmm_reference=rmm_path,
            )

            self.assertEqual(result["identity_count"], 2)
            self.assertEqual(result["record_count"], 2)
            common_hash = autoruns.trusted_key(
                signer=common["Signer"],
                image_path=common["ImagePath"],
                launch_string=common["LaunchString"],
            )
            self.assertEqual(
                golden.lookup_hashes(merged, [common_hash])[0][
                    "modified_time"
                ],
                "2026-02-01T00:00:00Z",
            )

    def test_remove_hash_rejects_category_scope_then_removes_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            record = {
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe /service",
            }
            golden.promote_records(
                database,
                [
                    {**record, "Category": "Logon"},
                    {**record, "Category": "Services"},
                ],
                rmm_reference=rmm_path,
            )
            hash_key = autoruns.trusted_key(
                signer=record["Signer"],
                image_path=record["ImagePath"],
                launch_string=record["LaunchString"],
            )

            before = database.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "[Cc]ategory"):
                golden.remove_hashes(
                    database, [hash_key], category="Logon",
                    rmm_reference=rmm_path,
                )
            self.assertEqual(database.read_bytes(), before)
            help_output = io.StringIO()
            with contextlib.redirect_stdout(help_output), self.assertRaises(SystemExit):
                golden.parser().parse_args(["remove", "--help"])
            self.assertNotIn("--category", help_output.getvalue())
            removed = golden.remove_hashes(
                database,
                [hash_key],
                rmm_reference=rmm_path,
            )
            after = golden.lookup_hashes(
                database,
                [hash_key],
            )[0]

        self.assertEqual(removed["removed_identity_count"], 1)
        self.assertFalse(after["known_good"])

    def test_remove_hash_fails_atomically_when_any_target_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            record = {
                "Category": "Logon",
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
            }
            golden.promote_records(
                database,
                [record],
                rmm_reference=rmm_path,
            )
            hash_key = autoruns.trusted_key(
                signer=record["Signer"],
                image_path=record["ImagePath"],
                launch_string=record["LaunchString"],
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "removal target not found",
            ):
                golden.remove_hashes(
                    database,
                    [hash_key, "f" * 40],
                    rmm_reference=rmm_path,
                )
            lookup = golden.lookup_hashes(
                database,
                [hash_key],
            )[0]

        self.assertTrue(lookup["known_good"])

    def test_default_publication_replaces_current_inventory_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
                modified_time="2026-07-28T07:32:47Z",
            )
            api = FakeInventoryApi()
            first = golden.publish_database(
                api, database, tool_name=golden.DEFAULT_TOOL_NAME,
                rmm_reference=rmm_path,
            )
            api.calls.clear()
            with mock.patch.object(golden.gzip, "compress", side_effect=AssertionError("unexpected compression")):
                unchanged = golden.publish_database(
                    api, database, tool_name=golden.DEFAULT_TOOL_NAME,
                    rmm_reference=rmm_path,
                )
            self.assertEqual(unchanged["status"], "current")
            self.assertFalse(unchanged["uploaded"])
            self.assertEqual(len(api.calls), 1)
            self.assertIn("inventory_get", api.calls[0][0])
            api.calls.clear()
            golden.promote_records(
                database,
                [{"Category": "Services", "Signer": "Vendor",
                  "ImagePath": r"C:\Vendor\Service.exe", "LaunchString": "service.exe"}],
                rmm_reference=rmm_path, modified_time="2026-08-01T07:32:47Z",
            )
            second = golden.publish_database(
                api, database, tool_name=golden.DEFAULT_TOOL_NAME,
                rmm_reference=rmm_path,
            )

        self.assertEqual(first["version"], "current")
        self.assertEqual(second["version"], "current")
        self.assertNotEqual(first["database_sha256"], second["database_sha256"])
        self.assertEqual(api.inventory, {
            (golden.DEFAULT_TOOL_NAME, "current"): second["database_sha256"],
        })
        self.assertEqual(len(api.calls), 3)
        self.assertTrue(second["uploaded"])
        self.assertEqual(second["status"], "updated")
        self.assertTrue(second["database_built_at"])

    def test_apply_delta_dry_run_does_not_modify_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            target = root / "golden.sqlite"
            delta = root / "delta.sqlite"
            golden.promote_records(
                target,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )
            before_hash = golden.file_sha256(target)
            golden.promote_records(
                delta,
                [
                    {
                        "Category": "Services",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                        "Description": "Reviewed vendor application",
                    }
                ],
                rmm_reference=rmm_path,
                baseline_databases=[target],
            )

            result = golden.apply_delta_database(
                target,
                delta,
                dry_run=True,
                rmm_reference=rmm_path,
            )

            self.assertEqual(golden.file_sha256(target), before_hash)
            self.assertEqual(result["changes"]["new_record_count"], 0)
            self.assertEqual(result["changes"]["improved_description_count"], 1)
            self.assertFalse(result["after"])
            self.assertFalse(
                target.with_name(f".{target.name}.lock").exists()
            )

    def test_apply_delta_merges_with_backup_and_atomic_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            target = root / "golden.sqlite"
            delta = root / "delta.sqlite"
            row = {
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
            }
            golden.promote_records(
                target,
                [{**row, "Category": "Logon"}],
                rmm_reference=rmm_path,
            )
            before_hash = golden.file_sha256(target)
            golden.promote_records(
                delta,
                [{**row, "Category": "Services", "Description": "Reviewed vendor application"}],
                rmm_reference=rmm_path,
                baseline_databases=[target],
            )

            result = golden.apply_delta_database(
                target,
                delta,
                rmm_reference=rmm_path,
            )

            self.assertNotEqual(result["after"]["sha256"], before_hash)
            self.assertTrue(Path(result["backup"]).is_file())
            hash_key = autoruns.trusted_key(
                signer=row["Signer"],
                image_path=row["ImagePath"],
                launch_string=row["LaunchString"],
            )
            self.assertEqual(
                golden.lookup_hashes(target, [hash_key])[0]["records"][0]["description"],
                "Reviewed vendor application",
            )

    def test_apply_delta_installs_first_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            target = root / "golden.sqlite"
            delta = root / "delta.sqlite"
            golden.promote_records(
                delta,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )
            # Build a first-install delta fixture with no prior database.
            with sqlite3.connect(delta) as connection:
                connection.execute("UPDATE metadata SET value='delta' WHERE key='build_mode'")

            result = golden.apply_delta_database(
                target,
                delta,
                rmm_reference=rmm_path,
            )

            self.assertTrue(target.is_file())
            self.assertEqual(result["backup"], "")
            self.assertEqual(result["after"]["identity_count"], 1)

    def test_build_can_create_delta_against_existing_golden_db(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            baseline = root / "baseline.sqlite"
            delta_input = root / "delta.json"
            delta = root / "delta.sqlite"
            merged = root / "merged.sqlite"
            common = {
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
                "Entry": "Vendor App",
                "Description": "Vendor application",
                "Company": "Vendor",
            }
            golden.promote_records(
                baseline,
                [{**common, "Category": "Logon"}],
                rmm_reference=rmm_path,
            )
            delta_input.write_text(
                json.dumps(
                    [
                        {**common, "Category": "Logon"},
                        {**common, "Category": "Services"},
                        {
                            "Category": "Drivers",
                            "Signer": "Another Vendor",
                            "ImagePath": r"C:\Vendor\Driver.exe",
                            "LaunchString": "driver.exe",
                            "Entry": "Vendor Driver",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            result = golden.build_database(
                delta,
                [delta_input],
                baseline_databases=[baseline],
                rmm_reference=rmm_path,
            )
            golden.merge_databases(
                merged,
                [baseline, delta],
                rmm_reference=rmm_path,
            )

            self.assertEqual(result["skipped_baseline"], 2)
            self.assertEqual(
                result["retained_baseline_enrichment"],
                0,
            )
            self.assertEqual(result["validation"]["identity_count"], 1)
            self.assertEqual(
                result["validation"]["metadata"]["build_mode"],
                "delta",
            )
            self.assertEqual(
                result["validation"]["metadata"][
                    "baseline_database_count"
                ],
                "1",
            )
            common_hash = autoruns.trusted_key(
                signer=common["Signer"],
                image_path=common["ImagePath"],
                launch_string=common["LaunchString"],
            )
            self.assertTrue(golden.lookup_hashes(merged, [common_hash])[0]["known_good"])
            self.assertEqual(golden.validate_database(merged)["record_count"], 2)

    def test_delta_retains_richer_context_for_existing_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            baseline = root / "baseline.sqlite"
            delta_input = root / "delta.json"
            delta = root / "delta.sqlite"
            merged = root / "merged.sqlite"
            identity = {
                "Category": "Logon",
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
                "Entry": "Vendor App",
            }
            golden.promote_records(
                baseline,
                [identity],
                rmm_reference=rmm_path,
            )
            delta_input.write_text(
                json.dumps(
                    [
                        {
                            **identity,
                            "Description": "Vendor application",
                            "Company": "Vendor",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            result = golden.build_database(
                delta,
                [delta_input],
                baseline_databases=[baseline],
                rmm_reference=rmm_path,
            )
            golden.merge_databases(
                merged,
                [baseline, delta],
                rmm_reference=rmm_path,
            )

            self.assertEqual(result["skipped_baseline"], 0)
            self.assertEqual(
                result["retained_baseline_enrichment"],
                1,
            )
            hash_key = autoruns.trusted_key(
                signer=identity["Signer"],
                image_path=identity["ImagePath"],
                launch_string=identity["LaunchString"],
            )
            self.assertEqual(
                golden.lookup_hashes(merged, [hash_key])[0]["records"][0][
                    "description"
                ],
                "Vendor application",
            )

    def test_lookup_returns_identity_and_metadata_without_categories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            row = {
                "Category": "Logon",
                "EntryLocation": r"HKU\S-1-5-21-1-2-3-1001\Software\Vendor",
                "Entry": "Vendor App",
                "Description": "Vendor application",
                "Company": "Vendor",
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
            }
            golden.promote_records(
                database,
                [row],
                rmm_reference=rmm_path,
            )
            hash_key = autoruns.trusted_key(
                signer=row["Signer"],
                image_path=row["ImagePath"],
                launch_string=row["LaunchString"],
            )

            results = golden.lookup_hashes(
                database,
                [hash_key, "f" * 40],
            )

            self.assertTrue(results[0]["known_good"])
            self.assertNotIn("categories", results[0])
            self.assertNotIn("category", results[0]["records"][0])
            self.assertEqual(
                results[0]["records"][0]["description"],
                "Vendor application",
            )
            self.assertFalse(results[1]["known_good"])

    def test_publish_probe_failure_does_not_upload(self):
        api = mock.Mock()
        api.query.side_effect = RuntimeError("permission denied")
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "golden.sqlite"
            database.write_bytes(b"test")
            with mock.patch.object(golden, "validate_database", return_value={"sha256": "a" * 64}):
                with self.assertRaisesRegex(RuntimeError, "permission denied"):
                    golden.publish_database(api, database, tool_name=golden.DEFAULT_TOOL_NAME)
        self.assertEqual(api.query.call_count, 1)
        self.assertIn("inventory_get", api.query.call_args.args[0])

    def test_publish_missing_version_uploads_and_verifies(self):
        api = mock.Mock()
        expected = hashlib.sha256(b"test").hexdigest()
        api.query.side_effect = [
            golden.velociraptor_api.InventoryNotFoundError("missing"),
            [{"Published": {"hash": expected}}],
            [{"Definition": {"Definition": {"hash": expected}}}],
        ]
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "golden.sqlite"
            database.write_bytes(b"test")
            with mock.patch.object(golden, "validate_database", return_value={"sha256": expected}):
                result = golden.publish_database(api, database, tool_name=golden.DEFAULT_TOOL_NAME)
        self.assertTrue(result["uploaded"])
        self.assertEqual(api.query.call_count, 3)

    def test_publish_uploads_and_verifies_inventory_tool(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )
            api = FakeInventoryApi()

            result = golden.publish_database(
                api,
                database,
                tool_name="Autoruns.GoldenDB",
                tool_version="20260728",
                rmm_reference=rmm_path,
            )

            self.assertEqual(result["tool"], "Autoruns.GoldenDB")
            self.assertEqual(len(api.calls), 3)
            self.assertIn("inventory_add", api.calls[1][0])
            self.assertIn("gunzip", api.calls[1][0])
            self.assertIn('accessor="data"', api.calls[1][0])
            self.assertNotIn("tempfile(", api.calls[1][0])
            self.assertIn("DatabaseGzipBase64", api.calls[1][1])
            self.assertNotIn("DatabaseBase64", api.calls[1][1])
            self.assertIn("inventory_get", api.calls[2][0])
            self.assertEqual(api.uploaded_bytes, database.read_bytes())
            self.assertEqual(
                result["database_sha256"],
                hashlib.sha256(api.uploaded_bytes).hexdigest(),
            )
            self.assertEqual(result["transport"], "grpc-vql-gzip-base64")
            self.assertLess(result["gzip_bytes"], result["database_bytes"])
            self.assertEqual(
                result["base64_bytes"],
                len(api.calls[1][1]["DatabaseGzipBase64"]),
            )
            self.assertLess(
                result["base64_bytes"],
                result["base64_limit_bytes"],
            )

    def test_live_lookup_payload_is_read_only_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            promoted = golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    },
                    {
                        "Category": "Services",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    },
                ],
                rmm_reference=rmm_path,
            )
            before = database.read_bytes()

            first = golden.live_lookup_payload(
                database,
                rmm_reference=rmm_path,
            )
            second = golden.live_lookup_payload(
                database,
                rmm_reference=rmm_path,
            )

            keys = json.loads(
                gzip.decompress(
                    base64.b64decode(first["lookup_gzip_base64"])
                )
            )
            hash_key = promoted["validation"]["sha256"]
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(first["lookup_gzip_base64"], second[
                "lookup_gzip_base64"
            ])
            self.assertEqual(first["lookup_key_count"], 1)
            self.assertEqual(len(keys), 1)
            self.assertTrue(all(golden.HASH_RE.fullmatch(value) for value in keys))
            self.assertEqual(first["sha256"], hash_key)
            self.assertEqual(
                first["lookup_transport"],
                "gzip-base64-json",
            )

    def test_filter_autoruns_rows_matches_identities_with_any_or_missing_category(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "(Verified) Vendor",
                        "ImagePath": r"C:\Users\Alice\App.exe",
                        "LaunchString": (
                            r"C:\Users\Alice\App.exe --background"
                        ),
                    }
                ],
                rmm_reference=rmm_path,
            )
            output = root / "residual.csv"

            result = golden.filter_autoruns_rows(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "(Verified) Vendor",
                        "ImagePath": r"C:\Users\Bob\App.exe",
                        "LaunchString": (
                            r"C:\Users\Bob\App.exe --background"
                        ),
                        "Entry": "Known",
                    },
                    {
                        "Category": "Services",
                        "Signer": "(Verified) Vendor",
                        "ImagePath": r"C:\Users\Carol\App.exe",
                        "LaunchString": (
                            r"C:\Users\Carol\App.exe --background"
                        ),
                        "Entry": "New category",
                    },
                    {
                        "Signer": "(Verified) Vendor",
                        "ImagePath": r"C:\Users\Dave\App.exe",
                        "LaunchString": r"C:\Users\Dave\App.exe --background",
                        "Entry": "Missing category",
                    },
                    {
                        "Category": "Logon",
                        "Signer": "Unknown",
                        "ImagePath": r"C:\Temp\evil.exe",
                        "LaunchString": r"C:\Temp\evil.exe",
                        "Entry": "Residual",
                    },
                    {
                        "Category": "Logon",
                        "Signer": "",
                        "ImagePath": "",
                        "LaunchString": "",
                        "Entry": "No identity",
                    },
                ],
                output=output,
            )

            with output.open(
                "r",
                encoding="utf-8",
                newline="",
            ) as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(result["input_rows"], 5)
        self.assertEqual(result["known_good_filtered_rows"], 3)
        self.assertEqual(result["empty_identity_dropped_rows"], 1)
        self.assertEqual(result["residual_rows"], 1)
        self.assertEqual(
            [row["GoldenDBStatus"] for row in rows],
            ["not_known_good"],
        )
        self.assertEqual(rows[0]["Category"], "Logon")
        self.assertTrue(all(len(row["HashKey"]) == 40 for row in rows))

    def test_filter_collection_manifest_selects_only_autoruns_exports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [],
                rmm_reference=rmm_path,
            )
            autoruns_csv = root / "Windows.Sysinternals.Autoruns_full.csv"
            autoruns_csv.write_text(
                "Category,Signer,ImagePath,LaunchString\n"
                "Logon,Unknown,C:\\\\Temp\\\\x.exe,C:\\\\Temp\\\\x.exe\n",
                encoding="utf-8",
            )
            other_csv = root / "Windows.System.Services_full.csv"
            other_csv.write_text("Name\nService\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "exported_files": [
                            {
                                "artifact": "Windows.Sysinternals.Autoruns",
                                "output_file": autoruns_csv.name,
                            },
                            {
                                "artifact": "Windows.System.Services",
                                "output_file": other_csv.name,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = golden.filter_autoruns_inputs(
                database,
                manifest=manifest,
            )

        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["residual_rows"], 1)
        self.assertEqual(
            result["results"][0]["artifact"],
            "Windows.Sysinternals.Autoruns",
        )
        self.assertTrue(
            result["results"][0]["output"].endswith(
                "Windows.Sysinternals.Autoruns_full.golden-residual.csv"
            )
        )

    def test_lookup_identity_reports_hash_match_across_categories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            row = {
                "Category": "Logon",
                "Signer": "Vendor",
                "ImagePath": r"C:\Vendor\App.exe",
                "LaunchString": "app.exe",
            }
            golden.promote_records(
                database,
                [row],
                rmm_reference=rmm_path,
            )

            result = golden.lookup_identity(
                database,
                category="Services",
                signer="Vendor",
                image_path=r"C:\Vendor\App.exe",
                launch_string="app.exe",
            )

        self.assertTrue(result["known_good"])
        self.assertTrue(result["hash_match"])
        self.assertTrue(result["filter_match"])

    def test_publish_rejects_oversized_uncompressed_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )

            with mock.patch.object(
                golden,
                "MAX_PUBLISH_UNCOMPRESSED_BYTES",
                database.stat().st_size - 1,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "gunzip\\(\\) materializes",
                ):
                    golden.publish_database(
                        FakeInventoryApi(),
                        database,
                        tool_name="Autoruns.GoldenDB",
                        tool_version="20260728",
                        rmm_reference=rmm_path,
                    )

    def test_publish_honors_configured_grpc_message_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )

            with mock.patch.dict(
                "os.environ",
                {"VELO_GRPC_MAX_MESSAGE_BYTES": "1024"},
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "leaves no room",
                ):
                    golden.publish_database(
                        FakeInventoryApi(),
                        database,
                        tool_name="Autoruns.GoldenDB",
                        tool_version="20260728",
                        rmm_reference=rmm_path,
                    )

    def test_publish_rejects_oversized_compressed_request(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )

            with mock.patch.object(
                golden,
                "MAX_PUBLISH_BASE64_BYTES",
                1,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "gzip payload requires",
                ):
                    golden.publish_database(
                        FakeInventoryApi(),
                        database,
                        tool_name="Autoruns.GoldenDB",
                        tool_version="20260728",
                        rmm_reference=rmm_path,
                    )

    def test_publish_rejects_inventory_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rmm_path = root / "rmm.json"
            write_rmm_reference(rmm_path)
            database = root / "golden.sqlite"
            golden.promote_records(
                database,
                [
                    {
                        "Category": "Logon",
                        "Signer": "Vendor",
                        "ImagePath": r"C:\Vendor\App.exe",
                        "LaunchString": "app.exe",
                    }
                ],
                rmm_reference=rmm_path,
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "inventory hash mismatch",
            ):
                golden.publish_database(
                    FakeInventoryApi(verified_hash="0" * 64),
                    database,
                    tool_name="Autoruns.GoldenDB",
                    tool_version="20260728",
                    rmm_reference=rmm_path,
                )

    def test_lolrmm_csv_parser_extracts_windows_patterns(self):
        payload = golden.parse_lolrmm_csv(
            "\n".join(
                [
                    (
                        "Name,Category,Filename,OriginalFileName,"
                        "InstallationPaths"
                    ),
                    (
                        'Example,RMM,Example.exe,,"C:\\Program Files\\'
                        'Example\\Example*.exe, /usr/bin/example"'
                    ),
                ]
            ),
            source="test",
        )

        self.assertEqual(payload["tool_count"], 1)
        self.assertIn("example.exe", payload["executables"])
        self.assertIn("example*.exe", payload["executables"])
        self.assertEqual(
            payload["installation_paths"],
            [r"c:\program files\example\example*.exe"],
        )


class AutorunsCategoryFreeMigrationTest(unittest.TestCase):
    def write_legacy_database(self, path, version):
        record = golden.normalized_record({
            "ImagePath": r"c:\vendor\service.exe",
            "LaunchString": "vendor-service --approved", "Signer": "Vendor",
        })
        connection = sqlite3.connect(path)
        try:
            connection.executescript("""
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE autoruns_known_good (
                    hash_key TEXT NOT NULL, category TEXT NOT NULL,
                    image_path TEXT NOT NULL, launch_string TEXT NOT NULL,
                    signer TEXT NOT NULL, description TEXT NOT NULL,
                    modified_time TEXT NOT NULL,
                    PRIMARY KEY (hash_key, category)
                );
            """)
            connection.executemany(
                "INSERT INTO metadata VALUES (?, ?)",
                {**golden.REQUIRED_METADATA, "schema_version": version}.items(),
            )
            for category, description, timestamp in (
                ("logon", "", "2026-01-01T00:00:00Z"),
                ("services", "Reviewed vendor service", "2026-02-01T00:00:00Z"),
            ):
                connection.execute(
                    "INSERT INTO autoruns_known_good VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (record["hash_key"], category, record["image_path"],
                     record["launch_string"], record["signer"], description, timestamp),
                )
            if version != "3":
                signer_column = ", signer_regex TEXT NOT NULL DEFAULT ''" if version == "5" else ""
                connection.execute(
                    "CREATE TABLE autoruns_regex_rules (category TEXT NOT NULL, "
                    "image_path_regex TEXT NOT NULL, launch_string_regex TEXT NOT NULL, "
                    "description TEXT NOT NULL, modified_time TEXT NOT NULL"
                    + signer_column
                    + ", PRIMARY KEY (category, image_path_regex, launch_string_regex)) WITHOUT ROWID"
                )
                for category, description, timestamp in (
                    ("logon", "", "2026-01-01T00:00:00Z"),
                    ("services", "Reviewed vendor family", "2026-03-01T00:00:00Z"),
                ):
                    values = [category, r"c:\\vendor\\service\.exe",
                              "vendor-service --approved", description, timestamp]
                    if version == "5":
                        values.append("vendor" if category == "services" else "")
                    connection.execute(
                        "INSERT INTO autoruns_regex_rules VALUES ("
                        + ",".join("?" for _ in values) + ")", values,
                    )
            connection.commit()
        finally:
            connection.close()
        return record

    def test_legacy_read_and_merge_collapse_categories_without_losing_metadata(self):
        for version in ("3", "4", "5"):
            with self.subTest(schema=version), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                legacy = root / "legacy.sqlite"
                migrated = root / "migrated.sqlite"
                record = self.write_legacy_database(legacy, version)
                before = legacy.read_bytes()
                lookup = golden.live_lookup_payload(legacy)
                self.assertEqual(lookup["lookup_key_count"], 1)
                golden.merge_databases(migrated, [legacy])
                self.assertEqual(legacy.read_bytes(), before)
                report = golden.validate_database(migrated)
                self.assertEqual(report["metadata"]["schema_version"], "6")
                self.assertEqual(report["record_count"], 1)
                self.assertEqual(report["regex_rule_count"], 0 if version == "3" else 1)
                connection = golden.connect_database(migrated, readonly=True)
                try:
                    for table in ("autoruns_known_good", "autoruns_regex_rules"):
                        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                        self.assertNotIn("category", columns)
                    exact = dict(connection.execute("SELECT * FROM autoruns_known_good").fetchone())
                    self.assertEqual(exact["hash_key"], record["hash_key"])
                    self.assertEqual(exact["description"], "Reviewed vendor service")
                    self.assertEqual(exact["modified_time"], "2026-02-01T00:00:00Z")
                    rules = golden.regex_records(connection)
                    if rules:
                        self.assertEqual(rules[0]["description"], "Reviewed vendor family")
                        self.assertEqual(rules[0]["modified_time"], "2026-03-01T00:00:00Z")
                        self.assertEqual(rules[0]["signer_regex"], "vendor" if version == "5" else "")
                finally:
                    connection.close()

    def test_legacy_in_place_initialization_fails_without_relabeling_schema(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "legacy.sqlite"
            self.write_legacy_database(database, "5")
            before = database.read_bytes()
            connection = golden.connect_database(database)
            try:
                with self.assertRaisesRegex(RuntimeError, "[Mm]erge|[Mm]igrat"):
                    golden.initialize_database(connection, built_at="2026-04-01T00:00:00Z")
            finally:
                connection.close()
            self.assertEqual(database.read_bytes(), before)

    def test_legacy_direct_removal_fails_without_changing_database(self):
        for version in ("3", "4", "5"):
            with self.subTest(schema=version), tempfile.TemporaryDirectory() as temp_dir:
                database = Path(temp_dir) / "legacy.sqlite"
                record = self.write_legacy_database(database, version)
                before = database.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "[Mm]erge|[Mm]igrat"):
                    golden.remove_hashes(database, [record["hash_key"]])
                self.assertEqual(database.read_bytes(), before)

    def test_legacy_regex_duplicates_cannot_hide_invalid_physical_records(self):
        for field_name, value in (("signer_regex", "("), ("modified_time", "")):
            with self.subTest(field=field_name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                database = root / "legacy.sqlite"
                output = root / "migrated.sqlite"
                self.write_legacy_database(database, "5")
                connection = sqlite3.connect(database)
                try:
                    connection.execute(
                        f"UPDATE autoruns_regex_rules SET {field_name}=? WHERE category='logon'",
                        (value,),
                    )
                    connection.commit()
                finally:
                    connection.close()
                before = database.read_bytes()
                with self.assertRaises(RuntimeError):
                    golden.validate_database(database)
                with self.assertRaises(RuntimeError):
                    golden.merge_databases(output, [database])
                self.assertEqual(database.read_bytes(), before)
                self.assertFalse(output.exists())

    def test_validation_rejects_legacy_tables_mislabeled_as_schema_six(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "mislabeled.sqlite"
            self.write_legacy_database(database, "5")
            connection = sqlite3.connect(database)
            try:
                connection.execute("UPDATE metadata SET value='6' WHERE key='schema_version'")
                connection.commit()
            finally:
                connection.close()
            before = database.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "[Ss]chema|[Cc]ategory"):
                golden.validate_database(database)
            self.assertEqual(database.read_bytes(), before)


class AutorunsOfflineImportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.database = self.root / "golden # baseline.sqlite"
        golden.promote_records(self.database, [])
        self.source = self.root / "reviewed.csv"
        self.row = {
            "Category": "Services", "ImagePath": r"c:\vendor\service.exe",
            "LaunchString": r'"c:\vendor\service.exe" --service',
            "Signer": "(verified) vendor", "Description": "Reviewed vendor service",
        }
        self.row["HashKey"] = autoruns.trusted_key(
            image_path=self.row["ImagePath"], launch_string=self.row["LaunchString"],
            signer=self.row["Signer"],
        )
        self.fields = ("HashKey", "Category", "ImagePath", "LaunchString", "Signer", "Description")
        self.write_csv([self.row])

    def write_csv(self, rows, *, fields=None):
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=fields or self.fields, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(rows)
        self.source.write_text("\ufeff# Reviewed input\r\n\r\n" + buffer.getvalue(), newline="")

    def run_import(self, *extra):
        return golden.import_offline_rules(golden.parser().parse_args([
            "import", "--db", str(self.database), "--input", str(self.source), *extra,
        ]))

    def test_multiline_csv_preserves_comments_quotes_and_following_rows(self):
        second = {**self.row, "LaunchString": "vendor-service --other"}
        second["HashKey"] = golden.normalized_record({
            name: value for name, value in second.items() if name != "HashKey"
        })["hash_key"]
        rows = [
            {**self.row, "Description": 'Reviewed, with "quotes"\r\n# tail'},
            second,
        ]
        self.write_csv(rows)
        self.assertEqual(list(golden.iter_rows(self.source)), rows)
        before = self.database.read_bytes()
        files = sorted(self.root.iterdir())
        report = self.run_import("--dry-run")
        self.assertEqual(report["exact_input_row_count"], 2)
        self.assertEqual(report["application"]["changes"]["new_record_count"], 2)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertEqual(sorted(self.root.iterdir()), files)

    def test_malformed_csv_fails_before_mutation(self):
        header = ",".join(self.fields)
        values = ",".join(self.row[name] for name in self.fields)
        invalid = [
            header + ",Category\n" + values + ",Logon\n",
            header + ",category\n" + values + ",Logon\n",
            header + ",Image Path\n" + values + ",different.exe\n",
            header + "\n" + values + ",extra\n",
            header + "\n" + ",".join(self.row[name] for name in self.fields[:4]) + "\n",
            '"unclosed,header\n',
            header + '\n"unterminated',
            "not,a,valid,header\n", "# comments only\n",
            header + "\n# comments after the header are not supported\n",
        ]
        before = self.database.read_bytes()
        for content in invalid:
            with self.subTest(content=content):
                self.source.write_text(content)
                with self.assertRaises(RuntimeError):
                    self.run_import()
                self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse((self.root / "backups").exists())

    def test_offline_json_requires_unambiguous_typed_identity_fields(self):
        self.source = self.root / "reviewed.json"
        before = self.database.read_bytes()
        for field_name, value in [
            ("Signer", None), ("ImagePath", {}), ("LaunchString", 12),
            ("HashKey", None),
        ]:
            with self.subTest(field=field_name, value=value):
                self.source.write_text(json.dumps([{**self.row, field_name: value}]))
                with self.assertRaises(RuntimeError):
                    self.run_import()
                self.assertEqual(self.database.read_bytes(), before)
        for content in [
            json.dumps(self.row)[:-1] + ', "Category":"Logon"}',
            json.dumps({**self.row, "category": "Logon"}),
            json.dumps({**self.row, "trusted_key": self.row["HashKey"]}),
        ]:
            self.source.write_text(content)
            with self.assertRaisesRegex(RuntimeError, "duplicate"):
                self.run_import()

    def test_extra_category_is_ignored_in_offline_json(self):
        self.source = self.root / "reviewed.json"
        for value in ("", " ", " Services ", "Services\n", ["Services"], None):
            with self.subTest(category=value):
                self.source.write_text(json.dumps([{**self.row, "Category": value}]))
                result = self.run_import("--dry-run")
                self.assertEqual(result["application"]["changes"]["new_record_count"], 1)

    def test_duplicate_identities_across_inputs_fail_despite_different_categories(self):
        second = self.root / "second.json"
        before = self.database.read_bytes()
        for category in ("SERVICES", "Logon", ""):
            with self.subTest(category=category):
                second.write_text(json.dumps([{**self.row, "Category": category}]))
                with self.assertRaisesRegex(RuntimeError, "duplicate HashKey"):
                    self.run_import("--input", str(second))
                self.assertEqual(self.database.read_bytes(), before)

    def test_prohibited_exact_identity_and_missing_input_fail_closed(self):
        before = self.database.read_bytes()
        for image in (r"c:\tools\anydesk.exe", r"File not found: c:\vendor\service.exe"):
            row = {**self.row, "ImagePath": image}
            row["HashKey"] = autoruns.trusted_key(
                image_path=image, launch_string=row["LaunchString"], signer=row["Signer"],
            )
            self.write_csv([row])
            with self.assertRaises(RuntimeError):
                self.run_import()
            self.assertEqual(self.database.read_bytes(), before)
        self.source.unlink()
        with self.assertRaisesRegex(RuntimeError, "not found"):
            self.run_import()

    def test_cli_import_never_resolves_case_state_or_connects_to_api(self):
        from vraptor import legacy_cli as cli

        before = self.database.read_bytes()
        output = io.StringIO()
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network access")), \
             mock.patch.object(golden.velociraptor_api, "VeloApiClient", side_effect=AssertionError("API access")), \
             mock.patch.object(golden, "apply_engagement_context", side_effect=AssertionError("case state")), \
             mock.patch.object(golden, "publish_database", side_effect=AssertionError("publication")), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main([
                "autoruns", "import", "--db", str(self.database),
                "--input", str(self.source), "--dry-run",
            ]), 0)
        self.assertTrue(json.loads(output.getvalue())["offline"])
        self.assertEqual(self.database.read_bytes(), before)

    def test_matching_contract_changes_invalidate_lookup_identity(self):
        rule = {
            "category": "services", "image_path_regex": r"c:\\vendor\\service\.exe",
            "launch_string_regex": r"service --approved", "description": "Reviewed",
        }
        golden.promote_records(self.database, [], regex_rows=[rule])
        first = golden.live_lookup_payload(self.database)
        with mock.patch.object(golden.autoruns_regex, "MATCHING_POLICY", "changed-approved-rule-contract"):
            second = golden.live_lookup_payload(self.database)
        self.assertNotEqual(first["lookup_payload_sha256"], second["lookup_payload_sha256"])
        self.assertEqual(first["sha256"], second["sha256"])

    def test_input_digest_describes_parsed_bytes_even_after_source_changes(self):
        captured_hash = golden.file_sha256(self.source)
        snapshot = golden._snapshot_import_baseline

        def change_input(target, destination):
            snapshot(target, destination)
            self.source.write_text("replaced source")

        apply = golden.apply_delta_database

        def delete_input(*args, **kwargs):
            result = apply(*args, **kwargs)
            self.source.unlink()
            return result

        with mock.patch.object(golden, "_snapshot_import_baseline", side_effect=change_input), \
             mock.patch.object(golden, "apply_delta_database", side_effect=delete_input):
            result = self.run_import()
        self.assertEqual(result["inputs"][0]["sha256"], captured_hash)
        self.assertEqual(result["application"]["after"]["identity_count"], 1)
        self.assertTrue(result["application"]["installed"])

    def test_baseline_drift_during_delta_build_fails_including_noop(self):
        golden.promote_records(self.database, [self.row])
        original = self.database.read_bytes()
        replacement = self.root / "replacement.sqlite"
        golden.promote_records(replacement, [])
        replacement_bytes = replacement.read_bytes()
        promote = golden.promote_records
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                self.database.write_bytes(original)
                replacement.write_bytes(replacement_bytes)

                def replace_baseline(*args, **kwargs):
                    os.replace(replacement, self.database)
                    return promote(*args, **kwargs)

                with mock.patch.object(golden, "promote_records", side_effect=replace_baseline):
                    with self.assertRaisesRegex(RuntimeError, "target revision does not match"):
                        self.run_import(*(["--dry-run"] if dry_run else []))
                self.assertEqual(self.database.read_bytes(), replacement_bytes)
        self.assertFalse((self.root / "backups").exists())

    def test_import_preserves_permissions_backup_bytes_and_replay(self):
        self.database.chmod(0o600)
        before = self.database.read_bytes()
        previous_umask = os.umask(0o022)
        try:
            result = self.run_import()
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        self.assertEqual(Path(result["application"]["backup"]).read_bytes(), before)
        installed = self.database.read_bytes()
        backups = sorted((self.root / "backups").iterdir())
        replay = self.run_import()
        self.assertTrue(replay["application"]["no_changes"])
        self.assertFalse(replay["application"]["installed"])
        self.assertEqual(self.database.read_bytes(), installed)
        self.assertEqual(sorted((self.root / "backups").iterdir()), backups)

    def test_replacement_failure_preserves_database_and_cleans_temporary_files(self):
        before = self.database.read_bytes()
        replace = golden.os.replace
        snapshots = []
        snapshot = golden._snapshot_import_baseline

        def capture_snapshot(target, path):
            snapshots.append(path.parent)
            snapshot(target, path)

        def fail_replace(source, target):
            if Path(target) == self.database:
                raise OSError("simulated replacement failure")
            return replace(source, target)

        with mock.patch.object(golden, "_snapshot_import_baseline", side_effect=capture_snapshot), \
             mock.patch.object(golden.os, "replace", side_effect=fail_replace):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.run_import()
        self.assertEqual(self.database.read_bytes(), before)
        self.assertTrue(snapshots)
        self.assertTrue(all(not path.exists() for path in snapshots))
        self.assertFalse(list(self.root.glob("*.tmp")))

    def test_wal_database_is_rejected_without_touching_target_or_sidecars(self):
        connection = sqlite3.connect(self.database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("UPDATE metadata SET value=value WHERE key='built_at'")
        connection.commit()
        before = {p: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        with self.assertRaisesRegex(RuntimeError, "without WAL"):
            self.run_import("--dry-run")
        self.assertEqual({p: p.read_bytes() for p in self.root.iterdir() if p.is_file()}, before)

    def test_merge_failure_removes_nested_working_database(self):
        before = self.database.read_bytes()
        insert = golden.insert_record

        def fail_merge(connection, record, **kwargs):
            if golden.metadata(connection).get("build_mode") == "merged":
                raise RuntimeError("simulated merge failure")
            return insert(connection, record, **kwargs)

        with mock.patch.object(golden, "insert_record", side_effect=fail_merge):
            with self.assertRaisesRegex(RuntimeError, "simulated merge failure"):
                self.run_import()
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse(list(self.root.glob("*.tmp")))
        self.assertFalse((self.root / "backups").exists())

    def test_concurrent_imports_cannot_overwrite_another_revision(self):
        second = self.root / "second.json"
        second.write_text(json.dumps([{**self.row, "Category": "Logon"}]))
        script = '''
import sys
from unittest import mock
from vraptor.autoruns import golden as g
snapshot = g._snapshot_import_baseline
def barrier(target, path):
    snapshot(target, path)
    print("ready", flush=True)
    sys.stdin.readline()
with mock.patch.object(g, "_snapshot_import_baseline", side_effect=barrier):
    try:
        g.import_offline_rules(g.parser().parse_args(sys.argv[1:]))
    except RuntimeError as exc:
        print(str(exc), flush=True)
        sys.exit(1)
'''
        processes = [subprocess.Popen(
            [sys.executable, "-c", script, "import", "--db", str(self.database),
             "--input", str(source)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        ) for source in (self.source, second)]
        try:
            for process in processes:
                self.assertEqual(process.stdout.readline().strip(), "ready")
            for process in processes:
                process.stdin.write("apply\n")
                process.stdin.flush()
            results = [process.communicate(timeout=20) for process in processes]
            self.assertEqual(sorted(process.returncode for process in processes), [0, 1], results)
            self.assertTrue(any("target revision does not match" in out for out, _ in results))
            self.assertEqual(golden.validate_database(self.database)["record_count"], 1)
            self.assertEqual(len(list((self.root / "backups").iterdir())), 1)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
