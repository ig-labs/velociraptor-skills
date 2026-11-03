import csv
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "src/vraptor/hunt/analysis.py"
)


def load_hunt_analysis_module():
    module_name = f"test_hunt_analysis_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class HuntAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_hunt_analysis_module()

    def test_autoruns_user_paths_normalize_to_stable_user_component(self):
        value = (
            r'"C:\Users\Alice\AppData\Local\agent.exe" '
            r'--config C:\Users\Bob\agent.json '
            r'--system %SystemRoot%\System32 '
            r'--windir %WinDir%\Temp'
        )

        normalized = self.module.normalize_stack_text(
            value,
            "autoruns_user_path",
        )

        self.assertEqual(
            normalized,
            (
                r'"c:\users\user\appdata\local\agent.exe" '
                r'--config c:\users\user\agent.json '
                r'--system c:\windows\system32 '
                r'--windir c:\windows\temp'
            ),
        )

    def test_lolrmm_sub_source_uses_exact_catalog_projection(self):
        module = self.module
        profiles = module.artifact_policy.load_artifact_policy().profiles
        key, profile, resolution = module.artifact_profiles.resolve_profile_match(
            "DetectRaptor.Windows.Detection.LolRMM/Processes",
            profiles,
        )
        projection = module.build_saved_hunt_projection(
            key,
            profile,
            resolution,
            {
                "artifact": "DetectRaptor.Windows.Detection.LolRMM/Processes",
                "artifact_name": "DetectRaptor.Windows.Detection.LolRMM/Processes",
            },
            ["Source", "Name", "Description", "LolRMMLink", "Event", "Fqdn"],
            50,
        )

        self.assertEqual(
            projection["artifact_profile_key"],
            "DetectRaptor.Windows.Detection.LolRMM/Processes",
        )
        self.assertEqual(projection["artifact_profile_resolution"], "exact")
        self.assertEqual(
            projection["summary_fields"],
            ["Source", "Name", "Description", "LolRMMLink", "Event"],
        )
        self.assertEqual(
            projection["output_fields"][:4],
            list(module.GENERATED_REVIEW_FIELDS),
        )

    def write_csv(self, path: Path, rows: list[dict[str, str]]) -> None:
        headers = list(rows[0].keys()) if rows else []
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    def write_jsonl(self, path: Path, rows: list[dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = self.module.main(argv)
        return exit_code, stderr.getvalue()

    def run_main_with_stdout(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = self.module.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_analyze_from_state_uses_latest_manifests_and_materializes_review_outputs(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            case_root = Path(tmpdir)
            hunt_dir = case_root / "IR9001" / "hunts" / "H.1234"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"

            self.write_csv(
                csv_path,
                [
                    {
                        "EventTime": "2026-06-01T01:02:03Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": "4624",
                        "EventRecordID": "10",
                        "Username": "alice",
                        "EventData": "{\"IpAddress\":\"192.0.2.5\"}",
                        "UserData": ""
                    }
                ],
            )
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T01:02:03Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": 4624,
                        "Username": "alice",
                        "EventData": {"IpAddress": "192.0.2.5"},
                    }
                ],
            )

            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest = {
                "exported_at": "2026-06-01T02:00:00Z",
                "investigation_id": "IR9001",
                "hunt_id": "H.1234",
                "target_collection_type": "DetectRaptor.Windows.Detection.Evtx",
                "requested_groups": [],
                "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                "expected_spec_arguments": [{"label": "Windows.EventLogs.EvtxHunter", "artifact": "Windows.EventLogs.EvtxHunter", "env": {}}],
                "exported_files": [
                    {
                        "artifact": "Windows.EventLogs.EvtxHunter",
                        "artifact_name": "Windows.EventLogs.EvtxHunter",
                        "mode": "hunt-results",
                        "row_count": 1,
                        "output_file": str(csv_path),
                    }
                ],
            }
            download_manifest = {
                "downloaded_at": "2026-06-01T02:05:00Z",
                "investigation_id": "IR9001",
                "hunt_id": "H.1234",
                "target_collection_type": "DetectRaptor.Windows.Detection.Evtx",
                "requested_groups": [],
                "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                "expected_spec_arguments": [{"label": "Windows.EventLogs.EvtxHunter", "artifact": "Windows.EventLogs.EvtxHunter", "env": {}}],
                "downloaded_files": [
                    {
                        "artifact": "Windows.EventLogs.EvtxHunter",
                        "artifact_name": "Windows.EventLogs.EvtxHunter",
                        "mode": "hunt-results-jsonl",
                        "row_count": 1,
                        "output_file": str(jsonl_path),
                    }
                ],
            }
            export_manifest_path.write_text(json.dumps(export_manifest) + "\n", encoding="utf-8")
            download_manifest_path.write_text(json.dumps(download_manifest) + "\n", encoding="utf-8")
            (hunt_dir / "baseline-targets.json").write_text(json.dumps({"target_count": 12}) + "\n", encoding="utf-8")

            state_path = hunt_dir / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR9001",
                        "hunt_id": "H.1234",
                        "hunt_description": "Test hunt",
                        "profile": "detectraptor",
                        "target_os": "windows",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "expected_spec_arguments": [{"label": "Windows.EventLogs.EvtxHunter", "artifact": "Windows.EventLogs.EvtxHunter", "env": {}}],
                        "review_readiness": "ready_for_review",
                        "completion_ratio": 0.9,
                        "baseline_target_count": 12,
                        "latest_export_manifest_file": str(export_manifest_path),
                        "latest_download_manifest_file": str(download_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            args = module.argparse.Namespace(
                state_file=str(state_path),
                export_manifest=None,
                hunt_id=None,
                download_manifest=None,
                investigation_id=None,
                case_root=str(case_root),
                target=None,
                artifact=[],
                sample_limit=25,
            )
            payload = module.command_analyze(args)

            review_dir = (hunt_dir / "review").resolve()
            input_contract = module.read_json(review_dir / "hunt-analysis-input.json")
            review_manifest = module.read_json(review_dir / "hunt-analysis.json")
            projection = module.read_json(
                review_dir
                / "projections"
                / "Windows.EventLogs.EvtxHunter_saved-hunt-projection.json"
            )
            review_csv_path = review_dir / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            review_jsonl_path = review_dir / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.jsonl"

            self.assertEqual(payload["manifest_file"], str(review_dir / "hunt-analysis.json"))
            self.assertEqual(input_contract["state_file"], str(state_path.resolve()))
            self.assertEqual(input_contract["export_manifest_file"], str(export_manifest_path.resolve()))
            self.assertEqual(input_contract["download_manifest_file"], str(download_manifest_path.resolve()))
            self.assertEqual(input_contract["target_collection_type"], "DetectRaptor.Windows.Detection.Evtx")
            self.assertEqual(input_contract["baseline_target_count"], 12)
            self.assertEqual(review_manifest["artifacts_analyzed"], 1)
            self.assertEqual(review_manifest["manifest_file"], str(review_dir / "hunt-analysis.json"))
            self.assertEqual(review_manifest["requested_artifacts"], ["Windows.EventLogs.EvtxHunter"])
            self.assertEqual(projection["contract_version"], "2")
            self.assertEqual(projection["catalog_schema_version"], 4)
            self.assertEqual(
                projection["artifact_profile_key"],
                "Windows.EventLogs.EvtxHunter",
            )
            self.assertEqual(projection["artifact_profile_resolution"], "exact")
            self.assertEqual(projection["selected_source_fields"], ["EventID", "Provider"])
            self.assertTrue(projection["artifact_profile_hash"])
            self.assertTrue(projection["projection_hash"])
            self.assertEqual(
                projection["artifact_profile_sources"],
                [str(module.artifact_profiles.BUILTIN_REFERENCE_PATH.resolve())],
            )
            self.assertTrue(review_csv_path.exists())
            self.assertTrue(review_jsonl_path.exists())

            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                review_rows = list(reader)
            self.assertEqual(review_rows[0]["ReviewArtifact"], "Windows.EventLogs.EvtxHunter")
            self.assertEqual(review_rows[0]["ReviewTimestamp"], "2026-06-01T01:02:03Z")
            self.assertIn("Provider=Microsoft-Windows-Security-Auditing", review_rows[0]["ReviewSummary"])
            self.assertIn("Username=alice", review_rows[0]["ReviewSummary"])

    def test_analyze_from_explicit_manifest_without_state(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR2000" / "hunts" / "H.2000"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.NTFS.MFT_full.csv"
            self.write_csv(
                csv_path,
                [
                    {
                        "OSPath": "C:\\Windows\\Temp\\evil.exe",
                        "FileSize": "1024",
                        "Created0x10": "2026-06-01T01:00:00Z",
                        "LastModified0x10": "2026-06-01T01:10:00Z",
                        "EntryNumber": "55",
                        "ParentEntryNumber": "5",
                        "InUse": "true",
                    }
                ],
            )
            (hunt_dir / "baseline-targets.json").write_text(json.dumps({"target_count": 3}) + "\n", encoding="utf-8")
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "exported_at": "2026-06-01T02:00:00Z",
                        "investigation_id": "IR2000",
                        "hunt_id": "H.2000",
                        "target_collection_type": "timeline",
                        "requested_groups": ["timeline"],
                        "requested_artifacts": ["Windows.NTFS.MFT"],
                        "expected_spec_arguments": [{"label": "Windows.NTFS.MFT", "artifact": "Windows.NTFS.MFT", "env": {}}],
                        "exported_files": [
                            {
                                "artifact": "Windows.NTFS.MFT",
                                "artifact_name": "Windows.NTFS.MFT",
                                "mode": "hunt-results",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            args = module.argparse.Namespace(
                state_file=None,
                export_manifest=str(export_manifest_path),
                hunt_id=None,
                download_manifest=None,
                investigation_id=None,
                case_root=str(root),
                target=None,
                artifact=[],
                sample_limit=20,
            )
            payload = module.command_analyze(args)
            review_dir = hunt_dir / "review"
            self.assertEqual(payload["artifacts_analyzed"], 1)
            review_manifest = module.read_json(review_dir / "hunt-analysis.json")
            self.assertEqual(review_manifest["baseline_target_count"], 3)
            projection = module.read_json(
                review_dir
                / "projections"
                / "Windows.NTFS.MFT_saved-hunt-projection.json"
            )
            self.assertEqual(projection["artifact_profile_key"], "Windows.NTFS.MFT")
            self.assertEqual(projection["artifact_profile_resolution"], "exact")

    def test_explicit_manifest_mode_ignores_incidental_sibling_state(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR2001" / "hunts" / "H.2001"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.NTFS.MFT_full.csv"
            self.write_csv(
                csv_path,
                [
                    {
                        "OSPath": "C:\\Windows\\Temp\\evil.exe",
                        "FileSize": "1024",
                        "Created0x10": "2026-06-01T01:00:00Z",
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR2001",
                        "hunt_id": "H.2001",
                        "target_collection_type": "timeline",
                        "requested_groups": ["timeline"],
                        "requested_artifacts": ["Windows.NTFS.MFT"],
                        "expected_spec_arguments": [{"label": "Windows.NTFS.MFT", "artifact": "Windows.NTFS.MFT", "env": {}}],
                        "exported_files": [
                            {
                                "artifact": "Windows.NTFS.MFT",
                                "artifact_name": "Windows.NTFS.MFT",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (hunt_dir / "state.json").write_text(
                json.dumps(
                    {
                        "investigation_id": "IR-STALE",
                        "hunt_id": "H.STALE",
                        "profile": "stale-profile",
                        "target_collection_type": "stale-type",
                        "requested_artifacts": ["Stale.Artifact"],
                        "requested_groups": ["stale-group"],
                        "expected_spec_arguments": [{"label": "Stale.Artifact", "artifact": "Stale.Artifact", "env": {}}],
                        "review_readiness": "stale",
                        "completion_ratio": 0.01,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["hunt_id"], "H.2001")
            self.assertEqual(payload["target_collection_type"], "timeline")
            self.assertEqual(payload["requested_artifacts"], ["Windows.NTFS.MFT"])
            self.assertEqual(payload["state_file"], "")
            self.assertEqual(payload["review_readiness"], "")

    def test_explicit_export_and_download_manifests_with_mismatched_requested_artifacts_fail_closed(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR2002" / "hunts" / "H.2002"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Artifact.Old_full.csv"
            jsonl_path = downloads_dir / "Artifact.New.jsonl"
            self.write_csv(csv_path, [{"Timestamp": "2026-06-01T01:00:00Z", "Host": "WS1", "Message": "old"}])
            self.write_jsonl(jsonl_path, [{"Timestamp": "2026-06-01T01:01:00Z", "Host": "WS1", "Message": "new"}])
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR2002",
                        "hunt_id": "H.2002",
                        "requested_artifacts": ["Artifact.Old"],
                        "exported_files": [
                            {
                                "artifact": "Artifact.Old",
                                "artifact_name": "Artifact.Old",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR2002",
                        "hunt_id": "H.2002",
                        "requested_artifacts": ["Artifact.New"],
                        "downloaded_files": [
                            {
                                "artifact": "Artifact.New",
                                "artifact_name": "Artifact.New",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=str(download_manifest_path),
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

    def test_explicit_export_and_download_manifests_with_mismatched_expected_specs_fail_closed(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR2003" / "hunts" / "H.2003"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Artifact.Scope_full.csv"
            jsonl_path = downloads_dir / "Artifact.Scope.jsonl"
            self.write_csv(csv_path, [{"Timestamp": "2026-06-01T01:00:00Z", "Host": "WS1", "Message": "csv"}])
            self.write_jsonl(jsonl_path, [{"Timestamp": "2026-06-01T01:01:00Z", "Host": "WS1", "Message": "jsonl"}])
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR2003",
                        "hunt_id": "H.2003",
                        "requested_artifacts": ["Artifact.Scope"],
                        "expected_spec_arguments": [
                            {"label": "Artifact.Scope", "artifact": "Artifact.Scope", "env": {}}
                        ],
                        "exported_files": [
                            {
                                "artifact": "Artifact.Scope",
                                "artifact_name": "Artifact.Scope",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR2003",
                        "hunt_id": "H.2003",
                        "requested_artifacts": ["Artifact.Scope"],
                        "expected_spec_arguments": [
                            {"label": "Artifact.Scope.Alias", "artifact": "Artifact.Scope", "env": {}}
                        ],
                        "downloaded_files": [
                            {
                                "artifact": "Artifact.Scope",
                                "artifact_name": "Artifact.Scope",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=str(download_manifest_path),
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

    def test_state_resolution_prefers_latest_manifest_fields_over_transient_action_fields(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            case_root = Path(tmpdir)
            hunt_dir = case_root / "IR3000" / "hunts" / "H.3000"
            exports_dir = hunt_dir / "exports"
            good_csv_path = exports_dir / "Windows.Search.FileFinder_full.csv"
            self.write_csv(
                good_csv_path,
                [
                    {
                        "OSPath": "C:\\Temp\\beacon.dll",
                        "Path": "C:\\Temp\\beacon.dll",
                        "FileName": "beacon.dll",
                        "Sha256": "abc123",
                    }
                ],
            )
            stale_manifest_path = exports_dir / "stale-export.json"
            latest_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            stale_manifest_path.write_text(json.dumps({"exported_files": []}) + "\n", encoding="utf-8")
            latest_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR3000",
                        "hunt_id": "H.3000",
                        "requested_artifacts": ["Windows.Search.FileFinder"],
                        "exported_files": [
                            {
                                "artifact": "Windows.Search.FileFinder",
                                "artifact_name": "Windows.Search.FileFinder",
                                "row_count": 1,
                                "output_file": str(good_csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state_path = hunt_dir / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR3000",
                        "hunt_id": "H.3000",
                        "profile": "filefinder",
                        "export_manifest_file": str(stale_manifest_path),
                        "latest_export_manifest_file": str(latest_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=str(state_path),
                    export_manifest=None,
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(case_root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts_analyzed"], 1)
            input_contract = module.read_json((hunt_dir / "review" / "hunt-analysis-input.json").resolve())
            self.assertEqual(input_contract["export_manifest_file"], str(latest_manifest_path.resolve()))

    def test_unknown_artifact_uses_deterministic_generic_projection(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR4000" / "hunts" / "H.4000"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Custom.Artifact_full.csv"
            self.write_csv(
                csv_path,
                [
                    {
                        "Timestamp": "2026-06-01T03:00:00Z",
                        "Host": "WS01",
                        "Path": "C:\\Temp\\odd.txt",
                        "Message": "odd row",
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR4000",
                        "hunt_id": "H.4000",
                        "requested_artifacts": ["Custom.Artifact"],
                        "exported_files": [
                            {
                                "artifact": "Custom.Artifact",
                                "artifact_name": "Custom.Artifact",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts_analyzed"], 1)
            projection = module.read_json(
                (
                    hunt_dir
                    / "review"
                    / "projections"
                    / "Custom.Artifact_saved-hunt-projection.json"
                ).resolve()
            )
            self.assertEqual(projection["artifact_profile_key"], "")
            self.assertEqual(
                projection["artifact_profile_resolution"],
                "generic-default",
            )
            self.assertEqual(
                projection["selected_source_fields"],
                ["Timestamp", "Host", "Message", "Path"],
            )

    def test_analyze_from_download_manifest_without_export_manifest(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5000" / "hunts" / "H.5000"
            downloads_dir = hunt_dir / "downloads"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T04:05:06Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": 4625,
                        "EventRecordID": 99,
                        "Username": "download-only-user",
                        "EventData": {"IpAddress": "198.51.100.10"},
                    }
                ],
            )
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "downloaded_at": "2026-06-01T04:10:00Z",
                        "investigation_id": "IR5000",
                        "hunt_id": "H.5000",
                        "target_collection_type": "DetectRaptor.Windows.Detection.Evtx",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "mode": "hunt-results-jsonl",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=None,
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["download_manifest_file"], str(download_manifest_path.resolve()))
            self.assertEqual(payload["export_manifest_file"], "")
            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")

            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["ReviewArtifact"], "Windows.EventLogs.EvtxHunter")
            self.assertIn("Username=download-only-user", rows[0]["ReviewSummary"])

    def test_cli_accepts_download_manifest_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5050" / "hunts" / "H.5050"
            downloads_dir = hunt_dir / "downloads"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T04:15:00Z",
                        "Provider": "Provider",
                        "EventID": 2,
                        "Username": "cli-download-only",
                    }
                ],
            )
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5050",
                        "hunt_id": "H.5050",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stdout_text, stderr_text = self.run_main_with_stdout(
                [
                    "--download-manifest",
                    str(download_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr_text, "")
            payload = json.loads(stdout_text)
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["hunt_id"], "H.5050")

    def test_csv_and_jsonl_split_fields_preserve_jsonl_only_review_fields(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5100" / "hunts" / "H.5100"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_csv(
                csv_path,
                [
                    {
                        "EventTime": "2026-06-01T05:00:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": "4624",
                        "EventRecordID": "41",
                    }
                ],
            )
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T05:00:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": 4624,
                        "EventRecordID": 41,
                        "Username": "jsonl-only-user",
                        "EventData": {"IpAddress": "203.0.113.55"},
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5100",
                        "hunt_id": "H.5100",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5100",
                        "hunt_id": "H.5100",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertNotIn("Username", rows[0])
            self.assertNotIn("EventData", rows[0])

            projection = module.read_json(
                hunt_dir
                / "review"
                / "projections"
                / "Windows.EventLogs.EvtxHunter_saved-hunt-projection.json"
            )
            self.assertEqual(projection["selected_source_fields"], ["EventID", "Provider"])

    def test_mismatched_export_and_download_manifests_fail_closed(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            export_hunt_dir = root / "IR7000" / "hunts" / "H.7000"
            download_hunt_dir = root / "IR8000" / "hunts" / "H.8000"
            export_csv_path = export_hunt_dir / "exports" / "Windows.EventLogs.EvtxHunter_full.csv"
            download_jsonl_path = download_hunt_dir / "downloads" / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_csv(
                export_csv_path,
                [{"EventTime": "2026-06-01T05:30:00Z", "Provider": "Provider", "EventID": "4624"}],
            )
            self.write_jsonl(
                download_jsonl_path,
                [{"EventTime": "2026-06-01T05:30:00Z", "Provider": "Provider", "EventID": 4624, "Username": "wrong-hunt"}],
            )
            export_manifest_path = export_hunt_dir / "exports" / "velociraptor-hunting-export.json"
            download_manifest_path = download_hunt_dir / "downloads" / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR7000",
                        "hunt_id": "H.7000",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(export_csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR8000",
                        "hunt_id": "H.8000",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(download_jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=str(download_manifest_path),
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

    def test_artifact_name_only_manifest_entries_use_non_empty_stable_review_names(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5200" / "hunts" / "H.5200"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "artifact-name-only.csv"
            self.write_csv(
                csv_path,
                [
                    {
                        "Timestamp": "2026-06-01T06:00:00Z",
                        "Host": "WS-5200",
                        "Message": "artifact-name-only row",
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5200",
                        "hunt_id": "H.5200",
                        "requested_artifacts": ["Custom.NameOnly.Artifact"],
                        "exported_files": [
                            {
                                "artifact_name": "Custom.NameOnly.Artifact",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            review_csv_path = hunt_dir / "review" / "by-artifact" / "Custom.NameOnly.Artifact_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(payload["artifacts"][0]["artifact"], "Custom.NameOnly.Artifact")
            self.assertEqual(rows[0]["ReviewArtifact"], "Custom.NameOnly.Artifact")
            self.assertTrue(review_csv_path.exists())

    def test_export_and_download_aliases_for_same_logical_artifact_analyze_once(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5250" / "hunts" / "H.5250"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "detectraptor-evtx.csv"
            jsonl_path = downloads_dir / "evtxhunter.jsonl"

            self.write_csv(
                csv_path,
                [
                    {
                        "EventTime": "2026-06-01T06:30:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": "4624",
                        "Username": "alice",
                    }
                ],
            )
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T06:30:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": 4624,
                        "Username": "alice",
                    }
                ],
            )

            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5250",
                        "hunt_id": "H.5250",
                        "target_collection_type": "DetectRaptor.Windows.Detection.Evtx",
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "exported_files": [
                            {
                                "artifact": "DetectRaptor.Windows.Detection.Evtx",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5250",
                        "hunt_id": "H.5250",
                        "target_collection_type": "DetectRaptor.Windows.Detection.Evtx",
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            review_dir = hunt_dir / "review"
            input_contract = module.read_json(review_dir / "hunt-analysis-input.json")
            review_manifest = module.read_json(review_dir / "hunt-analysis.json")

            self.assertEqual(len(input_contract["artifacts"]), 1)
            self.assertEqual(input_contract["artifacts"][0]["csv_file"], str(csv_path))
            self.assertEqual(input_contract["artifacts"][0]["jsonl_file"], str(jsonl_path))
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(review_manifest["artifacts_analyzed"], 1)
            self.assertEqual(len(review_manifest["artifacts"]), 1)
            self.assertTrue(Path(review_manifest["artifacts"][0]["review_csv_file"]).exists())
            self.assertTrue(Path(review_manifest["artifacts"][0]["review_jsonl_file"]).exists())

    def test_narrower_artifact_rerun_removes_stale_review_files(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5260" / "hunts" / "H.5260"
            exports_dir = hunt_dir / "exports"
            evtx_csv_path = exports_dir / "Windows.EventLogs.EvtxHunter.csv"
            mft_csv_path = exports_dir / "Windows.NTFS.MFT.csv"

            self.write_csv(
                evtx_csv_path,
                [
                    {
                        "EventTime": "2026-06-01T07:00:00Z",
                        "Provider": "Microsoft-Windows-Security-Auditing",
                        "EventID": "4624",
                        "Username": "alice",
                    }
                ],
            )
            self.write_csv(
                mft_csv_path,
                [
                    {
                        "OSPath": "C:\\Windows\\Temp\\evil.exe",
                        "FileSize": "1024",
                        "Created0x10": "2026-06-01T07:10:00Z",
                    }
                ],
            )

            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5260",
                        "hunt_id": "H.5260",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter", "Windows.NTFS.MFT"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(evtx_csv_path),
                            },
                            {
                                "artifact": "Windows.NTFS.MFT",
                                "artifact_name": "Windows.NTFS.MFT",
                                "row_count": 1,
                                "output_file": str(mft_csv_path),
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            full_args = module.argparse.Namespace(
                state_file=None,
                export_manifest=str(export_manifest_path),
                hunt_id=None,
                download_manifest=None,
                investigation_id=None,
                case_root=str(root),
                target=None,
                artifact=[],
                sample_limit=10,
            )
            narrow_args = module.argparse.Namespace(
                state_file=None,
                export_manifest=str(export_manifest_path),
                hunt_id=None,
                download_manifest=None,
                investigation_id=None,
                case_root=str(root),
                target=None,
                artifact=["Windows.EventLogs.EvtxHunter"],
                sample_limit=10,
            )

            module.command_analyze(full_args)

            review_dir = hunt_dir / "review"
            evtx_review_csv = review_dir / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            evtx_review_jsonl = review_dir / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.jsonl"
            evtx_projection = review_dir / "projections" / "Windows.EventLogs.EvtxHunter_saved-hunt-projection.json"
            mft_review_csv = review_dir / "by-artifact" / "Windows.NTFS.MFT_review.csv"
            mft_review_jsonl = review_dir / "by-artifact" / "Windows.NTFS.MFT_review.jsonl"
            mft_projection = review_dir / "projections" / "Windows.NTFS.MFT_saved-hunt-projection.json"

            self.assertTrue(evtx_review_csv.exists())
            self.assertTrue(mft_review_csv.exists())
            self.assertTrue(mft_projection.exists())

            payload = module.command_analyze(narrow_args)
            review_manifest = module.read_json(review_dir / "hunt-analysis.json")

            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(review_manifest["artifacts_analyzed"], 1)
            self.assertEqual([item["artifact"] for item in review_manifest["artifacts"]], ["Windows.EventLogs.EvtxHunter"])
            self.assertTrue(evtx_review_csv.exists())
            self.assertTrue(evtx_review_jsonl.exists())
            self.assertTrue(evtx_projection.exists())
            self.assertFalse(mft_review_csv.exists())
            self.assertFalse(mft_review_jsonl.exists())
            self.assertFalse(mft_projection.exists())

    def test_state_file_and_foreign_manifest_fail_closed(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_hunt_dir = root / "IR6100" / "hunts" / "H.6100"
            foreign_hunt_dir = root / "IR6200" / "hunts" / "H.6200"
            state_path = state_hunt_dir / "state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6100",
                        "hunt_id": "H.6100",
                        "target_os": "windows",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            foreign_jsonl_path = foreign_hunt_dir / "downloads" / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                foreign_jsonl_path,
                [{"EventTime": "2026-06-01T06:30:00Z", "Provider": "Provider", "EventID": 1}],
            )
            foreign_manifest_path = foreign_hunt_dir / "downloads" / "velociraptor-hunting-download.json"
            foreign_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6200",
                        "hunt_id": "H.6200",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(foreign_jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=str(state_path),
                        export_manifest=None,
                        hunt_id=None,
                        download_manifest=str(foreign_manifest_path),
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

    def test_reordered_jsonl_rows_do_not_backfill_csv_rows(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6150" / "hunts" / "H.6150"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_csv(
                csv_path,
                [
                    {"EventTime": "2026-06-01T06:31:00Z", "Provider": "Provider", "EventID": "100", "EventRecordID": "1"},
                    {"EventTime": "2026-06-01T06:32:00Z", "Provider": "Provider", "EventID": "200", "EventRecordID": "2"},
                ],
            )
            self.write_jsonl(
                jsonl_path,
                [
                    {"EventTime": "2026-06-01T06:32:00Z", "Provider": "Provider", "EventID": 200, "EventRecordID": 2, "Username": "user-two"},
                    {"EventTime": "2026-06-01T06:31:00Z", "Provider": "Provider", "EventID": 100, "EventRecordID": 1, "Username": "user-one"},
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6150",
                        "hunt_id": "H.6150",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 2,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6150",
                        "hunt_id": "H.6150",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 2,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["EventID"] for row in rows], ["100", "200"])
            self.assertNotIn("Username", rows[0])

    def test_alias_mismatched_export_and_download_entries_merge_into_one_artifact(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6160" / "hunts" / "H.6160"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "DetectRaptor.Windows.Detection.Evtx_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T06:35:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            self.write_jsonl(
                jsonl_path,
                [{"EventTime": "2026-06-01T06:35:00Z", "Provider": "Provider", "EventID": 1}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            expected_spec_arguments = [
                {
                    "label": "DetectRaptor.Windows.Detection.Evtx",
                    "artifact": "Windows.EventLogs.EvtxHunter",
                    "env": {},
                }
            ]
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6160",
                        "hunt_id": "H.6160",
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "expected_spec_arguments": expected_spec_arguments,
                        "exported_files": [
                            {
                                "artifact": "DetectRaptor.Windows.Detection.Evtx",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6160",
                        "hunt_id": "H.6160",
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "expected_spec_arguments": expected_spec_arguments,
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["artifact"], "DetectRaptor.Windows.Detection.Evtx")

    def test_rerun_prunes_stale_review_files(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6165" / "hunts" / "H.6165"
            exports_dir = hunt_dir / "exports"
            first_csv = exports_dir / "Artifact.One_full.csv"
            second_csv = exports_dir / "Artifact.Two_full.csv"
            self.write_csv(first_csv, [{"Timestamp": "2026-06-01T06:36:00Z", "Host": "WS1", "Message": "one"}])
            self.write_csv(second_csv, [{"Timestamp": "2026-06-01T06:37:00Z", "Host": "WS1", "Message": "two"}])
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6165",
                        "hunt_id": "H.6165",
                        "requested_artifacts": ["Artifact.One", "Artifact.Two"],
                        "exported_files": [
                            {
                                "artifact": "Artifact.One",
                                "artifact_name": "Artifact.One",
                                "row_count": 1,
                                "output_file": str(first_csv),
                            },
                            {
                                "artifact": "Artifact.Two",
                                "artifact_name": "Artifact.Two",
                                "row_count": 1,
                                "output_file": str(second_csv),
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            stale_review_path = hunt_dir / "review" / "by-artifact" / "Artifact.Two_review.csv"
            self.assertTrue(stale_review_path.exists())

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=["Artifact.One"],
                    sample_limit=10,
                )
            )

            self.assertFalse(stale_review_path.exists())
            review_manifest = module.read_json(hunt_dir / "review" / "hunt-analysis.json")
            self.assertEqual(review_manifest["artifacts_analyzed"], 1)

    def test_hunt_id_cannot_be_combined_with_explicit_manifest(self):
        exit_code, stderr_text = self.run_main(
            [
                "--investigation-id",
                "IRX",
                "--hunt-id",
                "H.1234",
                "--download-manifest",
                "/tmp/example.json",
            ]
        )
        self.assertEqual(exit_code, 1)
        self.assertIn("--hunt-id cannot be combined", stderr_text)

    def test_hunt_id_resolves_saved_state_successfully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6500" / "hunts" / "H.6500"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T08:00:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6500",
                        "hunt_id": "H.6500",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state_path = hunt_dir / "state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6500",
                        "hunt_id": "H.6500",
                        "target_os": "windows",
                        "latest_export_manifest_file": str(export_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stdout_text, stderr_text = self.run_main_with_stdout(
                [
                    "--investigation-id",
                    "IR6500",
                    "--hunt-id",
                    "H.6500",
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr_text, "")
            payload = json.loads(stdout_text)
            self.assertEqual(payload["hunt_id"], "H.6500")
            self.assertEqual(payload["artifacts_analyzed"], 1)

    def test_hunt_id_resolves_saved_state_with_latest_download_manifest_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6501" / "hunts" / "H.6501"
            downloads_dir = hunt_dir / "downloads"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                jsonl_path,
                [{"EventTime": "2026-06-01T08:01:00Z", "Provider": "Provider", "EventID": 1}],
            )
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6501",
                        "hunt_id": "H.6501",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state_path = hunt_dir / "state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6501",
                        "hunt_id": "H.6501",
                        "target_os": "windows",
                        "latest_download_manifest_file": str(download_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stdout_text, stderr_text = self.run_main_with_stdout(
                [
                    "--investigation-id",
                    "IR6501",
                    "--hunt-id",
                    "H.6501",
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr_text, "")
            payload = json.loads(stdout_text)
            self.assertEqual(payload["hunt_id"], "H.6501")
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")

    def test_saved_state_ignores_stale_latest_export_when_latest_download_is_valid(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6502" / "hunts" / "H.6502"
            downloads_dir = hunt_dir / "downloads"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                jsonl_path,
                [{"EventTime": "2026-06-01T08:02:00Z", "Provider": "Provider", "EventID": 1}],
            )
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6502",
                        "hunt_id": "H.6502",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state_path = hunt_dir / "state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6502",
                        "hunt_id": "H.6502",
                        "target_os": "windows",
                        "latest_export_manifest_file": str(hunt_dir / "exports" / "missing-export.json"),
                        "latest_download_manifest_file": str(download_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=str(state_path),
                    export_manifest=None,
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")

    def test_saved_state_ignores_obsolete_latest_export_manifest_when_download_is_current(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6503" / "hunts" / "H.6503"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            old_csv_path = exports_dir / "Artifact.Old_full.csv"
            old_csv_path.parent.mkdir(parents=True, exist_ok=True)
            old_csv_path.write_text("Path\nC:/old\n", encoding="utf-8")
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6503",
                        "hunt_id": "H.6503",
                        "requested_artifacts": ["Artifact.Old"],
                        "exported_files": [
                            {
                                "artifact": "Artifact.Old",
                                "artifact_name": "Artifact.Old",
                                "row_count": 1,
                                "output_file": str(old_csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            jsonl_path = downloads_dir / "Artifact.New.jsonl"
            self.write_jsonl(jsonl_path, [{"Timestamp": "2026-06-01T08:03:00Z", "Host": "WS1", "Message": "new"}])
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6503",
                        "hunt_id": "H.6503",
                        "requested_artifacts": ["Artifact.New"],
                        "downloaded_files": [
                            {
                                "artifact": "Artifact.New",
                                "artifact_name": "Artifact.New",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state_path = hunt_dir / "state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6503",
                        "hunt_id": "H.6503",
                        "target_os": "windows",
                        "requested_artifacts": ["Artifact.New"],
                        "latest_export_manifest_file": str(export_manifest_path),
                        "latest_download_manifest_file": str(download_manifest_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=str(state_path),
                    export_manifest=None,
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["artifact"], "Artifact.New")
            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")

    def test_failed_rerun_preserves_last_successful_review_manifest(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6510" / "hunts" / "H.6510"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T08:05:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest = {
                "investigation_id": "IR6510",
                "hunt_id": "H.6510",
                "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                "exported_files": [
                    {
                        "artifact": "Windows.EventLogs.EvtxHunter",
                        "artifact_name": "Windows.EventLogs.EvtxHunter",
                        "row_count": 1,
                        "output_file": str(csv_path),
                    }
                ],
            }
            export_manifest_path.write_text(json.dumps(export_manifest) + "\n", encoding="utf-8")

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            review_manifest_path = hunt_dir / "review" / "hunt-analysis.json"
            self.assertTrue(review_manifest_path.exists())

            export_manifest["exported_files"][0]["output_file"] = str(exports_dir / "missing.csv")
            export_manifest_path.write_text(json.dumps(export_manifest) + "\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=None,
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )
            self.assertTrue(review_manifest_path.exists())
            review_manifest = module.read_json(review_manifest_path)
            self.assertEqual(review_manifest["artifacts_analyzed"], 1)
            self.assertFalse((hunt_dir / "review.__tmp__").exists())

    def test_failed_two_artifact_rerun_preserves_last_successful_review_tree(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6511" / "hunts" / "H.6511"
            exports_dir = hunt_dir / "exports"
            good_csv = exports_dir / "Artifact.One_full.csv"
            bad_csv = exports_dir / "Artifact.Two_full.csv"
            self.write_csv(good_csv, [{"Timestamp": "2026-06-01T08:06:00Z", "Host": "WS1", "Message": "one"}])
            self.write_csv(bad_csv, [{"Timestamp": "2026-06-01T08:07:00Z", "Host": "WS1", "Message": "two"}])
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest = {
                "investigation_id": "IR6511",
                "hunt_id": "H.6511",
                "requested_artifacts": ["Artifact.One", "Artifact.Two"],
                "exported_files": [
                    {
                        "artifact": "Artifact.One",
                        "artifact_name": "Artifact.One",
                        "row_count": 1,
                        "output_file": str(good_csv),
                    },
                    {
                        "artifact": "Artifact.Two",
                        "artifact_name": "Artifact.Two",
                        "row_count": 1,
                        "output_file": str(bad_csv),
                    },
                ],
            }
            export_manifest_path.write_text(json.dumps(export_manifest) + "\n", encoding="utf-8")

            module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            export_manifest["exported_files"][1]["output_file"] = str(exports_dir / "missing.csv")
            export_manifest_path.write_text(json.dumps(export_manifest) + "\n", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=None,
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

            review_dir = hunt_dir / "review"
            self.assertTrue((review_dir / "hunt-analysis.json").exists())
            self.assertTrue((review_dir / "hunt-analysis-input.json").exists())
            self.assertTrue((review_dir / "by-artifact" / "Artifact.One_review.csv").exists())
            self.assertTrue(
                (
                    review_dir
                    / "projections"
                    / "Artifact.One_saved-hunt-projection.json"
                ).exists()
            )
            self.assertFalse((hunt_dir / "review.__tmp__").exists())

    def test_manifest_output_file_outside_hunt_tree_fails_closed(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6300" / "hunts" / "H.6300"
            foreign_hunt_dir = root / "IR6301" / "hunts" / "H.6301"
            foreign_csv_path = foreign_hunt_dir / "exports" / "foreign.csv"
            self.write_csv(
                foreign_csv_path,
                [{"EventTime": "2026-06-01T07:00:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = hunt_dir / "exports" / "velociraptor-hunting-export.json"
            export_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6300",
                        "hunt_id": "H.6300",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(foreign_csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                module.command_analyze(
                    module.argparse.Namespace(
                        state_file=None,
                        export_manifest=str(export_manifest_path),
                        hunt_id=None,
                        download_manifest=None,
                        investigation_id=None,
                        case_root=str(root),
                        target=None,
                        artifact=[],
                        sample_limit=10,
                    )
                )

    def test_relative_manifest_output_file_resolves_from_the_manifest_folder(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir, tempfile.TemporaryDirectory() as elsewhere:
            root = Path(tmpdir)
            exports_dir = root / "IR6302" / "hunts" / "H.6302" / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T07:00:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            args = module.argparse.Namespace(
                state_file=None,
                export_manifest=str(export_manifest_path),
                hunt_id=None,
                download_manifest=None,
                investigation_id=None,
                case_root=str(root),
                target=None,
                artifact=[],
                sample_limit=10,
            )
            results = []
            # The process CWD must not decide which file a saved manifest names.
            with contextlib.chdir(elsewhere):
                for output_file in (csv_path.name, f"../../H.6303/exports/{csv_path.name}"):
                    export_manifest_path.write_text(
                        json.dumps(
                            {
                                "investigation_id": "IR6302",
                                "hunt_id": "H.6302",
                                "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                                "exported_files": [
                                    {
                                        "artifact": "Windows.EventLogs.EvtxHunter",
                                        "artifact_name": "Windows.EventLogs.EvtxHunter",
                                        "row_count": 1,
                                        "output_file": output_file,
                                    }
                                ],
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    try:
                        results.append(module.command_analyze(args))
                    except RuntimeError as exc:
                        results.append(str(exc))

        accepted, rejected = results
        self.assertIsInstance(accepted, dict, accepted)
        self.assertEqual(Path(accepted["artifacts"][0]["source_file"]), csv_path.resolve())
        self.assertEqual(accepted["artifacts"][0]["review_row_count_csv"], 1)
        self.assertIn("is outside the expected hunt", rejected)

    def test_headerless_csv_falls_back_to_jsonl(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6175" / "hunts" / "H.6175"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_path.write_text("2026-06-01T06:40:00Z,Provider,4624,headerless-user\n", encoding="utf-8")
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T06:40:00Z",
                        "Provider": "Provider",
                        "EventID": 4624,
                        "Username": "headerless-user",
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6175",
                        "hunt_id": "H.6175",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6175",
                        "hunt_id": "H.6175",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")
            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertIn("Username=headerless-user", rows[0]["ReviewSummary"])

    def test_header_only_csv_falls_back_to_jsonl(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6180" / "hunts" / "H.6180"
            exports_dir = hunt_dir / "exports"
            downloads_dir = hunt_dir / "downloads"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_path.write_text("EventTime,Provider,EventID,Username\n", encoding="utf-8")
            self.write_jsonl(
                jsonl_path,
                [
                    {
                        "EventTime": "2026-06-01T06:41:00Z",
                        "Provider": "Provider",
                        "EventID": 4624,
                        "Username": "header-only-user",
                    }
                ],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6180",
                        "hunt_id": "H.6180",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 0,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6180",
                        "hunt_id": "H.6180",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=str(download_manifest_path),
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )

            self.assertEqual(payload["artifacts"][0]["source_kind"], "jsonl")
            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertIn("Username=header-only-user", rows[0]["ReviewSummary"])

    def test_empty_csv_without_jsonl_produces_empty_review_outputs(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6400" / "hunts" / "H.6400"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_path.write_text("", encoding="utf-8")
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6400",
                        "hunt_id": "H.6400",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 0,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["source_kind"], "csv")
            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows, [])

    def test_single_column_csv_does_not_traceback(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6425" / "hunts" / "H.6425"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Custom.Artifact_full.csv"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_path.write_text("Path\nC:/x\n", encoding="utf-8")
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6425",
                        "hunt_id": "H.6425",
                        "requested_artifacts": ["Custom.Artifact"],
                        "exported_files": [
                            {
                                "artifact": "Custom.Artifact",
                                "artifact_name": "Custom.Artifact",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["source_kind"], "csv")

    def test_large_csv_field_does_not_fail_review(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6426" / "hunts" / "H.6426"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            large_message = "A" * 200000
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T07:20:00Z", "Provider": "Provider", "EventID": "1", "Message": large_message}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6426",
                        "hunt_id": "H.6426",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = module.command_analyze(
                module.argparse.Namespace(
                    state_file=None,
                    export_manifest=str(export_manifest_path),
                    hunt_id=None,
                    download_manifest=None,
                    investigation_id=None,
                    case_root=str(root),
                    target=None,
                    artifact=[],
                    sample_limit=10,
                )
            )
            self.assertEqual(payload["artifacts_analyzed"], 1)
            self.assertEqual(payload["artifacts"][0]["source_kind"], "csv")
            review_csv_path = hunt_dir / "review" / "by-artifact" / "Windows.EventLogs.EvtxHunter_review.csv"
            with review_csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Message"], large_message)

    def test_malformed_manifest_row_count_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6450" / "hunts" / "H.6450"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T07:30:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6450",
                        "hunt_id": "H.6450",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": "NaN",
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stderr_text = self.run_main(
                [
                    "--export-manifest",
                    str(export_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("row_count", stderr_text)

    def test_missing_manifest_row_count_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6460" / "hunts" / "H.6460"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T07:35:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6460",
                        "hunt_id": "H.6460",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stderr_text = self.run_main(
                [
                    "--export-manifest",
                    str(export_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("row_count", stderr_text)

    def test_manifest_row_count_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR6470" / "hunts" / "H.6470"
            exports_dir = hunt_dir / "exports"
            csv_path = exports_dir / "Windows.EventLogs.EvtxHunter_full.csv"
            self.write_csv(
                csv_path,
                [{"EventTime": "2026-06-01T07:40:00Z", "Provider": "Provider", "EventID": "1"}],
            )
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR6470",
                        "hunt_id": "H.6470",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 99,
                                "output_file": str(csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stderr_text = self.run_main(
                [
                    "--export-manifest",
                    str(export_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("row_count mismatch", stderr_text)

    def test_malformed_state_and_manifest_inputs_fail_closed_with_user_facing_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5300" / "hunts" / "H.5300"
            downloads_dir = hunt_dir / "downloads"
            jsonl_path = downloads_dir / "Windows.EventLogs.EvtxHunter.jsonl"
            self.write_jsonl(
                jsonl_path,
                [{"EventTime": "2026-06-01T07:00:00Z", "Provider": "Provider", "EventID": 1}],
            )

            valid_download_manifest_path = downloads_dir / "velociraptor-hunting-download.json"
            valid_download_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5300",
                        "hunt_id": "H.5300",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "downloaded_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(jsonl_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            malformed_state_path = hunt_dir / "state.json"
            malformed_state_path.write_text("[]\n", encoding="utf-8")
            exit_code, stderr_text = self.run_main(
                [
                    "--state-file",
                    str(malformed_state_path),
                    "--download-manifest",
                    str(valid_download_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("State file", stderr_text)

            malformed_state_path.unlink()
            exports_dir = hunt_dir / "exports"
            malformed_manifest_path = exports_dir / "bad-export-manifest.json"
            malformed_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            malformed_manifest_path.write_text("[]\n", encoding="utf-8")
            exit_code, stderr_text = self.run_main(
                [
                    "--export-manifest",
                    str(malformed_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("Manifest", stderr_text)

    def test_missing_output_file_fails_closed_with_user_facing_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            hunt_dir = root / "IR5400" / "hunts" / "H.5400"
            exports_dir = hunt_dir / "exports"
            missing_csv_path = exports_dir / "missing.csv"
            export_manifest_path = exports_dir / "velociraptor-hunting-export.json"
            export_manifest_path.parent.mkdir(parents=True, exist_ok=True)
            export_manifest_path.write_text(
                json.dumps(
                    {
                        "investigation_id": "IR5400",
                        "hunt_id": "H.5400",
                        "requested_artifacts": ["Windows.EventLogs.EvtxHunter"],
                        "exported_files": [
                            {
                                "artifact": "Windows.EventLogs.EvtxHunter",
                                "artifact_name": "Windows.EventLogs.EvtxHunter",
                                "row_count": 1,
                                "output_file": str(missing_csv_path),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code, stderr_text = self.run_main(
                [
                    "--export-manifest",
                    str(export_manifest_path),
                    "--case-root",
                    str(root),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("No readable source file exists", stderr_text)

    def test_multi_source_manifest_items_remain_distinct(self):
        module = self.module
        items = [
            {
                "artifact": "Generic.Client.Info",
                "artifact_name": "Generic.Client.Info",
                "artifact_source": "Generic.Client.Info/BasicInformation",
                "row_count": 2,
            },
            {
                "artifact": "Generic.Client.Info",
                "artifact_name": "Generic.Client.Info",
                "artifact_source": "Generic.Client.Info/LinuxInfo",
                "row_count": 2,
            },
        ]

        mapped = module.build_manifest_item_map(
            items,
            [{"label": "Generic.Client.Info", "artifact": "Generic.Client.Info"}],
            ["Generic.Client.Info"],
        )
        entries = [
            module.build_artifact_entry(item, None, 10)
            for item in mapped.values()
        ]
        coalesced = module.coalesce_artifact_entries(entries)

        self.assertEqual(
            list(mapped),
            [
                "Generic.Client.Info/BasicInformation",
                "Generic.Client.Info/LinuxInfo",
            ],
        )
        self.assertEqual(len(coalesced), 2)
        self.assertTrue(
            all(
                module.artifact_matches_selector(entry, ["Generic.Client.Info"])
                for entry in coalesced
            )
        )

    def test_saved_state_lookup_uses_flat_hunt_directory(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            state_path = (
                root
                / "IR9003"
                / "hunts"
                / "H.unscoped"
                / "state.json"
            )
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text("{}\n", encoding="utf-8")

            self.assertEqual(
                module.find_saved_state_by_hunt_id(root, "IR9003", "H.unscoped"),
                state_path,
            )


if __name__ == "__main__":
    unittest.main()
