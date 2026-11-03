import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vraptor.collect import hydrate


class HydrateVelociraptorExportsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = hydrate


    def test_cli_accepts_shared_progress_options(self):
        args = self.module.parse_args(
            ["--id", "case-hydrate", "--no-progress", "--progress-interval-seconds", "3"]
        )

        self.assertTrue(args.no_progress)
        self.assertEqual(args.progress_interval_seconds, 3.0)


    def test_hydrate_saved_request_reuses_export_ready_coverage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            investigation_dir = Path(tmpdir) / "case-hydrate"
            state_path = (
                investigation_dir
                / "systems"
                / "host01"
                / "collection"
                / "requests"
                / "req-001"
                / "state.json"
            )
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text("{}", encoding="utf-8")
            coverage_path = state_path.parent / "coverage.json"
            coverage_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"artifact": "Windows.Detection.Amcache", "export_state": "exported"},
                            {"artifact": "Windows.EventLogs.EvtxHunter", "export_state": "not_applicable"},
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = self.module.hydrate_saved_request(
                mock.sentinel.api,
                "case-hydrate",
                "host01",
                state_path,
                force_export=False,
            )

            self.assertEqual(result["status"], "already_exported")
            self.assertEqual(result["coverage_manifest_file"], str(coverage_path))

    def test_request_coverage_export_ready_allows_partial_but_rejects_failed_no_output(self):
        partial_payload = {
            "items": [
                {
                    "artifact": "Windows.Registry.Hunter[all]",
                    "status": "partial",
                    "export_state": "exported",
                    "output_classification": "partial-from-error",
                },
                {
                    "artifact": "Windows.EventLogs.EvtxHunter",
                    "status": "empty",
                    "export_state": "not_applicable",
                    "output_classification": "zero-row",
                },
            ]
        }
        failed_payload = {
            "items": [
                {
                    "artifact": "Windows.Sysinternals.Autoruns",
                    "status": "failed",
                    "export_state": "not_applicable",
                    "output_classification": "failed-no-output",
                }
            ]
        }

        self.assertTrue(self.module.request_coverage_export_ready(partial_payload))
        self.assertFalse(self.module.request_coverage_export_ready(failed_payload))

    def test_main_writes_batch_manifest_with_mixed_host_results(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmpdir:
            investigation_dir = Path(tmpdir) / "case-hydrate-main"
            request_dir = (
                investigation_dir
                / "systems"
                / "host01"
                / "collection"
                / "requests"
                / "req-001"
            )
            request_dir.mkdir(parents=True, exist_ok=True)
            (request_dir / "state.json").write_text("{}", encoding="utf-8")

            api_client = Path(tmpdir) / "api_client.yaml"
            api_client.write_text("stub", encoding="utf-8")
            args = module.argparse.Namespace(
                investigation_id="case-hydrate-main",
                investigation_dir=str(investigation_dir),
                case_root=None,
                host=["host01", "host02"],
                api_client=str(api_client),
                org_id="root",
                force_export=False,
                no_progress=False,
                progress_interval_seconds=20.0,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            api_context = mock.MagicMock()
            api_context.__enter__.return_value = mock.sentinel.api
            api_context.__exit__.return_value = False

            with (
                mock.patch.object(module, "parse_args", return_value=args),
                mock.patch.object(
                    module.engagement_context,
                    "resolve",
                    return_value=mock.Mock(
                        engagement_id="case-hydrate-main",
                        server_profile="lab7",
                        api_client=api_client,
                        case_root=investigation_dir.parent,
                        engagement_dir=investigation_dir,
                    ),
                ),
                mock.patch.object(module.collection, "VeloApiClient", return_value=api_context),
                mock.patch.object(
                    module,
                    "hydrate_saved_request",
                    return_value={
                        "hostname": "host01",
                        "request_id": "req-001",
                        "state_file": str(request_dir / "state.json"),
                        "status": "already_exported",
                        "coverage_manifest_file": str(request_dir / "coverage.json"),
                        "export_manifest_file": "",
                        "exported_files": [],
                        "artifact_summary": {},
                        "error": "",
                    },
                ) as hydrate_mock,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = module.main()

            self.assertEqual(exit_code, 0)
            hydrate_mock.assert_called_once()
            payload = json.loads(stdout.getvalue())
            self.assertIn("scope=collection", stderr.getvalue())
            self.assertIn("command=hydrate", stderr.getvalue())
            self.assertIn("phase=complete status=complete", stderr.getvalue())
            self.assertEqual(payload["summary"]["host_status_counts"]["fully_exported"], 1)
            self.assertEqual(payload["summary"]["host_status_counts"]["missing_saved_state"], 1)
            hosts_by_name = {row["hostname"]: row for row in payload["hosts"]}
            self.assertEqual(hosts_by_name["host01"]["host_status"], "fully_exported")
            self.assertEqual(hosts_by_name["host02"]["host_status"], "missing_saved_state")

            manifest_path = (
                investigation_dir
                / "evidence"
                / "velociraptor"
                / "export-hydration.json"
            )
            self.assertTrue(manifest_path.exists())
            manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest_payload["summary"], payload["summary"])


if __name__ == "__main__":
    unittest.main()
