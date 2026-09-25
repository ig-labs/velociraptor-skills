"""Public Autoruns profile routing, retirement and collection isolation."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from vraptor.agent.config import ResolvedAgentExecution, application_default_agent_route
from vraptor.hunt import command as workflow
from vraptor.autoruns import golden

ARTIFACT = "IG.Windows.Sysinternals.Autoruns"

class AutorunsWorkflowTest(unittest.TestCase):
    def argv(self, *extra):
        return ["analyze", "--id", "fixture", "--hunt-id", "H.fixture",
                "--artifact", ARTIFACT, "--profile", "autoruns", *extra]

    def test_only_canonical_profile_is_available(self):
        args = workflow.parse_args(self.argv())
        self.assertEqual(args.profile, "autoruns")
        self.assertNotIn("autoruns_test", workflow.generic.HUNT_PROFILES)
        self.assertIn("autoruns", workflow.generic.HUNT_PROFILES)
        for retired in ("autoruns_test", "autoruns_dedup"):
            for command in ("run", "analyze"):
                with self.subTest(retired=retired, command=command), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        workflow.parse_args([command, "--id", "fixture", "--profile", retired])

    def test_test_flags_and_unsupported_scope_are_rejected(self):
        for extra in (("--autoruns-test-mode", "regex-review"), ("--vql-only",),
                      ("--show-vql",), ("--autoruns-test-vql-file", "/fixture/query.vql"),
                      ("--analysis-mode", "stack"), ("--use-case", "autoruns-lolbin"),
                      ("--autoruns-golden-tool", "Autoruns.GoldenDB"),
                      ("--autoruns-golden-version", "current"),
                      ("--no-autoruns-golden",), ("--autoruns-golden-promote-reviewed",),
                      ("--time-from", "2026-09-01T00:00:00Z"), ("--update",)):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    workflow.parse_args(self.argv(*extra))

    def test_shared_stack_threshold_option(self):
        self.assertEqual(workflow.parse_args(self.argv()).stack_max_total_rows, 20)
        self.assertIsNone(workflow.parse_args(self.argv("--stack-max-total-rows", "0")).stack_max_total_rows)
        self.assertEqual(workflow.parse_args(self.argv("--stack-max-total-rows", "100")).stack_max_total_rows, 100)
        generic = workflow.parse_args(["analyze", "--id", "fixture", "--hunt-id", "H.fixture",
            "--analysis-mode", "stack", "--stack-max-total-rows", "100"])
        self.assertEqual(generic.stack_max_total_rows, 100)
        for extra in ([], ["--stack-max-total-rows", "0"]):
            generic = workflow.parse_args(["analyze", "--id", "fixture", "--hunt-id", "H.fixture",
                "--analysis-mode", "stack", *extra])
            self.assertIsNone(generic.stack_max_total_rows)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            workflow.parse_args(["analyze", "--snapshot", "/fixture/snapshot.json",
                                 "--stack-max-total-rows", "100"])
        for value in ("-1", "1.5"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    workflow.parse_args(self.argv("--stack-max-total-rows", value))

    def test_profile_routes_to_dedup_handler(self):
        args = workflow.parse_args(self.argv())
        with mock.patch.object(workflow, "command_autoruns", return_value={"action":"autoruns"}) as review, \
             mock.patch.object(workflow.live_hunt_analysis, "analyze_live_hunt", side_effect=AssertionError("legacy review")):
            self.assertEqual(workflow.command_analyze(args), {"action":"autoruns"})
        review.assert_called_once_with(args)

    def test_general_autoruns_fails_before_any_hunt_is_processed(self):
        # Even when Autoruns occurs later in a group, no preceding hunt is retried/reviewed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_path = root / "api.yaml"
            api_path.write_text("fixture")
            args = workflow.parse_args(["analyze", "--id", "fixture", "--group", "G.fixture",
                "--api-client", str(api_path), "--case-root", str(root / "cases")])
            rows = [{"hunt_id":"H.other", "artifacts":["Windows.System.Services"]},
                    {"hunt_id":"H.autoruns", "artifacts":[ARTIFACT]}]
            with mock.patch.object(workflow, "VeloApiClient"), \
                 mock.patch.object(golden, "publish_database", return_value={"status": "current", "database_sha256": "a" * 64}) as sync, \
                 mock.patch.object(workflow, "discover_hunt_rows", return_value=rows), \
                 mock.patch.object(workflow, "retry_missing_clients", side_effect=AssertionError("retry")), \
                 mock.patch.object(workflow, "resolve_agent_execution", side_effect=AssertionError("model")):
                with self.assertRaisesRegex(RuntimeError, "--profile autoruns"):
                    workflow.command_analyze(args)

    def test_live_command_uses_canonical_source_export_labels(self):
        for extra, expected in (((), 20), (("--stack-max-total-rows", "100"), 100),
                                (("--stack-max-total-rows", "0"), None)):
            with self.subTest(extra=extra):
                self._assert_live_command_source_export(extra, expected)

    def _assert_live_command_source_export(self, extra, expected):
        from vraptor.autoruns import dedup_ai as dedup
        from vraptor.autoruns import review as source
        with tempfile.TemporaryDirectory() as directory:
            args = workflow.parse_args(self.argv("--case-root", str(Path(directory)/"cases"), *extra))
            with mock.patch.object(dedup.autoruns_regex_db, "load"), \
                 mock.patch.object(workflow, "resolve_agent_execution", return_value=ResolvedAgentExecution(route=application_default_agent_route())), \
                 mock.patch.object(workflow, "resolve_api_client", return_value=Path("/fixture/api.yaml")), \
                 mock.patch.object(workflow, "VeloApiClient"), \
                 mock.patch.object(golden, "publish_database", return_value={"status": "current", "database_sha256": "a" * 64}) as sync, \
                 mock.patch.object(workflow.generic, "query_single_hunt", return_value={"artifacts":[ARTIFACT]}), \
                 mock.patch.object(source, "run", return_value={"stats_json":"/fixture/stats.json"}) as export, \
                 mock.patch.object(dedup, "review_saved", return_value={"action":"autoruns"}) as review:
                self.assertEqual(workflow.command_autoruns(args), {"action":"autoruns"})
            sync.assert_called_once()
            self.assertEqual(sync.call_args.kwargs["tool_version"], "current")
            self.assertEqual(export.call_args.kwargs["workflow"], "autoruns")
            self.assertEqual(export.call_args.kwargs["max_total_rows"], expected)
            hunt_root = Path(directory).resolve()/"cases/fixture/hunts/H.fixture"
            self.assertEqual(review.call_args.kwargs["hunt_root"], hunt_root)
            source_dir = export.call_args.kwargs["output_dir"]
            self.assertEqual(source_dir.parent.parent, hunt_root.parent)
            self.assertFalse(source_dir.parent.exists())
            self.assertEqual(review.call_args.args, ("/fixture/stats.json",))
            self.assertEqual(review.call_args.kwargs["max_total_rows"], expected)

    def test_skip_ai_does_not_resolve_model_credentials(self):
        from vraptor.autoruns import dedup_ai as dedup
        from vraptor.autoruns import review as source
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        args = workflow.parse_args(self.argv("--skip-ai", "--case-root", temporary.name))
        with mock.patch.object(dedup.autoruns_regex_db, "load"), \
             mock.patch.object(workflow, "resolve_agent_execution", side_effect=AssertionError("credentials")), \
             mock.patch.object(workflow, "resolve_api_client", return_value=Path("/fixture/api.yaml")), \
             mock.patch.object(workflow, "VeloApiClient"), \
                 mock.patch.object(golden, "publish_database", return_value={"status": "current", "database_sha256": "a" * 64}) as sync, \
             mock.patch.object(workflow.generic, "query_single_hunt", return_value={"artifacts":[ARTIFACT]}), \
             mock.patch.object(source, "run", return_value={"stats_json":"/fixture/stats.json"}) as export, \
             mock.patch.object(dedup, "review_saved", return_value={}) as review:
            events = []
            sync.side_effect = lambda *a, **kw: events.append("sync") or {"status": "current", "database_sha256": "a" * 64}
            export.side_effect = lambda *a, **kw: events.append("query") or {"stats_json": "/fixture/stats.json"}
            workflow.command_autoruns(args)
            self.assertEqual(events, ["sync", "query"])
            sync.side_effect = RuntimeError("sync failed")
            export.reset_mock()
            review.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "sync failed"):
                workflow.command_autoruns(args)
            export.assert_not_called()
            review.assert_not_called()
            args.no_autoruns_golden_sync = True
            sync.reset_mock()
            workflow.command_autoruns(args)
            sync.assert_not_called()
        self.assertTrue(review.call_args.kwargs["skip_ai"])
        self.assertIsNone(review.call_args.kwargs["execution"])
        self.assertEqual(export.call_args.kwargs["vql_file"], dedup.template())

    def test_removed_review_switches_are_rejected(self):
        for option in ("--autoruns-review-from", "--autoruns-review-output-dir"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    workflow.parse_args(self.argv(option, "/fixture/path"))

    def test_repeated_runs_use_new_source_paths_and_same_analysis_csv(self):
        from vraptor.autoruns import dedup_ai as dedup
        from vraptor.autoruns import review as source
        with tempfile.TemporaryDirectory() as directory:
            args = workflow.parse_args(self.argv("--case-root", directory))
            # Profile is also a supported case namespace when no explicit ID is supplied.
            args.investigation_id = None
            args.server_profile = "fixture"
            with mock.patch.object(dedup.autoruns_regex_db, "load"), \
                 mock.patch.object(workflow, "resolve_agent_execution", return_value=ResolvedAgentExecution(route=application_default_agent_route())), \
                 mock.patch.object(workflow, "resolve_api_client", return_value=Path("/fixture/api.yaml")), \
                 mock.patch.object(workflow, "VeloApiClient"), \
                 mock.patch.object(golden, "publish_database", return_value={"status": "current", "database_sha256": "a" * 64}) as sync, \
                 mock.patch.object(workflow.generic, "query_single_hunt", return_value={"artifacts":[ARTIFACT]}), \
                 mock.patch.object(source, "run", return_value={"stats_json":"/fixture/stats.json"}) as export, \
                 mock.patch.object(dedup, "review_saved", return_value={}) as review:
                workflow.command_autoruns(args)
                workflow.command_autoruns(args)
            first, second = [call.kwargs for call in review.call_args_list]
            self.assertEqual(first["hunt_root"], Path(directory).resolve()/"fixture/hunts/H.fixture")
            self.assertEqual(first["hunt_root"], second["hunt_root"])
            self.assertNotEqual(*[call.kwargs["output_dir"] for call in export.call_args_list])
            self.assertEqual(export.call_count, 2)



    def test_historical_test_hunt_marker_remains_recognized(self):
        self.assertTrue(workflow.generic.is_autoruns_hunt({"tags":["dfir-analysis:autoruns_test"]}))
        self.assertFalse(workflow.generic.is_autoruns_hunt({"hunt_description":"question=autoruns_test"}))

    def test_public_type_uses_autoruns_collector_and_rejects_retries(self):
        args = workflow.parse_args([
            "run", "--id", "fixture", "--profile", "autoruns",
            "--question", "Measure filtering and complete residual stacks",
        ])
        self.assertEqual(workflow.public_artifacts(args), [ARTIFACT])
        for option in ("--retry-missing-after-hours", "--retry-max-attempts", "--retry-batch-size"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    workflow.parse_args([
                        "run", "--id", "fixture", "--profile", "autoruns",
                        "--question", "fixture", option, "1",
                    ])

    def test_public_type_returns_reduced_followup_without_retry_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_path = root / "api.yaml"
            api_path.write_text("fixture\n", encoding="utf-8")
            args = workflow.parse_args([
                "run", "--id", "fixture", "--profile", "autoruns",
                "--question", "Benchmark filtering", "--group", "AT-fixture",
                "--api-client", str(api_path), "--case-root", str(root / "cases"),
            ])
            with mock.patch.object(workflow.generic, "parse_args") as native_args, \
                 mock.patch.object(workflow.generic, "command_check", return_value={}), \
                 mock.patch.object(workflow.generic, "command_ensure", return_value={
                     "hunt_id": "H.fixture", "action": "created_new_hunt",
                 }), \
                 mock.patch.object(workflow, "configure_retry_policy",
                                   side_effect=AssertionError("retry configuration")):
                result = workflow.command_run(args)
            self.assertEqual(result["profile"], "autoruns")
            self.assertFalse(result["automatic_missing_client_retries"])
            self.assertIsNone(result["hunts"][0]["retry_policy"])
            argv = result["analysis_follow_up"]["argv"]
            self.assertEqual(argv[argv.index("--profile") + 1], "autoruns")
            self.assertEqual(argv[argv.index("--hunt-id") + 1], "H.fixture")
            self.assertEqual(result["analysis_follow_up"]["required_options"], [])
            native_argv = native_args.call_args.args[0]
            self.assertEqual(native_argv[native_argv.index("--profile") + 1], "autoruns")
            manifest = json.loads(Path(result["group_manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["profile"], "autoruns")

    def test_generic_analysis_refuses_profile_hunt_before_retry_or_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_path = root / "api.yaml"
            api_path.write_text("fixture\n", encoding="utf-8")
            args = workflow.parse_args([
                "analyze", "--id", "fixture", "--hunt-id", "H.fixture",
                "--api-client", str(api_path), "--case-root", str(root / "cases"),
            ])
            with mock.patch.object(workflow, "VeloApiClient"), \
                 mock.patch.object(golden, "publish_database", return_value={"status": "current", "database_sha256": "a" * 64}) as sync, \
                 mock.patch.object(workflow, "discover_hunt_rows", return_value=[{
                     "hunt_id": "H.fixture", "tags": ["dfir-analysis:autoruns"],
                 }]), \
                 mock.patch.object(workflow, "retry_missing_clients",
                                   side_effect=AssertionError("retry")), \
                 mock.patch.object(workflow, "resolve_agent_execution",
                                   side_effect=AssertionError("model")), \
                 mock.patch.object(workflow, "analysis_status_for_row",
                                   side_effect=AssertionError("review")):
                with self.assertRaisesRegex(RuntimeError, "--profile autoruns"):
                    workflow.command_analyze(args)
            self.assertEqual([path for path in (root / "cases").rglob("*") if path.is_file()], [])

    def test_local_group_reuse_depends_on_request_not_retired_profile(self):
        for requested_test, stored_test in ((True, False), (False, True), (True, True)):
            with self.subTest(requested_test=requested_test, stored_test=stored_test), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                groups = root / "fixture" / "hunts" / "groups"
                groups.mkdir(parents=True)
                (groups / "same-signature.json").write_text(json.dumps({
                    "profile": "autoruns" if stored_test else "targeted-artifact",
                    "group": "existing", "hunts": [{
                        "artifact": ARTIFACT, "request_signature": "identical",
                    }],
                }), encoding="utf-8")
                args = workflow.parse_args([
                    "run", "--id", "fixture", "--case-root", str(root),
                    "--question", "fixture", *(
                        ["--profile", "autoruns"] if requested_test else ["--artifact", ARTIFACT]
                    ),
                ])
                with mock.patch.object(workflow.generic, "request_signature", return_value="identical"), \
                     mock.patch.object(workflow.generic, "find_matching_hunts", return_value=[]), \
                     mock.patch.object(workflow, "VeloApiClient"):
                    result = workflow.find_reusable_group(
                        args, artifacts=[ARTIFACT], investigation_id="fixture",
                        api_client=root / "api.yaml", org_id="root",
                    )
                self.assertEqual(result, "existing")

    def test_explicit_group_cannot_overwrite_unknown_artifacts(self):
        for requested_test in (True, False):
            with self.subTest(requested_test=requested_test):
                args = workflow.parse_args([
                    "run", "--id", "fixture", "--group", "existing", "--question", "fixture",
                    *(["--profile", "autoruns"] if requested_test else ["--artifact", ARTIFACT]),
                ])
                with mock.patch.object(workflow, "load_group_manifest", return_value=({
                    "profile": "targeted-artifact" if requested_test else "autoruns",
                }, None)), mock.patch.object(workflow, "resolve_api_client") as resolve:
                    with self.assertRaisesRegex(RuntimeError, "separate --group"):
                        workflow.command_run(args)
                    resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
