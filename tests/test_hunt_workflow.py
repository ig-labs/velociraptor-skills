import argparse
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = (
    REPO_ROOT
    / "src/vraptor/hunt/command.py"
)
ANALYSIS_PATH = (
    REPO_ROOT
    / "src/vraptor/hunt/analysis.py"
)


def load_module(path: Path, prefix: str):
    name = f"{prefix}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write_snapshot_v2(
    snapshot_dir: Path,
    *,
    hunt_id: str,
    artifact: str,
    rows: list[dict],
    group: str = "IR-test",
    fingerprint: str = "fixture",
    max_tokens: int = 200_000,
    token_encoding: str = "o200k_base",
) -> Path:
    workflow = load_module(WORKFLOW_PATH, "hunt_workflow_fixture")
    writer = workflow.TokenBoundedCsvWriter(
        snapshot_dir / "chunks" / workflow.safe_token(artifact),
        max_tokens=max_tokens,
        token_encoding=token_encoding,
    )
    for row in rows:
        writer.write(row)
    files = writer.close()
    for item in files:
        item["file"] = str(Path(item["file"]).relative_to(snapshot_dir))
    snapshot_path = snapshot_dir / "snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        json.dumps(
            {
                "snapshot_version": 2,
                "chunk_format": "canonical-csv-v1",
                "max_tokens_per_chunk": max_tokens,
                "token_encoding": token_encoding,
                "token_estimator": f"tiktoken:{token_encoding}",
                "hunt_id": hunt_id,
                "group": group,
                "fingerprint": fingerprint,
                "consistent": True,
                "results": [
                    {
                        "artifact": artifact,
                        "artifact_name": artifact,
                        "expected_row_count": len(rows),
                        "extracted_row_count": len(rows),
                        "complete": True,
                        "files": files,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return snapshot_path


def write_snapshot_v3(
    snapshot_dir: Path,
    *,
    hunt_id: str,
    artifact: str,
    rows: list[dict],
    group: str = "IR-test",
    fingerprint: str = "fixture",
    max_tokens: int = 200_000,
    token_encoding: str = "o200k_base",
) -> Path:
    workflow = load_module(WORKFLOW_PATH, "hunt_workflow_v3_fixture")
    chunk_root = Path("chunks") / workflow.safe_token(artifact)
    writer = workflow.TokenBoundedCsvWriter(
        snapshot_dir / chunk_root,
        max_tokens=max_tokens,
        token_encoding=token_encoding,
    )
    for row in rows:
        writer.write(row)
    files = writer.close()
    chunks = []
    for item in files:
        relative_file = Path(item["file"]).relative_to(snapshot_dir)
        chunks.append(
            {
                "path": str(relative_file.relative_to(chunk_root)),
                "partition": item["partition"],
                "hash": item["sha256"],
                "rows": item["row_count"],
                "bytes": item["size_bytes"],
                "tokens": item["estimated_tokens"],
            }
        )
    snapshot_path = snapshot_dir / "snapshot.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(
        json.dumps(
            {
                "snapshot_version": 3,
                "created_at": "2026-07-24T00:00:00Z",
                "hunt": {
                    "id": hunt_id,
                    "group": group,
                    "description": "test fixture",
                },
                "fingerprint": fingerprint,
                "status": "complete",
                "chunking": {
                    "format": "canonical-csv-v1",
                    "max_tokens": max_tokens,
                    "encoding": token_encoding,
                    "estimator": f"tiktoken:{token_encoding}",
                },
                "projection_reference": {"sha256": "fixture"},
                "capture": {},
                "artifacts": [
                    {
                        "label": artifact,
                        "name": artifact,
                        "status": "complete",
                        "expected_rows": len(rows),
                        "extracted_rows": len(rows),
                        "projection": ["*"],
                        "transport": {
                            "batch_rows": 50_000,
                            "attempts": [
                                {"rows": 50_000, "status": "ok"}
                            ],
                        },
                        "chunk_root": str(chunk_root),
                        "chunks": chunks,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return snapshot_path


class HuntWorkflowTest(unittest.TestCase):
    def assert_public_run_uses_api_client(
        self,
        module,
        argv,
        expected_api_client,
    ):
        args = module.parse_args(argv)
        fake_api = mock.MagicMock()
        ensure_result = {
            "hunt_id": "H.regression",
            "action": "created_new_hunt",
            "state": "RUNNING",
            "review_readiness": "not_ready_retry_later",
            "request_signature": "fixture-signature",
            "hunt_description": "fixture",
            "state_file": "",
        }
        native_context = mock.Mock(
            engagement_id="ir9006",
            server_profile="ir9006",
            api_client=expected_api_client.resolve(),
            case_root=Path(args.case_root).resolve(),
        )
        with (
            mock.patch.object(module, "find_reusable_group", return_value=""),
            mock.patch.object(
                module.generic.engagement_context,
                "resolve",
                return_value=native_context,
            ) as resolve_native_context,
            mock.patch.object(
                module.generic.collection,
                "VeloApiClient",
            ) as api_client_class,
            mock.patch.object(
                module.generic,
                "find_matching_hunts",
                return_value=[],
            ) as find_matching_hunts,
            mock.patch.object(
                module.generic,
                "command_ensure",
                return_value=ensure_result,
            ) as command_ensure,
        ):
            api_client_class.return_value.__enter__.return_value = fake_api
            result = module.command_run(args)

        native_args = command_ensure.call_args.args[0]
        self.assertEqual(native_args.api_client_path, expected_api_client.resolve())
        self.assertEqual(native_args.env, ["UserRegex=^admin[.]radius$"])
        self.assertEqual(native_args.include_label, ["ir9006"])
        self.assertTrue(native_args.authorize_template_create)
        self.assertFalse(native_args.force_run)
        self.assertEqual(module.generic.CASE_ROOT, Path(args.case_root).resolve())
        self.assertEqual(module.generic.CURRENT_HUNT_GROUP, result["group"])
        self.assertEqual(
            module.generic.CURRENT_HUNT_QUESTION,
            "Collect historical RDP server names and MRU entries",
        )
        self.assertEqual(module.generic.CURRENT_SERVER_PROFILE, "ir9006")
        api_client_class.assert_called_once_with(
            expected_api_client.resolve(),
            org_id="root",
        )
        find_matching_hunts.assert_called_once()
        resolve_native_context.assert_called_once_with(
            repo_root=module.generic.REPO_ROOT,
            engagement_id="ir9006",
            server_profile=None,
            api_client=str(expected_api_client.resolve()),
            case_root=str(Path(args.case_root).resolve()),
            expected_org_id="root",
        )
        self.assertEqual(result["action"], "hunt_group_ensured")
        self.assertEqual(result["hunt_count"], 1)

    def test_public_run_explicit_api_client_reaches_native_preflight(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_explicit_api")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "explicit-api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")

            self.assert_public_run_uses_api_client(
                module,
                [
                    "run",
                    "--id",
                    "ir9006",
                    "--server-profile",
                    "ir9006",
                    "--api-client",
                    str(api_client),
                    "--case-root",
                    str(root / "cases"),
                    "--artifact",
                    "Windows.Registry.RDP",
                    "--env",
                    "UserRegex=^admin[.]radius$",
                    "--include-label",
                    "ir9006",
                    "--question",
                    "Collect historical RDP server names and MRU entries",
                    "--authorize-template-create",
                ],
                api_client,
            )

    def test_public_run_server_profile_api_client_reaches_native_preflight(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_profile_api")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "ir9006_api_client.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            argv = [
                "run",
                "--id",
                "ir9006",
                "--server-profile",
                "ir9006",
                "--case-root",
                str(root / "cases"),
                "--artifact",
                "Windows.Registry.RDP",
                "--env",
                "UserRegex=^admin[.]radius$",
                "--include-label",
                "ir9006",
                "--question",
                "Collect historical RDP server names and MRU entries",
                "--authorize-template-create",
            ]

            with mock.patch.dict(
                "os.environ",
                {"VELO_LOCAL_CONFIG_ROOT": str(root)},
            ):
                self.assert_public_run_uses_api_client(
                    module,
                    argv,
                    api_client,
                )

    def test_group_run_preflights_all_artifacts_before_template_gate(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_template_preflight")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = argparse.Namespace(
                profile="detectraptor",
                artifact=[
                    "DetectRaptor.Windows.Detection.Evtx",
                    "DetectRaptor.Windows.Detection.MFT",
                ],
                question="Review persistence",
                group="GROUP-test",
                investigation_id="IR2000",
                api_client=str(api_client),
                org_id="root",
                case_root=str(root / "cases"),
                env=[],
                include_label=[],
                exclude_label=[],
                date_after=None,
                date_before=None,
                force_run=False,
                start_paused=False,
                activate_paused=False,
                authorize_template_create=False,
            )

            with (
                mock.patch.object(
                    module.generic,
                    "parse_args",
                    side_effect=[argparse.Namespace(name="one"), argparse.Namespace(name="two")],
                ),
                mock.patch.object(
                    module.generic,
                    "command_check",
                    side_effect=[
                        {"selection_decision": "create_new_hunt"},
                        {
                            "selection_decision": "template_authorization_required",
                            "recommended_template": {
                                "hunt_id": "H.template",
                                "source_artifact_set": [
                                    "DetectRaptor.Windows.Detection.MFT",
                                    "Windows.NTFS.MFT",
                                ],
                                "source_parameters": [],
                            },
                        },
                    ],
                ),
                mock.patch.object(module.generic, "command_ensure") as ensure_mock,
            ):
                result = module.command_run(args)

        self.assertEqual(result["action"], "hunt_group_template_authorization_required")
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["blocked_artifact_count"], 1)
        ensure_mock.assert_not_called()

    def test_validation_debug_routes_snapshot_analysis(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_debug")
        args = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--snapshot",
                "/tmp/snapshot.json",
                "--debug",
            ]
        )

        with mock.patch.object(
            module,
            "command_analyze_snapshot",
            return_value={"status": "complete"},
        ) as analyze_snapshot:
            result = module.command_analyze(args)

        self.assertEqual(result["status"], "complete")
        analyze_snapshot.assert_called_once_with(
            args,
            resolved_limits=mock.ANY,
            resolved_policy=mock.ANY,
            task_mode="targeted_hunt",
            response_depth="standard",
        )

    def test_analyze_operation_resolves_policy_once(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_policy_once")
        args = module.parse_args(
            ["analyze", "--snapshot", "/tmp/snapshot.json"]
        )
        snapshot = module.artifact_policy.build_artifact_policy(
            profiles={},
            scenarios={},
        )

        with mock.patch.object(
            module.artifact_policy,
            "load_artifact_policy",
            return_value=snapshot,
        ) as load_policy, mock.patch.object(
            module,
            "command_analyze_snapshot",
            return_value={"status": "complete"},
        ) as analyze_snapshot:
            result = module.command_analyze(args)

        self.assertEqual(result["status"], "complete")
        load_policy.assert_called_once_with([])
        self.assertIs(
            analyze_snapshot.call_args.kwargs["resolved_policy"],
            snapshot,
        )

    def test_snapshot_debug_writes_bounded_planning_manifest(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_debug_file")
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text("{}", encoding="utf-8")
            args = module.parse_args(
                ["analyze", "--snapshot", str(snapshot), "--debug"]
            )
            with mock.patch.object(
                module.analysis,
                "analyze_snapshot",
                return_value={"status": "complete", "hunt_id": "H.1"},
            ):
                result = module.command_analyze_snapshot(
                    args,
                    resolved_limits=module.analysis_limits.resolve_analysis_limits(),
                    resolved_policy=module.artifact_policy.load_artifact_policy(),
                )
            debug_path = Path(result["validation_debug_file"])
            debug = json.loads(debug_path.read_text(encoding="utf-8"))

        self.assertEqual(debug["schema_version"], 3)
        self.assertEqual(debug["scope_type"], "snapshot")
        self.assertEqual(debug["lane"], "snapshot_planning")
        self.assertEqual(debug["status"], "complete")
        self.assertFalse(debug["raw_rows_persisted"])

    def test_analyze_cli_defaults_to_bounded_live_memory_review(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_analyze_args")
        with mock.patch.dict(
            "os.environ",
            {"AI_SKILLS_ANALYST_AGENT_TIMEOUT_SECONDS": "1800"},
            clear=False,
        ):
            args = module.parse_args(
                [
                    "analyze",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                ]
            )

        self.assertEqual(args.direct_row_limit, 1000)
        self.assertEqual(args.max_review_rows, 1000)
        self.assertEqual(args.max_stack_groups, 2500)
        self.assertEqual(args.sample_rows, 100)
        self.assertIsNone(args.max_review_tokens)
        self.assertEqual(args.max_branches, 20)
        self.assertEqual(args.indicator, [])
        self.assertEqual(args.filter_reference, [])
        self.assertIsNone(args.use_case)
        self.assertIsNone(args.snapshot)
        self.assertFalse(args.update)
        self.assertEqual(args.analysis_mode, "stream")
        self.assertEqual(args.task_mode, "")
        self.assertEqual(args.response_depth, "")
        self.assertEqual(
            module.resolve_task_output(args),
            ("targeted_hunt", "standard"),
        )
        self.assertEqual(args.stack_field_preference, [])
        self.assertEqual(args.stack_field_guidance, "")

        self.assertFalse(args.debug)
        self.assertFalse(args.no_autoruns_golden_sync)
        self.assertFalse(args.include_review_rows)
        self.assertFalse(hasattr(args, "no_stack_ai_review"))
        self.assertFalse(hasattr(args, "stack_ai_model"))
        self.assertFalse(hasattr(args, "stack_ai_timeout_seconds"))

        debug = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--debug",
            ]
        )
        self.assertTrue(debug.debug)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
            SystemExit
        ):
            module.parse_args(
                [
                    "analyze",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                    "--debug-validation",
                ]
            )

        explicit = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--update",
                "--include-review-rows",
                "--format",
                "json",
            ]
        )
        self.assertTrue(explicit.update)
        self.assertTrue(explicit.include_review_rows)
        assessment = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--task-mode",
                "compromise-assessment",
                "--response-depth",
                "rapid",
            ]
        )
        self.assertEqual(
            module.resolve_task_output(assessment),
            ("compromise_assessment", "rapid"),
        )

        with self.assertRaises(SystemExit):
            module.parse_args(
                [
                    "analyze",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                    "--include-review-rows",
                ]
            )
        guided = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--analysis-mode",
                "stack",
                "--stack-field-preference",
                "Name",
                "--stack-field-preference",
                "Exe",
                "--stack-field-preference",
                "CommandLine",
                "--stack-field-guidance",
                "Use one process identity stack.",
            ]
        )
        self.assertEqual(
            guided.stack_field_preference,
            ["Name", "Exe", "CommandLine"],
        )
        self.assertEqual(
            guided.stack_field_guidance,
            "Use one process identity stack.",
        )
        for removed_option in (
            "--no-stack-ai-review",
            "--stack-ai-model",
            "--stack-ai-timeout-seconds",
        ):
            argv = [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                removed_option,
            ]
            if removed_option == "--stack-ai-model":
                argv.append("test-model")
            elif removed_option == "--stack-ai-timeout-seconds":
                argv.append("123")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit
            ):
                module.parse_args(argv)

    def test_analyze_inherits_persisted_group_task_output(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_persisted_output")
        with tempfile.TemporaryDirectory() as tmpdir:
            case_root = Path(tmpdir) / "cases"
            module.write_group_manifest(
                case_root=case_root,
                investigation_id="IR1500",
                group="ASSESS-1",
                profile="targeted-artifact",
                question="Assess the environment",
                hunts=[{"artifact": "Artifact.One", "hunt_id": "H.1"}],
                task_mode="compromise_assessment",
                response_depth="deep",
            )
            args = module.parse_args(
                [
                    "analyze",
                    "--id",
                    "IR1500",
                    "--case-root",
                    str(case_root),
                    "--group",
                    "ASSESS-1",
                ]
            )

            self.assertEqual(
                module.resolve_task_output(args),
                ("compromise_assessment", "deep"),
            )

            args.task_mode = "targeted-hunt"
            self.assertEqual(
                module.resolve_task_output(args),
                ("targeted_hunt", "standard"),
            )

    def test_live_analysis_mode_uses_stack_only_for_explicit_need(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_analysis_mode")
        args = SimpleNamespace(
            analysis_mode="stream",
            use_case=None,
            decisions=None,
            indicator=[],
            filter_reference=[],
        )

        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.Evtx"
                },
            ),
            {"mode": "stream", "reason": "detectraptor_evtx_automatic"},
        )
        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"DetectRaptor.Windows.Detection.MFT"},
            ),
            {"mode": "stream", "reason": "detectraptor_stream"},
        )
        args.detection_regex = "^Rule$"
        with self.assertRaisesRegex(RuntimeError, "available only"):
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"Artifact.Test"},
            )
        args.detection_regex = ""

        args.analysis_mode = "stack"
        with self.assertRaisesRegex(
            RuntimeError,
            "DetectRaptor artifacts use --analysis-mode stream",
        ):
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.MFT"
                },
            )

        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"Artifact.Test"},
            ),
            {"mode": "stack", "reason": "explicit_stack"},
        )

        args.analysis_mode = "stream"
        args.indicator = ["Evidence=evil"]
        with self.assertRaisesRegex(RuntimeError, "--analysis-mode stack"):
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"Artifact.Test"},
            )

        args.indicator = []
        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"Windows.Sysinternals.Autoruns"},
            ),
            {"mode": "stack", "reason": "autoruns_artifact"},
        )

    def test_detectraptor_stream_rejects_stack_only_controls_and_mixed_autoruns(self):
        module = load_module(
            WORKFLOW_PATH,
            "hunt_workflow_detectraptor_stream_only",
        )
        args = SimpleNamespace(
            analysis_mode="stream",
            use_case=None,
            decisions=Path("/case/decisions.json"),
            indicator=[],
            filter_reference=[],
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "--decisions are unavailable",
        ):
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.MFT"
                },
            )

    def test_detectraptor_stack_alias_uses_canonical_evtx_planner(self):
        module = load_module(
            WORKFLOW_PATH,
            "hunt_workflow_detectraptor_stack",
        )
        pattern = r"^Powershell Suspicious CommandLet - IN DEVELOPMENT$"
        args = SimpleNamespace(
            analysis_mode="detectraptor-stack",
            detection_regex=pattern,
            use_case=None,
            decisions=None,
            indicator=[],
            filter_reference=[],
        )

        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.Evtx"
                },
            ),
            {
                "mode": "stream",
                "reason": "detectraptor_stack_compatibility_alias",
            },
        )
        args.detection_regex = ""
        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.Evtx"
                },
            ),
            {
                "mode": "stream",
                "reason": "detectraptor_stack_compatibility_alias",
            },
        )

        args.analysis_mode = "stream"
        args.detection_regex = pattern
        self.assertEqual(
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={"DetectRaptor.Windows.Detection.Evtx"},
            ),
            {"mode": "stream", "reason": "detectraptor_evtx_automatic"},
        )

    def test_analyze_cli_accepts_detectraptor_stack_regex(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_detectraptor_stack_args")
        args = module.parse_args(
            [
                "analyze",
                "--id",
                "IR9008",
                "--hunt-id",
                "H.1",
                "--artifact",
                "DetectRaptor.Windows.Detection.Evtx",
                "--analysis-mode",
                "detectraptor-stack",
                "--detection-regex",
                "^Rule$",
            ]
        )
        self.assertEqual(args.analysis_mode, "detectraptor-stack")
        self.assertEqual(args.detection_regex, "^Rule$")

        args.decisions = None
        with self.assertRaisesRegex(
            RuntimeError,
            "analyzed separately from Autoruns",
        ):
            module.resolve_live_analysis_mode(
                args,
                selected_artifacts={
                    "DetectRaptor.Windows.Detection.MFT",
                    "IG.Windows.Sysinternals.Autoruns",
                },
            )

    def test_analyze_cli_accepts_focused_autoruns_use_case(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_use_case_args")
        for use_case in (
            "autoruns-lolbin",
            "autoruns-rmm",
            "autoruns-unverified",
        ):
            with self.subTest(use_case=use_case):
                args = module.parse_args(
                    [
                        "analyze",
                        "--id",
                        "IR1500",
                        "--hunt-id",
                        "H.1",
                        "--use-case",
                        use_case,
                    ]
                )

                self.assertEqual(args.use_case, use_case)

    def test_analyze_live_command_is_rejected(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_no_analyze_live")
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            module.parse_args(
                [
                    "analyze-live",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                ]
            )

    def test_analyze_snapshot_is_explicit_and_does_not_require_case_id(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_explicit_snapshot")
        args = module.parse_args(
            [
                "analyze",
                "--snapshot",
                "/tmp/snapshot.json",
            ]
        )

        self.assertEqual(args.snapshot, "/tmp/snapshot.json")
        self.assertIsNone(args.investigation_id)

    def test_analyze_rejects_mixed_live_and_snapshot_options(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_mixed_analysis")
        for argv in (
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--snapshot-output",
                "derived",
            ],
            [
                "analyze",
                "--snapshot",
                "/tmp/snapshot.json",
                "--indicator",
                "Evidence=evil",
            ],
            [
                "analyze",
                "--snapshot",
                "/tmp/snapshot.json",
                "--no-autoruns-golden-sync",
            ],
        ):
            with (
                self.subTest(argv=argv),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                module.parse_args(argv)

    def test_analyze_rejects_existing_outputs_before_api_connection(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_output_preflight")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n")
            args = module.parse_args([
                "analyze", "--id", "IR1500", "--hunt-id", "H.1",
                "--artifact", "Artifact.Two", "--api-client", str(api_client),
                "--case-root", str(root / "cases"),
            ])
            bad = module.resolved_hunts_root(args) / "H.1" / "analysis" / "old.sqlite"
            bad.parent.mkdir(parents=True)
            bad.write_text("historical evidence")
            with mock.patch.object(module, "VeloApiClient") as api:
                with self.assertRaisesRegex(RuntimeError, "output_preflight"):
                    module.command_analyze(args)
                api.assert_not_called()
            self.assertEqual(bad.read_text(), "historical evidence")

    def test_group_checks_later_hunt_before_processing_first_hunt(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_group_output_preflight")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n")
            args = module.parse_args([
                "analyze", "--id", "IR1500", "--group", "test",
                "--api-client", str(api_client), "--case-root", str(root / "cases"),
            ])
            bad = module.resolved_hunts_root(args) / "H.2" / "analysis" / "old.sqlite"
            bad.parent.mkdir(parents=True)
            bad.write_text("historical evidence")
            with (
                mock.patch.object(module, "VeloApiClient"),
                mock.patch.object(module, "discover_hunt_rows", return_value=[
                    {"hunt_id": "H.1"}, {"hunt_id": "H.2"},
                ]),
                mock.patch.object(module, "request_for_selected_row") as request,
            ):
                with self.assertRaisesRegex(RuntimeError, "output_preflight"):
                    module.command_analyze(args)
                request.assert_not_called()
            self.assertTrue(bad.exists())

    def test_analyze_hunt_routes_live_without_snapshot_lookup(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_live_route")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = module.parse_args(
                [
                    "analyze",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                    "--artifact",
                    "Artifact.Two",
                    "--api-client",
                    str(api_client),
                    "--case-root",
                    str(root / "cases"),
                ]
            )
            context = mock.MagicMock()
            context.__enter__.return_value = object()
            context.__exit__.return_value = False
            analyst_execution = SimpleNamespace(
                enabled=True,
                timeout_seconds=600,
                max_concurrency=1,
                route=SimpleNamespace(model="test-model", model_context_tokens=0, model_max_output_tokens=0, provider="openai"),
            )
            with (
                mock.patch.object(module, "VeloApiClient", return_value=context),
                mock.patch.object(
                    module,
                    "discover_hunt_rows",
                    return_value=[{"hunt_id": "H.1", "state": "FINISHED"}],
                ),
                mock.patch.object(
                    module,
                    "analysis_status_for_row",
                    side_effect=lambda api, row, case_root, **kwargs: {
                        **row,
                        "baseline_scope_available": False,
                        "review_scope": "ad_hoc_review",
                        "responded_client_count": 90,
                        "completed_client_count": 87,
                        "terminal_client_count": 90,
                        "failed_client_count": 3,
                        "open_client_count": 0,
                        "reported_result_row_count": 123,
                    },
                ),
                mock.patch.object(
                    module,
                    "request_for_selected_row",
                    return_value=object(),
                ) as selected_request,
                mock.patch.object(
                    module,
                    "retry_missing_clients",
                    return_value={
                        "status": "disabled",
                        "hunt_id": "H.1",
                        "queued_count": 0,
                    },
                ),
                mock.patch.object(
                    module,
                    "resolve_agent_execution",
                    return_value=analyst_execution,
                ),
                mock.patch.object(
                    module.flow_analysis_coordinator,
                    "analyze_hunt_flows",
                    return_value={
                        "hunt_id": "H.1",
                        "status": "complete",
                        "review_items": [],
                    },
                ) as analyze_flows,
                mock.patch.object(
                    module.analysis,
                    "analyze_snapshot",
                    side_effect=AssertionError("snapshot analysis was invoked"),
                ),
            ):
                result = module.command_analyze(args)

        self.assertEqual(result["action"], "live_hunt_group_analysis")
        self.assertFalse(result["snapshot_created"])
        self.assertEqual(result["analyses"][0]["analysis_mode"], "stream")
        self.assertEqual(
            result["analyses"][0]["analysis_mode_reason"],
            "default_stream",
        )
        analyze_flows.assert_called_once()
        self.assertEqual(analyze_flows.call_args.kwargs["hunt_id"], "H.1")
        self.assertFalse(analyze_flows.call_args.kwargs["selected_artifacts"])
        self.assertEqual(analyze_flows.call_args.kwargs["hunt_state"], "FINISHED")
        self.assertEqual(
            analyze_flows.call_args.kwargs["reported_result_rows"],
            123,
        )
        self.assertEqual(
            analyze_flows.call_args.kwargs["target_execution_coverage"],
            "not_assessed",
        )
        self.assertEqual(
            analyze_flows.call_args.kwargs["review_scope"],
            "ad_hoc_review",
        )
        self.assertEqual(analyze_flows.call_args.kwargs["task_mode"], "targeted_hunt")
        self.assertEqual(analyze_flows.call_args.kwargs["response_depth"], "standard")
        selected_request.assert_called_once()
        self.assertEqual(
            selected_request.call_args.args[0][module.SELECTED_ARTIFACTS_KEY],
            ["Artifact.Two"],
        )



    def test_autoruns_analysis_can_disable_server_golden_sync(self):
        module = load_module(
            WORKFLOW_PATH,
            "hunt_workflow_autoruns_no_sync",
        )
        args = module.parse_args(
            [
                "analyze",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
                "--no-autoruns-golden-sync",
            ]
        )

        self.assertTrue(args.no_autoruns_golden_sync)


    def test_analyze_snapshot_route_never_opens_live_api(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_route")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot = Path(temp_dir) / "snapshot.json"
            snapshot.write_text("{}\n", encoding="utf-8")
            args = module.parse_args(
                [
                    "analyze",
                    "--snapshot",
                    str(snapshot),
                ]
            )
            with (
                mock.patch.object(
                    module.analysis,
                    "analyze_snapshot",
                    return_value={"hunt_id": "H.1"},
                ) as analyze_snapshot,
                mock.patch.object(
                    module,
                    "VeloApiClient",
                    side_effect=AssertionError("live API was opened"),
                ),
            ):
                result = module.command_analyze(args)

        self.assertEqual(result["action"], "hunt_snapshot_analyzed")
        analyze_snapshot.assert_called_once()

    def test_missing_client_retry_is_bounded_and_idempotent(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_retry")

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query(self, vql, env=None, **kwargs):
                self.calls.append((vql, dict(env or {}), kwargs))
                if "hunt_flows" in vql:
                    return [{"ClientId": "C.1", "State": "FINISHED"}]
                return [{"ClientId": "C.2", "Result": True}]

        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "IR1" / "hunts" / "H.1"
            module.configure_retry_policy(
                hunt_root,
                retry_after_hours=1,
                max_attempts=1,
                batch_size=100,
            )
            baseline = {
                "captured_at": "2026-07-25T00:00:00Z",
                "targets": [
                    {"client_id": "C.1"},
                    {"client_id": "C.2"},
                ],
            }
            api = FakeApi()
            first = module.retry_missing_clients(
                api,
                hunt_id="H.1",
                hunt_root=hunt_root,
                baseline=baseline,
                current_time=module.datetime(
                    2026, 7, 25, 2, 0, tzinfo=module.timezone.utc
                ),
            )
            second = module.retry_missing_clients(
                api,
                hunt_id="H.1",
                hunt_root=hunt_root,
                baseline=baseline,
                current_time=module.datetime(
                    2026, 7, 25, 4, 0, tzinfo=module.timezone.utc
                ),
            )
            state = json.loads(
                module.retry_state_path(hunt_root).read_text(encoding="utf-8")
            )

        queue_calls = [
            call for call in api.calls if "hunt_add" in call[0]
        ]
        self.assertEqual(first["queued_count"], 1)
        self.assertEqual(second["queued_count"], 0)
        self.assertEqual(len(queue_calls), 1)
        self.assertEqual(
            json.loads(queue_calls[0][1]["TargetsJson"]),
            [{"ClientId": "C.2"}],
        )
        self.assertEqual(state["attempts"]["C.2"]["count"], 1)

    def test_missing_client_retry_fails_closed_without_baseline(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_retry_baseline")
        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "IR1" / "hunts" / "H.1"
            module.configure_retry_policy(
                hunt_root,
                retry_after_hours=1,
                max_attempts=1,
                batch_size=100,
            )
            result = module.retry_missing_clients(
                object(),
                hunt_id="H.1",
                hunt_root=hunt_root,
                baseline=None,
            )

        self.assertEqual(result["status"], "baseline_unavailable")
        self.assertEqual(result["queued_count"], 0)

    def test_missing_client_retry_does_not_count_failed_hunt_add(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_retry_failure")

        class FakeApi:
            def query(self, vql, env=None, **kwargs):
                if "hunt_flows" in vql:
                    return []
                return [{"ClientId": "C.1", "Result": False}]

        with tempfile.TemporaryDirectory() as temp_dir:
            hunt_root = Path(temp_dir) / "IR1" / "hunts" / "H.1"
            module.configure_retry_policy(
                hunt_root,
                retry_after_hours=1,
                max_attempts=1,
                batch_size=100,
            )
            result = module.retry_missing_clients(
                FakeApi(),
                hunt_id="H.1",
                hunt_root=hunt_root,
                baseline={
                    "captured_at": "2026-07-25T00:00:00Z",
                    "targets": [{"client_id": "C.1"}],
                },
                current_time=module.datetime(
                    2026, 7, 25, 2, 0, tzinfo=module.timezone.utc
                ),
            )
            state = json.loads(
                module.retry_state_path(hunt_root).read_text(encoding="utf-8")
            )

        self.assertEqual(result["status"], "queue_failed")
        self.assertEqual(result["requested_count"], 1)
        self.assertEqual(result["queued_count"], 0)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(state["attempts"]["C.1"]["count"], 1)
        self.assertNotIn("last_queued_at", state["attempts"]["C.1"])

    def test_retry_missing_command_configures_existing_hunt_without_api(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_retry_command")
        with tempfile.TemporaryDirectory() as temp_dir:
            case_root = Path(temp_dir) / "cases"
            hunt_root = case_root / "IR1" / "hunts" / "H.1"
            baseline_path = hunt_root / "baseline-targets.json"
            module.generic.write_json(
                baseline_path,
                {
                    "captured_at": "2026-07-25T00:00:00Z",
                    "targets": [{"client_id": "C.1"}],
                },
            )
            module.generic.write_json(
                hunt_root / "state.json",
                {"baseline_targets_file": str(baseline_path)},
            )
            args = module.parse_args(
                [
                    "retry-missing",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                    "--case-root",
                    str(case_root),
                    "--after-hours",
                    "24",
                    "--max-attempts",
                    "2",
                    "--batch-size",
                    "50",
                ]
            )
            result = module.command_retry_missing(args)
            policy = json.loads(
                module.retry_policy_path(hunt_root).read_text(encoding="utf-8")
            )

        self.assertEqual(result["action"], "missing_client_retry_configured")
        self.assertFalse(result["server_mutated"])
        self.assertEqual(policy["retry_after_hours"], 24)
        self.assertEqual(policy["max_attempts"], 2)
        self.assertEqual(policy["batch_size"], 50)

    def test_retry_missing_command_requires_saved_baseline(self):
        module = load_module(
            WORKFLOW_PATH,
            "hunt_workflow_retry_command_baseline",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            args = module.parse_args(
                [
                    "retry-missing",
                    "--id",
                    "IR1",
                    "--hunt-id",
                    "H.1",
                    "--case-root",
                    str(Path(temp_dir) / "cases"),
                    "--after-hours",
                    "24",
                ]
            )
            with self.assertRaisesRegex(RuntimeError, "saved target baseline"):
                module.command_retry_missing(args)

    def test_snapshot_cli_defers_token_limit_to_canonical_resolver(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_tokens")
        with mock.patch.dict(
            "os.environ",
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "12345"},
        ):
            args = module.parse_args(
                [
                    "snapshot",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                ]
            )

        self.assertFalse(hasattr(args, "max_tokens"))
        self.assertEqual(
            module.analysis_limits.resolve_analysis_limits(
                {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "12345"}
            ).maximum_evidence_tokens_per_item,
            12345,
        )
        self.assertEqual(args.query_batch_rows, 50_000)
        self.assertEqual(args.query_workers, 8)
        self.assertFalse(hasattr(args, "max_rows"))
        self.assertFalse(hasattr(args, "max_bytes"))
        self.assertFalse(hasattr(args, "max_total_rows"))
        with self.assertRaises(module.analysis_limits.AnalysisLimitsError):
            module.analysis_limits.resolve_analysis_limits(
                {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "500000"}
            )
        with self.assertRaises(SystemExit):
            module.parse_args(
                [
                    "snapshot",
                    "--id",
                    "IR1500",
                    "--hunt-id",
                    "H.1",
                    "--max-tokens",
                    "1000",
                ]
            )

    def test_snapshot_resource_exhaustion_halves_transport_batch(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_halving_batches")
        rows = [{"ClientId": "C.1", "Value": "ok"}]
        resource_error = RuntimeError("response exceeds gRPC message limit")

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch.object(
                    module,
                    "result_batches",
                    side_effect=[
                        resource_error,
                        resource_error,
                        iter([rows]),
                    ],
                ) as result_batches,
                mock.patch.object(
                    module.generic,
                    "is_resource_exhausted_error",
                    side_effect=lambda exc: exc is resource_error,
                ),
            ):
                result = module.extract_artifact_snapshot(
                    object(),
                    hunt_id="H.1",
                    artifact="Artifact.Test",
                    artifact_name="Artifact.Test",
                    expected_rows=1,
                    chunks_root=Path(temp_dir),
                    max_tokens=200_000,
                    token_encoding="o200k_base",
                    query_batch_rows=50_000,
                )

        self.assertEqual(
            [
                call.kwargs["batch_rows"]
                for call in result_batches.call_args_list
            ],
            [50_000, 25_000, 12_500],
        )
        self.assertEqual(
            [attempt["status"] for attempt in result["attempts"]],
            ["resource_exhausted", "resource_exhausted", "ok"],
        )
        self.assertEqual(result["query_batch_rows"], 12_500)
        self.assertTrue(result["complete"])

    def test_snapshot_resource_exhaustion_calculates_batch_from_message_size(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_sized_batches")
        rows = [{"ClientId": "C.1", "Value": "ok"}]
        resource_error = RuntimeError(
            "CLIENT: Received message larger than max "
            "(219388928 vs. 67108864)"
        )
        expected_next, sizing = module.next_query_batch_rows(
            50_000,
            expected_rows=23_379,
            error=resource_error,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch.object(
                    module,
                    "result_batches",
                    side_effect=[resource_error, iter([rows])],
                ) as result_batches,
                mock.patch.object(
                    module.generic,
                    "is_resource_exhausted_error",
                    return_value=True,
                ),
            ):
                result = module.extract_artifact_snapshot(
                    object(),
                    hunt_id="H.1",
                    artifact="Artifact.Test",
                    artifact_name="Artifact.Test",
                    expected_rows=1,
                    chunks_root=Path(temp_dir),
                    max_tokens=200_000,
                    token_encoding="o200k_base",
                    query_batch_rows=50_000,
                )

        self.assertEqual(sizing["strategy"], "response_size")
        self.assertEqual(expected_next, 4827)
        self.assertEqual(
            [
                call.kwargs["batch_rows"]
                for call in result_batches.call_args_list
            ],
            [50_000, 1],
        )
        self.assertEqual(
            result["attempts"][0]["actual_response_bytes"],
            219388928,
        )
        self.assertEqual(
            result["attempts"][0]["next_query_batch_rows"],
            1,
        )
        self.assertTrue(result["complete"])

    def test_concurrent_flow_extraction_is_bounded_and_complete(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_concurrent_flows")
        artifact = "Artifact.Test"
        flow_rows = [
            {
                "ClientId": f"C.{index}",
                "FlowId": f"F.{index}",
                "Flow": {
                    "state": "FINISHED",
                    "total_collected_rows": 1,
                    "artifacts_with_results": [artifact],
                },
            }
            for index in range(4)
        ]

        class FakeApi:
            def __init__(self):
                self.lock = threading.Lock()
                self.active = 0
                self.max_active = 0

            def query_batches(self, vql, env, **kwargs):
                with self.lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                try:
                    time.sleep(0.03)
                    yield [
                        {
                            "Fqdn": "",
                            "Value": env["FlowId"],
                        }
                    ]
                finally:
                    with self.lock:
                        self.active -= 1

        api = FakeApi()
        with tempfile.TemporaryDirectory() as temp_dir:
            result = module.extract_artifact_snapshot_concurrent(
                api,
                flow_rows=flow_rows,
                client_identities={
                    f"C.{index}": {
                        "fqdn": f"C.{index}.example.test",
                        "hostname": f"C.{index}",
                    }
                    for index in range(4)
                },
                workers=2,
                hunt_id="H.1",
                artifact=artifact,
                artifact_name=artifact,
                expected_rows=4,
                chunks_root=Path(temp_dir),
                max_tokens=200_000,
                token_encoding="o200k_base",
                query_batch_rows=50_000,
            )
            files_exist = all(
                Path(item["file"]).is_file() for item in result["files"]
            )

        self.assertEqual(result["transport_mode"], "concurrent-flow")
        self.assertEqual(result["query_workers"], 2)
        self.assertEqual(result["flow_count"], 4)
        self.assertEqual(result["extracted_row_count"], 4)
        self.assertEqual(len(result["files"]), 4)
        self.assertTrue(result["complete"])
        self.assertTrue(files_exist)
        self.assertEqual(api.max_active, 2)
        self.assertEqual(
            {item["partition"] for item in result["files"]},
            {
                "Fqdn-C.0.example.test",
                "Fqdn-C.1.example.test",
                "Fqdn-C.2.example.test",
                "Fqdn-C.3.example.test",
            },
        )

    def test_snapshot_result_vql_uses_global_projection_and_select_star_fallback(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_projection")
        projections = module.load_snapshot_projections(
            module.artifact_policy.load_artifact_policy()
        )
        selected = projections["DetectRaptor.Windows.Detection.Evtx"]

        class FakeApi:
            def __init__(self):
                self.calls = []

            def query_batches(self, vql, env, **kwargs):
                self.calls.append((vql, env, kwargs))
                yield []

        api = FakeApi()
        list(
            module.result_batches(
                api,
                "H.1",
                "DetectRaptor.Windows.Detection.Evtx",
                batch_rows=50_000,
                vql_select=selected,
            )
        )
        list(
            module.result_batches(
                api,
                "H.1",
                "Artifact.Unprofiled",
                batch_rows=50_000,
            )
        )

        projected_vql = api.calls[0][0]
        self.assertIn("Detection.Name AS Detection", projected_vql)
        self.assertIn(
            "if(condition=Message, then=Message, else=EventData) AS Evidence",
            projected_vql,
        )
        self.assertNotIn("SELECT *", projected_vql)
        self.assertEqual(
            api.calls[1][0],
            "SELECT * FROM hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
        )

    def test_snapshot_fails_when_one_csv_row_exceeds_token_limit(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_oversized_row")
        with tempfile.TemporaryDirectory() as temp_dir:
            writer = module.TokenBoundedCsvWriter(
                Path(temp_dir),
                max_tokens=10,
                token_encoding="o200k_base",
            )
            with self.assertRaisesRegex(
                module.SnapshotRowTokenLimitError,
                "One snapshot row exceeds",
            ):
                writer.write(
                    {
                        "ClientId": "C.1",
                        "Message": "oversized evidence " * 100,
                    }
                )

    def test_force_run_is_passed_to_native_ensure(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        args = argparse.Namespace(
            profile=None,
            artifact=["Artifact.Targeted"],
            question="Collect fresh results",
            group=None,
            investigation_id="case-test",
            api_client="/tmp/api.yaml",
            org_id="root",
            case_root="/tmp/cases",
            env=[],
            include_label=[],
            exclude_label=[],
            date_after=None,
            date_before=None,
            force_run=True,
            start_paused=False,
            activate_paused=False,
        )

        argv = module.generic_ensure_argv(
            args,
            artifact="Artifact.Targeted",
            group="HUNT-fresh",
            investigation_id="case-test",
            api_client=Path("/tmp/api.yaml"),
            org_id="root",
        )

        self.assertIn("--force-run", argv)

    def test_detectraptor_run_fans_out_to_priority_native_hunts(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = argparse.Namespace(
                profile="detectraptor",
                artifact=[],
                question="Find compromise leads",
                group="DR-test",
                investigation_id="case-test",
                api_client=str(api_client),
                org_id="root",
                case_root=str(root / "cases"),
                env=[],
                include_label=[],
                exclude_label=[],
                date_after=None,
                date_before=None,
                force_run=False,
                start_paused=False,
                activate_paused=False,
            )
            parsed = []

            def fake_parse(argv, **kwargs):
                parsed.append(argv)
                artifact = argv[argv.index("--artifact") + 1]
                return argparse.Namespace(artifact=artifact)

            def fake_ensure(generic_args):
                artifact = generic_args.artifact
                return {
                    "hunt_id": f"H.{len(parsed)}",
                    "action": "created_new_hunt",
                    "state": "RUNNING",
                    "review_readiness": "not_ready_retry_later",
                    "request_signature": artifact,
                    "hunt_description": f"dfir-group=DR-test {artifact}",
                    "state_file": "",
                }

            with (
                mock.patch.object(module, "find_reusable_group", return_value=""),
                mock.patch.object(module.generic, "parse_args", side_effect=fake_parse),
                mock.patch.object(
                    module.generic,
                    "command_check",
                    return_value={"selection_decision": "create_new_hunt"},
                ),
                mock.patch.object(module.generic, "command_ensure", side_effect=fake_ensure),
            ):
                result = module.command_run(args)

        self.assertEqual(
            result["hunt_count"],
            len(module.generic.profile_artifact_labels("detectraptor")),
        )
        self.assertEqual(
            [item["artifact"] for item in result["hunts"]],
            module.generic.profile_artifact_labels("detectraptor"),
        )
        self.assertTrue(all("--group" in argv for argv in parsed))

    def test_detectraptor_run_accepts_subset_artifacts(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            requested = [
                "DetectRaptor.Windows.Detection.Evtx",
                "DetectRaptor.Windows.Detection.Applications",
                "DetectRaptor.Windows.Detection.Powershell.PSReadline",
                "DetectRaptor.Windows.Detection.MFT",
            ]
            args = argparse.Namespace(
                profile="detectraptor",
                artifact=requested,
                question="Find compromise leads",
                group="DR-test",
                investigation_id="case-test",
                api_client=str(api_client),
                org_id="root",
                case_root=str(root / "cases"),
                env=[],
                include_label=[],
                exclude_label=[],
                date_after=None,
                date_before=None,
                force_run=False,
                start_paused=False,
                activate_paused=False,
            )
            parsed = []

            def fake_parse(argv, **kwargs):
                parsed.append(argv)
                artifact = argv[argv.index("--artifact") + 1]
                return argparse.Namespace(artifact=artifact)

            def fake_ensure(generic_args):
                artifact = generic_args.artifact
                return {
                    "hunt_id": f"H.{len(parsed)}",
                    "action": "created_new_hunt",
                    "state": "RUNNING",
                    "review_readiness": "not_ready_retry_later",
                    "request_signature": artifact,
                    "hunt_description": f"dfir-group=DR-test {artifact}",
                    "state_file": "",
                }

            with (
                mock.patch.object(module, "find_reusable_group", return_value=""),
                mock.patch.object(module.generic, "parse_args", side_effect=fake_parse),
                mock.patch.object(
                    module.generic,
                    "command_check",
                    return_value={"selection_decision": "create_new_hunt"},
                ),
                mock.patch.object(module.generic, "command_ensure", side_effect=fake_ensure),
            ):
                result = module.command_run(args)

            self.assertEqual(result["hunt_count"], 4)
            self.assertEqual([item["artifact"] for item in result["hunts"]], requested)
            manifest = json.loads(Path(result["group_manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(
                [item["artifact"] for item in manifest["hunts"]],
                requested,
            )

    def test_detectraptor_group_applies_time_bounds_to_evtx_and_mft_only(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        args = argparse.Namespace(
            profile="detectraptor",
            question="Find compromise leads",
            env=[],
            include_label=[],
            exclude_label=[],
            date_after="2026-07-01T00:00:00Z",
            date_before="2026-07-02T00:00:00Z",
            force_run=False,
            start_paused=False,
            activate_paused=False,
        )

        def argv_for(artifact):
            return module.generic_ensure_argv(
                args,
                artifact=artifact,
                group="DR-test",
                investigation_id="IR-test",
                api_client=Path("/tmp/api.yaml"),
                org_id="root",
            )

        for artifact in (
            "DetectRaptor.Generic.Detection.YaraWebshell",
            "DetectRaptor.Windows.Detection.Evtx",
            "DetectRaptor.Windows.Detection.MFT",
        ):
            argv = argv_for(artifact)
            self.assertIn("--date-after", argv)
            self.assertIn("--date-before", argv)

        psreadline_argv = argv_for(
            "DetectRaptor.Windows.Detection.Powershell.PSReadline"
        )
        self.assertNotIn("--date-after", psreadline_argv)
        self.assertNotIn("--date-before", psreadline_argv)

    def test_selected_lolrmm_request_expands_named_result_sources(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        request = module.collection.CollectionRequest(
            target_collection_type="DetectRaptor.Windows.Detection.LolRMM",
            requested_groups=[],
            requested_artifacts=["DetectRaptor.Windows.Detection.LolRMM"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="DetectRaptor.Windows.Detection.LolRMM",
                    artifact="DetectRaptor.Windows.Detection.LolRMM",
                    env={},
                )
            ],
        )
        row = {
            "hunt_id": "H.lolrmm",
            "artifact_sources": [
                "DetectRaptor.Windows.Detection.LolRMM",
                "DetectRaptor.Windows.Detection.LolRMM/Processes",
                "DetectRaptor.Windows.Detection.LolRMM/ResolvedDomains",
            ],
        }

        with mock.patch.object(
            module.generic,
            "resolve_request_from_hunt_row",
            return_value=request,
        ):
            selected = module.request_for_selected_row(row)

        self.assertEqual(
            [spec.artifact for spec in selected.expected_specs],
            row["artifact_sources"],
        )

    def test_group_manifest_discovers_hunt_without_group_marker_and_preserves_artifact_subset(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        with tempfile.TemporaryDirectory() as temp_dir:
            case_root = Path(temp_dir) / "cases"
            module.write_group_manifest(
                case_root=case_root,
                investigation_id="case-test",
                group="DR-manifest",
                profile="detectraptor",
                question="Find compromise leads",
                hunts=[
                    {
                        "artifact": "Artifact.One",
                        "hunt_id": "H.manifest",
                        "request_signature": "one",
                    },
                    {
                        "artifact": "Artifact.Two",
                        "hunt_id": "H.manifest",
                        "request_signature": "two",
                    },
                ],
            )
            row = {
                "hunt_id": "H.manifest",
                "hunt_description": "hunt without group marker",
            }
            with mock.patch.object(
                module.generic,
                "query_single_hunt",
                return_value=row,
            ) as query_single:
                rows = module.discover_hunt_rows(
                    object(),
                    hunt_id=None,
                    group="DR-manifest",
                    case_root=case_root,
                )

        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0][module.SELECTED_ARTIFACTS_KEY],
            ["Artifact.One", "Artifact.Two"],
        )
        self.assertEqual(rows[0][module.SELECTED_GROUP_KEY], "DR-manifest")
        query_single.assert_called_once_with(mock.ANY, "H.manifest")

    def test_selected_group_request_excludes_unrequested_hunt_artifacts(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        full_request = module.collection.CollectionRequest(
            target_collection_type="hunt",
            requested_groups=[],
            requested_artifacts=["Artifact.One", "Artifact.Two"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Artifact.One",
                    artifact="Artifact.One",
                    env={},
                ),
                module.collection.ArtifactSpec(
                    label="Artifact.Two",
                    artifact="Artifact.Two",
                    env={},
                ),
            ],
        )
        row = {
            "hunt_id": "H.multi",
            module.SELECTED_ARTIFACTS_KEY: ["Artifact.Two"],
        }

        with mock.patch.object(
            module.generic,
            "resolve_request_from_hunt_row",
            return_value=full_request,
        ):
            selected = module.request_for_selected_row(row)

        self.assertEqual(selected.requested_artifacts, ["Artifact.Two"])
        self.assertEqual(
            [spec.artifact for spec in selected.expected_specs],
            ["Artifact.Two"],
        )

    def test_local_exact_group_is_reused_without_server_lookup(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = argparse.Namespace(
                profile="detectraptor",
                artifact=[
                    "DetectRaptor.Windows.Detection.Evtx",
                    "DetectRaptor.Windows.Detection.MFT",
                ],
                question="Find compromise leads",
                group=None,
                investigation_id="case-test",
                api_client=str(api_client),
                org_id="root",
                case_root=str(root / "cases"),
                env=[],
                include_label=[],
                exclude_label=[],
                date_after=None,
                date_before=None,
                force_run=False,
                start_paused=False,
                activate_paused=False,
            )
            module.write_group_manifest(
                case_root=root / "cases",
                investigation_id="case-test",
                group="DR-existing",
                profile="detectraptor",
                question="Find compromise leads",
                hunts=[
                    {
                        "artifact": "DetectRaptor.Windows.Detection.Evtx",
                        "hunt_id": "H.1",
                        "request_signature": "DetectRaptor.Windows.Detection.Evtx",
                    },
                    {
                        "artifact": "DetectRaptor.Windows.Detection.MFT",
                        "hunt_id": "H.2",
                        "request_signature": "DetectRaptor.Windows.Detection.MFT",
                    },
                ],
            )

            with (
                mock.patch.object(
                    module.generic,
                    "request_signature",
                    side_effect=lambda request, *_: request.expected_specs[0].label,
                ),
                mock.patch.object(module, "VeloApiClient") as api_client_class,
            ):
                group = module.find_reusable_group(
                    args,
                    artifacts=args.artifact,
                    investigation_id="case-test",
                    api_client=api_client,
                    org_id="root",
                )

        self.assertEqual(group, "DR-existing")
        api_client_class.assert_not_called()

    def test_group_discovery_uses_server_description_marker(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")

        class FakeApi:
            pass

        rows = [
            {"hunt_id": "H.1", "hunt_description": "x dfir-group=DR-one"},
            {"hunt_id": "H.2", "hunt_description": "x dfir-group=DR-two"},
        ]
        with mock.patch.object(module.generic, "query_hunts", return_value=rows):
            result = module.discover_hunt_rows(FakeApi(), hunt_id=None, group="DR-two")
        self.assertEqual([item["hunt_id"] for item in result], ["H.2"])

    def test_run_without_group_reuses_best_exact_match_group(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "api.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = argparse.Namespace(
                profile=None,
                artifact=["Artifact.Targeted"],
                question="Scope a known IOC",
                group=None,
                investigation_id=None,
                api_client=str(api_client),
                org_id="root",
                case_root=str(root / "cases"),
                env=["Needle=value"],
                include_label=[],
                exclude_label=[],
                date_after=None,
                date_before=None,
                force_run=False,
                start_paused=False,
                activate_paused=False,
            )
            with (
                mock.patch.object(module, "find_reusable_group", return_value="HUNT-existing"),
                mock.patch.object(
                    module.generic,
                    "parse_args",
                    return_value=argparse.Namespace(),
                ) as parse_args,
                mock.patch.object(
                    module.generic,
                    "command_check",
                    return_value={"selection_decision": "reuse_exact_case_hunt"},
                ),
                mock.patch.object(
                    module.generic,
                    "command_ensure",
                    return_value={
                        "hunt_id": "H.existing",
                        "action": "reused_existing_hunt",
                        "state": "FINISHED",
                        "review_readiness": "ready_for_review",
                        "request_signature": "sig",
                        "hunt_description": "dfir-group=HUNT-existing",
                        "state_file": "",
                    },
                ),
            ):
                result = module.command_run(args)

        self.assertEqual(result["group"], "HUNT-existing")
        self.assertEqual(result["investigation_id"], "HUNT-existing")
        self.assertIn("HUNT-existing", parse_args.call_args.args[0])

    def test_live_status_and_snapshot_accept_case_aware_api_resolution(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_case_api")
        explicit_api_client = "/tmp/explicit-api.yaml"

        status_args = module.parse_args(
            [
                "status",
                "--id",
                "IR1500",
                "--api-client",
                explicit_api_client,
                "--hunt-id",
                "H.1",
            ]
        )
        snapshot_args = module.parse_args(
            [
                "snapshot",
                "--id",
                "IR1500",
                "--hunt-id",
                "H.1",
            ]
        )
        self.assertEqual(status_args.investigation_id, "IR1500")
        self.assertEqual(status_args.api_client, explicit_api_client)
        self.assertEqual(
            module.resolve_api_client(
                status_args,
                status_args.investigation_id,
            ),
            Path(explicit_api_client).resolve(),
        )
        self.assertEqual(snapshot_args.investigation_id, "IR1500")
        with mock.patch.object(
            module.dfir_paths,
            "resolve_velociraptor_api_client_path",
            return_value=Path("/tmp/IR1500_api_client.yaml"),
        ) as resolver:
            resolved = module.resolve_api_client(
                snapshot_args,
                snapshot_args.investigation_id,
            )

        self.assertEqual(resolved, Path("/tmp/IR1500_api_client.yaml"))
        resolver.assert_called_once_with(
            None,
            module.REPO_ROOT,
            server_profile=None,
        )

    def test_snapshot_command_resolves_api_client_from_investigation_id(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_snapshot_case_api")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            api_client = root / "IR1500_api_client.yaml"
            api_client.write_text("fixture\n", encoding="utf-8")
            args = argparse.Namespace(
                api_client=None,
                org_id="root",
                investigation_id="IR1500",
                hunt_id="H.1",
                group=None,
                case_root=str(root / "cases"),
                query_batch_rows=10000,
            )

            with (
                mock.patch.object(
                    module,
                    "resolve_api_client",
                    return_value=api_client,
                ) as resolver,
                mock.patch.object(module, "VeloApiClient") as api_client_class,
                mock.patch.object(
                    module,
                    "discover_hunt_rows",
                    return_value=[{"hunt_id": "H.1"}],
                ),
                mock.patch.object(
                    module,
                    "snapshot_hunt",
                    return_value={
                        "hunt_id": "H.1",
                        "group": "",
                        "snapshot": "/tmp/snapshot.json",
                    },
                ) as snapshot_hunt,
            ):
                result = module.command_snapshot(args)

        resolver.assert_called_once_with(args, "IR1500")
        api_client_class.assert_called_once_with(api_client, org_id="root")
        self.assertEqual(
            snapshot_hunt.call_args.kwargs["output_root"],
            (root / "cases" / "IR1500" / "hunts").resolve(),
        )
        self.assertEqual(
            snapshot_hunt.call_args.kwargs["max_tokens"],
            module.analysis_limits.DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM,
        )
        self.assertEqual(result["investigation_id"], "IR1500")

    def test_snapshot_streams_to_bounded_files_and_writes_latest_pointer(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        request = module.collection.CollectionRequest(
            target_collection_type="test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Artifact.Test",
                    artifact="Artifact.Test",
                    env={},
                )
            ],
        )
        row = {
            "hunt_id": "H.1234",
            "hunt_description": "velociraptor-hunting windows case Artifact.Test abc dfir-group=DR-test",
        }
        status = {
            "hunt_id": "H.1234",
            "hunt_description": row["hunt_description"],
            "state": "FINISHED",
            "artifact_result_counts": [
                {"artifact": "Artifact.Test", "artifact_name": "Artifact.Test", "row_count": 5}
            ],
        }
        rows = [{"ClientId": "C.1", "Value": index} for index in range(5)]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "reviews"
            two_row_tokens = module.token_budget.estimate_tokens(
                module.canonical_csv_chunk(rows[:2])[0].decode("utf-8"),
                "o200k_base",
            )
            with (
                mock.patch.object(module, "status_for_row", side_effect=[status, status]),
                mock.patch.object(module.generic, "resolve_request_from_hunt_row", return_value=request),
                mock.patch.object(module, "result_batches", return_value=iter([rows[:3], rows[3:]])),
            ):
                result = module.snapshot_hunt(
                    object(),
                    row,
                    output_root=output,
                    case_root=Path(temp_dir) / "cases",
                    max_tokens=two_row_tokens,
                    token_encoding="o200k_base",
                    query_batch_rows=10000,
                    policy_snapshot=module.artifact_policy.load_artifact_policy(),
                )

            snapshot = json.loads(Path(result["snapshot"]).read_text(encoding="utf-8"))
            artifact_record = snapshot["artifacts"][0]
            files = artifact_record["chunks"]
            latest = json.loads((output / "H.1234" / "latest.json").read_text(encoding="utf-8"))
            snapshot_state = json.loads(
                (output / "H.1234" / "snapshot-state.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual([item["rows"] for item in files], [2, 2, 1])
        self.assertTrue(all(not Path(item["path"]).is_absolute() for item in files))
        self.assertTrue(all(item["path"].endswith(".csv") for item in files))
        self.assertTrue(all(item["tokens"] <= two_row_tokens for item in files))
        self.assertFalse((Path(result["snapshot"]).parent / "results").exists())
        self.assertEqual(snapshot["snapshot_version"], 3)
        self.assertEqual(snapshot["status"], "complete")
        self.assertEqual(snapshot["hunt"]["id"], "H.1234")
        self.assertEqual(artifact_record["status"], "complete")
        self.assertEqual(artifact_record["projection"], ["*"])
        self.assertEqual(
            artifact_record["chunk_root"],
            "chunks/Artifact.Test",
        )
        self.assertNotIn("pre_status", snapshot)
        self.assertNotIn("post_status", snapshot)
        self.assertNotIn("server_stats", snapshot)
        self.assertNotIn("requested_artifacts", snapshot)
        self.assertNotIn("expected_spec_arguments", snapshot)
        self.assertNotIn("flows_sample", json.dumps(snapshot))
        self.assertNotIn("max_total_rows_per_artifact", snapshot)
        self.assertEqual(latest["fingerprint"], snapshot["fingerprint"])
        self.assertEqual(latest["snapshot_state"], result["snapshot_state"])
        self.assertEqual(snapshot_state["latest_snapshot"], result["snapshot"])
        self.assertEqual(snapshot_state["latest_status"], "complete")
        self.assertIn("attempts", snapshot_state["artifacts"][0]["transport"])

    def test_snapshot_fingerprint_uses_stable_evidence_fields_only(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_fingerprint")
        records = [
            {
                "artifact": "Alias.B",
                "artifact_name": "Artifact.B",
                "vql_select": ["Timestamp", "Value"],
                "expected_row_count": 99,
                "query_batch_rows": 50_000,
                "files": [
                    {
                        "sha256": "b" * 64,
                        "partition": "host-b",
                        "row_count": 10,
                        "size_bytes": 1000,
                        "estimated_tokens": 250,
                    },
                    {
                        "sha256": "a" * 64,
                        "partition": "host-a",
                        "row_count": 20,
                        "size_bytes": 2000,
                        "estimated_tokens": 500,
                    },
                ],
            },
            {
                "artifact": "Alias.A",
                "artifact_name": "Artifact.A",
                "vql_select": ["*"],
                "expected_row_count": 1,
                "query_batch_rows": 1_000,
                "files": [{"sha256": "c" * 64}],
            },
        ]
        reordered_with_changed_transport = [
            {
                **records[1],
                "expected_row_count": 500,
                "query_batch_rows": 1,
            },
            {
                **records[0],
                "expected_row_count": 30,
                "query_batch_rows": 25_000,
                "files": list(reversed(records[0]["files"])),
            },
        ]

        fingerprint = module.snapshot_evidence_fingerprint("H.1234", records)

        self.assertEqual(
            fingerprint,
            module.snapshot_evidence_fingerprint(
                "H.1234",
                reordered_with_changed_transport,
            ),
        )
        self.assertNotEqual(
            fingerprint,
            module.snapshot_evidence_fingerprint("H.changed", records),
        )
        changed_projection = [
            {
                **records[0],
                "vql_select": ["Timestamp"],
            },
            records[1],
        ]
        self.assertNotEqual(
            fingerprint,
            module.snapshot_evidence_fingerprint(
                "H.1234",
                changed_projection,
            ),
        )
        changed_chunk = [
            records[0],
            {
                **records[1],
                "files": [{"sha256": "d" * 64}],
            },
        ]
        self.assertNotEqual(
            fingerprint,
            module.snapshot_evidence_fingerprint("H.1234", changed_chunk),
        )

    def test_snapshot_has_no_local_total_row_ceiling(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow")
        row = {"hunt_id": "H.large", "hunt_description": "dfir-group=DR-large"}
        status = {
            "hunt_id": "H.large",
            "hunt_description": row["hunt_description"],
            "state": "RUNNING",
            "artifact_result_counts": [
                {"artifact": "Artifact.Large", "artifact_name": "Artifact.Large", "row_count": 1_000_001}
            ],
        }
        request = module.collection.CollectionRequest(
            target_collection_type="test",
            requested_groups=[],
            requested_artifacts=["Artifact.Large"],
            expected_specs=[
                module.collection.ArtifactSpec(
                    label="Artifact.Large",
                    artifact="Artifact.Large",
                    env={},
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch.object(module, "status_for_row", side_effect=[status, status]),
                mock.patch.object(module.generic, "resolve_request_from_hunt_row", return_value=request),
                mock.patch.object(
                    module,
                    "extract_artifact_snapshot",
                    return_value={
                        "artifact": "Artifact.Large",
                        "artifact_name": "Artifact.Large",
                        "expected_row_count": 1_000_001,
                        "extracted_row_count": 1_000_001,
                        "complete": True,
                        "query_batch_rows": 50_000,
                        "projection_applied": False,
                        "vql_select": ["*"],
                        "attempts": [],
                        "files": [],
                        "error": "",
                    },
                ) as extract,
            ):
                result = module.snapshot_hunt(
                    object(),
                    row,
                    output_root=Path(temp_dir),
                    case_root=Path(temp_dir) / "cases",
                    max_tokens=200_000,
                    token_encoding="o200k_base",
                    query_batch_rows=50_000,
                    policy_snapshot=module.artifact_policy.load_artifact_policy(),
                )

            snapshot = json.loads(Path(result["snapshot"]).read_text(encoding="utf-8"))

        self.assertEqual(extract.call_args.kwargs["expected_rows"], 1_000_001)
        self.assertEqual(snapshot["status"], "complete")
        self.assertNotIn("max_total_rows_per_artifact", snapshot)

    def test_status_uses_hunt_flow_metadata_without_result_count_query(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_result_count")
        api = mock.Mock()
        spec = SimpleNamespace(
            label="DetectRaptor.Evtx",
            artifact="DetectRaptor.Windows.Detection.Evtx",
        )
        summary = {
            "hunt_id": "H.D934KOO9H8B38",
            "reported_result_row_count": 23379,
        }
        with (
            mock.patch.object(module, "load_cached_baseline", return_value=None),
            mock.patch.object(
                module.generic,
                "refresh_hunt_status",
                return_value=summary,
            ),
            mock.patch.object(
                module,
                "request_for_selected_row",
                return_value=SimpleNamespace(expected_specs=[spec]),
            ),
        ):
            result = module.status_for_row(
                api,
                {"hunt_id": "H.D934KOO9H8B38"},
                Path("/cases"),
            )

        api.query.assert_not_called()
        self.assertEqual(result["result_row_count"], 23379)
        self.assertTrue(result["results_available_for_review"])
        self.assertEqual(
            result["artifact_result_counts"],
            [
                {
                    "artifact": "DetectRaptor.Evtx",
                    "artifact_name": "DetectRaptor.Windows.Detection.Evtx",
                    "row_count": 23379,
                    "count_source": "hunt_flow_metadata",
                    "count_error": "",
                }
            ],
        )

    def test_status_does_not_invent_per_artifact_counts(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_aggregate_count")
        specs = [
            SimpleNamespace(label="Artifact.One", artifact="Artifact.One"),
            SimpleNamespace(label="Artifact.Two", artifact="Artifact.Two"),
        ]
        with (
            mock.patch.object(module, "load_cached_baseline", return_value=None),
            mock.patch.object(
                module.generic,
                "refresh_hunt_status",
                return_value={"reported_result_row_count": 31},
            ),
            mock.patch.object(
                module,
                "request_for_selected_row",
                return_value=SimpleNamespace(expected_specs=specs),
            ),
        ):
            result = module.status_for_row(
                mock.Mock(),
                {"hunt_id": "H.multi"},
                Path("/cases"),
            )

        self.assertEqual(result["result_row_count"], 31)
        self.assertTrue(result["results_available_for_review"])
        self.assertEqual(
            [item["row_count"] for item in result["artifact_result_counts"]],
            [None, None],
        )
        self.assertEqual(
            {item["count_source"] for item in result["artifact_result_counts"]},
            {"aggregate_only"},
        )

    def test_hunt_flow_status_projects_metadata_without_limiting_inventory(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_flow_status")
        api = mock.Mock()
        api.query.return_value = []

        module.generic.query_hunt_flows(api, "H.1234")

        vql, env = api.query.call_args.args
        self.assertIn("basic_info=FALSE", vql)
        self.assertNotIn("SELECT *", vql)
        self.assertNotIn("LIMIT", vql)
        self.assertIn("artifacts_with_results=Flow.artifacts_with_results", vql)
        self.assertEqual(api.query.call_args.kwargs["max_row"], 100)
        self.assertEqual(env, {"HuntId": "H.1234"})

    def test_hunt_flow_summary_reads_nested_flow_state(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_nested_flow")

        summary = module.generic.summary_from_hunt_flows(
            [
                {
                    "ClientId": "C.1",
                    "Flow": {
                        "state": "FINISHED",
                        "total_collected_rows": 10,
                    },
                },
                {
                    "ClientId": "C.2",
                    "Flow": {
                        "state": "RUNNING",
                        "total_collected_rows": 20,
                    },
                },
                {
                    "ClientId": "C.3",
                    "Flow": {"state": "ERROR"},
                },
                {
                    "ClientId": "C.4",
                    "Flow": {"state": "UNRESPONSIVE"},
                },
            ]
        )

        self.assertEqual(
            summary["flow_states"],
            {
                "FINISHED": 1,
                "RUNNING": 1,
                "ERROR": 1,
                "UNRESPONSIVE": 1,
            },
        )
        self.assertEqual(summary["open_client_count"], 1)
        self.assertEqual(summary["completed_client_count"], 1)
        self.assertEqual(summary["failed_client_count"], 2)
        self.assertEqual(summary["reported_result_row_count"], 30)

    def test_analysis_status_includes_host_execution_counts(self):
        module = load_module(
            WORKFLOW_PATH,
            "hunt_workflow_analysis_status",
        )
        baseline = {
            "targets": [
                {"client_id": "C.1"},
                {"client_id": "C.2"},
            ]
        }
        refreshed = {
            "hunt_id": "H.1",
            "state": "RUNNING",
            "baseline_completed_client_count": 1,
            "baseline_terminal_client_count": 1,
            "baseline_responded_client_count": 1,
            "baseline_failed_client_count": 0,
            "baseline_open_client_count": 0,
            "baseline_pending_client_count": 1,
        }
        readiness = {
            "baseline_scope_available": True,
            "baseline_target_count": 2,
            "strict_complete": False,
        }
        row = {
            "hunt_id": "H.1",
            module.SELECTED_ARTIFACTS_KEY: ["Artifact.One"],
        }
        with (
            mock.patch.object(
                module,
                "load_cached_baseline",
                return_value=baseline,
            ),
            mock.patch.object(
                module.generic,
                "refresh_hunt_status",
                return_value=refreshed,
            ) as refresh,
            mock.patch.object(
                module.generic,
                "baseline_and_readiness_payload",
                return_value=readiness,
            ),
        ):
            result = module.analysis_status_for_row(
                object(),
                row,
                Path("/cases"),
                investigation_id="IR1",
            )

        refresh.assert_called_once()
        self.assertEqual(result["baseline_target_count"], 2)
        self.assertEqual(
            result["baseline_completed_client_count"],
            1,
        )
        self.assertEqual(
            result[module.SELECTED_ARTIFACTS_KEY],
            ["Artifact.One"],
        )

    def test_analysis_status_uses_ad_hoc_scope_without_local_collection_state(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_ad_hoc_scope")
        summary = {
            "hunt_id": "H.imported",
            "state": "FINISHED",
            "responded_client_count": 11,
            "terminal_client_count": 11,
            "reported_result_row_count": 813,
        }
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(module, "load_cached_baseline", return_value=None),
            mock.patch.object(
                module.generic,
                "refresh_hunt_status",
                return_value=summary,
            ),
        ):
            result = module.analysis_status_for_row(
                object(),
                {"hunt_id": "H.imported"},
                Path(temp_dir),
                investigation_id="IR1",
            )

        self.assertEqual(result["review_scope"], "ad_hoc_review")
        self.assertEqual(result["review_readiness"], "ready_for_review")
        self.assertEqual(result["coverage_readiness"], "result_set_only")
        self.assertEqual(result["target_execution_coverage"], "not_assessed")
        self.assertFalse(result["baseline_scope_required"])

    def test_local_collection_state_retains_managed_scope_without_baseline(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_managed_scope")
        summary = {"hunt_id": "H.managed", "state": "RUNNING"}
        readiness = {
            "baseline_scope_available": False,
            "review_readiness": "baseline_unavailable",
            "strict_complete": False,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            case_root = Path(temp_dir)
            hunt_root = case_root / "IR1" / "hunts" / "H.managed"
            hunt_root.mkdir(parents=True)
            (hunt_root / "state.json").write_text(
                json.dumps({"hunt_id": "H.managed"}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    module,
                    "load_cached_baseline",
                    return_value=None,
                ),
                mock.patch.object(
                    module.generic,
                    "refresh_hunt_status",
                    return_value=summary,
                ),
                mock.patch.object(
                    module.generic,
                    "baseline_and_readiness_payload",
                    return_value=readiness,
                ),
            ):
                result = module.analysis_status_for_row(
                    object(),
                    {"hunt_id": "H.managed"},
                    case_root,
                    investigation_id="IR1",
                )

        self.assertEqual(result["review_scope"], "managed_collection")
        self.assertEqual(result["review_readiness"], "baseline_unavailable")


class HuntSnapshotAnalysisTest(unittest.TestCase):
    def test_analysis_rejects_unsupported_snapshot_format(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_unsupported_rejected")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "snapshot.json"
            snapshot_path.write_text(
                json.dumps(
                    {
                        "snapshot_version": 1,
                        "hunt_id": "H.unsupported",
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "Unsupported snapshot format",
            ):
                module.analyze_snapshot(snapshot_path)

    def test_workflow_analysis_cli_defers_limits_to_canonical_resolver(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_analysis_defaults")
        with mock.patch.dict(
            "os.environ",
            {
                "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "8765",
            },
        ):
            args = module.parse_args(
                [
                "analyze",
                "--snapshot",
                "/tmp/snapshot.json",
            ]
            )

        self.assertFalse(hasattr(args, "max_tokens"))
        self.assertEqual(args.review_mode, "exhaustive")
        self.assertEqual(args.snapshot_output, "chunks")
        self.assertFalse(hasattr(args, "max_analysis_item_tokens"))
        self.assertEqual(
            module.analysis_limits.resolve_analysis_limits(
                {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "8765"}
            )
            .maximum_evidence_tokens_per_item,
            8765,
        )
        self.assertIsNone(args.max_total_analysis_tokens)

    def test_removed_snapshot_analysis_flags_are_rejected(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_removed_flags")
        for flag, value in (
            ("--model-policy", "policy.json"),
            ("--model-profile", "compact-review"),
            ("--review-route", "reasoning"),
            ("--review-task", "correlation"),
            ("--max-analysis-item-tokens", "1000"),
            ("--token-encoding", "o200k_base"),
        ):
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                module.parse_args(
                    ["analyze", "--snapshot", "/tmp/snapshot.json", flag, value]
                )

    def test_chunk_output_reuses_snapshot_csv_without_writing_files(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_chunks")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir) / "H.STANDARD" / "snapshots" / "one"
            snapshot_path = write_snapshot_v3(
                snapshot_dir,
                hunt_id="H.STANDARD",
                artifact="Artifact.Test",
                fingerprint="chunks",
                rows=[
                    {
                        "ClientId": "C.1",
                        "Hostname": "host01",
                        "Message": "evidence",
                    }
                ],
            )
            files_before = {
                path.relative_to(snapshot_dir).as_posix()
                for path in snapshot_dir.rglob("*")
                if path.is_file()
            }
            summary = module.analyze_snapshot(snapshot_path)
            csv_files = [Path(path) for path in summary["review_csv_files"]]
            files_after = {
                path.relative_to(snapshot_dir).as_posix()
                for path in snapshot_dir.rglob("*")
                if path.is_file()
            }
            csv_text = csv_files[0].read_text(encoding="utf-8")

        self.assertEqual(summary["snapshot_output"], "chunks")
        self.assertEqual(summary["row_count"], 1)
        self.assertEqual(summary["chunk_count"], 1)
        self.assertEqual(summary["summary_json"], "")
        self.assertEqual(summary["model_review_manifest"], "")
        self.assertEqual(len(csv_files), 1)
        self.assertIn("Message", csv_text)
        self.assertEqual(files_after, files_before)
        self.assertFalse((snapshot_dir / "analysis").exists())

    def test_snapshot_csv_chunker_enforces_header_inclusive_token_limit(self):
        module = load_module(WORKFLOW_PATH, "hunt_workflow_csv_tokens")
        rows = [
            {"ClientId": "C.1", "Message": "alpha " * 20},
            {"ClientId": "C.1", "Message": "beta " * 20},
        ]
        per_row_limit = max(
            module.token_budget.estimate_tokens(
                module.canonical_csv_chunk([row])[0].decode("utf-8"),
                "o200k_base",
            )
            for row in rows
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            writer = module.TokenBoundedCsvWriter(
                Path(temp_dir),
                max_tokens=per_row_limit,
                token_encoding="o200k_base",
            )
            for row in rows:
                writer.write(row)
            chunks = writer.close()

        self.assertEqual(len(chunks), 2)
        self.assertEqual([chunk["row_count"] for chunk in chunks], [1, 1])
        self.assertTrue(
            all(chunk["estimated_tokens"] <= per_row_limit for chunk in chunks)
        )

    def test_chunk_and_derived_outputs_use_canonical_analysis_limit(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_policy_limit")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            snapshot_dir = root / "H.POLICY" / "snapshots" / "one"
            rows = [
                {
                    "ClientId": "C.1",
                    "Message": "alpha " * 300,
                },
                {
                    "ClientId": "C.1",
                    "Message": "beta " * 300,
                },
            ]
            snapshot_path = write_snapshot_v2(
                snapshot_dir,
                hunt_id="H.POLICY",
                artifact="Artifact.Test",
                rows=rows,
                fingerprint="policy-limit",
                max_tokens=500,
            )
            limits = module.analysis_limits.AnalysisLimits(
                maximum_evidence_tokens_per_item=500
            )

            chunks = module.analyze_snapshot(
                snapshot_path,
                limits=limits,
                snapshot_output="chunks",
            )
            derived = module.analyze_snapshot(
                snapshot_path,
                limits=limits,
                snapshot_output="derived",
            )
            review_files_exist = all(
                Path(path).is_file()
                for path in chunks["review_csv_files"]
                + derived["review_csv_files"]
            )
            derived_csv_files = list(
                (snapshot_dir / "analysis-v8").rglob("*.csv")
            )
            shared_review_files = (
                chunks["review_csv_files"] == derived["review_csv_files"]
            )

        self.assertEqual(
            chunks["analysis_limits"]["maximum_evidence_tokens_per_item"],
            500,
        )
        self.assertEqual(derived["max_tokens_per_chunk"], 500)
        self.assertEqual(derived["chunk_count"], 2)
        self.assertNotIn("max_rows_per_chunk", derived)
        self.assertNotIn("max_bytes_per_chunk", derived)
        self.assertTrue(
            all(
                chunk["estimated_tokens"] <= 500
                for chunk in derived["chunks"]
            )
        )
        self.assertTrue(review_files_exist)
        self.assertTrue(shared_review_files)
        self.assertEqual(derived_csv_files, [])

    def test_analysis_partitions_by_client_and_reuses_chunk_hash(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir) / "H.1" / "snapshots" / "one"
            rows = [
                {"ClientId": "C.1", "EventID": 1},
                {"ClientId": "C.1", "EventID": 2},
                {"ClientId": "C.2", "EventID": 3},
            ]
            snapshot_path = write_snapshot_v2(
                snapshot_dir,
                hunt_id="H.1",
                artifact="Artifact.Test",
                rows=rows,
                group="DR-test",
                fingerprint="abc",
                max_tokens=100_000,
            )

            first = module.analyze_snapshot(
                snapshot_path,
                limits=module.analysis_limits.AnalysisLimits(maximum_evidence_tokens_per_item=100_000),
                snapshot_output="derived",
            )
            second = module.analyze_snapshot(
                snapshot_path,
                limits=module.analysis_limits.AnalysisLimits(maximum_evidence_tokens_per_item=100_000),
                snapshot_output="derived",
            )

        self.assertEqual(first["row_count"], 3)
        self.assertEqual(first["partition_count"], 2)
        self.assertEqual(first["max_tokens_per_chunk"], 100_000)
        self.assertEqual(first["token_estimator"].split(":", 1)[0], "tiktoken")
        self.assertEqual(first["review_mode"], "exhaustive")
        self.assertTrue(first["complete_evidence_coverage"])
        self.assertEqual(first["new_chunk_analysis_count"], 2)
        self.assertEqual(second["reused_chunk_analysis_count"], 2)

    def test_analysis_builds_deduplicated_budgeted_model_review_plan(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_review_plan")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir) / "H.1A" / "snapshots" / "one"
            duplicate = {
                "ClientId": "C.1",
                "Timestamp": "2026-07-23T00:00:00Z",
                "Message": "ordinary repeated event",
                "Empty": "",
            }
            rows = [
                duplicate,
                duplicate,
                {
                    "ClientId": "C.1",
                    "Timestamp": "2026-07-23T00:01:00Z",
                    "Message": "wp2shell indicator",
                },
            ]
            snapshot_path = write_snapshot_v2(
                snapshot_dir,
                hunt_id="H.1A",
                artifact="Artifact.Test",
                rows=rows,
                fingerprint="review-plan",
                max_tokens=100_000,
            )

            summary = module.analyze_snapshot(
                snapshot_path,
                limits=module.analysis_limits.AnalysisLimits(maximum_evidence_tokens_per_item=100_000),
                review_terms=["wp2shell"],
                review_mode="selective",
                max_total_analysis_tokens=1000,
                snapshot_output="derived",
            )
            artifact = summary["artifacts"][0]
            review_manifest = json.loads(
                Path(summary["model_review_manifest"]).read_text(encoding="utf-8")
            )
            artifact_manifest = json.loads(
                Path(artifact["model_review_manifest"]).read_text(encoding="utf-8")
            )
            package = artifact_manifest["packages"][0]
            package_csv = Path(package["package_csv_file"])
            package_csv_exists = package_csv.is_file()

        self.assertEqual(artifact["raw_row_count"], 3)
        self.assertEqual(artifact["unique_evidence_count"], 2)
        self.assertEqual(artifact["duplicate_row_count"], 1)
        self.assertLessEqual(summary["selected_review_tokens"], 1000)
        self.assertEqual(summary["review_mode"], "selective")
        self.assertEqual(review_manifest["selection_terms"], ["wp2shell"])
        self.assertEqual(
            artifact_manifest["analysis_routing"],
            {"route": "high-volume", "task": "extraction"},
        )
        self.assertTrue(package_csv_exists)
        self.assertTrue(package["source_snapshot_chunk"])
        self.assertIn("/chunks/", package_csv.as_posix())
        self.assertEqual(artifact["evidence_file"], "")
        self.assertNotIn("package_file", package)
        self.assertFalse((snapshot_dir / "analysis-v8" / "evidence").exists())

    def test_detectraptor_snapshot_keeps_detection_scope_stack_only(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis")
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_dir = Path(temp_dir) / "H.2" / "snapshots" / "one"
            rows = [
                {
                    "ClientId": "C.1",
                    "Computer": "HOST-1",
                    "EventTime": "2026-07-15T00:00:01Z",
                    "Detection": {"Name": "PowerShell test detection"},
                    "EventData": r"Path=C:\Users\alice\AppData\Local\tool.exe",
                },
                {
                    "ClientId": "C.2",
                    "Computer": "HOST-2",
                    "EventTime": "2026-07-15T00:00:02Z",
                    "Detection": {"Name": "PowerShell test detection"},
                    "EventData": r"Path=C:\Users\bob\AppData\Local\tool.exe",
                },
                {
                    "ClientId": "C.3",
                    "Computer": "HOST-3",
                    "EventTime": "2026-07-15T00:00:03Z",
                    "Detection": {"Name": "PowerShell test detection"},
                    "EventData": r"Path=C:\ProgramData\other.exe",
                },
            ]
            snapshot_path = write_snapshot_v2(
                snapshot_dir,
                hunt_id="H.2",
                artifact="DetectRaptor.Windows.Detection.Evtx",
                rows=rows,
                group="DR-test",
                fingerprint="def",
                max_tokens=100_000,
            )

            summary = module.analyze_snapshot(
                snapshot_path,
                limits=module.analysis_limits.AnalysisLimits(maximum_evidence_tokens_per_item=100_000),
                snapshot_output="derived",
            )
            stack_path = Path(summary["artifacts"][0]["stack_file"])
            stack = json.loads(stack_path.read_text(encoding="utf-8"))

        self.assertEqual(stack["status"], "ok")
        self.assertEqual(stack["default_stack"], "detection")
        self.assertEqual(stack["stack_count"], 1)
        self.assertEqual(stack["rows_stacked"], 3)
        detection_stack = stack["stacks"]["detection"]
        self.assertEqual(detection_stack["dimensions"], ["DetectionIdentity"])
        self.assertEqual(detection_stack["group_count"], 1)
        self.assertEqual(detection_stack["groups"][0]["count"], 3)
        self.assertEqual(detection_stack["groups"][0]["distinct_host_count"], 3)

    def test_application_stack_normalizes_user_paths_but_evidence_preserves_users(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_application_paths")
        profiles = module.artifact_policy.load_artifact_policy().profiles
        artifact = "DetectRaptor.Windows.Detection.Applications"
        profile = profiles[artifact]
        rows = [
            {
                "Category": "RMM - ExampleTool",
                "DisplayName": "ExampleTool 1.0",
                "DisplayVersion": "1.0",
                "InstallLocation": r"C:\Users\alice\AppData\Local\ExampleTool",
                "InstallSource": r"C:\Users\alice\Downloads",
                "Publisher": "Example Publisher",
                "ClientId": "C.1",
                "Fqdn": "host1.example.test",
            },
            {
                "Category": "RMM - ExampleTool",
                "DisplayName": "ExampleTool 1.0",
                "DisplayVersion": "1.0",
                "InstallLocation": "C:/Users/bob/AppData/Local/ExampleTool",
                "InstallSource": r"C:\Users\bob\Downloads",
                "Publisher": "Example Publisher",
                "ClientId": "C.2",
                "Fqdn": "host2.example.test",
            },
            {
                "Category": "Data Transfer - OneDrive",
                "DisplayName": "Microsoft OneDrive",
                "DisplayVersion": "1.0",
                "Publisher": "Microsoft Corporation",
                "ClientId": "C.3",
                "Fqdn": "host3.example.test",
            },
        ]

        stack = module.profile_stack(rows, artifact, artifact, profile)
        application_stack = stack["stacks"]["application"]
        location_stack = stack["stacks"]["install_location"]
        source_stack = stack["stacks"]["install_source"]

        self.assertEqual(stack["default_stack"], "application")
        self.assertEqual(application_stack["rows_stacked"], 3)
        self.assertEqual(application_stack["group_count"], 2)
        self.assertEqual(location_stack["rows_stacked"], 2)
        self.assertEqual(location_stack["group_count"], 1)
        self.assertEqual(location_stack["groups"][0]["count"], 2)
        self.assertEqual(location_stack["groups"][0]["distinct_host_count"], 2)
        self.assertEqual(
            location_stack["groups"][0]["values"]["NormalizedInstallLocation"],
            r"c:\users\<user>\appdata\local\exampletool",
        )
        self.assertEqual(source_stack["rows_stacked"], 2)
        self.assertEqual(source_stack["group_count"], 1)

        accumulator = module.evidence_records.EvidenceAccumulator(artifact)
        for line_number, row in enumerate(rows, start=1):
            accumulator.add(
                row,
                partition=module.row_partition(row),
                source_file="/tmp/applications.jsonl",
                source_line=line_number,
            )
        evidence_values = [record["values"] for record in accumulator.records()]
        self.assertEqual(
            evidence_values[0]["InstallLocation"],
            r"C:\Users\alice\AppData\Local\ExampleTool",
        )
        self.assertEqual(
            evidence_values[1]["InstallLocation"],
            "C:/Users/bob/AppData/Local/ExampleTool",
        )

        self.assertEqual(
            module.normalize_stack_text(
                r"C:\Documents and Settings\Alice\Local Settings\ExampleTool",
                "windows_path",
            ),
            r"c:\documents and settings\<user>\local settings\exampletool",
        )

    def test_windows_services_rows_feed_all_named_stack_views_in_one_pass(self):
        module = load_module(ANALYSIS_PATH, "hunt_analysis_services")
        profiles = module.artifact_policy.load_artifact_policy().profiles
        profile = profiles["Windows.System.Services"]
        rows = [
            {
                "Name": "UpdaterSvc",
                "AbsoluteExePath": r"C:\Users\alice\AppData\Local\svc.exe",
                "ServiceDll": r"C:\Users\alice\AppData\Local\svc.dll",
                "UserAccount": "LocalSystem",
                "HashServiceExe": {"SHA256": "AA"},
                "HashServiceDll": {"SHA256": "BB"},
                "StartMode": "Auto",
                "Fqdn": "host1.example.test",
            },
            {
                "Name": "UpdaterSvc",
                "AbsoluteExePath": r"C:\Users\bob\AppData\Local\svc.exe",
                "ServiceDll": r"C:\Users\bob\AppData\Local\svc.dll",
                "UserAccount": "LocalSystem",
                "HashServiceExe": {"SHA256": "AA"},
                "HashServiceDll": {"SHA256": "BB"},
                "StartMode": "Auto",
                "Fqdn": "host2.example.test",
            },
            {
                "Name": "OneOffSvc",
                "AbsoluteExePath": r"C:\ProgramData\oneoff.exe",
                "FailureCommand": "cmd.exe /c C:\\ProgramData\\recover.cmd",
                "UserAccount": "NetworkService",
                "StartMode": "Manual",
                "Fqdn": "host3.example.test",
            },
        ]

        stack = module.profile_stack(
            rows,
            "Windows.System.Services",
            "Windows.System.Services",
            profile,
        )

        self.assertEqual(stack["status"], "ok")
        self.assertEqual(stack["default_stack"], "service_name")
        self.assertEqual(stack["stack_count"], 9)
        self.assertEqual(stack["rows_stacked"], 3)
        self.assertEqual(stack["stacks"]["service_name"]["groups"][0]["count"], 2)
        self.assertEqual(stack["stacks"]["executable_path"]["groups"][0]["count"], 2)
        self.assertEqual(
            stack["stacks"]["executable_path"]["groups"][0]["distinct_host_count"],
            2,
        )
        self.assertEqual(stack["stacks"]["service_dll"]["groups"][0]["count"], 2)
        self.assertEqual(stack["stacks"]["executable_hash"]["groups"][0]["count"], 2)
        self.assertEqual(stack["stacks"]["failure_command"]["rows_stacked"], 1)


if __name__ == "__main__":
    unittest.main()
