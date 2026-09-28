import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

import grpc
from vraptor import api as velociraptor_api
from vraptor.api import org_id_candidates


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    REPO_ROOT
    / "src/vraptor/collect/requests.py"
)


def load_module():
    module_name = f"test_run_velociraptor_collection_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class RunVelociraptorCollectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def ready_context(self, api_client: Path, engagement_id: str = "case-123"):
        return mock.Mock(
            engagement_id=engagement_id,
            server_profile="lab7",
            api_client=api_client.resolve(),
            case_root=self.module.CASE_ROOT.resolve(),
        )

    def test_resolve_org_id_prefers_root_and_preserves_legacy_fallback(self):
        self.assertEqual(self.module.resolve_org_id(None), "root")
        self.assertEqual(self.module.resolve_org_id(""), "root")
        self.assertEqual(self.module.resolve_org_id("root"), "root")
        self.assertEqual(self.module.resolve_org_id("orgs/root"), "root")
        self.assertEqual(
            org_id_candidates("orgs/root"),
            ["root", "orgs/root"],
        )
        self.assertFalse(hasattr(self.module, "org_id_candidates"))

    def test_status_refresh_waits_for_queue_state_write_lock(self):
        original_case_root = self.module.CASE_ROOT
        with tempfile.TemporaryDirectory() as directory:
            self.module.CASE_ROOT = Path(directory)
            writer_entered = threading.Event()
            allow_writer = threading.Event()
            reader_finished = threading.Event()
            marker_path = (
                self.module.get_output_dir("IR1", "host01") / "queue-marker.txt"
            )
            marker_path.parent.mkdir(parents=True, exist_ok=True)

            def writer():
                with self.module.collection_state_lock("IR1", "host01"):
                    writer_entered.set()
                    allow_writer.wait(1)
                    marker_path.write_text("F.NEW", encoding="utf-8")

            def unlocked_status(*_args, **_kwargs):
                return {"flow_id": marker_path.read_text(encoding="utf-8")}

            result = {}

            def reader():
                result.update(
                    self.module.status_payload(
                        mock.sentinel.api,
                        "IR1",
                        "host01",
                    )
                )
                reader_finished.set()

            try:
                with mock.patch.object(
                    self.module,
                    "_status_payload_unlocked",
                    side_effect=unlocked_status,
                ):
                    writer_thread = threading.Thread(target=writer)
                    reader_thread = threading.Thread(target=reader)
                    writer_thread.start()
                    self.assertTrue(writer_entered.wait(1))
                    reader_thread.start()
                    self.assertFalse(reader_finished.wait(0.05))
                    allow_writer.set()
                    writer_thread.join(1)
                    reader_thread.join(1)
            finally:
                self.module.CASE_ROOT = original_case_root

        self.assertEqual(result["flow_id"], "F.NEW")

    def test_concurrent_ensure_serializes_selection_and_queues_once(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        queued_flow = self.module.FlowRecord(
            session_id="F.queued",
            state="RUNNING",
            total_rows=0,
            created="1",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )
        server_flows = []
        queue_entered = threading.Event()
        allow_queue = threading.Event()
        results = {}
        errors = []

        def list_flows(*_args, **_kwargs):
            return list(server_flows)

        def queue_artifact(*_args, **_kwargs):
            queue_entered.set()
            if not allow_queue.wait(1):
                raise RuntimeError("test queue release timed out")
            server_flows.append(queued_flow)
            return self.module.artifact_status_from_flow(expected, queued_flow)

        def run_ensure(name):
            try:
                results[name] = self.module.ensure_collection(
                    mock.sentinel.api,
                    "IR1",
                    "host01",
                    request,
                    60,
                    False,
                    client=client,
                )
            except Exception as exc:
                errors.append(exc)

        original_case_root = self.module.CASE_ROOT
        with tempfile.TemporaryDirectory() as directory:
            self.module.CASE_ROOT = Path(directory)
            try:
                with (
                    mock.patch.object(
                        self.module,
                        "preflight_artifact_availability",
                        return_value={
                            "status": "ready",
                            "requested_artifacts": ["Artifact.Test"],
                            "available_artifacts": ["Artifact.Test"],
                            "missing_artifacts": [],
                            "checked_at": "2026-08-11T00:00:00Z",
                        },
                    ) as preflight,
                    mock.patch.object(
                        self.module,
                        "get_all_flows",
                        side_effect=list_flows,
                    ),
                    mock.patch.object(
                        self.module,
                        "queue_single_artifact",
                        side_effect=queue_artifact,
                    ) as queue,
                ):
                    first = threading.Thread(target=run_ensure, args=("first",))
                    second = threading.Thread(target=run_ensure, args=("second",))
                    first.start()
                    self.assertTrue(queue_entered.wait(1))
                    second.start()
                    second.join(0.05)
                    self.assertTrue(second.is_alive())
                    self.assertEqual(preflight.call_count, 1)
                    self.assertEqual(queue.call_count, 1)
                    allow_queue.set()
                    first.join(2)
                    second.join(2)
                    self.assertFalse(first.is_alive())
                    self.assertFalse(second.is_alive())
            finally:
                self.module.CASE_ROOT = original_case_root

        self.assertEqual(errors, [])
        self.assertEqual(queue.call_count, 1)
        self.assertEqual(results["first"]["action"], "queued_new_flows")
        self.assertEqual(results["second"]["action"], "reused_existing_flows")
        self.assertEqual(
            results["second"]["artifact_flows"][0]["flow_id"],
            "F.queued",
        )

    def test_status_refresh_waits_for_complete_ensure_transaction(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        queued_flow = self.module.FlowRecord(
            session_id="F.queued",
            state="RUNNING",
            total_rows=0,
            created="1",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )
        queue_entered = threading.Event()
        allow_queue = threading.Event()
        status_finished = threading.Event()
        errors = []
        status_result = {}

        def queue_artifact(*_args, **_kwargs):
            queue_entered.set()
            if not allow_queue.wait(1):
                raise RuntimeError("test queue release timed out")
            return self.module.artifact_status_from_flow(expected, queued_flow)

        def run_ensure():
            try:
                self.module.ensure_collection(
                    mock.sentinel.api,
                    "IR1",
                    "host01",
                    request,
                    60,
                    False,
                    client=client,
                )
            except Exception as exc:
                errors.append(exc)

        def read_status(*_args, **_kwargs):
            state = self.module.read_state(
                self.module.get_request_state_path(
                    "IR1",
                    "host01",
                    self.module.request_id_for_request(request),
                )
            )
            return {"queue_progress": state["queue_progress"]}

        def run_status():
            try:
                status_result.update(
                    self.module.status_payload(
                        mock.sentinel.api,
                        "IR1",
                        "host01",
                    )
                )
            except Exception as exc:
                errors.append(exc)
            finally:
                status_finished.set()

        original_case_root = self.module.CASE_ROOT
        with tempfile.TemporaryDirectory() as directory:
            self.module.CASE_ROOT = Path(directory)
            try:
                with (
                    mock.patch.object(
                        self.module,
                        "preflight_artifact_availability",
                        return_value={
                            "status": "ready",
                            "requested_artifacts": ["Artifact.Test"],
                            "available_artifacts": ["Artifact.Test"],
                            "missing_artifacts": [],
                            "checked_at": "2026-08-11T00:00:00Z",
                        },
                    ),
                    mock.patch.object(
                        self.module,
                        "get_all_flows",
                        return_value=[],
                    ),
                    mock.patch.object(
                        self.module,
                        "queue_single_artifact",
                        side_effect=queue_artifact,
                    ),
                    mock.patch.object(
                        self.module,
                        "_status_payload_unlocked",
                        side_effect=read_status,
                    ),
                ):
                    ensure_thread = threading.Thread(target=run_ensure)
                    status_thread = threading.Thread(target=run_status)
                    ensure_thread.start()
                    self.assertTrue(queue_entered.wait(1))
                    status_thread.start()
                    self.assertFalse(status_finished.wait(0.05))
                    allow_queue.set()
                    ensure_thread.join(2)
                    status_thread.join(2)
                    self.assertFalse(ensure_thread.is_alive())
                    self.assertFalse(status_thread.is_alive())
            finally:
                self.module.CASE_ROOT = original_case_root

        self.assertEqual(errors, [])
        self.assertEqual(status_result["queue_progress"]["status"], "complete")
        self.assertEqual(
            status_result["queue_progress"]["completed_artifacts"],
            1,
        )

    def test_collection_cli_accepts_exact_client_id_instead_of_hostname(self):
        args = self.module.parse_args(
            [
                "check",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
            ]
        )

        self.assertEqual(args.client_id, "C.1234abcd")
        self.assertIsNone(args.host)
        self.assertFalse(args.no_progress)
        self.assertEqual(args.progress_interval_seconds, 20.0)

    def test_collection_cli_accepts_shared_progress_options(self):
        for command in (
            "queue",
            "check",
            "ensure",
            "export",
            "export-registry-hunter",
            "status",
            "poll",
        ):
            with self.subTest(command=command):
                args = self.module.parse_args(
                    [
                        command,
                        "--investigation-id",
                        "case-123",
                        "--client-id",
                        "C.1234abcd",
                        "--no-progress",
                        "--progress-interval-seconds",
                        "5",
                    ]
                )

                self.assertTrue(args.no_progress)
                self.assertEqual(args.progress_interval_seconds, 5.0)

    def test_collection_cli_rejects_client_id_and_hostname_together(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.module.parse_args(
                    [
                        "check",
                        "--investigation-id",
                        "case-123",
                        "--client-id",
                        "C.1234abcd",
                        "--host",
                        "host01",
                        "--artifact",
                        "Generic.Client.Info",
                    ]
                )

    def test_collection_cli_keeps_results_server_side_unless_export_is_explicit(self):
        default_args = self.module.parse_args(
            [
                "ensure",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
            ]
        )
        export_args = self.module.parse_args(
            [
                "ensure",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
                "--export",
            ]
        )
        compatibility_export_args = self.module.parse_args(
            [
                "ensure",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
                "--export",
                "--allow-export",
            ]
        )

        self.assertFalse(default_args.export)
        self.assertFalse(self.module.export_after_requested(default_args))
        self.assertTrue(export_args.export)
        self.assertTrue(self.module.export_after_requested(export_args))
        self.assertTrue(self.module.export_after_requested(compatibility_export_args))

    def test_standalone_export_accepts_legacy_flag_without_changing_request(self):
        explicit = self.module.parse_args(
            [
                "export",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
            ]
        )
        allowed = self.module.parse_args(
            [
                "export",
                "--investigation-id",
                "case-123",
                "--client-id",
                "C.1234abcd",
                "--artifact",
                "Generic.Client.Info",
                "--allow-export",
            ]
        )

        self.assertFalse(vars(explicit).pop("allow_export"))
        self.assertTrue(vars(allowed).pop("allow_export"))
        self.assertEqual(vars(explicit), vars(allowed))

    def test_latest_state_pointer_resolves_request_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            request_state = root / "requests" / "request-123" / "state.json"
            request_state.parent.mkdir(parents=True)
            request_state.write_text(
                json.dumps(
                    {
                        "request_id": "request-123",
                        "artifact_flows": [{"artifact": "Generic.Client.Info"}],
                    }
                ),
                encoding="utf-8",
            )
            latest_state = root / "current.json"
            latest_state.write_text(
                json.dumps(
                    {
                        "latest_request_id": "request-123",
                        "state_file": "requests/request-123/state.json",
                    }
                ),
                encoding="utf-8",
            )

            resolved = self.module.read_state(latest_state)

        self.assertEqual(resolved["request_id"], "request-123")
        self.assertEqual(resolved["artifact_flows"][0]["artifact"], "Generic.Client.Info")

    def test_zero_row_export_does_not_leave_empty_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "empty.csv"
            output_path.write_text("stale", encoding="utf-8")

            row_count = self.module.write_csv(output_path, [])

            self.assertEqual(row_count, 0)
            self.assertFalse(output_path.exists())
            self.assertEqual(self.module.exported_output_file(output_path, row_count), "")

    def test_resolve_cli_collection_target_uses_exact_client_id(self):
        api = mock.MagicMock()
        api.query.return_value = [
            {
                "client_id": "C.1234abcd",
                "Hostname": "host01",
                "LastSeen": "2026-07-22T00:00:00Z",
            }
        ]
        args = self.module.argparse.Namespace(
            client_id="C.1234abcd",
            host=None,
        )

        hostname, client = self.module.resolve_cli_collection_target(api, args)

        self.assertEqual(hostname, "host01")
        self.assertEqual(client.client_id, "C.1234abcd")
        self.assertEqual(client.selector_type, "client_id")
        self.assertEqual(client.requested_client_id, "C.1234abcd")

    def test_hostname_resolution_fails_when_multiple_clients_match(self):
        api = mock.MagicMock()
        api.query_file.return_value = [
            {"client_id": "C.1111", "Hostname": "host01", "LastSeen": ""},
            {"client_id": "C.2222", "Hostname": "host01", "LastSeen": ""},
        ]

        with self.assertRaisesRegex(RuntimeError, "Use --client-id"):
            self.module.get_client(api, "host01")

    def test_query_retries_orgs_fallback_when_root_is_unavailable(self):
        client = self.module.VeloApiClient(Path("/tmp/api_client.yaml"), org_id="root")

        class FakeOrgNotFoundError(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

            def details(self):
                return "Org not found"

        class FakeStub:
            def __init__(self):
                self.calls: list[str] = []

            def Query(self, request):
                self.calls.append(request.org_id)
                if request.org_id == "root":
                    raise FakeOrgNotFoundError()
                return iter([mock.Mock(Response=json.dumps([{"ok": True}]))])

        client._stub = FakeStub()

        rows = client.query("SELECT 1 AS ok FROM scope()")

        self.assertEqual(rows, [{"ok": True}])
        self.assertEqual(client._stub.calls, ["root", "orgs/root"])

    def test_query_batches_yields_each_grpc_response_without_full_materialization(self):
        client = self.module.VeloApiClient(Path("/tmp/api_client.yaml"), org_id="root")

        class FakeStub:
            def Query(self, request):
                return iter(
                    [
                        mock.Mock(Response=json.dumps([{"row": 1}, {"row": 2}])),
                        mock.Mock(Response=json.dumps([{"row": 3}])),
                    ]
                )

        client._stub = FakeStub()

        batches = list(client.query_batches("SELECT * FROM scope()", max_row=10000))

        self.assertEqual(batches, [[{"row": 1}, {"row": 2}], [{"row": 3}]])

    def test_query_uses_client_deadline_when_timeout_is_set(self):
        client = self.module.VeloApiClient(Path("/tmp/api_client.yaml"), org_id="root")

        class FakeStub:
            def __init__(self):
                self.timeout = None

            def Query(self, request, *, timeout=None):
                self.timeout = timeout
                return iter([mock.Mock(Response=json.dumps([{"ok": True}]))])

        client._stub = FakeStub()

        rows = client.query("SELECT 1 AS ok FROM scope()", timeout=30)

        self.assertEqual(rows, [{"ok": True}])
        self.assertEqual(client._stub.timeout, 30)

    def test_api_client_reconnect_replaces_channel_with_stable_safe_identity(self):
        config = {
            "api_connection_string": "velo.example:8001",
            "ca_certificate": "SAFE-CA-MATERIAL",
            "client_private_key": "PRIVATE-KEY-MUST-NOT-LEAK",
            "client_cert": "CLIENT-CERT-MUST-NOT-LEAK",
        }
        first_channel = mock.Mock()
        second_channel = mock.Mock()
        first_stub = mock.Mock()
        second_stub = mock.Mock()

        with mock.patch.object(
            velociraptor_api.pyvelociraptor,
            "LoadConfigFile",
            return_value=config,
        ), mock.patch.object(
            velociraptor_api.grpc,
            "ssl_channel_credentials",
            return_value=mock.sentinel.credentials,
        ), mock.patch.object(
            velociraptor_api.grpc,
            "secure_channel",
            side_effect=[first_channel, second_channel],
        ), mock.patch.object(
            velociraptor_api.api_pb2_grpc,
            "APIStub",
            side_effect=[first_stub, second_stub],
        ):
            client = self.module.VeloApiClient(Path("/tmp/api_client.yaml"))
            client.reconnect()
            first_identity = client.server_identity
            self.assertIs(client._channel, first_channel)
            self.assertIs(client._stub, first_stub)

            client.reconnect()

        first_channel.close.assert_called_once_with()
        self.assertIs(client._channel, second_channel)
        self.assertIs(client._stub, second_stub)
        self.assertEqual(client.server_identity, first_identity)
        self.assertRegex(first_identity, r"^[0-9a-f]{64}$")
        self.assertNotIn(config["client_private_key"], first_identity)
        self.assertNotIn(config["client_cert"], first_identity)
        self.assertNotIn(config["api_connection_string"], first_identity)

    def test_flow_queries_use_bounded_deadlines(self):
        api = mock.Mock()
        api.query_file.side_effect = [
            [],
            [
                {
                    "session_id": "F.1",
                    "state": "FINISHED",
                    "total_rows": 0,
                    "created": "",
                    "last_active": "",
                    "request_timeout_seconds": None,
                    "artifacts_with_results": [],
                    "requested_specs": [],
                }
            ],
        ]

        self.assertEqual(self.module.get_all_flows(api, "C.1"), [])
        self.module.get_flow(api, "C.1", "F.1")

        self.assertEqual(
            api.query_file.call_args_list[0].kwargs["timeout"],
            self.module.DEFAULT_FLOW_QUERY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            api.query_file.call_args_list[1].kwargs["timeout"],
            self.module.DEFAULT_FLOW_QUERY_TIMEOUT_SECONDS,
        )

    def test_query_raises_when_velociraptor_returns_vql_error_log(self):
        client = self.module.VeloApiClient(
            Path("/tmp/api_client.yaml"),
            org_id="root",
        )

        class FakeStub:
            def Query(self, request):
                return iter(
                    [
                        mock.Mock(
                            Response="",
                            log="ERROR: VQL parse error near WHERE",
                        )
                    ]
                )

        client._stub = FakeStub()

        with self.assertRaisesRegex(RuntimeError, "reported a query error"):
            client.query("SELECT broken FROM scope()")

    def test_query_distinguishes_only_exact_inventory_not_found(self):
        missing = "inventory_get: Not Found"
        cases = [
            ([missing], True),
            ([missing, missing], True),
            (["inventory_get: permission denied"], False),
            (["source: Not Found"], False),
            ([missing, "ERROR: VQL parse error"], False),
            ([missing + "\nERROR: permission denied"], False),
            ([missing, "info " * velociraptor_api.MAX_SERVER_LOG_CHARS], False),
            ([missing + " " * i for i in range(101)] + ["ERROR: permission denied"], False),
        ]
        for logs, expected_missing in cases:
            with self.subTest(logs=len(logs), last=logs[-1][:60]):
                client = self.module.VeloApiClient(Path("/unused/api.yaml"))
                client._stub = mock.Mock()
                client._stub.Query.return_value = iter([
                    mock.Mock(Response='[{"Inventory": null}]', log=log)
                    for log in logs
                ])
                with self.assertRaises(RuntimeError) as raised:
                    client.query("SELECT inventory_get(tool='test', probe=TRUE) FROM scope()")
                self.assertEqual(
                    isinstance(raised.exception, velociraptor_api.InventoryNotFoundError),
                    expected_missing,
                )
                self.assertIn("reported a query error", str(raised.exception))

    def test_build_request_rejects_timeline_with_extra_artifacts(self):
        with self.assertRaisesRegex(RuntimeError, "cannot be combined with --artifact"):
            self.module.build_request(
                "timeline",
                ["Windows.Forensics.Prefetch"],
                [],
                self.module.TimelineOptions(),
            )

    def test_build_request_rejects_timeline_flags_for_non_timeline_collection(self):
        with self.assertRaisesRegex(RuntimeError, "Timeline-specific flags require --collection-type timeline"):
            self.module.build_request(
                "triage",
                [],
                [],
                self.module.TimelineOptions(date_after="2026-01-01"),
            )

    def test_build_request_defaults_to_all_groups(self):
        request = self.module.build_request(None, [], [])

        self.assertEqual(request.target_collection_type, "all")
        self.assertEqual(request.requested_groups, list(self.module.ALL_COLLECTION_GROUPS))
        self.assertIn("DetectRaptor.Windows.Detection.Evtx", request.requested_artifacts)
        self.assertNotIn("Windows.Registry.Hunter[execution]", request.requested_artifacts)
        self.assertNotIn("Windows.Registry.Hunter[all]", request.requested_artifacts)
        self.assertNotIn("Windows.NTFS.MFT", request.requested_artifacts)
        self.assertNotIn("Windows.EventLogs.EvtxHunter", request.requested_artifacts)
        self.assertIn("Windows.Network.NetstatEnriched", request.requested_artifacts)
        self.assertIn("Windows.Detection.PublicIP", request.requested_artifacts)

    def test_network_collection_type_is_in_all_and_available_individually(self):
        request = self.module.build_request("network", [], [])

        self.assertEqual(request.target_collection_type, "network")
        self.assertEqual(request.requested_groups, ["network"])
        self.assertEqual(
            request.requested_artifacts,
            [
                "Windows.Network.NetstatEnriched",
                "Windows.System.DNSCache",
            ],
        )
        self.assertIn("network", self.module.COLLECTION_TYPE_CHOICES)
        self.assertIn("network", self.module.ALL_COLLECTION_GROUPS)

    def test_evtx_collection_type_is_standalone_and_part_of_triage(self):
        evtx = self.module.build_request("evtx", [], [])
        triage = self.module.build_request("triage", [], [])

        self.assertEqual(evtx.target_collection_type, "evtx")
        self.assertEqual(evtx.requested_groups, ["evtx"])
        self.assertEqual(
            evtx.requested_artifacts,
            [
                "DetectRaptor.Windows.Detection.Evtx",
                "Windows.Detection.PublicIP",
            ],
        )
        self.assertTrue(set(evtx.requested_artifacts).issubset(triage.requested_artifacts))
        self.assertIn("evtx", self.module.COLLECTION_TYPE_CHOICES)
        self.assertNotIn("evtx", self.module.ALL_COLLECTION_GROUPS)

    def test_mft_collection_type_is_standalone_and_part_of_triage(self):
        mft = self.module.build_request("mft", [], [])
        triage = self.module.build_request("triage", [], [])

        self.assertEqual(mft.target_collection_type, "mft")
        self.assertEqual(mft.requested_groups, ["mft"])
        self.assertEqual(
            mft.requested_artifacts,
            ["DetectRaptor.Windows.Detection.MFT"],
        )
        self.assertTrue(set(mft.requested_artifacts).issubset(triage.requested_artifacts))
        self.assertIn("mft", self.module.COLLECTION_TYPE_CHOICES)
        self.assertNotIn("mft", self.module.ALL_COLLECTION_GROUPS)

    def test_detectraptor_collection_type_contains_exact_detectraptor_bundle(self):
        detectraptor = self.module.build_request("detectraptor", [], [])
        triage = self.module.build_request("triage", [], [])

        self.assertEqual(detectraptor.target_collection_type, "detectraptor")
        self.assertEqual(detectraptor.requested_groups, ["detectraptor"])
        self.assertEqual(
            detectraptor.requested_artifacts,
            [
                "DetectRaptor.Windows.Detection.Evtx",
                "DetectRaptor.Windows.Detection.MFT",
                "DetectRaptor.Windows.Detection.Powershell.PSReadline",
                "DetectRaptor.Windows.Detection.Applications",
                "DetectRaptor.Windows.Detection.LolRMM",
                "DetectRaptor.Windows.Detection.Amcache",
                "DetectRaptor.Windows.Detection.BinaryRename",
                "DetectRaptor.Windows.Detection.Webhistory",
                "DetectRaptor.Windows.Detection.YaraProcessWin",
                "DetectRaptor.Generic.Detection.YaraWebshell",
                "DetectRaptor.Generic.Detection.BrowserExtensions",
                "DetectRaptor.Windows.Detection.ZoneIdentifier",
            ],
        )
        self.assertNotIn(
            "Windows.Detection.PublicIP",
            detectraptor.requested_artifacts,
        )
        self.assertNotIn(
            "DetectRaptor.Generic.Detection.YaraWebshell",
            triage.requested_artifacts,
        )
        self.assertTrue(
            (
                set(detectraptor.requested_artifacts)
                - {"DetectRaptor.Generic.Detection.YaraWebshell"}
            ).issubset(triage.requested_artifacts)
        )
        self.assertIn("detectraptor", self.module.COLLECTION_TYPE_CHOICES)
        self.assertNotIn("detectraptor", self.module.ALL_COLLECTION_GROUPS)

    def test_analysis_inputs_persist_without_changing_flow_identity(self):
        first = self.module.build_request(
            None,
            ["Linux.Sys.LogHunter"],
            [
                "TargetFiles=/var/log/nginx/*.log",
                "SearchRegex=wp-login",
            ],
            analysis_input_values=[
                "date_after=2026-08-01T10:00:00Z",
                "date_before=2026-08-01T11:00:00Z",
            ],
        )
        second = self.module.build_request(
            None,
            ["Linux.Sys.LogHunter"],
            [
                "TargetFiles=/var/log/nginx/*.log",
                "SearchRegex=wp-login",
            ],
            analysis_input_values=[
                "date_after=2026-08-01T11:00:00Z",
                "date_before=2026-08-01T12:00:00Z",
            ],
        )
        self.assertEqual(
            self.module.collection_run_identity(
                "C.1234",
                first.expected_specs,
            ),
            self.module.collection_run_identity(
                "C.1234",
                second.expected_specs,
            ),
        )
        self.assertNotEqual(
            self.module.request_id_for_request(first),
            self.module.request_id_for_request(second),
        )
        self.assertEqual(
            first.analysis_inputs["Linux.Sys.LogHunter"]["date_after"],
            "2026-08-01T10:00:00Z",
        )
        restored = self.module.request_from_state(
            {
                "target_collection_type": first.target_collection_type,
                "requested_artifacts": first.requested_artifacts,
                "expected_spec_arguments": self.module.serialize_specs(
                    first.expected_specs
                ),
                "analysis_inputs": first.analysis_inputs,
            },
            [],
        )
        self.assertEqual(restored.analysis_inputs, first.analysis_inputs)

    def test_analysis_inputs_require_one_explicit_artifact(self):
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            self.module.build_request(
                None,
                [],
                [],
                analysis_input_values=["date_after=2026-08-01T10:00:00Z"],
            )

    def test_persistence_defaults_to_live_autoruns(self):
        request = self.module.build_request("persistence", [], [])

        self.assertEqual(request.requested_groups, ["persistence"])
        self.assertEqual(
            request.requested_artifacts,
            ["Windows.Sysinternals.Autoruns"],
        )

    def test_persistence_expanded_retains_complementary_artifacts(self):
        request = self.module.build_request("persistence-expanded", [], [])

        self.assertEqual(
            request.requested_groups,
            ["persistence-expanded"],
        )
        self.assertEqual(
            request.requested_artifacts,
            [
                "Windows.Sys.StartupItems",
                "Windows.System.Services",
                "Windows.System.TaskScheduler",
                "Windows.Registry.TaskCache.HiddenTasks",
                "Windows.Persistence.PermanentWMIEvents",
                "Windows.Sysinternals.Autoruns",
            ],
        )
        self.assertIn(
            "persistence-expanded",
            self.module.ALL_COLLECTION_GROUPS,
        )
        self.assertNotIn("persistence", self.module.ALL_COLLECTION_GROUPS)

    def test_flow_parses_server_compiled_collector_arguments(self):
        flow = self.module.flow_from_row(
            {
                "session_id": "F.1234",
                "state": "FINISHED",
                "total_collected_rows": 1,
                "artifacts_with_results": ["Linux.Forensics.Journal"],
                "RequestTimeoutSeconds": 600,
                "RequestSpecsJson": json.dumps(
                    [
                        {
                            "artifact": "Linux.Forensics.Journal",
                            "parameters": {
                                "env": [
                                    {"key": "DateAfter", "value": "2026-07-18T00:00:00Z"},
                                ]
                            },
                        }
                    ]
                ),
                "CompiledCollectorArgsJson": json.dumps(
                    [{"query_id": 1, "env": [{"key": "DateAfter", "value": "2026-07-18T00:00:00Z"}]}]
                ),
            }
        )

        self.assertEqual(flow.compiled_collector_args[0]["query_id"], 1)
        self.assertEqual(
            flow.requested_specs[0].env["DateAfter"],
            "2026-07-18T00:00:00Z",
        )

    def test_effective_argument_validation_detects_changed_time_and_regex_bounds(self):
        expected = self.module.ArtifactSpec(
            label="Linux.Forensics.Journal",
            artifact="Linux.Forensics.Journal",
            env={
                "DateAfter": "2026-07-18T00:00:00Z",
                "IocRegex": "wp2shell",
            },
            timeout_seconds=600,
        )
        flow = self.module.FlowRecord(
            session_id="F.1234",
            state="FINISHED",
            total_rows=1,
            created="",
            last_active="",
            request_timeout_seconds=600,
            artifacts_with_results=["Linux.Forensics.Journal"],
            requested_specs=[
                self.module.ArtifactSpec(
                    label="Linux.Forensics.Journal",
                    artifact="Linux.Forensics.Journal",
                    env={
                        "DateAfter": "2026-07-19T00:00:00Z",
                        "IocRegex": "generic",
                    },
                    timeout_seconds=600,
                )
            ],
        )

        status = self.module.artifact_status_from_flow(expected, flow)

        self.assertFalse(status["effective_argument_validation"]["validated"])
        self.assertEqual(
            status["effective_argument_validation"]["bounded_argument_keys"],
            ["DateAfter", "IocRegex"],
        )
        with self.assertRaisesRegex(RuntimeError, "server-effective artifact arguments differ"):
            self.module.raise_for_effective_argument_validation(
                [status],
                context="analysis handoff",
            )

    def test_state_records_exact_identity_and_server_effective_arguments(self):
        client = self.module.ClientRecord(
            client_id="C.1234abcd",
            hostname="host01",
            last_seen="2026-07-22T00:00:00Z",
            selector_type="client_id",
            requested_client_id="C.1234abcd",
        )
        expected = self.module.ArtifactSpec(
            label="Linux.Forensics.Journal",
            artifact="Linux.Forensics.Journal",
            env={"IocRegex": "wp2shell"},
        )
        flow = self.module.FlowRecord(
            session_id="F.1234",
            state="FINISHED",
            total_rows=1,
            created="",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=["Linux.Forensics.Journal"],
            requested_specs=[expected],
        )
        status = self.module.artifact_status_from_flow(expected, flow)
        request = self.module.CollectionRequest(
            target_collection_type="Linux.Forensics.Journal",
            requested_groups=[],
            requested_artifacts=["Linux.Forensics.Journal"],
            expected_specs=[expected],
        )

        state = self.module.build_state_payload(
            client,
            "case-123",
            "host01",
            request,
            [status],
        )

        self.assertEqual(state["target_selector_type"], "client_id")
        self.assertEqual(state["requested_client_id"], "C.1234abcd")
        self.assertEqual(state["resolved_hostname"], "host01")
        self.assertTrue(state["effective_arguments_valid"])
        self.assertEqual(
            state["server_effective_artifact_arguments"][0]["source"],
            "flow.request.specs",
        )
        self.assertEqual(
            state["run_identity"]["target"]["client_id"],
            "C.1234abcd",
        )
        self.assertEqual(len(state["run_identity_sha256"]), 64)

    def test_exact_flow_selection_prefers_terminal_success(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={"Needle": "value"},
        )

        def flow(flow_id, state, created):
            return self.module.FlowRecord(
                session_id=flow_id,
                state=state,
                total_rows=1,
                created=str(created),
                last_active="",
                request_timeout_seconds=None,
                artifacts_with_results=["Artifact.Test"],
                requested_specs=[expected],
            )

        selection = self.module.select_matching_flow_for_spec(
            mock.sentinel.api,
            "C.1234",
            expected,
            flows=[
                flow("F.error", "ERROR", 30),
                flow("F.running", "RUNNING", 20),
                flow("F.finished", "FINISHED", 10),
            ],
        )

        self.assertEqual(selection["selected_flow"].session_id, "F.finished")
        self.assertEqual(
            [
                item["classification"]
                for item in selection["exact_match_candidates"]
            ],
            ["terminal_success", "in_flight", "failed_or_cancelled"],
        )

    def test_exact_embedded_artifact_flow_beats_failed_single_artifact_flow(self):
        expected = self.module.ArtifactSpec(
            label="DetectRaptor.Windows.Detection.ZoneIdentifier",
            artifact="DetectRaptor.Windows.Detection.ZoneIdentifier",
            env={},
        )
        webhistory = self.module.ArtifactSpec(
            label="DetectRaptor.Windows.Detection.Webhistory",
            artifact="DetectRaptor.Windows.Detection.Webhistory",
            env={},
        )
        completed_multi = self.module.FlowRecord(
            session_id="F.finished-multi",
            state="FINISHED",
            total_rows=9,
            created="10",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[
                "DetectRaptor.Windows.Detection.ZoneIdentifier",
                "DetectRaptor.Windows.Detection.Webhistory",
            ],
            requested_specs=[expected, webhistory],
        )
        failed_single = self.module.FlowRecord(
            session_id="F.failed-single",
            state="ERROR",
            total_rows=0,
            created="20",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )

        selection = self.module.select_matching_flow_for_spec(
            mock.sentinel.api,
            "C.1234",
            expected,
            flows=[failed_single, completed_multi],
        )

        self.assertTrue(self.module.flow_matches_spec(completed_multi, expected))
        self.assertEqual(
            selection["selected_flow"].session_id,
            "F.finished-multi",
        )
        self.assertEqual(
            selection["blocked_flow"].session_id,
            "F.failed-single",
        )

    def test_server_assigned_default_timeout_does_not_break_exact_match(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
            timeout_seconds=None,
        )
        flow = self.module.FlowRecord(
            session_id="F.default-timeout",
            state="FINISHED",
            total_rows=1,
            created="1",
            last_active="",
            request_timeout_seconds=9000,
            artifacts_with_results=["Artifact.Test"],
            requested_specs=[expected],
        )

        self.assertTrue(self.module.flow_matches_spec(flow, expected))
        status = self.module.artifact_status_from_flow(expected, flow)
        self.assertTrue(status["matching_flow_matches_expected_arguments"])
        self.assertTrue(status["effective_argument_validation"]["validated"])

    def test_ensure_requires_force_for_failed_exact_flow(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[expected],
        )
        failed = self.module.FlowRecord(
            session_id="F.failed",
            state="ERROR",
            total_rows=0,
            created="1",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")

        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                with (
                    mock.patch.object(
                        self.module,
                        "preflight_artifact_availability",
                        return_value={
                            "status": "ready",
                            "requested_artifacts": ["Artifact.Test"],
                            "available_artifacts": ["Artifact.Test"],
                            "missing_artifacts": [],
                            "checked_at": "2026-08-11T00:00:00Z",
                        },
                    ),
                    mock.patch.object(self.module, "get_all_flows", return_value=[failed]),
                    mock.patch.object(self.module, "queue_single_artifact") as queue_mock,
                ):
                    with self.assertRaisesRegex(RuntimeError, "--force-run"):
                        self.module.ensure_collection(
                            mock.sentinel.api,
                            "case-123",
                            "host01",
                            request,
                            60,
                            False,
                            client=client,
                        )
                state = self.module.read_state(
                    self.module.get_request_state_path(
                        "case-123",
                        "host01",
                        self.module.request_id_for_request(request),
                    )
                )
            finally:
                self.module.CASE_ROOT = original_case_root

        queue_mock.assert_not_called()
        self.assertEqual(state["queue_progress"]["status"], "failed")
        self.assertIn("--force-run", state["queue_progress"]["error"])

    def test_ensure_persists_failed_state_when_flow_listing_fails(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")

        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                with (
                    mock.patch.object(
                        self.module,
                        "preflight_artifact_availability",
                        return_value={
                            "status": "ready",
                            "requested_artifacts": ["Artifact.Test"],
                            "available_artifacts": ["Artifact.Test"],
                            "missing_artifacts": [],
                            "checked_at": "2026-08-11T00:00:00Z",
                        },
                    ),
                    mock.patch.object(
                        self.module,
                        "get_all_flows",
                        side_effect=RuntimeError("flow listing failed"),
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "flow listing failed"):
                        self.module.ensure_collection(
                            mock.sentinel.api,
                            "case-123",
                            "host01",
                            request,
                            60,
                            False,
                            client=client,
                        )
                state = self.module.read_state(
                    self.module.get_request_state_path(
                        "case-123",
                        "host01",
                        self.module.request_id_for_request(request),
                    )
                )
            finally:
                self.module.CASE_ROOT = original_case_root

        self.assertEqual(state["queue_progress"]["status"], "failed")
        self.assertIn("flow listing failed", state["queue_progress"]["error"])

    def test_queue_single_artifact_bounds_api_timeout_and_reports_progress(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        queued = self.module.FlowRecord(
            session_id="F.queued",
            state="RUNNING",
            total_rows=0,
            created="1",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )
        api = mock.Mock()
        api.query_file.return_value = [{"flow_id": "F.queued"}]
        progress = []

        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                with (
                    mock.patch.object(self.module, "get_all_flows", return_value=[]),
                    mock.patch.object(self.module, "get_flow", return_value=queued),
                ):
                    result = self.module.queue_single_artifact(
                        api,
                        client,
                        "case-123",
                        "host01",
                        expected,
                        900,
                        progress_callback=progress.append,
                    )
            finally:
                self.module.CASE_ROOT = original_case_root

        self.assertEqual(api.query_file.call_args.kwargs["timeout"], 60)
        self.assertEqual(result["flow_id"], "F.queued")
        self.assertEqual(
            [item["status"] for item in progress],
            ["submitting", "queued"],
        )

    def test_force_run_queues_fresh_flow_despite_terminal_exact_match(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Test",
            artifact="Artifact.Test",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Test",
            requested_groups=[],
            requested_artifacts=["Artifact.Test"],
            expected_specs=[expected],
        )
        existing = self.module.FlowRecord(
            session_id="F.existing",
            state="FINISHED",
            total_rows=1,
            created="1",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=["Artifact.Test"],
            requested_specs=[expected],
        )
        fresh = self.module.FlowRecord(
            session_id="F.fresh",
            state="RUNNING",
            total_rows=0,
            created="2",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=[],
            requested_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        fresh_status = self.module.artifact_status_from_flow(expected, fresh)
        progress = []

        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                with (
                    mock.patch.object(
                        self.module,
                        "preflight_artifact_availability",
                        return_value={
                            "status": "ready",
                            "requested_artifacts": ["Artifact.Test"],
                            "available_artifacts": ["Artifact.Test"],
                            "missing_artifacts": [],
                            "checked_at": "2026-08-11T00:00:00Z",
                        },
                    ),
                    mock.patch.object(
                        self.module,
                        "get_all_flows",
                        return_value=[existing],
                    ),
                    mock.patch.object(
                        self.module,
                        "queue_single_artifact",
                        return_value=fresh_status,
                    ) as queue_mock,
                ):
                    result = self.module.ensure_collection(
                        mock.sentinel.api,
                        "case-123",
                        "host01",
                        request,
                        60,
                        True,
                        client=client,
                        progress_callback=progress.append,
                    )
            finally:
                self.module.CASE_ROOT = original_case_root

        queue_mock.assert_called_once()
        self.assertEqual(result["action"], "forced_new_flows")
        self.assertTrue(result["force_run_requested"])
        self.assertEqual(
            result["artifact_flows"][0]["reuse_decision"],
            "forced_new_flow",
        )
        self.assertEqual(
            result["artifact_flows"][0]["exact_match_count"],
            1,
        )
        self.assertEqual(
            [event["phase"] for event in progress],
            ["preflight", "checking-existing", "queueing"],
        )
        self.assertEqual(progress[-1]["total"], 1)

    def test_artifact_preflight_reports_missing_server_definitions(self):
        request = self.module.CollectionRequest(
            target_collection_type="custom",
            requested_groups=[],
            requested_artifacts=["Artifact.Present", "Artifact.Missing"],
            expected_specs=[
                self.module.ArtifactSpec(
                    label="Artifact.Present",
                    artifact="Artifact.Present",
                    env={},
                ),
                self.module.ArtifactSpec(
                    label="Artifact.Missing",
                    artifact="Artifact.Missing",
                    env={},
                ),
            ],
        )
        api = mock.Mock()
        api.query_file.return_value = [{"name": "Artifact.Present"}]

        result = self.module.preflight_artifact_availability(api, request)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["missing_artifacts"], ["Artifact.Missing"])
        api.query_file.assert_called_once()
        call = api.query_file.call_args
        self.assertEqual(call.args[0], "list_artifact_availability.vql")
        self.assertEqual(
            self.module.json.loads(call.args[1]["Artifacts"]),
            ["Artifact.Missing", "Artifact.Present"],
        )
        self.assertEqual(call.kwargs["timeout"], 30)

    def test_artifact_preflight_records_api_and_org_provenance(self):
        request = self.module.build_request(
            None,
            ["Artifact.Present"],
            [],
        )
        with tempfile.TemporaryDirectory() as directory:
            api_config = Path(directory) / "api.yaml"
            api_config.write_text("name: analyst\n", encoding="utf-8")
            expected_hash = self.module.hashlib.sha256(
                api_config.read_bytes()
            ).hexdigest()
            api = mock.Mock()
            api.api_config = api_config
            api.org_id = "root"
            api.query_file.return_value = [{"name": "Artifact.Present"}]

            result = self.module.preflight_artifact_availability(api, request)

        self.assertEqual(result["api_client_path"], str(api_config.resolve()))
        self.assertEqual(
            result["api_client_sha256"],
            expected_hash,
        )
        self.assertEqual(result["org_id"], "root")
        self.assertTrue(result["checked_at"].endswith("Z"))

    def test_superseded_request_accepts_old_preflight_but_requires_exact_partition(self):
        original_case_root = self.module.CASE_ROOT
        with tempfile.TemporaryDirectory() as directory:
            self.module.CASE_ROOT = Path(directory)
            try:
                previous_request_id = "all-failed"
                previous_path = self.module.get_request_state_path(
                    "IR1",
                    "host01",
                    previous_request_id,
                )
                previous_path.parent.mkdir(parents=True, exist_ok=True)
                previous_path.write_text(
                    json.dumps(
                        {
                            "request_id": previous_request_id,
                            "target_collection_type": "all",
                            "requested_artifacts": [
                                "Artifact.Available",
                                "Artifact.Missing",
                            ],
                            "artifact_flows": {},
                            "artifact_preflight": {
                                "status": "failed",
                                "requested_artifacts": [
                                    "Artifact.Available",
                                    "Artifact.Missing",
                                ],
                                "available_artifacts": ["Artifact.Available"],
                                "missing_artifacts": ["Artifact.Missing"],
                                "checked_at": "2000-01-01T00:00:00Z",
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                replacement = self.module.build_request(
                    None,
                    ["Artifact.Available"],
                    [],
                )
                replacement.supersedes_request_id = previous_request_id
                replacement.unavailable_artifacts = ["Artifact.Missing"]

                self.module.validate_request_supersession(
                    "IR1",
                    "host01",
                    replacement,
                )

                replacement.unavailable_artifacts = []
                with self.assertRaisesRegex(RuntimeError, "exactly match"):
                    self.module.validate_request_supersession(
                        "IR1",
                        "host01",
                        replacement,
                    )
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_superseded_request_rejects_prior_flow_ownership(self):
        original_case_root = self.module.CASE_ROOT
        with tempfile.TemporaryDirectory() as directory:
            self.module.CASE_ROOT = Path(directory)
            try:
                previous_path = self.module.get_request_state_path(
                    "IR1",
                    "host01",
                    "failed-with-flow",
                )
                previous_path.parent.mkdir(parents=True, exist_ok=True)
                previous_path.write_text(
                    json.dumps(
                        {
                            "request_id": "failed-with-flow",
                            "target_collection_type": "all",
                            "requested_artifacts": ["Artifact.Available"],
                            "artifact_flows": {
                                "Artifact.Available": {"flow_id": "F.1234"}
                            },
                            "artifact_preflight": {
                                "status": "failed",
                                "requested_artifacts": ["Artifact.Available"],
                                "available_artifacts": ["Artifact.Available"],
                                "missing_artifacts": [],
                                "checked_at": self.module.now_utc(),
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                replacement = self.module.build_request(
                    None,
                    ["Artifact.Available"],
                    [],
                )
                replacement.supersedes_request_id = "failed-with-flow"

                with self.assertRaisesRegex(RuntimeError, "no recorded flow IDs"):
                    self.module.validate_request_supersession(
                        "IR1",
                        "host01",
                        replacement,
                    )
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_ensure_fails_before_flow_listing_when_artifact_is_missing(self):
        expected = self.module.ArtifactSpec(
            label="Artifact.Missing",
            artifact="Artifact.Missing",
            env={},
        )
        request = self.module.CollectionRequest(
            target_collection_type="Artifact.Missing",
            requested_groups=[],
            requested_artifacts=["Artifact.Missing"],
            expected_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        api = mock.Mock()
        api.query_file.return_value = []

        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                with (
                    mock.patch.object(self.module, "get_all_flows") as flows_mock,
                    mock.patch.object(self.module, "queue_single_artifact") as queue_mock,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "Missing requested artifact definition.*Artifact.Missing",
                    ):
                        self.module.ensure_collection(
                            api,
                            "case-123",
                            "host01",
                            request,
                            60,
                            False,
                            client=client,
                        )
                state = self.module.read_state(
                    self.module.get_request_state_path(
                        "case-123",
                        "host01",
                        self.module.request_id_for_request(request),
                    )
                )
            finally:
                self.module.CASE_ROOT = original_case_root

        flows_mock.assert_not_called()
        queue_mock.assert_not_called()
        self.assertEqual(state["queue_progress"]["status"], "failed")
        self.assertEqual(state["artifact_preflight"]["status"], "failed")
        self.assertEqual(
            state["artifact_preflight"]["missing_artifacts"],
            ["Artifact.Missing"],
        )

    def test_export_fails_closed_on_effective_argument_mismatch(self):
        expected = self.module.ArtifactSpec(
            label="Linux.Forensics.Journal",
            artifact="Linux.Forensics.Journal",
            env={"IocRegex": "wp2shell"},
        )
        flow = self.module.FlowRecord(
            session_id="F.1234",
            state="FINISHED",
            total_rows=1,
            created="",
            last_active="",
            request_timeout_seconds=None,
            artifacts_with_results=["Linux.Forensics.Journal"],
            requested_specs=[
                self.module.ArtifactSpec(
                    label="Linux.Forensics.Journal",
                    artifact="Linux.Forensics.Journal",
                    env={"IocRegex": "generic"},
                )
            ],
        )
        request = self.module.CollectionRequest(
            target_collection_type="Linux.Forensics.Journal",
            requested_groups=[],
            requested_artifacts=["Linux.Forensics.Journal"],
            expected_specs=[expected],
        )
        client = self.module.ClientRecord("C.1234", "host01", "")
        status = self.module.artifact_status_from_flow(expected, flow)

        with mock.patch.object(
            self.module,
            "get_matching_artifact_statuses",
            return_value=(client, [status]),
        ):
            with self.assertRaisesRegex(RuntimeError, "server-effective artifact arguments differ"):
                self.module.export_collection(
                    mock.sentinel.api,
                    "case-123",
                    "host01",
                    request,
                    client=client,
                )

    def test_main_passes_exact_client_to_collection_operation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("stub", encoding="utf-8")
            args = self.module.argparse.Namespace(
                api_client=str(api_client),
                org_id="root",
                command="check",
                investigation_id="case-123",
                client_id="C.1234abcd",
                host=None,
                no_progress=False,
                progress_interval_seconds=20.0,
            )
            request = self.module.CollectionRequest(
                target_collection_type="Generic.Client.Info",
                requested_groups=[],
                requested_artifacts=["Generic.Client.Info"],
                expected_specs=[
                    self.module.ArtifactSpec(
                        label="Generic.Client.Info",
                        artifact="Generic.Client.Info",
                        env={},
                    )
                ],
            )
            client = self.module.ClientRecord(
                client_id="C.1234abcd",
                hostname="host01",
                last_seen="",
                selector_type="client_id",
                requested_client_id="C.1234abcd",
            )
            payload = {
                "investigation_id": "case-123",
                **self.module.client_identity_payload(client),
                "requested_artifacts": ["Generic.Client.Info"],
                "artifact_flows": [],
            }
            api_context = mock.MagicMock()
            api_context.__enter__.return_value = mock.sentinel.api
            api_context.__exit__.return_value = False
            stderr = io.StringIO()

            with (
                mock.patch.object(self.module, "parse_args", return_value=args),
                mock.patch.object(
                    self.module.engagement_context,
                    "resolve",
                    return_value=self.ready_context(api_client),
                ),
                mock.patch.object(self.module, "VeloApiClient", return_value=api_context),
                mock.patch.object(
                    self.module,
                    "resolve_cli_collection_target",
                    return_value=("host01", client),
                ),
                mock.patch.object(self.module, "build_request_from_args", return_value=request),
                mock.patch.object(self.module, "check_collection", return_value=payload) as check_mock,
                mock.patch.object(
                    self.module,
                    "write_coverage_manifest",
                    side_effect=lambda value: value,
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                return_code = self.module.main()

        self.assertEqual(return_code, 0)
        check_mock.assert_called_once_with(
            mock.sentinel.api,
            "case-123",
            "host01",
            request,
            client=client,
        )
        progress_lines = stderr.getvalue().splitlines()
        self.assertTrue(
            all(line.startswith("DFIR-STATUS v=1") for line in progress_lines)
        )
        self.assertIn("scope=collection", progress_lines[0])
        self.assertTrue(any("command=check" in line for line in progress_lines))
        self.assertTrue(any("phase=complete status=complete" in line for line in progress_lines))

    def test_build_request_supports_exfiltration_preset(self):
        exfil_request = self.module.build_request(
            "exfiltration",
            [],
            [],
            self.module.TimelineOptions(
                date_after="2026-09-01T00:00:00Z",
                date_before="2026-09-01T06:00:00Z",
                mft_path_regex=r"(?i)\\staging\\",
                evtx_ioc_regex=r"(?i)archive|upload",
            ),
        )

        self.assertEqual(exfil_request.requested_groups, ["exfiltration"])
        self.assertEqual(
            exfil_request.requested_artifacts,
            [
                "Windows.EventLogs.EvtxHunter",
                "Windows.NTFS.MFT",
                "Windows.Forensics.SRUM",
                "Windows.Forensics.Prefetch",
            ],
        )
        specs = {spec.label: spec for spec in exfil_request.expected_specs}
        self.assertEqual(
            specs["Windows.NTFS.MFT"].env["DateAfter"],
            "2026-09-01T00:00:00Z",
        )
        self.assertEqual(
            specs["Windows.EventLogs.EvtxHunter"].env["DateBefore"],
            "2026-09-01T06:00:00Z",
        )

    def test_exfiltration_requires_a_closed_time_window(self):
        with self.assertRaisesRegex(RuntimeError, "requires both --date-after"):
            self.module.build_request("exfiltration", [], [])
        with self.assertRaisesRegex(RuntimeError, "requires both --date-after"):
            self.module.build_request(
                "exfiltration",
                [],
                [],
                self.module.TimelineOptions(date_after="2026-09-01T00:00:00Z"),
            )
        with self.assertRaisesRegex(RuntimeError, "requires at least one concrete"):
            self.module.build_request(
                "exfiltration",
                [],
                [],
                self.module.TimelineOptions(
                    date_after="2026-09-01T00:00:00Z",
                    date_before="2026-09-01T06:00:00Z",
                ),
            )

    def test_registry_hunter_presets_are_category_scoped(self):
        execution = self.module.build_request(
            None,
            ["Windows.Registry.Hunter[execution]"],
            [],
        )
        persistence = self.module.build_request(
            None,
            ["Windows.Registry.Hunter[persistence]"],
            [],
        )

        self.assertEqual(
            json.loads(execution.expected_specs[0].env["Categories"]),
            ["Program Execution"],
        )
        self.assertEqual(
            json.loads(persistence.expected_specs[0].env["Categories"]),
            ["Persistence"],
        )
        self.assertEqual(execution.expected_specs[0].timeout_seconds, 1800)
        self.assertEqual(persistence.expected_specs[0].timeout_seconds, 1800)

    def test_registry_hunter_preset_retains_category_when_custom_env_is_added(self):
        request = self.module.build_request(
            None,
            ["Windows.Registry.Hunter[persistence]"],
            [
                "IocRegex=(?i)powershell",
                "ModifiedAfter=2026-07-01T00:00:00Z",
                "ModifiedBefore=2026-07-02T00:00:00Z",
            ],
        )

        self.assertEqual(
            json.loads(request.expected_specs[0].env["Categories"]),
            ["Persistence"],
        )
        self.assertEqual(
            request.expected_specs[0].env["IocRegex"],
            "(?i)powershell",
        )
        self.assertEqual(
            request.expected_specs[0].env["ModifiedAfter"],
            "2026-07-01T00:00:00Z",
        )
        self.assertEqual(
            request.expected_specs[0].env["ModifiedBefore"],
            "2026-07-02T00:00:00Z",
        )

    def test_full_registry_hunter_collection_is_standalone_type(self):
        request = self.module.build_request("registry", [], [])

        self.assertEqual(request.requested_groups, ["registry"])
        self.assertEqual(
            request.requested_artifacts,
            ["Windows.Registry.Hunter[all]"],
        )
        self.assertIn("registry", self.module.COLLECTION_TYPE_CHOICES)
        self.assertNotIn("registry", self.module.ALL_COLLECTION_GROUPS)

    def test_registry_collection_type_rejects_extra_artifacts(self):
        with self.assertRaisesRegex(RuntimeError, "standalone"):
            self.module.build_request(
                "registry",
                ["Windows.System.Services"],
                [],
            )

    def test_explicit_all_registry_hunter_rejects_other_collection_targets(self):
        with self.assertRaisesRegex(RuntimeError, "standalone"):
            self.module.build_request(
                "execution",
                ["Windows.Registry.Hunter[all]"],
                [],
            )

    def test_unknown_registry_hunter_preset_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "Unsupported Registry Hunter preset"):
            self.module.build_request(
                None,
                ["Windows.Registry.Hunter[unknown]"],
                [],
            )

    def test_build_coverage_manifest_tracks_status_and_exports(self):
        payload = {
            "investigation_id": "case-123",
            "hostname": "host01",
            "client_id": "C.1234",
            "target_selector_type": "client_id",
            "requested_client_id": "C.1234",
            "resolved_client_id": "C.1234",
            "resolved_hostname": "host01",
            "request_id": "triage-abcd1234",
            "target_collection_type": "triage",
            "requested_groups": ["triage", "persistence"],
            "requested_artifacts": [
                "DetectRaptor.Windows.Detection.Evtx",
                "Windows.Persistence.PermanentWMIEvents",
            ],
            "expected_spec_arguments": [{"artifact": "DetectRaptor.Windows.Detection.Evtx"}],
            "artifact_flows": [
                {
                    "artifact": "DetectRaptor.Windows.Detection.Evtx",
                    "artifact_name": "DetectRaptor.Windows.Detection.Evtx",
                    "matching_flow_found": True,
                    "matching_flow_matches_expected_arguments": True,
                    "flow_id": "F.1111",
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 5,
                    "available_result_components": ["DetectRaptor.Windows.Detection.Evtx"],
                    "expected_env": {},
                    "expected_timeout_seconds": 600,
                    "server_effective_spec_arguments": [
                        {
                            "artifact": "DetectRaptor.Windows.Detection.Evtx",
                            "env": {},
                            "timeout_seconds": 600,
                        }
                    ],
                    "server_compiled_collector_args": [{"query_id": 1}],
                    "effective_argument_source": (
                        "flow.request.compiled_collector_args+flow.request.specs"
                    ),
                    "effective_argument_validation": {
                        "status": "validated",
                        "validated": True,
                    },
                },
                {
                    "artifact": "Windows.Persistence.PermanentWMIEvents",
                    "artifact_name": "Windows.Persistence.PermanentWMIEvents",
                    "matching_flow_found": True,
                    "matching_flow_matches_expected_arguments": True,
                    "flow_id": "F.2222",
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 0,
                    "available_result_components": [],
                    "expected_env": {},
                    "expected_timeout_seconds": 600,
                },
            ],
            "server_effective_artifact_arguments": [
                {
                    "artifact": "DetectRaptor.Windows.Detection.Evtx",
                    "flow_id": "F.1111",
                    "source": "flow.request.specs",
                    "effective_spec_arguments": [],
                    "compiled_collector_args": [],
                    "validation": {"status": "validated", "validated": True},
                }
            ],
            "effective_arguments_valid": True,
            "effective_argument_validation_failures": [],
            "exported_files": [
                {
                    "artifact": "DetectRaptor.Windows.Detection.Evtx",
                    "row_count": 5,
                    "output_file": "/tmp/DetectRaptor.Windows.Detection.Evtx_full.csv",
                }
            ],
        }

        manifest = self.module.build_coverage_manifest(payload)

        self.assertIsNotNone(manifest)
        self.assertEqual(manifest["status_counts"], {"collected": 1, "empty": 1})
        self.assertEqual(manifest["export_state_counts"], {"exported": 1, "not_applicable": 1})
        self.assertEqual(manifest["output_classification_counts"], {"complete": 1, "zero-row": 1})
        self.assertEqual(manifest["zero_row_fallback_required_count"], 1)
        self.assertEqual(manifest["zero_row_fallback_collection_ready_count"], 0)
        self.assertTrue(manifest["host_coverage_complete"])
        self.assertTrue(manifest["review_ready"])
        self.assertFalse(manifest["timeline"]["requested"])
        self.assertFalse(manifest["timeline"]["present"])
        self.assertFalse(manifest["timeline"]["complete"])
        self.assertEqual(manifest["expected_spec_arguments"], payload["expected_spec_arguments"])
        self.assertEqual(manifest["target_selector_type"], "client_id")
        self.assertEqual(manifest["resolved_client_id"], "C.1234")
        self.assertTrue(manifest["effective_arguments_valid"])
        self.assertEqual(
            manifest["server_effective_artifact_arguments"],
            payload["server_effective_artifact_arguments"],
        )
        self.assertEqual(
            [item["artifact"] for item in manifest["items"]],
            payload["requested_artifacts"],
        )
        self.assertEqual(
            manifest["items"][0]["collection_groups"],
            ["triage", "detectraptor", "evtx"],
        )
        self.assertEqual(manifest["items"][0]["output_classification"], "complete")
        self.assertEqual(
            manifest["items"][0]["effective_argument_source"],
            "flow.request.compiled_collector_args+flow.request.specs",
        )
        self.assertTrue(
            manifest["items"][0]["effective_argument_validation"]["validated"]
        )
        self.assertEqual(manifest["items"][0]["exported_row_count"], 5)
        self.assertEqual(
            manifest["items"][0]["exported_files"],
            ["/tmp/DetectRaptor.Windows.Detection.Evtx_full.csv"],
        )
        self.assertEqual(manifest["items"][1]["status"], "empty")
        self.assertEqual(manifest["items"][1]["export_state"], "not_applicable")
        self.assertEqual(manifest["items"][1]["output_classification"], "zero-row")
        self.assertEqual(
            manifest["items"][1]["zero_row_fallback"]["recommended_artifacts"],
            [
                "Windows.System.TaskScheduler",
                "Windows.System.Services",
                "Windows.EventLogs.EvtxHunter",
            ],
        )
        self.assertFalse(manifest["items"][1]["zero_row_fallback"]["collection_ready"])

    def test_write_coverage_manifest_writes_host_and_request_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                payload = {
                    "investigation_id": "case-123",
                    "hostname": "host01",
                    "client_id": "C.1234",
                    "request_id": "execution-abcd1234",
                    "target_collection_type": "execution",
                    "requested_groups": ["execution"],
                    "requested_artifacts": ["Windows.EventLogs.RDPAuth"],
                    "artifact_flows": [],
                    "exported_files": [],
                }

                updated_payload = self.module.write_coverage_manifest(payload)

                coverage_path = Path(updated_payload["coverage_manifest_file"])
                request_coverage_path = Path(updated_payload["request_coverage_manifest_file"])
                self.assertTrue(coverage_path.exists())
                self.assertTrue(request_coverage_path.exists())

                manifest = json.loads(coverage_path.read_text(encoding="utf-8"))
                self.assertEqual(manifest["hostname"], "host01")
                self.assertEqual(manifest["request_id"], "execution-abcd1234")
                self.assertEqual(manifest["items"][0]["artifact"], "Windows.EventLogs.RDPAuth")
                self.assertEqual(manifest["items"][0]["status"], "missing")
                self.assertEqual(manifest["items"][0]["export_state"], "not_ready")
                self.assertEqual(manifest["items"][0]["output_classification"], "failed-no-output")
                self.assertIsNone(manifest["items"][0]["zero_row_fallback"])
                self.assertFalse(manifest["timeline"]["requested"])
                self.assertFalse(manifest["timeline"]["present"])
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_status_refresh_preserves_existing_exports_for_same_request_and_flow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                export_path = Path(temp_dir) / "exports" / "base-file.csv"
                export_path.parent.mkdir(parents=True, exist_ok=True)
                export_path.write_text("Path\nC:/Windows/SysWOW64/n.ps1\n", encoding="utf-8")
                request_coverage_path = self.module.get_request_coverage_path(
                    "case-123",
                    "base-file",
                    "base-file-abc123",
                )
                request_coverage_path.parent.mkdir(parents=True, exist_ok=True)
                self.module.write_json(
                    request_coverage_path,
                    {
                        "request_id": "base-file-abc123",
                        "items": [
                            {
                                "artifact": "Windows.Search.FileFinder",
                                "flow_id": "F.1234",
                                "export_state": "exported",
                                "exported_row_count": 1,
                                "exported_files": [str(export_path)],
                            }
                        ],
                    },
                )
                payload = {
                    "investigation_id": "case-123",
                    "hostname": "base-file",
                    "client_id": "C.1234",
                    "request_id": "base-file-abc123",
                    "target_collection_type": "Windows.Search.FileFinder",
                    "requested_groups": [],
                    "requested_artifacts": ["Windows.Search.FileFinder"],
                    "artifact_flows": [
                        {
                            "artifact": "Windows.Search.FileFinder",
                            "artifact_name": "Windows.Search.FileFinder",
                            "matching_flow_found": True,
                            "matching_flow_matches_expected_arguments": True,
                            "flow_id": "F.1234",
                            "flow_state": "FINISHED",
                            "is_finished": True,
                            "total_rows": 1,
                            "available_result_components": ["Windows.Search.FileFinder"],
                            "expected_env": {},
                            "expected_timeout_seconds": None,
                        }
                    ],
                    "exported_files": [],
                }

                updated_payload = self.module.write_coverage_manifest(payload)

                manifest = json.loads(Path(updated_payload["request_coverage_manifest_file"]).read_text(encoding="utf-8"))
                item = manifest["items"][0]
                self.assertEqual(item["export_state"], "exported")
                self.assertEqual(item["exported_files"], [str(export_path)])
                self.assertEqual(item["exported_row_count"], 1)
                self.assertTrue(item["export_state_preserved"])
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_status_refresh_does_not_preserve_exports_for_different_flow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                export_path = Path(temp_dir) / "exports" / "base-file.csv"
                export_path.parent.mkdir(parents=True, exist_ok=True)
                export_path.write_text("Path\nC:/Windows/SysWOW64/n.ps1\n", encoding="utf-8")
                request_coverage_path = self.module.get_request_coverage_path(
                    "case-123",
                    "base-file",
                    "base-file-abc123",
                )
                request_coverage_path.parent.mkdir(parents=True, exist_ok=True)
                self.module.write_json(
                    request_coverage_path,
                    {
                        "request_id": "base-file-abc123",
                        "items": [
                            {
                                "artifact": "Windows.Search.FileFinder",
                                "flow_id": "F.OLD",
                                "export_state": "exported",
                                "exported_row_count": 1,
                                "exported_files": [str(export_path)],
                            }
                        ],
                    },
                )
                payload = {
                    "investigation_id": "case-123",
                    "hostname": "base-file",
                    "client_id": "C.1234",
                    "request_id": "base-file-abc123",
                    "target_collection_type": "Windows.Search.FileFinder",
                    "requested_groups": [],
                    "requested_artifacts": ["Windows.Search.FileFinder"],
                    "artifact_flows": [
                        {
                            "artifact": "Windows.Search.FileFinder",
                            "artifact_name": "Windows.Search.FileFinder",
                            "matching_flow_found": True,
                            "matching_flow_matches_expected_arguments": True,
                            "flow_id": "F.NEW",
                            "flow_state": "FINISHED",
                            "is_finished": True,
                            "total_rows": 1,
                            "available_result_components": ["Windows.Search.FileFinder"],
                            "expected_env": {},
                            "expected_timeout_seconds": None,
                        }
                    ],
                    "exported_files": [],
                }

                manifest = self.module.build_coverage_manifest(payload)
                item = manifest["items"][0]
                self.assertEqual(item["export_state"], "not_exported")
                self.assertEqual(item["exported_files"], [])
                self.assertFalse(item["export_state_preserved"])
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_request_specific_status_refresh_does_not_promote_request_to_current(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                current_request = self.module.CollectionRequest(
                    target_collection_type="triage",
                    requested_groups=["triage"],
                    requested_artifacts=["DetectRaptor.Windows.Detection.Evtx"],
                    expected_specs=[
                        self.module.ArtifactSpec(
                            label="DetectRaptor.Windows.Detection.Evtx",
                            artifact="DetectRaptor.Windows.Detection.Evtx",
                            env={},
                        )
                    ],
                )
                old_request = self.module.CollectionRequest(
                    target_collection_type="base-file",
                    requested_groups=[],
                    requested_artifacts=["Windows.Search.FileFinder"],
                    expected_specs=[
                        self.module.ArtifactSpec(
                            label="Windows.Search.FileFinder",
                            artifact="Windows.Search.FileFinder",
                            env={},
                        )
                    ],
                )
                current_request_id = self.module.request_id_for_request(current_request)
                old_request_id = self.module.request_id_for_request(old_request)
                current_payload = {
                    "investigation_id": "case-123",
                    "hostname": "host01",
                    "client_id": "C.1234",
                    "request_id": current_request_id,
                    "target_collection_type": current_request.target_collection_type,
                    "requested_groups": current_request.requested_groups,
                    "requested_artifacts": current_request.requested_artifacts,
                    "expected_spec_arguments": self.module.serialize_specs(current_request.expected_specs),
                    "artifact_flows": {
                        "DetectRaptor.Windows.Detection.Evtx": {
                            "artifact": "DetectRaptor.Windows.Detection.Evtx",
                            "artifact_name": "DetectRaptor.Windows.Detection.Evtx",
                            "flow_id": "F.CURRENT",
                            "queue_response_file": "",
                        }
                    },
                }
                old_payload = {
                    **current_payload,
                    "request_id": old_request_id,
                    "queue_progress": {
                        "status": "complete",
                        "artifact": "",
                        "completed_artifacts": 1,
                        "planned_artifacts": 1,
                        "error": "",
                        "updated_at": "2026-08-11T00:00:00Z",
                    },
                    "artifact_preflight": {
                        "status": "ready",
                        "requested_artifacts": ["Windows.Search.FileFinder"],
                        "available_artifacts": ["Windows.Search.FileFinder"],
                        "missing_artifacts": [],
                        "checked_at": "2026-08-11T00:00:00Z",
                    },
                    "target_collection_type": old_request.target_collection_type,
                    "requested_groups": old_request.requested_groups,
                    "requested_artifacts": old_request.requested_artifacts,
                    "expected_spec_arguments": self.module.serialize_specs(old_request.expected_specs),
                    "artifact_flows": {
                        "Windows.Search.FileFinder": {
                            "artifact": "Windows.Search.FileFinder",
                            "artifact_name": "Windows.Search.FileFinder",
                            "flow_id": "F.OLD",
                            "queue_response_file": "",
                        }
                    },
                }
                self.module.write_state("case-123", "host01", current_payload)
                self.module.write_state(
                    "case-123",
                    "host01",
                    old_payload,
                    update_current_pointer=False,
                )

                old_flow = self.module.FlowRecord(
                    session_id="F.OLD",
                    state="FINISHED",
                    total_rows=3,
                    created="",
                    last_active="",
                    request_timeout_seconds=None,
                    artifacts_with_results=["Windows.Search.FileFinder"],
                    requested_specs=[
                        self.module.ArtifactSpec(
                            label="Windows.Search.FileFinder",
                            artifact="Windows.Search.FileFinder",
                            env={},
                        )
                    ],
                )
                with (
                    mock.patch.object(
                        self.module,
                        "get_saved_client",
                        return_value=self.module.ClientRecord(
                            client_id="C.1234",
                            hostname="host01",
                            last_seen="2026-06-10T00:00:00Z",
                        ),
                    ),
                    mock.patch.object(
                        self.module,
                        "get_all_flows",
                        return_value=[old_flow],
                    ) as all_flows,
                    mock.patch.object(self.module, "get_flow") as get_flow,
                ):
                    payload = self.module.status_payload(
                        mock.sentinel.api,
                        "case-123",
                        "host01",
                        request_id=old_request_id,
                    )

                self.assertEqual(payload["request_id"], old_request_id)
                all_flows.assert_called_once_with(mock.sentinel.api, "C.1234")
                get_flow.assert_not_called()
                old_state = json.loads(
                    self.module.get_request_state_path("case-123", "host01", old_request_id).read_text(
                        encoding="utf-8"
                    )
                )
                current_state = json.loads(
                    self.module.get_current_state_path("case-123", "host01").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(old_state["last_seen"], "2026-06-10T00:00:00Z")
                self.assertEqual(old_state["artifact_flows"]["Windows.Search.FileFinder"]["flow_id"], "F.OLD")
                self.assertEqual(old_state["queue_progress"], old_payload["queue_progress"])
                self.assertEqual(payload["queue_progress"], old_payload["queue_progress"])
                self.assertEqual(
                    old_state["artifact_preflight"],
                    old_payload["artifact_preflight"],
                )
                self.assertEqual(
                    payload["artifact_preflight"],
                    old_payload["artifact_preflight"],
                )
                self.assertEqual(
                    current_state["latest_request_id"],
                    current_request_id,
                )
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_resolve_export_request_reconstructs_poll_target_from_saved_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                state_path = self.module.get_current_state_path("case-123", "host01")
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state = {
                    "investigation_id": "case-123",
                    "hostname": "host01",
                    "client_id": "C.1234",
                    "request_id": "persistence-abc123",
                    "target_collection_type": "persistence",
                    "requested_groups": ["persistence"],
                    "requested_artifacts": ["Windows.Registry.Hunter[all]"],
                    "expected_spec_arguments": [
                        {
                            "label": "Windows.Registry.Hunter[all]",
                            "artifact": "Windows.Registry.Hunter",
                            "env": {"RemappingStrategy": "None"},
                            "timeout_seconds": 1800,
                        }
                    ],
                }
                self.module.write_json(state_path, state)
                args = self.module.argparse.Namespace(request_id=None)

                request = self.module.resolve_export_request(args, "case-123", "host01")

                self.assertEqual(request.target_collection_type, "persistence")
                self.assertEqual(request.requested_groups, ["persistence"])
                self.assertEqual(request.requested_artifacts, ["Windows.Registry.Hunter[all]"])
                self.assertEqual(request.expected_specs[0].artifact, "Windows.Registry.Hunter")
                self.assertEqual(request.expected_specs[0].env, {"RemappingStrategy": "None"})
                self.assertEqual(request.expected_specs[0].timeout_seconds, 1800)
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_poll_collection_emits_per_artifact_progress(self):
        first_payload = {
            "hostname": "host01",
            "request_id": "triage-abc123",
            "all_artifacts_expected_complete": False,
            "artifact_flows": [
                {
                    "artifact": "Windows.Forensics.Prefetch",
                    "flow_id": "F.1",
                    "flow_state": "FINISHED",
                    "matching_flow_found": True,
                    "is_finished": True,
                    "total_rows": 4,
                },
                {
                    "artifact": "Windows.Registry.Hunter[all]",
                    "flow_id": "F.2",
                    "flow_state": "RUNNING",
                    "matching_flow_found": True,
                    "is_finished": False,
                    "total_rows": 7,
                },
            ],
        }
        second_payload = {
            **first_payload,
            "all_artifacts_expected_complete": True,
            "artifact_flows": [
                first_payload["artifact_flows"][0],
                {
                    **first_payload["artifact_flows"][1],
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 12,
                },
            ],
        }
        stderr = io.StringIO()

        with (
            mock.patch.object(self.module, "status_payload", side_effect=[first_payload, second_payload]),
            mock.patch.object(
                self.module,
                "wait_for_flow_completion_event",
                return_value={"FlowId": "F.2"},
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.poll_collection(
                mock.sentinel.api,
                "case-123",
                "host01",
                interval_seconds=1,
                timeout_seconds=60,
            )

        self.assertFalse(result["poll_timed_out"])
        self.assertEqual(result["poll_finished_artifact_count"], 2)
        self.assertEqual(result["poll_total_artifact_count"], 2)
        self.assertEqual(result["poll_progress"][1]["state"], "complete")
        self.assertEqual(result["poll_watcher_event_count"], 1)
        progress_output = stderr.getvalue()
        self.assertIn("done 1/2", progress_output)
        self.assertIn("Windows.Registry.Hunter[all]=RUNNING rows=7", progress_output)
        self.assertIn("done 2/2", progress_output)

    def test_collection_progress_callback_emits_structured_poll_accounting(self):
        stderr = io.StringIO()
        reporter = self.module.analysis_cli_output.ProgressReporter(
            scope="collection",
            scope_id="case-123",
            stream=stderr,
            heartbeat_seconds=0,
            throttle_seconds=0,
        )
        update = self.module.collection_progress_callback(reporter, "poll")

        update(
            {
                "hostname": "host01",
                "client_id": "C.1234",
                "request_id": "execution-abc123",
                "poll_finished_artifact_count": 1,
                "poll_total_artifact_count": 2,
                "poll_progress": [
                    {"artifact": "Artifact.One", "total_rows": 4},
                    {"artifact": "Artifact.Two", "total_rows": 7},
                ],
                "raw_evidence": "must-not-appear",
            }
        )

        output = stderr.getvalue()
        self.assertIn("phase=monitoring status=running", output)
        self.assertIn("command=poll", output)
        self.assertIn("completed=1", output)
        self.assertIn("total=2", output)
        self.assertIn("rows=11", output)
        self.assertNotIn("must-not-appear", output)

    def test_poll_collection_callback_receives_server_flow_transitions(self):
        first_payload = {
            "investigation_id": "case-123",
            "hostname": "host01",
            "client_id": "C.1234",
            "request_id": "execution-abc123",
            "requested_groups": ["execution"],
            "requested_artifacts": ["Windows.Forensics.Prefetch"],
            "all_artifacts_expected_complete": False,
            "artifact_flows": [
                {
                    "artifact": "Windows.Forensics.Prefetch",
                    "artifact_name": "Windows.Forensics.Prefetch",
                    "flow_id": "F.1",
                    "flow_state": "RUNNING",
                    "matching_flow_found": True,
                    "matching_flow_matches_expected_arguments": True,
                    "is_finished": False,
                    "total_rows": 0,
                }
            ],
        }
        second_payload = {
            **first_payload,
            "all_artifacts_expected_complete": True,
            "artifact_flows": [
                {
                    **first_payload["artifact_flows"][0],
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 5,
                }
            ],
        }
        transitions = []

        with (
            mock.patch.object(
                self.module,
                "status_payload",
                side_effect=[first_payload, second_payload],
            ),
            mock.patch.object(
                self.module,
                "wait_for_flow_completion_event",
                return_value={"FlowId": "F.1"},
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.module.poll_collection(
                mock.sentinel.api,
                "case-123",
                "host01",
                interval_seconds=1,
                timeout_seconds=60,
                progress_callback=lambda item: transitions.append(
                    item["artifact_flows"][0]["flow_state"]
                ),
            )

        self.assertEqual(transitions, ["RUNNING", "FINISHED"])

    def test_wait_for_flow_completion_event_filters_exact_saved_flow_ids(self):
        api = mock.Mock()
        api.query_file.return_value = [{"FlowId": "F.2", "ClientId": "C.1"}]

        result = self.module.wait_for_flow_completion_event(
            api,
            ["F.2", "F.1"],
            15,
        )

        self.assertEqual(result["FlowId"], "F.2")
        api.query_file.assert_called_once_with(
            "watch_flow_completions.vql",
            {"flow_id_regex": r"^(?:F\.1|F\.2)$"},
            timeout=15,
            max_wait=1,
            max_row=1,
        )

    def test_poll_reconciles_after_watcher_timeout_without_manual_status(self):
        first_payload = {
            "hostname": "host01",
            "request_id": "execution-abc123",
            "all_artifacts_expected_complete": False,
            "artifact_flows": [
                {
                    "artifact": "Artifact.Test",
                    "flow_id": "F.1",
                    "flow_state": "RUNNING",
                    "matching_flow_found": True,
                    "is_finished": False,
                    "total_rows": 0,
                }
            ],
        }
        terminal_payload = {
            **first_payload,
            "all_artifacts_expected_complete": True,
            "artifact_flows": [
                {
                    **first_payload["artifact_flows"][0],
                    "flow_state": "FINISHED",
                    "is_finished": True,
                    "total_rows": 4,
                }
            ],
        }
        with (
            mock.patch.object(
                self.module,
                "status_payload",
                side_effect=[first_payload, terminal_payload],
            ) as status,
            mock.patch.object(
                self.module,
                "wait_for_flow_completion_event",
                return_value=None,
            ) as watch,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = self.module.poll_collection(
                mock.sentinel.api,
                "case-123",
                "host01",
                interval_seconds=1,
                timeout_seconds=60,
            )

        self.assertFalse(result["poll_timed_out"])
        self.assertEqual(result["poll_watcher_event_count"], 0)
        self.assertEqual(status.call_count, 2)
        watch.assert_called_once_with(mock.sentinel.api, ["F.1"], 1)

    def test_poll_collection_rejects_zero_interval(self):
        with self.assertRaisesRegex(RuntimeError, "interval-seconds"):
            self.module.poll_collection(
                mock.sentinel.api,
                "case-123",
                "host01",
                interval_seconds=0,
                timeout_seconds=60,
            )

    def test_automatic_export_uses_the_polled_flow_instead_of_an_older_match(self):
        request = self.module.CollectionRequest(
            target_collection_type="Generic.Client.Info",
            requested_groups=[],
            requested_artifacts=["Generic.Client.Info"],
            expected_specs=[
                self.module.ArtifactSpec(
                    label="Generic.Client.Info",
                    artifact="Generic.Client.Info",
                    env={},
                )
            ],
        )
        artifact_statuses = [
            {
                "artifact": "Generic.Client.Info",
                "artifact_name": "Generic.Client.Info",
                "flow_id": "F.new",
                "flow_state": "FINISHED",
                "is_finished": True,
                "is_expected_complete": True,
                "matching_flow_found": True,
                "matching_flow_matches_expected_arguments": True,
                "total_rows": 3,
            }
        ]
        payload = {
            "hostname": "host01",
            "client_id": "C.1234",
            "all_artifacts_expected_complete": True,
            "artifact_flows": artifact_statuses,
        }
        client = self.module.ClientRecord("C.1234", "host01", "")
        manifest = {
            "manifest_file": "/tmp/manifest.json",
            "exported_files": [
                {
                    "artifact": "Generic.Client.Info",
                    "flow_id": "F.new",
                    "output_file": "/tmp/Generic.Client.Info_full.csv",
                }
            ],
        }

        with (
            mock.patch.object(self.module, "get_client_by_id", return_value=client),
            mock.patch.object(
                self.module,
                "export_collection",
                return_value=manifest,
            ) as export_mock,
        ):
            result = self.module.maybe_export_after_collection(
                mock.sentinel.api,
                payload,
                "case-123",
                "host01",
                request,
                True,
            )

        export_mock.assert_called_once_with(
            mock.sentinel.api,
            "case-123",
            "host01",
            request,
            client=client,
            artifact_statuses=artifact_statuses,
        )
        self.assertEqual(result["exported_files"][0]["flow_id"], "F.new")

    def test_main_poll_no_export_does_not_resolve_export_request(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("stub", encoding="utf-8")
            args = self.module.argparse.Namespace(
                api_client=str(api_client),
                org_id="root",
                command="poll",
                investigation_id="case-123",
                host="host01",
                request_id=None,
                interval_seconds=1,
                timeout_seconds=60,
                no_export=True,
            )
            poll_payload = {
                "investigation_id": "case-123",
                "hostname": "host01",
                "client_id": "C.1234",
                "request_id": "triage-abcd1234",
                "target_collection_type": "triage",
                "requested_groups": ["triage"],
                "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                "artifact_flows": [],
                "all_artifacts_expected_complete": True,
            }
            stdout = io.StringIO()
            api_context = mock.MagicMock()
            api_context.__enter__.return_value = mock.sentinel.api
            api_context.__exit__.return_value = False

            with (
                mock.patch.object(self.module, "parse_args", return_value=args),
                mock.patch.object(
                    self.module.engagement_context,
                    "resolve",
                    return_value=self.ready_context(api_client),
                ),
                mock.patch.object(self.module, "VeloApiClient", return_value=api_context),
                mock.patch.object(self.module, "poll_collection", return_value=poll_payload),
                mock.patch.object(self.module, "resolve_export_request") as resolve_mock,
                mock.patch.object(
                    self.module,
                    "write_coverage_manifest",
                    side_effect=lambda payload: payload,
                ),
                contextlib.redirect_stdout(stdout),
            ):
                return_code = self.module.main()

            self.assertEqual(return_code, 0)
            resolve_mock.assert_not_called()
            payload = json.loads(stdout.getvalue())
            self.assertFalse(payload["exported_after_action"])
            self.assertEqual(payload["export_skipped_reason"], "disabled")
            self.assertIn("does not run analysis or final review", payload["analysis_note"])
            self.assertTrue(payload["all_artifacts_expected_complete"])

    def test_main_poll_export_reconstructs_saved_request_without_target_args(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                api_client = Path(temp_dir) / "api_client.yaml"
                api_client.write_text("stub", encoding="utf-8")
                state_path = self.module.get_request_state_path(
                    "case-123",
                    "host01",
                    "triage-abcd1234",
                )
                state_path.parent.mkdir(parents=True, exist_ok=True)
                self.module.write_json(
                    state_path,
                    {
                        "investigation_id": "case-123",
                        "hostname": "host01",
                        "client_id": "C.1234",
                        "request_id": "triage-abcd1234",
                        "target_collection_type": "triage",
                        "requested_groups": ["triage"],
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "expected_spec_arguments": [
                            {
                                "label": "DetectRaptor.Windows.Detection.Evtx",
                                "artifact": "DetectRaptor.Windows.Detection.Evtx",
                                "env": {},
                                "timeout_seconds": None,
                            }
                        ],
                    },
                )
                args = self.module.argparse.Namespace(
                    api_client=str(api_client),
                    org_id="root",
                    command="poll",
                    investigation_id="case-123",
                    host="host01",
                    request_id="triage-abcd1234",
                    interval_seconds=1,
                    timeout_seconds=60,
                    no_export=False,
                )
                poll_payload = {
                    "investigation_id": "case-123",
                    "hostname": "host01",
                    "client_id": "C.1234",
                    "request_id": "triage-abcd1234",
                    "target_collection_type": "triage",
                    "requested_groups": ["triage"],
                    "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                    "artifact_flows": [],
                    "all_artifacts_expected_complete": True,
                }
                stdout = io.StringIO()
                api_context = mock.MagicMock()
                api_context.__enter__.return_value = mock.sentinel.api
                api_context.__exit__.return_value = False

                def fake_export(_api, payload, _investigation_id, _host, request, export_after):
                    self.assertTrue(export_after)
                    self.assertEqual(request.target_collection_type, "triage")
                    self.assertEqual(request.requested_artifacts, ["DetectRaptor.Windows.Detection.Evtx"])
                    return {**payload, "exported_after_action": True}

                with (
                    mock.patch.object(self.module, "parse_args", return_value=args),
                    mock.patch.object(
                        self.module.engagement_context,
                        "resolve",
                        return_value=self.ready_context(api_client),
                    ),
                    mock.patch.object(self.module, "VeloApiClient", return_value=api_context),
                    mock.patch.object(self.module, "poll_collection", return_value=poll_payload),
                    mock.patch.object(self.module, "maybe_export_after_collection", side_effect=fake_export),
                    mock.patch.object(
                        self.module,
                        "write_coverage_manifest",
                        side_effect=lambda payload: payload,
                    ),
                    contextlib.redirect_stdout(stdout),
                ):
                    return_code = self.module.main()

                self.assertEqual(return_code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertTrue(payload["exported_after_action"])
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_main_export_uses_saved_request_state_for_request_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_case_root = self.module.CASE_ROOT
            self.module.CASE_ROOT = Path(temp_dir)
            try:
                api_client = Path(temp_dir) / "api_client.yaml"
                api_client.write_text("stub", encoding="utf-8")
                state_path = self.module.get_request_state_path(
                    "case-123",
                    "host01",
                    "triage-abcd1234",
                )
                state_path.parent.mkdir(parents=True, exist_ok=True)
                self.module.write_json(
                    state_path,
                    {
                        "investigation_id": "case-123",
                        "hostname": "host01",
                        "client_id": "C.1234",
                        "requested_client_id": "C.1234",
                        "target_selector_type": "client_id",
                        "resolved_client_id": "C.1234",
                        "resolved_hostname": "host01",
                        "request_id": "triage-abcd1234",
                        "target_collection_type": "triage",
                        "requested_groups": ["triage"],
                        "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                        "expected_spec_arguments": [
                            {
                                "label": "DetectRaptor.Windows.Detection.Evtx",
                                "artifact": "DetectRaptor.Windows.Detection.Evtx",
                                "env": {},
                                "timeout_seconds": None,
                            }
                        ],
                        "artifact_flows": {
                            "DetectRaptor.Windows.Detection.Evtx": {
                                "flow_id": "F.saved",
                                "artifact": "DetectRaptor.Windows.Detection.Evtx",
                                "artifact_name": "DetectRaptor.Windows.Detection.Evtx",
                                "matching_flow_found": True,
                                "matching_flow_matches_expected_arguments": True,
                                "flow_state": "FINISHED",
                                "total_rows": 7,
                                "available_result_components": ["DetectRaptor.Windows.Detection.Evtx"],
                                "expected_env": {},
                                "expected_timeout_seconds": None,
                                "server_effective_spec_arguments": [],
                                "server_compiled_collector_args": [],
                                "effective_argument_source": "flow.request.specs",
                                "effective_argument_validation": {
                                    "validated": True,
                                    "status": "validated",
                                },
                            }
                        },
                    },
                )
                args = self.module.argparse.Namespace(
                    api_client=str(api_client),
                    org_id="root",
                    command="export",
                    allow_export=True,
                    investigation_id="case-123",
                    host="host01",
                    request_id="triage-abcd1234",
                    collection_type=None,
                    artifact=None,
                    env=None,
                    flow_timeout_seconds=None,
                    date_after=None,
                    date_before=None,
                    mft_drive=None,
                    mft_path_regex=None,
                    mft_file_regex=None,
                    mft_size_min=None,
                    mft_size_max=None,
                    evtx_glob=None,
                    evtx_ioc_regex=None,
                    evtx_whitelist_regex=None,
                    evtx_path_regex=None,
                    evtx_channel_regex=None,
                    evtx_provider_regex=None,
                    evtx_id_regex=None,
                    evtx_vss_analysis_age=None,
                )
                client = self.module.ClientRecord(
                    client_id="C.1234",
                    hostname="host01",
                    last_seen="",
                    selector_type="client_id",
                    requested_client_id="C.1234",
                )
                saved_status = {
                    "investigation_id": "case-123",
                    **self.module.client_identity_payload(client),
                    "request_id": "triage-abcd1234",
                    "artifact_flows": [
                        {
                            "artifact": "DetectRaptor.Windows.Detection.Evtx",
                            "artifact_name": "DetectRaptor.Windows.Detection.Evtx",
                            "flow_id": "F.saved",
                            "flow_state": "FINISHED",
                            "total_rows": 7,
                            "available_result_components": ["DetectRaptor.Windows.Detection.Evtx"],
                            "matching_flow_found": True,
                            "matching_flow_matches_expected_arguments": True,
                            "server_effective_spec_arguments": [],
                            "server_compiled_collector_args": [],
                            "effective_argument_source": "flow.request.specs",
                            "effective_argument_validation": {
                                "validated": True,
                                "status": "validated",
                            },
                        }
                    ],
                }
                api_context = mock.MagicMock()
                api_context.__enter__.return_value = mock.sentinel.api
                api_context.__exit__.return_value = False

                with (
                    mock.patch.object(self.module, "parse_args", return_value=args),
                    mock.patch.object(
                        self.module.engagement_context,
                        "resolve",
                        return_value=self.ready_context(api_client),
                    ),
                    mock.patch.object(self.module, "VeloApiClient", return_value=api_context),
                    mock.patch.object(
                        self.module,
                        "resolve_cli_collection_target",
                        return_value=("host01", client),
                    ),
                    mock.patch.object(
                        self.module,
                        "resolve_export_request",
                        return_value=self.module.CollectionRequest(
                            target_collection_type="triage",
                            requested_groups=["triage"],
                            requested_artifacts=["DetectRaptor.Windows.Detection.Evtx"],
                            expected_specs=[
                                self.module.ArtifactSpec(
                                    label="DetectRaptor.Windows.Detection.Evtx",
                                    artifact="DetectRaptor.Windows.Detection.Evtx",
                                    env={},
                                )
                            ],
                        ),
                    ),
                    mock.patch.object(self.module, "status_payload", return_value=saved_status) as status_mock,
                    mock.patch.object(
                        self.module,
                        "export_collection",
                        return_value={"manifest_file": "/tmp/manifest.json", "exported_files": []},
                    ) as export_mock,
                    mock.patch.object(
                        self.module,
                        "write_coverage_manifest",
                        side_effect=lambda payload: payload,
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    return_code = self.module.main()

                self.assertEqual(return_code, 0)
                status_mock.assert_called_once_with(
                    mock.sentinel.api,
                    "case-123",
                    "host01",
                    request_id="triage-abcd1234",
                    client=client,
                )
                export_mock.assert_called_once()
                self.assertEqual(
                    export_mock.call_args.kwargs["artifact_statuses"][0]["flow_id"],
                    "F.saved",
                )
            finally:
                self.module.CASE_ROOT = original_case_root

    def test_build_coverage_manifest_classifies_error_outputs(self):
        payload = {
            "investigation_id": "case-123",
            "hostname": "host01",
            "client_id": "C.1234",
            "request_id": "persistence-abcd1234",
            "target_collection_type": "persistence",
            "requested_groups": ["persistence"],
            "requested_artifacts": [
                "Windows.Registry.Hunter[all]",
                "Windows.Sysinternals.Autoruns",
            ],
            "artifact_flows": [
                {
                    "artifact": "Windows.Registry.Hunter[all]",
                    "artifact_name": "Windows.Registry.Hunter",
                    "matching_flow_found": True,
                    "matching_flow_matches_expected_arguments": True,
                    "flow_id": "F.1111",
                    "flow_state": "ERROR",
                    "is_finished": True,
                    "total_rows": 27,
                    "available_result_components": ["Windows.Registry.Hunter/Results"],
                    "expected_env": {},
                    "expected_timeout_seconds": 1800,
                },
                {
                    "artifact": "Windows.Sysinternals.Autoruns",
                    "artifact_name": "Windows.Sysinternals.Autoruns",
                    "matching_flow_found": True,
                    "matching_flow_matches_expected_arguments": True,
                    "flow_id": "F.2222",
                    "flow_state": "ERROR",
                    "is_finished": True,
                    "total_rows": 0,
                    "available_result_components": [],
                    "expected_env": {},
                    "expected_timeout_seconds": 600,
                },
            ],
            "exported_files": [
                {
                    "artifact": "Windows.Registry.Hunter[all]",
                    "row_count": 27,
                    "output_file": "/tmp/Windows.Registry.Hunter.Services.csv",
                }
            ],
        }

        manifest = self.module.build_coverage_manifest(payload)

        self.assertEqual(manifest["status_counts"], {"partial": 1, "failed": 1})
        self.assertEqual(
            manifest["output_classification_counts"],
            {"partial-from-error": 1, "failed-no-output": 1},
        )
        self.assertFalse(manifest["host_coverage_complete"])
        self.assertFalse(manifest["review_ready"])
        self.assertEqual(manifest["items"][0]["status"], "partial")
        self.assertEqual(manifest["items"][0]["output_classification"], "partial-from-error")
        self.assertIn("partial positive context", manifest["items"][0]["output_caveat"])
        self.assertEqual(manifest["items"][1]["status"], "failed")
        self.assertEqual(manifest["items"][1]["output_classification"], "failed-no-output")
        self.assertIn("without reusable output", manifest["items"][1]["output_caveat"])

    def test_error_zero_row_empty_export_stays_failed_no_output(self):
        artifact_status = {
            "artifact": "Windows.Sysinternals.Autoruns",
            "artifact_name": "Windows.Sysinternals.Autoruns",
            "matching_flow_found": True,
            "matching_flow_matches_expected_arguments": True,
            "flow_id": "F.3333",
            "flow_state": "ERROR",
            "is_finished": True,
            "total_rows": 0,
            "available_result_components": [],
            "expected_env": {},
            "expected_timeout_seconds": 600,
        }
        empty_export = {
            "artifact": "Windows.Sysinternals.Autoruns",
            "flow_id": "F.3333",
            "mode": "full",
            "source_components": [],
            "row_count": 0,
            "output_file": "/tmp/Windows.Sysinternals.Autoruns_full.csv",
        }
        payload = {
            "investigation_id": "case-123",
            "hostname": "host01",
            "client_id": "C.1234",
            "request_id": "persistence-abcd1234",
            "target_collection_type": "persistence",
            "requested_groups": ["persistence"],
            "requested_artifacts": ["Windows.Sysinternals.Autoruns"],
            "artifact_flows": [artifact_status],
            "exported_files": [empty_export],
        }

        manifest = self.module.build_coverage_manifest(payload)
        annotated = self.module.annotate_exported_files_with_provenance(
            [empty_export],
            [artifact_status],
        )

        self.assertEqual(manifest["status_counts"], {"failed": 1})
        self.assertEqual(manifest["export_state_counts"], {"not_applicable": 1})
        self.assertEqual(manifest["output_classification_counts"], {"failed-no-output": 1})
        self.assertEqual(manifest["items"][0]["output_classification"], "failed-no-output")
        self.assertEqual(annotated[0]["output_classification"], "failed-no-output")

    def test_main_fails_when_api_client_is_missing(self):
        args = self.module.argparse.Namespace(
            api_client="/tmp/missing-api-client.yaml",
            org_id="root",
            command="status",
            investigation_id="case-123",
            host="host01",
            request_id=None,
        )
        stderr = io.StringIO()

        with (
            mock.patch.object(self.module, "parse_args", return_value=args),
            contextlib.redirect_stderr(stderr),
        ):
            return_code = self.module.main()

        self.assertEqual(return_code, 1)
        self.assertIn("API client config not found", stderr.getvalue())

    def test_main_writes_coverage_manifest_before_returning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            api_client = Path(temp_dir) / "api_client.yaml"
            api_client.write_text("stub", encoding="utf-8")
            args = self.module.argparse.Namespace(
                api_client=str(api_client),
                org_id="root",
                command="status",
                investigation_id="case-123",
                host="host01",
                request_id=None,
                no_progress=True,
                progress_interval_seconds=20.0,
            )
            status_payload = {
                "investigation_id": "case-123",
                "hostname": "host01",
                "client_id": "C.1234",
                "request_id": "triage-abcd1234",
                "target_collection_type": "triage",
                "requested_groups": ["triage"],
                "requested_artifacts": ["DetectRaptor.Windows.Detection.Evtx"],
                "artifact_flows": [],
            }
            stdout = io.StringIO()
            stderr = io.StringIO()
            api_context = mock.MagicMock()
            api_context.__enter__.return_value = mock.sentinel.api
            api_context.__exit__.return_value = False

            with (
                mock.patch.object(self.module, "parse_args", return_value=args),
                mock.patch.object(
                    self.module.engagement_context,
                    "resolve",
                    return_value=self.ready_context(api_client),
                ),
                mock.patch.object(self.module, "VeloApiClient", return_value=api_context),
                mock.patch.object(self.module, "status_payload", return_value=status_payload) as status_mock,
                mock.patch.object(
                    self.module,
                    "write_coverage_manifest",
                    side_effect=lambda payload: {**payload, "coverage_manifest_file": "/tmp/coverage.json"},
                ) as coverage_mock,
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                return_code = self.module.main()

            self.assertEqual(return_code, 0)
            status_mock.assert_called_once_with(
                mock.sentinel.api,
                "case-123",
                "host01",
                request_id=None,
            )
            coverage_mock.assert_called_once()
            self.assertIn('"coverage_manifest_file": "/tmp/coverage.json"', stdout.getvalue())
            self.assertEqual("", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
