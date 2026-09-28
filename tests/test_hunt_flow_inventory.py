"""Preflight must not transport repeated compiled collector requests."""
import json
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
import subprocess
import unittest
from unittest import mock

from vraptor.hunt import operations as hunting
from vraptor.hunt import command as hunt_workflow


BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


class HuntFlowInventoryTest(unittest.TestCase):
    @unittest.skipUnless(BINARY.exists(), "Local Velociraptor unavailable")
    def test_server_projection_preserves_status_and_snapshot_routing(self):
        source = [
            {"ClientId": f"C.{i}", "FlowId": f"F.{i}", "Flow": {
                "client_id": f"C.{i}", "session_id": f"F.{i}",
                "state": state, "total_collected_rows": count,
                "artifacts_with_results": ["Windows.Test"],
                "request": {"compiled_collector_args": "x" * 60000},
            }}
            for i, state, count in [(1, "FINISHED", 10), (2, "RUNNING", 20)]
        ]
        api = mock.Mock()
        hunting.query_hunt_flows(api, "H.test")
        query = api.query.call_args.args[0].replace(
            "hunt_flows(hunt_id=HuntId, basic_info=FALSE)",
            "foreach(row=parse_json_array(data=TestFlows))",
        )
        result = subprocess.run(
            [str(BINARY), "query", "--format=jsonl", "--env",
             "TestFlows=" + json.dumps(source), query],
            text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(result.stderr)
        projected = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertLess(len(result.stdout), 1000)
        self.assertEqual(len(projected), 2)
        self.assertTrue(all("request" not in row["Flow"] for row in projected))
        self.assertEqual(hunting.summary_from_hunt_flows(projected),
                         hunting.summary_from_hunt_flows(source))
        self.assertEqual(hunt_workflow.flow_snapshot_targets(projected, "Windows.Test"),
                         hunt_workflow.flow_snapshot_targets(source, "Windows.Test"))
        self.assertEqual(len(hunt_workflow.flow_snapshot_targets(projected, "Windows.Test")), 2)

    def test_transport_batch_size_is_not_a_total_flow_limit(self):
        flows = [{"ClientId": f"C.{i}"} for i in range(1101)]
        api = mock.Mock()
        api.query.return_value = flows
        self.assertEqual(hunting.query_hunt_flows(api, "H.test"), flows)
        self.assertEqual(api.query.call_args.kwargs["max_row"], 100)
        self.assertNotIn("LIMIT", api.query.call_args.args[0])
