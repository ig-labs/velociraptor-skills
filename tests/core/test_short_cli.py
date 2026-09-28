"""Synthetic CLI, source-selection and no-mutation contracts."""
import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from vraptor import cli, results
from vraptor.collect import requests as collection
from vraptor.analyze import command as analysis
from vraptor.analyze import existing as existing_analysis


@pytest.mark.parametrize("args", [
    [], ["--flow", "F.1", "--hunt", "H.1"],
    ["--request", "r", "--force-run"],
    ["--hunt", "H.1", "--retry-missing-after-hours", "1"],
    ["--hunt", "H.1", "--client", "C.1"],
    ["--from", "manifest.json", "--group", "group"],
])
def test_conflicting_or_mutating_selectors_fail(args):
    if not args:
        assert cli.main(["analyze"]) == 0
    else:
        assert cli.main(["analyze", *args]) == 1


@pytest.mark.parametrize("target", ["venv", "velociraptor", "volatility", "plaso", "tsk", "all"])
def test_preparation_dispatch_preserves_targets_without_installing(target):
    with patch.object(cli.subprocess, "run", return_value=Mock(returncode=17)) as run:
        assert cli.main(["tools", "prep", "-t", target, "-d", "/synthetic/tools"]) == 17
    assert run.call_args.args[0][2:] == ["-t", target, "-d", "/synthetic/tools"]


def test_guard_blocks_mutations_through_nested_operations():
    with results.operation_policy(existing_only=True):
        with results.operation_policy():
            with pytest.raises(RuntimeError, match="forbids remote mutation"):
                results.require_remote_mutation("collect_client")
    results.require_remote_mutation("collect_client")


def test_lowest_submission_primitives_reject_existing_analysis():
    from vraptor.hunt import operations

    api = Mock()
    with results.operation_policy(existing_only=True):
        with pytest.raises(RuntimeError, match="queue_single_artifact"):
            collection.queue_single_artifact(api, None, "IR1", "host01", None, 30)
        with pytest.raises(RuntimeError, match="create_hunt"):
            operations.create_hunt(api, "IR1", "fixture", None, None, [], [], [], True)
    assert not api.mock_calls


def test_exact_flow_adoption_reuses_request_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(collection, "CASE_ROOT", tmp_path)
    client = collection.ClientRecord("C.1", "host01", "")
    spec = collection.ArtifactSpec("Artifact.Test", "Artifact.Test", {})
    flow = collection.FlowRecord("F.1", "FINISHED", 0, "1", "2", None, [], [spec])
    request = collection.CollectionRequest("custom", [], [spec.artifact], [spec])
    state = collection.build_state_payload(client, "IR1", "host01", request, [collection.artifact_status_from_flow(spec, flow)])
    collection.write_state("IR1", "host01", state, update_current_pointer=False)
    state_path = collection.get_request_state_path("IR1", "host01", state["request_id"])
    evidence = state_path.parent / "evidence.jsonl"
    evidence.write_bytes(b'{"event":"synthetic"}\n')
    original = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (state_path, evidence)}
    args = analysis.build_parser().parse_args(["--id", "IR1", "--client-id", "C.1", "--artifact", "Artifact.Test"])
    args.flow_id = "F.1"
    with patch.object(collection, "get_flow", return_value=flow), patch.object(collection, "status_payload", return_value=state) as status, patch.object(collection, "write_state") as write:
        result = existing_analysis.adopt_flow(Mock(), args, "host01", client)
    assert result[2] == "reused_exact_flow"
    assert status.call_args.kwargs["request_id"] == state["request_id"]
    write.assert_not_called()
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in original} == original
    assert "/systems/host01/collection/requests/" in str(state_path)
    assert not (tmp_path / "IR1/workspace.json").exists()


def test_saved_request_cannot_fall_through_to_ensure():
    args = analysis.build_parser().parse_args(["--id", "IR1", "--client-id", "C.1"])
    args.existing_only = True
    with patch.object(collection, "resolve_cli_collection_target", return_value=("host01", Mock())), patch.object(collection, "ensure_collection") as ensure:
        with pytest.raises(RuntimeError, match="requires --flow or --request-id"):
            analysis.start_collection(Mock(), args, policy=Mock())
    ensure.assert_not_called()


def test_hunt_short_route_keeps_readiness_and_existing_guard():
    from vraptor.hunt import command as hunt_workflow
    with patch.object(hunt_workflow, "main", return_value=2) as main:
        assert cli.main(["analyze", "--hunt", "H.1", "--id", "IR1", "--skip-ai", "--json"]) == 2
    assert main.call_args.kwargs == {"existing_only": True}
    assert main.call_args.args[0] == ["analyze", "--hunt-id", "H.1", "--id", "IR1", "--skip-ai", "--format", "json"]


def test_hunt_preparation_is_incomplete_only_on_new_route(tmp_path):
    from vraptor.hunt import command

    arguments = ["analyze", "--hunt-id", "H.1", "--id", "IR1", "--case-root", str(tmp_path), "--skip-ai", "--no-progress", "--format", "json"]
    with patch.object(command, "validate_live_engagement", return_value=None), patch.object(
        command, "command_analyze", return_value={"ai_review_status": "skipped", "review_complete": False}
    ):
        assert command.main(arguments, existing_only=True) == 2
        assert command.main(arguments) == 0


@pytest.mark.parametrize("field", ["org_id", "api_client_sha256"])
def test_saved_connection_change_fails_closed(tmp_path, field):
    api_file = tmp_path / "api.yaml"
    api_file.write_text("synthetic API configuration")
    api = Mock(api_config=api_file, org_id="root")
    recorded = existing_analysis.connection_identity(api)
    recorded[field] = "different"
    with pytest.raises(RuntimeError, match="Saved request connection changed"):
        existing_analysis.validate_saved_connection(api, {"artifact_preflight": recorded})


def test_missing_flow_does_not_submit_collection():
    args = analysis.build_parser().parse_args(["--id", "IR1", "--client-id", "C.1"])
    args.flow_id = "F.missing"
    args.existing_only = True
    with patch.object(collection, "resolve_cli_collection_target", return_value=("host01", Mock())), patch.object(collection, "get_flow", side_effect=RuntimeError("not found")), patch.object(collection, "ensure_collection") as ensure:
        with pytest.raises(RuntimeError, match="not found"):
            analysis.start_collection(Mock(), args, policy=Mock())
    ensure.assert_not_called()
