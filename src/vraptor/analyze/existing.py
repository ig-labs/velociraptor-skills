"""Adopt an explicitly selected flow using the existing collection state contract."""
from __future__ import annotations

from pathlib import Path
from vraptor.common.hashing import sha256_file
from vraptor.collect import requests as collection


def adopt_flow(api, args, hostname, client):
    flow = collection.get_flow(api, client.client_id, args.flow_id)
    if flow.session_id != args.flow_id:
        raise RuntimeError("Exact flow lookup returned a different flow identity")
    selected = set(args.artifact or [spec.artifact for spec in flow.requested_specs])
    specs = [spec for spec in flow.requested_specs if spec.artifact in selected]
    if not specs or selected != {spec.artifact for spec in specs}:
        raise RuntimeError("Selected artifacts are not present in the exact flow request")
    if any((args.env, args.analysis_input, args.collection_type, args.bundle,
            args.collection_group, args.target_mode, args.flow_timeout_seconds,
            args.supersedes_request_id, args.unavailable_artifact)) or collection.timeline_options_present(collection.timeline_options_from_args(args)):
        raise RuntimeError("Existing-flow analysis cannot change collection arguments")
    with collection.collection_state_lock(args.investigation_id, hostname):
        request = collection.CollectionRequest("custom", [], sorted(selected), specs)
        request_id = collection.request_id_for_request(request)
        # Prefer the original saved request, including its policy-derived identity.
        matches = []
        for path in collection.layout.state_paths_for_host(collection.CASE_ROOT / args.investigation_id, hostname):
            state = collection.read_state(path)
            entries = dict(state.get("artifact_flows") or {})
            if set(state.get("requested_artifacts") or []) == selected and entries and all(
                item.get("flow_id") == flow.session_id for item in entries.values()
            ):
                matches.append(str(state["request_id"]))
        if len(set(matches)) > 1:
            raise RuntimeError("Multiple saved requests select this flow; specify --request-id")
        if matches:
            request_id = matches[0]
            validate_saved_connection(api, collection.read_state(collection.get_request_state_path(args.investigation_id, hostname, request_id)))
        else:
            path = collection.get_request_state_path(args.investigation_id, hostname, request_id)
            if path.exists():
                raise RuntimeError("A different saved flow owns this request identity; select its --request-id")
            statuses = [collection.artifact_status_from_flow(spec, flow) for spec in specs]
            state = collection.build_state_payload(client, args.investigation_id, hostname, request, statuses)
            state["artifact_preflight"] = connection_identity(api)
            collection.write_state(args.investigation_id, hostname, state, update_current_pointer=False)
        payload = collection.status_payload(api, args.investigation_id, hostname, request_id=request_id, client=client)
    return hostname, payload, "reused_exact_flow", client


def connection_identity(api):
    path = getattr(api, "api_config", None)
    return {
        "api_client_path": str(path) if isinstance(path, (str, Path)) else "",
        "api_client_sha256": sha256_file(Path(path)) if isinstance(path, (str, Path)) and Path(path).is_file() else "",
        "org_id": str(getattr(api, "org_id", "") or ""),
    }


def validate_saved_connection(api, state):
    saved = dict(state.get("artifact_preflight") or {})
    current = connection_identity(api)
    for key in ("api_client_sha256", "org_id"):
        if saved.get(key) and saved[key] != current.get(key):
            raise RuntimeError(f"Saved request connection changed: {key}")
