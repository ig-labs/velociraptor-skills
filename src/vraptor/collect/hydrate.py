#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


from vraptor.resources import repository_root
REPO_ROOT = repository_root()

from vraptor.paths import add_case_root_arg

from vraptor.analyze import cli_output as analysis_cli_output
from vraptor.collect import requests as collection
from vraptor import context as engagement_context
from vraptor.collect import layout


EXPORT_READY_STATES = {"exported", "not_applicable"}
EXPORT_READY_CLASSIFICATIONS = {"complete", "zero-row", "partial-from-error"}
EXPORT_NOT_READY_CLASSIFICATIONS = {"failed-no-output", "in-progress"}


def normalize(value: str | None) -> str:
    return str(value or "").strip()


def normalize_lower(value: str | None) -> str:
    return normalize(value).lower()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export saved Velociraptor host collection requests across the current investigation scope."
    )
    parser.add_argument(
        "--engagement-id",
        "--investigation-id",
        "--id",
        dest="investigation_id",
        help="Local engagement folder; defaults to --server-profile.",
    )
    parser.add_argument("--investigation-dir", help="Explicit investigation directory. Overrides the case root.")
    add_case_root_arg(parser)
    parser.add_argument(
        "--server-profile",
        help="Velociraptor server/config profile used by this engagement.",
    )
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="Restrict hydration to one host. Repeat as needed.",
    )
    parser.add_argument(
        "--api-client",
        help=(
            "Path to the Velociraptor API client config for this engagement. "
            "Defaults to the shared Velociraptor collection runtime resolution logic."
        ),
    )
    parser.add_argument("--org-id", default=None, help="Velociraptor org id. Defaults to root.")
    parser.add_argument(
        "--force-export",
        action="store_true",
        help="Re-export finished requests even when request-scoped coverage already shows exported outputs.",
    )
    analysis_cli_output.add_progress_args(parser)
    return parser.parse_args(argv)


def get_hydration_manifest_path(investigation_dir: Path) -> Path:
    return (
        investigation_dir
        / "evidence"
        / "velociraptor"
        / "export-hydration.json"
    )


def state_paths_for_host(investigation_dir: Path, hostname: str) -> list[Path]:
    return layout.state_paths_for_host(investigation_dir, hostname)


def request_hosts_from_systems(investigation_dir: Path) -> list[str]:
    return layout.hostnames_with_collection_state(investigation_dir)


def resolve_scope_hosts(investigation_dir: Path, explicit_hosts: list[str]) -> list[dict[str, str]]:
    requested = [normalize(host) for host in explicit_hosts if normalize(host)]
    hosts = requested or request_hosts_from_systems(investigation_dir)
    return [{"hostname": host, "system_status": "", "scope_source": "explicit" if requested else "requests"} for host in hosts]


def coverage_item_export_ready(item: dict[str, Any]) -> bool:
    export_state = normalize_lower(item.get("export_state", ""))
    if export_state not in EXPORT_READY_STATES:
        return False

    coverage_status = normalize_lower(item.get("status", ""))
    if coverage_status in {"missing", "failed", "in_progress"}:
        return False

    output_classification = normalize_lower(item.get("output_classification", ""))
    if output_classification in EXPORT_NOT_READY_CLASSIFICATIONS:
        return False
    if output_classification:
        return output_classification in EXPORT_READY_CLASSIFICATIONS

    return True


def request_coverage_export_ready(payload: dict[str, Any]) -> bool:
    items = list(payload.get("items") or [])
    if not items:
        return False
    return all(isinstance(item, dict) and coverage_item_export_ready(item) for item in items)


def summarize_request_result(
    *,
    hostname: str,
    request_id: str,
    state_file: Path,
    status: str,
    coverage_manifest_file: str = "",
    export_manifest_file: str = "",
    exported_files: list[dict[str, Any]] | None = None,
    artifact_summary: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    return {
        "hostname": hostname,
        "request_id": request_id,
        "state_file": str(state_file),
        "status": status,
        "coverage_manifest_file": coverage_manifest_file,
        "export_manifest_file": export_manifest_file,
        "exported_files": exported_files or [],
        "artifact_summary": artifact_summary or {},
        "error": error,
    }


def hydrate_saved_request(
    api: Any,
    investigation_id: str,
    investigation_dir: Path,
    hostname: str,
    state_path: Path,
    *,
    force_export: bool,
) -> dict[str, Any]:
    request_id = state_path.parent.name
    coverage_path = state_path.parent / "coverage.json"
    if not force_export and coverage_path.is_file():
        coverage_payload = read_json(coverage_path)
        if request_coverage_export_ready(coverage_payload):
            return summarize_request_result(
                hostname=hostname,
                request_id=request_id,
                state_file=state_path,
                status="already_exported",
                coverage_manifest_file=str(coverage_path),
            )

    try:
        latest_status = collection.status_payload(api, investigation_id, hostname, request_id=request_id)
        latest_status = collection.write_coverage_manifest(latest_status)
        artifact_summary = {
            "all_artifacts_expected_complete": bool(latest_status.get("all_artifacts_expected_complete")),
            "artifacts_missing": list(latest_status.get("artifacts_missing") or []),
            "artifacts_in_progress": list(latest_status.get("artifacts_in_progress") or []),
            "artifacts_with_results": list(latest_status.get("artifacts_with_results") or []),
        }
        if not latest_status.get("all_artifacts_expected_complete"):
            return summarize_request_result(
                hostname=hostname,
                request_id=request_id,
                state_file=state_path,
                status="incomplete_collection",
                coverage_manifest_file=str(latest_status.get("request_coverage_manifest_file") or latest_status.get("coverage_manifest_file") or ""),
                artifact_summary=artifact_summary,
            )

        state = collection.read_state(state_path)
        request = collection.request_from_state(state, collection.normalize_artifacts(state.get("requested_artifacts")))
        manifest = collection.export_collection(api, investigation_id, hostname, request)
        manifest = collection.write_coverage_manifest(manifest)
        return summarize_request_result(
            hostname=hostname,
            request_id=request_id,
            state_file=state_path,
            status="exported_now",
            coverage_manifest_file=str(manifest.get("request_coverage_manifest_file") or manifest.get("coverage_manifest_file") or ""),
            export_manifest_file=str(manifest.get("manifest_file") or ""),
            exported_files=list(manifest.get("exported_files") or []),
            artifact_summary=artifact_summary,
        )
    except Exception as exc:
        return summarize_request_result(
            hostname=hostname,
            request_id=request_id,
            state_file=state_path,
            status="export_failed",
            error=str(exc),
        )


def host_status_for_request_results(request_results: list[dict[str, Any]]) -> str:
    if not request_results:
        return "missing_saved_state"
    completed = {"already_exported", "exported_now"}
    statuses = {normalize_lower(item.get("status", "")) for item in request_results}
    if statuses and statuses.issubset(completed):
        return "fully_exported"
    if statuses.intersection(completed):
        return "partially_exported"
    if "incomplete_collection" in statuses:
        return "incomplete_collection"
    return "failed"


def build_host_result(
    *,
    hostname: str,
    system_status: str,
    scope_source: str,
    request_results: list[dict[str, Any]],
) -> dict[str, Any]:
    request_status_counts: dict[str, int] = {}
    for item in request_results:
        request_status = normalize_lower(item.get("status", "")) or "unknown"
        request_status_counts[request_status] = request_status_counts.get(request_status, 0) + 1
    return {
        "hostname": hostname,
        "system_status": system_status,
        "scope_source": scope_source,
        "host_status": host_status_for_request_results(request_results),
        "saved_request_count": len(request_results),
        "request_status_counts": request_status_counts,
        "requests": request_results,
    }


def build_batch_manifest(
    *,
    investigation_id: str,
    investigation_dir: Path,
    scope_hosts: list[dict[str, str]],
    host_results: list[dict[str, Any]],
    force_export: bool,
) -> dict[str, Any]:
    host_status_counts: dict[str, int] = {}
    request_status_counts: dict[str, int] = {}
    for host_result in host_results:
        host_status = normalize_lower(host_result.get("host_status", "")) or "unknown"
        host_status_counts[host_status] = host_status_counts.get(host_status, 0) + 1
        for request_result in host_result.get("requests", []):
            request_status = normalize_lower(request_result.get("status", "")) or "unknown"
            request_status_counts[request_status] = request_status_counts.get(request_status, 0) + 1

    manifest_path = get_hydration_manifest_path(investigation_dir)
    return {
        "generated_at": collection.now_utc(),
        "investigation_id": investigation_id,
        "investigation_dir": str(investigation_dir),
        "manifest_path": str(manifest_path),
        "force_export": force_export,
        "scope_hosts": scope_hosts,
        "summary": {
            "host_count": len(host_results),
            "request_count": sum(len(result.get("requests", [])) for result in host_results),
            "host_status_counts": host_status_counts,
            "request_status_counts": request_status_counts,
        },
        "hosts": host_results,
    }


def main(argv: list[str] | None = None, *, scope_records: list[dict[str, str]] | None = None) -> int:
    args = parse_args(argv)
    started_at = time.monotonic()
    reporter = analysis_cli_output.ProgressReporter(
        scope="collection",
        scope_id=str(
            getattr(args, "investigation_id", "")
            or getattr(args, "server_profile", "")
            or ""
        ),
        enabled=not bool(getattr(args, "no_progress", False)),
        heartbeat_seconds=float(
            getattr(
                args,
                "progress_interval_seconds",
                analysis_cli_output.DEFAULT_HEARTBEAT_SECONDS,
            )
        ),
    )
    reporter.start(phase="preflight", command="hydrate")
    try:
        explicit_dir = (
            Path(args.investigation_dir).expanduser().resolve()
            if args.investigation_dir
            else None
        )
        if explicit_dir and args.investigation_id and explicit_dir.name != args.investigation_id:
            raise RuntimeError("--investigation-dir name must match --engagement-id")
        selected_id = args.investigation_id or (explicit_dir.name if explicit_dir else None)
        selected_root = str(explicit_dir.parent) if explicit_dir else args.case_root
        org_id = collection.resolve_org_id(
            args.org_id
        )
        context = engagement_context.resolve(
            repo_root=REPO_ROOT,
            engagement_id=selected_id,
            server_profile=getattr(args, "server_profile", None),
            api_client=args.api_client,
            case_root=selected_root,
            expected_org_id=org_id,
        )
        args.investigation_id = context.engagement_id
        args.server_profile = context.server_profile
        investigation_dir = context.engagement_dir
        scope_hosts = (list(scope_records) if scope_records is not None else
                       resolve_scope_hosts(investigation_dir, args.host))
        collection.CASE_ROOT = investigation_dir.parent.resolve()
        storage_investigation_id = investigation_dir.name

        api_client = context.api_client

        host_results: list[dict[str, Any]] = []
        with collection.VeloApiClient(api_client, org_id=org_id) as api:
            for index, scope_host in enumerate(scope_hosts, start=1):
                hostname = normalize(scope_host.get("hostname", ""))
                reporter.emit(
                    phase="hydrating",
                    command="hydrate",
                    hostname=hostname,
                    completed=index - 1,
                    total=len(scope_hosts),
                )
                request_paths = state_paths_for_host(investigation_dir, hostname)
                request_results = [
                    hydrate_saved_request(
                        api,
                        storage_investigation_id,
                        investigation_dir,
                        hostname,
                        state_path,
                        force_export=bool(args.force_export),
                    )
                    for state_path in request_paths
                ]
                host_results.append(
                    build_host_result(
                        hostname=hostname,
                        system_status=normalize(scope_host.get("system_status", "")),
                        scope_source=normalize(scope_host.get("scope_source", "")),
                        request_results=request_results,
                    )
                )

        reporter.emit(
            phase="persisting",
            command="hydrate",
            completed=len(host_results),
            total=len(scope_hosts),
        )
        manifest = build_batch_manifest(
            investigation_id=args.investigation_id,
            investigation_dir=investigation_dir,
            scope_hosts=scope_hosts,
            host_results=host_results,
            force_export=bool(args.force_export),
        )
        write_json(get_hydration_manifest_path(investigation_dir), manifest)
        reporter.close(
            status="complete",
            command="hydrate",
            completed=len(host_results),
            total=len(scope_hosts),
            elapsed_seconds=round(time.monotonic() - started_at, 3),
        )
        print(json.dumps(manifest, indent=2, sort_keys=False))
        return 0
    except (RuntimeError, ValueError) as exc:
        reporter.close(
            status="failed",
            phase="failed",
            command="hydrate",
            elapsed_seconds=round(time.monotonic() - started_at, 3),
        )
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
