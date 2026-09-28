"""Controlled saved-request forward validation for collection analysis."""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vraptor.common import atomic_io
from vraptor.common.hashing import sha256_file
from vraptor.analyze import checkpoints as host_analysis_state


ACCEPTED_STATUSES = {"complete", "complete_with_failures"}
RAW_EVIDENCE_MARKERS = (
    "--- CSV EVIDENCE START ---",
    "--- CSV EVIDENCE END ---",
)
def build_saved_request_command(
    *,
    repo_root: Path,
    case_root: Path,
    investigation_id: str,
    hostname: str,
    client_id: str,
    request_id: str,
    question: str,
    api_client: Path | None = None,
    org_id: str | None = None,
) -> list[str]:
    """Build a saved-request-only command; never permit recollection arguments."""
    required = {
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client_id,
        "request_id": request_id,
        "question": question,
    }
    missing = [name for name, value in required.items() if not str(value).strip()]
    if missing:
        raise ValueError(
            "saved-request forward validation requires: " + ", ".join(missing)
        )
    command = [
        str(repo_root / "dfir"),
        "velociraptor",
        "collect",
        "analyze",
        "--case-root",
        str(case_root),
        "--investigation-id",
        investigation_id,
        "--client-id",
        client_id,
        "--request-id",
        request_id,
        "--question",
        question,
        "--format",
        "json",
        "--no-progress",
    ]
    if api_client is not None:
        command.extend(["--api-client", str(api_client)])
    if org_id:
        command.extend(["--org-id", org_id])
    return command


def _sha256(path: Path) -> str:
    return sha256_file(path)


def validate_forward_outputs(
    result: dict[str, Any],
    *,
    case_root: Path,
    investigation_id: str,
    hostname: str,
    client_id: str,
    request_id: str,
    saw_provisional_report: bool,
) -> dict[str, Any]:
    """Validate final saved-request outputs without trusting process stdout alone."""
    status = str(result.get("status") or "")
    if status not in ACCEPTED_STATUSES:
        raise RuntimeError(f"forward run ended with unacceptable status {status!r}")
    expected = {
        "hostname": hostname,
        "client_id": client_id,
        "request_id": request_id,
    }
    for key, value in expected.items():
        if str(result.get(key) or "") != value:
            raise RuntimeError(f"forward result {key} does not match the requested target")

    expected_host_root = (case_root / investigation_id / "systems" / hostname).resolve()
    expected_request_analysis = (
        expected_host_root / "collection" / "requests" / request_id / "analysis"
    )
    expected_paths = {
        "request_checkpoint_file": expected_request_analysis / "request-analysis.json",
        "host_state_file": expected_host_root / "host-analysis-state.json",
        "host_report_file": expected_host_root / "analysis-host.md",
    }
    paths: dict[str, Path] = {}
    for key, expected_path in expected_paths.items():
        path = Path(str(result.get(key) or "")).resolve()
        if not path.is_file():
            raise RuntimeError(f"forward result {key} does not exist: {path}")
        if path != expected_path.resolve():
            raise RuntimeError(f"forward result {key} is outside its canonical path")
        paths[key] = path

    checkpoint = json.loads(
        paths["request_checkpoint_file"].read_text(encoding="utf-8")
    )
    state = json.loads(paths["host_state_file"].read_text(encoding="utf-8"))
    for payload_name, payload in (("checkpoint", checkpoint), ("state", state)):
        for key, value in expected.items():
            if str(payload.get(key) or "") != value:
                raise RuntimeError(
                    f"durable {payload_name} {key} does not match the requested target"
                )
    if (
        int(checkpoint.get("schema_version") or 0)
        != host_analysis_state.REQUEST_CHECKPOINT_SCHEMA_VERSION
        or int(state.get("schema_version") or 0)
        != host_analysis_state.SCHEMA_VERSION
    ):
        raise RuntimeError("forward outputs use an unsupported host analysis schema")
    if str(checkpoint.get("status") or "") != status:
        raise RuntimeError("forward stdout status does not match durable checkpoint")
    if bool(checkpoint.get("evidence_persisted")) or bool(state.get("evidence_persisted")):
        raise RuntimeError("forward run unexpectedly persisted raw evidence")
    expected_checkpoint_fingerprint = host_analysis_state.canonical_hash(
        {
            key: value
            for key, value in checkpoint.items()
            if key not in {"completed_at", "checkpoint_fingerprint"}
        }
    )
    if str(checkpoint.get("checkpoint_fingerprint") or "") != expected_checkpoint_fingerprint:
        raise RuntimeError("request checkpoint fingerprint does not validate")
    synthesis = dict(state.get("synthesis") or {})
    if str(synthesis.get("request_checkpoint_sha256") or "") != _sha256(
        paths["request_checkpoint_file"]
    ):
        raise RuntimeError("host state does not reference the durable request checkpoint")
    durable_text = json.dumps(
        {"checkpoint": checkpoint, "state": state},
        ensure_ascii=False,
        sort_keys=True,
    )
    for marker in RAW_EVIDENCE_MARKERS:
        if marker in durable_text:
            raise RuntimeError(f"durable forward state contains raw evidence marker {marker}")

    checkpoint_hash = _sha256(paths["request_checkpoint_file"])
    host_report_hash = _sha256(paths["host_report_file"])
    final_report = paths["host_report_file"].read_text(encoding="utf-8")
    if "Provisional running report" in final_report:
        raise RuntimeError("canonical host report remained provisional")
    if not saw_provisional_report:
        raise RuntimeError("forward run did not expose a provisional running report")

    artifact_results = list(checkpoint.get("artifact_summaries") or [])
    reported_files = {
        str(key): Path(str(value)).resolve()
        for key, value in dict(result.get("artifact_report_files") or {}).items()
    }
    for artifact_result in artifact_results:
        artifact = str(artifact_result.get("artifact") or "")
        report_path = Path(str(artifact_result.get("report_file") or "")).resolve()
        if expected_host_root not in report_path.parents or not report_path.is_file():
            raise RuntimeError(f"artifact report escaped or is missing for {artifact}")
        if reported_files.get(artifact) != report_path:
            raise RuntimeError(f"stdout omitted or changed artifact report for {artifact}")
        if str(artifact_result.get("report_sha256") or "") != _sha256(report_path):
            raise RuntimeError(f"artifact report hash does not validate for {artifact}")
    failed_artifacts = [
        str(artifact or "")
        for artifact, item in dict(state.get("artifacts") or {}).items()
        if str(dict(item).get("analysis_status") or "") not in ACCEPTED_STATUSES
    ]
    retried_tasks = [
        str(artifact)
        for artifact, item in dict(state.get("artifacts") or {}).items()
        if int(dict(item).get("attempts") or 0) > 1
        or int(dict(item).get("retry_count") or 0) > 0
    ]
    host_result = dict(checkpoint.get("result") or {})
    coverage = dict(host_result.get("coverage") or {})
    source_fingerprint = host_analysis_state.canonical_hash(
        {
            str(item.get("artifact") or ""): str(item.get("source_fingerprint") or "")
            for item in artifact_results
        }
    )
    return {
        "schema_version": 1,
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "investigation_id": investigation_id,
        "hostname": hostname,
        "client_id": client_id,
        "request_id": request_id,
        "source_fingerprint": source_fingerprint,
        "planned_artifacts": len(dict(state.get("artifacts") or {})),
        "accepted_artifacts": len(artifact_results),
        "failed_artifacts": failed_artifacts,
        "planned_rows": int(coverage.get("planned_rows") or 0),
        "reviewed_rows": int(coverage.get("reviewed_rows") or 0),
        "retried_tasks": retried_tasks,
        "saw_provisional_report": saw_provisional_report,
        "request_checkpoint_sha256": checkpoint_hash,
        "host_report_sha256": host_report_hash,
        "domain_assessments": dict(host_result.get("domain_assessments") or {}),
        "evidence_persisted": False,
    }


def run_saved_request_forward_validation(
    *,
    repo_root: Path,
    case_root: Path,
    investigation_id: str,
    hostname: str,
    client_id: str,
    request_id: str,
    question: str,
    output: Path,
    api_client: Path | None = None,
    org_id: str | None = None,
    poll_interval_seconds: float = 0.5,
) -> dict[str, Any]:
    """Run and validate one existing request without collecting new evidence."""
    command = build_saved_request_command(
        repo_root=repo_root,
        case_root=case_root,
        investigation_id=investigation_id,
        hostname=hostname,
        client_id=client_id,
        request_id=request_id,
        question=question,
        api_client=api_client,
        org_id=org_id,
    )
    report = (
        case_root
        / investigation_id
        / "systems"
        / hostname
        / "analysis-host.md"
    )
    process = subprocess.Popen(
        command,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    saw_provisional = False
    while process.poll() is None:
        if report.is_file():
            try:
                saw_provisional = saw_provisional or (
                    "Provisional running report"
                    in report.read_text(encoding="utf-8")
                )
            except OSError:
                pass
        time.sleep(max(0.05, poll_interval_seconds))
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(
            f"saved-request forward command failed ({process.returncode}): "
            f"{stderr.strip() or stdout.strip()}"
        )
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("saved-request forward command returned invalid JSON") from exc
    validation = validate_forward_outputs(
        result,
        case_root=case_root,
        investigation_id=investigation_id,
        hostname=hostname,
        client_id=client_id,
        request_id=request_id,
        saw_provisional_report=saw_provisional,
    )
    atomic_io.write_json_atomic(output, validation, sort_keys=True)
    return validation
