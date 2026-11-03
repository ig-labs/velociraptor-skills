"""Render saved, integrity-checked analysis without inference or acquisition."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from vraptor.analyze import flow, saved, summary, synthesis
from vraptor.analyze.report_publication import publish_report
from vraptor.analyze.reporting import current_policy
from vraptor.common import atomic_io
from vraptor.logging import operations


def _saved_result(checkpoint: dict, artifacts: list[dict], plan: dict) -> tuple[dict, str]:
    cache = checkpoint.get("synthesis_cache") or {}
    warning = ""
    if cache:
        result = cache.get("result")
        if not isinstance(result, dict) or cache.get("result_fingerprint") != synthesis.fingerprint(result):
            raise ValueError("Saved synthesis result failed integrity validation")
        expected_source = synthesis.source_fingerprint(
            artifacts, question=str(checkpoint.get("question") or artifacts[0].get("question") or "").strip(),
            scope=plan["scope_type"], plan=plan,
        )
        if cache.get("source_fingerprint") == expected_source:
            return copy.deepcopy(result), "synthesis_cache"
        warning = "Saved synthesis cache has no matching accepted-source fingerprint; this report uses the current checkpoint result instead of treating that cached review as current."
    if plan["scope_type"] == "host":
        result = checkpoint.get("result")
    elif checkpoint.get("partial_candidates"):
        # load_accepted selected the failed update's current candidates. The
        # published checkpoint may still describe an older successful run.
        result = None
        warning = "A newer hunt update has partial accepted candidates; the older published assessment is not treated as current."
    else:
        published = dict(checkpoint.get("checkpoint") or {})
        result = published.get("result")
        expected_hash = published.get("result_sha256")
        if result and expected_hash:
            actual_hash = hashlib.sha256(flow.canonical_json(result).encode("utf-8")).hexdigest()
            if actual_hash != expected_hash:
                raise ValueError("Saved hunt result failed integrity validation")
        elif result:
            result = None
            warning = "Saved hunt result has no integrity fingerprint; this report uses the retained accepted candidates."
    if isinstance(result, dict) and result:
        result, selection = copy.deepcopy(result), "saved_result"
    else:
        result, selection = synthesis.preliminary(artifacts, question=checkpoint.get("question", ""), scope=plan["scope_type"]), "accepted_candidates"
    if warning:
        result["limitations"] = [*(result.get("limitations") or []), warning]
    return result, selection


def render_saved_report(result: dict, *, checkpoint: Path, checkpoint_hash: str, scope: str, source_reports=(), model_calls: int = 0) -> str:
    """Unclipped Markdown; only the shared per-section presentation policy applies."""
    lines = [f"# Saved {scope} analysis report", "",
             f"- Status: `{result.get('status', 'unknown')}`",
             f"- Review: {summary.analysis_stage(result)}",
             f"- Source checkpoint: `{checkpoint}`",
             f"- Source SHA-256: `{checkpoint_hash}`",
             (f"- Report generation: {model_calls} synthesis model call(s); no evidence acquisition."
              if model_calls else "- Re-render only: no model calls or evidence acquisition."), "",
             "## Coverage", ""]
    for key, value in dict(result.get("coverage") or {}).items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Question", "", str(result.get("question") or "Not retained."),
              "", "## Assessment", "", str(result.get("answer") or "No accepted assessment text."),
              "", "## Findings", "", *summary.render_compact_findings(result),
              "", "## Relevant context", "", *summary.render_relevant_context(result),
              *summary.render_final_review(result), "", "## Limitations", ""]
    limitations = summary.unique_limitations(result.get("limitations") or [])
    lines += [f"- {item}" for item in limitations] or ["- None recorded."]
    lines += ["- Older compact checkpoints may not retain every example. Re-rendering cannot recover discarded evidence values; use the linked accepted artifact reports and authoritative source.",
              "", "## Follow-up", ""]
    lines += summary.render_follow_up(result)
    if source_reports:
        lines += ["", "## Accepted artifact reports", ""]
        lines += [f"- [{item['artifact']}]({item['path']}) — SHA-256 `{item['sha256']}`" for item in source_reports]
    return "\n".join(lines).rstrip() + "\n"


def render_checkpoint(path: Path, *, output_dir: Path | None = None) -> dict:
    path = Path(path).expanduser().resolve()
    original = path.read_bytes()
    checkpoint_hash = hashlib.sha256(original).hexdigest()
    checkpoint, artifacts, plan = saved.load_accepted(path)
    result, selection = _saved_result(checkpoint, artifacts, plan)
    policy = current_policy()
    identity = synthesis.fingerprint({"source_sha256": checkpoint_hash, "reporting": policy.as_dict()})[:20]
    destination = (output_dir.expanduser().resolve() if output_dir else path.parent / "rendered-reports" / identity)
    report_path = destination / "saved-analysis.md"
    manifest_path = destination / "report-manifest.json"
    protected = {path, *(Path(str(item.get("report_file"))).expanduser().resolve() for item in checkpoint.get("artifact_summaries") or [] if item.get("report_file"))}
    if report_path in protected or manifest_path in protected:
        raise ValueError("Re-render destination conflicts with an accepted source file")
    if report_path.exists() and not manifest_path.is_file():
        raise ValueError("Output contains an unrelated saved-analysis.md; choose another output directory")
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        if previous.get("format") != "vraptor-derived-report-v1":
            raise ValueError("Output contains an unrelated report manifest")
    source_reports = [{"artifact": str(item.get("artifact") or item.get("artifact_name") or "artifact"),
                       "path": str(item["report_file"]), "sha256": str(item.get("report_sha256") or "")}
                      for item in checkpoint.get("artifact_summaries") or [] if item.get("report_file")]
    report = render_saved_report(result, checkpoint=path, checkpoint_hash=checkpoint_hash, scope=plan["scope_type"], source_reports=source_reports)
    if path.read_bytes() != original:
        raise RuntimeError("Source checkpoint changed during report rendering; no report was published")
    publication = publish_report(report_path, report)
    compact = summary.compact_result(result)
    manifest = {"format": "vraptor-derived-report-v1", "checkpoint": str(path),
                "checkpoint_sha256": checkpoint_hash, "selected_result": selection,
                "source_status": result.get("status", "unknown"),
                "source_review_status": result.get("review_status", "unknown"),
                "coverage": copy.deepcopy(result.get("coverage") or {}),
                "source_reports": source_reports,
                "reporting": policy.public_dict(), "selection": compact.get("reporting", {}),
                "finding_count": len(result.get("findings") or []),
                "model_calls": 0, "acquisition_calls": 0,
                "legacy_examples": "Only retained examples can be rendered; no omitted values are reconstructed.",
                "publication": publication}
    atomic_io.write_json_atomic(manifest_path, manifest, sort_keys=True)
    return {"status": "rendered", "report": str(report_path), "manifest": str(manifest_path),
            "source_status": manifest["source_status"], "model_calls": 0, "publication": publication,
            **operations.correlation_metadata()}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vraptor reports")
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render", help="Re-render saved accepted analysis without inference")
    render.add_argument("--checkpoint", type=Path, required=True)
    render.add_argument("--output-dir", type=Path)
    render.add_argument("--ai-config-file", "--config-file", dest="config_file", help="Reporting configuration selected by the CLI wrapper")
    render.add_argument("--execution-profile", help="Reporting profile selected by the CLI wrapper")
    render.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    payload = render_checkpoint(args.checkpoint, output_dir=args.output_dir)
    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.format == "json" else f"Report: {payload['report']}\nManifest: {payload['manifest']}\nModel calls: 0")
    return 0
