"""Derived reporting stays complete, byte-bounded and independent of inference."""
import hashlib
import json
from pathlib import Path

import pytest
from test_synthesis_modes import make_checkpoint
from vraptor.analyze import (
    checkpoints,
    flow,
    report_command,
    report_publication,
    saved,
    synthesis,
)
from vraptor.analyze.reporting import ReportingPolicy, reporting_scope
from vraptor.artifacts import persistence


def bind_result(path, result, *, source_identity=True):
    checkpoint, artifacts, plan = saved.load_accepted(path)
    checkpoint["synthesis_cache"] = synthesis.cache_record(
        result, "synthetic-model-cache-key",
        source_identity=synthesis.source_fingerprint(artifacts, question=checkpoint["question"], scope=plan["scope_type"], plan=plan) if source_identity else "",
    )
    checkpoint["checkpoint_fingerprint"] = checkpoints.canonical_hash({k: v for k, v in checkpoint.items() if k not in {"checkpoint_fingerprint", "completed_at"}})
    path.write_text(json.dumps(checkpoint))


def result():
    return {"status": "complete_with_failures", "review_status": "complete",
            "question": "Assess", "answer": "A supported finding; coverage remains partial.",
            "coverage": {"overall": "partial"}, "limitations": ["Partial SSH evidence."],
            "findings": [{"id": "F1", "summary": "High priority finding", "report_priority": "high", "confidence": "medium", "sources": [], "examples": []}]}


def test_exact_byte_boundary_and_unicode_pages_preserve_all_content(tmp_path):
    path = tmp_path / "report.md"
    text = "é" * 512
    assert not report_publication.publish_report(path, text, max_bytes=1024)["paginated"]
    text += "é🙂漢" * 2000
    publication = report_publication.publish_report(path, text, max_bytes=1024)
    assert publication["paginated"]
    pages = [Path(name) for name in publication["files"][1:]]
    assert all(item.stat().st_size <= 1024 for item in [path, *pages])
    restored = "".join(item.read_text().split("\n\n", 1)[1] for item in pages)
    assert restored == text
    before = {item: item.stat().st_mtime_ns for item in pages}
    report_publication.publish_report(path, text, max_bytes=1024)
    assert before == {item: item.stat().st_mtime_ns for item in pages}


def test_publication_failure_keeps_previous_index(tmp_path, monkeypatch):
    path = tmp_path / "report.md"
    path.write_text("previous report")
    original = report_publication.atomic_io.write_text_atomic
    calls = []

    def interrupted(destination, content, **kwargs):
        calls.append(destination)
        if len(calls) == 2:
            raise OSError("synthetic interruption")
        original(destination, content, **kwargs)

    monkeypatch.setattr(report_publication.atomic_io, "write_text_atomic", interrupted)
    with pytest.raises(OSError):
        report_publication.publish_report(path, "finding\n" * 1000, max_bytes=1024)
    assert path.read_text() == "previous report"


def test_no_overwrite_of_changed_content_addressed_page(tmp_path):
    path = tmp_path / "report.md"
    publication = report_publication.publish_report(path, "finding\n" * 1000, max_bytes=1024)
    page = Path(publication["files"][1])
    page.write_text("operator modification")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="changed or unrelated"):
        report_publication.publish_report(path, "finding\n" * 1000, max_bytes=1024)
    assert path.read_bytes() == before
    assert page.read_text() == "operator modification"


def test_large_fence_and_exact_context_do_not_become_compact_fragments(tmp_path):
    path = tmp_path / "report.md"
    for text in ("```json\n" + "x" * 5000 + "\n```\n", "### Evidence 1\n- Supports: F1\n" + "x" * 5000):
        with pytest.raises(ValueError):
            report_publication.publish_report(path, text, max_bytes=1024)
        assert not path.exists()
        assert not list(tmp_path.glob("*--pages-*"))


def test_rerender_preserves_checkpoint_and_reports_with_zero_calls(tmp_path, monkeypatch):
    path = make_checkpoint(tmp_path)
    bind_result(path, result())
    source_report = tmp_path / "artifact.md"
    before = path.read_bytes(), source_report.read_bytes()
    monkeypatch.setattr(saved, "create_agent_runner", lambda *args, **kwargs: pytest.fail("inference invoked"))
    with reporting_scope(ReportingPolicy(compact_markdown_bytes=1024)):
        payload = report_command.render_checkpoint(path)
    assert payload["model_calls"] == 0
    assert (path.read_bytes(), source_report.read_bytes()) == before
    manifest = json.loads(Path(payload["manifest"]).read_text())
    assert manifest["source_status"] == "complete_with_failures"
    assert manifest["selected_result"] == "synthesis_cache"
    assert manifest["coverage"]["overall"] == "partial"
    assert manifest["source_reports"][0]["sha256"] == saved.sha256_file(source_report)
    rendered = "\n".join(Path(name).read_text() for name in manifest["publication"]["files"])
    assert "Partial SSH evidence" in rendered
    assert "High priority finding" in rendered
    assert "artifact.md" in rendered


def test_fresh_synthesis_report_does_not_claim_zero_model_calls(tmp_path):
    text = report_command.render_saved_report(
        result(), checkpoint=tmp_path / "checkpoint.json", checkpoint_hash="test",
        scope="host", model_calls=3,
    )
    assert "3 synthesis model call(s)" in text
    assert "no model calls" not in text


@pytest.mark.parametrize("change", ["unbound", "question", "task_mode", "time_filter"])
def test_unbound_or_stale_synthesis_never_replaces_current_candidates(tmp_path, change):
    path = make_checkpoint(tmp_path)
    old = result()
    old["answer"] = "STALE FINAL ASSESSMENT"
    bind_result(path, old, source_identity=change != "unbound")
    if change != "unbound":
        checkpoint = json.loads(path.read_text())
        checkpoint[change] = {"question": "Changed scope", "task_mode": "targeted_hunt", "time_filter": {"start": "2026-01-01"}}[change]
        checkpoint["checkpoint_fingerprint"] = checkpoints.canonical_hash({k: v for k, v in checkpoint.items() if k not in {"checkpoint_fingerprint", "completed_at"}})
        path.write_text(json.dumps(checkpoint))
    payload = report_command.render_checkpoint(path)
    manifest = json.loads(Path(payload["manifest"]).read_text())
    assert manifest["selected_result"] != "synthesis_cache"
    text = Path(payload["report"]).read_text()
    assert "STALE FINAL ASSESSMENT" not in text
    assert "no matching accepted-source fingerprint" in text


def test_rerender_rejects_changed_source_without_creating_outputs(tmp_path):
    path = make_checkpoint(tmp_path)
    (tmp_path / "artifact.md").write_text("changed")
    with pytest.raises(ValueError, match="report"):
        report_command.render_checkpoint(path)
    assert not (tmp_path / "rendered-reports").exists()


def test_hunt_candidates_rerender_without_host_or_provider_state(tmp_path):
    accepted = result()
    accepted.update(artifact="hunt-evidence", review_status="not_requested")
    path = tmp_path / "hunt-analysis-state.json"
    path.write_text(json.dumps({"scope_id": "H.test", "question": "Assess", "checkpoint": {
        "accepted_result": accepted, "accepted_fingerprint": synthesis.fingerprint(accepted), "result": accepted,
    }}))
    before = path.read_bytes()
    payload = report_command.render_checkpoint(path)
    assert path.read_bytes() == before
    assert "Saved hunt analysis report" in Path(payload["report"]).read_text()
    assert payload["model_calls"] == 0


def test_failed_hunt_update_rerenders_current_partial_candidates_not_previous_review(tmp_path):
    partial = result()
    partial.update(artifact="hunt-evidence", review_status="not_requested")
    partial["findings"][0]["summary"] = "CURRENT PARTIAL CANDIDATE"
    previous = result()
    previous.update(status="complete", answer="STALE SUCCESSFUL ASSESSMENT")
    previous["findings"][0]["summary"] = "STALE FINDING"
    path = tmp_path / "hunt-analysis-state.json"
    path.write_text(json.dumps({"scope_id": "H.test", "question": "Assess",
        "checkpoint": {"result": previous},
        "partial_candidates": {"accepted_result": partial,
                               "accepted_fingerprint": synthesis.fingerprint(partial)}}))
    before = path.read_bytes()
    payload = report_command.render_checkpoint(path)
    manifest = json.loads(Path(payload["manifest"]).read_text())
    text = Path(payload["report"]).read_text()
    assert manifest["selected_result"] == "accepted_candidates"
    assert manifest["source_status"] == "complete_with_failures"
    assert "CURRENT PARTIAL CANDIDATE" in text
    assert "STALE SUCCESSFUL ASSESSMENT" not in text
    assert "STALE FINDING" not in text
    assert "older published assessment is not treated as current" in text
    assert path.read_bytes() == before


@pytest.mark.parametrize("state", ["valid", "missing", "changed"])
def test_hunt_published_result_requires_its_integrity_fingerprint(tmp_path, state):
    accepted = result()
    accepted.update(artifact="hunt-evidence", review_status="not_requested")
    reviewed = result()
    reviewed["answer"] = "CURRENT REVIEW"
    checkpoint = {"accepted_result": accepted,
                  "accepted_fingerprint": synthesis.fingerprint(accepted),
                  "result": reviewed}
    if state != "missing":
        checkpoint["result_sha256"] = hashlib.sha256(flow.canonical_json(reviewed).encode()).hexdigest()
    if state == "changed":
        reviewed["answer"] = "MODIFIED REVIEW"
    path = tmp_path / "hunt-analysis-state.json"
    path.write_text(json.dumps({"scope_id": "H.test", "question": "Assess", "checkpoint": checkpoint}))
    if state == "changed":
        with pytest.raises(ValueError, match="hunt result failed integrity"):
            report_command.render_checkpoint(path)
        assert not (tmp_path / "rendered-reports").exists()
    else:
        payload = report_command.render_checkpoint(path)
        text = Path(payload["report"]).read_text()
        assert ("CURRENT REVIEW" in text) == (state == "valid")


def test_persistence_uses_effective_config_without_relaxing_evidence_rules(tmp_path):
    path = tmp_path / "analysis-hunt.md"
    path.write_text("summary\n" * 200)
    with reporting_scope(ReportingPolicy(compact_markdown_bytes=1024)), pytest.raises(persistence.PersistencePolicyError, match="1024-byte"):
        persistence.classify_analysis_file(path, analysis_root=tmp_path, source_ids=["H.test"])
    with reporting_scope(ReportingPolicy(compact_markdown_bytes=4096)):
        assert persistence.classify_analysis_file(path, analysis_root=tmp_path, source_ids=["H.test"])["content_profile"] == "compact_human_summary"
        path.write_text("### Evidence 1\nraw payload\n")
        with pytest.raises(persistence.PersistencePolicyError, match="row-shaped"):
            persistence.classify_analysis_file(path, analysis_root=tmp_path, source_ids=["H.test"])


def test_root_cli_rerender_honors_profile_without_credentials(tmp_path, monkeypatch, capsys):
    from vraptor import cli

    path = make_checkpoint(tmp_path)
    config = tmp_path / "reporting.toml"
    config.write_text('schema_version=2\n[reporting]\npreview_chars=40\n[profiles.review]\nprovider="openai"\nmodel="gpt-6-luna"\n[profiles.review.reporting]\ndetailed_findings=1\n')
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert cli.main(["reports", "render", "--checkpoint", str(path), "--ai-config-file", str(config), "--execution-profile", "review", "--report-preview-chars", "60", "--no-log-file"]) == 0
    payload = json.loads(capsys.readouterr().out)
    manifest = json.loads(Path(payload["manifest"]).read_text())
    assert manifest["reporting"]["effective"]["detailed_findings"] == 1
    assert manifest["reporting"]["effective"]["preview_chars"] == 60


def test_cumulative_host_memory_applies_priority_before_detail_cap(tmp_path, monkeypatch):
    from vraptor.analyze import command

    findings = [{"id": f"L{i:02d}", "summary": f"Low finding {i}", "report_priority": "low", "confidence": "high", "sources": [], "examples": []} for i in range(20)]
    findings.append({"id": "H1", "summary": "High finding arrived last", "report_priority": "high", "confidence": "medium", "sources": [], "examples": []})
    checkpoint = {"result": {"status": "complete", "findings": findings}, "artifact_summaries": []}
    monkeypatch.setattr(command, "_host_report_checkpoints", lambda paths: ({}, [checkpoint]))
    with reporting_scope(ReportingPolicy(detailed_findings=20)):
        rendered = command.render_cumulative_host_memory(paths={"host_state": tmp_path / "state.json"})
    assert rendered.index("### H1:") < rendered.index("### L00:")
    assert "### L19:" not in rendered
    assert "`L19`" in rendered
    assert len(findings) == 21
