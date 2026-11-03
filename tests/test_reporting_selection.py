"""Report budgets select priority without changing accepted evidence."""
import copy

from vraptor.analyze import coordinator, summary
from vraptor.analyze.reporting import ReportingPolicy, reporting_scope
from vraptor.autoruns import publication as autoruns_publication
from vraptor.autoruns import reporting as autoruns_reporting


def finding(number, priority="low", confidence="high"):
    return {
        "id": f"F{number}", "summary": f"Finding {number}",
        "confidence": confidence, "report_priority": priority,
        "priority_rationale": "Recorded review priority.",
        "evidence": [{"ref": f"S0001-R{number}", "fields": {
            "Command": f"command-{number}", "Timestamp": f"2026-01-{number:02d}T12:00:00Z",
        }}],
    }


def test_high_finding_last_displaces_low_and_keeps_all_evidence():
    result = {"findings": [finding(i) for i in range(1, 21)] + [finding(21, "high", "low")]}
    before = copy.deepcopy(result)
    compact = summary.compact_result(result)
    assert compact["findings"][0]["id"] == "F21"
    assert len(compact["findings"]) == 21
    assert all(item["examples"] for item in compact["findings"])
    text = "\n".join(summary.render_compact_findings(compact))
    assert "### F21: Finding 21" in text
    assert "### F20: Finding 20" not in text
    assert "`F20` [low; confidence=high]" in text
    assert "command-20" not in text
    assert compact["reporting"]["priority_counts"]["high"]["detailed"] == 1
    assert compact["reporting"]["priority_counts"]["low"]["indexed"] == 1
    assert compact["reporting"]["omitted_examples"] == 1
    assert result == before


def test_all_high_findings_remain_represented_and_reordering_is_deterministic():
    rows = [finding(i, "high") for i in range(1, 26)]
    with reporting_scope(ReportingPolicy(detailed_findings=2)):
        first = summary.compact_result({"findings": rows})
        second = summary.compact_result({"findings": list(reversed(rows))})
        assert first == second
        text = "\n".join(summary.render_compact_findings(first))
    assert first["reporting"]["priority_counts"]["high"] == {
        "total": 25, "detailed": 2, "indexed": 23, "omitted_examples": 23,
    }
    assert "`F25` [high; confidence=high]" in text


def test_context_and_timeline_select_priority_before_limits():
    result = {"findings": [finding(1), finding(2, "critical")], "relevant_context": [
        {"finding_id": "F1", "summary": "Lower priority context", "ref": "S0001-R1"},
        {"finding_id": "F2", "summary": "Critical context", "ref": "S0001-R2"},
    ]}
    with reporting_scope(ReportingPolicy(context_items=1, timeline_rows=1)):
        compact = summary.compact_result(result)
        assert len(compact["relevant_context"]) == 2  # retained for later re-render
        context = "\n".join(summary.render_relevant_context(result))
        timeline = "\n".join(summary.render_utc_timeline(result))
    assert "Critical context" in context and "Lower priority context" not in context
    assert "2026-01-02" in timeline and "2026-01-01" not in timeline
    assert "1 additional timeline row(s) omitted" in timeline


def test_evidence_budget_keeps_high_priority_group_first():
    result = {"findings": [finding(1), finding(2, "high")]}
    for item in result["findings"]:
        item["evidence"][0]["_full_fields"] = {"Command": item["summary"] * 5}
    with reporting_scope(ReportingPolicy(evidence_chars=100)):
        text = summary.render_finding_supplement(result, title="Selected evidence")
    assert "- Supports: F2" in text
    assert "- Supports: F1" not in text
    assert "additional selected full-row group" in text


def test_chat_preserves_late_limitations_over_verbose_low_detail():
    result = {"status": "complete_with_failures", "answer": "Assessment", "findings": [
        {**finding(i), "summary": "Long low priority narrative " * 100} for i in range(1, 10)
    ] + [finding(10, "critical", "low")], "limitations": ["SSH collection is partial."],
        "bounded_follow_up": ["Acquire missing evidence."]}
    with reporting_scope(ReportingPolicy(chat_chars=1500)):
        text = summary.render_chat_summary(result)
    assert len(text) <= 1500
    assert "complete_with_failures" in text
    assert "SSH collection is partial." in text
    assert "F10" in text
    assert "complete analysis report" in text


def test_specialized_hunt_uses_shared_limit_and_indexes_overflow(tmp_path):
    state = {"findings": [finding(1), finding(2), finding(3, "high")]}
    with reporting_scope(ReportingPolicy(detailed_findings=1)):
        text = coordinator.render_specialized_hunt_section(state, hunt_root=tmp_path)
    assert text.index("Finding 3") < text.index("Finding 1")
    assert "Indexed [low]: Finding 1" in text
    assert "Indexed [low]: Finding 2" in text


def test_autoruns_context_priority_and_preview_policy():
    rows = [{"Severity": "low", "Entry": "low-item", "Reason": "Low"},
            {"Severity": "high", "Entry": "high-item", "Reason": "x" * 80}]
    with reporting_scope(ReportingPolicy(context_items=1, preview_chars=20)):
        text = "\n".join(autoruns_reporting.render_context(rows, heading_level=3))
    assert "high-item" in text and "low-item" not in text
    assert "x" * 21 not in text


def test_old_findings_do_not_infer_priority_from_confidence():
    result = {"findings": [{"id": "F1", "confidence": "high", "summary": "Legacy"}]}
    compact = summary.compact_result(result)
    assert compact["findings"][0]["report_priority"] == "unranked"
    assert compact["findings"][0]["available_example_count"] == 0
    assert compact["findings"][0]["example_coverage"] == "unavailable"


def test_missing_priority_label_in_specialized_and_detectraptor_reports(tmp_path):
    legacy = {"id": "F1", "summary": "Retained finding", "confidence": "high"}
    state = {"findings": [legacy]}
    before = copy.deepcopy(state)
    text = coordinator.render_specialized_hunt_section(state, hunt_root=tmp_path)
    assert "[Not assessed]" in text
    notes = "\n".join(coordinator._render_detectraptor_report_notes(
        [{**legacy, "detection": "Detection.Test", "count": 1}], context_ledger="context.json",
    ))
    assert "Report priority: `Not assessed`" in notes
    assert state == before


def test_native_autoruns_summary_bounds_chat_and_sanitizes_indexed_legacy_rows():
    record = {"counts": {"SourceRows": 100, "MatchedRows": 0, "GroupCount": 100, "ResidualRows": 100},
              "review_complete": True, "result_review": "partial"}
    rows = [{"Severity": "info", "TotalRows": 1, "Category": "test", "ImagePath": "test.exe",
             "LaunchString": "test.exe", "IdentityId": f"ID{i}\x1b[2J", "Reason": "Legacy\ncontext " * 50}
            for i in range(100)]
    before = copy.deepcopy(rows)
    with reporting_scope(ReportingPolicy(detailed_findings=1, chat_chars=850)):
        full = autoruns_publication.render_summary(record, {"suspicious_rows": rows}, bounded=False)
        compact = autoruns_publication.render_summary(record, {"suspicious_rows": rows})
    assert "Indexed [informational]" in full
    assert "\x1b" not in full and "Legacy\ncontext" not in full
    assert len(compact) <= 850
    assert "Result review: `partial`" in compact
    assert "presence and signer labels do not prove execution" in compact
    assert rows == before


def test_chat_overflow_retains_missing_priority_and_legacy_classification():
    result = {"findings": [
        {"id": f"F{i}", "summary": "Long retained finding " * 20, "confidence": "high"}
        for i in range(30)
    ] + [{"id": "LEGACY", "report_priority": "informational", "summary": "Saved context finding"}]}
    with reporting_scope(ReportingPolicy(chat_chars=1200)):
        text = summary.render_chat_summary(result)
    assert len(text) <= 1200
    assert "Not assessed" in text
    assert "informational" in text
    assert "unranked" not in text


def test_exact_repeat_consolidation_retains_highest_priority():
    low = finding(1)
    high = {**finding(1, "high"), "id": "F2"}
    merged = summary.consolidate_exact_findings([low, high], id_prefix="S")
    assert len(merged) == 1
    assert merged[0]["report_priority"] == "high"
    assert len(merged[0]["evidence"]) == 1


def test_chat_reserves_all_critical_ids_before_verbose_detail():
    result = {"status": "complete_with_failures", "findings": [finding(i, "critical") for i in range(1, 9)],
              "limitations": ["SSH partial: " + "Evidence gap " * 50]}
    with reporting_scope(ReportingPolicy(detailed_findings=1, chat_chars=850)):
        text = summary.render_chat_summary(result)
    assert len(text) <= 850
    for index in range(1, 9):
        assert f"[critical] F{index}" in text
    assert "SSH partial:" in text
    assert "Shortened limitations: 1" in text
    assert "Unshown priority entries: 0 critical" in text


def test_specialized_semantic_input_cap_does_not_hide_high_findings(tmp_path):
    findings = [{"id": f"F{i}", "artifact": "Artifact", "summary": f"High item {i}", "severity": "high"}
                for i in range(205)]
    inputs = coordinator._specialized_finding_inputs(findings)
    consolidated = coordinator._deterministic_specialized_finding_summary(inputs, source_hash="test")
    state = {"findings": findings, "specialized_finding_summary": consolidated}
    before = copy.deepcopy(state)
    with reporting_scope(ReportingPolicy(detailed_findings=1)):
        text = coordinator.render_specialized_hunt_section(state, hunt_root=tmp_path)
    for item in findings:
        assert item["summary"] in text
    assert state == before


def test_followup_limit_changes_presentation_only():
    result = {"bounded_follow_up": ["First action", "Second action", "Third action"]}
    with reporting_scope(ReportingPolicy(follow_up_actions=1)):
        text = "\n".join(summary.render_follow_up(result))
    assert "First action" in text and "Second action" not in text
    assert "2 additional action(s)" in text
    assert len(result["bounded_follow_up"]) == 3


def test_low_only_chat_overflow_still_shows_findings_and_assessment():
    result = {"status": "complete", "answer": "Material investigation assessment.",
              "findings": [{"id": f"LOW{i:03}", "summary": "supported finding " + str(i) + " " + "x" * 300,
                            "report_priority": "low"} for i in range(200)],
              "limitations": ["Coverage is restricted to the selected flow."]}
    with reporting_scope(ReportingPolicy(chat_chars=32000)):
        text = summary.render_chat_summary(result)
    assert len(text) <= 32000
    assert len(text) > 20000
    assert "LOW000" in text
    assert "Material investigation assessment." in text
    assert "Coverage is restricted" in text
    assert "Unshown other entries:" in text


def test_smaller_preview_policy_applies_to_saved_compact_examples():
    result = {"findings": [finding(1)]}
    result["findings"][0]["evidence"][0]["fields"]["Command"] = "x" * 100
    compact = summary.compact_result(result)
    with reporting_scope(ReportingPolicy(preview_chars=20)):
        rerendered = summary.compact_result(compact)
    assert len(rerendered["findings"][0]["examples"][0]["fields"]["Command"]) == 20
    assert len(compact["findings"][0]["examples"][0]["fields"]["Command"]) == 100
