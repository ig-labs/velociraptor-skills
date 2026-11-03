"""Presentation changes must not discard saved hunt priority or retained fields."""

import copy
import json

from vraptor.analyze import coordinator, reporting


def test_persisted_hunt_checkpoint_preserves_priority_and_fixed_evidence_preview(tmp_path):
    state = {
        "checkpoint": {"result": {
            "status": "complete", "priority_schema_version": 1,
            "findings": [{
                "id": "F1", "confidence": "low", "report_priority": "critical",
                "priority_rationale": "Urgent validation of potential impact.",
                "summary": "Supported observation", "domains": ["Execution"],
                "evidence": [{"ref": "S0001-R1", "fields": {"Command": "x" * 400}}],
            }, {
                "id": "F2", "confidence": "high", "report_priority": "informational",
                "priority_rationale": "Retained earlier classification.", "evidence": [],
            }],
            "relevant_context": [{"ref": "S0001-R2", "fields": {"Name": "y" * 400}}],
        }},
    }
    original = copy.deepcopy(state)
    results = []
    for limit in (8, 320, 1000):
        path = tmp_path / f"checkpoint-{limit}.json"
        with reporting.reporting_scope(reporting.ReportingPolicy(preview_chars=limit)):
            coordinator.write_state(path, copy.deepcopy(state))
        checkpoint = json.loads(path.read_text())["checkpoint"]
        results.append(checkpoint)
        assert checkpoint["result_sha256"] == coordinator._sha256_json(checkpoint["result"])
    assert results[0] == results[1] == results[2]
    result = results[0]["result"]
    assert result["priority_schema_version"] == 1
    assert result["findings"][0]["report_priority"] == "critical"
    assert result["findings"][0]["confidence"] == "low"
    assert result["findings"][0]["priority_rationale"] == "Urgent validation of potential impact."
    assert result["findings"][1]["report_priority"] == "informational"
    assert len(result["findings"][0]["evidence"][0]["fields"]["Command"]) == 320
    assert len(result["relevant_context"][0]["fields"]["Name"]) == 320
    assert state == original
