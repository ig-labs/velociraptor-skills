from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vraptor.analyze import detached as detached_evidence


class DetachedEvidenceManifestTest(unittest.TestCase):
    def test_contract_defines_shared_workflows_and_policy(self):
        contract = detached_evidence.load_contract()

        self.assertEqual(
            contract["workflows"],
            ["dfir-data-stacking", "dfir-log-chunker"],
        )
        self.assertEqual(
            contract["required_policy"],
            {
                "rarity_is_malicious": False,
                "reduced_output_is_raw_evidence_copy": False,
            },
        )
        self.assertIn("duplicate_reference_count", contract["required_coverage_keys"])

    def test_build_write_and_validate_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_path = root / "source.jsonl"
            output_path = root / "stack.json"
            manifest_path = root / "stack.manifest.json"
            source_path.write_text('{"event":"one"}\n', encoding="utf-8")
            output_path.write_text('{"groups":[]}\n', encoding="utf-8")

            manifest = detached_evidence.build_manifest(
                workflow="dfir-data-stacking",
                question="Which events are present?",
                source=detached_evidence.source_record(
                    path=str(source_path),
                    sha256=detached_evidence.sha256_file(source_path),
                    size_bytes=source_path.stat().st_size,
                    input_format="jsonl",
                    system="SIEM",
                    acquisition_context="Sanitized export",
                ),
                scope={
                    "filters": ["event.category=process"],
                    "projection": "event,host",
                    "time_bounds": {"after": "", "before": ""},
                },
                reduction={"operation": "prevalence-stack"},
                coverage={
                    "state": "filtered",
                    "source_record_count": 1,
                    "processed_record_count": 1,
                    "omitted_record_count": 0,
                    "duplicate_reference_count": 0,
                    "closure_eligible": True,
                    "limitations": [],
                },
                outputs=[
                    detached_evidence.output_record(
                        output_path,
                        role="stack-json",
                        record_count=0,
                    )
                ],
                source_references={"method": "source-row"},
            )
            detached_evidence.write_manifest(manifest_path, manifest)
            rendered = json.loads(manifest_path.read_text(encoding="utf-8"))

        detached_evidence.validate_manifest(rendered)
        self.assertRegex(rendered["handoff_id"], r"^[0-9a-f]{64}$")

    def test_invalid_policy_and_closure_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_path = root / "source.txt"
            output_path = root / "chunk.txt"
            source_path.write_text("one\n", encoding="utf-8")
            output_path.write_text("one\n", encoding="utf-8")
            manifest = detached_evidence.build_manifest(
                workflow="dfir-log-chunker",
                question="Which line needs review?",
                source=detached_evidence.source_record(
                    path=str(source_path),
                    sha256=detached_evidence.sha256_file(source_path),
                    size_bytes=source_path.stat().st_size,
                    input_format="text",
                    system="application",
                    acquisition_context="Rotated log copy",
                ),
                scope={},
                reduction={"operation": "chunk"},
                coverage={
                    "state": "exhaustive",
                    "source_record_count": 1,
                    "processed_record_count": 1,
                    "omitted_record_count": 0,
                    "duplicate_reference_count": 0,
                    "closure_eligible": True,
                    "limitations": [],
                },
                outputs=[
                    detached_evidence.output_record(
                        output_path,
                        role="text-chunk",
                        record_count=1,
                    )
                ],
                source_references={"source_units": ["1:1"]},
            )

        invalid_policy = json.loads(json.dumps(manifest))
        invalid_policy["policy"]["rarity_is_malicious"] = True
        invalid_policy["handoff_id"] = detached_evidence.manifest_identity(
            invalid_policy
        )
        with self.assertRaisesRegex(
            detached_evidence.DetachedEvidenceError,
            "policy",
        ):
            detached_evidence.validate_manifest(invalid_policy)

        invalid_coverage = json.loads(json.dumps(manifest))
        invalid_coverage["coverage"]["state"] = "sampled"
        invalid_coverage["handoff_id"] = detached_evidence.manifest_identity(
            invalid_coverage
        )
        with self.assertRaisesRegex(
            detached_evidence.DetachedEvidenceError,
            "closure eligible",
        ):
            detached_evidence.validate_manifest(invalid_coverage)

if __name__ == "__main__":
    unittest.main()
