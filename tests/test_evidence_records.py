from __future__ import annotations

import unittest

from vraptor.analyze import records as evidence_records


class EvidenceRecordsTest(unittest.TestCase):
    def test_normalization_removes_empty_values_but_preserves_false_and_zero(self):
        normalized = evidence_records.normalized_values(
            {
                "empty": "",
                "none": None,
                "nested": {"empty": [], "value": "kept"},
                "list": ["", None, "kept"],
                "zero": 0,
                "false": False,
            }
        )

        self.assertEqual(
            normalized,
            {
                "nested": {"value": "kept"},
                "list": ["kept"],
                "zero": 0,
                "false": False,
            },
        )

    def test_exact_duplicates_collapse_with_reversible_source_ranges(self):
        accumulator = evidence_records.EvidenceAccumulator("Artifact.Test")
        row = {
            "ClientId": "C.1",
            "EventTime": "2026-07-23T00:00:00Z",
            "Message": "same evidence",
            "Empty": "",
        }
        for line in (1, 2, 3, 5):
            accumulator.add(
                row,
                partition="ClientId-C.1",
                source_file="/evidence/part-1.jsonl",
                source_line=line,
            )

        records = accumulator.records()
        metrics = accumulator.metrics()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["occurrence_count"], 4)
        self.assertEqual(
            records[0]["provenance"],
            [
                {
                    "source_file": "/evidence/part-1.jsonl",
                    "line_ranges": ["1-3", "5"],
                }
            ],
        )
        self.assertNotIn("Empty", records[0]["values"])
        self.assertEqual(metrics["raw_row_count"], 4)
        self.assertEqual(metrics["unique_evidence_count"], 1)
        self.assertEqual(metrics["duplicate_row_count"], 3)
        self.assertLess(metrics["deduplicated_tokens"], metrics["raw_tokens"])

    def test_evidence_id_is_stable_across_dictionary_order(self):
        first = evidence_records.record_content_hash(
            "Artifact.Test",
            "host-a",
            {"a": 1, "b": {"x": 2, "y": 3}},
        )
        second = evidence_records.record_content_hash(
            "Artifact.Test",
            "host-a",
            {"b": {"y": 3, "x": 2}, "a": 1},
        )

        self.assertEqual(first, second)
        self.assertEqual(
            evidence_records.evidence_id(first),
            evidence_records.evidence_id(second),
        )

    def test_partition_is_part_of_evidence_identity(self):
        values = {"Message": "same"}

        first = evidence_records.record_content_hash("Artifact.Test", "host-a", values)
        second = evidence_records.record_content_hash("Artifact.Test", "host-b", values)

        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
