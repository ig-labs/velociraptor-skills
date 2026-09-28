from __future__ import annotations

import unittest

from vraptor.analyze import line_protocol as analyst_line_protocol
from vraptor.analyze import coordinator as flow_analysis_coordinator


class AnalystLineProtocolTest(unittest.TestCase):
    def test_tab_records_accepts_compact_records_and_exact_end(self):
        records = analyst_line_protocol.tab_records(
            "FLAG\t17\tnotable\tlow\treview source rows\nEND",
            output_name="test output",
            allowed_records={"FLAG"},
        )

        self.assertEqual(records[0][0], 1)
        self.assertEqual(records[0][1][1], "17")

    def test_tab_records_preserves_tabs_in_declared_final_text_field(self):
        records = analyst_line_protocol.tab_records(
            "FLAG\t17\tnotable\tlow\treview\tsource rows\nEND",
            output_name="test output",
            allowed_records={"FLAG"},
            trailing_text_fields={"FLAG": 4},
        )

        self.assertEqual(
            records[0][1],
            ["FLAG", "17", "notable", "low", "review\tsource rows"],
        )

    def test_rejects_json_markdown_metadata_and_unknown_records(self):
        cases = (
            ('{"flagged":[]}', "model-generated JSON"),
            ("```text\nEND\n```", "Markdown fences"),
            ("Skills used: none\nEND", "forbidden agent metadata"),
            ("UNKNOWN\tvalue\nEND", "unsupported record"),
        )
        for output, message in cases:
            with self.subTest(output=output), self.assertRaisesRegex(
                analyst_line_protocol.LineProtocolError,
                message,
            ):
                analyst_line_protocol.tab_records(
                    output,
                    output_name="test output",
                    allowed_records={"FLAG"},
                )

    def test_rejects_missing_or_early_end(self):
        for output, message in (
            ("FLAG\t1", "missing the END marker"),
            ("END\nFLAG\t1\nEND", "content after END"),
        ):
            with self.subTest(output=output), self.assertRaisesRegex(
                analyst_line_protocol.LineProtocolError,
                message,
            ):
                analyst_line_protocol.strict_lines(
                    output,
                    output_name="test output",
                )

    def test_specialized_manager_requires_exact_source_coverage(self):
        groups = flow_analysis_coordinator._parse_specialized_finding_output(
            "GROUP\tG1\tRelated\tpersistence\n"
            "SOURCE\tG1\tS1\nSOURCE\tG1\tS2\nEND",
            source_ids={"S1", "S2"},
        )
        self.assertEqual(groups[0]["summary"], "Related persistence")
        self.assertEqual(groups[0]["source_ids"], ["S1", "S2"])

        with self.assertRaisesRegex(ValueError, "cover every source_id"):
            flow_analysis_coordinator._parse_specialized_finding_output(
                "GROUP\tG1\tRelated persistence\nSOURCE\tG1\tS1\nEND",
                source_ids={"S1", "S2"},
            )


if __name__ == "__main__":
    unittest.main()
