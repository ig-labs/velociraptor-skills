from __future__ import annotations

import unittest

from vraptor.analyze import references as evidence_references


def source(source_id: str, component: str) -> dict:
    return {
        "source_id": source_id,
        "scope_type": "hunt",
        "scope_id": "H.1",
        "org_id": "root",
        "client_id": "C.1",
        "flow_id": "F.1",
        "artifact": "Artifact.Multi",
        "source": component,
    }


class EvidenceReferencesTest(unittest.TestCase):
    def test_reference_requires_source_alias_and_positive_source_row(self):
        self.assertEqual(
            evidence_references.format_source_reference("S0003", 1004),
            "S0003-R1004",
        )
        self.assertEqual(
            evidence_references.parse_source_reference("S0003-R1004"),
            ("S0003", 1004),
        )
        for invalid in ("R1004", "S0000-R1", "S0003-R0", "S3-R1004"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                evidence_references.parse_source_reference(invalid)

    def test_source_identity_separates_result_components_and_scopes(self):
        base = {
            "scope_type": "hunt",
            "scope_id": "H.1",
            "org_id": "root",
            "client_id": "C.1",
            "flow_id": "F.1",
            "artifact": "Artifact.Multi",
        }
        first = evidence_references.evidence_source_id(
            **base,
            source="Artifact.Multi/First",
        )
        second = evidence_references.evidence_source_id(
            **base,
            source="Artifact.Multi/Second",
        )
        other_scope = evidence_references.evidence_source_id(
            **{**base, "scope_id": "H.2"},
            source="Artifact.Multi/First",
        )

        self.assertNotEqual(first, second)
        self.assertNotEqual(first, other_scope)

    def test_aliases_are_monotonic_and_stable_when_sources_are_added(self):
        initial = evidence_references.ensure_source_aliases(
            None,
            [source("source-b", "Second"), source("source-a", "First")],
        )
        self.assertEqual(initial["source-a"]["alias"], "S0001")
        self.assertEqual(initial["source-b"]["alias"], "S0002")

        resumed = evidence_references.ensure_source_aliases(
            initial,
            [
                source("source-0", "New"),
                source("source-a", "First"),
                source("source-b", "Second"),
            ],
        )

        self.assertEqual(resumed["source-a"]["alias"], "S0001")
        self.assertEqual(resumed["source-b"]["alias"], "S0002")
        self.assertEqual(resumed["source-0"]["alias"], "S0003")


if __name__ == "__main__":
    unittest.main()
