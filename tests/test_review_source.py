from __future__ import annotations

import unittest

from vraptor.hunt import live as live_hunt_analysis
from vraptor.analyze import source as review_source


class ReviewSourceTest(unittest.TestCase):
    def test_hunt_source_preserves_existing_vql_contract(self):
        source = review_source.hunt_source("H.1234", "Artifact.Test")

        self.assertEqual(source.source_type, "hunt")
        self.assertEqual(
            source.vql,
            "hunt_results(hunt_id=HuntId, artifact=ArtifactName)",
        )
        self.assertEqual(
            source.query_environment(),
            {"HuntId": "H.1234", "ArtifactName": "Artifact.Test"},
        )

    def test_flow_source_uses_bound_client_flow_and_artifact_values(self):
        source = review_source.ReviewSource(
            source_type="flow",
            source_id="C.1234:F.5678:Artifact.Test/Results",
            artifact="Artifact.Test/Results",
            vql="source(client_id=ClientId, flow_id=FlowId, artifact=ArtifactName)",
            environment={
                "ClientId": "C.1234",
                "FlowId": "F.5678",
                "ArtifactName": "Artifact.Test/Results",
            },
        )

        self.assertEqual(source.source_type, "flow")
        self.assertEqual(
            source.vql,
            "source(client_id=ClientId, flow_id=FlowId, artifact=ArtifactName)",
        )
        self.assertEqual(
            source.query_environment(),
            {
                "ClientId": "C.1234",
                "FlowId": "F.5678",
                "ArtifactName": "Artifact.Test/Results",
            },
        )

        vql = live_hunt_analysis.select_vql(
            ["Fqdn", "ClientId", "RuleID"],
            "",
            10,
            source=source,
        )
        self.assertIn("LET FlowReviewRows = SELECT *", vql)
        self.assertIn("client_info(client_id=ClientId).os_info.fqdn AS Fqdn", vql)
        self.assertIn(
            "FROM source(client_id=ClientId, flow_id=FlowId, artifact=ArtifactName)",
            vql,
        )
        self.assertIn("FROM FlowReviewRows", vql)

        residual_vql = live_hunt_analysis.autoruns_residual_stack_vql(
            "",
            source=source,
        )
        self.assertIn("LET FlowReviewRows = SELECT *", residual_vql)
        self.assertIn("FROM FlowReviewRows", residual_vql)
        self.assertNotIn("FROM hunt_results(hunt_id=HuntId", residual_vql)

    def test_autoruns_stack_uses_one_deterministic_vql_sort_key(self):
        vql = live_hunt_analysis.autoruns_residual_stack_vql("")

        self.assertIn("LET AutorunsResidualStack = SELECT", vql)
        self.assertIn("format(format='%020d|%v'", vql)
        self.assertIn("serialize(item=dict(", vql)
        self.assertEqual(
            [
                line
                for line in vql.splitlines()
                if line.startswith("ORDER BY ")
            ],
            ["ORDER BY SortKey DESC"],
        )
        self.assertNotIn("ORDER BY Total DESC,", vql)


if __name__ == "__main__":
    unittest.main()
