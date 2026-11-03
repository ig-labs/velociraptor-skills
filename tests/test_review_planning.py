from __future__ import annotations

import unittest

from vraptor.analyze import planning as review_planning


class ReviewPlanningTest(unittest.TestCase):
    def test_global_budget_allocation_is_fair_and_reuses_spare_capacity(self):
        allocations = review_planning.allocate_token_budgets(
            [10, 100, 100],
            100,
        )

        self.assertEqual(allocations[0], 10)
        self.assertEqual(sum(allocations), 100)
        self.assertEqual(allocations[1:], [45, 45])

    def test_selective_review_uses_explicit_total_ceiling(self):
        mode, ceiling = review_planning.resolve_review_options(
            review_mode="selective",
            maximum_total_analysis_tokens=1234,
        )

        self.assertEqual(mode, "selective")
        self.assertEqual(ceiling, 1234)

    def test_default_snapshot_output_is_chunks(self):
        self.assertEqual(
            review_planning.resolve_snapshot_output(None),
            "chunks",
        )
        self.assertEqual(
            review_planning.resolve_snapshot_output("DERIVED"),
            "derived",
        )

    def test_selective_options_require_explicit_total_ceiling(self):
        with self.assertRaisesRegex(
            review_planning.ReviewPlanningError,
            "requires maximum_total_analysis_tokens",
        ):
            review_planning.resolve_review_options(review_mode="selective")


if __name__ == "__main__":
    unittest.main()
