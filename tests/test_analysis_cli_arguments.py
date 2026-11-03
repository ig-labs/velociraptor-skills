from __future__ import annotations

import argparse
import unittest

from vraptor.analyze import limits as analysis_limits
from vraptor.analyze import cli_arguments as analysis_cli_arguments


class AnalysisCliArgumentsTests(unittest.TestCase):
    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        analysis_cli_arguments.add_artifact_reference_argument(parser)
        analysis_cli_arguments.add_snapshot_review_arguments(parser)
        return parser

    def test_shared_snapshot_defaults_and_repeatable_values(self) -> None:
        args = analysis_cli_arguments.normalize_snapshot_review_arguments(
            self.parser().parse_args(
                [
                    "--artifact-reference",
                    "site.json",
                    "--artifact-reference",
                    "case.json",
                    "--review-term",
                    "one",
                    "--review-term",
                    "two",
                ]
            )
        )

        self.assertEqual(args.artifact_reference, ["site.json", "case.json"])
        self.assertEqual(args.review_term, ["one", "two"])
        self.assertEqual(args.review_mode, "exhaustive")
        self.assertEqual(args.selection_policy, "indicator-first")
        self.assertEqual(args.snapshot_output, "chunks")

    def test_total_token_limit_must_be_positive(self) -> None:
        with self.assertRaises(SystemExit):
            self.parser().parse_args(["--max-total-analysis-tokens", "0"])

    def test_live_review_limit_defaults_to_effective_policy(self) -> None:
        limits = analysis_limits.resolve_analysis_limits(
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "180000"}
        )

        self.assertEqual(
            analysis_cli_arguments.resolve_live_review_tokens(None, limits),
            180_000,
        )
        self.assertEqual(
            analysis_cli_arguments.resolve_live_review_tokens(90_000, limits),
            90_000,
        )
        with self.assertRaisesRegex(ValueError, "may not exceed"):
            analysis_cli_arguments.resolve_live_review_tokens(180_001, limits)

    def test_supplied_option_detection_supports_equals_form(self) -> None:
        self.assertEqual(
            analysis_cli_arguments.supplied_options(
                ["analyze", "--review-mode=selective"],
                analysis_cli_arguments.SNAPSHOT_REVIEW_OPTIONS,
            ),
            ["--review-mode"],
        )


if __name__ == "__main__":
    unittest.main()
