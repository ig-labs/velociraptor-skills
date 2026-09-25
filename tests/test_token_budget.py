from __future__ import annotations

import os
import unittest
from unittest import mock

from vraptor.common import token_budget


class TokenBudgetTest(unittest.TestCase):
    def test_estimate_tokens_and_name(self):
        self.assertEqual(token_budget.estimate_tokens(""), 0)
        self.assertGreater(token_budget.estimate_tokens("evidence"), 0)
        self.assertEqual(
            token_budget.token_estimator_name(),
            f"tiktoken:{token_budget.token_encoding_name()}",
        )
        self.assertEqual(
            token_budget.token_estimator_name("cl100k_base"),
            "tiktoken:cl100k_base",
        )
        self.assertGreater(
            token_budget.estimate_tokens("evidence", "cl100k_base"),
            0,
        )

    def test_split_text_chunks_preserves_unicode_and_budget(self):
        text = "host=alpha\nPowerShell café 🚨\n" + ("x" * 80)

        chunks = token_budget.split_text_chunks(text, 5)

        self.assertEqual("".join(chunks), text)
        self.assertTrue(chunks)
        self.assertTrue(
            all(token_budget.estimate_tokens(chunk) <= 5 for chunk in chunks)
        )

    def test_oversized_split_preserves_utf8_boundaries(self):
        text = ("évidence-🚨-" * 40) + "done"

        chunks = token_budget.split_oversized_text_by_token_budget(text, 4)

        self.assertEqual("".join(chunks), text)
        self.assertTrue(
            all(token_budget.estimate_tokens(chunk) <= 4 for chunk in chunks)
        )

    def test_split_prefers_whole_lines(self):
        text = "alpha\nbeta\ngamma\n"

        chunks = token_budget.split_text_chunks(text, 2)

        self.assertEqual(chunks, ["alpha\n", "beta\n", "gamma\n"])

    def test_invalid_limit_fails_closed(self):
        with self.assertRaises(token_budget.TokenBudgetError):
            token_budget.split_text_chunks("evidence", 0)

    def test_optional_budget_environment_returns_none_when_unset(self):
        with mock.patch.dict(
            os.environ,
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": ""},
        ):
            self.assertIsNone(
                token_budget.configured_optional_positive_int(
                    "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS"
                )
            )

    def test_analysis_item_precedence_is_explicit_canonical_default(self):
        with mock.patch.dict(
            os.environ,
            {
                "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "3000",
            },
            clear=False,
        ):
            self.assertEqual(
                token_budget.configured_analysis_item_tokens(
                    1000,
                    explicit=4000,
                ),
                4000,
            )
            self.assertEqual(
                token_budget.configured_analysis_item_tokens(1000),
                3000,
            )
        with mock.patch.dict(
            os.environ,
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": ""},
            clear=False,
        ):
            self.assertEqual(token_budget.configured_analysis_item_tokens(1000), 1000)

    def test_explicit_analysis_item_bypasses_invalid_environment(self):
        with mock.patch.dict(
            os.environ,
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "invalid"},
            clear=False,
        ):
            self.assertEqual(
                token_budget.configured_analysis_item_tokens(
                    1000,
                    explicit=1500,
                ),
                1500,
            )


if __name__ == "__main__":
    unittest.main()
