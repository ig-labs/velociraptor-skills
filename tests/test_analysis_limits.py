from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from types import MappingProxyType

from vraptor.analyze import limits as analysis_limits
from vraptor.paths import EnvironmentLayer
from vraptor.paths import RepositoryEnvironment


class AnalysisLimitsTests(unittest.TestCase):
    def test_code_defaults_are_valid_and_immutable(self) -> None:
        limits = analysis_limits.resolve_analysis_limits({})

        self.assertEqual(limits.model_context_tokens, 400_000)
        self.assertEqual(limits.operational_context_tokens, 360_000)
        self.assertEqual(limits.maximum_evidence_tokens_per_item, 200_000)
        self.assertEqual(limits.maximum_analysis_item_rows, 50_000)
        self.assertEqual(limits.maximum_analysis_item_bytes, 16 * 1024 * 1024)
        self.assertEqual(limits.as_dict()["schema_version"], 1)
        with self.assertRaises(FrozenInstanceError):
            limits.maximum_input_tokens = 1  # type: ignore[misc]

    def test_environment_overrides_operational_limits(self) -> None:
        limits = analysis_limits.resolve_analysis_limits(
            {
                "AI_SKILLS_CONTEXT_WINDOW_TOKENS": "390000",
                "AI_SKILLS_MAX_INPUT_TOKENS": "280000",
                "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "180000",
                "AI_SKILLS_MAX_OUTPUT_TOKENS": "70000",
                "AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "12000",
                "AI_SKILLS_MAX_ANALYSIS_ITEM_BYTES": "9000000",
                "AI_SKILLS_TOKEN_ENCODING": "o200k_base",
            }
        )

        self.assertEqual(limits.operational_context_tokens, 390_000)
        self.assertEqual(limits.maximum_input_tokens, 280_000)
        self.assertEqual(limits.maximum_evidence_tokens_per_item, 180_000)
        self.assertEqual(limits.maximum_output_tokens, 70_000)
        self.assertEqual(limits.maximum_analysis_item_rows, 12_000)
        self.assertEqual(limits.maximum_analysis_item_bytes, 9_000_000)
        self.assertEqual(
            limits.provenance_dict()["maximum_analysis_item_rows"],
            {
                "kind": "environment",
                "name": "AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS",
                "location": "",
                "explicit": True,
            },
        )

    def test_default_provenance_names_code_constant(self) -> None:
        limits = analysis_limits.resolve_analysis_limits({})

        self.assertEqual(
            limits.provenance_dict()["maximum_output_tokens"],
            {
                "kind": "application_default",
                "name": "DEFAULT_MAXIMUM_OUTPUT_TOKENS",
                "location": "",
                "explicit": False,
            },
        )
        self.assertEqual(
            limits.public_dict()["identity"],
            limits.identity(),
        )

    def test_environment_layers_preserve_precedence_and_provenance(self) -> None:
        layers = RepositoryEnvironment(
            process=EnvironmentLayer(
                kind="process_environment",
                location="process",
                values=MappingProxyType(
                    {"AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "9000"}
                ),
            ),
            repository=EnvironmentLayer(
                kind="repository_dotenv",
                location="/repo/.env",
                values=MappingProxyType(
                    {
                        "AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "8000",
                        "AI_SKILLS_MAX_ANALYSIS_ITEM_BYTES": "7000000",
                    }
                ),
            ),
            shared=EnvironmentLayer(
                kind="shared_dotenv",
                location="/home/.codex/.env",
                values=MappingProxyType(
                    {
                        "AI_SKILLS_MAX_ANALYSIS_ITEM_BYTES": "6000000",
                        "AI_SKILLS_TOKEN_ENCODING": "o200k_base",
                    }
                ),
            ),
        )

        limits = analysis_limits.resolve_analysis_limits(
            environment_layers=layers
        )

        self.assertEqual(limits.maximum_analysis_item_rows, 9000)
        self.assertEqual(limits.maximum_analysis_item_bytes, 7_000_000)
        self.assertEqual(
            limits.provenance_dict()["maximum_analysis_item_rows"]["kind"],
            "process_environment",
        )
        self.assertEqual(
            limits.provenance_dict()["maximum_analysis_item_bytes"],
            {
                "kind": "repository_dotenv",
                "name": "AI_SKILLS_MAX_ANALYSIS_ITEM_BYTES",
                "location": "/repo/.env",
                "explicit": True,
            },
        )

    def test_invalid_environment_values_fail_closed(self) -> None:
        for value in ("0", "-1", "not-an-integer"):
            with self.subTest(value=value), self.assertRaises(
                analysis_limits.AnalysisLimitsError
            ):
                analysis_limits.resolve_analysis_limits(
                    {"AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": value}
                )

    def test_inconsistent_token_envelope_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            analysis_limits.AnalysisLimitsError,
            "fixed input reserves",
        ):
            analysis_limits.resolve_analysis_limits(
                {
                    "AI_SKILLS_MAX_INPUT_TOKENS": "250000",
                    "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": "200000",
                }
            )

    def test_route_to_task_mapping_is_code_owned(self) -> None:
        self.assertEqual(
            analysis_limits.ANALYSIS_ROUTES,
            ("high-volume", "reasoning", "synthesis"),
        )
        self.assertEqual(
            analysis_limits.analysis_routing("reasoning"),
            {"route": "reasoning", "task": "correlation"},
        )
        with self.assertRaises(analysis_limits.AnalysisLimitsError):
            analysis_limits.analysis_routing("compact-review")

        self.assertEqual(
            analysis_limits.stage_routing("chunk"),
            {"route": "high-volume", "task": "extraction"},
        )
        self.assertEqual(
            analysis_limits.stage_routing("host-synthesis"),
            {"route": "synthesis", "task": "investigation_synthesis"},
        )
        with self.assertRaises(analysis_limits.AnalysisLimitsError):
            analysis_limits.stage_routing("unknown-stage")

    def test_empty_environment_values_do_not_mask_defaults(self) -> None:
        limits = analysis_limits.resolve_analysis_limits(
            {
                "AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "",
                "AI_SKILLS_TOKEN_ENCODING": "",
            }
        )

        self.assertEqual(limits.maximum_analysis_item_rows, 50_000)
        self.assertEqual(limits.token_encoding, "o200k_base")

    def test_identity_changes_with_operational_limit(self) -> None:
        first = analysis_limits.resolve_analysis_limits({})
        second = analysis_limits.resolve_analysis_limits(
            {"AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "49999"}
        )
        self.assertNotEqual(first.identity(), second.identity())


if __name__ == "__main__":
    unittest.main()
