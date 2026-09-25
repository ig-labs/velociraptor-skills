"""Shared CLI arguments for artifact references and snapshot review policy."""

from __future__ import annotations

import argparse
from collections.abc import Iterable

from vraptor.analyze import limits as analysis_limits
from vraptor.common.cli_arguments import non_negative_int
from vraptor.common.cli_arguments import positive_int
from vraptor.analyze import planning as review_planning


SNAPSHOT_REVIEW_OPTIONS = frozenset(
    {
        "--analysis-route",
        "--review-term",
        "--selection-policy",
        "--review-mode",
        "--snapshot-output",
        "--max-total-analysis-tokens",
    }
)


def add_skip_ai_argument(parser: argparse.ArgumentParser) -> None:
    add_synthesis_argument(parser)
    parser.add_argument(
        "--skip-ai", action="store_true",
        help="Prepare evidence and deterministic outputs without AI review or model credentials.",
    )


def add_synthesis_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--synthesis", choices=("none", "full"), default="none",
        help="none (default) returns preliminary candidates for caller review without artifact/host/hunt AI synthesis; full explicitly requests a final assessment. Run-only.",
    )


def add_prompt_debug_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--debug-chunk-prompts", nargs="?", const=1, default=0, type=positive_int,
        metavar="N",
        help=(
            "Explicitly export up to N standard chunk prompts and their AI responses, "
            "including evidence, under the case debug/chunk-prompts directory. Flag alone "
            "saves one; omitted saves none. Separate from metadata-only --debug."
        ),
    )


def add_query_timeout_argument(parser: argparse.ArgumentParser) -> None:
    """Shared per-query ceiling for hunt and host analysis clients."""
    parser.add_argument(
        "--query-timeout-seconds", type=non_negative_int, default=0,
        help=(
            "Per-query timeout ceiling for live analysis, in seconds; 0 adds no limit "
            "(default). Includes streamed-result backpressure; does not set AI, "
            "endpoint collection, or collection polling timeouts."
        ),
    )


def add_artifact_reference_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--artifact-reference",
        action="append",
        default=[],
        help=(
            "Site or case artifact-reference JSON file or directory. Repeat "
            "to apply ordered overlays. Explicit values replace "
            "VELO_ARTIFACT_REFERENCE_PATHS."
        ),
    )


def add_scenario_reference_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scenario-reference",
        action="append",
        default=[],
        help=(
            "Site or case detection-scenario JSON file or directory. Repeat "
            "to apply ordered overlays. Explicit values replace "
            "VELO_DETECTION_SCENARIO_PATHS."
        ),
    )


def add_policy_reference_arguments(parser: argparse.ArgumentParser) -> None:
    add_artifact_reference_argument(parser)
    add_scenario_reference_argument(parser)


def add_snapshot_review_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the complete shared snapshot-review argument contract."""

    parser.add_argument(
        "--analysis-route",
        choices=analysis_limits.ANALYSIS_ROUTES,
        help="Override the artifact profile route for snapshot analysis.",
    )
    parser.add_argument(
        "--review-term",
        action="append",
        default=[],
        help=(
            "Prioritize snapshot chunks containing this literal term. "
            "Repeat as needed."
        ),
    )
    parser.add_argument(
        "--selection-policy",
        choices=review_planning.SELECTION_POLICIES,
        default=review_planning.DEFAULT_SELECTION_POLICY,
        help="Deterministic chunk selection order in selective review mode.",
    )
    parser.add_argument(
        "--review-mode",
        choices=review_planning.REVIEW_MODES,
        help=(
            "Exhaustive packages all evidence; selective applies an explicit "
            "total ceiling."
        ),
    )
    parser.add_argument(
        "--snapshot-output",
        choices=review_planning.SNAPSHOT_OUTPUTS,
        default=review_planning.DEFAULT_SNAPSHOT_OUTPUT,
        help=(
            "Chunks returns immutable snapshot package references without "
            "writing derived analysis files; derived also writes stacks, cache "
            "records, manifests, and summaries."
        ),
    )
    parser.add_argument(
        "--max-total-analysis-tokens",
        type=positive_int,
        help=(
            "Optional exhaustive-mode fail-closed ceiling, or required "
            "selective-mode total evidence ceiling."
        ),
    )


def normalize_snapshot_review_arguments(
    args: argparse.Namespace,
) -> argparse.Namespace:
    args.review_mode, args.max_total_analysis_tokens = (
        review_planning.resolve_review_options(
            review_mode=args.review_mode,
            maximum_total_analysis_tokens=args.max_total_analysis_tokens,
        )
    )
    return args


def resolve_live_review_tokens(
    value: int | None,
    limits: analysis_limits.AnalysisLimits,
) -> int:
    """Resolve an optional CLI narrowing limit against canonical policy."""

    resolved = (
        limits.maximum_evidence_tokens_per_item
        if value is None
        else int(value)
    )
    if resolved <= 0:
        raise ValueError("max_review_tokens must be greater than zero.")
    if resolved > limits.maximum_evidence_tokens_per_item:
        raise ValueError(
            "--max-review-tokens may not exceed the effective "
            "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS limit "
            f"({limits.maximum_evidence_tokens_per_item})."
        )
    return resolved


def supplied_options(
    argv: Iterable[str],
    option_names: Iterable[str],
) -> list[str]:
    tokens = tuple(str(token) for token in argv)
    return [
        option
        for option in sorted(set(option_names))
        if any(
            token == option or token.startswith(f"{option}=")
            for token in tokens
        )
    ]
