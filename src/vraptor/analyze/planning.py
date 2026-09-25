"""Review controls and token allocation for the active evidence planners."""

from __future__ import annotations

from vraptor.analyze import limits as analysis_limits


REVIEW_PLAN_VERSION = 4
REVIEW_MODES = ("exhaustive", "selective")
SNAPSHOT_OUTPUTS = ("chunks", "derived")
DEFAULT_REVIEW_MODE = "exhaustive"
DEFAULT_SNAPSHOT_OUTPUT = "chunks"
SELECTION_POLICIES = ("indicator-first", "rare-first")
DEFAULT_SELECTION_POLICY = "indicator-first"


class ReviewPlanningError(ValueError):
    """Raised when evidence cannot satisfy the configured planning policy."""


def resolve_snapshot_output(snapshot_output: str | None) -> str:
    """Return the normalized snapshot materialization mode."""
    mode = str(snapshot_output or DEFAULT_SNAPSHOT_OUTPUT).strip().casefold()
    if mode not in SNAPSHOT_OUTPUTS:
        raise ReviewPlanningError(
            f"Unknown snapshot_output {mode!r}; expected one of "
            f"{', '.join(SNAPSHOT_OUTPUTS)}."
        )
    return mode


def resolve_maximum_evidence_tokens_per_item(
    limits: analysis_limits.AnalysisLimits,
) -> int:
    """Return the validated canonical CSV evidence limit."""
    limits.validate()
    return limits.maximum_evidence_tokens_per_item


def resolve_review_options(
    *,
    review_mode: str | None = None,
    maximum_total_analysis_tokens: int | None = None,
) -> tuple[str, int | None]:
    """Normalize exhaustive or explicitly bounded selective review controls."""
    explicit_mode = str(review_mode or "").strip()
    mode = explicit_mode or DEFAULT_REVIEW_MODE
    if mode not in REVIEW_MODES:
        raise ReviewPlanningError(
            f"Unknown review_mode {mode!r}; expected one of "
            f"{', '.join(REVIEW_MODES)}."
        )
    if maximum_total_analysis_tokens is not None:
        maximum_total_analysis_tokens = int(maximum_total_analysis_tokens)
        if maximum_total_analysis_tokens <= 0:
            raise ReviewPlanningError(
                "maximum_total_analysis_tokens must be greater than zero."
            )
    if mode == "selective" and maximum_total_analysis_tokens is None:
        raise ReviewPlanningError(
            "Selective review mode requires maximum_total_analysis_tokens."
        )
    return mode, maximum_total_analysis_tokens


def allocate_token_budgets(
    demands: list[int],
    total_analysis_tokens: int,
) -> list[int]:
    """Fairly allocate an explicit selective-mode token ceiling."""
    if total_analysis_tokens <= 0:
        raise ReviewPlanningError("total_analysis_tokens must be greater than zero.")
    normalized = [max(0, int(demand)) for demand in demands]
    allocations = [0 for _ in normalized]
    remaining = min(total_analysis_tokens, sum(normalized))
    pending = {index for index, demand in enumerate(normalized) if demand > 0}
    while remaining > 0 and pending:
        share = max(1, remaining // len(pending))
        progressed = False
        for index in sorted(pending):
            unmet = normalized[index] - allocations[index]
            if unmet <= 0:
                continue
            granted = min(unmet, share, remaining)
            if granted <= 0:
                continue
            allocations[index] += granted
            remaining -= granted
            progressed = True
            if remaining == 0:
                break
        pending = {
            index
            for index in pending
            if allocations[index] < normalized[index]
        }
        if not progressed:
            break
    return allocations
