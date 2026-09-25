"""Offline setup hints, not a model allowlist or account pricing discovery."""

from dataclasses import asdict, dataclass, replace

# Dated references for the default Anthropic-hosted Claude Code aliases. Keep
# execution aliases unchanged; these are planning limits, not live discovery.
CLAUDE_ALIAS_MODELS = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-5",
    "opus": "claude-opus-5-5",
    "fable": "claude-fable-5-1",
}


MIN_INPUT_TOKENS = 100_000
MIN_OUTPUT_TOKENS = 32_000


@dataclass(frozen=True)
class ModelBudget:
    context_tokens: int
    standard_price_input_ceiling: int
    max_output_tokens: int
    source: str
    pricing_source: str
    checked: str = "2026-09-23"
    output_budget_tokens: int | None = None
    input_budget_tokens: int | None = None
    alias_reference_model: str | None = None

    @property
    def default_output_tokens(self) -> int:
        return self.output_budget_tokens or self.max_output_tokens

    @property
    def max_input_tokens(self) -> int:
        return min(
            self.standard_price_input_ceiling,
            self.context_tokens - self.default_output_tokens,
        )

    @property
    def default_input_tokens(self) -> int:
        return min(
            self.input_budget_tokens or self.max_input_tokens, self.max_input_tokens
        )

    def public_dict(self) -> dict:
        return {
            **asdict(self),
            "max_input_tokens": self.max_input_tokens,
            "default_output_tokens": self.default_output_tokens,
            "default_input_tokens": self.default_input_tokens,
        }


def model_budget(provider: str, model: str) -> ModelBudget | None:
    # Only documented default Claude aliases have offline references. Never
    # infer a model from an arbitrary deployment name or future snapshot.
    if provider == "anthropic" and model in CLAUDE_ALIAS_MODELS:
        target = CLAUDE_ALIAS_MODELS[model]
        return replace(
            model_budget(provider, target),
            alias_reference_model=target,
            checked="2026-09-24",
        )
    if provider in {"openai", "azure_openai"} and model in {
        "gpt-6-astra",
        "gpt-6-sol",
        "gpt-6-luna",
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    }:
        source = f"https://developers.openai.com/api/docs/models/{model}"
        return ModelBudget(1_050_000, 272_000, 128_000, source, source)
    if provider == "anthropic":
        source = "https://platform.claude.com/docs/en/models/overview"
        pricing = "https://platform.claude.com/docs/en/about-claude/pricing"
        if model in {"claude-sonnet-5", "claude-opus-5-5", "claude-fable-5-1"}:
            return ModelBudget(1_000_000, 1_000_000, 128_000, source, pricing)
        if model in {"claude-haiku-4-5-20251001", "claude-haiku-4-5"}:
            return ModelBudget(
                200_000,
                200_000,
                64_000,
                source,
                pricing,
                input_budget_tokens=120_000,
            )
    return None
