"""Offline setup hints, not a model allowlist or account pricing discovery.

The model data lives in ``resources/model-catalog.toml``. Unlisted model IDs and
deployment names are accepted; they keep saved or application budgets.
"""

import tomllib
from dataclasses import asdict, dataclass
from functools import lru_cache

from vraptor.resources import resource_root

CATALOG_PATH = resource_root() / "model-catalog.toml"

MIN_INPUT_TOKENS = 100_000
MIN_OUTPUT_TOKENS = 32_000
CLAUDE_CODE_DISABLE_1M = "CLAUDE_CODE_DISABLE_1M_CONTEXT"


@dataclass(frozen=True)
class ModelBudget:
    context_tokens: int
    standard_price_input_ceiling: int
    max_output_tokens: int
    source: str
    pricing_source: str
    checked: str
    output_budget_tokens: int | None = None
    input_budget_tokens: int | None = None
    alias_reference_model: str | None = None
    # "needs_1m_variant" or "1m_disabled" when the Claude Code window applies.
    claude_code_limit: str = ""

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


@lru_cache(maxsize=1)
def load_model_catalog() -> dict:
    with CATALOG_PATH.open("rb") as source:
        return tomllib.load(source)


def _provider(provider: str) -> dict:
    # Azure deployments may reuse an exact OpenAI model ID as their name.
    name = "openai" if provider == "azure_openai" else provider
    return load_model_catalog()["providers"].get(name, {})


def model_aliases(provider: str) -> dict[str, str]:
    return dict(_provider(provider).get("aliases", {}))


def model_examples(provider: str) -> tuple[tuple[str, str], ...]:
    return tuple(
        (item["id"], item["purpose"])
        for item in _provider(provider).get("models", ())
        if item.get("purpose")
    )


def _alias_target(entry: dict, model: str) -> str | None:
    # Alias keys are lowercase; match Opus or Sonnet[1M] as well.
    return entry.get("aliases", {}).get(model.lower())


def _effort_family(provider: str, model: str) -> dict | None:
    entry = _provider(provider)
    selected = (_alias_target(entry, model) or model).lower()
    for family in entry.get("efforts", ()):
        if selected in family.get("ids", ()) or selected.startswith(
            tuple(family.get("prefixes", ()))
        ):
            return family
    return None


def effort_levels(provider: str, model: str) -> tuple[str, ...] | None:
    """Known effort ladder; empty when the model takes none, None when unknown."""
    family = _effort_family(provider, model)
    return None if family is None else tuple(family["levels"])


def adaptive_thinking(provider: str, model: str) -> bool:
    """False only for listed models that take effort without adaptive thinking."""
    family = _effort_family(provider, model)
    return family is None or family.get("adaptive_thinking", True)


def effort_label(provider: str, model: str) -> str:
    family = _effort_family(provider, model)
    return family["label"] if family else model


def effort_summary(provider: str) -> list[str]:
    return [
        f"  {family['label']}: "
        + (", ".join(family["levels"]) or "no effort setting")
        for family in _provider(provider).get("efforts", ())
    ]


def claude_code_1m_disabled(value: object) -> bool:
    # Claude Code reads CLAUDE_CODE_DISABLE_1M_CONTEXT as 1, true, yes or on.
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def claude_code_window() -> dict:
    """Claude Code limits for any model while 1M context is disabled."""
    return dict(_provider("anthropic")["claude_code_200k"])


def model_budget(
    provider: str, model: str, protocol: str = "", *, claude_code_1m: bool = True
) -> ModelBudget | None:
    # Only exact catalog IDs and the listed aliases have offline references.
    # Never infer a model from an arbitrary deployment name or future snapshot.
    entry = _provider(provider)
    alias_target = _alias_target(entry, model)
    selected = alias_target or model
    window = entry.get("claude_code_200k", {}) if protocol == "claude_agent_sdk" else {}
    extended = bool(window) and selected.lower().endswith("[1m]")
    if extended:
        # Claude Code selects the 1M window of claude-opus-4-6[1m] and similar.
        selected = selected[: -len("[1m]")]
    for item in entry.get("models", ()):
        if selected != item["id"] and selected not in item.get("snapshots", ()):
            continue
        limit = (
            ""
            if not window or item["context_tokens"] <= window["context_tokens"]
            else "1m_disabled"
            if not claude_code_1m
            else "needs_1m_variant"
            if item.get("claude_code_1m_variant") and not extended
            else ""
        )
        limits = _windowed(item, window) if limit else item
        return ModelBudget(
            limits["context_tokens"],
            limits["standard_price_input_ceiling"],
            limits["max_output_tokens"],
            entry["source"].format(model=item["id"]),
            entry["pricing_source"].format(model=item["id"]),
            load_model_catalog()["checked"],
            output_budget_tokens=limits.get("output_budget_tokens"),
            input_budget_tokens=limits.get("input_budget_tokens"),
            alias_reference_model=alias_target,
            claude_code_limit=limit,
        )
    return None


def _windowed(item: dict, window: dict) -> dict:
    return {
        **item,
        **window,
        "standard_price_input_ceiling": min(
            item["standard_price_input_ceiling"], window["standard_price_input_ceiling"]
        ),
        # Output shares the window with at least the minimum input.
        "max_output_tokens": min(
            item["max_output_tokens"], window["context_tokens"] - MIN_INPUT_TOKENS
        ),
    }


def captured_envelopes(provider: str) -> set[tuple[int, int]]:
    """Context/output pairs that setup saves for listed models on any route."""
    entry = _provider(provider)
    window = entry.get("claude_code_200k")
    pairs = set()
    for item in entry.get("models", ()):
        variants = [item]
        if window and item["context_tokens"] > window["context_tokens"]:
            variants.append(_windowed(item, window))
        for limits in variants:
            context = limits["context_tokens"]
            pairs.add(
                (context, min(context - MIN_INPUT_TOKENS, limits["max_output_tokens"]))
            )
    return pairs
