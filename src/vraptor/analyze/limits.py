"""Canonical immutable limits and route semantics for DFIR analysis."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from vraptor.agent.config import REPO_ROOT
from vraptor.agent.runtime import AgentRuntimeLimits
from vraptor.common import token_budget
from vraptor.paths import RepositoryEnvironment, repository_environment

ANALYSIS_LIMITS_SCHEMA_VERSION = 1
MODEL_CONTEXT_TOKENS = 400_000
DEFAULT_OPERATIONAL_CONTEXT_TOKENS = 360_000
DEFAULT_MAXIMUM_INPUT_TOKENS = 272_000
DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM = 200_000
DEFAULT_MAXIMUM_OUTPUT_TOKENS = 64_000
DEFAULT_MAXIMUM_ANALYSIS_ITEM_ROWS = 50_000
DEFAULT_MAXIMUM_ANALYSIS_ITEM_BYTES = 16 * 1024 * 1024
DEFAULT_VALIDATION_CORRECTION_ATTEMPTS = 2
DEFAULT_SYNTHESIS_CORRECTION_ATTEMPTS = 2
MAX_CORRECTION_ATTEMPTS = 5

INSTRUCTION_RESERVE_TOKENS = 12_000
PRIOR_CONTEXT_RESERVE_TOKENS = 30_000
SAFETY_RESERVE_TOKENS = 20_000

DEFAULT_ANALYSIS_ROUTE = "high-volume"
ANALYSIS_TASK_BY_ROUTE = MappingProxyType(
    {
        "high-volume": "extraction",
        "reasoning": "correlation",
        "synthesis": "investigation_synthesis",
    }
)
ANALYSIS_ROUTES = tuple(ANALYSIS_TASK_BY_ROUTE)
ANALYSIS_ROUTE_BY_STAGE = MappingProxyType(
    {
        "chunk": "high-volume",
        "artifact-synthesis": "reasoning",
        "specialized-finding-consolidation": "reasoning",
        "host-synthesis": "synthesis",
        "hunt-synthesis": "synthesis",
    }
)

INTEGER_ENVIRONMENT_FIELDS = MappingProxyType(
    {
        "AI_SKILLS_CONTEXT_WINDOW_TOKENS": "operational_context_tokens",
        "AI_SKILLS_MAX_INPUT_TOKENS": "maximum_input_tokens",
        "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS": ("maximum_evidence_tokens_per_item"),
        "AI_SKILLS_MAX_OUTPUT_TOKENS": "maximum_output_tokens",
        "AI_SKILLS_MAX_ANALYSIS_ITEM_ROWS": "maximum_analysis_item_rows",
        "AI_SKILLS_MAX_ANALYSIS_ITEM_BYTES": "maximum_analysis_item_bytes",
        "AI_SKILLS_ANALYST_AGENT_VALIDATION_CORRECTION_ATTEMPTS": "validation_correction_attempts",
        "AI_SKILLS_ANALYST_AGENT_SYNTHESIS_CORRECTION_ATTEMPTS": "synthesis_correction_attempts",
    }
)
TOKEN_ENCODING_ENVIRONMENT = "AI_SKILLS_TOKEN_ENCODING"
TOML_FIELDS = MappingProxyType(
    {
        "context_window_tokens": "operational_context_tokens",
        "max_input_tokens": "maximum_input_tokens",
        "token_encoding": "token_encoding",
        "max_analysis_item_tokens": "maximum_evidence_tokens_per_item",
        "max_output_tokens": "maximum_output_tokens",
        "validation_correction_attempts": "validation_correction_attempts",
        "synthesis_correction_attempts": "synthesis_correction_attempts",
    }
)


def default_analysis_settings() -> dict[str, Any]:
    """Return the shared settings written by setup from canonical code defaults."""
    defaults = AnalysisLimits()
    return {name: getattr(defaults, field) for name, field in TOML_FIELDS.items()}


def derive_profile_budgets(
    input_tokens: int, output_tokens: int, evidence_ceiling: int
) -> dict[str, int]:
    """Reserve prompt overhead and derive a bounded evidence budget from a pair."""
    input_tokens = _positive_int(input_tokens, "max_input_tokens")
    output_tokens = _positive_int(output_tokens, "max_output_tokens")
    reserves = {
        "instruction_reserve_tokens": min(
            INSTRUCTION_RESERVE_TOKENS, input_tokens // 10
        ),
        "prior_context_reserve_tokens": min(
            PRIOR_CONTEXT_RESERVE_TOKENS, input_tokens // 10
        ),
        "safety_reserve_tokens": min(SAFETY_RESERVE_TOKENS, input_tokens // 10),
    }
    return {
        "operational_context_tokens": input_tokens + output_tokens,
        "maximum_evidence_tokens_per_item": min(
            evidence_ceiling, input_tokens - sum(reserves.values())
        ),
        **reserves,
    }


_DEFAULT_CONSTANT_BY_FIELD = MappingProxyType(
    {
        "model_context_tokens": "MODEL_CONTEXT_TOKENS",
        "operational_context_tokens": "DEFAULT_OPERATIONAL_CONTEXT_TOKENS",
        "maximum_input_tokens": "DEFAULT_MAXIMUM_INPUT_TOKENS",
        "maximum_evidence_tokens_per_item": (
            "DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM"
        ),
        "maximum_output_tokens": "DEFAULT_MAXIMUM_OUTPUT_TOKENS",
        "maximum_analysis_item_rows": "DEFAULT_MAXIMUM_ANALYSIS_ITEM_ROWS",
        "maximum_analysis_item_bytes": "DEFAULT_MAXIMUM_ANALYSIS_ITEM_BYTES",
        "validation_correction_attempts": "DEFAULT_VALIDATION_CORRECTION_ATTEMPTS",
        "synthesis_correction_attempts": "DEFAULT_SYNTHESIS_CORRECTION_ATTEMPTS",
        "token_encoding": "token_budget.DEFAULT_ENCODING_NAME",
        "instruction_reserve_tokens": "INSTRUCTION_RESERVE_TOKENS",
        "prior_context_reserve_tokens": "PRIOR_CONTEXT_RESERVE_TOKENS",
        "safety_reserve_tokens": "SAFETY_RESERVE_TOKENS",
    }
)


class AnalysisLimitsError(ValueError):
    """Raised when analysis limits or routing are invalid."""


@dataclass(frozen=True, slots=True)
class LimitSource:
    """Safe source provenance for one effective analysis-limit value."""

    kind: str
    name: str
    location: str = ""
    explicit: bool = False

    def public_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "location": self.location,
            "explicit": self.explicit,
        }


def _empty_sources() -> Mapping[str, LimitSource]:
    return MappingProxyType({})


def _positive_int(value: Any, description: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisLimitsError(f"{description} must be an integer.") from exc
    if parsed <= 0:
        raise AnalysisLimitsError(f"{description} must be greater than zero.")
    return parsed


def correction_attempts(value: Any) -> int:
    """A bounded number of extra semantic attempts, separate from transport retries."""
    if (
        isinstance(value, bool)
        or not str(value).isdigit()
        or not 0 <= int(value) <= MAX_CORRECTION_ATTEMPTS
    ):
        raise AnalysisLimitsError("correction_attempts must be an integer from 0 to 5.")
    return int(value)


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    """One operation's fully resolved analysis limits and safe provenance."""

    model_context_tokens: int = MODEL_CONTEXT_TOKENS
    operational_context_tokens: int = DEFAULT_OPERATIONAL_CONTEXT_TOKENS
    maximum_input_tokens: int = DEFAULT_MAXIMUM_INPUT_TOKENS
    maximum_evidence_tokens_per_item: int = DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM
    maximum_output_tokens: int = DEFAULT_MAXIMUM_OUTPUT_TOKENS
    maximum_analysis_item_rows: int = DEFAULT_MAXIMUM_ANALYSIS_ITEM_ROWS
    maximum_analysis_item_bytes: int = DEFAULT_MAXIMUM_ANALYSIS_ITEM_BYTES
    validation_correction_attempts: int = DEFAULT_VALIDATION_CORRECTION_ATTEMPTS
    synthesis_correction_attempts: int = DEFAULT_SYNTHESIS_CORRECTION_ATTEMPTS
    token_encoding: str = token_budget.DEFAULT_ENCODING_NAME
    instruction_reserve_tokens: int = INSTRUCTION_RESERVE_TOKENS
    prior_context_reserve_tokens: int = PRIOR_CONTEXT_RESERVE_TOKENS
    safety_reserve_tokens: int = SAFETY_RESERVE_TOKENS
    field_sources: Mapping[str, LimitSource] = field(
        default_factory=_empty_sources,
        repr=False,
        compare=False,
    )

    def validate(self) -> None:
        correction_attempts(self.validation_correction_attempts)
        correction_attempts(self.synthesis_correction_attempts)
        for name in (
            "model_context_tokens",
            "operational_context_tokens",
            "maximum_input_tokens",
            "maximum_evidence_tokens_per_item",
            "maximum_output_tokens",
            "maximum_analysis_item_rows",
            "maximum_analysis_item_bytes",
            "instruction_reserve_tokens",
            "prior_context_reserve_tokens",
            "safety_reserve_tokens",
        ):
            _positive_int(getattr(self, name), name)
        if self.operational_context_tokens > self.model_context_tokens:
            raise AnalysisLimitsError(
                "operational_context_tokens cannot exceed model_context_tokens."
            )
        if (
            self.maximum_input_tokens + self.maximum_output_tokens
            > self.operational_context_tokens
        ):
            raise AnalysisLimitsError(
                "Maximum input and output tokens exceed operational_context_tokens."
            )
        reserved_input = (
            self.maximum_evidence_tokens_per_item
            + self.instruction_reserve_tokens
            + self.prior_context_reserve_tokens
            + self.safety_reserve_tokens
        )
        if reserved_input > self.maximum_input_tokens:
            raise AnalysisLimitsError(
                "Evidence and fixed input reserves exceed maximum_input_tokens."
            )
        if not self.token_encoding.strip():
            raise AnalysisLimitsError("token_encoding must not be empty.")
        try:
            if self.token_encoding not in token_budget.tiktoken.list_encoding_names():
                raise ValueError(self.token_encoding)
        except Exception as exc:
            raise AnalysisLimitsError(
                f"Unknown token_encoding {self.token_encoding!r}."
            ) from exc

    @property
    def maximum_safe_evidence_tokens(self) -> int:
        return self.maximum_input_tokens - (
            self.instruction_reserve_tokens
            + self.prior_context_reserve_tokens
            + self.safety_reserve_tokens
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_context_tokens": self.model_context_tokens,
            "operational_context_tokens": self.operational_context_tokens,
            "maximum_input_tokens": self.maximum_input_tokens,
            "maximum_evidence_tokens_per_item": (self.maximum_evidence_tokens_per_item),
            "maximum_output_tokens": self.maximum_output_tokens,
            "maximum_analysis_item_rows": self.maximum_analysis_item_rows,
            "maximum_analysis_item_bytes": self.maximum_analysis_item_bytes,
            "validation_correction_attempts": self.validation_correction_attempts,
            "synthesis_correction_attempts": self.synthesis_correction_attempts,
            "token_encoding": self.token_encoding,
            "schema_version": ANALYSIS_LIMITS_SCHEMA_VERSION,
            "instruction_reserve_tokens": self.instruction_reserve_tokens,
            "prior_context_reserve_tokens": self.prior_context_reserve_tokens,
            "safety_reserve_tokens": self.safety_reserve_tokens,
        }

    def provenance_dict(self) -> dict[str, dict[str, Any]]:
        output: dict[str, dict[str, Any]] = {}
        for field_name, constant_name in _DEFAULT_CONSTANT_BY_FIELD.items():
            source = self.field_sources.get(field_name)
            if source is None:
                source = LimitSource(
                    kind="application_default",
                    name=constant_name,
                )
            output[field_name] = source.public_dict()
        return output

    def public_dict(self) -> dict[str, Any]:
        return {
            "effective": self.as_dict(),
            "sources": self.provenance_dict(),
            "identity": self.identity(),
        }

    def identity(self) -> str:
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def runtime_limits(self) -> AgentRuntimeLimits:
        return AgentRuntimeLimits(
            model_context_tokens=self.model_context_tokens,
            operational_context_tokens=self.operational_context_tokens,
            maximum_input_tokens=self.maximum_input_tokens,
            maximum_output_tokens=self.maximum_output_tokens,
            token_encoding=self.token_encoding,
        )

    def for_execution(self, execution) -> AnalysisLimits:
        """Tighten the shared envelope to the operator's model/deployment limits.

        Input/output share the declared context. Instruction, prior-context and
        safety reserves are already accounted for inside the input budget.
        """
        route = execution.route
        context = route.model_context_tokens or self.model_context_tokens
        if not route.model_context_tokens and not route.model_max_output_tokens:
            return self
        if context < 1024:
            raise AnalysisLimitsError(
                "Analyst model context must be at least 1024 tokens"
            )
        operational = min(self.operational_context_tokens, context)
        output = min(
            self.maximum_output_tokens,
            route.model_max_output_tokens
            or (self.maximum_output_tokens if route.analysis_profile else 4096),
            # Preserve the configured output share when a smaller model reduces
            # context, keeping usable input space even without an output ceiling.
            max(
                1,
                self.maximum_output_tokens
                * operational
                // self.operational_context_tokens,
            )
            if route.analysis_profile
            else operational // 4,
        )
        maximum_input = min(self.maximum_input_tokens, operational - output)
        instruction = min(self.instruction_reserve_tokens, maximum_input // 10)
        prior = min(self.prior_context_reserve_tokens, maximum_input // 10)
        safety = min(self.safety_reserve_tokens, maximum_input // 10)
        values = {
            "model_context_tokens": context,
            "operational_context_tokens": operational,
            "maximum_input_tokens": maximum_input,
            "maximum_output_tokens": output,
            "maximum_evidence_tokens_per_item": min(
                self.maximum_evidence_tokens_per_item,
                maximum_input - instruction - prior - safety,
            ),
            "instruction_reserve_tokens": instruction,
            "prior_context_reserve_tokens": prior,
            "safety_reserve_tokens": safety,
        }
        sources = dict(self.field_sources)
        for name, value in values.items():
            if value != getattr(self, name):
                sources[name] = LimitSource(
                    kind="model_envelope",
                    name=name,
                    location=route.config_file,
                    explicit=True,
                )
        result = replace(self, **values, field_sources=MappingProxyType(sources))
        result.validate()
        return result


def resolve_analysis_limits(
    environment: Mapping[str, str] | None = None,
    *,
    environment_layers: RepositoryEnvironment | None = None,
    execution: Any | None = None,
    validate: bool = True,
) -> AnalysisLimits:
    """Resolve CLI, environment, profile budgets, shared TOML and code defaults.

    CLI budget assembly may defer validation until the complete pair is bounded.
    All execution and planning callers validate the final limits.
    """

    layers = None
    if environment is None:
        layers = environment_layers or repository_environment(REPO_ROOT)

    def selected_value(
        environment_name: str,
    ) -> tuple[str | None, LimitSource | None]:
        if layers is None:
            raw = environment.get(environment_name) if environment is not None else None
            if raw is None or not str(raw).strip():
                return None, None
            return str(raw), LimitSource(
                kind="environment",
                name=environment_name,
                explicit=True,
            )
        for layer in layers.priority_layers():
            raw = layer.values.get(environment_name)
            if raw is None or not str(raw).strip():
                continue
            return str(raw), LimitSource(
                kind=layer.kind,
                name=environment_name,
                location=layer.location,
                explicit=True,
            )
        return None, None

    # Reuse the already validated document captured by route resolution when available.
    profile_budget, profile_name, model_context = {}, "", MODEL_CONTEXT_TOKENS
    if execution is not None:
        configured = execution.route.analysis_defaults
        config_path = execution.route.config_file
        profile_budget = execution.route.analysis_profile
        profile_name = execution.route.execution_profile
        # Smaller deployment ceilings are applied by for_execution, as for legacy
        # shared budgets. A larger declared model may admit larger profile budgets.
        model_context = max(execution.route.model_context_tokens, MODEL_CONTEXT_TOKENS)
    elif layers is not None:
        from vraptor.agent.sources import (
            PREFIX,
            PROFILE_BUDGET_FIELDS,
            load_document,
            setting,
        )

        document, config_path = load_document(layers, {})
        configured = document.get("analysis_defaults", {})
        profile_name = setting(layers, PREFIX + "PROFILE")
        if not profile_name and (
            setting(layers, PREFIX + "CONFIG_SOURCE") or "auto"
        ) in {"auto", "application"}:
            profile_name = document.get("selection", {}).get("default_profile", "")
        profiles = document.get("profiles", {})
        if profile_name and profile_name not in profiles:
            raise RuntimeError("Selected execution profile does not exist")
        selected = profiles.get(profile_name, {})
        profile_budget = {
            key: selected[key] for key in PROFILE_BUDGET_FIELDS if key in selected
        }
        declared_context = (
            setting(layers, PREFIX + "MODEL_CONTEXT_TOKENS")
            or selected.get("model_context_tokens")
            or document.get("execution_defaults", {}).get("model_context_tokens")
        )
        if declared_context:
            model_context = max(
                _positive_int(declared_context, "model_context_tokens"),
                MODEL_CONTEXT_TOKENS,
            )
    else:
        configured, config_path = {}, ""
    values: dict[str, Any] = {
        TOML_FIELDS[name]: value for name, value in configured.items()
    }
    sources: dict[str, LimitSource] = {
        field_name: LimitSource(
            kind="application_default",
            name=constant_name,
        )
        for field_name, constant_name in _DEFAULT_CONSTANT_BY_FIELD.items()
    }
    for name in configured:
        sources[TOML_FIELDS[name]] = LimitSource(
            kind="analysis_defaults",
            name=f"analysis_defaults.{name}",
            location=config_path,
            explicit=True,
        )
    for name, value in profile_budget.items():
        values[TOML_FIELDS[name]] = value
        sources[TOML_FIELDS[name]] = LimitSource(
            kind="execution_profile",
            name=f"profiles.{profile_name}.{name}",
            location=config_path,
            explicit=True,
        )
    cli_fields = {
        TOML_FIELDS[name]
        for name in profile_budget
        if execution is not None
        and (source := execution.route.field_sources.get(name)) is not None
        and source.kind == "cli"
    }
    if cli_fields:
        cli_fields.add("operational_context_tokens")
    environment_fields = set()
    for environment_name, field_name in INTEGER_ENVIRONMENT_FIELDS.items():
        if field_name in cli_fields:
            continue
        raw, selected_source = selected_value(environment_name)
        if raw is not None and selected_source is not None:
            values[field_name] = (
                correction_attempts(raw)
                if field_name.endswith("correction_attempts")
                else _positive_int(raw, environment_name)
            )
            sources[field_name] = selected_source
            environment_fields.add(field_name)
    raw_encoding, encoding_source = selected_value(TOKEN_ENCODING_ENVIRONMENT)
    if raw_encoding is not None and encoding_source is not None:
        values["token_encoding"] = str(raw_encoding).strip()
        sources["token_encoding"] = encoding_source
    if execution is not None:
        # Invocation-only analysis budgets outrank environment and saved profiles,
        # including when a downstream runner resolves this captured route again.
        for name, value in profile_budget.items():
            source = execution.route.field_sources.get(name)
            if source is not None and source.kind == "cli":
                field_name = TOML_FIELDS[name]
                values[field_name] = value
                sources[field_name] = LimitSource(kind="cli", name=source.name, explicit=True)
                environment_fields.discard(field_name)
                environment_fields.discard("operational_context_tokens")
    if profile_budget:
        derived = derive_profile_budgets(
            values.get("maximum_input_tokens", DEFAULT_MAXIMUM_INPUT_TOKENS),
            values.get("maximum_output_tokens", DEFAULT_MAXIMUM_OUTPUT_TOKENS),
            values.get(
                "maximum_evidence_tokens_per_item",
                DEFAULT_MAXIMUM_EVIDENCE_TOKENS_PER_ITEM,
            ),
        )
        # Explicit environment overrides remain authoritative and are validated below.
        for name, value in derived.items():
            if name not in environment_fields:
                values[name] = value
                sources[name] = LimitSource(
                    kind="derived_profile_budget",
                    name="max_input_tokens + max_output_tokens"
                    if name == "operational_context_tokens"
                    else name,
                    location=config_path,
                )
        values["model_context_tokens"] = model_context
        sources["model_context_tokens"] = LimitSource(
            kind="model_envelope"
            if model_context != MODEL_CONTEXT_TOKENS
            else "application_default",
            name="model_context_tokens",
            location=config_path,
        )
    limits = AnalysisLimits(
        **values,
        field_sources=MappingProxyType(sources),
    )
    if validate:
        limits.validate()
    return limits


def analysis_route(value: str | None = None) -> str:
    route = str(value or DEFAULT_ANALYSIS_ROUTE).strip()
    if route not in ANALYSIS_TASK_BY_ROUTE:
        raise AnalysisLimitsError(
            f"Unknown analysis route {route!r}; expected one of "
            f"{', '.join(ANALYSIS_ROUTES)}."
        )
    return route


def analysis_task(route: str | None = None) -> str:
    return ANALYSIS_TASK_BY_ROUTE[analysis_route(route)]


def analysis_routing(route: str | None = None) -> dict[str, str]:
    selected = analysis_route(route)
    return {"route": selected, "task": ANALYSIS_TASK_BY_ROUTE[selected]}


def stage_routing(stage: str) -> dict[str, str]:
    normalized = str(stage).strip()
    route = ANALYSIS_ROUTE_BY_STAGE.get(normalized)
    if route is None:
        raise AnalysisLimitsError(f"Unknown analysis stage {normalized!r}.")
    return analysis_routing(route)


def routing_catalog() -> dict[str, dict[str, str]]:
    """Return the code-owned route and stage mappings for safe reporting."""

    return {
        "routes": dict(ANALYSIS_TASK_BY_ROUTE),
        "stage_defaults": dict(ANALYSIS_ROUTE_BY_STAGE),
    }
