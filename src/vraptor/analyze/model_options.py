"""Invocation-only model and token budgets shared by host and hunt analysis."""

import argparse
from dataclasses import replace
from types import MappingProxyType

from vraptor.agent.config import SourceProvenance, resolve_agent_execution
from vraptor.agent.model_budgets import (
    MIN_INPUT_TOKENS,
    MIN_OUTPUT_TOKENS,
    model_budget,
)
from vraptor.analyze import limits as analysis_limits


ROUTE_FIELDS = ("execution_profile", "model", "reasoning_effort", "ai_config_file")
BUDGET_FIELDS = (
    "max_input_tokens",
    "max_output_tokens",
    "model_context_tokens",
    "model_max_output_tokens",
)
OPTIONS = frozenset(
    "--" + name.replace("_", "-") for name in (*ROUTE_FIELDS, *BUDGET_FIELDS)
)


def token_value(value):
    if str(value).lower() == "max":
        return "max"
    try:
        count = int(value)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("Use a positive token count or max") from exc
    if count < 1:
        raise argparse.ArgumentTypeError("Use a positive token count or max")
    return count


def add_arguments(parser):
    group = parser.add_argument_group("AI model and token overrides (this run only)")
    group.add_argument(
        "--execution-profile", help="Select a saved AI execution profile."
    )
    group.add_argument(
        "--ai-config-file", metavar="PATH", help="Select an analyst-agents.toml file."
    )
    group.add_argument("--model", help="Model ID / deployment name for this analysis.")
    group.add_argument(
        "--reasoning-effort", help="Model-supported reasoning effort for this analysis."
    )
    for name, help_text in (
        (
            "max_input_tokens",
            "Input budget; minimum 100000. max fills remaining context within the standard-price tier.",
        ),
        (
            "max_output_tokens",
            "Output budget; minimum 32000. max uses the model/deployment output maximum (including 64000 for Haiku).",
        ),
        (
            "model_context_tokens",
            "Deployment context ceiling; max uses the published model context instead of a saved smaller cap.",
        ),
        (
            "model_max_output_tokens",
            "Deployment output ceiling; max uses the published model maximum instead of a saved smaller cap.",
        ),
    ):
        group.add_argument(
            "--" + name.replace("_", "-"),
            type=token_value,
            metavar="TOKENS|max",
            help=help_text,
        )


def supplied(args):
    return any(
        getattr(args, name, None) is not None
        for name in (*ROUTE_FIELDS, *BUDGET_FIELDS)
    )


def resolve(args, *, resolver=None, allow_missing_credentials=False):
    """Resolve once locally; return the same bounded route used for execution."""
    resolver = resolver or resolve_agent_execution
    cli = {
        ("config_file" if name == "ai_config_file" else name): getattr(args, name)
        for name in ROUTE_FIELDS
        if getattr(args, name, None) is not None
    }
    execution = resolver(
        cli_values=cli, allow_missing_credentials=allow_missing_credentials
    )
    route = execution.route
    reference = model_budget(route.provider, route.model)
    # Superseded environment values must not fail validation before CLI values
    # are applied. Resolve unchanged fields first; validate the final pair below.
    preliminary = dict(route.analysis_profile)
    preliminary_sources = dict(route.field_sources)
    for field, placeholder in (("max_input_tokens", 100000), ("max_output_tokens", 1)):
        if getattr(args, field, None) is not None:
            preliminary[field] = placeholder
            preliminary_sources[field] = SourceProvenance(
                kind="cli", name=field, explicit=True
            )
    baseline = analysis_limits.resolve_analysis_limits(
        execution=replace(
            execution,
            route=replace(
                route,
                analysis_profile=MappingProxyType(preliminary),
                field_sources=MappingProxyType(preliminary_sources),
            ),
        ),
        validate=False,
    )

    def ceiling(field, published, fallback):
        value = getattr(args, field, None)
        if value == "max":
            if published is None:
                raise ValueError(
                    f"--{field.replace('_', '-')} max needs a recognized model ID; specify a numeric deployment limit"
                )
            value = published
        resolved = int(value if value is not None else fallback)
        if published is not None and resolved > published:
            if value is not None:
                raise ValueError(
                    f"--{field.replace('_', '-')} exceeds model maximum {published}"
                )
            resolved = published
        return resolved

    context = ceiling(
        "model_context_tokens",
        reference.context_tokens if reference else None,
        route.model_context_tokens
        or (reference.context_tokens if reference else baseline.model_context_tokens),
    )
    output_cap = ceiling(
        "model_max_output_tokens",
        reference.max_output_tokens if reference else None,
        route.model_max_output_tokens
        or (reference.max_output_tokens if reference else context - 10),
    )
    output_maximum = min(output_cap, context - MIN_INPUT_TOKENS)
    if output_maximum < MIN_OUTPUT_TOKENS:
        raise ValueError(
            "Model/deployment limits must allow at least 100000 input and 32000 output tokens"
        )
    requested_output = getattr(args, "max_output_tokens", None)
    if (
        requested_output == "max"
        and reference is None
        and not route.model_max_output_tokens
        and getattr(args, "model_max_output_tokens", None) is None
    ):
        raise ValueError(
            "--max-output-tokens max needs a recognized model or numeric --model-max-output-tokens"
        )
    output = (
        output_maximum
        if requested_output == "max"
        else int(
            requested_output or min(baseline.maximum_output_tokens, output_maximum)
        )
    )
    if not MIN_OUTPUT_TOKENS <= output <= output_maximum:
        raise ValueError(
            f"--max-output-tokens must be between {MIN_OUTPUT_TOKENS} and {output_maximum}"
        )
    input_maximum = min(
        context - output,
        reference.standard_price_input_ceiling if reference else context - output,
    )
    requested_input = getattr(args, "max_input_tokens", None)
    if (
        requested_input == "max"
        and reference is None
        and not route.model_context_tokens
        and getattr(args, "model_context_tokens", None) is None
    ):
        raise ValueError(
            "--max-input-tokens max needs a recognized model or numeric --model-context-tokens"
        )
    input_tokens = (
        input_maximum
        if requested_input == "max"
        else int(requested_input or min(baseline.maximum_input_tokens, input_maximum))
    )
    input_minimum = MIN_INPUT_TOKENS
    if requested_input is None:
        input_tokens = max(input_minimum, input_tokens)
    if not input_minimum <= input_tokens <= input_maximum:
        raise ValueError(
            f"--max-input-tokens must be between {input_minimum} and {input_maximum} after reserving {output} output tokens"
        )
    profile = {
        **route.analysis_profile,
        "max_input_tokens": input_tokens,
        "max_output_tokens": output,
    }
    provenance = dict(route.field_sources)
    for field in BUDGET_FIELDS:
        provenance[field] = SourceProvenance(
            kind="cli",
            name="--" + field.replace("_", "-")
            if getattr(args, field, None) is not None
            else "derived from analysis CLI overrides",
            explicit=True,
        )
    execution = replace(
        execution,
        route=replace(
            route,
            analysis_profile=MappingProxyType(profile),
            model_context_tokens=context,
            model_max_output_tokens=output_cap,
            field_sources=MappingProxyType(provenance),
        ),
    )
    limits = analysis_limits.resolve_analysis_limits(execution=execution).for_execution(
        execution
    )
    return execution, limits
