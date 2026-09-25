"""Shared analyst configuration CLI and safe reporting helpers."""

from __future__ import annotations

import argparse
from typing import Any

from vraptor.analyze import limits as analysis_limits
from vraptor.common.cli_arguments import non_negative_int
from vraptor.common.cli_arguments import positive_int
from vraptor.agent.config import CONFIG_SOURCES
from vraptor.agent.config import ResolvedAgentExecution
from vraptor.agent.config import application_default_agent_route
from vraptor.agent.config import VALID_AGENT_PROVIDERS
from vraptor.agent.config import VALID_ANALYST_AGENT_TRANSPORTS


AGENT_CONFIG_SCHEMA_VERSION = 3


def add_agent_config_arguments(parser: argparse.ArgumentParser) -> None:
    """Register diagnostic-only analyst route overrides."""

    selection = parser.add_argument_group("View and profile selection")
    selection.add_argument(
        "--view",
        choices=("effective", "defaults"),
        default="effective",
        help=(
            "Report effective local configuration (default) or machine-independent "
            "application defaults."
        ),
    )

    selection.add_argument("--config-file", metavar="PATH", help="Select an analyst-agents.toml file.")
    selection.add_argument("--execution-profile", metavar="NAME", help="Select a named AI execution profile.")
    route = parser.add_argument_group("Diagnostic route overrides (not saved)")
    route.add_argument(
        "--provider",
        choices=sorted(VALID_AGENT_PROVIDERS),
        help="Explicit provider override for this diagnostic resolution.",
    )
    route.add_argument(
        "--model",
        help="Explicit model or deployment override for this diagnostic resolution.",
    )
    route.add_argument(
        "--transport",
        choices=sorted(VALID_ANALYST_AGENT_TRANSPORTS),
        help="Explicit transport override for this diagnostic resolution.",
    )
    route.add_argument(
        "--reasoning-effort",
        help="Explicit reasoning-effort override for this diagnostic resolution.",
    )
    route.add_argument(
        "--timeout-seconds",
        type=positive_int,
        help="Explicit total-operation timeout for this diagnostic resolution.",
    )
    route.add_argument(
        "--max-retries",
        type=non_negative_int,
        help="Explicit transient retry count for this diagnostic resolution.",
    )
    route.add_argument(
        "--max-concurrency",
        type=positive_int,
        help="Explicit scope concurrency ceiling for this diagnostic resolution.",
    )
    sources = parser.add_argument_group("Native configuration sources")
    sources.add_argument(
        "--config-source",
        choices=sorted(CONFIG_SOURCES),
        help="Routing source mode for this diagnostic resolution.",
    )
    sources.add_argument(
        "--codex-config",
        help="Explicit Codex config.toml path for this diagnostic resolution.",
    )
    sources.add_argument(
        "--codex-profile",
        help="Explicit Codex profile name for this diagnostic resolution.",
    )


def agent_config_cli_values(args: argparse.Namespace) -> dict[str, Any]:
    """Translate present argparse fields into source-aware resolver inputs."""

    values: dict[str, Any] = {}
    fields = (
        ("provider", "provider", "--provider"),
        ("model", "model", "--model"),
        ("transport", "transport", "--transport"),
        ("reasoning_effort", "reasoning_effort", "--reasoning-effort"),
        ("timeout_seconds", "timeout_seconds", "--timeout-seconds"),
        ("max_retries", "max_retries", "--max-retries"),
        ("max_concurrency", "max_concurrency", "--max-concurrency"),
        ("config_source", "config_source_mode", "--config-source"),
        ("codex_config", "codex_config", "--codex-config"),
        ("codex_profile", "codex_profile", "--codex-profile"),
        ("config_file", "config_file", "--config-file"),
        ("execution_profile", "execution_profile", "--execution-profile"),
    )
    for argument_name, field_name, source_name in fields:
        value = getattr(args, argument_name, None)
        if value is not None:
            values[field_name] = value
            values[f"{field_name}_source"] = source_name
    return values


def _public_source(value: Any) -> Any:
    public_dict = getattr(value, "public_dict", None)
    return public_dict() if callable(public_dict) else value


def _credential_records(
    execution: ResolvedAgentExecution,
) -> list[dict[str, Any]]:
    route = execution.route
    sources = route.field_sources
    records: list[dict[str, Any]] = []
    if route.credential_variable:
        records.append(
            {
                "purpose": "primary",
                "variable": route.credential_variable,
                "present": bool(execution.inputs.credential_present),
                "source": _public_source(sources.get("credential")),
            }
        )
    for header, binding in sorted(route.header_bindings.items()):
        records.append(
            {
                "purpose": f"header:{header}",
                "variable": binding.variable,
                "present": bool(binding.configured),
                "source": _public_source(binding.source),
            }
        )
    return records


def _execution_record(execution: ResolvedAgentExecution) -> dict[str, Any]:
    route = execution.route
    return {
        "enabled": route.enabled,
        "transport": (
            route.protocol
            if route.protocol in {"codex_app_server", "claude_agent_sdk"}
            else "api"
        ),
        "provider": route.provider,
        "model": route.model,
        "reasoning_effort": route.reasoning_effort,
        "timeout_seconds": route.timeout_seconds,
        "max_retries": route.max_retries,
        "max_concurrency": route.max_concurrency,
        "protocol": route.protocol,
        "auth_mode": route.auth_mode,
        "config_source_mode": route.config_source_mode,
        "config_file": route.config_file,
        "execution_profile": route.execution_profile,
    }


def _configuration_payload(
    execution: ResolvedAgentExecution,
    limits: analysis_limits.AnalysisLimits,
    *,
    view: str,
    credentials: list[dict[str, Any]],
) -> dict[str, Any]:
    route = execution.route
    return {
        "schema_version": AGENT_CONFIG_SCHEMA_VERSION,
        "view": view,
        "execution": {
            "effective": _execution_record(execution),
            "sources": {
                key: _public_source(value)
                for key, value in sorted(route.field_sources.items())
            },
            "identity": route.identity(),
        },
        "analysis_limits": limits.public_dict(),
        "analysis_routing": analysis_limits.routing_catalog(),
        "credentials": credentials,
    }


def agent_configuration_payload(
    execution: ResolvedAgentExecution,
    limits: analysis_limits.AnalysisLimits,
) -> dict[str, Any]:
    """Return one versioned non-secret execution and analysis configuration."""

    return _configuration_payload(
        execution,
        limits,
        view="effective",
        credentials=_credential_records(execution),
    )


def application_defaults_payload() -> dict[str, Any]:
    """Return code-owned defaults without reading environment or harness state."""

    route = application_default_agent_route()
    limits = analysis_limits.resolve_analysis_limits({})
    execution = ResolvedAgentExecution(route=route)
    credentials: list[dict[str, str]] = []
    if route.credential_variable:
        credentials.append(
            {
                "purpose": "primary",
                "variable": route.credential_variable,
            }
        )
    return _configuration_payload(
        execution,
        limits,
        view="defaults",
        credentials=credentials,
    )
