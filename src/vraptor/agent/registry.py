"""Code-owned provider contracts. No environment reads or SDK imports."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class ProviderDefinition:
    protocol: str
    base_url: str
    credential_variable: str
    transports: frozenset[str]
    auth_modes: frozenset[str]
    dependency: str


PROVIDERS = MappingProxyType(
    {
        "openai": ProviderDefinition(
            "responses",
            "https://api.openai.com/v1/",
            "OPENAI_API_KEY",
            frozenset({"api", "codex_app_server"}),
            frozenset({"api_key", "codex_managed"}),
            "openai",
        ),
        "azure_openai": ProviderDefinition(
            "responses",
            "",
            "AZURE_OPENAI_API_KEY",
            frozenset({"api"}),
            frozenset({"api_key", "entra"}),
            "openai",
        ),
        "anthropic": ProviderDefinition(
            "messages",
            "https://api.anthropic.com",
            "ANTHROPIC_API_KEY",
            frozenset({"api", "claude_agent_sdk"}),
            frozenset({"api_key", "claude_managed"}),
            "anthropic",
        ),
    }
)


def validate_endpoint(value: str) -> str:
    """Endpoints are public metadata: never accept credentials or query strings."""
    if not value:
        return value
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "Provider endpoint must be an HTTP(S) URL without credentials, query or fragment"
        )
    try:
        parsed.port
    except ValueError as exc:
        raise RuntimeError("Provider endpoint has an invalid port") from exc
    return urlunsplit(parsed)
