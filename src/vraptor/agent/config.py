"""Provider-neutral analyst API configuration.

Credentials are read only from environment variables. Codex integration imports
allowlisted, non-secret routing fields; secret values remain excluded from public
configuration and representations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from vraptor.paths import RepositoryEnvironment
from vraptor.paths import repository_environment
from vraptor.agent.registry import PROVIDERS, validate_endpoint
from vraptor.agent import sources as config_sources


from vraptor.resources import repository_root

REPO_ROOT = repository_root()
ANALYST_AGENT_MODEL_ENV = "AI_SKILLS_ANALYST_AGENT_MODEL"
ANALYST_AGENT_ENABLED_ENV = "AI_SKILLS_ANALYST_AGENT_ENABLED"
ANALYST_AGENT_PROVIDER_ENV = "AI_SKILLS_ANALYST_AGENT_PROVIDER"
ANALYST_AGENT_TRANSPORT_ENV = "AI_SKILLS_ANALYST_AGENT_TRANSPORT"
ANALYST_AGENT_REASONING_ENV = "AI_SKILLS_ANALYST_AGENT_REASONING_EFFORT"
ANALYST_AGENT_TIMEOUT_ENV = "AI_SKILLS_ANALYST_AGENT_TIMEOUT_SECONDS"
ANALYST_AGENT_MAX_RETRIES_ENV = "AI_SKILLS_ANALYST_AGENT_MAX_RETRIES"
ANALYST_AGENT_MAX_CONCURRENCY_ENV = "AI_SKILLS_ANALYST_AGENT_MAX_CONCURRENCY"
DEFAULT_ANALYST_AGENT_MODEL = "gpt-5.6-luna"
DEFAULT_ANALYST_AGENT_PROVIDER = "openai"
DEFAULT_ANALYST_AGENT_TIMEOUT_SECONDS = 600
DEFAULT_ANALYST_AGENT_MAX_RETRIES = 2
DEFAULT_ANALYST_AGENT_MAX_CONCURRENCY = 5
VALID_AGENT_PROVIDERS = frozenset(PROVIDERS)
VALID_ANALYST_AGENT_TRANSPORTS = frozenset(
    {"api", "codex_app_server", "claude_agent_sdk", "auto"}
)

CODEX_CONFIG_ENV = "AI_SKILLS_ANALYST_AGENT_CODEX_CONFIG"
CODEX_PROFILE_ENV = "AI_SKILLS_ANALYST_AGENT_CODEX_PROFILE"
CONFIG_SOURCE_ENV = "AI_SKILLS_ANALYST_AGENT_CONFIG_SOURCE"
CONFIG_SOURCES = frozenset({"auto", "application", "codex", "claude_code"})
EXECUTION_ROUTE_IDENTITY_SCHEMA_VERSION = 3


def _empty_mapping() -> Mapping[str, Any]:
    return MappingProxyType({})


@dataclass(frozen=True)
class SourceProvenance:
    """Safe provenance for one selected configuration value."""

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


@dataclass(frozen=True)
class ConfigCandidate:
    """One source candidate; presence is independent from value equality."""

    present: bool
    value: Any
    source: SourceProvenance


@dataclass(frozen=True)
class UnresolvedAgentConfig:
    """Immutable non-secret configuration candidates before route resolution."""

    fields: Mapping[str, tuple[ConfigCandidate, ...]]
    codex_hint: HarnessProviderHint | None
    codex_status: str
    selection: Mapping[str, str] = field(default_factory=_empty_mapping)
    analysis_defaults: Mapping[str, Any] = field(default_factory=_empty_mapping)
    analysis_profile: Mapping[str, Any] = field(default_factory=_empty_mapping)


@dataclass(frozen=True)
class CredentialBinding:
    mode: str
    variable: str = ""
    configured: bool = False
    source: SourceProvenance | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "variable": self.variable,
            "configured": self.configured,
            "source": self.source.public_dict() if self.source is not None else None,
        }


@dataclass(frozen=True)
class ResolvedAgentRoute:
    """Non-secret execution route resolved before credential hydration."""

    provider: str
    model: str
    protocol: str
    base_url: str = ""
    auth_mode: str = "api_key"
    api_version: str = ""
    default_query: Mapping[str, str] = field(default_factory=_empty_mapping)
    header_variables: Mapping[str, str] = field(default_factory=_empty_mapping)
    max_concurrency: int = 1
    reasoning_effort: str = ""
    enabled: bool = True
    timeout_seconds: int = 600
    max_retries: int = 2
    config_source_mode: str = "auto"
    codex_status: str = "not_found"
    harness: str = ""
    harness_profile: str = ""
    harness_config_path: str = ""
    execution_profile: str = ""
    config_file: str = ""
    analysis_defaults: Mapping[str, Any] = field(default_factory=_empty_mapping)
    analysis_profile: Mapping[str, Any] = field(default_factory=_empty_mapping)
    detected_harness: str = ""
    model_context_tokens: int = 0
    model_max_output_tokens: int = 0
    read_timeout_seconds: int = 120
    credential_variable: str = ""
    harness_credential_variable: str = ""
    field_sources: Mapping[str, SourceProvenance] = field(
        default_factory=_empty_mapping
    )
    credential_binding: CredentialBinding | None = None
    header_bindings: Mapping[str, CredentialBinding] = field(
        default_factory=_empty_mapping
    )

    def identity_dict(self) -> dict[str, Any]:
        """Return the versioned, allowlisted cache identity for this route."""

        return {
            "schema_version": EXECUTION_ROUTE_IDENTITY_SCHEMA_VERSION,
            "provider": self.provider,
            "model": self.model,
            "protocol": self.protocol,
            "base_url": self.base_url,
            "auth_mode": self.auth_mode,
            "api_version": self.api_version,
            "default_query": dict(sorted(self.default_query.items())),
            "default_header_keys": sorted(self.header_variables),
            "max_concurrency": self.max_concurrency,
            "reasoning_effort": self.reasoning_effort,
            "enabled": self.enabled,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "model_context_tokens": self.model_context_tokens,
            "model_max_output_tokens": self.model_max_output_tokens,
            "read_timeout_seconds": self.read_timeout_seconds,
            **(
                {"analysis_profile": dict(self.analysis_profile)}
                if self.analysis_profile
                else {}
            ),
        }

    def identity(self) -> str:
        payload = json.dumps(
            self.identity_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def public_dict(self) -> dict[str, Any]:
        """Return safe route metadata without credentials or header values."""

        return {
            **self.identity_dict(),
            "identity": self.identity(),
            "harness": self.harness,
            "harness_profile": self.harness_profile,
            "harness_config_path": self.harness_config_path,
            "execution_profile": self.execution_profile,
            "config_file": self.config_file,
            "detected_harness": self.detected_harness,
            "credential_variable": self.credential_variable,
            "harness_credential_variable": self.harness_credential_variable,
            "header_variables": dict(self.header_variables),
            "field_sources": {
                key: (
                    value.public_dict()
                    if isinstance(value, SourceProvenance)
                    else value
                )
                for key, value in self.field_sources.items()
            },
            "config_source_mode": self.config_source_mode,
            "codex_status": self.codex_status,
            "credential_binding": (
                self.credential_binding.public_dict()
                if self.credential_binding is not None
                else None
            ),
            "header_bindings": {
                header: binding.public_dict()
                for header, binding in self.header_bindings.items()
            },
        }


@dataclass(frozen=True)
class HydratedProviderInputs:
    """Credential-bearing inputs attached to one already-resolved route."""

    api_key: str = field(default="", repr=False)
    default_headers: Mapping[str, str] = field(
        default_factory=_empty_mapping, repr=False
    )
    azure_client_secret: Mapping[str, str] = field(
        default_factory=_empty_mapping, repr=False
    )
    credential_present: bool = False


@dataclass(frozen=True)
class ResolvedAgentExecution:
    """One operation-scoped route and its privately hydrated provider inputs."""

    route: ResolvedAgentRoute
    inputs: HydratedProviderInputs = field(
        default_factory=HydratedProviderInputs,
        repr=False,
    )

    @property
    def enabled(self) -> bool:
        return self.route.enabled

    @property
    def provider(self) -> str:
        return self.route.provider

    @property
    def model(self) -> str:
        return self.route.model

    @property
    def protocol(self) -> str:
        return self.route.protocol

    @property
    def base_url(self) -> str:
        return self.route.base_url

    @property
    def auth_mode(self) -> str:
        return self.route.auth_mode

    @property
    def api_version(self) -> str:
        return self.route.api_version

    @property
    def default_query(self) -> Mapping[str, str]:
        return self.route.default_query

    @property
    def reasoning_effort(self) -> str:
        return self.route.reasoning_effort

    @property
    def timeout_seconds(self) -> int:
        return self.route.timeout_seconds

    @property
    def max_retries(self) -> int:
        return self.route.max_retries

    @property
    def max_concurrency(self) -> int:
        return self.route.max_concurrency

    def public_dict(self) -> dict[str, Any]:
        """Return safe operational metadata without credential values."""

        return {
            **self.route.public_dict(),
            "default_query_keys": sorted(self.route.default_query),
            "default_header_keys": sorted(self.inputs.default_headers),
            "credential_present": self.inputs.credential_present,
            "execution_route_identity": self.route.identity(),
        }


def analyst_execution_metadata(
    spec: ResolvedAgentExecution,
) -> dict[str, Any]:
    """Return compatible durable metadata using the actual resolved route."""

    selected_route = spec.route
    return {
        "enabled": selected_route.enabled,
        "provider": selected_route.provider,
        "model": selected_route.model,
        "protocol": selected_route.protocol,
        "reasoning_effort": selected_route.reasoning_effort,
        "timeout_seconds": selected_route.timeout_seconds,
        "max_retries": selected_route.max_retries,
        "max_concurrency": selected_route.max_concurrency,
        "execution_route_identity": selected_route.identity(),
        "execution_route": selected_route.public_dict(),
    }


def analyst_execution_identity(
    spec: ResolvedAgentExecution,
) -> dict[str, Any]:
    """Return only execution-affecting values suitable for cache hashing."""

    selected_route = spec.route
    return {
        "execution_route": selected_route.identity_dict(),
        "runtime_policy": {
            "enabled": selected_route.enabled,
            "timeout_seconds": selected_route.timeout_seconds,
            "max_retries": selected_route.max_retries,
            "max_concurrency": selected_route.max_concurrency,
        },
    }


@dataclass(frozen=True)
class HarnessProviderHint:
    harness: str
    profile: str
    model: str
    provider: str
    base_url: str
    env_key: str
    protocol: str
    default_query: Mapping[str, str]
    env_headers: Mapping[str, str]
    source_path: str
    reasoning_effort: str = ""


def _normalized_provider(value: object) -> str:
    provider = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {"azure": "azure_openai"}
    return aliases.get(provider, provider)


def codex_config_candidates(
    explicit_path: str | Path | None = None,
    *,
    configured_path: str = "",
    codex_home: str = "",
    home: str = "",
) -> tuple[Path, ...]:
    """Return config paths in documented precedence order without reading them."""

    def expand(value: str | Path) -> Path:
        raw = str(value)
        selected_home = home.strip()
        if selected_home:
            for prefix in ("$HOME", "${HOME}", "~"):
                if raw == prefix:
                    raw = selected_home
                    break
                if raw.startswith(f"{prefix}/"):
                    raw = f"{selected_home}/{raw[len(prefix) + 1 :]}"
                    break
        return Path(raw).expanduser()

    candidates: list[Path] = []
    if explicit_path:
        candidates.append(expand(explicit_path))
    elif configured := configured_path.strip():
        candidates.append(expand(configured))
    elif selected_codex_home := codex_home.strip():
        candidates.append(expand(selected_codex_home) / "config.toml")
    else:
        candidates.append(Path.home() / ".codex" / "config.toml")
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in unique:
            unique.append(resolved)
    return tuple(unique)


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(item)
        for key, item in value.items()
        if str(key).strip() and isinstance(item, (str, int, float, bool))
    }


def load_codex_provider_hint(
    *,
    explicit_path: str | Path | None = None,
    requested_profile: str = "",
    configured_path: str = "",
    codex_home: str = "",
    home: str = "",
) -> HarnessProviderHint | None:
    """Import only non-secret provider routing fields from Codex config.toml."""

    config_path = next(
        (
            path
            for path in codex_config_candidates(
                explicit_path,
                configured_path=configured_path,
                codex_home=codex_home,
                home=home,
            )
            if path.is_file()
        ),
        None,
    )
    if config_path is None:
        return None
    payload = config_sources.read_config(config_path)
    profile_name = (
        requested_profile.strip() or str(payload.get("profile") or "").strip()
    )
    selected: dict[str, Any] = {}
    selected_source_path = config_path
    profiles = payload.get("profiles")
    if profile_name and (
        not isinstance(profiles, dict) or profile_name not in profiles
    ):
        profile_path = config_path.parent / f"{profile_name}.config.toml"
        if (
            not config_sources.NAME.fullmatch(profile_name)
            or not profile_path.is_file()
        ):
            raise RuntimeError("Selected Codex profile was not found")
        selected = config_sources.read_config(profile_path)
        selected_source_path = profile_path
    if profile_name and isinstance(profiles, dict):
        raw_profile = profiles.get(profile_name)
        if isinstance(raw_profile, dict):
            selected = raw_profile
    model = str(selected.get("model") or payload.get("model") or "").strip()
    provider_name = str(
        selected.get("model_provider") or payload.get("model_provider") or ""
    ).strip()
    if model and not provider_name:
        provider_name = "openai"
    providers = (
        dict(payload.get("model_providers") or {})
        if isinstance(payload.get("model_providers"), dict)
        else {}
    )
    if isinstance(selected.get("model_providers"), dict):
        providers.update(selected["model_providers"])
    raw_provider: dict[str, Any] = {}
    if provider_name and isinstance(providers, dict):
        candidate = providers.get(provider_name)
        if isinstance(candidate, dict):
            raw_provider = candidate
    provider = _normalized_provider(raw_provider.get("name") or provider_name)
    env_key = str(raw_provider.get("env_key") or "").strip()
    env_headers = _string_mapping(
        raw_provider.get("env_http_headers") or raw_provider.get("env_headers")
    )
    return HarnessProviderHint(
        harness="codex",
        profile=profile_name,
        model=model,
        reasoning_effort=str(
            selected.get("model_reasoning_effort")
            or payload.get("model_reasoning_effort")
            or ""
        ).strip(),
        provider=provider,
        base_url=str(raw_provider.get("base_url") or "").strip(),
        env_key=env_key,
        protocol=str(raw_provider.get("wire_api") or "").strip().lower(),
        default_query=MappingProxyType(
            _string_mapping(
                raw_provider.get("query_params")
                or raw_provider.get("required_query_params")
            )
        ),
        env_headers=MappingProxyType(env_headers),
        source_path=str(selected_source_path),
    )


_FIELD_ENVIRONMENTS: Mapping[str, str] = MappingProxyType(
    {
        "enabled": ANALYST_AGENT_ENABLED_ENV,
        "provider": ANALYST_AGENT_PROVIDER_ENV,
        "model": ANALYST_AGENT_MODEL_ENV,
        "transport": ANALYST_AGENT_TRANSPORT_ENV,
        "reasoning_effort": ANALYST_AGENT_REASONING_ENV,
        "timeout_seconds": ANALYST_AGENT_TIMEOUT_ENV,
        "max_retries": ANALYST_AGENT_MAX_RETRIES_ENV,
        "max_concurrency": ANALYST_AGENT_MAX_CONCURRENCY_ENV,
        "config_source_mode": CONFIG_SOURCE_ENV,
        "codex_config": CODEX_CONFIG_ENV,
        "codex_profile": CODEX_PROFILE_ENV,
        "openai_base_url": "OPENAI_BASE_URL",
        "azure_endpoint": "AZURE_OPENAI_ENDPOINT",
        "azure_auth_mode": "AZURE_OPENAI_AUTH_MODE",
        "azure_api_version": "AZURE_OPENAI_API_VERSION",
        "base_url": "AI_SKILLS_ANALYST_AGENT_BASE_URL",
        "auth_mode": "AI_SKILLS_ANALYST_AGENT_AUTH_MODE",
        "api_key_env": "AI_SKILLS_ANALYST_AGENT_API_KEY_ENV",
        "config_file": "AI_SKILLS_ANALYST_AGENT_CONFIG_FILE",
        "execution_profile": "AI_SKILLS_ANALYST_AGENT_PROFILE",
        "model_context_tokens": "AI_SKILLS_ANALYST_AGENT_MODEL_CONTEXT_TOKENS",
        "model_max_output_tokens": "AI_SKILLS_ANALYST_AGENT_MODEL_MAX_OUTPUT_TOKENS",
        "read_timeout_seconds": "AI_SKILLS_ANALYST_AGENT_READ_TIMEOUT_SECONDS",
    }
)
AGENT_CONFIGURATION_ENVIRONMENT_VARIABLES = tuple(
    sorted(
        set(_FIELD_ENVIRONMENTS.values())
        | {"AI_SKILLS_ANALYST_AGENT_HARNESS", "AI_SKILLS_ANALYST_AGENT_CLAUDE_CONFIG"}
    )
)

_APPLICATION_DEFAULTS: Mapping[str, Any] = MappingProxyType(
    {
        "enabled": True,
        "provider": DEFAULT_ANALYST_AGENT_PROVIDER,
        "model": DEFAULT_ANALYST_AGENT_MODEL,
        "transport": "api",
        "reasoning_effort": "",
        "timeout_seconds": DEFAULT_ANALYST_AGENT_TIMEOUT_SECONDS,
        "max_retries": DEFAULT_ANALYST_AGENT_MAX_RETRIES,
        "max_concurrency": DEFAULT_ANALYST_AGENT_MAX_CONCURRENCY,
        "config_source_mode": "auto",
        "codex_config": "",
        "codex_profile": "",
        "openai_base_url": "",
        "azure_endpoint": "",
        "azure_auth_mode": "api_key",
        "azure_api_version": "",
        "base_url": "",
        "auth_mode": "",
        "api_key_env": "",
        "config_file": "",
        "execution_profile": "",
        "model_context_tokens": 0,
        "model_max_output_tokens": 0,
        "read_timeout_seconds": 120,
    }
)

_APPLICATION_DEFAULT_CONSTANT_NAMES: Mapping[str, str] = MappingProxyType(
    {
        "provider": "DEFAULT_ANALYST_AGENT_PROVIDER",
        "model": "DEFAULT_ANALYST_AGENT_MODEL",
        "timeout_seconds": "DEFAULT_ANALYST_AGENT_TIMEOUT_SECONDS",
        "max_retries": "DEFAULT_ANALYST_AGENT_MAX_RETRIES",
        "max_concurrency": "DEFAULT_ANALYST_AGENT_MAX_CONCURRENCY",
    }
)


def _application_default_source_name(field_name: str) -> str:
    return _APPLICATION_DEFAULT_CONSTANT_NAMES.get(
        field_name,
        f"agent_config._APPLICATION_DEFAULTS.{field_name}",
    )


def _candidate(
    value: Any,
    *,
    kind: str,
    name: str,
    location: str = "",
    explicit: bool,
    present: bool | None = None,
) -> ConfigCandidate:
    normalized_present = bool(str(value).strip()) if present is None else bool(present)
    return ConfigCandidate(
        present=normalized_present,
        value=value,
        source=SourceProvenance(
            kind=kind,
            name=name,
            location=location,
            explicit=explicit,
        ),
    )


def _field_candidates(
    field_name: str,
    *,
    cli_values: Mapping[str, Any],
    environment: RepositoryEnvironment,
) -> tuple[ConfigCandidate, ...]:
    variable = _FIELD_ENVIRONMENTS[field_name]
    candidates: list[ConfigCandidate] = []
    if field_name in cli_values:
        candidates.append(
            _candidate(
                cli_values[field_name],
                kind="cli",
                name=str(cli_values.get(f"{field_name}_source") or field_name),
                explicit=True,
                present=True,
            )
        )
    for layer in environment.priority_layers():
        value = layer.values.get(variable, "")
        candidates.append(
            _candidate(
                value,
                kind=layer.kind,
                name=variable,
                location=layer.location,
                explicit=True,
            )
        )
    candidates.append(
        _candidate(
            _APPLICATION_DEFAULTS[field_name],
            kind="application_default",
            name=_application_default_source_name(field_name),
            explicit=False,
            present=True,
        )
    )
    return tuple(candidates)


def _selected_candidate(
    unresolved: UnresolvedAgentConfig,
    field_name: str,
) -> ConfigCandidate:
    for candidate in unresolved.fields[field_name]:
        if candidate.present:
            return candidate
    raise RuntimeError(f"No configuration candidate exists for {field_name}")


def _selected_text(
    unresolved: UnresolvedAgentConfig, field_name: str
) -> tuple[str, SourceProvenance]:
    candidate = _selected_candidate(unresolved, field_name)
    return str(candidate.value or "").strip(), candidate.source


def _selected_bool(
    unresolved: UnresolvedAgentConfig, field_name: str
) -> tuple[bool, SourceProvenance]:
    candidate = _selected_candidate(unresolved, field_name)
    if isinstance(candidate.value, bool):
        return candidate.value, candidate.source
    raw = str(candidate.value or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True, candidate.source
    if raw in {"0", "false", "no", "off"}:
        return False, candidate.source
    raise RuntimeError(f"{candidate.source.name} must be true or false, got {raw!r}")


def _selected_int(
    unresolved: UnresolvedAgentConfig,
    field_name: str,
    *,
    minimum: int,
) -> tuple[int, SourceProvenance]:
    candidate = _selected_candidate(unresolved, field_name)
    try:
        value = int(candidate.value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"{candidate.source.name} must be an integer, got {candidate.value!r}"
        ) from exc
    if value < minimum:
        comparator = "zero or greater" if minimum == 0 else "greater than zero"
        raise RuntimeError(f"{candidate.source.name} must be {comparator}, got {value}")
    return value, candidate.source


def collect_unresolved_agent_config(
    *,
    cli_values: Mapping[str, Any] | None = None,
    repo_root: Path = REPO_ROOT,
    process_environment: Mapping[str, str] | None = None,
    environment: RepositoryEnvironment | None = None,
) -> UnresolvedAgentConfig:
    """Parse every non-secret source once without applying route defaults early."""

    cli = dict(cli_values or {})
    layers = environment or repository_environment(
        repo_root,
        process_environment=process_environment,
    )
    fields = {
        name: _field_candidates(name, cli_values=cli, environment=layers)
        for name in _FIELD_ENVIRONMENTS
    }
    selected = config_sources.load_selection(layers, cli)
    selected_provider = selected.values.get("provider")
    override_provider = next(
        (
            item.value
            for item in fields["provider"]
            if item.present and item.source.explicit
        ),
        "",
    )
    if (
        selected_provider
        and override_provider
        and _normalized_provider(override_provider) != selected_provider
    ):
        raise RuntimeError(
            "Provider override conflicts with selected profile/harness; select a compatible profile"
        )
    for name, value in selected.values.items():
        target = "azure_api_version" if name == "api_version" else name
        if target not in fields:
            continue
        fields[target] = (
            *fields[target][:-1],
            _candidate(
                value,
                kind=selected.origins.get(name, "execution_profile"),
                name=name,
                location=selected.source_path
                if selected.origins.get(name)
                else selected.path,
                explicit=True,
                present=value != "",
            ),
            fields[target][-1],
        )
    selection = MappingProxyType(
        {
            "execution_profile": selected.profile,
            "config_file": selected.path,
            "detected_harness": selected.harness,
            "source_path": selected.source_path,
        }
    )
    provisional = UnresolvedAgentConfig(
        fields=MappingProxyType(fields),
        codex_hint=None,
        codex_status="not_evaluated",
        selection=selection,
        analysis_defaults=MappingProxyType(selected.analysis_defaults),
        analysis_profile=MappingProxyType(selected.analysis_profile),
    )
    source_mode, _source = _selected_text(provisional, "config_source_mode")
    source_mode = source_mode.lower()
    if source_mode not in CONFIG_SOURCES:
        raise RuntimeError(
            f"{CONFIG_SOURCE_ENV} must be one of {', '.join(sorted(CONFIG_SOURCES))}"
        )
    if (
        (source_mode == "application" and selected.harness != "codex")
        or selected.harness == "claude_code"
        or (selected.profile and not selected.harness)
    ):
        return replace(provisional, codex_status="disabled")
    codex_config, _config_source = _selected_text(provisional, "codex_config")
    codex_profile, _profile_source = _selected_text(provisional, "codex_profile")
    process_home = str(layers.process.values.get("HOME") or "").strip()
    codex_home = str(layers.process.values.get("CODEX_HOME") or "").strip()
    if not codex_home:
        if process_home:
            codex_home = str(Path(process_home) / ".codex")
    hint = load_codex_provider_hint(
        explicit_path=codex_config or None,
        requested_profile=codex_profile,
        codex_home=codex_home,
        home=process_home,
    )
    if hint is None:
        if source_mode == "codex":
            raise RuntimeError("Requested codex harness configuration was not found")
        status = "not_found"
    elif hint.provider and hint.model:
        status = "selected"
    else:
        if source_mode == "codex":
            raise RuntimeError("Requested codex harness configuration is incomplete")
        status = "incomplete"
    return replace(
        provisional,
        codex_hint=hint,
        codex_status=status,
    )


def application_default_agent_route() -> ResolvedAgentRoute:
    """Return the code-only fallback route without inspecting local state."""

    fields = {
        field_name: (
            _candidate(
                _APPLICATION_DEFAULTS[field_name],
                kind="application_default",
                name=_application_default_source_name(field_name),
                explicit=False,
                present=True,
            ),
        )
        for field_name in _FIELD_ENVIRONMENTS
    }
    unresolved = UnresolvedAgentConfig(
        fields=MappingProxyType(fields),
        codex_hint=None,
        codex_status="not_evaluated",
    )
    return resolve_unresolved_agent_route(unresolved)


def _require(value: str, variable: str, provider: str) -> str:
    if value:
        return value
    raise RuntimeError(f"{provider} requires environment variable {variable}")


def _azure_base_url(endpoint: str) -> str:
    base = endpoint.rstrip("/")
    if base.endswith("/openai/v1"):
        return base + "/"
    return base + "/openai/v1/"


def _higher_precedence_candidate(
    unresolved: UnresolvedAgentConfig,
    field_name: str,
) -> ConfigCandidate | None:
    for candidate in unresolved.fields[field_name]:
        if candidate.source.kind == "application_default":
            continue
        if candidate.present:
            return candidate
    return None


def _resolved_text_with_codex(
    unresolved: UnresolvedAgentConfig,
    field_name: str,
    codex_value: str,
    codex_field: str,
) -> tuple[str, SourceProvenance]:
    higher = _higher_precedence_candidate(unresolved, field_name)
    if higher is not None:
        return str(higher.value or "").strip(), higher.source
    if codex_value and unresolved.codex_hint is not None:
        return codex_value, SourceProvenance(
            kind="codex_route",
            name=codex_field,
            location=unresolved.codex_hint.source_path,
            explicit=False,
        )
    return _selected_text(unresolved, field_name)


def _resolve_existing_provider_route(
    unresolved: UnresolvedAgentConfig,
) -> ResolvedAgentRoute:
    """Purely resolve one immutable non-secret configuration snapshot."""

    hint = unresolved.codex_hint
    provider, provider_source = _resolved_text_with_codex(
        unresolved,
        "provider",
        _normalized_provider(hint.provider) if hint is not None else "",
        "model_provider",
    )
    provider = _normalized_provider(provider)
    if provider not in {"openai", "azure_openai"}:
        raise RuntimeError(f"Unsupported analyst agent provider: {provider}")
    compatible_hint = hint if hint is not None and hint.provider == provider else None
    codex_status = unresolved.codex_status
    if hint is not None and compatible_hint is None:
        codex_status = "incompatible"
    model, model_source = _resolved_text_with_codex(
        unresolved,
        "model",
        compatible_hint.model if compatible_hint is not None else "",
        "model",
    )
    if not model:
        raise RuntimeError(f"{ANALYST_AGENT_MODEL_ENV} cannot be empty")

    enabled, enabled_source = _selected_bool(unresolved, "enabled")
    reasoning_effort, reasoning_source = _resolved_text_with_codex(
        unresolved,
        "reasoning_effort",
        compatible_hint.reasoning_effort if compatible_hint is not None else "",
        "model_reasoning_effort",
    )
    timeout_seconds, timeout_source = _selected_int(
        unresolved, "timeout_seconds", minimum=1
    )
    max_retries, retries_source = _selected_int(unresolved, "max_retries", minimum=0)
    max_concurrency, concurrency_source = _selected_int(
        unresolved, "max_concurrency", minimum=1
    )
    transport, transport_source = _selected_text(unresolved, "transport")
    transport = transport.lower()
    if transport not in VALID_ANALYST_AGENT_TRANSPORTS:
        supported = ", ".join(sorted(VALID_ANALYST_AGENT_TRANSPORTS))
        raise RuntimeError(f"{ANALYST_AGENT_TRANSPORT_ENV} must be one of: {supported}")
    config_source_mode, config_mode_source = _selected_text(
        unresolved, "config_source_mode"
    )
    config_source_mode = config_source_mode.lower()
    _codex_config, codex_config_source = _selected_text(unresolved, "codex_config")
    _codex_profile, codex_profile_source = _selected_text(unresolved, "codex_profile")
    hint_source = SourceProvenance(
        kind="codex_route",
        name="provider_route",
        location=compatible_hint.source_path if compatible_hint is not None else "",
        explicit=False,
    )
    provider_default = SourceProvenance(
        kind="provider_default", name=provider, explicit=False
    )
    sources: dict[str, SourceProvenance] = {
        "enabled": enabled_source,
        "provider": provider_source,
        "model": model_source,
        "transport": transport_source,
        "reasoning_effort": reasoning_source,
        "timeout_seconds": timeout_source,
        "max_retries": retries_source,
        "max_concurrency": concurrency_source,
        "config_source_mode": config_mode_source,
        "codex_config": codex_config_source,
        "codex_profile": codex_profile_source,
    }

    common = {
        "provider": provider,
        "model": model,
        "enabled": enabled,
        "timeout_seconds": timeout_seconds,
        "max_retries": max_retries,
        "max_concurrency": max_concurrency,
        "reasoning_effort": reasoning_effort,
        "config_source_mode": config_source_mode,
        "codex_status": codex_status,
        "harness": compatible_hint.harness if compatible_hint is not None else "",
        "harness_profile": compatible_hint.profile
        if compatible_hint is not None
        else "",
        "harness_config_path": (
            compatible_hint.source_path if compatible_hint is not None else ""
        ),
    }

    if provider == "openai":
        if transport == "codex_app_server":
            sources.update(
                protocol=transport_source,
                base_url=provider_default,
                auth_mode=SourceProvenance(
                    kind="codex_managed", name="Codex managed login"
                ),
                default_query=provider_default,
                default_headers=provider_default,
            )
            return ResolvedAgentRoute(
                protocol="codex_app_server",
                auth_mode="codex_managed",
                credential_variable="Codex managed login",
                credential_binding=CredentialBinding(
                    mode="codex_managed",
                    variable="Codex managed login",
                    configured=True,
                    source=SourceProvenance(
                        kind="codex_managed", name="Codex managed login"
                    ),
                ),
                field_sources=MappingProxyType(sources),
                **common,
            )
        base_candidate = _higher_precedence_candidate(unresolved, "openai_base_url")
        if base_candidate is not None:
            base_url = str(base_candidate.value or "").strip()
            base_source = base_candidate.source
        elif compatible_hint is not None and compatible_hint.base_url:
            base_url = compatible_hint.base_url
            base_source = hint_source
        else:
            base_url = ""
            base_source = provider_default
        sources.update(
            protocol=provider_default,
            base_url=base_source,
            auth_mode=provider_default,
            default_query=(
                hint_source
                if compatible_hint is not None and compatible_hint.default_query
                else provider_default
            ),
            default_headers=(
                hint_source
                if compatible_hint is not None and compatible_hint.env_headers
                else provider_default
            ),
        )
        credential_variable = (
            compatible_hint.env_key
            if compatible_hint is not None and compatible_hint.env_key
            else "OPENAI_API_KEY"
        )
        return ResolvedAgentRoute(
            protocol="responses",
            base_url=base_url,
            default_query=MappingProxyType(
                dict(compatible_hint.default_query)
                if compatible_hint is not None
                else {}
            ),
            header_variables=MappingProxyType(
                dict(compatible_hint.env_headers) if compatible_hint is not None else {}
            ),
            credential_variable=credential_variable,
            harness_credential_variable=(
                compatible_hint.env_key if compatible_hint is not None else ""
            ),
            credential_binding=CredentialBinding(
                mode="environment", variable=credential_variable
            ),
            field_sources=MappingProxyType(sources),
            **common,
        )

    if transport == "codex_app_server":
        raise RuntimeError(
            "codex_app_server transport currently supports only the openai provider"
        )
    endpoint_candidate = _higher_precedence_candidate(unresolved, "azure_endpoint")
    if endpoint_candidate is not None:
        endpoint = str(endpoint_candidate.value or "").strip()
        endpoint_source = endpoint_candidate.source
    elif compatible_hint is not None and compatible_hint.base_url:
        endpoint = compatible_hint.base_url
        endpoint_source = hint_source
    else:
        endpoint = ""
        endpoint_source = provider_default
    endpoint = _require(endpoint, "AZURE_OPENAI_ENDPOINT", provider)
    auth_mode, auth_source = _selected_text(unresolved, "azure_auth_mode")
    auth_mode = auth_mode.lower()
    if auth_mode not in {"api_key", "entra"}:
        raise RuntimeError("AZURE_OPENAI_AUTH_MODE must be api_key or entra")
    api_version, version_source = _selected_text(unresolved, "azure_api_version")
    sources.update(
        protocol=provider_default,
        base_url=endpoint_source,
        auth_mode=auth_source,
        api_version=version_source,
        default_query=(
            hint_source
            if compatible_hint is not None and compatible_hint.default_query
            else provider_default
        ),
        default_headers=(
            hint_source
            if compatible_hint is not None and compatible_hint.env_headers
            else provider_default
        ),
    )
    credential_variable = (
        "AzureDefaultCredential"
        if auth_mode == "entra"
        else compatible_hint.env_key
        if compatible_hint is not None and compatible_hint.env_key
        else "AZURE_OPENAI_API_KEY"
    )
    return ResolvedAgentRoute(
        protocol="responses",
        base_url=_azure_base_url(endpoint),
        auth_mode=auth_mode,
        api_version=api_version,
        default_query=MappingProxyType(
            dict(compatible_hint.default_query) if compatible_hint is not None else {}
        ),
        header_variables=MappingProxyType(
            dict(compatible_hint.env_headers) if compatible_hint is not None else {}
        ),
        credential_variable=credential_variable,
        harness_credential_variable=(
            compatible_hint.env_key if compatible_hint is not None else ""
        ),
        credential_binding=CredentialBinding(
            mode="azure_default" if auth_mode == "entra" else "environment",
            variable=credential_variable,
        ),
        field_sources=MappingProxyType(sources),
        **common,
    )


def resolve_unresolved_agent_route(
    unresolved: UnresolvedAgentConfig,
) -> ResolvedAgentRoute:
    """Resolve provider-specific details using shared selection and validation."""
    hint = unresolved.codex_hint
    provider, provider_source = _resolved_text_with_codex(
        unresolved, "provider", hint.provider if hint else "", "model_provider"
    )
    provider = _normalized_provider(provider)
    if provider not in PROVIDERS:
        raise RuntimeError(f"Unsupported analyst agent provider: {provider}")
    definition = PROVIDERS[provider]
    fields = dict(unresolved.fields)
    transport, transport_source = _selected_text(unresolved, "transport")
    if transport == "auto" or (
        transport_source.kind == "application_default"
        and unresolved.selection.get("detected_harness")
    ):
        harness = unresolved.selection.get("detected_harness")
        if (
            provider == "openai"
            and harness == "codex"
            and not (hint and (hint.base_url or hint.env_key))
        ):
            transport = "codex_app_server"
        elif provider == "anthropic" and harness == "claude_code":
            transport = "claude_agent_sdk"
        else:
            transport = "api"
        fields["transport"] = (
            _candidate(
                transport,
                kind="harness_detection",
                name="transport",
                explicit=False,
                present=True,
            ),
        )
        transport_source = fields["transport"][0].source
    if transport not in definition.transports:
        if transport == "codex_app_server":
            raise RuntimeError(
                "codex_app_server transport currently supports only the openai provider"
            )
        raise RuntimeError(f"{transport} transport does not support {provider}")
    endpoint_candidate = _higher_precedence_candidate(unresolved, "base_url")
    auth_candidate = _higher_precedence_candidate(unresolved, "auth_mode")
    key_candidate = _higher_precedence_candidate(unresolved, "api_key_env")
    compatible_hint = hint if hint is not None and hint.provider == provider else None
    if provider not in {"openai", "azure_openai"} and compatible_hint:
        if compatible_hint.protocol not in {"", definition.protocol}:
            raise RuntimeError(
                "Imported Codex protocol is incompatible with the selected provider"
            )
        if compatible_hint.default_query or compatible_hint.env_headers:
            raise RuntimeError(
                "This provider does not import Codex query/header settings; configure an explicit connection"
            )
        if not endpoint_candidate and compatible_hint.base_url:
            endpoint_candidate = _candidate(
                compatible_hint.base_url,
                kind="codex_route",
                name="base_url",
                location=compatible_hint.source_path,
                explicit=False,
                present=True,
            )
        if not key_candidate and compatible_hint.env_key:
            key_candidate = _candidate(
                compatible_hint.env_key,
                kind="codex_route",
                name="env_key",
                location=compatible_hint.source_path,
                explicit=False,
                present=True,
            )

    def prefer_environment(generic, specific):
        rank = {
            "cli": 0,
            "process_environment": 1,
            "repository_dotenv": 2,
            "shared_dotenv": 3,
            "execution_profile": 4,
            "harness_config": 5,
        }
        other = _higher_precedence_candidate(unresolved, specific)
        if (
            other
            and generic
            and rank.get(other.source.kind, 6) < rank.get(generic.source.kind, 6)
        ):
            return other
        return generic

    if provider in {"openai", "azure_openai"}:
        endpoint_candidate = prefer_environment(
            endpoint_candidate,
            "openai_base_url" if provider == "openai" else "azure_endpoint",
        )
    if provider == "azure_openai":
        auth_candidate = prefer_environment(auth_candidate, "azure_auth_mode")
    if key_candidate and not config_sources.ENV_NAME.fullmatch(
        str(key_candidate.value)
    ):
        raise RuntimeError(
            "AI_SKILLS_ANALYST_AGENT_API_KEY_ENV must name an environment variable"
        )
    if provider in {"openai", "azure_openai"}:
        if endpoint_candidate:
            fields["openai_base_url" if provider == "openai" else "azure_endpoint"] = (
                endpoint_candidate,
            )
        if auth_candidate and provider == "azure_openai":
            fields["azure_auth_mode"] = (auth_candidate,)
        route = _resolve_existing_provider_route(
            replace(unresolved, fields=MappingProxyType(fields))
        )
        if auth_candidate and str(auth_candidate.value) != route.auth_mode:
            raise RuntimeError(
                "Authentication mode is incompatible with the selected transport"
            )
    else:
        model, model_source = _resolved_text_with_codex(
            unresolved,
            "model",
            compatible_hint.model if compatible_hint else "",
            "model",
        )
        if not model or model_source.kind == "application_default":
            raise RuntimeError(
                f"{provider} requires an explicit model or imported model setting"
            )
        auth_mode = (
            str(auth_candidate.value)
            if auth_candidate
            else (
                "claude_managed"
                if transport == "claude_agent_sdk"
                else "api_key"
            )
        )
        if auth_mode not in definition.auth_modes or (
            transport == "claude_agent_sdk"
        ) != (auth_mode == "claude_managed"):
            raise RuntimeError(
                "Authentication mode is incompatible with the selected transport"
            )
        values: dict[str, Any] = {}
        provenance = {
            "provider": provider_source,
            "model": model_source,
            "transport": transport_source,
        }
        provenance["base_url"] = (
            endpoint_candidate.source
            if endpoint_candidate
            else SourceProvenance(kind="provider_default", name=f"{provider}.base_url")
        )
        provenance["auth_mode"] = (
            auth_candidate.source
            if auth_candidate
            else SourceProvenance(
                kind="provider_default", name=f"{provider}.{transport}.auth_mode"
            )
        )
        provenance["protocol"] = SourceProvenance(
            kind="provider_default", name=f"{provider}.{transport}.protocol"
        )
        for name, minimum in (
            ("timeout_seconds", 1),
            ("max_retries", 0),
            ("max_concurrency", 1),
        ):
            values[name], provenance[name] = _selected_int(
                unresolved, name, minimum=minimum
            )
        values["enabled"], provenance["enabled"] = _selected_bool(unresolved, "enabled")
        values["reasoning_effort"], provenance["reasoning_effort"] = (
            _resolved_text_with_codex(
                unresolved,
                "reasoning_effort",
                compatible_hint.reasoning_effort if compatible_hint is not None else "",
                "model_reasoning_effort",
            )
        )
        if provider == "anthropic" and values["reasoning_effort"] not in {
            "",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        }:
            raise RuntimeError(
                "Anthropic reasoning_effort must be low, medium, high, xhigh or max"
            )
        if provider == "anthropic" and (
            model in {"haiku", "claude-haiku-4-5", "claude-haiku-4-5-20251001"}
        ):
            # Haiku 4.5 has no effort parameter. In particular, a model switch
            # must not carry a saved/native Sonnet effort into SDK/API requests.
            values["reasoning_effort"] = ""
            provenance["reasoning_effort"] = SourceProvenance(
                kind="model_capability", name="Haiku 4.5 does not support effort"
            )
        key = (
            str(key_candidate.value)
            if key_candidate
            else definition.credential_variable
        )
        route = ResolvedAgentRoute(
            provider=provider,
            model=model,
            protocol=transport if transport != "api" else definition.protocol,
            base_url=str(endpoint_candidate.value)
            if endpoint_candidate
            else definition.base_url,
            auth_mode=auth_mode,
            credential_variable=key if auth_mode == "api_key" else "",
            credential_binding=CredentialBinding(
                mode="environment" if auth_mode == "api_key" else auth_mode,
                variable=key if auth_mode == "api_key" else "",
            ),
            field_sources=MappingProxyType(provenance),
            config_source_mode=_selected_text(unresolved, "config_source_mode")[0],
            harness=compatible_hint.harness
            if compatible_hint
            else unresolved.selection.get("detected_harness", ""),
            harness_profile=compatible_hint.profile if compatible_hint else "",
            harness_config_path=compatible_hint.source_path
            if compatible_hint
            else unresolved.selection.get("source_path", ""),
            codex_status=unresolved.codex_status,
            **values,
        )
    source_values = dict(route.field_sources)
    extras: dict[str, Any] = {}
    for name in (
        "model_context_tokens",
        "model_max_output_tokens",
        "read_timeout_seconds",
    ):
        extras[name], source_values[name] = _selected_int(
            unresolved, name, minimum=1 if name == "read_timeout_seconds" else 0
        )
    if (
        extras["model_context_tokens"]
        and extras["model_max_output_tokens"] >= extras["model_context_tokens"]
    ):
        raise RuntimeError(
            "Model output limit must be smaller than the configured context"
        )
    if endpoint_candidate:
        source_values["base_url"] = endpoint_candidate.source
    if key_candidate:
        if route.auth_mode != "api_key":
            raise RuntimeError(
                "api_key_env cannot be combined with managed login, Entra or unauthenticated execution"
            )
        extras["credential_variable"] = str(key_candidate.value)
        extras["harness_credential_variable"] = ""
        source_values["api_key_env"] = key_candidate.source
    return replace(
        route,
        base_url=validate_endpoint(route.base_url),
        field_sources=MappingProxyType(source_values),
        execution_profile=unresolved.selection.get("execution_profile", ""),
        config_file=unresolved.selection.get("config_file", ""),
        analysis_defaults=unresolved.analysis_defaults,
        analysis_profile=unresolved.analysis_profile,
        detected_harness=unresolved.selection.get("detected_harness", ""),
        **extras,
    )


def _merged_environment(
    environment: RepositoryEnvironment,
) -> tuple[dict[str, str], dict[str, SourceProvenance]]:
    values: dict[str, str] = {}
    sources: dict[str, SourceProvenance] = {}
    for layer in reversed(environment.priority_layers()):
        for name, raw_value in layer.values.items():
            value = str(raw_value or "").strip()
            if not value:
                continue
            values[name] = value
            sources[name] = SourceProvenance(
                kind=layer.kind,
                name=name,
                location=layer.location,
                explicit=True,
            )
    return values, sources


def hydrate_agent_execution(
    route: ResolvedAgentRoute,
    *,
    allow_missing_credentials: bool = False,
    environment: Mapping[str, str],
    environment_sources: Mapping[str, SourceProvenance] | None = None,
) -> ResolvedAgentExecution:
    """Hydrate one resolved route with environment-backed credentials."""

    environment_values = environment
    source_values = environment_sources or {}

    def environment_value(name: str) -> str:
        return str(environment_values.get(name) or "").strip()

    if route.protocol in {"codex_app_server", "claude_agent_sdk"}:
        if route.protocol == "claude_agent_sdk":
            # Managed login does not hydrate API credentials. The SDK adapter
            # clears inherited credential variables only in its child environment.
            return ResolvedAgentExecution(route=route)
        sources = dict(route.field_sources)
        credential_source = SourceProvenance(
            kind="codex_managed", name="Codex managed login"
        )
        sources["credential"] = credential_source
        hydrated_route = replace(
            route,
            field_sources=MappingProxyType(sources),
            credential_binding=CredentialBinding(
                mode="codex_managed",
                variable="Codex managed login",
                configured=True,
                source=credential_source,
            ),
        )
        return ResolvedAgentExecution(
            route=hydrated_route,
            inputs=HydratedProviderInputs(credential_present=True),
        )

    header_values = {
        header: value
        for header, variable in route.header_variables.items()
        if (value := environment_value(variable))
    }
    header_bindings = {
        header: CredentialBinding(
            mode="environment",
            variable=variable,
            configured=header in header_values,
            source=(
                source_values.get(variable)
                if header in header_values
                else SourceProvenance(kind="missing", name=variable)
            ),
        )
        for header, variable in route.header_variables.items()
    }
    standard_variable = (
        route.credential_variable
        if "api_key_env" in route.field_sources
        else PROVIDERS[route.provider].credential_variable
    )
    api_key = environment_value(standard_variable)
    credential_variable = standard_variable
    credential_source = (
        source_values.get(standard_variable)
        or SourceProvenance(
            kind="process_environment",
            name=standard_variable,
            location="process",
            explicit=True,
        )
        if api_key
        else SourceProvenance(kind="missing", name=standard_variable)
    )
    if not api_key and route.harness_credential_variable:
        credential_variable = route.harness_credential_variable
        api_key = environment_value(credential_variable)
        credential_source = (
            source_values.get(credential_variable)
            or SourceProvenance(
                kind="process_environment",
                name=credential_variable,
                location="process",
                explicit=True,
            )
            if api_key
            else SourceProvenance(kind="missing", name=credential_variable)
        )

    sources = dict(route.field_sources)
    azure_client_secret: dict[str, str] = {}
    credential_mode = "environment"
    if route.provider == "azure_openai" and route.auth_mode == "entra":
        if environment_value("AZURE_CLIENT_SECRET"):
            for parameter, variable in (
                ("tenant_id", "AZURE_TENANT_ID"),
                ("client_id", "AZURE_CLIENT_ID"),
                ("client_secret", "AZURE_CLIENT_SECRET"),
            ):
                value = environment_value(variable)
                _require(value, variable, route.provider)
                azure_client_secret[parameter] = value
            credential_variable = "AZURE_CLIENT_SECRET"
            credential_source = source_values.get(credential_variable) or SourceProvenance(
                kind="process_environment", name=credential_variable, location="process", explicit=True,
            )
            credential_mode = "azure_client_secret"
        else:
            credential_variable = "AzureDefaultCredential"
            credential_source = SourceProvenance(
                kind="provider_default", name="AzureDefaultCredential"
            )
            credential_mode = "azure_default"
    elif not allow_missing_credentials:
        _require(
            api_key, credential_variable or route.credential_variable, route.provider
        )
    sources["credential"] = credential_source
    configured = bool(api_key) or route.auth_mode == "entra"
    hydrated_route = replace(
        route,
        field_sources=MappingProxyType(sources),
        header_bindings=MappingProxyType(header_bindings),
        credential_binding=CredentialBinding(
            mode=credential_mode,
            variable=credential_variable or route.credential_variable,
            configured=configured,
            source=(
                credential_source
                if isinstance(credential_source, SourceProvenance)
                else None
            ),
        ),
    )

    return ResolvedAgentExecution(
        route=hydrated_route,
        inputs=HydratedProviderInputs(
            api_key=api_key,
            default_headers=MappingProxyType(header_values),
            azure_client_secret=MappingProxyType(azure_client_secret),
            credential_present=configured,
        ),
    )


def resolve_agent_execution(
    *,
    cli_values: Mapping[str, Any] | None = None,
    repo_root: Path = REPO_ROOT,
    process_environment: Mapping[str, str] | None = None,
    allow_missing_credentials: bool = False,
) -> ResolvedAgentExecution:
    """Collect, resolve, and hydrate one immutable operation snapshot exactly once."""

    layers = repository_environment(
        repo_root,
        process_environment=process_environment,
    )
    unresolved = collect_unresolved_agent_config(
        cli_values=cli_values,
        repo_root=repo_root,
        environment=layers,
    )
    route = resolve_unresolved_agent_route(unresolved)
    values, sources = _merged_environment(layers)
    return hydrate_agent_execution(
        route,
        allow_missing_credentials=allow_missing_credentials,
        environment=values,
        environment_sources=sources,
    )
