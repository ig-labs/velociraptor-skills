"""Bounded, non-secret execution profile and harness routing imports.

No authentication stores, hooks, helpers or model endpoints are accessed here.
Only the selected file/source is imported. Profiles do not mutate os.environ.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PREFIX = "AI_SKILLS_ANALYST_AGENT_"
MAX_CONFIG_BYTES = 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
EXECUTION_FIELDS = frozenset(
    {
        "model",
        "transport",
        "enabled",
        "reasoning_effort",
        "timeout_seconds",
        "read_timeout_seconds",
        "max_retries",
        "max_concurrency",
        "model_context_tokens",
        "model_max_output_tokens",
    }
)
CONNECTION_FIELDS = frozenset(
    {"provider", "base_url", "auth_mode", "api_key_env", "api_version"}
)
PROFILE_BUDGET_FIELDS = frozenset({"max_input_tokens", "max_output_tokens"})
ANALYSIS_FIELDS = frozenset(
    {
        "context_window_tokens",
        "max_input_tokens",
        "token_encoding",
        "max_analysis_item_tokens",
        "max_output_tokens",
        "validation_correction_attempts",
        "synthesis_correction_attempts",
    }
)


@dataclass
class Selection:
    values: dict[str, Any] = field(default_factory=dict)
    origins: dict[str, str] = field(default_factory=dict)
    path: str = ""
    profile: str = ""
    harness: str = ""
    source_path: str = ""
    analysis_defaults: dict[str, Any] = field(default_factory=dict)
    analysis_profile: dict[str, Any] = field(default_factory=dict)


def setting(layers: Any, variable: str) -> str:
    for layer in layers.priority_layers():
        value = str(layer.values.get(variable) or "").strip()
        if value:
            return value
    return ""


def expand_path(value: str, home: str, relative_to: Path | None = None) -> Path:
    for marker in ("~", "$HOME", "${HOME}"):
        if value == marker or value.startswith(marker + "/"):
            value = home + value[len(marker) :]
            break
    path = Path(value)
    if not path.is_absolute() and relative_to is not None:
        path = relative_to / path
    return path.resolve()


def default_config_path(environment: Mapping[str, str]) -> Path:
    root = environment.get("XDG_CONFIG_HOME")
    return (
        (
            Path(root)
            if root
            else Path(environment.get("HOME") or Path.home()) / ".config"
        )
        / "vraptor"
        / "analyst-agents.toml"
    )


def migrate_default_config(path: Path) -> None:
    """Move the legacy default without copying bytes/mode or replacing a destination."""
    legacy = path.parent.parent / "ai_skills" / path.name
    if path.exists() or path.is_symlink() or not legacy.is_file():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Both defaults share the configuration root. link is atomic and exclusive.
        os.link(legacy, path)
    except FileExistsError:
        return
    legacy.unlink()


def resolve_config_path(layers: Any, cli: Mapping[str, Any]) -> tuple[Path, bool]:
    """Return the shared read/write destination and whether it was explicit."""
    from vraptor.settings import active_value

    env = layers.process.values
    raw_path = str(
        cli.get("config_file")
        or setting(layers, PREFIX + "CONFIG_FILE")
        or active_value("analyst_config_file")
        or ""
    )
    home = str(env.get("HOME") or Path.home())
    if raw_path:
        path = expand_path(raw_path, home)
    else:
        path = default_config_path(env)
        migrate_default_config(path)
        path = path.resolve()
    return path, bool(raw_path)


def read_config(path: Path, *, json_format: bool = False) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise RuntimeError("Agent configuration exceeds the 1 MiB size limit")
        data = json.loads(raw) if json_format else tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        # Parser diagnostics can contain literal secret values from the source.
        raise RuntimeError("Invalid JSON/TOML agent configuration") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Agent configuration must be an object")
    return data


def _fields(value: Any, allowed: frozenset[str], section: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - allowed:
        raise RuntimeError(f"Invalid or unknown fields in {section}")
    for name, item in value.items():
        if name == "enabled":
            valid = isinstance(item, bool)
        elif name.endswith("correction_attempts"):
            valid = (
                isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 5
            )
        elif name.endswith(("_tokens", "_seconds")) or name in {
            "max_concurrency",
            "max_retries",
        }:
            valid = (
                isinstance(item, int)
                and not isinstance(item, bool)
                and item >= (0 if name == "max_retries" else 1)
            )
        else:
            valid = isinstance(item, str) and bool(item.strip())
        if not valid:
            raise RuntimeError(f"Invalid {section}.{name}")
    if "api_key_env" in value and not ENV_NAME.fullmatch(value["api_key_env"]):
        raise RuntimeError("api_key_env must name an environment variable")
    return dict(value)


def _named_tables(data: Mapping[str, Any], section: str) -> dict[str, Any]:
    entries = data.get(section, {})
    if not isinstance(entries, dict):
        raise RuntimeError(f"{section} must be a table")
    for name, value in entries.items():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise RuntimeError(f"Invalid name in {section}")
        if not isinstance(value, dict):
            raise RuntimeError(f"Entries in {section} must be tables")
    return entries


def _connection(value: Any) -> dict[str, Any]:
    from vraptor.agent.registry import PROVIDERS, validate_endpoint

    result = _fields(value, CONNECTION_FIELDS, "connection")
    provider = result.get("provider")
    if provider not in PROVIDERS:
        raise RuntimeError("Connection requires a supported provider")
    if result.get("auth_mode", "api_key") not in PROVIDERS[provider].auth_modes:
        raise RuntimeError("Connection authentication is incompatible with provider")
    validate_endpoint(result.get("base_url", ""))
    return result


def _source(value: Any) -> dict[str, Any]:
    result = _fields(value, frozenset({"kind", "path", "profile"}), "source")
    if result.get("kind") not in {"codex", "claude_code"}:
        raise RuntimeError("Configuration source kind must be codex or claude_code")
    if result["kind"] == "claude_code" and "profile" in result:
        raise RuntimeError(
            "Named harness profiles are supported only for Codex sources"
        )
    return result


def normalize_document(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate once and return an independent version-2 document without file I/O."""
    version = data.get("schema_version")
    if type(version) is not int or version != 2:
        raise RuntimeError("analyst-agents.toml requires schema_version = 2")
    sections = {
        "schema_version",
        "selection",
        "execution_defaults",
        "analysis_defaults",
        "connections",
        "profiles",
    }
    if set(data) - sections:
        raise RuntimeError("Unknown analyst configuration section")
    selection = _fields(
        data.get("selection", {}), frozenset({"default_profile"}), "selection"
    )
    defaults = _fields(
        data.get("execution_defaults", {}),
        EXECUTION_FIELDS - {"model"},
        "execution_defaults",
    )
    analysis_defaults = _fields(
        data.get("analysis_defaults", {}), ANALYSIS_FIELDS, "analysis_defaults"
    )
    connections = {
        name: _connection(value)
        for name, value in _named_tables(data, "connections").items()
    }
    profiles = {}
    for name, value in _named_tables(data, "profiles").items():
        profile = _fields(
            {key: item for key, item in value.items() if key != "source"},
            EXECUTION_FIELDS
            | CONNECTION_FIELDS
            | PROFILE_BUDGET_FIELDS
            | {"connection"},
            "profiles",
        )
        if "source" in value:
            profile["source"] = _source(value["source"])
        if sum(key in profile for key in ("provider", "connection", "source")) != 1:
            raise RuntimeError(
                "Profile requires exactly one inline provider, connection reference or source"
            )
        if "provider" in profile:
            _connection(
                {key: item for key, item in profile.items() if key in CONNECTION_FIELDS}
            )
        elif CONNECTION_FIELDS.intersection(profile):
            raise RuntimeError(
                "Connection settings cannot be combined with a connection reference or source"
            )
        if "connection" in profile and profile["connection"] not in connections:
            raise RuntimeError("Profile references a missing connection")
        profiles[name] = profile
    if (
        selection.get("default_profile")
        and selection["default_profile"] not in profiles
    ):
        raise RuntimeError("Default execution profile does not exist")
    result: dict[str, Any] = {"schema_version": 2, "profiles": profiles}
    for section, values in (
        ("selection", selection),
        ("execution_defaults", defaults),
        ("analysis_defaults", analysis_defaults),
        ("connections", connections),
    ):
        if section in data:
            result[section] = values
    return result


def detect_harness(environment: Mapping[str, str]) -> str:
    explicit = environment.get(PREFIX + "HARNESS", "").strip()
    if explicit:
        if explicit not in {"codex", "claude_code", "none"}:
            raise RuntimeError(
                "AI_SKILLS_ANALYST_AGENT_HARNESS must be codex, claude_code or none"
            )
        return "" if explicit == "none" else explicit
    signals = []
    if environment.get("CODEX_THREAD_ID"):
        signals.append("codex")
    if environment.get("CLAUDECODE") == "1":
        signals.append("claude_code")
    if len(signals) > 1:
        raise RuntimeError(
            "Ambiguous active harness; select an execution profile or set AI_SKILLS_ANALYST_AGENT_HARNESS"
        )
    return signals[0] if signals else ""


def claude_settings_path(
    home: str, explicit: str = "", base: Path | None = None
) -> Path:
    """Resolve one settings source; explicit and malformed files never fall back."""
    if explicit:
        path = expand_path(explicit, home, base)
        if not path.is_file():
            raise RuntimeError(
                "Selected Claude harness configuration file does not exist"
            )
        return path
    candidates = (
        Path(home) / "Library/Application Support/Claude/settings.json",
        Path(home) / ".claude/settings.json",
    )
    path = next((path for path in candidates if path.exists()), candidates[0])
    if path.exists() and not path.is_file():
        raise RuntimeError("Selected Claude settings path is not a file")
    return path


def import_claude_settings(
    path: Path, environment: Mapping[str, str]
) -> dict[str, Any]:
    data = read_config(path, json_format=True) if path.exists() else {}
    env = data.get("env", {})
    if not isinstance(env, dict):
        raise RuntimeError("Invalid Claude settings environment")
    # Routing imports never execute apiKeyHelper or import authentication values.
    for name in (
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    ):
        if str(environment.get(name) or env.get(name) or "").lower() not in {
            "",
            "0",
            "false",
        }:
            raise RuntimeError(
                "This Claude hosting provider is not supported; configure a supported execution profile"
            )
    model = (
        environment.get("ANTHROPIC_MODEL")
        or data.get("model")
        or env.get("ANTHROPIC_MODEL")
    )
    if not isinstance(model, str) or not model.strip():
        raise RuntimeError(
            "Claude model is unavailable; set AI_SKILLS_ANALYST_AGENT_MODEL or a model in Claude settings"
        )
    values = {"provider": "anthropic", "model": model.strip()}
    endpoint = environment.get("ANTHROPIC_BASE_URL") or env.get("ANTHROPIC_BASE_URL")
    if endpoint:
        values["base_url"] = str(endpoint)
    effort = environment.get("CLAUDE_CODE_EFFORT_LEVEL") or data.get("effortLevel")
    if effort and effort != "auto":
        values["reasoning_effort"] = str(effort)
    return values


def load_document(layers: Any, cli: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Read the selected TOML without opening any harness source or credential store."""
    path, explicit_path = resolve_config_path(layers, cli)
    if not path.is_file():
        if explicit_path:
            raise RuntimeError("Selected analyst configuration file does not exist")
        return {}, ""
    return normalize_document(read_config(path)), str(path)


def load_selection(layers: Any, cli: Mapping[str, Any]) -> Selection:
    """Read one optional profile document and at most its selected harness source."""
    env = layers.process.values
    home = str(env.get("HOME") or Path.home())
    profile = str(cli.get("execution_profile") or setting(layers, PREFIX + "PROFILE"))
    mode = str(
        cli.get("config_source_mode")
        or setting(layers, PREFIX + "CONFIG_SOURCE")
        or "auto"
    )
    data, config_path = load_document(layers, cli)
    result = Selection(
        path=config_path, analysis_defaults=dict(data.get("analysis_defaults", {}))
    )
    path = Path(config_path)
    if not profile and mode in {"auto", "application"}:
        profile = data.get("selection", {}).get("default_profile", "")
    if profile:
        selected = data.get("profiles", {}).get(profile)
        if selected is None:
            raise RuntimeError("Selected execution profile does not exist")
        result.profile = profile
        result.analysis_profile = {
            key: selected[key] for key in PROFILE_BUDGET_FIELDS if key in selected
        }
        values = dict(data.get("execution_defaults", {}))
        source = selected.get("source")
        if source:
            kind = source["kind"]
            source_path = (
                claude_settings_path(
                    home,
                    setting(layers, PREFIX + "CLAUDE_CONFIG") or source.get("path", ""),
                    path.parent,
                )
                if kind == "claude_code"
                else expand_path(
                    source.get("path", home + "/.codex/config.toml"), home, path.parent
                )
            )
            if kind == "codex" and not source_path.is_file():
                raise RuntimeError("Selected harness configuration file does not exist")
            inherited = dict(env)
            if kind == "claude_code" and (
                model := cli.get("model")
                or setting(layers, PREFIX + "MODEL")
                or selected.get("model")
            ):
                inherited["ANTHROPIC_MODEL"] = str(model)
            imported = (
                import_claude_settings(source_path, inherited)
                if kind != "codex"
                else {}
            )
            values.update(imported)
            result.harness, result.source_path = kind, str(source_path)
            if kind == "codex":
                values.update(
                    codex_config=str(source_path),
                    codex_profile=source.get("profile", ""),
                )
            result.origins.update({key: "harness_config" for key in imported})
        elif "connection" in selected:
            values.update(data["connections"][selected["connection"]])
        values.update(
            {
                key: value
                for key, value in selected.items()
                if key in EXECUTION_FIELDS | CONNECTION_FIELDS
            }
        )
        for key in selected:
            result.origins.pop(key, None)
        result.values = values
        return result
    explicit_provider = cli.get("provider") or setting(layers, PREFIX + "PROVIDER")
    if mode == "application" or explicit_provider:
        return result
    hint_environment = dict(env)
    if explicit_harness := setting(layers, PREFIX + "HARNESS"):
        hint_environment[PREFIX + "HARNESS"] = explicit_harness
    harness = (
        "claude_code"
        if mode == "claude_code"
        else "codex"
        if mode == "codex"
        else detect_harness(hint_environment)
    )
    if not harness:
        if (Path(home) / ".codex/config.toml").is_file() and claude_settings_path(
            home
        ).exists():
            raise RuntimeError(
                "Multiple harness configurations found without an active caller; select an execution profile"
            )
        return result
    # Codex imports retain their existing query/header/profile precedence handling.
    if harness == "codex":
        result.harness = harness
        return result
    result.source_path = str(
        claude_settings_path(home, setting(layers, PREFIX + "CLAUDE_CONFIG"))
    )
    inherited = dict(env)
    explicit_model = cli.get("model") or setting(layers, PREFIX + "MODEL")
    if explicit_model:
        inherited["ANTHROPIC_MODEL"] = str(explicit_model)
    result.values = import_claude_settings(Path(result.source_path), inherited)
    result.values["transport"] = "claude_agent_sdk"
    result.origins = {key: "harness_config" for key in result.values}
    result.harness = harness
    return result
