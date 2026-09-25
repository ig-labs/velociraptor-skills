"""Operator setup, diagnosis and explicitly requested live model checks."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from vraptor.agent.config import REPO_ROOT, resolve_agent_execution
from vraptor.agent.model_budgets import (
    MIN_INPUT_TOKENS,
    MIN_OUTPUT_TOKENS,
    model_budget,
)
from vraptor.agent.registry import PROVIDERS
from vraptor.agent.sources import (
    NAME,
    claude_settings_path,
    expand_path,
    normalize_document,
    read_config,
    resolve_config_path,
)
from vraptor.paths import repository_environment


# Offline examples checked 2026-09-23; these are hints, never a model allowlist.
# https://developers.openai.com/api/docs/models
# https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.6
# https://platform.claude.com/docs/en/models/overview
# https://code.claude.com/docs/en/model-config
_MODEL_EXAMPLES = {
    "openai": (
        ("gpt-6-astra", "Demanding reasoning and complex workflows"),
        ("gpt-6-sol", "Balanced coding and analysis"),
        ("gpt-6-luna", "Efficient, high-volume tasks"),
        ("gpt-5.6-sol", "Previous-generation flagship"),
        ("gpt-5.6-terra", "Previous-generation balanced option"),
        ("gpt-5.6-luna", "Previous-generation economical option"),
    ),
    "anthropic": (
        ("claude-haiku-4-5-20251001", "Fast extraction and simple classification"),
        ("claude-sonnet-5", "Balanced analysis and coding"),
        ("claude-opus-5-5", "Complex reasoning and demanding analysis"),
        ("claude-fable-5-1", "Hard reasoning and long-running tasks"),
    ),
}


def _model_options_help(provider: str, harness: str = "") -> str:
    """Share offline model hints between CLI help and the interactive prompt."""
    if provider == "azure_openai":
        return "Azure: enter your deployment name, which may differ from the model ID."
    label = "Claude / Anthropic" if provider == "anthropic" else "OpenAI"
    lines = [f"{label} model examples:"]
    for model, purpose in _MODEL_EXAMPLES[provider]:
        lines.append(f"  {model:<27} {purpose}")
    lines.append(
        "Other supported model IDs are accepted; availability varies by account/client."
    )
    if harness == "claude_code":
        lines.append("Claude Code also accepts aliases: sonnet, opus, haiku, fable.")
    elif harness == "codex":
        lines.append(
            "Codex can inherit its model; an Azure-backed source needs its deployment name."
        )
    return "\n".join(lines)


def _claude_effort_levels(model: str) -> tuple[str, ...]:
    """Known effort-capable families; unknown models receive no automatic effort."""
    selected = model.lower()
    if selected.startswith(("claude-opus-4-6", "claude-sonnet-4-6")):
        return ("low", "medium", "high", "max")
    if selected.startswith("claude-opus-4-5"):
        return ("low", "medium", "high")
    if selected in {"opus", "sonnet", "fable"} or selected.startswith(
        (
            "claude-opus-5",
            "claude-sonnet-5",
            "claude-fable-5",
            "claude-opus-4-7",
            "claude-opus-4-8",
        )
    ):
        return ("low", "medium", "high", "xhigh", "max")
    return ()


def _reasoning_options_help(provider: str, model: str = "") -> str:
    """Offline effort guidance; unknown models/deployments keep free-form input.

    References: OpenAI model pages and Claude's build-with-claude/effort guide.
    """
    levels = ("low", "medium", "high", "xhigh", "max")
    selected = model.lower()
    if provider == "anthropic":
        label = "Claude / Anthropic"
        if selected == "haiku" or selected.startswith("claude-haiku-"):
            return (
                "Haiku does not support a reasoning-effort setting; leave it unset.\n"
                "Setup clears any saved or inherited effort for Haiku."
            )
        levels = _claude_effort_levels(model)
        if not levels:
            return (
                "Claude / Anthropic reasoning efforts (model-dependent):\n"
                "  Sonnet 5, Opus 5/5.5, Fable 5/5.1: low, medium, high, xhigh, max\n"
                "  Opus/Sonnet 4.6: low, medium, high, max\n"
                "  Haiku: no effort setting\n"
                "Aliases depend on the model selected by your client. Enter keeps/inherits the displayed setting."
            )
    else:
        label = "OpenAI"
        legacy_gpt5 = selected == "gpt-5" or selected.startswith("gpt-5-2025-")
        if (
            provider == "azure_openai"
            or not legacy_gpt5
            and not selected.startswith(
                (
                    "gpt-6-astra",
                    "gpt-6-sol",
                    "gpt-6-luna",
                    "gpt-5.6",
                )
            )
        ):
            return (
                "OpenAI reasoning efforts (model-dependent):\n"
                "  GPT-6 Astra: low, medium, high, xhigh, max\n"
                "  GPT-6 Sol/Luna and GPT-5.6: none, low, medium, high, xhigh, max\n"
                "  GPT-5: minimal, low, medium, high\n"
                "Other models and Azure deployments may support fewer levels.\n"
                "Enter keeps/inherits the displayed setting."
            )
        if legacy_gpt5:
            levels = ("minimal", "low", "medium", "high")
        elif not selected.startswith("gpt-6-astra"):
            levels = ("none", *levels)
    meanings = {
        "none": "No reasoning effort (supported models only)",
        "minimal": "Minimal reasoning for older GPT-5 models",
        "low": "Faster, lower token usage",
        "medium": "Balance depth, speed and token usage",
        "high": "Deeper reasoning for complex tasks",
        "xhigh": "Additional reasoning effort",
        "max": "Highest reasoning effort; greater token usage",
    }
    return "\n".join(
        [
            f"{label} reasoning efforts for {model}:",
            *(f"  {level:<8} {meanings[level]}" for level in levels),
            "Enter keeps/inherits the displayed setting. Support depends on the model and client.",
        ]
    )


def parser_for(command: str) -> argparse.ArgumentParser:
    descriptions = {
        "setup": "Create or update a named AI profile. Interactive prompts keep saved values on Enter.",
        "doctor": "Check configuration, token budgets and dependencies without model inference.",
        "models": "List provider model metadata online; Claude reports native login status only.",
        "test": "Send one small synthetic model request to check inference (may incur usage).",
        "login": "Sign in using the native Codex or Claude Code CLI; vraptor does not copy login tokens.",
    }
    parser = argparse.ArgumentParser(
        prog=f"vraptor ai {command}",
        usage="%(prog)s [options]",
        description=descriptions[command],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vraptor ai setup --from-harness codex\n"
            "  vraptor ai setup --from-harness claude_code\n"
            "  vraptor ai setup --provider openai\n"
            "  vraptor ai setup --provider anthropic --model MODEL_ID\n\n"
            "Claude settings discovery:\n"
            "  Explicit --harness-config or saved path, then\n"
            "  ~/Library/Application Support/Claude/settings.json, then\n"
            "  ~/.claude/settings.json. No file is required with --model.\n"
            "  Desktop config.json login caches are not imported.\n\n"
            + _model_options_help("openai")
            + "\n\n"
            + _model_options_help("anthropic", "claude_code")
            + "\n\n"
            + _reasoning_options_help("openai")
            + "\n\n"
            + _reasoning_options_help("anthropic")
            if command == "setup"
            else None
        ),
    )
    if command == "login":
        parser.add_argument(
            "--harness",
            required=True,
            choices=("codex", "claude_code"),
            help="codex: Codex login; claude_code: Claude Code login.",
        )
        return parser
    selection = parser.add_argument_group("Profile selection")
    selection.add_argument(
        "--config-file",
        metavar="PATH",
        help="Analyst TOML file (default: ~/.config/vraptor/analyst-agents.toml).",
    )
    selection.add_argument(
        "--execution-profile",
        metavar="NAME",
        help="Named profile; setup otherwise selects by config type.",
    )
    if command == "doctor":
        parser.add_argument(
            "--live",
            action="store_true",
            help="Check authentication/model metadata online, or native Claude login status; no inference.",
        )
    elif command == "setup":
        selection.add_argument(
            "--profile-name",
            metavar="NAME",
            help="Custom name for the new or selected profile; skips the name prompt.",
        )
        selection.add_argument(
            "--set-default",
            action="store_true",
            help="Make this profile the default; otherwise keep the saved selection.",
        )
        connection = parser.add_argument_group("Connection and authentication")
        choice = connection.add_mutually_exclusive_group()
        choice.add_argument(
            "--provider",
            choices=sorted(PROVIDERS),
            help="Direct API connection; anthropic uses ANTHROPIC_API_KEY.",
        )
        choice.add_argument(
            "--from-harness",
            choices=("codex", "claude_code"),
            help="Import native settings: codex (Codex) or claude_code (Claude managed login).",
        )
        connection.add_argument(
            "--harness-config",
            metavar="PATH",
            help="Explicit native settings file; a missing file is an error.",
        )
        connection.add_argument(
            "--base-url",
            metavar="URL",
            help="API endpoint override; required for Azure OpenAI.",
        )
        connection.add_argument(
            "--api-key-env",
            metavar="VARIABLE",
            help="Environment variable containing the API key; never pass the key itself.",
        )
        connection.add_argument(
            "--auth-mode",
            choices=("api_key", "entra"),
            help="Direct API authentication; entra is Azure only.",
        )
        model = parser.add_argument_group("Model and execution")
        model.add_argument(
            "--model",
            metavar="MODEL_ID",
            help="Model ID, or Azure deployment name; overrides the imported model. Interactive setup lists examples and accepts other supported IDs.",
        )
        model.add_argument(
            "--reasoning-effort",
            metavar="LEVEL",
            help="Model-supported reasoning effort; interactive setup lists the options. Enter keeps or inherits the saved setting.",
        )
        model.add_argument(
            "--timeout-seconds",
            type=int,
            metavar="SECONDS",
            help="Per-operation timeout (new profiles: 600).",
        )
        model.add_argument(
            "--max-concurrency",
            type=int,
            metavar="COUNT",
            help="Maximum concurrent requests (new profiles: 20).",
        )
        budgets = parser.add_argument_group("Analysis token budgets")
        budgets.add_argument(
            "--auto-token-budgets",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Default: use maximum model output and remaining standard-price input; Haiku defaults to 120000 input / 64000 output. Use --no-auto-token-budgets to retain valid saved budgets. Explicit token flags win.",
        )
        budgets.add_argument(
            "--max-input-tokens",
            type=int,
            metavar="TOKENS",
            help="Explicit input budget; minimum 100000. Overrides automatic budgeting within model and standard-price limits. OpenAI/Azure fallback: 272000.",
        )
        budgets.add_argument(
            "--max-output-tokens",
            type=int,
            metavar="TOKENS",
            help="Explicit output budget; minimum 32000, maximum set by model/context limits. Defaults to the model maximum: Haiku 64000; OpenAI/Azure fallback 128000.",
        )
        advanced = parser.add_argument_group("Advanced transport and model limits")
        advanced.add_argument(
            "--transport",
            choices=("api", "codex_app_server", "claude_agent_sdk"),
            help="Runtime override; normally selected from the connection type.",
        )
        advanced.add_argument(
            "--model-context-tokens",
            type=int,
            metavar="TOKENS",
            help="Optional deployed-model context ceiling; validated with the budgets.",
        )
        advanced.add_argument(
            "--model-max-output-tokens",
            type=int,
            metavar="TOKENS",
            help="Optional deployed-model output ceiling.",
        )
    elif command == "test":
        parser.add_argument(
            "--max-output-tokens",
            type=int,
            default=256,
            help="Synthetic request output cap: 1-4096 (default: 256).",
        )
    return parser


def _toml(data: dict[str, Any]) -> str:
    """Serialize the deliberately small validated profile schema."""
    lines = [f"schema_version = {data['schema_version']}", ""]

    def scalar(value: Any) -> str:
        if isinstance(value, dict):
            return (
                "{ "
                + ", ".join(f"{key} = {scalar(item)}" for key, item in value.items())
                + " }"
            )
        return (
            str(value).lower()
            if isinstance(value, bool)
            else str(value)
            if isinstance(value, int)
            else json.dumps(value, ensure_ascii=False)
        )

    for group in (
        "selection",
        "execution_defaults",
        "analysis_defaults",
        "connections",
        "profiles",
    ):
        if group not in data:
            continue
        table = data[group]
        if group == "analysis_defaults":
            lines.append(
                "# Check these token budgets against your deployed model's context/output limits."
            )
        sections = (
            table.items() if group in {"connections", "profiles"} else [(None, table)]
        )
        for name, values in sections:
            # Profile names permit dots, which need quoting to remain one key.
            table_name = json.dumps(name) if name and "." in name else name
            lines.append(f"[{group}" + ("." + table_name if name else "") + "]")
            for key, value in values.items():
                line = f"{key} = {scalar(value)}"
                if (
                    group == "profiles"
                    and key == "model"
                    and _profile_type(values, data.get("connections", {}))
                    == "azure_openai"
                ):
                    line += "  # Must match your Azure deployment name"
                lines.append(line)
            lines.append("")
    return "\n".join(lines)


def _atomic_write(path: Path, content: bytes) -> None:
    """Replace one file with an owner-only, fully written copy."""
    handle, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _profile_type(profile: dict[str, Any], connections: dict[str, Any]) -> str:
    if source := profile.get("source"):
        return source["kind"]
    if "connection" in profile:
        return connections[profile["connection"]]["provider"]
    return profile["provider"]


def _validate_profile_name(name: str) -> None:
    if name == "default":
        raise RuntimeError(
            "Use a descriptive profile name, such as azure or codex; default is reserved"
        )
    if not NAME.fullmatch(name):
        raise RuntimeError(
            "Profile names must contain 1-100 letters, digits, underscores, dots or hyphens"
        )


def _rename_profile(data: dict[str, Any], old: str, new: str) -> None:
    if new in data["profiles"]:
        raise RuntimeError("Profile name already exists; choose another name")
    data["profiles"][new] = data["profiles"].pop(old)
    selection = data.get("selection", {})
    if selection.get("default_profile") == old:
        selection["default_profile"] = new


def _rename_default_profile(data: dict[str, Any]) -> dict[str, str]:
    """Give the old generic profile a unique name and repair its selection reference."""
    profiles = data["profiles"]
    if "default" not in profiles:
        return {}
    kind = _profile_type(profiles["default"], data.get("connections", {}))
    base = "azure" if kind == "azure_openai" else kind
    name = base
    suffix = 2
    while name in profiles:
        name = f"{base}_{suffix}"
        suffix += 1
    _rename_profile(data, "default", name)
    return {"default": name}


def _setup_profile_name(
    data: dict[str, Any], config_type: str, requested: str | None
) -> str:
    """Choose one matching profile without reading any harness configuration."""
    types = {
        name: _profile_type(profile, data.get("connections", {}))
        for name, profile in data["profiles"].items()
    }
    name = requested or ("azure" if config_type == "azure_openai" else config_type)
    if not requested:
        matches = [key for key, value in types.items() if value == config_type]
        if len(matches) > 1:
            raise RuntimeError(
                "Multiple profiles match this config type; select one with --execution-profile"
            )
        if matches:
            name = matches[0]
    if name in types and types[name] != config_type:
        raise RuntimeError(
            "Execution profile belongs to a different config type; choose another --execution-profile"
        )
    return name


def _setup_value(
    args: argparse.Namespace,
    field: str,
    label: str,
    default: Any,
    *,
    integer: bool = False,
    required: bool = True,
) -> Any:
    """Explicit flags win; Enter keeps the saved value or suggested default."""
    value = getattr(args, field)
    if value is None:
        value = default
        if os.isatty(0):
            hint = (
                str(default)
                if default is not None
                else "required"
                if required
                else "inherit"
            )
            answer = input(f"{label} [{hint}] (Enter to keep): ").strip()
            if answer:
                value = answer
    if value is None or value == "":
        if required:
            raise RuntimeError(f"Setup requires --{field.replace('_', '-')}")
        return None
    if integer:
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"{label} must be a positive integer") from exc
        if value < 1:
            raise RuntimeError(f"{label} must be a positive integer")
    return value


def _setup_budget(args, field, label, default, maximum):
    """Clamp interactive choices; reject invalid explicit flags before writing."""
    minimum = MIN_INPUT_TOKENS if field == "max_input_tokens" else MIN_OUTPUT_TOKENS
    if maximum < minimum:
        raise RuntimeError(
            f"{label} requires at least {minimum} tokens; configured model/deployment maximum is {maximum}"
        )
    suggested = max(minimum, min(int(default), maximum))
    adjustments = {}
    if suggested != default:
        adjustments = {"previous": default, "suggested": suggested}
    explicit = getattr(args, field)
    if explicit is not None:
        if not minimum <= explicit <= maximum:
            raise RuntimeError(f"{label} must be between {minimum} and {maximum}")
        return explicit, adjustments
    if not os.isatty(0):
        if int(default) < minimum:
            raise ValueError(f"{label} must be at least {minimum}")
        return suggested, adjustments
    print(
        f"{label}: allowed {minimum:,}–{maximum:,}; enter max (or auto) to use {maximum:,}.",
        file=sys.stderr,
    )
    if adjustments:
        print(
            f"{label}: saved value {default} is outside the allowed range; defaulting to {suggested}.",
            file=sys.stderr,
        )
    while True:
        answer = input(f"{label} [{suggested}] (Enter to keep): ").strip().lower()
        if answer in {"max", "auto"}:
            return maximum, adjustments
        try:
            value = int(answer) if answer else suggested
        except ValueError:
            print("Enter a positive integer, max, or auto.", file=sys.stderr)
            continue
        if value < minimum:
            print(f"Enter at least {minimum} tokens.", file=sys.stderr)
            continue
        if value > maximum:
            print(
                f"{label}: {value:,} exceeds the available budget; using {maximum:,}.",
                file=sys.stderr,
            )
            return maximum, {"entered": value, "selected": maximum}
        return value, adjustments


def _heading(title: str, explanation: str = "") -> None:
    if os.isatty(0):
        print(f"\n{title}\n{'─' * len(title)}", file=sys.stderr)
        if explanation:
            print(explanation, file=sys.stderr)
        print(file=sys.stderr)


def _confirm(prompt: str) -> bool:
    if not os.isatty(0):
        return False
    while True:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
        if answer in {"", "n", "no"}:
            return False
        if answer in {"y", "yes"}:
            return True
        print("Please enter yes or no.", file=sys.stderr)


def claude_auth_status() -> dict[str, Any]:
    """Use native status only; never expose account details or command output."""
    binary = shutil.which("claude")
    if not binary:
        return {
            "authentication": "not_checked",
            "note": "Install the Claude Code CLI, then run vraptor ai login --harness claude_code.",
        }
    try:
        with tempfile.TemporaryDirectory(prefix="vraptor-auth-") as directory:
            result = subprocess.run(
                [binary, "auth", "status", "--json"],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        status = json.loads(result.stdout)
        if isinstance(status, dict):
            if status.get("loggedIn") is False and result.returncode in {0, 1}:
                return {"authentication": "login_required"}
            if status.get("loggedIn") is True and result.returncode == 0:
                if status.get("authMethod") in {"api_key", "apiKey", "auth_token"}:
                    return {
                        "authentication": "login_required",
                        "note": "Use Claude managed login, or configure --provider anthropic for API-key access.",
                    }
                return {"authentication": "verified"}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return {
        "authentication": "not_checked",
        "note": "Native login status was unavailable; update Claude Code or run claude auth status --json.",
    }


def setup(args: argparse.Namespace) -> dict[str, Any]:
    for requested in (args.execution_profile, args.profile_name):
        if requested is not None:
            _validate_profile_name(requested)
    if args.provider and args.from_harness:
        raise RuntimeError("Select one provider or harness source")
    if args.harness_config and not args.from_harness:
        raise RuntimeError("--harness-config requires --from-harness")
    if args.from_harness and any((args.base_url, args.api_key_env, args.auth_mode)):
        raise RuntimeError(
            "API endpoint and authentication flags require --provider; native sources own those settings"
        )
    path, _ = resolve_config_path(
        repository_environment(REPO_ROOT), {"config_file": args.config_file}
    )
    data = normalize_document(
        read_config(path) if path.is_file() else {"schema_version": 2}
    )
    renamed_profiles = _rename_default_profile(data)
    _heading(
        "Connection and authentication",
        "Managed/native settings: codex (Codex), claude_code (Claude login).\n"
        "API key connections: openai, azure_openai, anthropic (Anthropic API).\n"
        "Azure also supports Entra authentication with --auth-mode entra.",
    )
    preferred_name = args.execution_profile
    if not args.provider and not args.from_harness:
        current_name = preferred_name or data.get("selection", {}).get(
            "default_profile"
        )
        current = data["profiles"].get(current_name, {})
        current_type = (
            _profile_type(current, data.get("connections", {})) if current else ""
        )
        choice = current_type
        if os.isatty(0):
            choice = (
                input(
                    "Connection (codex, claude_code, openai, azure_openai, anthropic)"
                    f" [{current_type or 'codex'}] (Enter to keep): "
                ).strip()
                or current_type
                or "codex"
            )
        elif not choice:
            raise RuntimeError(
                "Use --provider or --from-harness for non-interactive setup"
            )
        if current_type == choice:
            preferred_name = current_name
        if choice in {"codex", "claude_code"}:
            args.from_harness = choice
        elif choice in PROVIDERS:
            args.provider = choice
        else:
            raise RuntimeError("Unknown connection selection")
    provider = args.provider or (
        "openai" if args.from_harness == "codex" else "anthropic"
    )
    from vraptor.analyze.limits import (
        MODEL_CONTEXT_TOKENS,
        default_analysis_settings,
        resolve_analysis_limits,
    )

    analysis_defaults = data.setdefault("analysis_defaults", {})
    saved_analysis_defaults = dict(analysis_defaults)
    for key, value in default_analysis_settings().items():
        analysis_defaults.setdefault(key, value)
    name = _setup_profile_name(data, args.from_harness or provider, preferred_name)
    _heading(
        "Profile",
        "Saved profiles and the current default are retained unless selected for update.",
    )
    profiles = data["profiles"]
    custom_name = args.profile_name
    if custom_name is None and not args.execution_profile and os.isatty(0):
        custom_name = input(f"Profile name [{name}] (Enter to keep): ").strip() or name
    if custom_name is not None:
        _validate_profile_name(custom_name)
        if custom_name != name:
            if name in profiles:
                _rename_profile(data, name, custom_name)
                # Report the original saved name when automatic and custom renames combine.
                originals = [
                    old for old, new in renamed_profiles.items() if new == name
                ]
                for old in originals or [name]:
                    renamed_profiles[old] = custom_name
            elif custom_name in profiles:
                raise RuntimeError("Profile name already exists; choose another name")
            name = custom_name
    profile_action = "updated" if name in profiles else "added"
    profile = dict(profiles.get(name, {}))
    defaults = data.get("execution_defaults", {})
    if connection_name := profile.pop("connection", None):
        # Copy shared connection settings before applying profile-local overrides.
        profile = {**data["connections"][connection_name], **profile}
    native_model = None
    native_effort = None
    if args.from_harness:
        _heading(
            "Native settings",
            "Import model settings only; authentication stays with the native tool.",
        )
        home = str(Path.home())
        source = dict(profile.get("source", {"kind": args.from_harness}))
        saved_path = source.get("path")
        default_source = (
            expand_path(args.harness_config, home)
            if args.harness_config
            else expand_path(saved_path, home, path.parent)
            if saved_path
            else Path(home) / ".codex/config.toml"
            if args.from_harness == "codex"
            else claude_settings_path(home)
        )
        source_path = args.harness_config
        if not source_path and os.isatty(0):
            label = (
                "Codex config" if args.from_harness == "codex" else "Claude settings"
            )
            source_path = input(
                f"{label} file [{default_source}] (Enter for default): "
            ).strip()
        selected_source = expand_path(source_path or str(default_source), home)
        if (
            args.from_harness == "codex"
            or saved_path
            or source_path
            or selected_source.exists()
        ):
            source["path"] = str(selected_source)
        if (
            args.from_harness == "claude_code"
            and selected_source.is_file()
            and (
                (os.isatty(0) and args.model is None and not profile.get("model"))
                or (
                    args.reasoning_effort is None
                    and "reasoning_effort" not in profile
                    and "reasoning_effort" not in defaults
                )
            )
        ):
            native = read_config(selected_source, json_format=True)
            native_env = native.get("env", {})
            native_model = native.get("model") or (
                native_env.get("ANTHROPIC_MODEL")
                if isinstance(native_env, dict)
                else None
            )
            native_effort = native.get("effortLevel")
        profile.update(
            source=source,
            transport=args.transport
            or profile.get("transport")
            or defaults.get("transport")
            or ("auto" if args.from_harness == "codex" else "claude_agent_sdk"),
        )
    else:
        profile["provider"] = provider
        for option in ("base_url", "api_key_env", "auth_mode"):
            value = getattr(args, option)
            if value is not None:
                profile[option] = value
        if provider == "azure_openai":
            profile["base_url"] = _setup_value(
                args, "base_url", "Azure endpoint URL", profile.get("base_url")
            )
        if _confirm("Configure advanced API endpoint and authentication"):
            _heading(
                "Advanced API settings",
                "Enter the name of a credential environment variable, never its secret value.",
            )
            for option, label, fallback in (
                ("base_url", "API endpoint URL", PROVIDERS[provider].base_url),
                ("auth_mode", "Authentication mode (api_key or entra)", "api_key"),
                (
                    "api_key_env",
                    "API key environment variable",
                    PROVIDERS[provider].credential_variable,
                ),
            ):
                if option == "auth_mode" and provider != "azure_openai":
                    continue
                if (
                    option == "api_key_env"
                    and (args.auth_mode or profile.get("auth_mode")) == "entra"
                ):
                    continue
                profile[option] = _setup_value(
                    args, option, label, profile.get(option, fallback)
                )
        if profile.get("auth_mode") != "entra" and not profile.get("api_key_env"):
            profile["api_key_env"] = PROVIDERS[provider].credential_variable
        profile["transport"] = (
            args.transport
            or profile.get("transport")
            or defaults.get("transport")
            or "api"
        )
    default_model = (
        "gpt-5.6-luna"
        if provider in {"openai", "azure_openai"} and not args.from_harness
        else None
    )
    _heading(
        "Model and execution",
        "Use a model ID supported by your account; Azure uses a deployment name.",
    )
    if args.model is None and os.isatty(0):
        print(_model_options_help(provider, args.from_harness or ""), file=sys.stderr)
        print(file=sys.stderr)
    model = _setup_value(
        args,
        "model",
        "Model ID / deployment name",
        profile.get("model", native_model or default_model),
        required=not args.from_harness
        or (args.from_harness == "claude_code" and os.isatty(0) and not native_model),
    )
    if model is not None and (
        model != native_model or args.model is not None or "model" in profile
    ):
        profile["model"] = model
    default_effort = (
        "high"
        if provider in {"openai", "azure_openai"} and not args.from_harness
        else "medium"
        if provider == "anthropic" and _claude_effort_levels(model or "")
        else None
    )
    is_haiku = provider == "anthropic" and (
        (model or native_model) == "haiku"
        or (model or native_model or "").startswith("claude-haiku-")
    )
    if is_haiku:
        if args.reasoning_effort:
            raise RuntimeError("Haiku does not support a reasoning-effort setting")
        profile.pop("reasoning_effort", None)
        native_effort = None
    if args.reasoning_effort is None:
        _heading("Reasoning effort", _reasoning_options_help(provider, model or ""))
    effort = _setup_value(
        args,
        "reasoning_effort",
        "Reasoning effort",
        None
        if is_haiku
        else profile.get(
            "reasoning_effort",
            defaults.get("reasoning_effort", native_effort or default_effort),
        ),
        required=False,
    )
    if is_haiku and effort:
        raise RuntimeError("Haiku does not support a reasoning-effort setting")
    if effort is not None and (
        effort != native_effort
        or args.reasoning_effort is not None
        or "reasoning_effort" in profile
    ):
        profile["reasoning_effort"] = effort
    for option, label, fallback in (
        ("timeout_seconds", "Timeout seconds", 600),
        ("max_concurrency", "Maximum concurrency", 20),
    ):
        profile[option] = _setup_value(
            args,
            option,
            label,
            profile.get(option, defaults.get(option, fallback)),
            integer=True,
        )
    if "max_retries" not in profile and "max_retries" not in defaults:
        profile["max_retries"] = 2
    for option in ("model_context_tokens", "model_max_output_tokens"):
        if getattr(args, option) is not None:
            profile[option] = getattr(args, option)
    profiles[name] = profile
    budget_model = model
    budget_provider = provider
    if not budget_model and args.from_harness:
        # Use the real resolver for inherited native models (including named
        # Codex profiles), without login, discovery requests, or inference.
        with tempfile.TemporaryDirectory(prefix="vraptor-model-preview-") as scratch:
            candidate = Path(scratch) / "analyst-agents.toml"
            candidate.write_text(_toml(data), encoding="utf-8")
            preview = resolve_agent_execution(
                cli_values={"config_file": str(candidate), "execution_profile": name},
                repo_root=Path(scratch),
                process_environment={"HOME": str(Path.home())},
                allow_missing_credentials=True,
            )
            budget_model = preview.route.model
            budget_provider = preview.route.provider
    reference = model_budget(budget_provider, budget_model or "")
    reference_report = {
        "model": budget_model,
        "known": reference is not None,
        **(reference.public_dict() if reference else {}),
    }
    if os.isatty(0):
        print(
            "\nAnalysis token budgets\n──────────────────────\nChoose output first; input uses the remaining model context within the standard-price tier.\nEnter accepts the displayed default; max/auto fills the available budget.\n",
            file=sys.stderr,
        )
        print(f"Model: {budget_model or 'inherited (unresolved)'}", file=sys.stderr)
        if reference:
            if reference.alias_reference_model:
                print(
                    f"  Default alias budget reference: {reference.alias_reference_model}.\n"
                    "  Alias resolution is not verified; for remapped aliases select the exact model ID or configure smaller deployment caps.",
                    file=sys.stderr,
                )
            print(
                f"  Published context: {reference.context_tokens:,} tokens\n"
                f"  Standard-price input ceiling: {reference.standard_price_input_ceiling:,} tokens\n"
                f"  Maximum model output: {reference.max_output_tokens:,} tokens\n"
                f"  Reference defaults: {reference.default_input_tokens:,} input / {reference.default_output_tokens:,} output",
                file=sys.stderr,
            )
            if reference.standard_price_input_ceiling < reference.context_tokens:
                print(
                    "  Input above the standard-price ceiling has a long-context surcharge.",
                    file=sys.stderr,
                )
            else:
                print(
                    "  No long-context surcharge in the published standard API pricing.",
                    file=sys.stderr,
                )
            print(
                f"  Offline reference checked {reference.checked}; deployment and managed-plan limits may differ.\n",
                file=sys.stderr,
            )
        else:
            print(
                "  Model limits/pricing unverified; using saved values or application defaults.\n",
                file=sys.stderr,
            )
    configured_context = profile.get(
        "model_context_tokens", defaults.get("model_context_tokens")
    )
    context = int(
        configured_context
        or (reference.context_tokens if reference else MODEL_CONTEXT_TOKENS)
    )
    if reference:
        context = min(context, reference.context_tokens)
        # Capture the real model envelope even when editing an existing profile.
        # Otherwise the resolver's generic 400K fallback silently restricts it.
        profile["model_context_tokens"] = context
    if context < MIN_INPUT_TOKENS + MIN_OUTPUT_TOKENS:
        raise RuntimeError(
            "Model context must allow at least 100000 input and 32000 output tokens"
        )
    output_cap = profile.get(
        "model_max_output_tokens", defaults.get("model_max_output_tokens")
    )
    output_maximum = min(
        context - MIN_INPUT_TOKENS,
        int(output_cap) if output_cap else context - MIN_INPUT_TOKENS,
        reference.max_output_tokens if reference else context - MIN_INPUT_TOKENS,
    )
    if reference:
        profile["model_max_output_tokens"] = output_maximum
    if os.isatty(0):
        source = (
            "configured model/deployment limit"
            if configured_context
            else "selected model"
            if reference
            else "application fallback (unverified model)"
        )
        print(f"Effective context: {context:,} tokens ({source}).", file=sys.stderr)
        if configured_context and reference and context < reference.context_tokens:
            print(
                "A smaller saved/explicit context applies; use --model-context-tokens to change it.",
                file=sys.stderr,
            )
    recommended_output = (
        reference.default_output_tokens
        if reference
        else 128_000
        if profile_action == "added" and provider in {"openai", "azure_openai"}
        else int(analysis_defaults["max_output_tokens"])
    )
    if not reference and configured_context and "max_output_tokens" not in profile:
        recommended_output = min(
            recommended_output,
            int(output_cap) if output_cap else MIN_OUTPUT_TOKENS,
            context - MIN_INPUT_TOKENS,
        )
    automatic_budgets = args.auto_token_budgets and reference is not None
    output_default = (
        recommended_output
        if automatic_budgets
        else int(
            profile.get(
                "max_output_tokens",
                saved_analysis_defaults.get("max_output_tokens", recommended_output),
            )
        )
    )
    budget_adjustments = {}
    budget_maxima = {"max_output_tokens": output_maximum}
    if (
        reference
        and output_default <= output_maximum
        and output_default != recommended_output
        and os.isatty(0)
    ):
        print(
            f"Maximum output tokens: keeping {output_default}; model reference default is {recommended_output}.",
            file=sys.stderr,
        )
    output, adjustment = _setup_budget(
        args,
        "max_output_tokens",
        "Maximum output tokens",
        output_default,
        output_maximum,
    )
    profile["max_output_tokens"] = output
    if adjustment:
        budget_adjustments["max_output_tokens"] = adjustment
    input_maximum = min(
        context - output,
        reference.standard_price_input_ceiling if reference else context - output,
    )
    budget_maxima["max_input_tokens"] = input_maximum
    recommended_input = min(
        input_maximum,
        (reference.input_budget_tokens or input_maximum)
        if reference
        else input_maximum,
    )
    input_default = (
        recommended_input
        if automatic_budgets
        else int(
            profile.get(
                "max_input_tokens",
                saved_analysis_defaults.get(
                    "max_input_tokens",
                    recommended_input
                    if reference
                    else analysis_defaults["max_input_tokens"],
                ),
            )
        )
    )
    if reference and input_default < recommended_input and os.isatty(0):
        print(
            f"Maximum input tokens: keeping {input_default}; model reference default is {recommended_input}.",
            file=sys.stderr,
        )
    if os.isatty(0):
        print(
            f"\nAvailable input: min({context:,} context - {output:,} output, standard-price ceiling) = {input_maximum:,} tokens.",
            file=sys.stderr,
        )
    profile["max_input_tokens"], adjustment = _setup_budget(
        args, "max_input_tokens", "Maximum input tokens", input_default, input_maximum
    )
    if adjustment:
        budget_adjustments["max_input_tokens"] = adjustment
    selection = data.setdefault("selection", {})
    if args.set_default or not selection.get("default_profile"):
        selection["default_profile"] = name
    elif selection["default_profile"] != name and os.isatty(0):
        while True:
            answer = (
                input(
                    f"Make '{name}' the default profile? "
                    f"Current: '{selection['default_profile']}' [y/N]: "
                )
                .strip()
                .lower()
            )
            if answer in {"", "n", "no"}:
                break
            if answer in {"y", "yes"}:
                selection["default_profile"] = name
                break
            print("Please enter yes or no.")
    content = _toml(data).encode("utf-8")
    # Validate route and bounds with a temporary config before replacing user state.
    with tempfile.TemporaryDirectory(prefix="vraptor-setup-") as scratch:
        candidate = Path(scratch) / "analyst-agents.toml"
        candidate.write_bytes(content)
        execution = resolve_agent_execution(
            cli_values={"config_file": str(candidate), "execution_profile": name},
            repo_root=Path(scratch),
            process_environment={"HOME": str(Path.home())},
            allow_missing_credentials=True,
        )
        execution = replace(
            execution, route=replace(execution.route, config_file=str(path))
        )
        effective_limits = resolve_analysis_limits(
            environment={}, execution=execution
        ).for_execution(execution)
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = ""
    if path.exists():
        backup = str(path.with_name(path.name + ".bak"))
        _atomic_write(Path(backup), path.read_bytes())
    _atomic_write(path, content)
    authentication = {"authentication": "not_checked"}
    if args.from_harness == "claude_code":
        _heading(
            "Claude login",
            "Settings discovery does not import Desktop config.json tokens.\nUse vraptor ai login --harness claude_code to sign in separately.",
        )
        if _confirm("Check Claude Code login and sign in if needed"):
            authentication = claude_auth_status()
            if authentication["authentication"] == "login_required":
                main("login", ["--harness", "claude_code"])
                authentication = claude_auth_status()
    doctor_command = shlex.join(
        [
            "vraptor",
            "ai",
            "doctor",
            "--config-file",
            str(path),
            "--execution-profile",
            name,
        ]
    )
    return {
        "status": "configured",
        "config_file": str(path),
        "execution_profile": name,
        "profile_action": profile_action,
        "renamed_profiles": renamed_profiles,
        "analysis_defaults": analysis_defaults,
        "analysis_limits": effective_limits.public_dict(),
        "model_token_reference": reference_report,
        "token_budget_maxima": budget_maxima,
        "token_budget_adjustments": budget_adjustments,
        "token_limits_note": "Check this profile's input/output budgets against the deployed model's limits; context and evidence budgets are derived and model limits may reduce them.",
        "default_profile": selection["default_profile"],
        "schema_version": 2,
        "backup": backup,
        **authentication,
        "inference": "not_tested",
        "next": f"Run {doctor_command}; existing environment overrides still apply.",
    }


async def model_metadata(execution) -> dict[str, Any]:
    from vraptor.agent.providers import _normalized_exception

    route = execution.route
    if route.protocol == "codex_app_server":
        from vraptor.agent.codex_app_server import CodexAppServerClient

        client = CodexAppServerClient()
        try:
            async with asyncio.timeout(20):
                await client.start()
                account = await client.request("account/read", {"refreshToken": False})
                models = await client.request("model/list", {})
            return {
                "authentication": "verified"
                if account.get("account")
                else "login_required",
                "models": [
                    {"id": item.get("model", item.get("id"))}
                    for item in models.get("data", [])[:200]
                ],
                "listing_complete": len(models.get("data", [])) <= 200
                and not bool(models.get("nextCursor")),
            }
        finally:
            await client.close()
    if route.protocol == "claude_agent_sdk":
        return {
            **claude_auth_status(),
            "models": [],
            "models_note": "Claude SDK does not expose model listing; ai test checks isolated inference.",
        }
    # Metadata listing does not require an analysis context envelope.
    from vraptor.agent.providers import adapter_for
    from vraptor.agent.runtime import TimeoutPolicy

    adapter = adapter_for(execution, timeout_policy=TimeoutPolicy(10, 20, 30, 20))
    try:
        adapter.client = adapter._build_client()
        async with asyncio.timeout(30):
            result = await adapter.client.models.list()
        models = []
        for model in result.data[:200]:
            record = {"id": model.id}
            for key in ("max_input_tokens", "max_tokens"):
                value = getattr(model, key, None)
                if isinstance(value, int):
                    record[key] = value
            models.append(record)
        return {
            "authentication": "verified",
            "models": models,
            "listing_complete": len(result.data) <= 200
            and not bool(getattr(result, "has_more", False)),
            "note": "Azure model IDs are not deployment names; ai test validates the selected deployment."
            if route.provider == "azure_openai"
            else "",
        }
    except Exception as exc:
        raise _normalized_exception(exc, execution.provider) from exc
    finally:
        await adapter.close()


async def inspect_or_test(
    command: str, args: argparse.Namespace
) -> tuple[dict[str, Any], int]:
    from vraptor.agent.cli import agent_configuration_payload
    from vraptor.analyze.limits import resolve_analysis_limits

    cli = {
        key: value
        for key in ("config_file", "execution_profile")
        if (value := getattr(args, key, None))
    }
    execution = resolve_agent_execution(
        cli_values=cli, allow_missing_credentials=command == "doctor" and not args.live
    )
    limits = resolve_analysis_limits(execution=execution)
    issues = []
    try:
        limits = limits.for_execution(execution)
    except (RuntimeError, ValueError) as exc:
        issues.append(str(exc))
    route = execution.route
    dependency = (
        "claude-agent-sdk"
        if route.protocol == "claude_agent_sdk"
        else PROVIDERS[route.provider].dependency
    )
    if route.protocol == "codex_app_server":
        dependency = "codex"
        installed = shutil.which("codex") is not None
        installed_version = "native"
    else:
        try:
            installed_version = version(dependency)
            installed = True
        except PackageNotFoundError:
            installed_version, installed = "", False
    if not installed:
        issues.append(f"Missing dependency: {dependency}")
    elif dependency == "claude-agent-sdk" and tuple(
        int(part) for part in installed_version.split(".")[:3]
    ) < (0, 2, 140):
        issues.append("Claude managed execution requires claude-agent-sdk>=0.2.140")
    if route.auth_mode == "entra":
        try:
            version("azure-identity")
        except PackageNotFoundError:
            issues.append("Missing dependency: azure-identity; install vraptor[azure]")
    if route.auth_mode == "api_key" and not execution.inputs.credential_present:
        issues.append(f"Missing credential variable: {route.credential_variable}")
    payload = {
        "status": "ready" if not issues else "needs_configuration",
        "configuration": agent_configuration_payload(execution, limits),
        "issues": issues,
        "dependency": {"name": dependency, "version": installed_version},
        "authentication": "not_checked",
        "inference": "not_tested",
    }
    if command == "models" or command == "doctor" and args.live:
        payload.update(await model_metadata(execution))
        if payload["authentication"] == "login_required":
            issues.append("Harness login required")
        elif (
            route.protocol == "claude_agent_sdk"
            and payload["authentication"] == "not_checked"
        ):
            issues.append("Claude login status could not be verified")
    if command == "test":
        if issues:
            return payload, 1
        if not 1 <= args.max_output_tokens <= 4096:
            raise RuntimeError(
                "Synthetic test max-output-tokens must be between 1 and 4096"
            )
        from vraptor.agent.factory import create_agent_runner
        from vraptor.agent.runtime import AgentRequest

        bounded = replace(
            execution, route=replace(route, max_retries=0, max_concurrency=1)
        )
        runner = create_agent_runner(
            bounded, limits=limits.runtime_limits(), persist_runtime_files=False
        )
        try:
            with tempfile.TemporaryDirectory(prefix="vraptor-agent-test-") as directory:
                result = await runner.run(
                    AgentRequest(
                        task_id="synthetic-check",
                        prompt="Return exactly READY and nothing else.",
                        output_name="check.txt",
                        metadata={},
                        max_output_tokens=args.max_output_tokens,
                    ),
                    output_dir=Path(directory),
                    workdir=Path(directory),
                )
            success = result.status == "succeeded" and result.output.strip() == "READY"
            payload.update(
                inference="passed" if success else "failed",
                usage=result.usage,
                error_classification=result.error_classification,
            )
            if not success:
                issues.append("Synthetic inference did not satisfy the output contract")
        finally:
            await runner.close()
    payload["status"] = "ready" if not issues else "needs_attention"
    return payload, int(bool(issues))


def main(command: str, argv: list[str]) -> int:
    args = parser_for(command).parse_args(argv)
    if command == "login":
        binary = "codex" if args.harness == "codex" else "claude"
        if not shutil.which(binary):
            raise RuntimeError(f"Install {binary} before logging in")
        with tempfile.TemporaryDirectory(prefix="vraptor-login-") as directory:
            return subprocess.run(
                [binary, "login"] if binary == "codex" else [binary, "auth", "login"],
                cwd=directory,
                check=False,
            ).returncode
    if command == "setup":
        payload, status = setup(args), 0
    else:
        payload, status = asyncio.run(inspect_or_test(command, args))
    print(json.dumps(payload, sort_keys=True, indent=2))
    return status
