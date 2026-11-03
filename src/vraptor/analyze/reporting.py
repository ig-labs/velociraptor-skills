"""Presentation policy, independent of inference budgets and evidence identity."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, fields
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True)
class ReportingPolicy:
    detailed_findings: int = 20
    examples_per_finding: int = 3
    context_items: int = 10
    timeline_rows: int = 20
    preview_chars: int = 320
    chat_chars: int = 32_000
    evidence_chars: int = 2_000_000
    compact_markdown_bytes: int = 524_288
    artifact_sections: int = 100
    detectraptor_notes: int = 100
    detectraptor_events: int = 3
    detectraptor_source_refs: int = 3
    follow_up_actions: int = 5
    sources: Mapping[str, Mapping[str, Any]] = field(
        default_factory=lambda: MappingProxyType({}), compare=False, repr=False
    )

    def __post_init__(self):
        validate_values(self.as_dict())
        object.__setattr__(
            self,
            "sources",
            MappingProxyType(
                {k: MappingProxyType(dict(v)) for k, v in self.sources.items()}
            ),
        )

    def as_dict(self) -> dict[str, int]:
        return {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if item.name != "sources"
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "effective": self.as_dict(),
            "sources": {
                key: dict(
                    self.sources.get(
                        key, {"kind": "application_default", "name": "reporting." + key}
                    )
                )
                for key in self.as_dict()
            },
        }


REPORTING_FIELDS = frozenset(
    item.name for item in fields(ReportingPolicy) if item.name != "sources"
)


def validate_values(value: Any, section: str = "reporting") -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) - REPORTING_FIELDS:
        raise ValueError(f"Invalid or unknown fields in {section}")
    for name, item in value.items():
        minimum = 512 if name in {"chat_chars", "compact_markdown_bytes"} else 1
        if type(item) is not int or item < minimum:
            raise ValueError(f"{section}.{name} must be an integer of at least {minimum}")
    return dict(value)


_DEFAULT = ReportingPolicy()

_ACTIVE: ContextVar[ReportingPolicy | None] = ContextVar(
    "vraptor_reporting_policy", default=None
)


def active_policy() -> ReportingPolicy | None:
    return _ACTIVE.get()


def current_policy() -> ReportingPolicy:
    return _ACTIVE.get() or _DEFAULT


@contextmanager
def reporting_scope(policy: ReportingPolicy):
    token = _ACTIVE.set(policy)
    try:
        yield policy
    finally:
        _ACTIVE.reset(token)


def resolve_reporting_policy(
    execution=None, cli_values=None, *, environment_layers=None
) -> ReportingPolicy:
    """Resolve safe settings without requiring credentials or selecting a model."""
    from vraptor.agent import sources
    from vraptor.paths import repository_environment
    from vraptor.resources import repository_root

    cli = dict(cli_values or {})
    layers = environment_layers or repository_environment(repository_root())
    if execution is not None:
        route = execution.route
        shared = dict(getattr(route, "reporting_defaults", {}))
        profile_values = dict(getattr(route, "reporting_profile", {}))
        profile = route.execution_profile
        path = route.config_file
    else:
        data, path = sources.load_document(layers, cli)
        profile = str(
            cli.get("execution_profile")
            or sources.setting(layers, sources.PREFIX + "PROFILE")
            or data.get("selection", {}).get("default_profile", "")
        )
        if profile and profile not in data.get("profiles", {}):
            raise ValueError("Selected execution profile does not exist")
        shared = data.get("reporting", {})
        profile_values = data.get("profiles", {}).get(profile, {}).get("reporting", {})
    values, origins = {}, {}
    for kind, prefix, selected in (
        ("reporting_defaults", "reporting", shared),
        ("execution_profile", f"profiles.{profile}.reporting", profile_values),
    ):
        for name, value in validate_values(selected).items():
            values[name] = value
            origins[name] = {
                "kind": kind,
                "name": prefix + "." + name,
                "location": path,
            }
    for name in REPORTING_FIELDS:
        if name in cli and cli[name] is not None:
            continue
        variable = "VRAPTOR_REPORT_" + name.upper()
        for layer in layers.priority_layers():
            raw = layer.values.get(variable)
            if raw is None or not str(raw).strip():
                continue
            try:
                values[name] = int(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{variable} must be a positive integer") from None
            origins[name] = {
                "kind": layer.kind,
                "name": variable,
                "location": layer.location,
            }
            break
    for name in REPORTING_FIELDS:
        if name in cli and cli[name] is not None:
            values[name] = cli[name]
            origins[name] = {
                "kind": "cli",
                "name": "--report-" + name.replace("_", "-"),
            }
    return ReportingPolicy(**values, sources=origins)


def _option(args, names):
    for index, arg in enumerate(args):
        if arg == "--":
            break
        for name in names:
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
            if arg == name and index + 1 < len(args):
                return args[index + 1]
    return None


def extract_options(argv):
    """Consume invocation-wide presentation overrides; preserve other arguments."""
    args, selected, index = list(argv), {}, 0
    forwarded = []
    options = {"--report-" + name.replace("_", "-"): name for name in REPORTING_FIELDS}
    while index < len(args):
        arg = args[index]
        if arg == "--":
            forwarded.extend(args[index:])
            break
        option, equals, raw = arg.partition("=")
        if option not in options:
            forwarded.append(arg)
            index += 1
            continue
        if not equals:
            index += 1
            if index >= len(args):
                raise ValueError(f"{option} requires a positive integer")
            raw = args[index]
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{option} requires a positive integer") from None
        selected[options[option]] = value
        index += 1
    validate_values(selected)
    for key, names in (
        ("config_file", ("--ai-config-file", "--config-file")),
        ("execution_profile", ("--execution-profile",)),
    ):
        if value := _option(forwarded, names):
            selected[key] = value
    return forwarded, selected


def run_with_policy(argv, dispatch):
    args = list(argv)
    if (
        not args
        or args[0] in {"help", "-h", "--help", "logs"}
        or any(arg in {"-h", "--help"} for arg in args)
    ):
        return dispatch(args)
    if _ACTIVE.get() is not None:
        return dispatch(args)
    forwarded, selected = extract_options(args)
    report_override = any(key in REPORTING_FIELDS for key in selected)
    render_command = args[0] in {
        "analyze",
        "summarize",
        "analysis-results",
        "reports",
    } or args[:2] in (
        ["hunt", "analyze"],
        ["hunt", "run"],
        ["hunt", "analyze-saved"],
        ["collect", "analyze"],
    )
    if not report_override and not render_command:
        return dispatch(forwarded)
    with reporting_scope(resolve_reporting_policy(cli_values=selected)):
        return dispatch(forwarded)
