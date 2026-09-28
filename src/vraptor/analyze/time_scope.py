"""Canonical, profile-driven time scopes for Velociraptor analysis queries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence


TIME_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
AFTER_ENV = "AnalysisTimeAfter"
BEFORE_ENV = "AnalysisTimeBefore"
EVENT_LOG_ARTIFACT_TOKEN = "EventLogs"
EVENT_LOG_FALLBACK_TIME_FILTER = {
    "default_roles": ["event"],
    "roles": {
        "event": {
            "semantics": "Windows Event Log event time inferred from the artifact naming contract",
            "expressions": ["EventTime"],
        }
    },
}


class TimeScopeError(RuntimeError):
    """Raised when a requested analysis time scope is invalid or unsupported."""


def _canonical_datetime(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimeScopeError(f"{label} must be a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise TimeScopeError(f"{label} must include an explicit timezone.")
    utc_value = parsed.astimezone(timezone.utc)
    rendered = utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z")


def _unique_roles(values: Sequence[str] | None) -> tuple[str, ...]:
    output: list[str] = []
    for raw in values or ():
        role = str(raw or "").strip().casefold()
        if not TIME_ROLE_RE.fullmatch(role):
            raise TimeScopeError(
                f"Invalid --time-field {raw!r}; expected lowercase letters, digits, and underscores."
            )
        if role not in output:
            output.append(role)
    return tuple(output)


@dataclass(frozen=True)
class TimeScope:
    mode: str
    after: str = ""
    before: str = ""
    requested_roles: tuple[str, ...] = ()

    @classmethod
    def from_values(
        cls,
        *,
        after: str = "",
        before: str = "",
        roles: Sequence[str] | None = None,
    ) -> "TimeScope":
        canonical_after = _canonical_datetime(after, "--time-after")
        canonical_before = _canonical_datetime(before, "--time-before")
        requested_roles = _unique_roles(roles)
        if requested_roles and not (canonical_after or canonical_before):
            raise TimeScopeError("--time-field requires --time-after or --time-before.")
        if canonical_after and canonical_before:
            left = datetime.fromisoformat(canonical_after.replace("Z", "+00:00"))
            right = datetime.fromisoformat(canonical_before.replace("Z", "+00:00"))
            if left >= right:
                raise TimeScopeError("--time-after must be earlier than --time-before.")
        return cls(
            mode="bounded" if canonical_after or canonical_before else "all",
            after=canonical_after,
            before=canonical_before,
            requested_roles=requested_roles,
        )

    @property
    def bounded(self) -> bool:
        return self.mode == "bounded"

    def canonical(self) -> dict[str, Any]:
        if not self.bounded:
            return {"mode": "all"}
        return {
            "mode": "bounded",
            "after": self.after,
            "before": self.before,
            "requested_roles": list(self.requested_roles),
        }

    def sha256(self) -> str:
        payload = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def environment(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.after:
            env[AFTER_ENV] = self.after
        if self.before:
            env[BEFORE_ENV] = self.before
        return env


@dataclass(frozen=True)
class ResolvedTimeScope:
    artifact: str
    scope: TimeScope
    roles: tuple[str, ...]
    expressions: Mapping[str, tuple[str, ...]]
    semantics: Mapping[str, str]

    def canonical(self) -> dict[str, Any]:
        if not self.scope.bounded:
            return {"mode": "all"}
        return {
            **self.scope.canonical(),
            "artifact": self.artifact,
            "resolved_roles": list(self.roles),
            "resolved_expressions": {
                role: list(self.expressions[role]) for role in self.roles
            },
            "semantics": {role: self.semantics[role] for role in self.roles},
        }

    def predicate(self) -> str:
        if not self.scope.bounded:
            return ""
        role_predicates: list[str] = []
        for role in self.roles:
            for expression in self.expressions[role]:
                comparisons: list[str] = []
                if self.scope.after:
                    comparisons.append(f"{expression} > {AFTER_ENV}")
                if self.scope.before:
                    comparisons.append(f"{expression} < {BEFORE_ENV}")
                role_predicates.append("(" + " AND ".join(comparisons) + ")")
        return "(" + " OR ".join(role_predicates) + ")"

    def includes(self, row: Mapping[str, Any]) -> bool:
        """Defensively apply the same open OR predicate to an acquired row.

        Server-side VQL applies the authoritative filter before transport. This
        local check validates only returned rows. Profiles are restricted to
        dotted field paths, so the evaluator is deterministic and deliberately
        small.
        """
        if not self.scope.bounded:
            return True
        after = _parse_row_time(self.scope.after) if self.scope.after else None
        before = _parse_row_time(self.scope.before) if self.scope.before else None
        for role in self.roles:
            for expression in self.expressions[role]:
                value = _dotted_value(row, expression)
                parsed = _parse_row_time(value)
                if parsed is None:
                    continue
                if after is not None and parsed <= after:
                    continue
                if before is not None and parsed >= before:
                    continue
                return True
        return False

    def filter_rows(self, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows if self.includes(row)]


def _dotted_value(row: Mapping[str, Any], expression: str) -> Any:
    value: Any = row
    for part in str(expression).split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _parse_row_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        # Accommodate common epoch seconds, milliseconds, microseconds, and
        # nanoseconds without artifact-specific coercion.
        magnitude = abs(number)
        if magnitude >= 1e17:
            number /= 1e9
        elif magnitude >= 1e14:
            number /= 1e6
        elif magnitude >= 1e11:
            number /= 1e3
        try:
            parsed = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value).strip()
        if not text:
            return None
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            return _parse_row_time(float(text))
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_for_profile(
    artifact: str,
    profile: Mapping[str, Any] | None,
    scope: TimeScope,
) -> ResolvedTimeScope:
    if not scope.bounded:
        return ResolvedTimeScope(artifact, scope, (), {}, {})
    review = dict((profile or {}).get("review") or {})
    if "time_filter" in review:
        # An explicit mapping, including an empty mapping, overrides or disables
        # the EventLogs naming fallback.
        contract = dict(review.get("time_filter") or {})
    elif EVENT_LOG_ARTIFACT_TOKEN in str(artifact).split("[", 1)[0]:
        contract = EVENT_LOG_FALLBACK_TIME_FILTER
    else:
        contract = {}
    configured_roles = dict(contract.get("roles") or {})
    roles = scope.requested_roles or tuple(contract.get("default_roles") or ())
    if not configured_roles or not roles:
        return ResolvedTimeScope(artifact, TimeScope("all"), (), {}, {})
    missing = [role for role in roles if role not in configured_roles]
    if missing:
        return ResolvedTimeScope(artifact, TimeScope("all"), (), {}, {})
    expressions = {
        role: tuple(str(value) for value in configured_roles[role]["expressions"])
        for role in roles
    }
    semantics = {
        role: str(configured_roles[role]["semantics"]) for role in roles
    }
    return ResolvedTimeScope(
        artifact=artifact,
        scope=scope,
        roles=tuple(roles),
        expressions=expressions,
        semantics=semantics,
    )


def resolve_all(
    artifacts: Sequence[str],
    profiles: Mapping[str, Mapping[str, Any]],
    scope: TimeScope,
    *,
    profile_resolver: Any,
) -> dict[str, ResolvedTimeScope]:
    if not scope.bounded:
        return {}
    resolved: dict[str, ResolvedTimeScope] = {}
    for artifact in sorted({str(value) for value in artifacts if str(value).strip()}):
        profile = profile_resolver(artifact, profiles)
        resolved[artifact] = resolve_for_profile(artifact, profile, scope)
    return resolved


def provenance(
    artifacts: Sequence[str],
    profiles: Mapping[str, Mapping[str, Any]],
    scope: TimeScope,
    resolved: Mapping[str, ResolvedTimeScope],
    *,
    profile_resolver: Callable[..., Mapping[str, Any] | None],
) -> dict[str, Any]:
    """Describe requested, resolved, and unsupported analysis-time coverage."""
    selected = sorted({str(value) for value in artifacts if str(value).strip()})
    filtered = sorted(
        artifact
        for artifact in selected
        if resolved.get(artifact) is not None
        and resolved[artifact].scope.bounded
    )
    unfiltered = sorted(set(selected).difference(filtered))
    unsupported = unfiltered if scope.bounded else []
    if not scope.bounded:
        coverage = "not_requested"
    elif filtered and not unsupported:
        coverage = "complete"
    elif filtered:
        coverage = "partial"
    else:
        coverage = "unsupported"
    collection_support: dict[str, str] = {}
    for artifact in selected:
        profile = profile_resolver(artifact, profiles)
        collection_support[artifact] = str(
            (profile or {}).get("time_bound_support") or "unknown"
        )
    return {
        "mode": scope.mode,
        "time_after": scope.after,
        "time_before": scope.before,
        "requested_time_fields": list(scope.requested_roles),
        "coverage": coverage,
        "filtered_artifacts": filtered,
        "unfiltered_artifacts": unfiltered,
        "unsupported_artifacts": unsupported,
        "resolved_artifacts": {
            artifact: {
                "roles": list(resolved[artifact].roles),
                "expressions": {
                    role: list(resolved[artifact].expressions[role])
                    for role in resolved[artifact].roles
                },
                "semantics": {
                    role: resolved[artifact].semantics[role]
                    for role in resolved[artifact].roles
                },
                "predicate": resolved[artifact].predicate(),
            }
            for artifact in filtered
        },
        "collection_time_bound_support": collection_support,
    }


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--time-after",
        default="",
        help=(
            "Analysis lower bound as timezone-aware ISO-8601; exclusive. "
            "This is distinct from collection DateAfter."
        ),
    )
    parser.add_argument(
        "--time-before",
        default="",
        help=(
            "Analysis upper bound as timezone-aware ISO-8601; exclusive. "
            "This is distinct from collection DateBefore."
        ),
    )
    parser.add_argument(
        "--time-field",
        action="append",
        default=[],
        help=(
            "Profile-defined logical time field. Repeat for OR semantics. "
            "Requires a time bound; omitted values use each artifact's defaults. "
            "Unsupported artifacts remain unfiltered and are reported as partial "
            "time-filter coverage."
        ),
    )


def from_args(args: argparse.Namespace) -> TimeScope:
    return TimeScope.from_values(
        after=str(getattr(args, "time_after", "") or ""),
        before=str(getattr(args, "time_before", "") or ""),
        roles=list(getattr(args, "time_field", []) or []),
    )
