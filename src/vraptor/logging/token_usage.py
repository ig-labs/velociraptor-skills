"""Payload-free token accounting for completed provider request attempts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

LOG_FILENAME = "token-usage.jsonl"
TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
)
USAGE_STATUSES = frozenset({"reported", "partial", "unavailable"})
RETRY_FIELDS = ("retry_attempts", "transport_retry_attempts", "correction_attempts")


class TokenUsageLedger:
    """Accumulate each invocation/attempt once, independently of progress events."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, int]] = set()
        self._groups: dict[tuple[str, str], dict[str, Any]] = {}
        self.records_dropped = 0

    @property
    def attempt_count(self) -> int:
        return len(self._seen)

    def record(
        self,
        *,
        invocation_id: str,
        attempt: int,
        provider: str,
        model: str,
        status: str,
        usage: Mapping[str, int],
        usage_status: str,
        correction_attempt: int = 0,
        **fields: Any,
    ) -> dict[str, Any] | None:
        key = (invocation_id, attempt)
        if key in self._seen:
            return None
        self._seen.add(key)
        correction_attempt = correction_attempt if type(correction_attempt) is int and correction_attempt > 0 else 0
        if usage_status not in USAGE_STATUSES:
            usage_status = "unavailable"
        counts = {
            name: (
                max(0, int(usage.get(name) or 0))
                if usage_status != "unavailable"
                else None
            )
            for name in TOKEN_FIELDS
        }
        group = self._groups.setdefault(
            (provider, model),
            {
                "provider": provider,
                "model": model,
                "attempts": 0,
                "retry_attempts": 0,
                "transport_retry_attempts": 0,
                "correction_attempts": 0,
                "reported_requests": 0,
                "partial_requests": 0,
                "unavailable_requests": 0,
                "statuses": Counter(),
                **{name: 0 for name in TOKEN_FIELDS},
            },
        )
        group["attempts"] += 1
        group["retry_attempts"] += int(attempt > 1 or correction_attempt > 0)
        group["transport_retry_attempts"] += int(attempt > 1)
        # One correction invocation may itself require transport retries.
        group["correction_attempts"] += int(correction_attempt > 0 and attempt == 1)
        group[f"{usage_status}_requests"] += 1
        group["statuses"][status] += 1
        for name, value in counts.items():
            group[name] += value or 0
        return {
            "event": "request_usage",
            "invocation_id": invocation_id,
            "attempt": attempt,
            "correction_attempt": correction_attempt,
            "provider": provider,
            "model": model,
            "status": status,
            "usage_status": usage_status,
            **counts,
            **fields,
        }

    def summary(self) -> dict[str, Any]:
        groups = [
            {**group, "statuses": dict(sorted(group["statuses"].items()))}
            for _, group in sorted(self._groups.items())
        ]
        total_fields = (
            "attempts",
            *RETRY_FIELDS,
            "reported_requests",
            "partial_requests",
            "unavailable_requests",
            *TOKEN_FIELDS,
        )
        totals = {name: sum(group[name] for group in groups) for name in total_fields}
        return {
            "event": "operation_summary",
            **totals,
            "usage_complete": not (
                totals["partial_requests"] or totals["unavailable_requests"]
            ),
            "records_dropped": self.records_dropped,
            "log_complete": self.records_dropped == 0,
            "groups": groups,
        }
