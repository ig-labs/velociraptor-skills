"""Normalize server label values for readiness and hunt scope matching."""

from __future__ import annotations

import json
from typing import Any


def parse_label_values(raw_value: Any) -> set[str]:
    if raw_value is None:
        return set()
    if isinstance(raw_value, list):
        return {str(item).strip() for item in raw_value if str(item).strip()}
    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return set()
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return {str(item).strip() for item in parsed if str(item).strip()}
        return {token.strip() for token in stripped.split(",") if token.strip()}
    return {str(raw_value).strip()}
