"""Order-preserving sequence helpers."""

from __future__ import annotations


def unique_ordered(values: list[str]) -> list[str]:
    """Keep the first occurrence of each value without normalizing it."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
