"""Strict helpers for compact model-facing Velociraptor line protocols."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


FORBIDDEN_METADATA_PREFIXES = (
    "skills used:",
    "tools used:",
    "mcp used:",
    "stats:",
)


@dataclass(frozen=True)
class LineProtocolError(ValueError):
    """A deterministic line-protocol validation failure."""

    message: str
    code: str
    line: int = 0
    record: str = ""
    value: str = ""

    def __str__(self) -> str:
        return self.message

    @property
    def diagnostic(self) -> dict[str, Any]:
        output: dict[str, Any] = {"code": self.code}
        if self.line:
            output["line"] = self.line
        if self.record:
            output["record"] = self.record
        if self.value:
            output["value"] = self.value
        return output


def strict_lines(value: Any, *, output_name: str) -> list[str]:
    """Return a validated envelope whose final and only marker is ``END``."""
    if not isinstance(value, str):
        raise LineProtocolError(
            f"{output_name} must be line-oriented text",
            "invalid_output_type",
        )
    text = value.strip()
    if not text:
        raise LineProtocolError(f"{output_name} is empty", "empty_output")
    if text.startswith(("{", "[")):
        raise LineProtocolError(
            f"model-generated JSON {output_name} is not supported",
            "unsupported_json",
        )
    if text.startswith("```") or "```" in text:
        raise LineProtocolError(
            f"{output_name} must not contain Markdown fences",
            "markdown_fence",
        )
    lines = text.splitlines()
    if lines[-1] != "END":
        raise LineProtocolError(
            f"{output_name} is missing the END marker",
            "missing_end",
        )
    if any(line == "END" for line in lines[:-1]):
        raise LineProtocolError(
            f"{output_name} contains content after END",
            "content_after_end",
        )
    for line_number, line in enumerate(lines, start=1):
        if line.strip().casefold().startswith(FORBIDDEN_METADATA_PREFIXES):
            raise LineProtocolError(
                f"{output_name} contains forbidden agent metadata",
                "forbidden_metadata",
                line=line_number,
            )
    return lines


def tab_fields(
    line: str,
    *,
    final_text_field: int | None = None,
) -> list[str]:
    """Split one record while preserving tabs in its final prose field."""
    if final_text_field is None:
        return line.split("\t")
    if final_text_field < 1:
        raise ValueError("final text field must follow at least one delimiter")
    return line.split("\t", final_text_field)


def tab_records(
    value: Any,
    *,
    output_name: str,
    allowed_records: Iterable[str],
    trailing_text_fields: Mapping[str, int] | None = None,
) -> list[tuple[int, list[str]]]:
    """Parse tab records, optionally retaining tabs in final prose fields."""
    allowed = set(allowed_records)
    trailing = dict(trailing_text_fields or {})
    unknown_trailing = set(trailing) - allowed
    if unknown_trailing:
        raise ValueError(
            "trailing text fields use unsupported records: "
            + ", ".join(sorted(unknown_trailing))
        )
    output: list[tuple[int, list[str]]] = []
    for line_number, line in enumerate(
        strict_lines(value, output_name=output_name)[:-1],
        start=1,
    ):
        if not line:
            continue
        record = line.partition("\t")[0]
        if record not in allowed:
            raise LineProtocolError(
                f"line {line_number} uses unsupported record {record!r}",
                "unsupported_record",
                line=line_number,
                record=record,
            )
        fields = tab_fields(
            line,
            final_text_field=trailing.get(record),
        )
        output.append((line_number, fields))
    return output
