"""Whole-field RE2 matching of reviewed GoldenDB rules."""
from __future__ import annotations

import re
from typing import Any, Iterable
import re2

MATCHING_POLICY = "goldendb-reviewed-rules-v2-category-any"

def category_pattern(pattern: str) -> str:
    """The schema-9 CategoryRegex '.' sentinel includes empty and multiline values."""
    return "(?s).*" if pattern == "." else pattern


def full_pattern(pattern: str) -> str:
    """Use Go/RE2 whole-string boundaries, including for multiline inputs."""
    return r"(?i)\A(?:" + pattern + r")\z"


def compile_pattern(pattern: str, *, whole_field: bool = True) -> Any:
    if not pattern:
        raise RuntimeError("GoldenDB regex fields must be explicit; use ^$ for an empty field.")
    # C++ RE2 supports byte matching, but Go regexp deliberately does not.
    if r"\C" in re.findall(r"\\.", pattern):
        raise RuntimeError("GoldenDB regex uses \\C, which Go/VQL does not support.")
    options = re2.Options()
    options.log_errors = False
    try:
        # Validate the supplied expression independently so unbalanced groups
        # cannot escape the enclosing whole-field boundary expression.
        re2.compile(pattern, options=options)
        expression = full_pattern(pattern) if whole_field else "(?i)(?:" + pattern + ")"
        return re2.compile(expression, options=options)
    except re2.error as exc:
        raise RuntimeError(f"Invalid GoldenDB RE2 regex {pattern!r}: {exc}") from exc



class RegexIndex:
    """Compile approved rules once; all fields in a rule must match together."""

    def __init__(self, rows: Iterable[dict[str, str]] = (), *, classifier=None):
        # Retained keyword for legacy callers; classifiers do not govern approved rules.
        rows = list(rows)
        self.search_rules = [tuple(compile_pattern(row[field], whole_field=False)
            for field in ("Category", "ImagePath", "LaunchString", "Signer"))
            for row in rows if "Category" in row]
        self.four_field_rules = [tuple(compile_pattern(category_pattern(row[field]) if field == "category_regex" else row[field]) for field in
            ("category_regex", "image_path_regex", "launch_string_regex", "signer_regex"))
            for row in rows if "category_regex" in row]
        self.rules = [(compile_pattern(row["image_path_regex"]),
                       compile_pattern(row["launch_string_regex"]))
                      for row in rows if "category_regex" not in row and "Category" not in row]

    def matches(self, record: dict[str, Any]) -> bool:
        if self.search_rules:
            return any(all(pattern.search(str(record.get(field) or "")) is not None
                for pattern, field in zip(rule, ("category", "image_path", "launch_string", "signer")))
                for rule in self.search_rules)
        if self.four_field_rules:
            return any(category.search(str(record.get("category") or "")) is not None
                and image.search(record["image_path"]) is not None
                and launch.search(record["launch_string"]) is not None
                and signer.search(record["signer"]) is not None
                for category, image, launch, signer in self.four_field_rules)
        return any(image.search(record["image_path"]) is not None
            and launch.search(record["launch_string"]) is not None
            for image, launch in self.rules)


def vql_match_function() -> str:
    """Use the same approved paired-rule semantics in inventory and live VQL."""
    return ("LET AutorunsGoldenRegexMatch(GoldenImage, GoldenLaunch) = "
        "any(items=AutorunsGoldenRegex, "
        'filter="rule=>GoldenImage =~ rule.ImagePathRegex AND GoldenLaunch =~ rule.LaunchStringRegex")')


def vql_preamble(*, source: str) -> str:
    """Materialize approved paired rules once."""
    return f"LET AutorunsGoldenRegex <= {source}\n" + vql_match_function()


def vql_regex_only_preamble(*, source: str) -> str:
    """A scalar rule array avoids SELECT materialization spill above 1,000 rules."""
    return (f"LET AutorunsGoldenRegex <= {source}\n"
        "LET AutorunsGoldenRegexOnlyMatch(GoldenCategory, GoldenImage, GoldenLaunch, GoldenSigner) = "
        'any(items=AutorunsGoldenRegex, filter="rule=>GoldenCategory =~ rule.CategoryRegex '
        'AND GoldenImage =~ rule.ImagePathRegex AND GoldenLaunch =~ rule.LaunchStringRegex '
        'AND GoldenSigner =~ rule.SignerRegex")')
