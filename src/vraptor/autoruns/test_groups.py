"""Evidence-based grouping and readable review of finite Autoruns identities.

Grouping changes the order and boundaries of finite expressions, never the
identity tuples they accept. Observed Category labels may separately constrain
experimental matching; an identity without labels keeps an unrestricted match.
Path and launch descriptions are grouping hints, not inferred Category evidence.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
from collections import defaultdict
from typing import Any

import re2

from vraptor.autoruns import pipeline as autoruns


_EXECUTABLE = re.compile(r'^(?:"([^"\r\n]+\.exe)"|([^"\r\n]+?\.exe))(?=$|[ \t])')


def _compile(pattern: str) -> Any:
    options = re2.Options()
    options.log_errors = False
    try:
        return re2.compile(pattern, options=options)
    except re2.error as exc:
        raise RuntimeError(f"Invalid grouped autoruns_test RE2 expression: {exc}") from exc


def _identities(exacts: list[tuple[str, str]]) -> dict[str, tuple[str, dict[str, str]]]:
    identities: dict[str, tuple[str, dict[str, str]]] = {}
    for key, payload in exacts:
        if not isinstance(key, str) or not isinstance(payload, str):
            raise RuntimeError("Grouped autoruns_test identities require string hashes and payloads.")
        if hashlib.sha1(payload.encode("utf-8")).hexdigest() != key:
            raise RuntimeError("Grouped autoruns_test identity payload/hash mismatch.")
        try:
            item = json.loads(payload)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Invalid grouped autoruns_test identity JSON.") from exc
        if (not isinstance(item, dict) or set(item) != {"ImagePath", "LaunchString", "Signer"}
                or not all(isinstance(value, str) for value in item.values())):
            raise RuntimeError("Invalid grouped autoruns_test identity fields.")
        # The verified hash already detects a repeated payload/key; a second
        # payload-index dictionary would retain the same large strings again.
        if key in identities:
            raise RuntimeError("Duplicate grouped autoruns_test identity.")
        identities[key] = payload, item
    return identities


def _category_set(key: str, categories: dict[str, list[str]]) -> tuple[str, ...]:
    values = categories.get(key, [])
    if not isinstance(values, list) or any(not isinstance(value, str) or not value
                                          or value != value.strip()
                                          for value in values):
        raise RuntimeError("Grouped autoruns_test categories require nonblank string labels without outer whitespace.")
    return tuple(sorted({autoruns.ascii_lower(value) for value in values}))


def _literal(value: str) -> str:
    return "".join("\\" + char if char in r"\.^$|?*+()[]{}" else
                   f"\\x{ord(char):02x}" if ord(char) < 32 or ord(char) == 127 else
                   char for char in value)


def _field_regex(value: str) -> str:
    return r"(?-i)\A(?:" + _literal(value) + r")\z"


def _category_regex(categories: tuple[str, ...]) -> str:
    if not categories:
        return ".*"
    # Runtime folds ASCII category labels before matching, as it does the
    # canonical identity fields. Unicode spelling remains evidence-bearing.
    return r"(?-i)\A(?:" + "|".join(_literal(value) for value in categories) + r")\z"


def _launch_family(image: str, launch: str) -> str:
    if not launch:
        return "empty launch"
    if launch == image:
        return "launch equals image"
    match = _EXECUTABLE.match(launch)
    if match:
        executable = (match.group(1) or match.group(2)).replace("/", "\\")
        family = ("svchost executable launch" if ntpath.basename(executable) == "svchost.exe"
                  else "other executable launch")
        return f"{family}: {executable}"
    return "other launch"


def grouped_patterns(
    exacts: list[tuple[str, str]], categories: dict[str, list[str]] | None = None,
    *, max_pattern_bytes: int = 32768,
) -> list[dict[str, Any]]:
    """Return deterministic finite patterns with one group per source identity.

    Groups share the complete observed category set, Windows image parent and
    extension, and launch family (including its executable path when present).
    Each pattern retains the existing 256-identity and caller-selected byte caps.
    Missing or empty category lists produce ``.*``, including the empty label.
    CategoryRegex matches ASCII-lowercased labels, preserving Unicode spelling.
    """
    # The database module imports this helper when loading/building; importing
    # its finite-expression generator here keeps module initialization acyclic.
    from vraptor.autoruns.test_store import exact_patterns

    exact_patterns([], max_pattern_bytes=max_pattern_bytes)  # Validate empty input too.
    identities = _identities(exacts)
    categories = {} if categories is None else categories
    if not isinstance(categories, dict) or any(key not in identities for key in categories):
        raise RuntimeError("Grouped autoruns_test category map contains an unknown identity.")
    buckets: dict[tuple[tuple[str, ...], str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for key, (payload, item) in identities.items():
        image, launch = item["ImagePath"], item["LaunchString"]
        parent = ntpath.dirname(image).replace("/", "\\")
        extension = ntpath.splitext(ntpath.basename(image))[1]
        group_key = (_category_set(key, categories), parent, extension, _launch_family(image, launch))
        buckets[group_key].append((key, payload))
    result: list[dict[str, Any]] = []
    for (labels, parent, extension, launch_family), records in sorted(buckets.items()):
        category_regex = _category_regex(labels)
        _compile(category_regex)
        label = (f"{', '.join(labels) if labels else 'Category unknown (all)'} | "
                 f"{parent or '(no image directory)'} | {extension or '(no extension)'} | "
                 f"{launch_family}")
        pending = dict(records)
        for pattern in exact_patterns((payload for _, payload in records),
                                      max_pattern_bytes=max_pattern_bytes):
            compiled = _compile(pattern)
            source_hashes = sorted(key for key, payload in pending.items()
                                   if compiled.search(payload) is not None)
            if not source_hashes:
                raise RuntimeError("Grouped autoruns_test pattern has no source identity.")
            rules = [{"HashKey": key, "CategoryRegex": category_regex,
                      "ImagePathRegex": _field_regex(identities[key][1]["ImagePath"]),
                      "LaunchStringRegex": _field_regex(identities[key][1]["LaunchString"]),
                      "SignerRegex": _field_regex(identities[key][1]["Signer"])}
                     for key in source_hashes]
            result.append({"Group": label, "CategoryRegex": category_regex,
                           "IdentityRegex": pattern, "SourceHashes": source_hashes,
                           "Rules": rules})
            for key in source_hashes:
                del pending[key]
        if pending:
            raise RuntimeError("Grouped autoruns_test expressions omitted source identities.")
    return result


def _code(value: str) -> str:
    longest = max((len(match[0]) for match in re.finditer(r"`+", value)), default=0)
    delimiter = "`" * (longest + 1)
    return f"{delimiter} {value} {delimiter}"


def _table_code(value: str) -> str:
    return _code(value.replace("\r", r"\r").replace("\n", r"\n").replace("|", r"\|"))


def render_grouped_review(
    exacts: list[tuple[str, str]], groups: list[dict[str, Any]], notes: dict[str, str] | None = None,
    paired_rules: list[dict[str, str]] | None = None,
) -> str:
    """Render Markdown with one correlated field-regex rule per physical line.

    Review whitespace is presentation only. Engine patterns are named by their
    one-based global positions; their full strings remain in the database/export.
    Notes contain review-only descriptions and never participate in matching.
    Optional paired rules preserve their existing category/signer-independent
    behavior; they remain separate from exact-derived rules.
    """
    identities = _identities(exacts)
    notes = {} if notes is None else notes
    if not isinstance(notes, dict) or any(key not in identities or not isinstance(value, str)
                                          for key, value in notes.items()):
        raise RuntimeError("Grouped autoruns_test notes require known identity hashes and strings.")
    paired_rules = [] if paired_rules is None else paired_rules
    if not isinstance(paired_rules, list) or any(
        not isinstance(rule, dict)
        or not all(isinstance(rule.get(field), str) for field in ("ImagePathRegex", "LaunchStringRegex"))
        or not isinstance(rule.get("Description", ""), str)
        for rule in paired_rules
    ):
        raise RuntimeError("Grouped autoruns_test paired review rules require string fields.")
    lines = ["# Grouped Autoruns exact identity review", "",
             "Each identity occupies one line. Group labels describe observed categories, image "
             "directories and launch forms; they do not infer a persistence category.", "",
             "Category `.*` is unrestricted, including an empty category. Display line breaks "
             "are not inserted into the engine regex patterns. Field matches stay correlated "
             "within each row; Notes are review-only.", ""]
    grouped: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    seen: set[str] = set()
    for position, pattern in enumerate(groups, start=1):
        grouped.setdefault((pattern["Group"], pattern["CategoryRegex"]), []).append((position, pattern))
    for group_position, ((label, category), patterns) in enumerate(grouped.items(), start=1):
        lines.extend([f"## Group {group_position:03d}", "",
                      f"Label: {_code(json.dumps(label, ensure_ascii=False))}", "",
                      f"CategoryRegex: {_code(category)}", ""])
        for pattern_position, (global_position, pattern) in enumerate(patterns, start=1):
            lines.extend([f"### Pattern {pattern_position:03d} (global position {global_position:03d})", "",
                          "| HashKey | Category | ImagePath | LaunchString | Signer | Notes |",
                          "| --- | --- | --- | --- | --- | --- |"])
            if sorted(rule["HashKey"] for rule in pattern["Rules"]) != sorted(pattern["SourceHashes"]):
                raise RuntimeError("Grouped autoruns_test review rules/source hashes differ.")
            if any(rule["HashKey"] not in identities for rule in pattern["Rules"]):
                raise RuntimeError("Grouped autoruns_test review has unknown source hashes.")
            ordered_rules = sorted(pattern["Rules"], key=lambda rule: (
                *(identities[rule["HashKey"]][1][field] for field in ("ImagePath", "LaunchString", "Signer")),
                rule["HashKey"],
            ))
            for rule in ordered_rules:
                key = rule["HashKey"]
                if key not in identities or key in seen:
                    raise RuntimeError("Grouped autoruns_test review has unknown or duplicate source hashes.")
                seen.add(key)
                values = [key, rule["CategoryRegex"], rule["ImagePathRegex"],
                          rule["LaunchStringRegex"], rule["SignerRegex"], notes.get(key, "")]
                lines.append("| " + " | ".join(_table_code(value) for value in values) + " |")
            lines.append("")
    if seen != set(identities):
        raise RuntimeError("Grouped autoruns_test review omitted source identities.")
    if paired_rules:
        lines.extend(["## Existing paired regex rules", "",
                      "These original rules match ImagePath and LaunchString together. Category "
                      "and Signer remain unrestricted (`.*`); approved paired rules match directly. "
                      "Notes preserve the original review-only Description.", "",
                      "| Rule | Category | ImagePath | LaunchString | Signer | Notes |",
                      "| --- | --- | --- | --- | --- | --- |"])
        for position, rule in enumerate(paired_rules, start=1):
            values = [f"{position:03d}", ".*", rule["ImagePathRegex"],
                      rule["LaunchStringRegex"], ".*", rule.get("Description", "")]
            lines.append("| " + " | ".join(_table_code(value) for value in values) + " |")
        lines.append("")
    return "\n".join(lines)
