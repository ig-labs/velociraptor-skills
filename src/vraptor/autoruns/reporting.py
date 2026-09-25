"""Bounded rendering helpers for Autoruns suspicious context."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


def hide_unassessed_target_execution(payload: Mapping[str, Any]) -> bool:
    """Omit redundant fleet-coverage status only for Autoruns-only output."""
    coverage = payload.get("coverage")
    target = (
        coverage.get("target_execution") or coverage.get("target_execution_status")
        if isinstance(coverage, Mapping)
        else None
    ) or payload.get("target_execution_coverage")
    artifacts = payload.get("selected_artifacts") or payload.get("artifacts") or []
    return target == "not_assessed" and bool(artifacts) and all(
        artifact in {"IG.Windows.Sysinternals.Autoruns", "Windows.Sysinternals.Autoruns"}
        for artifact in artifacts
    )


def _compact_text(
    value: Any,
    *,
    fallback: str = "",
    limit: int = 320,
) -> str:
    rendered = " ".join(str(value or "").split()).strip() or fallback
    if len(rendered) > limit:
        rendered = rendered[: limit - 1].rstrip() + "…"
    return rendered.replace("|", "\\|")


def _markdown_code(value: Any, *, fallback: str = "unknown") -> str:
    rendered = _compact_text(value, fallback=fallback)
    return "`" + rendered.replace("`", "\\`") + "`"


def _endpoint_key(value: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(value.get("fqdn") or value.get("Fqdn") or ""),
        str(value.get("client_id") or value.get("ClientId") or ""),
    )


def grouped_context(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated context and merge bounded endpoint/persistence summaries."""

    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        key = tuple(
            " ".join(str(row.get(field) or "").split())
            for field in (
                "identity_sha256",
                "Severity",
                "Reason",
                "Entry",
                "EntryLocation",
                "Category",
                "ImagePath",
                "LaunchString",
                "Signer",
                "Description",
                "Version",
                "SHA256",
            )
        )
        item = grouped.setdefault(
            key,
            {
                "row": row,
                "endpoints": {},
                "persistence": {},
                "row_count": 0,
                "host_count": 0,
                "omitted_endpoint_count": 0,
                "omitted_persistence_count": 0,
            },
        )
        item["row_count"] += max(int(row.get("row_count") or 1), 1)
        item["host_count"] += max(int(row.get("host_count") or 0), 0)

        raw_endpoints = row.get("endpoints") or []
        if isinstance(raw_endpoints, list):
            for raw_endpoint in raw_endpoints:
                if not isinstance(raw_endpoint, Mapping):
                    continue
                endpoint = _endpoint_key(raw_endpoint)
                if not any(endpoint):
                    continue
                item["endpoints"][endpoint] = (
                    int(item["endpoints"].get(endpoint) or 0)
                    + max(int(raw_endpoint.get("row_count") or 1), 1)
                )
        endpoint = (
            str(row.get("Fqdn") or ""),
            str(row.get("ClientId") or ""),
        )
        if any(endpoint):
            item["endpoints"][endpoint] = (
                int(item["endpoints"].get(endpoint) or 0) + 1
            )
        item["omitted_endpoint_count"] += max(
            int(row.get("omitted_endpoint_count") or 0), 0
        )

        raw_persistence = row.get("persistence") or []
        if isinstance(raw_persistence, list):
            for raw_variant in raw_persistence:
                if not isinstance(raw_variant, Mapping):
                    continue
                variant = (
                    str(raw_variant.get("category") or ""),
                    str(raw_variant.get("entry_location") or ""),
                    str(raw_variant.get("entry") or ""),
                )
                if any(variant):
                    item["persistence"][variant] = None
        legacy_variant = (
            str(row.get("Category") or ""),
            str(row.get("EntryLocation") or ""),
            str(row.get("Entry") or ""),
        )
        if any(legacy_variant):
            item["persistence"][legacy_variant] = None
        item["omitted_persistence_count"] += max(
            int(row.get("omitted_persistence_count") or 0), 0
        )

    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4}
    return sorted(
        grouped.values(),
        key=lambda item: (
            priority.get(
                str(item["row"].get("Severity") or "review").casefold(),
                5,
            ),
            -int(item["row_count"]),
            str(item["row"].get("Entry") or ""),
            str(item["row"].get("LaunchString") or ""),
        ),
    )


def render_context(
    rows: Iterable[Mapping[str, Any]],
    *,
    heading_level: int,
    context_group_count: int = 0,
    max_groups: int = 10,
    max_endpoints_per_group: int = 10,
) -> list[str]:
    """Render bounded context with explicit legacy and omission semantics."""

    groups = grouped_context(rows)
    if not groups:
        return ["- No suspicious context rows.", ""]
    lines = [f"{'#' * heading_level} Representative suspicious context", ""]
    for item in groups[:max_groups]:
        row = item["row"]
        severity = _compact_text(
            row.get("Severity"), fallback="review"
        ).upper()
        endpoints = sorted(item["endpoints"])
        visible_endpoints = endpoints[:max_endpoints_per_group]
        endpoint_text = ", ".join(
            f"{_markdown_code(fqdn)} ({_markdown_code(client_id)})"
            for fqdn, client_id in visible_endpoints
        )
        endpoint_omitted = max(
            len(endpoints) - len(visible_endpoints), 0
        ) + int(item.get("omitted_endpoint_count") or 0)
        if endpoint_omitted:
            endpoint_text += (
                (", " if endpoint_text else "")
                + f"plus {endpoint_omitted} more endpoint(s)"
            )
        host_count = max(int(item.get("host_count") or 0), len(endpoints))
        if not endpoint_text and host_count:
            endpoint_text = (
                f"{host_count} endpoint(s); identities unavailable in legacy "
                "compact state"
            )

        title = row.get("Entry") or row.get("ImagePath") or "Suspicious identity"
        lines.extend(
            [
                f"{'#' * (heading_level + 1)} {severity}: "
                f"{_markdown_code(title)}",
                "",
                f"- Reason: {_compact_text(row.get('Reason'))}",
            ]
        )
        persistence = sorted(item["persistence"])
        for category, entry_location, entry in persistence:
            parts = []
            if entry_location:
                parts.append(f"location {_markdown_code(entry_location)}")
            if category:
                parts.append(f"category {_markdown_code(category)}")
            if entry:
                parts.append(f"entry {_markdown_code(entry)}")
            if parts:
                lines.append("- Persistence: " + "; ".join(parts))
        if int(item.get("omitted_persistence_count") or 0):
            lines.append(
                "- Persistence: plus "
                f"{int(item['omitted_persistence_count'])} more variant(s)"
            )
        if row.get("ImagePath"):
            lines.append(f"- Image: {_markdown_code(row.get('ImagePath'))}")
        if row.get("LaunchString"):
            lines.append(
                f"- Launch example: {_markdown_code(row.get('LaunchString'))}"
            )
        lines.extend(
            [
                f"- Exact rows represented: {int(item['row_count'])}",
                f"- Endpoints: {endpoint_text or 'unknown'}",
            ]
        )
        source = row.get("source")
        if isinstance(source, Mapping) and source.get("query_sha256"):
            lines.append(
                "- Source query: "
                f"hunt {_markdown_code(source.get('hunt_id'))}; "
                f"artifact {_markdown_code(source.get('artifact'))}; "
                f"SHA-256 {_markdown_code(source.get('query_sha256'))}"
            )
        lines.append("")

    total_groups = max(int(context_group_count or 0), len(groups))
    omitted_groups = max(total_groups - min(len(groups), max_groups), 0)
    if omitted_groups:
        lines.extend(
            [
                f"{omitted_groups} additional suspicious identity summary "
                "group(s) remain authoritative in Velociraptor.",
                "",
            ]
        )
    return lines
