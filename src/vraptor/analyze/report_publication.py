"""Atomic, byte-bounded publication of generated compact Markdown reports."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from vraptor.analyze.reporting import current_policy
from vraptor.common import atomic_io


def _split_text(text: str, size: int) -> list[str]:
    """Keep fenced blocks intact; split long ordinary lines on UTF-8 boundaries."""
    blocks: list[str] = []
    fence, fenced = "", []
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence:
            fenced.append(line)
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence):
                blocks.append("".join(fenced))
                fence, fenced = "", []
        elif match:
            fence, fenced = match[1], [line]
        else:
            encoded = line.encode("utf-8")
            start = 0
            while len(encoded) - start > size:
                end = start + size
                # Back up over continuation bytes so each chunk decodes exactly.
                while end > start and encoded[end] & 0xC0 == 0x80:
                    end -= 1
                if end == start:
                    raise ValueError("Report byte budget cannot hold one Unicode character")
                blocks.append(encoded[start:end].decode("utf-8"))
                start = end
            blocks.append(encoded[start:].decode("utf-8"))
    if fenced:
        blocks.append("".join(fenced))
    pages: list[str] = []
    body, used = [], 0
    for block in blocks:
        count = len(block.encode("utf-8"))
        if count > size:
            raise ValueError("One fenced report block exceeds the Markdown page budget; increase the budget or publish selected evidence separately")
        if body and used + count > size:
            pages.append("".join(body))
            body, used = [], 0
        body.append(block)
        used += count
    if body:
        pages.append("".join(body))
    return pages


def publish_report(path: Path, text: str, *, max_bytes: int | None = None) -> dict[str, Any]:
    """Publish all compact content, with an index only when pagination is needed.

    Detail names are content-addressed. They are written before the mutable index,
    so an interrupted update leaves the previously published report readable.
    No old files or caller-authored content are removed.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Report destination must not be a symlink")
    maximum = current_policy().compact_markdown_bytes if max_bytes is None else max_bytes
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 512:
        raise ValueError("Compact Markdown page budget must be at least 512 bytes")
    encoded = text.encode("utf-8")
    content_hash = hashlib.sha256(encoded).hexdigest()
    if len(encoded) <= maximum:
        atomic_io.write_text_atomic(path, text, newline="")
        return {"path": str(path), "paginated": False, "page_count": 1,
                "content_sha256": content_hash, "files": [str(path)],
                "maximum_file_bytes": maximum, "omitted_content": False}
    # Exact selected evidence has its own authorization and retention contract.
    # Never turn fragments of a raw evidence block into apparently compact pages.
    if re.search(r"^- Supports:\s*\S", text, flags=re.MULTILINE) or re.search(r"^### Evidence \d+\s*$", text, flags=re.MULTILINE):
        raise ValueError("Selected exact evidence must use its dedicated report contract, not compact pagination")
    generation = hashlib.sha256(f"{content_hash}:{maximum}".encode()).hexdigest()[:16]
    prefix = f"{path.stem}--pages-{generation}"
    # Navigation is bounded independently of body content; filenames are derived
    # from the caller's existing report stem rather than source evidence values.
    link_size = len((prefix + "-000000.md").encode("utf-8"))
    reserve = 180 + 3 * link_size + len(path.name.encode("utf-8"))
    if maximum <= reserve + 16:
        raise ValueError("Markdown byte budget is too small for report navigation")
    bodies = _split_text(text, maximum - reserve)
    names = [f"{prefix}-{index:06d}.md" for index in range(1, len(bodies) + 1)]
    files: list[Path] = []
    pending: list[tuple[Path, str]] = []
    for index, (name, body) in enumerate(zip(names, bodies)):
        navigation = [f"[Report index]({path.name})"]
        if index:
            navigation.append(f"[Previous]({names[index - 1]})")
        if index + 1 < len(names):
            navigation.append(f"[Next]({names[index + 1]})")
        rendered = f"<!-- vraptor-report-page:{content_hash}:{index + 1} -->\n" + " | ".join(navigation) + "\n\n" + body
        if len(rendered.encode("utf-8")) > maximum:
            raise ValueError("Report navigation exceeded the configured byte budget")
        target = path.with_name(name)
        if target.is_symlink():
            raise ValueError("Report detail destination must not be a symlink")
        if target.exists() and target.read_text(encoding="utf-8") != rendered:
            raise ValueError("Report detail destination contains changed or unrelated content")
        if not target.exists():
            pending.append((target, rendered))
        files.append(target)
    index_text = (
        "# Paginated analysis report\n\n"
        f"All report content is retained in **{len(names)} linked pages**; no findings, "
        "coverage limitations or failure status were discarded by pagination.\n\n"
        f"[Read the report]({names[0]}) · [Last page]({names[-1]})\n\n"
        "Pages follow report priority order. Follow Next to read all findings and limitations.\n\n"
        f"Content SHA-256: `{content_hash}`\n"
    )
    if len(index_text.encode("utf-8")) > maximum:
        raise ValueError("Markdown byte budget is too small for the report index")
    for target, rendered in pending:
        atomic_io.write_text_atomic(target, rendered, newline="")
    atomic_io.write_text_atomic(path, index_text, newline="")
    return {"path": str(path), "paginated": True, "page_count": len(names),
            "content_sha256": content_hash, "files": [str(path), *(str(p) for p in files)],
            "maximum_file_bytes": maximum, "omitted_content": False}
