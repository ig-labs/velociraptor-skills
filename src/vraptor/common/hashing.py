"""Shared canonical-JSON and bounded-memory SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable


DEFAULT_HASH_BLOCK_SIZE = 1024 * 1024


def canonical_json(
    value: Any,
    *,
    ensure_ascii: bool = True,
    default: Callable[[Any], Any] | None = str,
) -> str:
    """Return key-sorted, compact JSON for hashes, fingerprints and identities."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        default=default,
    )


def sha256_json(
    value: Any,
    *,
    ensure_ascii: bool = True,
    default: Callable[[Any], Any] | None = str,
) -> str:
    """Return the SHA-256 of canonical_json(value) encoded as UTF-8."""

    rendered = canonical_json(value, ensure_ascii=ensure_ascii, default=default)
    return sha256_bytes(rendered.encode("utf-8"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(
    path: Path | str,
    *,
    block_size: int = DEFAULT_HASH_BLOCK_SIZE,
) -> str:
    """Return a file SHA-256 without materializing the complete file."""

    if block_size <= 0:
        raise ValueError("block_size must be greater than zero")
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()
