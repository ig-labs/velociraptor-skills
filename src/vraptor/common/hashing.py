"""Shared bounded-memory file hashing helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path


DEFAULT_HASH_BLOCK_SIZE = 1024 * 1024


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
