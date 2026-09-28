from __future__ import annotations

import hashlib
from pathlib import Path
from unittest import mock

import pytest

from vraptor.common.hashing import sha256_file


def test_sha256_file_streams_without_read_bytes(tmp_path: Path) -> None:
    path = tmp_path / "large.bin"
    content = b"abcdef0123456789" * 131_072
    path.write_bytes(content)

    with mock.patch.object(Path, "read_bytes", side_effect=AssertionError):
        actual = sha256_file(path, block_size=4096)

    assert actual == hashlib.sha256(content).hexdigest()


def test_sha256_file_rejects_non_positive_block_size(tmp_path: Path) -> None:
    path = tmp_path / "value.bin"
    path.write_bytes(b"value")

    with pytest.raises(ValueError, match="greater than zero"):
        sha256_file(path, block_size=0)
