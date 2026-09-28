from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TextIO


def sibling_work_path(
    destination: Path,
    *,
    suffix: str = ".tmp",
) -> Path:
    """Return a unique work path beside its final destination."""
    destination = destination.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}{suffix}"
    )


@contextmanager
def atomic_text_writer(
    destination: Path,
    *,
    encoding: str = "utf-8",
    newline: str | None = None,
) -> Iterator[TextIO]:
    """Write through a private sibling file and atomically replace."""
    temporary = sibling_work_path(destination)
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    replaced = False
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding=encoding,
            newline=newline,
        ) as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        replaced = True
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)


def write_text_atomic(
    destination: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    newline: str | None = None,
) -> None:
    with atomic_text_writer(
        destination,
        encoding=encoding,
        newline=newline,
    ) as handle:
        handle.write(text)


def write_json_atomic(
    destination: Path,
    payload: Any,
    *,
    sort_keys: bool = False,
) -> None:
    write_text_atomic(
        destination,
        json.dumps(payload, indent=2, sort_keys=sort_keys) + "\n",
    )


def create_work_directory(parent: Path, *, prefix: str) -> Path:
    """Create a private working directory under a controlled parent."""
    parent.mkdir(parents=True, exist_ok=True)
    while True:
        path = parent / f".{prefix}-{os.getpid()}-{uuid.uuid4().hex}"
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return path
