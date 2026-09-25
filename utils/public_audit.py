"""Local metadata-only audit records for public-export policy checks."""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def append_audit(repo: Path, *, check: str, status: str, **metadata: object) -> None:
    """Append one record; callers must supply counts/labels/hashes, never content.

    Refuse symlinks and non-regular files. A logging failure fails the caller,
    rather than silently claiming an auditable check succeeded.
    """
    directory = repo / ".local"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Serialize creation as well as writes: concurrent openat(O_CREAT |
        # O_NOFOLLOW) can fail with ENOENT on macOS during first creation.
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        fd = os.open(
            "public-checks.jsonl",
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("audit log must be a regular file with one link")
            os.fchmod(stream.fileno(), 0o600)
            record = {
                "schema_version": 1,
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "check": check,
                "status": status,
                **metadata,
            }
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
    finally:
        os.close(directory_fd)


def finding_metadata(findings: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Keep rule labels and stable path identifiers without retaining paths."""
    return [
        {"rule": label, "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest()}
        for path, label in findings
    ]
