#!/usr/bin/env python3
"""Validate an offline connected-server Velociraptor schema snapshot."""

from __future__ import annotations

import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from vraptor.artifacts import schema as artifact_schema_compatibility


def main(argv: list[str] | None = None) -> int:
    return artifact_schema_compatibility.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
