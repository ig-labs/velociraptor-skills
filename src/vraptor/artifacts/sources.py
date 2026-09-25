"""Deterministic ordered JSON source discovery and one-time loading."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class LoadedPolicyDocument:
    path: Path
    role: str
    order: int
    payload: Any
    content_sha256: str


def expand_reference_paths(
    values: Iterable[str | Path],
    *,
    description: str,
) -> list[Path]:
    output: list[Path] = []
    for raw in values:
        path = Path(raw).expanduser().resolve()
        if path.is_dir():
            candidates = sorted(path.glob("*.json"))
            if not candidates:
                raise RuntimeError(f"{description} directory {path} contains no JSON files.")
            output.extend(candidates)
        else:
            output.append(path)
    return output


def configured_overlay_paths(
    explicit: Iterable[str | Path] | None,
    *,
    environ: Mapping[str, str] | None,
    environment_variable: str,
    description: str,
) -> list[Path]:
    explicit_values = [value for value in (explicit or []) if str(value).strip()]
    if explicit_values:
        return expand_reference_paths(explicit_values, description=description)
    selected_environment = os.environ if environ is None else environ
    configured = str(selected_environment.get(environment_variable) or "").strip()
    if not configured:
        return []
    return expand_reference_paths(
        (value for value in configured.split(os.pathsep) if value.strip()),
        description=description,
    )


def read_document(path: Path | str, *, description: str) -> tuple[Any, str]:
    source = Path(path).expanduser().resolve()
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"{description} {source} could not be read: {exc}") from exc
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{description} {source} is invalid JSON: {exc}") from exc
    return payload, hashlib.sha256(data).hexdigest()


def load_documents(
    paths: Iterable[Path | str],
    *,
    description: str,
) -> tuple[LoadedPolicyDocument, ...]:
    documents: list[LoadedPolicyDocument] = []
    for order, raw_path in enumerate(paths):
        path = Path(raw_path).expanduser().resolve()
        payload, content_sha256 = read_document(path, description=description)
        documents.append(
            LoadedPolicyDocument(
                path=path,
                role="builtin" if order == 0 else "overlay",
                order=order,
                payload=payload,
                content_sha256=content_sha256,
            )
        )
    return tuple(documents)
