"""Shared token measurement and budget configuration helpers."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import tiktoken


DEFAULT_ENCODING_NAME = "o200k_base"
MAX_ANALYSIS_ITEM_TOKENS_ENV = "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS"


class TokenBudgetError(ValueError):
    """Raised when content cannot satisfy a requested token budget."""


def token_encoding_name() -> str:
    return os.getenv("AI_SKILLS_TOKEN_ENCODING", DEFAULT_ENCODING_NAME).strip() or DEFAULT_ENCODING_NAME


def token_cache_dir() -> Path:
    """Persistent tokenizer cache; tiktoken's default lives in the temp dir."""
    configured = os.environ.get("XDG_CACHE_HOME", "")
    root = Path(configured).expanduser() if configured else Path.home() / ".cache"
    if not root.is_absolute():
        root = Path.home() / ".cache"
    return root / "vraptor" / "tiktoken"


def _use_persistent_cache() -> None:
    if "TIKTOKEN_CACHE_DIR" in os.environ or "DATA_GYM_CACHE_DIR" in os.environ:
        return
    directory = token_cache_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    if os.access(directory, os.W_OK):
        os.environ["TIKTOKEN_CACHE_DIR"] = str(directory)


@lru_cache(maxsize=8)
def encoder_for_name(name: str):
    _use_persistent_cache()
    try:
        return tiktoken.get_encoding(name)
    except OSError as exc:
        raise TokenBudgetError(
            f"Token encoding {name} is not cached and could not be downloaded. "
            "Run `vraptor tools prep` once while online, or copy a populated "
            f"cache to {os.environ.get('TIKTOKEN_CACHE_DIR') or token_cache_dir()}."
        ) from exc


def token_encoder(encoding_name: str | None = None):
    return encoder_for_name(encoding_name or token_encoding_name())


def configured_optional_positive_int(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise TokenBudgetError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise TokenBudgetError(f"{name} must be greater than zero")
    return parsed


def configured_analysis_item_tokens(
    fallback: int | None,
    *,
    explicit: int | None = None,
) -> int | None:
    """Resolve CLI > canonical environment > supplied default."""
    if explicit is not None:
        parsed = int(explicit)
        if parsed <= 0:
            raise TokenBudgetError(
                "maximum analysis item tokens must be greater than zero"
            )
        return parsed
    canonical = configured_optional_positive_int(MAX_ANALYSIS_ITEM_TOKENS_ENV)
    if canonical is not None:
        return canonical
    return fallback


def estimate_tokens(text: object, encoding_name: str | None = None) -> int:
    clean = str(text or "")
    if not clean:
        return 0
    return max(1, len(token_encoder(encoding_name).encode(clean)))


def token_estimator_name(encoding_name: str | None = None) -> str:
    return f"tiktoken:{encoding_name or token_encoding_name()}"
