"""Shared token measurement and text chunking helpers."""

from __future__ import annotations

import os
from functools import lru_cache

import tiktoken


DEFAULT_ENCODING_NAME = "o200k_base"
MAX_ANALYSIS_ITEM_TOKENS_ENV = "AI_SKILLS_MAX_ANALYSIS_ITEM_TOKENS"


class TokenBudgetError(ValueError):
    """Raised when content cannot satisfy a requested token budget."""


def token_encoding_name() -> str:
    return os.getenv("AI_SKILLS_TOKEN_ENCODING", DEFAULT_ENCODING_NAME).strip() or DEFAULT_ENCODING_NAME


@lru_cache(maxsize=8)
def encoder_for_name(name: str):
    return tiktoken.get_encoding(name)


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


def split_oversized_text_by_token_budget(text: str, token_limit: int) -> list[str]:
    """Split text at UTF-8-safe token boundaries while preserving exact content."""
    if token_limit <= 0:
        raise TokenBudgetError("token limit must be greater than zero")
    if not text:
        return [""]

    encoder = token_encoder()
    tokens = encoder.encode(text)
    if len(tokens) <= token_limit:
        return [text]

    chunks: list[str] = []
    token_start = 0
    while token_start < len(tokens):
        maximum_end = min(token_start + token_limit, len(tokens))
        decoded = ""
        token_end = maximum_end
        while token_end > token_start:
            encoded_bytes = b"".join(
                encoder.decode_single_token_bytes(token)
                for token in tokens[token_start:token_end]
            )
            try:
                decoded = encoded_bytes.decode("utf-8")
                break
            except UnicodeDecodeError:
                token_end -= 1
        if token_end == token_start:
            raise TokenBudgetError(
                f"token limit {token_limit} cannot reach a UTF-8 character boundary"
            )
        chunks.append(decoded)
        token_start = token_end
    if "".join(chunks) != text:
        raise TokenBudgetError("token splitting did not preserve the original text")
    return chunks


def split_text_chunks(text: str, token_limit: int) -> list[str]:
    """Split text by whole lines, splitting a line only when required."""
    if token_limit <= 0:
        raise TokenBudgetError("token limit must be greater than zero")
    if text == "":
        return [""]

    chunks: list[str] = []
    current: list[str] = []

    def flush_current() -> None:
        if current:
            chunks.append("".join(current))
            current.clear()

    for line in text.splitlines(keepends=True):
        if estimate_tokens(line) > token_limit:
            flush_current()
            chunks.extend(split_oversized_text_by_token_budget(line, token_limit))
            continue
        candidate = "".join(current) + line
        if current and estimate_tokens(candidate) > token_limit:
            flush_current()
        current.append(line)

    flush_current()
    return chunks or [text]
