"""Shared Autoruns trusted-key canonicalization."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


CANONICALIZATION_VERSION = 4
TRUSTED_KEY_HASH = "SHA1"
# ASCII-only matching/folding is independent of Python/Go Unicode versions.
# Non-ASCII spelling and composition remain evidence-bearing identity values.
ASCII_LOWER_TABLE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]+")
CONTEXT_WHITESPACE_RE = re.compile(r"[ \t]+")
PATH_TRANSFORM_CACHE_KEY = "autoruns-path-v4"


def ascii_lower(value: Any) -> str:
    return str(value or "").translate(ASCII_LOWER_TABLE)


def _ascii_pattern(literal: str) -> str:
    return "".join(
        f"[{char.lower()}{char.upper()}]" if char.isascii() and char.isalpha()
        else re.escape(char) for char in literal
    )


PATH_TRANSFORMS = tuple((re.compile(pattern), replacement) for pattern, replacement in (
    (_ascii_pattern("%localappdata%"), r"c:\users\USER\appdata\local"),
    (_ascii_pattern("%appdata%"), r"c:\users\USER\appdata\roaming"),
    (_ascii_pattern("%userprofile%"), r"c:\users\USER"),
    (_ascii_pattern("c:\\users\\") + r"[^\\]+", r"c:\users\USER"),
    (_ascii_pattern("c:\\documents and settings\\") + r"[^\\]+", r"c:\users\USER"),
    (_ascii_pattern("s-1-5-21-") + r"(?:[0-9]+-){3}[0-9]+", "SID"),
    (_ascii_pattern("%systemroot%"), r"c:\windows"),
    (_ascii_pattern("%windir%"), r"c:\windows"),
    ("^" + _ascii_pattern("\\systemroot\\"), "c:\\windows\\"),
))


def normalize_sensitive_identifiers(value: Any, *, fold_ascii: bool) -> str:
    text = str(value or "")
    for pattern, replacement in PATH_TRANSFORMS:
        text = pattern.sub(lambda _, replacement=replacement: replacement, text)
    return ascii_lower(text) if fold_ascii else text


def normalize_user_path(value: Any) -> str:
    return normalize_sensitive_identifiers(value, fold_ascii=True)


def normalize_context_value(value: Any, *, max_length: int) -> str:
    text = normalize_sensitive_identifiers(value, fold_ascii=False)
    text = CONTROL_CHARACTER_RE.sub(" ", text)
    text = CONTEXT_WHITESPACE_RE.sub(" ", text).strip()
    # Truncation may leave a trailing separator at the boundary. Strip again
    # so repeated validation is idempotent.
    return text[:max_length].rstrip()


def trusted_key_payload(
    *,
    signer: Any,
    image_path: Any,
    launch_string: Any,
) -> dict[str, str]:
    return {
        "ImagePath": normalize_user_path(image_path),
        "LaunchString": normalize_user_path(launch_string),
        "Signer": ascii_lower(signer),
    }


def trusted_key_serialized(
    *,
    signer: Any,
    image_path: Any,
    launch_string: Any,
) -> str:
    # Velociraptor serialize(..., format="json") uses one-space indentation
    # and preserves dict insertion order. Keep this byte representation aligned
    # with trusted_key_vql().
    serialized = json.dumps(
        trusted_key_payload(
            signer=signer,
            image_path=image_path,
            launch_string=launch_string,
        ),
        indent=1,
        ensure_ascii=False,
    )
    # Go's encoding/json, used by Velociraptor serialize(format="json"),
    # HTML-escapes these characters before hashing.
    serialized = (
        serialized.replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
        .replace("\u2028", r"\u2028")
        .replace("\u2029", r"\u2029")
    )
    return serialized


def trusted_key(
    *,
    signer: Any,
    image_path: Any,
    launch_string: Any,
) -> str:
    return hashlib.sha1(trusted_key_serialized(
        signer=signer, image_path=image_path, launch_string=launch_string,
    ).encode("utf-8")).hexdigest()


def trusted_record(
    *,
    category: Any,
    signer: Any,
    image_path: Any,
    launch_string: Any,
) -> dict[str, str | int]:
    payload = trusted_key_payload(
        signer=signer,
        image_path=image_path,
        launch_string=launch_string,
    )
    return {
        "hash_key": trusted_key(
            signer=signer,
            image_path=image_path,
            launch_string=launch_string,
        ),
        "category": ascii_lower(category),
        "signer": payload["Signer"],
        "image_path": payload["ImagePath"],
        "launch_string": payload["LaunchString"],
    }


def ascii_lower_vql(expression: str, *, ascii_source: str | None = None) -> str:
    # Most evidence is ASCII. Only that subset may safely use Go's Unicode
    # lowercasing; keep the slower explicit mapping for all other strings.
    # A path's raw source can prove this without evaluating its transforms twice.
    transforms = ", ".join(
        f"`(?-i){upper}`='{lower}'"
        for upper, lower in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    )
    fallback = (
        f"regex_transform(source={expression}, map=dict({transforms}), "
        'key="autoruns-ascii-v4")'
    )
    return (
        f"if(condition={ascii_source or expression} =~ '''(?-i)^[\\x00-\\x7f]*$''', "
        f"then=lowcase(string={expression}), else={fallback})"
    )


def sensitive_identifiers_vql(expression: str) -> str:
    transforms = ", ".join(
        "`(?-i)" + pattern.pattern.replace("\\", "\\\\") + "`=" + json.dumps(replacement)
        for pattern, replacement in PATH_TRANSFORMS
    )
    return (
        f"regex_transform(source={expression}, map=dict({transforms}), "
        f'key="{PATH_TRANSFORM_CACHE_KEY}")'
    )


def user_path_vql(expression: str) -> str:
    return ascii_lower_vql(sensitive_identifiers_vql(expression), ascii_source=expression)


def trusted_key_serialized_vql() -> str:
    return (
        'serialize(item=dict('
        f"ImagePath={user_path_vql('`Image Path`')}, "
        f"LaunchString={user_path_vql('`Launch String`')}, "
        f"Signer={ascii_lower_vql('Signer')}"
        '), format="json")'
    )


def trusted_key_vql() -> str:
    return ('hash(accessor="data", hashselect="SHA1", path='
            + trusted_key_serialized_vql() + ').SHA1')
