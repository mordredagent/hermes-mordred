"""Shared no-interpolation dotenv semantics and strict effective memory keys."""

from __future__ import annotations

import io

from .._database_contracts import DatabaseRefused


def parse_env(plaintext: bytes) -> dict[str, str | None]:
    """Runtime-compatible, last-wins dotenv values without interpolation."""
    from dotenv import dotenv_values

    return dict(dotenv_values(stream=io.StringIO(plaintext.decode("utf-8")), interpolate=False))


def effective_memory_key(plaintext: bytes | None) -> bytes | None:
    """Authenticate an unambiguous effective key, comparing only decoded bytes.

    A missing entry means no source; a present empty/bare/invalid entry refuses.
    Duplicate well-formed entries retain runtime's last-wins interpretation.
    """
    from dotenv.parser import parse_stream

    from .memory_crypto import MemoryKeyError, decode_key

    if plaintext is None:
        return None
    try:
        text = plaintext.decode("utf-8")
        if any(binding.error for binding in parse_stream(io.StringIO(text))):
            raise DatabaseRefused("vault dotenv source is malformed or ambiguous")
        values = parse_env(plaintext)
        if "HERMES_MEMORY_KEY" not in values:
            return None
        value = values["HERMES_MEMORY_KEY"]
        if not value:
            raise DatabaseRefused("vault memory key is empty or ambiguous")
        return decode_key(value)
    except (UnicodeDecodeError, MemoryKeyError) as exc:
        raise DatabaseRefused("vault memory key source is invalid") from exc
