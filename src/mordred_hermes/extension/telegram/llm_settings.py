"""Pure changes to the sealed Telegram question-model settings.

Adapters own input prompts, custody checks and the single store transaction.
The retained local key is bound to the complete normalized endpoint.
"""

from __future__ import annotations

from dataclasses import replace
from enum import Enum, auto
from typing import Final

from .llm import LlmConfigError, normalize_local_endpoint, validate_local_api_key
from .secrets import TelegramSecrets


class _KeepKey(Enum):
    KEEP = auto()


KEEP_KEY: Final = _KeepKey.KEEP


def with_local_settings(
    current: TelegramSecrets,
    *,
    endpoint: str,
    model: str,
    api_key: str | None | _KeepKey = KEEP_KEY,
) -> TelegramSecrets:
    """Set a local target; omission retains a key only for the same endpoint."""
    canonical = normalize_local_endpoint(endpoint)
    key = None
    if isinstance(api_key, str):
        key = validate_local_api_key(api_key)
    elif isinstance(api_key, _KeepKey):
        try:
            if normalize_local_endpoint(current.local_endpoint or "") == canonical:
                key = current.local_api_key
        except LlmConfigError:
            pass  # An absent or malformed former endpoint cannot bind a key.
    return replace(
        current,
        backend="local",
        local_endpoint=canonical,
        local_model=model.strip(),
        local_api_key=key,
    )


def with_venice_settings(
    current: TelegramSecrets,
    *,
    api_key: str | _KeepKey = KEEP_KEY,
    model: str | None = None,
) -> TelegramSecrets:
    """Set Venice, preserving an omitted key and a falsey model."""
    key = api_key if isinstance(api_key, str) else current.venice_api_key
    if not key:
        raise LlmConfigError("venice_not_configured")
    return replace(current, backend="venice", venice_api_key=key, venice_model=model or current.venice_model)
