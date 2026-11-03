"""Process-private holder for the agent-memory key (``HERMES_MEMORY_KEY``).

The database key is HKDF-derived from this value, so it must not be observable
through ``os.environ``: Hermes's terminal environment does not strip the name,
and raw ``dict(os.environ)`` copies pass it to every child process. The runtime
shim therefore never puts a vault-sourced key there, a plaintext-sourced one is
evicted at the points SPEC.md lists, and consumers read it through
:func:`memory_key_value`.

This does not defend against same-UID memory inspection. Scope is this one name;
other vault-enrolled values stay in ``os.environ`` under Hermes's own blocklist.
Standard library only: this module is imported on every platform.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Mapping
from typing import Final

__all__ = ["evict_ambient_memory_key", "get_value", "memory_key_value", "set_value"]

MEMORY_KEY_ENV: Final = "HERMES_MEMORY_KEY"

_lock: Final = threading.Lock()
_value: str | None = None


def set_value(value: str) -> None:
    """Replace the held key."""
    global _value
    with _lock:
        _value = value


def get_value() -> str | None:
    """The held key, or ``None`` when nothing has been stored."""
    with _lock:
        return _value


def _reset_for_tests() -> None:
    global _value
    with _lock:
        _value = None


def memory_key_value(environ: Mapping[str, str]) -> str | None:
    """The memory key as seen through ``environ``.

    Only the real ``os.environ`` consults the holder. An explicit mapping (tests,
    ``KeyProvider(environ=...)``) keeps pure-dict semantics, so a *copy* of
    ``os.environ`` does not see the held key: pass ``os.environ`` itself.
    """
    if environ is os.environ:
        held = get_value()
        if held is not None:
            return held
    return environ.get(MEMORY_KEY_ENV)


def evict_ambient_memory_key() -> None:
    """Move an ambient key out of ``os.environ``; a no-op on Windows.

    Adopts the value only into an empty holder, then always removes the name, so a
    plaintext ``.env`` reloaded by Hermes stays visible only until the next call and
    cannot replace the key this process is already using. An empty variable is not a
    key and is removed without adoption. Never raises, and never logs the value.
    """
    global _value
    if sys.platform == "win32":
        return
    try:
        ambient = os.environ.pop(MEMORY_KEY_ENV, None)
        if ambient:
            with _lock:
                if _value is None:
                    _value = ambient
    except Exception:  # this runs on tool and session paths, which it must never break
        return
