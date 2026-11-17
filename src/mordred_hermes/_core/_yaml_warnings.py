"""Suppress YAML warnings on parsing threads without changing warning filters.

Warning filters and capture sinks are process-global on supported Python versions.
A temporary dispatcher leaves both alone and delegates warnings from other threads
to the caller's original function. Only scope entry/exit is serialized; parsing
stays concurrent. Forked children retain only their surviving thread's scopes.
"""

from __future__ import annotations

import operator
import os
import threading
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

_lock = threading.RLock()
_local = threading.local()
_scopes = 0
_original_warn: Callable[..., None] | None = None


def _after_fork() -> None:
    global _lock, _local, _scopes, _original_warn
    depth = getattr(_local, "depth", 0)
    _lock = threading.RLock()
    _local = threading.local()
    _local.depth = depth
    _scopes = depth
    if not depth and _original_warn is not None:
        warnings.warn = _original_warn
        _original_warn = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


@contextmanager
def quiet_yaml_warnings() -> Iterator[None]:
    """Drop only YAMLWarning on this thread; preserve every caller's warning policy."""
    from ruamel.yaml.error import YAMLWarning

    global _scopes, _original_warn
    with _lock:
        if not _scopes:
            original_warn = warnings.warn

            def warn(
                message: str | Warning,
                category: type[Warning] | None = None,
                stacklevel: int = 1,
                source: object | None = None,
                **kwargs: Any,
            ) -> None:
                try:
                    adjusted_stacklevel = max(1, operator.index(stacklevel)) + 1
                except TypeError:
                    original_warn(message, category, stacklevel=stacklevel, source=source, **kwargs)
                    return
                warning_type = type(message) if isinstance(message, Warning) else category
                if (
                    getattr(_local, "depth", 0)
                    and isinstance(warning_type, type)
                    and issubclass(warning_type, YAMLWarning)
                ):
                    return
                original_warn(message, category, stacklevel=adjusted_stacklevel, source=source, **kwargs)

            _original_warn = original_warn
            warnings.warn = warn
        _scopes += 1
        _local.depth = getattr(_local, "depth", 0) + 1
    try:
        yield
    finally:
        with _lock:
            _local.depth -= 1
            _scopes -= 1
            if not _scopes:
                assert _original_warn is not None
                warnings.warn = _original_warn
                _original_warn = None
