"""Compatibility boundary over the no-SQL root database lifecycle contracts."""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Final

from .._database_contracts import DatabaseBusy as MigrationBusy
from .._database_contracts import DatabaseRefused as MigrationError
from .._database_lifecycle import RuntimeLease, acquire_exclusive, acquire_runtime

__all__ = ["LOCK_SUBPATH", "MigrationBusy", "MigrationError", "migration_lock", "runtime_lease"]

LOCK_SUBPATH: Final = ("mordred", "db-encryption.lock")
_MUTEX = threading.RLock()
_LEASES: dict[Path, tuple[AbstractContextManager[RuntimeLease], RuntimeLease]] = {}


@contextlib.contextmanager
def runtime_lease(home: Path, *, timeout: float = 120.0) -> Iterator[None]:
    """Preserve the installed shim's process-lifetime shared lease convention."""
    base = home.absolute()
    with _MUTEX:
        existing = _LEASES.get(base)
        if existing is not None:
            existing[1].check()
            yield
            return
        # Legacy bootstrap also runs before first-time Hermes setup. Initialize
        # that previously unobserved home here, not in the identified-root core.
        # An existing lifetime lease is checked above before any creation, so
        # losing a root already known to this process always refuses.
        try:
            base.lstat()
        except FileNotFoundError:
            try:
                base.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as exc:
                raise MigrationError("fresh Hermes home could not be initialized safely") from exc
        context = acquire_runtime(base, timeout=timeout)
        lease = context.__enter__()
        try:
            yield
        except BaseException:
            context.__exit__(None, None, None)
            raise
        else:
            _LEASES[base] = (context, lease)


@contextlib.contextmanager
def migration_lock(home: Path, *, timeout: float = 0.0) -> Iterator[None]:
    """Root exclusion is reentrant only for the thread that acquired it."""
    with acquire_exclusive(home, timeout=timeout):
        yield


def _after_fork() -> None:
    global _MUTEX
    # The core discarded inherited handles/authority in its earlier callback.
    # Installed legacy shims still need exclusion before child Python resumes.
    homes = tuple(_LEASES)
    _LEASES.clear()
    _MUTEX = threading.RLock()
    try:
        for home in homes:
            context = acquire_runtime(home)
            _LEASES[home] = (context, context.__enter__())
    except BaseException:
        # A fork hook exception would otherwise be ignored, leaving an installed
        # legacy shim running without exclusion. Refuse that unsafe child.
        os._exit(74)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
