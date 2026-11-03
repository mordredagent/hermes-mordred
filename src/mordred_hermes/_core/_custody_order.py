"""Thread-local custody intent observations, independent of native custody/SQL.

Observe intent before waiting for any custody mutex or file lock. Only registry
metadata is consulted here; no filesystem checks or owner callbacks run.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from ._database_contracts import DatabaseRefused
from ._database_lifecycle import ExclusiveLease, current_thread_exclusive_leases


class _CustodyState(threading.local):
    def __init__(self) -> None:
        self.pid = os.getpid()
        self.scopes: list[tuple[ExclusiveLease, ...]] = []


_local = _CustodyState()


def _scopes() -> list[tuple[ExclusiveLease, ...]]:
    if _local.pid != os.getpid():
        _local.pid = os.getpid()
        _local.scopes = []
    return _local.scopes


@contextmanager
def custody_scope() -> Iterator[None]:
    """Capture preceding genuine leases before entering or waiting for custody."""
    scopes = _scopes()
    snapshot = current_thread_exclusive_leases()
    scopes.append(snapshot)
    try:
        yield
    finally:
        # An inherited parent's context may unwind after the child's reset.
        if scopes is _scopes():
            scopes.pop()


def active_custody_scopes() -> bool:
    return bool(_scopes())


def assert_preceding_database_lease(lease: ExclusiveLease | None) -> None:
    """Require exact live registry identity and precedence over ALL custody."""
    if not any(candidate is lease for candidate in current_thread_exclusive_leases()):
        raise DatabaseRefused("a genuine live preceding database lease is required")
    if any(not any(candidate is lease for candidate in snapshot) for snapshot in _scopes()):
        raise DatabaseRefused("database lease must precede every active custody scope")


def _after_fork() -> None:
    global _local
    _local = _CustodyState()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
