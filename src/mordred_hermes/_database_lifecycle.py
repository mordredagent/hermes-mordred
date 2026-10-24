"""Root database leases precede custody. This module never imports SQL/custody."""

from __future__ import annotations

import contextlib
import math
import os
import threading
from collections.abc import Iterator
from pathlib import Path

from ._database_contracts import DatabaseBusy, DatabaseRefused, NativeDatabaseLock, RootIdentity

_LOCK = threading.RLock()
_READERS: dict[RootIdentity, set[RuntimeLease]] = {}
_WRITERS: dict[RootIdentity, tuple[int, ExclusiveLease | None, int]] = {}
_HANDLES: set[NativeDatabaseLock] = set()


def _open(root: Path) -> NativeDatabaseLock:
    if os.name == "nt":
        from ._database_locking_windows import open_lock as windows_open

        return windows_open(root)
    if os.name == "posix":
        from ._database_locking_posix import open_lock as posix_open

        return posix_open(root)
    raise DatabaseRefused("database leases are unsupported on this platform")


def _timeout(value: float) -> None:
    if not math.isfinite(value) or value < 0:
        raise DatabaseRefused("invalid database lease timeout")


class RuntimeLease:
    def __init__(self, native: NativeDatabaseLock) -> None:
        self._native = native
        self.root = native.identity
        self._pid = os.getpid()
        self._closed = False

    def check(self) -> None:
        with _LOCK:
            if self._closed or self._pid != os.getpid() or self not in _READERS.get(self.root, set()):
                raise DatabaseRefused("database runtime lease is no longer held")
        self._native.check()

    def close(self) -> None:
        with _LOCK:
            if self._closed or self._pid != os.getpid():
                return
            self._closed = True
            _READERS.get(self.root, set()).discard(self)
            _HANDLES.discard(self._native)
        self._native.close()


class ExclusiveLease:
    def __init__(self, native: NativeDatabaseLock) -> None:
        self._native = native
        self.root = native.identity
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._closed = False

    def assert_held(self, root: Path) -> None:
        with _LOCK:
            state = _WRITERS.get(self.root)
            if (
                self._closed
                or self._pid != os.getpid()
                or self._thread != threading.get_ident()
                or state is None
                or state[1] is not self
            ):
                raise DatabaseRefused("a preceding exclusive database lease is required")
        self._native.check()
        # Observation is metadata-only: checking a wrong root cannot create
        # a lock or mutate that root before rejecting it.
        if os.name == "nt":
            from ._database_locking_windows import identify_root
        else:
            from ._database_locking_posix import identify_root
        if identify_root(root) != self.root:
            raise DatabaseRefused("exclusive database lease belongs to another root")

    def _release(self) -> None:
        with _LOCK:
            if self._closed or self._pid != os.getpid():
                return
            state = _WRITERS.get(self.root)
            if state is None or state[1] is not self or state[0] != threading.get_ident():
                raise DatabaseRefused("exclusive database lease owner changed")
            if state[2] > 1:
                _WRITERS[self.root] = (state[0], self, state[2] - 1)
                return
            del _WRITERS[self.root]
            _HANDLES.discard(self._native)
            self._closed = True
        self._native.close()


@contextlib.contextmanager
def acquire_runtime(root: Path, *, timeout: float = 120.0) -> Iterator[RuntimeLease]:
    _timeout(timeout)
    native = _open(root)
    lease = RuntimeLease(native)
    admitted = False
    try:
        with _LOCK:
            if native.identity in _WRITERS:
                raise DatabaseBusy("this process already owns exclusive database maintenance")
            _READERS.setdefault(native.identity, set()).add(lease)
            _HANDLES.add(native)
            admitted = True
        native.acquire(shared=True, timeout=timeout)
        lease.check()
        yield lease
    finally:
        if admitted:
            lease.close()
        else:
            native.close()


@contextlib.contextmanager
def acquire_exclusive(root: Path, *, timeout: float = 0.0) -> Iterator[ExclusiveLease]:
    _timeout(timeout)
    native = _open(root)
    identity = native.identity
    lease: ExclusiveLease | None = None
    reserved = False
    try:
        with _LOCK:
            if _READERS.get(identity):
                raise DatabaseBusy("this Hermes process is running; database leases cannot upgrade in place")
            previous = _WRITERS.get(identity)
            if previous is not None:
                if previous[0] != threading.get_ident() or previous[1] is None:
                    raise DatabaseBusy("database maintenance is already using this root")
                lease = previous[1]
                _WRITERS[identity] = (previous[0], lease, previous[2] + 1)
            else:
                _WRITERS[identity] = (threading.get_ident(), None, 1)
                _HANDLES.add(native)
                reserved = True
        if lease is not None:
            native.close()
            lease.assert_held(root)
            yield lease
        else:
            native.acquire(shared=False, timeout=timeout)
            lease = ExclusiveLease(native)
            with _LOCK:
                _WRITERS[identity] = (threading.get_ident(), lease, 1)
            lease.assert_held(root)
            yield lease
    finally:
        if lease is not None:
            lease._release()
        else:
            if reserved:
                with _LOCK:
                    _WRITERS.pop(identity, None)
                    _HANDLES.discard(native)
            native.close()


def _after_fork() -> None:
    global _LOCK
    for handle in tuple(_HANDLES):
        handle.close()
    _HANDLES.clear()
    _READERS.clear()
    _WRITERS.clear()
    _LOCK = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
