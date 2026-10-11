"""Exclude offline conversions from Hermes processes, including before their first DB open.

Runtimes keep a shared lease until exit. Converters take an exclusive lock;
the maintenance CLI skips the runtime lease so it can convert explicitly.
The POSIX primitive is loaded only when used on the supported platform.
"""

from __future__ import annotations

import contextlib
import os
import stat
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Final

LOCK_SUBPATH: Final = ("mordred", "db-encryption.lock")
_MUTEX = threading.RLock()
_LEASES: dict[Path, int] = {}
_EXCLUSIVE: dict[Path, int] = {}


class MigrationError(RuntimeError):
    """Conversion could not safely complete; retain protection and key material."""


class MigrationBusy(MigrationError):
    """Another runtime or converter is using this home."""


def _open(home: Path) -> int:
    path = home.joinpath(*LOCK_SUBPATH)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(fd)
        raise MigrationError("database conversion lock must be a private regular file")
    return fd


def _acquire(fd: int, *, shared: bool, timeout: float) -> None:
    import fcntl

    operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise MigrationBusy("Hermes is running or another process is converting the databases") from None
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))


@contextlib.contextmanager
def runtime_lease(home: Path, *, timeout: float = 120.0) -> Iterator[None]:
    """Wait for conversions, then keep the format stable for this runtime's lifetime."""
    base = home.resolve()
    with _MUTEX:
        if base in _LEASES:
            yield
            return
        fd = _open(base)
        try:
            _acquire(fd, shared=True, timeout=timeout)
            yield
            _LEASES[base] = fd
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)


@contextlib.contextmanager
def migration_lock(home: Path, *, timeout: float = 0.0) -> Iterator[None]:
    """Take exclusive custody, reentrant for one thread's uninstall/restore transaction.

    A process that has already entered normal runtime cannot convert its own
    databases: its threads may open a new connection at any time. Maintenance
    runs in a separate CLI process instead.
    """
    base = home.resolve()
    with _MUTEX:
        if base in _LEASES:
            raise MigrationBusy("this Hermes process is running; stop it and use the standalone maintenance CLI")
        if base in _EXCLUSIVE:
            yield
            return
        fd = _open(base)
        try:
            _acquire(fd, shared=False, timeout=timeout)
            _EXCLUSIVE[base] = fd
            try:
                yield
            finally:
                del _EXCLUSIVE[base]
        finally:
            os.close(fd)


def _after_fork() -> None:
    # A forked child must acquire its own lease. Closing the inherited handles
    # leaves the parent's locks intact and avoids extending them accidentally.
    global _MUTEX
    for fd in {*_LEASES.values(), *_EXCLUSIVE.values()}:
        os.close(fd)
    _LEASES.clear()
    _EXCLUSIVE.clear()
    _MUTEX = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
