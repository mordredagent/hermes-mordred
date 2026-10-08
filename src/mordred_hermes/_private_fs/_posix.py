"""Descriptor-relative private storage; no changes to legacy POSIX callers."""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import secrets
import stat
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

from ._types import CommitState, PrivateDirectory, PrivateFSError, PrivateTransaction, Reason, validate_leaf

_NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_guard = threading.Lock()
_owners: set[tuple[int, int, int]] = set()
_lock_fds: set[int] = set()


def _before_fork() -> None:
    _guard.acquire()


def _after_parent_fork() -> None:
    _guard.release()


def _after_child_fork() -> None:
    global _guard
    for fd in _lock_fds:
        with contextlib.suppress(OSError):
            os.close(fd)  # Never LOCK_UN a shared open-file description in the child.
    _lock_fds.clear()
    _owners.clear()
    _guard = threading.Lock()


os.register_at_fork(before=_before_fork, after_in_parent=_after_parent_fork, after_in_child=_after_child_fork)


def _error(exc: OSError, operation: str, committed: bool = False) -> PrivateFSError:
    reasons: dict[int | None, Reason] = {
        errno.ENOENT: "missing",
        errno.EEXIST: "exists",
        errno.ELOOP: "unsafe",
        errno.ENOTDIR: "unsafe",
        errno.EACCES: "access_denied",
        errno.EPERM: "access_denied",
    }
    reason = reasons.get(exc.errno, "io")
    state: CommitState = "uncertain" if committed else "not_committed"
    return PrivateFSError(reason, operation, native_code=exc.errno, commit_state=state)


def _private(fd: int, directory: bool = False) -> os.stat_result:
    info = os.fstat(fd)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or (not directory and info.st_nlink != 1)
    ):
        raise PrivateFSError("unsafe", "validate_object")
    return info


def _ancestor(fd: int) -> None:
    info = os.fstat(fd)
    if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        raise PrivateFSError("unsafe", "validate_ancestor")


def _flush(fd: int) -> None:
    os.fsync(fd)
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None and stat.S_ISREG(os.fstat(fd).st_mode):
        try:
            fcntl.fcntl(fd, full)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise


@contextlib.contextmanager
def open_private_directory(path: str | Path, *, create: bool = False) -> Iterator[PrivateDirectory]:
    raw = os.fspath(path)
    if not raw.startswith("/") or "\x00" in raw or ".." in raw.split("/") or "." in raw.split("/"):
        raise PrivateFSError("unsafe", "directory_path")
    parts = Path(raw).parts[1:]
    if not parts:
        raise PrivateFSError("unsafe", "directory_path")
    fds: list[int] = []
    directory: _Directory | None = None
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
        fds.append(fd)
        for i, part in enumerate(parts):
            _ancestor(fd)
            if create and i == len(parts) - 1:
                # A sticky shared parent protects existing entries, not an absent name.
                if os.fstat(fd).st_mode & 0o022:
                    raise PrivateFSError("unsafe", "create_parent")
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=fd)
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=fd)
            fds.append(fd)
        _private(fd, directory=True)
        directory = _Directory(fd)
        yield directory
    except PrivateFSError:
        raise
    except OSError as exc:
        raise _error(exc, "directory") from exc
    finally:
        if directory is not None:
            directory.active = False
        _close_fds(reversed(fds), committed=directory is not None and directory.published)


class _Directory:
    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.active = True
        self.pid = os.getpid()
        self.published = False

    def _check(self) -> None:
        if not self.active or self.pid != os.getpid():
            raise RuntimeError("private directory is closed or inherited across fork")
        _private(self.fd, directory=True)

    @contextlib.contextmanager
    def _open(self, name: str, *, lock: bool = False) -> Iterator[int]:
        self._check()
        flags = os.O_RDWR | os.O_CREAT if lock else os.O_RDONLY
        with _guard:
            fd = os.open(name, flags | _NOFOLLOW, 0o600, dir_fd=self.fd)
            if lock:
                _lock_fds.add(fd)
        try:
            info = _private(fd)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
                raise PrivateFSError("unsafe", "identity")
            yield fd
        finally:
            if not lock or self.pid == os.getpid():
                with _guard:
                    try:
                        _close_fds(iter((fd,)), committed=lock and self.published)
                    finally:
                        _lock_fds.discard(fd)

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        self._check()
        validate_leaf(name)
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        try:
            with self._open(name) as fd:
                chunks: list[bytes] = []
                size = 0
                while size <= max_bytes:
                    data = os.read(fd, min(65536, max_bytes + 1 - size))
                    if not data:
                        return b"".join(chunks)
                    size += len(data)
                    chunks.append(data)
                raise PrivateFSError("unsafe", "read_limit")
        except PrivateFSError:
            raise
        except OSError as exc:
            raise _error(exc, "read") from exc

    @contextlib.contextmanager
    def transaction(self, *, blocking: bool = True) -> Iterator[PrivateTransaction]:
        self._check()
        info = os.fstat(self.fd)
        owner = (info.st_dev, info.st_ino, threading.get_ident())
        with _guard:
            if owner in _owners:
                raise RuntimeError("recursive private transaction")
            _owners.add(owner)
        try:
            with self._open(".mordred-fs.lock", lock=True) as fd:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if not blocking:
                            raise PrivateFSError("busy", "lock") from None
                        time.sleep(0.05)
                tx = _Transaction(self)
                try:
                    _private(fd)
                    named = os.stat(".mordred-fs.lock", dir_fd=self.fd, follow_symlinks=False)
                    if os.fstat(fd).st_ino != named.st_ino:
                        raise PrivateFSError("unsafe", "lock_identity")
                    yield tx
                finally:
                    tx.active = False
                    # Closing the descriptor also releases the lock if unlock fails.
                    if self.pid == os.getpid():
                        with contextlib.suppress(OSError):
                            fcntl.flock(fd, fcntl.LOCK_UN)
        except PrivateFSError:
            raise
        except OSError as exc:
            raise _error(exc, "transaction") from exc
        finally:
            if self.pid == os.getpid():
                with _guard:
                    _owners.remove(owner)


class _Transaction:
    def __init__(self, directory: _Directory) -> None:
        self.directory = directory
        self.active = True
        self.thread = threading.get_ident()

    def _check(self) -> None:
        self.directory._check()
        if not self.active or self.thread != threading.get_ident():
            raise RuntimeError("private transaction is closed or belongs to another thread")

    def read_bytes(self, name: str, *, max_bytes: int) -> bytes:
        self._check()
        return self.directory.read_bytes(name, max_bytes=max_bytes)

    def create_bytes(self, name: str, data: bytes) -> None:
        self._write(name, data, replace=False)

    def replace_bytes(self, name: str, data: bytes) -> None:
        self._write(name, data, replace=True)

    def _write(self, name: str, data: bytes, *, replace: bool) -> None:
        self._check()
        validate_leaf(name)
        directory = self.directory
        tmp = ".mordred-fs-tmp-" + secrets.token_hex(16)
        fd: int | None = None
        identity: tuple[int, int] | None = None
        committed = False
        staged = False
        try:
            if replace:
                with directory._open(name):
                    pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=directory.fd)
            staged = True
            info = _private(fd)
            identity = (info.st_dev, info.st_ino)
            _write_staging(fd, data)
            if replace:
                # Revalidate immediately before publication; same-user hostile code is excluded.
                with directory._open(name):
                    pass
                os.replace(tmp, name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
                staged = False
                committed = True
            else:
                os.link(tmp, name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd, follow_symlinks=False)
                committed = True
                os.unlink(tmp, dir_fd=directory.fd)
                staged = False
            _private(fd)
            with directory._open(name) as published:
                after = os.fstat(published)
                if (after.st_dev, after.st_ino) != identity:
                    raise PrivateFSError("unsafe", "published_identity", commit_state="uncertain")
            _flush(directory.fd)
        except PrivateFSError as exc:
            if committed:
                exc.commit_state = "uncertain"
            raise
        except OSError as exc:
            raise _error(exc, "replace" if replace else "create", committed) from exc
        finally:
            if committed:
                directory.published = True
            if staged and not committed:
                _cleanup_staging(directory.fd, tmp, identity)
            if fd is not None:
                _close_fds(iter((fd,)), committed=committed)


def _close_fds(fds: Iterator[int], *, committed: bool) -> None:
    # Close every descriptor once and preserve an active body error. A close
    # failure after publication cannot make the enclosing with-block retry-safe.
    active_error = sys.exc_info()[0] is not None
    failure: OSError | None = None
    for fd in fds:
        try:
            os.close(fd)
        except OSError as exc:
            if failure is None:
                failure = exc
    if failure is not None and not active_error:
        raise _error(failure, "close", committed) from failure


def _cleanup_staging(directory_fd: int, name: str, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    with contextlib.suppress(OSError):
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=directory_fd)


def _write_staging(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "zero-length write")
        view = view[written:]
    _flush(fd)
