"""Private stable-inode POSIX database exclusion, without SQL or native custody."""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import time
from pathlib import Path
from typing import Literal

from ._database_contracts import DatabaseBusy, DatabaseRefused, RootIdentity

LOCK_NAME = "db-encryption.lock"


class PosixDatabaseLock:
    def __init__(self, root: Path) -> None:
        self.path = root.absolute()
        self._fds: list[int] = []
        try:
            self._root = self._open(self.path, os.O_RDONLY | os.O_DIRECTORY)
            root_info = os.fstat(self._root)
            if root_info.st_uid != os.getuid() or root_info.st_mode & 0o022:
                raise DatabaseRefused("database root must be owned and not writable by other users")
            platform: Literal["darwin", "linux"] = "darwin" if sys.platform == "darwin" else "linux"
            self.identity = RootIdentity(platform, root_info.st_dev, str(root_info.st_ino), str(root_info.st_uid))
            with contextlib.suppress(FileExistsError):
                os.mkdir("mordred", mode=0o700, dir_fd=self._root)
            self._directory = self._open("mordred", os.O_RDONLY | os.O_DIRECTORY, dir_fd=self._root)
            directory_info = os.fstat(self._directory)
            self._validate(directory_info, directory=True)
            self._directory_id = (directory_info.st_dev, directory_info.st_ino)
            try:
                self._lock = self._open(
                    LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK, dir_fd=self._directory
                )
            except FileExistsError:
                self._lock = self._open(LOCK_NAME, os.O_RDWR | os.O_NONBLOCK, dir_fd=self._directory)
            lock_info = os.fstat(self._lock)
            self._validate(lock_info, directory=False)
            self._lock_id = (lock_info.st_dev, lock_info.st_ino)
            self.check()
        except BaseException:
            self.close()
            raise

    def _open(self, path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        self._fds.append(fd)
        return fd

    @staticmethod
    def _validate(info: os.stat_result, *, directory: bool) -> None:
        kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        mode = stat.S_IMODE(info.st_mode)
        # Existing macOS pending/recovery directories were sometimes 0755.
        # Keep those stable inodes; only the lock file must be exactly 0600.
        unsafe_mode = bool(mode & 0o022) if directory else mode != 0o600
        if not kind or info.st_uid != os.getuid() or unsafe_mode or (not directory and info.st_nlink != 1):
            raise DatabaseRefused("database lock must be private, owned and regular")

    def acquire(self, *, shared: bool, timeout: float) -> None:
        import fcntl

        operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(self._lock, operation | fcntl.LOCK_NB)
                self.check()
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise DatabaseBusy("Hermes is running or another process is using the databases") from None
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def check(self) -> None:
        if not self._fds:
            raise DatabaseRefused("closed database lock")
        try:
            root = self.path.lstat()
            if (
                not stat.S_ISDIR(root.st_mode)
                or root.st_mode & 0o022
                or (root.st_dev, str(root.st_ino), str(root.st_uid))
                != (
                    self.identity.volume,
                    self.identity.file_id,
                    self.identity.owner,
                )
            ):
                raise DatabaseRefused("database root identity changed")
            directory = os.stat("mordred", dir_fd=self._root, follow_symlinks=False)
            lock = os.stat(LOCK_NAME, dir_fd=self._directory, follow_symlinks=False)
            self._validate(directory, directory=True)
            self._validate(lock, directory=False)
            if (directory.st_dev, directory.st_ino) != self._directory_id or (
                lock.st_dev,
                lock.st_ino,
            ) != self._lock_id:
                raise DatabaseRefused("database lock identity changed")
            self._validate(os.fstat(self._lock), directory=False)
        except OSError as exc:
            raise DatabaseRefused("database lock metadata unavailable") from exc

    def close(self) -> None:
        # Closing the child's inherited reference must never LOCK_UN a parent's
        # shared open-file description. The last descriptor releases the lock.
        descriptors, self._fds = self._fds, []
        error: OSError | None = None
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError as exc:
                error = exc
        if error is not None:
            raise DatabaseRefused("database lock close failed") from error


def identify_root(root: Path) -> RootIdentity:
    """Observe only the existing root; never create a lock during validation."""
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise DatabaseRefused("database root must be owned and not writable by other users")
            platform: Literal["darwin", "linux"] = "darwin" if sys.platform == "darwin" else "linux"
            return RootIdentity(platform, info.st_dev, str(info.st_ino), str(info.st_uid))
        finally:
            os.close(fd)
    except OSError as exc:
        raise DatabaseRefused("database root metadata unavailable") from exc


def open_lock(root: Path) -> PosixDatabaseLock:
    try:
        return PosixDatabaseLock(root)
    except OSError as exc:
        raise DatabaseRefused("database lock could not be opened safely") from exc


def _process_holds(process: Path, identities: set[tuple[int, int]]) -> bool:
    if process.stat().st_uid != os.getuid():
        return False  # Other UIDs cannot open the private files; root is outside this threat model.
    with os.scandir(process / "fd") as rows:
        descriptors = [Path(row.path) for row in rows]
    for descriptor in descriptors:
        try:
            info = descriptor.stat()
        except FileNotFoundError:
            continue  # A descriptor closed between enumeration and stat.
        if (info.st_dev, info.st_ino) in identities:
            return True
    return False


def linux_holders_of(paths: list[Path], *, proc: Path = Path("/proc")) -> list[int] | None:
    """Inspect same-user fd identities; uncertainty is never an empty result."""
    try:
        identities = {(info.st_dev, info.st_ino) for path in paths for info in (path.stat(),)}
        with os.scandir(proc) as rows:
            processes = [Path(row.path) for row in rows if row.name.isdecimal()]
    except OSError:
        return None
    holders: list[int] = []
    for process in processes:
        try:
            if _process_holds(process, identities):
                holders.append(int(process.name))
        except FileNotFoundError:
            # A vanished process is different from a live, inaccessible one.
            try:
                process.stat()
            except FileNotFoundError:
                continue
            except OSError:
                pass
            return None
        except OSError:
            return None
    return sorted(holders)


def assert_no_linux_holders(paths: list[Path], *, proc: Path = Path("/proc")) -> None:
    result = linux_holders_of(paths, proc=proc)
    if result is None or result:
        raise DatabaseRefused("database holder visibility is unknown or files are in use")
