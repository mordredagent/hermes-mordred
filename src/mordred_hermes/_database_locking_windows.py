"""Inert checked Windows database lease adapter, independent of SQL and custody.

Portable tests verify policy and resource ownership. Actual LockFileEx and
rename exclusion still require Task 5's native Windows qualification gate.
"""

from __future__ import annotations

import contextlib
import ctypes
import math
import sys
import time
from pathlib import Path

from ._database_contracts import DatabaseBusy, DatabaseRefused, RootIdentity
from ._private_fs._types import PrivateFSError
from ._private_fs._windows_api import Overlapped, OwnedHandle
from ._private_fs._windows_paths import CheckedDirectory, checked_directory, checked_directory_optional
from ._private_fs._windows_security import current_user_sid, validate_private

WINDOWS_LEASE_QUALIFIED = False
_LOCK_NAME = "db-encryption.lock"


def _root_identity(directory: CheckedDirectory, sid: bytes) -> RootIdentity:
    directory.check()
    if current_user_sid() != sid or directory.handle.api.descriptor(directory.handle).owner != sid:
        raise PrivateFSError("unsafe", "database_root_owner")
    return RootIdentity("win32", directory.identity.volume, directory.identity.file_id.hex(), sid.hex())


def _checked_root(stack: contextlib.ExitStack, root: Path) -> tuple[CheckedDirectory, RootIdentity]:
    sid = current_user_sid()
    # An existing profile-style home may have safe inherited ACLs. The
    # authority directory and lock below it must satisfy exact private policy.
    directory = stack.enter_context(checked_directory_optional(root, confidential=True))
    if directory is None:
        raise PrivateFSError("missing", "database_root")
    return directory, _root_identity(directory, sid)


def identify_root(root: Path) -> RootIdentity:
    """Observe physical root/SID metadata without creating authority resources."""
    try:
        with contextlib.ExitStack() as stack:
            _, identity = _checked_root(stack, root)
            return identity
    except OSError as exc:
        raise DatabaseRefused("Windows database root cannot be identified safely") from exc


def _open_lock(directory: CheckedDirectory) -> OwnedHandle:
    api = directory.handle.api
    path = directory.path + "\\" + _LOCK_NAME
    try:
        # CREATE_NEW installs the private descriptor atomically; share=3 omits
        # FILE_SHARE_DELETE, as do the checked root and ancestor handles.
        handle = api.open(path, access=0xC0020000, share=3, create=True)
    except PrivateFSError as exc:
        if exc.reason != "exists":
            raise
        handle = api.open(path, access=0xC0020000, share=3)
    try:
        validate_private(handle, directory=False)
        if api.metadata(handle).identity.volume != directory.identity.volume:
            raise PrivateFSError("unsafe", "database_lock_volume")
    except BaseException:
        # __exit__ preserves the validation failure if cleanup also fails.
        handle.__exit__(*sys.exc_info())
        raise
    return handle


class WindowsDatabaseLock:
    """Own pinned checked handles; acquire the byte lock only when requested."""

    def __init__(self, root: Path) -> None:
        self._closed = False
        self._held = False
        try:
            with contextlib.ExitStack() as stack:
                self._root, self.identity = _checked_root(stack, root)
                self._directory = stack.enter_context(checked_directory(root / "mordred", create=True))
                expected = self._root.path.rstrip("\\") + "\\mordred"
                if (
                    self._directory.path.casefold() != expected.casefold()
                    or self._directory.identity.volume != self.identity.volume
                ):
                    raise PrivateFSError("unsafe", "database_directory_identity")
                self._handle = stack.enter_context(_open_lock(self._directory))
                self._lock_identity = self._handle.api.metadata(self._handle).identity
                self.check()
                self._resources = stack.pop_all()
        except OSError as exc:
            self._closed = True
            raise DatabaseRefused("Windows database lease cannot be opened safely") from exc

    def acquire(self, *, shared: bool, timeout: float) -> None:
        if self._closed:
            raise DatabaseRefused("Windows database lease is closed")
        if self._held:
            raise DatabaseRefused("Windows database lease cannot be reacquired or upgraded")
        try:
            if not math.isfinite(timeout) or timeout < 0:
                raise DatabaseRefused("database lease timeout must be finite and nonnegative")
            self._acquire_byte_lock(shared=shared, deadline=time.monotonic() + timeout)
            self._held = True
            self.check()
        except BaseException as exc:
            try:
                self.close()
            except DatabaseRefused as cleanup:
                exc.add_note(f"Windows database lease cleanup failed: {type(cleanup).__name__}")
            if isinstance(exc, OSError):
                raise DatabaseRefused("Windows database lease acquisition failed") from exc
            raise

    def _acquire_byte_lock(self, *, shared: bool, deadline: float) -> None:
        while True:
            self.check()
            overlap = Overlapped()
            api = self._handle.api
            try:
                api.checked(
                    api.Lock(self._handle.value, 1 if shared else 3, 0, 1, 0, ctypes.byref(overlap)),
                    "database_lock",
                )
                return
            except PrivateFSError as exc:
                if exc.native_code != 33:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DatabaseBusy("Windows database domain is busy") from exc
                time.sleep(min(0.05, remaining))

    def check(self) -> None:
        if self._closed:
            raise DatabaseRefused("Windows database lease is closed")
        try:
            sid = bytes.fromhex(self.identity.owner)
            if _root_identity(self._root, sid) != self.identity:
                raise PrivateFSError("unsafe", "database_root_identity")
            self._directory.check()
            api = self._handle.api
            validate_private(self._handle, directory=False)
            if api.metadata(self._handle).identity != self._lock_identity:
                raise PrivateFSError("unsafe", "database_lock_identity")
            with api.open(self._directory.path + "\\" + _LOCK_NAME, share=3) as named:
                validate_private(named, directory=False)
                if api.metadata(named).identity != self._lock_identity:
                    raise PrivateFSError("unsafe", "database_lock_identity")
            if current_user_sid() != sid:
                raise PrivateFSError("unsafe", "database_root_owner")
        except OSError as exc:
            raise DatabaseRefused("Windows database lease identity validation failed") from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            with self._resources:
                if self._held:
                    self._held = False
                    self._handle.api.unlock(self._handle)
        except OSError as exc:
            raise DatabaseRefused("Windows database lease cleanup failed") from exc


def open_lock(root: Path) -> WindowsDatabaseLock:
    return WindowsDatabaseLock(root)
