"""Checked Windows storage for extension pairing, attestation and history files.

POSIX keeps its existing mode-``0600`` writers and the ``.lock`` flock; this
module is reached only when :data:`WINDOWS_STORAGE` is set. Every Windows
operation runs inside one exact-private ``_private_fs`` transaction on
``<home>/extension``, i.e. under the permanent ``.mordred-fs.lock`` that the
keyvault wallet selection already uses in that directory:

* reads are bounded and bound to the checked file identity observed under the
  lock (stat, read, stat again); only a checked missing final directory or
  file is absence, never an access, lock, cleanup or admission failure;
* writes choose exclusive creation for a checked absence and checked
  replacement for a present file whose identity still matches what this
  session observed; new files receive the private ACL before content;
* deletes are identity-bound; nothing is chmod-ed, repaired or adopted.

The foundation lock is not reentrant, so nested calls on the same thread reuse
the active session (pairing's read-modify-write cycles read ``state.json``
while holding the lock). A session that published anything reports any later
refusal as uncertain. Failures become content-free
:class:`ExtensionStorageError` instances carrying the classified reason,
native status and commit state; uncertain outcomes are never retried here.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Final, Literal

from .._private_fs import (
    FileIdentity,
    FileMetadata,
    PrivateDirectory,
    PrivateFSError,
    PrivateTransaction,
    open_optional_private_directory,
    open_private_directory,
)

WINDOWS_STORAGE: bool = sys.platform == "win32"

#: Per-file read and write bounds. ``state.json`` holds up to 32,768 replay
#: identities (about 3.5 MB) plus channel keys; history is one encrypted blob.
MAX_BYTES: Final[dict[str, int]] = {
    "pending.json": 1024 * 1024,
    "state.json": 8 * 1024 * 1024,
    "webauthn.json": 64 * 1024,
    "attest_key.pem": 16 * 1024,
    "history.enc": 64 * 1024 * 1024,
}
_DEFAULT_MAX_BYTES: Final = 1024 * 1024

_SESSION_LOCK = threading.RLock()
_local = threading.local()


def enabled() -> bool:
    """Whether extension state uses this checked storage (Windows only)."""
    return WINDOWS_STORAGE


def max_bytes(name: str) -> int:
    return MAX_BYTES.get(name, _DEFAULT_MAX_BYTES)


class ExtensionStorageError(RuntimeError):
    """A content-free refusal from checked Windows extension storage."""

    wire_reason = "storage_unavailable"
    commit_state: Literal["not_committed", "uncertain"] = "not_committed"
    _message = "extension state storage is unavailable or unsafe; refusing without fallback"

    def __init__(self, reason: str, operation: str, *, native_code: int | None = None) -> None:
        super().__init__(self._message)
        self.reason = reason
        self.operation = operation
        self.native_code = native_code

    @staticmethod
    def classify(error: PrivateFSError, *, published: bool = False) -> ExtensionStorageError:
        uncertain = published or error.commit_state == "uncertain"
        kind = ExtensionStorageUncertain if uncertain else ExtensionStorageError
        return kind(error.reason, error.operation, native_code=error.native_code)

    def promoted(self) -> ExtensionStorageUncertain:
        return ExtensionStorageUncertain(self.reason, self.operation, native_code=self.native_code)


class ExtensionStorageUncertain(ExtensionStorageError):
    """A mutation may have been published; inspect state before any retry."""

    wire_reason = "storage_uncertain"
    commit_state: Literal["not_committed", "uncertain"] = "uncertain"
    _message = "extension state save outcome is uncertain; inspect the extension state before retrying"


def _checked_missing(error: PrivateFSError) -> bool:
    # Windows reports the file's CreateFile failure as "open"; the POSIX
    # backend labels the same checked stat "stat". Lock, cleanup and
    # directory errors that also say "missing" never mean absence.
    return error.reason == "missing" and error.commit_state == "not_committed" and error.operation in ("open", "stat")


class _Unbound:
    pass


_UNBOUND: Final = _Unbound()


class Session:
    """One checked directory transaction, shared by nested same-thread calls."""

    def __init__(self, key: str, tx: PrivateTransaction | None) -> None:
        self.key = key
        self._tx = tx
        self.published = False
        self._bound: dict[str, FileIdentity | None] = {}

    @property
    def absent(self) -> bool:
        """The extension directory itself was a checked absence."""
        return self._tx is None

    def bound(self, name: str) -> FileIdentity | None | _Unbound:
        return self._bound.get(name, _UNBOUND)

    def _transaction(self) -> PrivateTransaction:
        if self._tx is None:
            raise RuntimeError("checked extension storage session has no directory")
        return self._tx

    def directory_identity(self) -> FileIdentity:
        try:
            return self._transaction().directory_identity()
        except PrivateFSError as exc:
            raise ExtensionStorageError.classify(exc) from None

    def stat(self, name: str) -> FileMetadata | None:
        """Checked metadata, or ``None`` only for a checked missing file."""
        if self._tx is None:
            self._bound[name] = None
            return None
        try:
            metadata = self._tx.stat(name)
        except PrivateFSError as exc:
            if _checked_missing(exc):
                self._bound[name] = None
                return None
            raise ExtensionStorageError.classify(exc) from None
        self._bound[name] = metadata.identity
        return metadata

    def read(self, name: str) -> bytes | None:
        """Bounded read bound to the identity validated before and after it."""
        limit = max_bytes(name)
        before = self.stat(name)
        if before is None:
            return None
        if before.size > limit:
            raise ExtensionStorageError("unsafe", "read_limit")
        tx = self._transaction()
        try:
            data = tx.read_bytes(name, max_bytes=limit)
            after = tx.stat(name)
        except PrivateFSError as exc:
            raise ExtensionStorageError.classify(exc) from None
        if after.identity != before.identity or after.size != len(data):
            raise ExtensionStorageError("unsafe", "read_identity")
        return data

    def write(self, name: str, data: bytes, *, exclusive: bool = False) -> None:
        """Create a checked absence, or replace the identity this session bound."""
        limit = max_bytes(name)
        if len(data) > limit:
            raise ExtensionStorageError("unsafe", "write_limit")
        tx = self._transaction()
        bound = self.bound(name)
        current = self.stat(name)
        self._require_bound(bound, current)
        if current is not None and exclusive:
            raise ExtensionStorageError("exists", "create")
        if current is not None and current.size > limit:
            raise ExtensionStorageError("unsafe", "read_limit")
        try:
            if current is None:
                tx.create_bytes(name, data)
            else:
                tx.replace_bytes(name, data)
        except PrivateFSError as exc:
            self.published = self.published or exc.commit_state == "uncertain"
            raise ExtensionStorageError.classify(exc) from None
        self.published = True
        try:
            self._bound[name] = tx.stat(name).identity
        except PrivateFSError as exc:
            raise ExtensionStorageError.classify(exc, published=True) from None

    def delete(self, name: str) -> None:
        """Identity-bound deletion; a checked missing file is already gone."""
        if self._tx is None:
            return
        bound = self.bound(name)
        current = self.stat(name)
        self._require_bound(bound, current)
        if current is None:
            return
        try:
            self._tx.delete_file(name, expected_identity=current.identity)
        except PrivateFSError as exc:
            self.published = self.published or exc.commit_state == "uncertain"
            raise ExtensionStorageError.classify(exc) from None
        self.published = True
        self._bound[name] = None

    @staticmethod
    def _require_bound(bound: FileIdentity | None | _Unbound, current: FileMetadata | None) -> None:
        if isinstance(bound, _Unbound):
            return
        if bound != (None if current is None else current.identity):
            raise ExtensionStorageError("unsafe", "identity")


@contextlib.contextmanager
def session(directory: Path, *, create: bool) -> Iterator[Session]:
    """Hold (or reuse) the checked transaction for ``directory`` on this thread.

    ``create`` admits only the final directory below an existing trusted
    parent; without it a checked missing directory yields an absent session.
    """
    key = str(directory)
    active: Session | None = getattr(_local, "session", None)
    if active is not None:
        if active.key != key:
            raise RuntimeError("nested extension storage sessions must use one directory")
        if create and active.absent:
            raise RuntimeError("extension storage cannot create inside a read-only absence")
        yield active
        return
    with _SESSION_LOCK:
        current: Session | None = None
        try:
            with contextlib.ExitStack() as stack:
                checked: PrivateDirectory | None
                if create:
                    checked = stack.enter_context(open_private_directory(directory, create=True))
                else:
                    checked = stack.enter_context(open_optional_private_directory(directory))
                tx = None if checked is None else stack.enter_context(checked.transaction())
                current = Session(key, tx)
                _local.session = current
                try:
                    yield current
                finally:
                    _local.session = None
        except PrivateFSError as exc:
            # Translate after every context exits: cleanup can promote commit state.
            raise ExtensionStorageError.classify(exc, published=current is not None and current.published) from None
        except ExtensionStorageError as exc:
            if current is not None and current.published and not isinstance(exc, ExtensionStorageUncertain):
                raise exc.promoted() from None
            raise


def read_file(path: Path) -> bytes | None:
    """Checked bounded read; ``None`` only for checked absence."""
    with session(path.parent, create=False) as active:
        return active.read(path.name)


def write_file(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """Checked create-or-replace (``exclusive``: create only, never replace)."""
    if len(data) > max_bytes(path.name):
        raise ExtensionStorageError("unsafe", "write_limit")
    with session(path.parent, create=True) as active:
        active.write(path.name, data, exclusive=exclusive)


def delete_file(path: Path) -> None:
    """Identity-bound checked deletion; absence is not an error."""
    with session(path.parent, create=False) as active:
        active.delete(path.name)
