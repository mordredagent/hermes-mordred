"""Checked Windows storage under ``<home>/mordred/telegram`` (C10b).

Only the win32 dispatch in :mod:`.store` and :mod:`.windows_secrets` uses this
module. Every operation admits the Telegram directory (and its ``dialogs``
child) through the shared ``_private_fs`` exact-private directory contract,
reads with a bound and an unchanged-identity check, publishes through staged
create-no-replace or checked replacement inside that directory's transaction,
and deletes only enumerated, validated leaves by identity. Nothing here repairs
an ACL, follows a reparse point, deletes recursively or removes a directory or
lock. Failures are classified ``PrivateFSError``; callers translate them only
after every context has exited (cleanup may promote the commit state).

Lock order: the sync lock (``sync-lock/.mordred-fs.lock``, only ever acquired
non-blocking) -> canonical home -> mordred -> telegram -> dialogs. Data
operations take one short telegram or dialogs transaction at a time, so a long
sync never blocks status reads, credential updates or questions.
"""

from __future__ import annotations

import contextlib
import functools
import re
import threading
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Protocol, TypeVar

from ..._private_fs import (
    FileIdentity,
    PrivateFSError,
    PrivateTransaction,
    open_optional_private_directory,
    open_private_directory,
)
from .store import _GITIGNORE

DIALOGS = "dialogs"
SYNC_DIR = "sync-lock"
INDEX_FILE = "index.enc"
GITIGNORE = ".gitignore"
#: Per-file bound for ``index.enc`` and each dialog segment (2000 messages).
MAX_FILE_BYTES = 64 * 1024 * 1024
#: Enumeration bound per directory (wipe) and per dialog (segment scan).
MAX_ENTRIES = 65536
_GITIGNORE_LIMIT = 4096
_SEGMENT = re.compile(r"[0-9a-f]{40}\.enc")
# POSIX labels a missing directory/file "directory"/"stat"/"read"; Windows
# labels every CreateFile failure "open". Nothing else authorizes absence.
_MISSING_OPERATIONS = frozenset({"open", "stat", "read", "directory"})

_T = TypeVar("_T")
_guard = threading.Lock()
#: Sync-lock directory identities held (or being acquired) in this process.
_held: set[FileIdentity] = set()


class Recorder(Protocol):
    """Outcome reporting for an owning custody receipt; grants no I/O authority."""

    def published(self) -> None: ...

    def uncertain(self, error: PrivateFSError) -> None: ...


class _Unrecorded:
    def published(self) -> None:
        return None

    def uncertain(self, error: PrivateFSError) -> None:
        return None


UNRECORDED: Recorder = _Unrecorded()


def missing(exc: PrivateFSError) -> bool:
    """Only a definite, uncommitted open/stat/read miss proves absence."""
    return exc.reason == "missing" and exc.commit_state == "not_committed" and exc.operation in _MISSING_OPERATIONS


def record(recorder: Recorder, call: Callable[[], _T]) -> _T:
    """Run one mutation and report its outcome before returning to the caller."""
    try:
        result = call()
    except PrivateFSError as exc:
        if exc.commit_state == "uncertain":
            recorder.uncertain(exc)
        raise
    except Exception:
        raise
    except BaseException:
        # An interrupt may land after the primitive committed: unknown outcome.
        with contextlib.suppress(Exception):
            recorder.uncertain(PrivateFSError("io", "telegram_publication_interrupted", commit_state="uncertain"))
        raise
    recorder.published()
    return result


def directory_present(path: Path) -> bool:
    """Checked presence; an absent final or ancestor component means absent."""
    try:
        with open_optional_private_directory(path) as directory:
            return directory is not None
    except PrivateFSError as exc:
        if missing(exc):
            return False
        raise


@contextlib.contextmanager
def transaction(
    path: Path, *, create: bool = False, recorder: Recorder = UNRECORDED
) -> Iterator[PrivateTransaction | None]:
    """A checked exact-private directory transaction; ``None`` when absent.

    With ``create`` the final directory is created private before content and
    its ``.gitignore`` is ensured; its parent must already exist.
    """
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(open_optional_private_directory(path))
        except PrivateFSError as exc:
            if create or not missing(exc):
                raise
            directory = None
        if directory is None:
            if not create:
                yield None
                return
            recorder.published()  # creation (and its cleanup) is owned by this scope
            directory = stack.enter_context(open_private_directory(path, create=True))
        tx = stack.enter_context(directory.transaction())
        if create:
            _ensure_gitignore(tx, recorder)
        yield tx


def present(tx: PrivateTransaction, name: str) -> bool:
    try:
        tx.stat(name)
    except PrivateFSError as exc:
        if missing(exc):
            return False
        raise
    return True


def read_optional(tx: PrivateTransaction, name: str, limit: int) -> bytes | None:
    """Bounded read of a validated private leaf whose identity stayed unchanged."""
    try:
        before = tx.stat(name)
    except PrivateFSError as exc:
        if missing(exc):
            return None
        raise
    if before.size > limit:
        raise PrivateFSError("unsafe", "telegram_read_limit")
    data = tx.read_bytes(name, max_bytes=limit)
    if len(data) != before.size or tx.stat(name) != before:
        raise PrivateFSError("unsafe", "telegram_read_changed")
    return data


def publish(tx: PrivateTransaction, name: str, data: bytes, recorder: Recorder, *, limit: int) -> None:
    """Staged create-no-replace (new) or checked replacement, then verify bytes."""
    if len(data) > limit:
        raise PrivateFSError("unsafe", "telegram_write_limit")
    if present(tx, name):
        record(recorder, lambda: tx.replace_bytes(name, data))
    else:
        record(recorder, lambda: tx.create_bytes(name, data))
    try:
        verified = read_optional(tx, name, limit) == data
    except PrivateFSError as exc:
        exc.commit_state = "uncertain"
        recorder.uncertain(exc)
        raise
    if not verified:
        error = PrivateFSError("unsafe", "telegram_publication_verify", commit_state="uncertain")
        recorder.uncertain(error)
        raise error


def remove(tx: PrivateTransaction, name: str, recorder: Recorder) -> None:
    """Delete one validated leaf by the identity just checked; absent is a no-op."""
    try:
        identity = tx.stat(name).identity
    except PrivateFSError as exc:
        if missing(exc):
            return
        raise
    record(recorder, lambda: tx.delete_file(name, expected_identity=identity))


def _ensure_gitignore(tx: PrivateTransaction, recorder: Recorder) -> None:
    if read_optional(tx, GITIGNORE, _GITIGNORE_LIMIT) != _GITIGNORE:
        publish(tx, GITIGNORE, _GITIGNORE, recorder, limit=_GITIGNORE_LIMIT)


def _split(root: Path, rel: str) -> tuple[Path, str]:
    directory, _, name = rel.rpartition("/")
    if directory not in ("", DIALOGS):
        raise PrivateFSError("unsafe", "telegram_archive_path")
    return (root / directory if directory else root), name


# -- archive data --------------------------------------------------------------------


def read_archive_file(root: Path, rel: str) -> bytes | None:
    path, name = _split(root, rel)
    with transaction(path) as tx:
        return None if tx is None else read_optional(tx, name, MAX_FILE_BYTES)


def write_archive_file(root: Path, rel: str, data: bytes) -> None:
    path, name = _split(root, rel)
    with transaction(root, create=True) as tx:
        assert tx is not None
        if path == root:
            publish(tx, name, data, UNRECORDED, limit=MAX_FILE_BYTES)
            return
    with transaction(path, create=True) as tx:
        assert tx is not None
        publish(tx, name, data, UNRECORDED, limit=MAX_FILE_BYTES)


def count_segments(root: Path, segment_name: Callable[[int], str]) -> int:
    """Number of consecutive existing segments of one dialog (one transaction)."""
    with transaction(root / DIALOGS) as tx:
        if tx is None:
            return 0
        for count in range(MAX_ENTRIES):
            if not present(tx, f"{segment_name(count)}.enc"):
                return count
    raise PrivateFSError("unsafe", "telegram_segment_limit")


def read_segments(root: Path, segment_name: Callable[[int], str]) -> list[tuple[str, bytes]]:
    """Every consecutive segment blob of one dialog, read in one transaction."""
    blobs: list[tuple[str, bytes]] = []
    with transaction(root / DIALOGS) as tx:
        if tx is None:
            return blobs
        for count in range(MAX_ENTRIES):
            name = segment_name(count)
            data = read_optional(tx, f"{name}.enc", MAX_FILE_BYTES)
            if data is None:
                return blobs
            blobs.append((name, data))
    raise PrivateFSError("unsafe", "telegram_segment_limit")


def index_mtime_ns(root: Path) -> int | None:
    with transaction(root) as tx:
        if tx is None:
            return None
        try:
            return tx.stat(INDEX_FILE).mtime_ns
        except PrivateFSError as exc:
            if missing(exc):
                return None
            raise


# -- sync lock -------------------------------------------------------------------------


@contextlib.contextmanager
def sync_lock(root: Path) -> Iterator[None]:
    """One sync (or wipe) at a time, across threads and processes, never waiting.

    The lock is the permanent ``.mordred-fs.lock`` of a dedicated private
    ``sync-lock`` directory, so holding it for a whole sync never blocks the
    short data transactions in the Telegram and dialogs directories.
    """
    with transaction(root, create=True):
        pass
    with open_private_directory(root / SYNC_DIR, create=True) as directory:
        identity = directory.directory_identity()
        with _guard:
            if identity in _held:
                raise PrivateFSError("busy", "telegram_sync_lock")
            _held.add(identity)
        try:
            with directory.transaction(blocking=False):
                yield
        finally:
            with _guard:
                _held.discard(identity)


def busy(root: Path) -> bool:
    """True while this or another process holds the sync lock; never waits."""
    if not directory_present(root):
        return False
    with open_optional_private_directory(root / SYNC_DIR) as directory:
        if directory is None:
            return False
        with _guard:
            if directory.directory_identity() in _held:
                return True
        try:
            with directory.transaction(blocking=False):
                return False
        except PrivateFSError as exc:
            if exc.reason == "busy" and exc.commit_state == "not_committed":
                return True
            raise


# -- wipe ------------------------------------------------------------------------------


def _archive_leaf(directory: str, name: str) -> bool:
    if directory == DIALOGS:
        return _SEGMENT.fullmatch(name) is not None
    return name == INDEX_FILE


def wipe(root: Path, recorder: Recorder = UNRECORDED, *, credentials: tuple[str, ...] = ()) -> None:
    """Delete enumerated archive files, then *credentials*; caller holds the sync lock.

    The telegram then dialogs transactions are held together (the global lock
    order), and every leaf to delete is enumerated within bounds and validated
    before the first deletion, so an unsafe object refuses the whole wipe.
    Segments go first, ``index.enc`` next and the named root *credentials*
    last. Unknown names, ``.gitignore``, locks and directories stay.
    """
    with transaction(root) as root_tx:
        if root_tx is None:
            return
        with transaction(root / DIALOGS) as dialogs_tx:
            plan: list[tuple[PrivateTransaction, str, FileIdentity]] = []
            for tx, directory in ((dialogs_tx, DIALOGS), (root_tx, "")):
                if tx is None:
                    continue
                for name in tx.list_names(max_entries=MAX_ENTRIES):
                    if _archive_leaf(directory, name):
                        plan.append((tx, name, tx.stat(name).identity))
            for name in credentials:
                if present(root_tx, name):
                    plan.append((root_tx, name, root_tx.stat(name).identity))
            for tx, name, identity in plan:
                record(recorder, functools.partial(tx.delete_file, name, expected_identity=identity))
