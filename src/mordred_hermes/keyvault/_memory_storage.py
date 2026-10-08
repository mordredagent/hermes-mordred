"""Checked flat Windows memory storage under explicit custody ownership."""

from __future__ import annotations

import contextlib
import fnmatch
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .._private_fs import (
    ConfidentialTransaction,
    FileIdentity,
    FileMetadata,
    PrivateFSError,
    open_confidential_directory,
    open_optional_confidential_directory,
)
from .._private_fs._types import validate_leaf
from ._exceptions import WrapError
from .memory_crypto import MemoryCryptoError, is_sealed, looks_like_magic_line, seal, unseal

if TYPE_CHECKING:
    from .._config_io import PublicationReceipt
    from ._windows_custody import GenerationLease, WindowsCustodySession, WindowsMemoryState

MEMORY_FILE_LIMIT = 8 * 1024 * 1024
MEMORY_TOTAL_LIMIT = 64 * 1024 * 1024
MEMORY_ENTRY_LIMIT = 4096


class MemoryStorageError(RuntimeError):
    """Checked memory or its custody cannot safely be consumed/published."""


@dataclass(frozen=True)
class MemoryFileSnapshot:
    name: str
    metadata: FileMetadata
    data: bytes


def _memory_leaf(name: str) -> None:
    validate_leaf(name)
    if not (fnmatch.fnmatchcase(name.casefold(), "*.md") or fnmatch.fnmatchcase(name.casefold(), "*.md.bak.*")):
        raise PrivateFSError("unsafe", "memory_leaf")


def _inventory(tx: ConfidentialTransaction) -> tuple[MemoryFileSnapshot, ...]:
    snapshots = []
    total = 0
    for name in sorted(tx.list_names(max_entries=MEMORY_ENTRY_LIMIT)):
        try:
            _memory_leaf(name)
        except PrivateFSError:
            continue
        metadata = tx.stat(name)
        if metadata.size > MEMORY_FILE_LIMIT or metadata.size > MEMORY_TOTAL_LIMIT - total:
            raise PrivateFSError("unsafe", "memory_inventory_limit")
        data = tx.read_bytes(name, max_bytes=max(1, min(MEMORY_FILE_LIMIT, MEMORY_TOTAL_LIMIT - total)))
        if tx.stat(name) != metadata or len(data) != metadata.size:
            raise PrivateFSError("unsafe", "memory_inventory_changed")
        total += len(data)
        snapshots.append(MemoryFileSnapshot(name, metadata, data))
    return tuple(snapshots)


def inventory_memory_files(home: Path) -> tuple[MemoryFileSnapshot, ...]:
    """Call under canonical home/mordred ownership; never suppress I/O failure."""
    with open_optional_confidential_directory(home / "memories") as directory:
        if directory is None:
            return ()
        with directory.transaction() as tx:
            return _inventory(tx)


def windows_memory_runtime_admitted(executable: Path | None = None) -> bool:
    """Structural C4 admission only; no subprocess, proof or lifecycle authority."""
    from .._windows_runtime import environment_root

    executable = Path(sys.executable) if executable is None else executable
    if executable.name.lower() == "pythonw.exe":
        if not executable.is_file():
            return False
        executable = executable.with_name("python.exe")
    return environment_root(executable) is not None


def _validate_target(home: Path, path: Path | None, identity: FileIdentity | None) -> None:
    if path is None:
        return
    _memory_leaf(path.name)
    if identity is None:
        if path.parent.absolute() != (home / "memories").absolute():
            raise MemoryStorageError("memory target does not belong to active profile")
        return
    with open_confidential_directory(path.parent) as target_parent:
        if target_parent.directory_identity() != identity:
            raise MemoryStorageError("memory target does not belong to active profile")


@contextmanager
def windows_memory_session(
    home: Path,
    *,
    path: Path | None = None,
    create: bool = False,
    custody: WindowsCustodySession | None = None,
    lease: GenerationLease | None = None,
    safe_mode: bool = False,
) -> Iterator[WindowsMemorySession]:
    """Acquire home -> mordred -> memories without ambient/reentrant loans."""
    from ._windows_custody import CustodyError, windows_custody_session

    admitted = windows_memory_runtime_admitted()  # before filesystem locks
    with ExitStack() as owner_stack:
        if custody is None:
            custody = owner_stack.enter_context(windows_custody_session(home, create=create))
        else:
            custody.check()
            with open_optional_confidential_directory(home) as alias:
                if alias is None or alias.directory_identity() != custody.canonical.home_directory_identity():
                    raise MemoryStorageError("memory owner belongs to another physical home")
        if lease is not None:
            if lease.role != "memory":
                raise MemoryStorageError("memory requires a memory generation lease")
            custody.validate_lease(lease)
        state = custody.memory_state()
        if state.lease is not None and not admitted:
            raise MemoryStorageError("managed Windows memory requires an admitted Python environment")
        # The fresh resolver inventories retained files; it must run before the
        # child lock. Once held, state validation performs no recursive inventory.
        try:
            key = custody.resolve_memory_key()
        except (CustodyError, MemoryCryptoError, WrapError) as exc:
            raise MemoryStorageError("Windows memory custody unavailable") from exc
        if custody.memory_state() != state:
            raise MemoryStorageError("memory custody changed while opening storage")
        with custody.canonical.publication_receipt() as receipt, ExitStack() as child_stack:
            directory = (
                None
                if custody.canonical.home_directory_identity() is None
                else child_stack.enter_context(open_optional_confidential_directory(home / "memories"))
            )
            if directory is None:
                _validate_target(home, path, None)
            if directory is None and create:
                receipt.mark_published()  # creation/cleanup is owned by this scope
                directory = child_stack.enter_context(open_confidential_directory(home / "memories", create=True))
            tx = None if directory is None else child_stack.enter_context(directory.transaction())
            _validate_target(home, path, None if directory is None else directory.directory_identity())
            session = WindowsMemorySession(custody, state, tx, receipt, key, safe_mode)
            try:
                yield session
                session.check()
            finally:
                session._live = False
                session._key = None


class WindowsMemorySession:
    """Explicit operation owner. Objects, keys and receipts expire on scope exit."""

    def __init__(
        self,
        custody: WindowsCustodySession,
        state: WindowsMemoryState,
        tx: ConfidentialTransaction | None,
        receipt: PublicationReceipt,
        key: bytes | None,
        safe_mode: bool,
    ) -> None:
        self._custody = custody
        self._state = state
        self._tx = tx
        self._receipt = receipt
        self._key = key
        self._safe_mode = safe_mode
        self._live = True
        self._thread = threading.get_ident()
        self._directory_identity = None if tx is None else tx.directory_identity()

    @property
    def custody(self) -> WindowsCustodySession:
        return self._custody

    @property
    def state(self) -> WindowsMemoryState:
        return self._state

    def check(self) -> None:
        if not self._live or self._thread != threading.get_ident():
            raise MemoryStorageError("Windows memory operation expired or changed thread")
        self.custody.check()
        if self.custody.memory_state() != self.state:
            raise MemoryStorageError("Windows memory generation or marker state changed")
        if self._tx is not None and self._tx.directory_identity() != self._directory_identity:
            raise MemoryStorageError("Windows memory directory identity changed")

    @property
    def armed(self) -> bool:
        self.check()
        return self.state.armed and not self._safe_mode

    def _name(self, name: str) -> str:
        self.check()
        _memory_leaf(name)
        if self._tx is None:
            return name
        try:
            identity = self._tx.stat(name).identity
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return name
            raise
        # Use the stored basename as AAD for NTFS casing aliases. Distinct
        # case-sensitive files remain distinct because selection uses identity.
        for existing in self._tx.list_names(max_entries=MEMORY_ENTRY_LIMIT):
            try:
                _memory_leaf(existing)
            except PrivateFSError:
                continue  # upstream locks/subdirectories are never memory aliases; never stat them
            if self._tx.stat(existing).identity == identity:
                return existing
        raise PrivateFSError("unsafe", "memory_name_identity")

    def inventory(self) -> tuple[MemoryFileSnapshot, ...]:
        self.check()
        return () if self._tx is None else _inventory(self._tx)

    def read_text(self, name: str, *, encoding: str = "utf-8") -> str | None:
        name = self._name(name)
        if self._tx is None:
            return None
        try:
            metadata = self._tx.stat(name)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None
            raise
        data = self._tx.read_bytes(name, max_bytes=MEMORY_FILE_LIMIT)
        if self._tx.stat(name) != metadata or len(data) != metadata.size:
            raise PrivateFSError("unsafe", "memory_read_changed")
        self.check()
        return data.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")

    @property
    def sealing_available(self) -> bool:
        """Whether this operation holds a native memory key (managed or adopted seals)."""
        self.check()
        return self._key is not None

    def read_classified(self, name: str, *, encoding: str = "utf-8") -> tuple[str | None, bool]:
        """Plaintext plus whether its stored bytes were an authenticated seal."""
        actual = self._name(name)
        text = self.read_text(actual, encoding=encoding)
        if text is None or not looks_like_magic_line(text):
            return text, False
        if not is_sealed(text) or self._key is None:
            raise MemoryStorageError("memory seal is broken or its native key is unavailable")
        try:
            return unseal(text.encode("utf-8"), key=self._key, name=actual).decode("utf-8"), True
        except (MemoryCryptoError, UnicodeError) as exc:
            raise MemoryStorageError("memory seal does not authenticate") from exc

    def read_plaintext(self, name: str, *, encoding: str = "utf-8") -> str | None:
        return self.read_classified(name, encoding=encoding)[0]

    def _bounded_existing(self, tx: ConfidentialTransaction, name: str, data: bytes) -> bool:
        """Check entry/byte bounds before publication; return whether ``name`` exists."""
        inventory = self.inventory()
        names = tx.list_names(max_entries=MEMORY_ENTRY_LIMIT)
        if name not in names and len(names) >= MEMORY_ENTRY_LIMIT:
            raise PrivateFSError("unsafe", "memory_publication_entry_limit")
        total = sum(len(row.data) for row in inventory if row.name != name) + len(data)
        if len(data) > MEMORY_FILE_LIMIT or total > MEMORY_TOTAL_LIMIT:
            raise PrivateFSError("unsafe", "memory_publication_limit")
        return any(row.name == name for row in inventory)

    def _publish(self, name: str, data: bytes, *, create: bool) -> None:
        name = self._name(name)
        if self._tx is None:
            raise MemoryStorageError("memory publication requires an existing checked directory")
        exists = self._bounded_existing(self._tx, name, data)
        published = False
        try:
            if create or not exists:
                self._tx.create_bytes(name, data)
            else:
                self._tx.replace_bytes(name, data)
            published = True
            self._receipt.mark_published()
            if self._tx.read_bytes(name, max_bytes=MEMORY_FILE_LIMIT) != data:
                raise PrivateFSError("unsafe", "memory_publication_verify", commit_state="uncertain")
            self.check()
        except Exception as exc:
            if published:
                if not isinstance(exc, PrivateFSError):
                    failure = PrivateFSError("unsafe", "memory_postpublication", commit_state="uncertain")
                    self._receipt.mark_uncertain(failure)
                    raise failure from exc
                exc.commit_state = "uncertain"
            if isinstance(exc, PrivateFSError) and exc.commit_state == "uncertain":
                self._receipt.mark_uncertain(exc)
            raise
        except BaseException:
            # An interrupt may land inside or after the primitive, so the outcome is
            # unknown: the owner learns that through a classified uncertain failure,
            # while the interrupt itself propagates unchanged. A receipt that cannot
            # take the report is already poisoned or closed; it must not replace it.
            with contextlib.suppress(Exception):
                self._receipt.mark_uncertain(
                    PrivateFSError("unsafe", "memory_postpublication", commit_state="uncertain")
                )
            raise

    def write_entries(self, name: str, entries: Sequence[str], *, delimiter: str) -> None:
        name = self._name(name)
        text = self.read_text(name)
        self.read_plaintext(name)  # validate existing seal before any rewrite
        sticky = text is not None and is_sealed(text)
        content = delimiter.join(entries) if entries else ""
        if sticky or self.armed:
            if self._key is None:
                raise MemoryStorageError("native memory key unavailable; refusing plaintext publication")
            data = seal(content.encode("utf-8"), key=self._key, name=name)
        else:
            if entries and looks_like_magic_line(entries[0]):
                raise MemoryStorageError("plaintext first entry cannot impersonate a memory seal")
            data = content.encode("utf-8")
        self._publish(name, data, create=False)

    def create_backup(self, name: str, plaintext: str) -> None:
        _memory_leaf(name)
        if not fnmatch.fnmatchcase(name.casefold(), "*.md.bak.*"):
            raise PrivateFSError("unsafe", "memory_backup_leaf")
        if self._key is None:
            raise MemoryStorageError("native memory key unavailable; refusing unsealed drift backup")
        self._publish(name, seal(plaintext.encode("utf-8"), key=self._key, name=name), create=True)
