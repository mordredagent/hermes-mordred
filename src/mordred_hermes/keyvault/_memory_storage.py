"""Checked flat Windows memory storage under explicit custody ownership."""

from __future__ import annotations

import contextlib
import fnmatch
import functools
import re
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final

from .._private_fs import (
    ConfidentialTransaction,
    FileIdentity,
    FileMetadata,
    PrivateFSError,
    PrivateTransaction,
    open_confidential_directory,
    open_optional_confidential_directory,
)
from .._private_fs._types import validate_leaf
from ._exceptions import WrapError
from .memory_crypto import MemoryCryptoError, is_sealed, looks_like_magic_line, seal, unseal

if TYPE_CHECKING:
    from .._config_io import PublicationReceipt
    from ._windows_custody import GenerationLease, WindowsCustodySession, WindowsMemoryState
    from ._windows_proof import WindowsRuntimeProof

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
        return (None, False) if text is None else _classify_text(text, actual, self._key)

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
        tx = self._tx
        if tx is None:
            raise MemoryStorageError("memory publication requires an existing checked directory")
        exists = self._bounded_existing(tx, name, data)
        write = tx.create_bytes if create or not exists else tx.replace_bytes
        self._report(
            functools.partial(write, name, data),
            verify=lambda: tx.read_bytes(name, max_bytes=MEMORY_FILE_LIMIT) == data,
        )

    def _report(self, action: Callable[[], object], *, verify: Callable[[], bool] | None = None) -> None:
        """Run one checked memories mutation and report its outcome to the canonical receipt."""
        published = False
        try:
            action()
            published = True
            self._receipt.mark_published()
            if verify is not None and not verify():
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
            # Fail-closed trade-off: the owning canonical session's exit then raises
            # that uncertain failure from the interrupt, so a KeyboardInterrupt or
            # SystemExit during a hook publication surfaces at the hook boundary as
            # MemoryEncryptionUnavailable. Retained uncertainty wins over interrupt
            # responsiveness.
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


def _classify_text(text: str, name: str, key: bytes | None) -> tuple[str, bool]:
    """Hook-visible plaintext and whether ``text`` was an authenticated seal for ``name``."""
    if not looks_like_magic_line(text):
        return text, False
    if not is_sealed(text) or key is None:
        raise MemoryStorageError("memory seal is broken or its native key is unavailable")
    try:
        return unseal(text.encode("utf-8"), key=key, name=name).decode("utf-8"), True
    except (MemoryCryptoError, UnicodeError) as exc:
        raise MemoryStorageError("memory seal does not authenticate") from exc


# ---------------------------------------------------------------------------
# Proof-bound lifecycle (C5b-2): the only Windows marker writers
# ---------------------------------------------------------------------------

#: Lifecycle staging siblings: never memory leaves, so hooks and inventories skip them.
_SIBLING_PREFIX: Final = ".mordred-memory-"
_SIBLING: Final = re.compile(r"\.mordred-memory-(seal|open)-((?:[0-9a-f]{2}){1,110})")
_ARMED_MARKER: Final = b"memory-encryption enabled\n"
_OPTOUT_MARKER: Final = b"opt-out\n"
_MARKER_LIMIT: Final = 4096


@dataclass(frozen=True)
class EnableReport:
    sealed: int
    already_sealed: int
    reconciled: int
    armed: bool


@dataclass(frozen=True)
class DisableReport:
    decrypted: int
    already_plaintext: int
    reconciled: int
    opted_out: bool


@dataclass(frozen=True)
class PurgeReport:
    managed: bool
    armed: bool
    opted_out: bool
    sealed: tuple[str, ...]
    broken: tuple[str, ...]
    plaintext: tuple[str, ...]
    backups: tuple[str, ...]
    pending: tuple[str, ...]
    reasons: tuple[str, ...]
    may_purge: bool


class MemoryLifecycleError(MemoryStorageError):
    """A transition stopped after mutating; every file stays plaintext or an authenticated seal."""

    def __init__(self, operation: str, completed: int, remaining: int, *, uncertain: bool) -> None:
        outcome = "; the last outcome is uncertain" if uncertain else ""
        super().__init__(
            f"Windows memory {operation} stopped after {completed} file(s), {remaining} remaining{outcome}; "
            "resolve the cause and rerun with a fresh installed-runtime proof"
        )
        self.operation = operation
        self.completed = completed
        self.remaining = remaining
        self.uncertain = uncertain


@dataclass
class _Progress:
    operation: str
    plan: list[tuple[MemoryFileSnapshot, bytes, str]] = field(default_factory=list)
    completed: int = 0
    mutated: bool = False


def _uncertain(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, PrivateFSError) and current.commit_state == "uncertain":
            return True
        current = current.__cause__ or current.__context__
    return False


def _hook_text(row: MemoryFileSnapshot) -> str:
    """The text the Windows hook reads for these bytes (UTF-8, newline-normalized)."""
    try:
        return row.data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeError as exc:
        raise MemoryStorageError(f"memory {row.name!r} is not UTF-8 text") from exc


def _exists(tx: ConfidentialTransaction, name: str) -> bool:
    try:
        tx.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return False
        raise
    return True


def _sibling_name(operation: str, target: str) -> str:
    name = f"{_SIBLING_PREFIX}{operation}-{target.encode('utf-8').hex()}"
    if not _SIBLING.fullmatch(name):
        raise MemoryStorageError("memory name is too long for checked lifecycle staging")
    return name


def _leftover_siblings(tx: ConfidentialTransaction) -> tuple[str, ...]:
    """Validated interrupted-staging siblings whose target still exists; others refuse."""
    found = []
    for name in tx.list_names(max_entries=MEMORY_ENTRY_LIMIT):
        if not name.startswith(_SIBLING_PREFIX):
            continue
        match = _SIBLING.fullmatch(name)
        try:
            target = bytes.fromhex(match.group(2)).decode("utf-8") if match else ""
            _memory_leaf(target)
        except (ValueError, PrivateFSError):
            raise MemoryStorageError(f"unrecognized memory lifecycle sibling {name!r} is preserved") from None
        if not _exists(tx, target):
            raise MemoryStorageError(f"memory lifecycle sibling {name!r} has no target; preserved for review")
        found.append(name)
    return tuple(found)


def _plan(
    session: WindowsMemorySession, key: bytes, *, seal_files: bool
) -> tuple[list[tuple[MemoryFileSnapshot, bytes, str]], int]:
    """Authenticate every file and prepare every replacement in RAM before any mutation."""
    plan = []
    kept = 0
    total = 0
    for row in session.inventory():
        text, sealed = _classify_text(_hook_text(row), row.name, key)
        if sealed == seal_files:
            kept += 1
            total += len(row.data)
            continue
        if seal_files:
            replacement = seal(text.encode("utf-8"), key=key, name=row.name)
            if unseal(replacement, key=key, name=row.name) != text.encode("utf-8"):
                raise MemoryStorageError("memory seal did not verify in memory")
        elif looks_like_magic_line(text):
            raise MemoryStorageError(f"decrypted memory {row.name!r} would impersonate a seal")
        else:
            replacement = text.encode("utf-8")
        _sibling_name("seal" if seal_files else "open", row.name)
        if len(replacement) > MEMORY_FILE_LIMIT:
            raise PrivateFSError("unsafe", "memory_publication_limit")
        total += len(replacement)
        plan.append((row, replacement, text))
    if total > MEMORY_TOTAL_LIMIT:
        raise PrivateFSError("unsafe", "memory_publication_limit")
    return plan, kept


def _convert(
    session: WindowsMemorySession,
    tx: ConfidentialTransaction,
    key: bytes,
    row: MemoryFileSnapshot,
    replacement: bytes,
    text: str,
    *,
    seal_files: bool,
) -> None:
    """Verified create-no-replace sibling, then atomic checked replacement, then cleanup."""
    sibling = _sibling_name("seal" if seal_files else "open", row.name)

    def matches(name: str) -> bool:
        data = tx.read_bytes(name, max_bytes=MEMORY_FILE_LIMIT)
        return data == replacement and (not seal_files or unseal(data, key=key, name=row.name) == text.encode("utf-8"))

    session._report(functools.partial(tx.create_bytes, sibling, replacement), verify=lambda: matches(sibling))
    staged = tx.stat(sibling).identity
    if tx.stat(row.name) != row.metadata:
        raise MemoryStorageError(f"memory {row.name!r} changed during the lifecycle transition")
    # The plaintext (or seal) is only ever replaced atomically by verified bytes.
    session._report(functools.partial(tx.replace_bytes, row.name, replacement), verify=lambda: matches(row.name))
    session._report(functools.partial(tx.delete_file, sibling, expected_identity=staged))


def _convert_all(session: WindowsMemorySession, progress: _Progress, *, seal_files: bool) -> tuple[int, int, int]:
    tx, key = session._tx, session._key
    if key is None:
        raise MemoryStorageError("managed memory key unavailable")
    if tx is None:
        return 0, 0, 0
    leftovers = _leftover_siblings(tx)
    progress.plan, kept = _plan(session, key, seal_files=seal_files)
    entries = len(tx.list_names(max_entries=MEMORY_ENTRY_LIMIT)) - len(leftovers)
    if progress.plan and entries >= MEMORY_ENTRY_LIMIT:
        raise PrivateFSError("unsafe", "memory_publication_entry_limit")  # no room for one staging sibling
    for sibling in leftovers:
        progress.mutated = True
        staged = tx.stat(sibling).identity
        session._report(functools.partial(tx.delete_file, sibling, expected_identity=staged))
    for row, replacement, text in progress.plan:
        progress.mutated = True
        _convert(session, tx, key, row, replacement, text, seal_files=seal_files)
        progress.completed += 1
    for row in session.inventory():
        if _classify_text(_hook_text(row), row.name, key)[1] != seal_files:
            raise MemoryStorageError(f"memory {row.name!r} was not converted")
    if any(name.startswith(_SIBLING_PREFIX) for name in tx.list_names(max_entries=MEMORY_ENTRY_LIMIT)):
        raise MemoryStorageError("memory lifecycle staging was not removed")
    return len(progress.plan), kept, len(leftovers)


def _optional_stat(tx: PrivateTransaction, name: str) -> FileMetadata | None:
    try:
        return tx.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return None
        raise


def _transition_markers(custody: WindowsCustodySession, *, armed: bool) -> None:
    """The only Windows marker writer: remove the opposite marker, then create-no-replace."""
    from ._windows_custody import MARKER, OPTOUT

    remove, create, data = (OPTOUT, MARKER, _ARMED_MARKER) if armed else (MARKER, OPTOUT, _OPTOUT_MARKER)
    with custody.canonical.borrow_mordred_transaction() as tx, custody.canonical.publication_receipt() as receipt:
        existing = _optional_stat(tx, remove)
        if existing is not None:
            tx.delete_file(remove, expected_identity=existing.identity)
        current = _optional_stat(tx, create)
        if current is not None and current.size > _MARKER_LIMIT:
            raise PrivateFSError("unsafe", "memory_marker_limit")
        if current is None:
            tx.create_bytes(create, data)
            if tx.read_bytes(create, max_bytes=_MARKER_LIMIT) != data:
                failure = PrivateFSError("unsafe", "memory_marker_verify", commit_state="uncertain")
                receipt.mark_uncertain(failure)
                raise failure


def _transition(
    home: Path, proof: WindowsRuntimeProof, *, seal_files: bool
) -> tuple[tuple[int, int, int], WindowsMemoryState]:
    from . import _runtime_probe
    from ._windows_custody import windows_custody_session
    from ._windows_proof import require_issued_proof, validate_windows_runtime_proof

    require_issued_proof(proof)
    progress = _Progress("enable" if seal_files else "disable")
    try:
        with windows_custody_session(home) as custody:
            with windows_memory_session(home, custody=custody) as session:
                validate_windows_runtime_proof(custody, proof)
                _runtime_probe.require_stopped_windows_gateways(home)
                counts = _convert_all(session, progress, seal_files=seal_files)
            # Arming/disarming is the final transition: revalidate under the held custody locks.
            validate_windows_runtime_proof(custody, proof)
            _runtime_probe.require_stopped_windows_gateways(home)
            progress.mutated = True
            _transition_markers(custody, armed=seal_files)
            state = custody.memory_state()
            if (state.marker is not None, state.optout is not None) != (seal_files, not seal_files):
                raise MemoryStorageError("memory marker transition did not verify")
    except Exception as exc:
        if not progress.mutated:
            raise
        remaining = len(progress.plan) - progress.completed
        raise MemoryLifecycleError(
            progress.operation, progress.completed, remaining, uncertain=_uncertain(exc)
        ) from exc
    return counts, state


def enable_memory_encryption(home: Path, proof: WindowsRuntimeProof) -> EnableReport:
    """Seal every checked plaintext memory, validate every seal, then arm.

    Requires a current issued installed-runtime proof, revalidated with the
    stopped-gateway gate under home -> mordred -> memories before any mutation
    and again before arming. Plaintext is replaced only atomically by verified
    seals; a failure leaves every file plaintext or authenticated and unarmed.
    """
    (sealed, kept, reconciled), state = _transition(home, proof, seal_files=True)
    return EnableReport(sealed=sealed, already_sealed=kept, reconciled=reconciled, armed=state.armed)


def disable_memory_encryption(home: Path, proof: WindowsRuntimeProof, *, keep_key: bool = True) -> DisableReport:
    """Decrypt and verify every memory, then disarm (marker removed, opt-out written).

    The memory key is always retained: ``keep_key=False`` refuses before any
    lock or mutation, because purge is the separate ceremony that starts with
    :func:`verify_memory_purge_candidates`. A failure keeps custody, remaining
    ciphertext and the armed state.
    """
    if keep_key is not True:
        raise MemoryStorageError(
            "disable never deletes the memory key; purge is a separate ceremony (verify_memory_purge_candidates)"
        )
    (decrypted, kept, reconciled), state = _transition(home, proof, seal_files=False)
    return DisableReport(
        decrypted=decrypted, already_plaintext=kept, reconciled=reconciled, opted_out=state.optout is not None
    )


def verify_memory_purge_candidates(home: Path) -> PurgeReport:
    """Load-only complete checked scan; no proof, no native key operation, no mutation."""
    from ._windows_custody import windows_custody_session

    rows: tuple[MemoryFileSnapshot, ...] = ()
    pending: tuple[str, ...] = ()
    with windows_custody_session(home) as custody:
        state = custody.memory_state()
        with open_optional_confidential_directory(home / "memories") as directory:
            if directory is not None:
                with directory.transaction() as tx:
                    pending = tuple(
                        n for n in tx.list_names(max_entries=MEMORY_ENTRY_LIMIT) if n.startswith(_SIBLING_PREFIX)
                    )
                    rows = _inventory(tx)
        if custody.memory_state() != state:
            raise MemoryStorageError("memory custody changed during purge verification")
    sealed = tuple(row.name for row in rows if is_sealed(row.data))
    broken = tuple(
        row.name
        for row in rows
        if not is_sealed(row.data) and looks_like_magic_line(row.data.decode("utf-8", "surrogateescape"))
    )
    plaintext = tuple(row.name for row in rows if row.name not in sealed and row.name not in broken)
    checks = (
        (state.lease is None, "memory custody is not managed"),
        (state.marker is not None, "memory opt-in marker is present"),
        (state.optout is None, "memory has not been explicitly disabled"),
        (bool(sealed), "sealed memory remains"),
        (bool(broken), "broken memory seals remain"),
        (bool(pending), "interrupted lifecycle staging remains"),
    )
    reasons = tuple(reason for failed, reason in checks if failed)
    return PurgeReport(
        managed=state.lease is not None,
        armed=state.armed,
        opted_out=state.optout is not None,
        sealed=sealed,
        broken=broken,
        plaintext=plaintext,
        backups=tuple(row.name for row in rows if fnmatch.fnmatchcase(row.name.casefold(), "*.md.bak.*")),
        pending=pending,
        reasons=reasons,
        may_purge=not reasons,
    )
