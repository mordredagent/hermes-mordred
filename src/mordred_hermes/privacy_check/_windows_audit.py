"""Windows audit-writer routing for privacy_check (C7b part 1).

On Windows the factory never consults the file-vault probe (there is no file
vault). It observes the independent audit custody role inside one load-only
custody session and decides:

* a committed current audit role -> the C5d ``WindowsEncryptedWriter``
  (MRAL), wrapped as :class:`WindowsEncryptedAuditWriter`;
* checked clean absence (no ownership, journal or retained generation, and
  no MRAL/unrecognized history in the audit namespace) -> the explicit
  degraded :class:`WindowsPlaintextAuditWriter`, which publishes only through
  C7a checked audit sessions;
* anything else -> :class:`AuditWriterRefused`: no writer, no plaintext over
  retained ciphertext, and no MRAL log is ever rotated aside.

The factory never enrolls, creates or probes native keys beyond C5d's
load-only lease. Lock order is C5d's: home -> mordred -> writer mutex -> audit
directory. Sticky failures (poison/uncertainty) are exposed through
``refusal`` so privacy hooks refuse the hooked operation. Keyvault imports stay
lazy, so importing privacy_check on POSIX/macOS is unchanged.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import logging
import os
import threading
import time
import zlib
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from .._log_rotation import audit_rotation_names, rotate_audit, sweep_audit_retention
from .._log_rotation import today_utc_date as _today_utc_date
from .._log_rotation import utcnow_iso as _utcnow_iso
from .._private_fs import PrivateFSError, open_optional_confidential_directory, open_optional_private_directory
from ._exceptions import AuditEntryRejected, AuditRefusalReason, AuditWriterRefused
from .audit import DEFAULT_RETENTION_DAYS, DEFAULT_ROTATE_BYTES, Writer, _serialize

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from .._audit_session import AuditSession
    from .._private_fs import FileIdentity, PrivateTransaction
    from ..keyvault._windows_custody import WindowsCustodySession
    from ..keyvault.windows_audit import WindowsEncryptedWriter, _RecordedAudit
    from ..keyvault.wrap import NativeBackend

_LOG = logging.getLogger("mordred.privacy_check.audit")

WindowsAuditMode = Literal["encrypted", "plaintext-degraded"]

# Recoverable outcomes refuse only the current operation; every other reason
# keeps the writer (or a refused construction) refused until explicit
# reconciliation and a restart.
_RECOVERABLE: Final[frozenset[AuditRefusalReason]] = frozenset(
    {"audit-unavailable", "policy-pending", "native-unavailable", "entry-rejected", "custody-nesting"}
)
_TRANSIENT_FS_REASONS: Final = frozenset({"busy", "io", "access_denied", "missing"})
# Bounds for inspecting retained history before a plaintext decision: C7a's
# gzip publication cap and its first-line probe limit.
_HISTORY_GZIP_LIMIT: Final = 16 * 1024 * 1024 + 65536
_FIRST_LINE_LIMIT: Final = 4096
_DAY_NS: Final = 86_400 * 1_000_000_000
# Canonical ``CanonicalPaths`` Mordred leaf: the default audit directory.
_MORDRED_LEAF: Final = "mordred"

# Sticky construction refusals, keyed by normalized (audit path, home): a later
# hook raises the same refusal without reentering custody or rescanning
# history. Cleared only by a restart (tests use the reset helper below).
_REFUSED_CONSTRUCTIONS: dict[tuple[str, str], AuditRefusalReason] = {}
_REFUSED_LOCK = threading.Lock()


def _classify_storage(exc: PrivateFSError) -> AuditRefusalReason:
    from .._config_io import PolicyPendingError

    if exc.commit_state != "not_committed":
        return "audit-uncertain"
    if isinstance(exc.__cause__, PolicyPendingError):
        # The foundation transaction wraps a pending-marker refusal raised
        # inside its scope as a definite I/O failure; keep the real reason.
        return "policy-pending"
    return "audit-unavailable" if exc.reason in _TRANSIENT_FS_REASONS else "audit-unsafe"


def classify_audit_failure(exc: BaseException) -> AuditRefusalReason:
    """Map a custody/storage/native failure onto the closed refusal vocabulary."""
    from .._config_io import PolicyPendingError
    from ..keyvault._exceptions import WrapError, WrapKeyNotFound
    from ..keyvault._windows_profile import CustodyError

    if isinstance(exc, AuditWriterRefused):
        return exc.reason
    if isinstance(exc, AuditEntryRejected):
        return "entry-rejected"
    if not isinstance(exc, Exception):
        return "interrupted"
    if isinstance(exc, PrivateFSError):
        return _classify_storage(exc)
    if isinstance(exc, PolicyPendingError):
        return "policy-pending"
    if isinstance(exc, CustodyError):
        return "custody-broken"
    if isinstance(exc, WrapKeyNotFound):
        return "native-key-missing"
    if isinstance(exc, WrapError):
        return "native-unavailable"
    if isinstance(exc, ValueError):
        # Identity, bound or validation invariants of the checked storage layers.
        return "audit-invalid"
    return "audit-uncertain"


def refusal_is_recoverable(reason: AuditRefusalReason) -> bool:
    """True when ``reason`` refuses only the current operation."""
    return reason in _RECOVERABLE


def audit_writer_refusal(writer: object) -> AuditRefusalReason | None:
    """Return the sticky refusal of a Windows audit writer, else ``None``."""
    return writer.refusal if isinstance(writer, _WindowsAuditWriter) else None


def _entry_bytes(serialize: Callable[[Mapping[str, Any]], bytes], entry: Mapping[str, Any]) -> bytes:
    """Serialize before any custody or I/O; reject oversized/unserializable entries."""
    try:
        return serialize({"ts": _utcnow_iso(), **dict(entry)})
    except (TypeError, ValueError) as exc:
        raise AuditEntryRejected(str(exc)) from exc


def _require_canonical_home(home: Path) -> None:
    """Refuse a relative or ``..``-aliased home as invalid, before custody entry."""
    from .._config_io import CanonicalPaths

    try:
        CanonicalPaths(home)
    except ValueError as exc:
        raise AuditWriterRefused("audit-invalid", str(exc)) from exc


def _lexical(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


@contextlib.contextmanager
def _custody(factory: Callable[[], AbstractContextManager[WindowsCustodySession]]) -> Iterator[WindowsCustodySession]:
    """Enter custody, labelling nested-canonical misuse at entry as ``custody-nesting``.

    Callers validate the canonical home first, so an entry ``ValueError`` here
    is nesting misuse rather than an invalid path.
    """
    with contextlib.ExitStack() as stack:
        try:
            session = stack.enter_context(factory())
        except ValueError as exc:
            raise AuditWriterRefused("custody-nesting", str(exc)) from exc
        yield session


def _audit_role_enrolled(session: WindowsCustodySession) -> bool:
    """Observe the audit role through C5e ``role_status``, with no native I/O.

    ``True`` is a committed current generation; ``False`` is checked, clean
    absence. A pending journal and retained generations without a current one
    refuse here; ``role_status`` itself refuses orphan journals and unowned
    records as broken custody.
    """
    status = session.role_status("audit")
    if status.pending:
        raise AuditWriterRefused("custody-pending", "unresolved audit enrollment or deletion journal")
    if status.current is None:
        if status.retained:
            raise AuditWriterRefused("custody-retained", "retained audit generations without a current role")
        return False
    return True


def _first_line_kind(prefix: bytes) -> str:
    """Classify a decoded first line exactly like C7a ``AuditSession.probe``."""
    from .._audit_session import _invalid_constant, _unique_object

    if not prefix:
        return "empty"
    line, newline, _rest = prefix.partition(b"\n")
    if not newline or len(line) > _FIRST_LINE_LIMIT:
        return "unknown"
    try:
        value = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        return "unknown"
    if not isinstance(value, dict):
        return "unknown"
    return "mral" if value.get("fmt") == "MRAL" else "ndjson"


def _history_kind(audit: AuditSession, name: str, compressed: bool) -> str:
    if not compressed:
        return audit.probe(name).kind
    snapshot = audit.snapshot(name, max_bytes=_HISTORY_GZIP_LIMIT)
    if snapshot is None:
        return "missing"
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(snapshot.data), mode="rb") as stream:
            prefix = stream.read(_FIRST_LINE_LIMIT + 1)
    except (OSError, EOFError, zlib.error):
        return "unknown"
    return _first_line_kind(prefix)


def _require_plaintext(kind: str) -> None:
    if kind == "mral":
        raise AuditWriterRefused("retained-ciphertext", "MRAL history without a usable audit role")
    if kind == "unknown":
        raise AuditWriterRefused("history-unrecognized", "audit history is not recognizable plaintext")


def _inspect_namespace(audit: AuditSession) -> None:
    """Refuse plaintext over retained ciphertext: active file and dated history."""
    _require_plaintext(audit.probe(audit.active_name).kind)
    for name, _date, _number, compressed in audit_rotation_names(audit):
        _require_plaintext(_history_kind(audit, name, compressed))


def _mordred_absent(exc: BaseException) -> bool:
    return (
        isinstance(exc, PrivateFSError)
        and exc.reason == "missing"
        and exc.operation == "mordred_transaction"
        and exc.commit_state == "not_committed"
    )


def _is_default_directory(path: Path, home: FileIdentity | None) -> bool:
    """Whether an absent audit directory is the canonical ``<home>/mordred``."""
    if home is None or path.parent.name.casefold() != _MORDRED_LEAF:
        return False
    with open_optional_confidential_directory(path.parent.parent) as parent:
        return parent is not None and parent.directory_identity() == home


def _check_without_mordred(path: Path, session: WindowsCustodySession, *, history: bool) -> None:
    """The ``_audit_scope`` directory rules when no protected Mordred loan exists.

    Only the checked-absent default directory has no history; a missing custom
    directory and the home itself refuse, exactly as with a Mordred loan.
    """
    from .._audit_session import audit_session

    home = session.canonical.home_directory_identity()
    if home is None and _lexical(path.parent) == _lexical(session.home / _MORDRED_LEAF):
        # Checked-absent Hermes home: no history can exist below it. The first
        # append creates ``<home>`` and ``<home>/mordred`` exact-private.
        return
    with open_optional_private_directory(path.parent) as directory:
        identity = None if directory is None else directory.directory_identity()
    if identity is None:
        if not _is_default_directory(path, home):
            raise PrivateFSError("missing", "audit_directory")
        return
    if identity == home:
        raise PrivateFSError("unsafe", "audit_home_lock_order")
    with audit_session(path, blocking=False) as audit:
        if audit.directory_identity() != identity:
            raise PrivateFSError("unsafe", "audit_directory_identity")
        if history:
            _inspect_namespace(audit)


def _check_namespace(path: Path, session: WindowsCustodySession, *, history: bool) -> None:
    """Apply the C5d directory rules at construction; scan history when asked.

    Read-only. Opening a checked transaction may create the foundation's
    permanent directory lock sidecar, never an audit file or directory.
    """
    from ..keyvault.windows_audit import _audit_scope

    try:
        with _audit_scope(path, session) as audit:
            if history:
                _inspect_namespace(audit)
        return
    except Exception as exc:
        if not _mordred_absent(exc):
            raise
    _check_without_mordred(path, session, history=history)


class _WindowsAuditWriter:
    """Shared sticky-refusal state; the first sticky reason wins."""

    mode: WindowsAuditMode

    def __init__(self) -> None:
        self._refusal: AuditRefusalReason | None = None

    @property
    def refusal(self) -> AuditRefusalReason | None:
        return self._refusal

    def _remember(self, exc: BaseException, *, published: bool = False) -> None:
        reason = classify_audit_failure(exc)
        if published and reason in _RECOVERABLE:
            reason = "audit-uncertain"
        if self._refusal is None and reason not in _RECOVERABLE:
            self._refusal = reason

    def _refuse_if_sticky(self) -> None:
        if self._refusal is not None:
            raise AuditWriterRefused(self._refusal, "writer is refused until audit custody is reconciled")


class WindowsEncryptedAuditWriter(_WindowsAuditWriter):
    """The C5d writer plus privacy's reported mode and sticky refusal."""

    mode: WindowsAuditMode = "encrypted"

    def __init__(self, inner: WindowsEncryptedWriter) -> None:
        super().__init__()
        self.inner = inner
        self.path = inner.path
        # Guards only the refusal flag; never held across custody or I/O.
        self._flag = threading.Lock()

    def append(self, entry: Mapping[str, Any]) -> None:
        self._call(entry, lambda: self.inner.append(entry))

    def append_in_custody(
        self,
        entry: Mapping[str, Any],
        *,
        custody: WindowsCustodySession,
        transaction: PrivateTransaction | None = None,
    ) -> None:
        self._call(entry, lambda: self.inner.append_in_custody(entry, custody=custody, transaction=transaction))

    def close(self) -> None:
        self.inner.close()

    def _call(self, entry: Mapping[str, Any], call: Callable[[], None]) -> None:
        from ..keyvault import log_encryption as mral

        _entry_bytes(mral._serialize, entry)  # the C5d writer's own entry limit
        self._refuse_if_sticky()
        try:
            call()
        except BaseException as exc:
            with self._flag:
                self._remember(exc)
            raise


class WindowsPlaintextAuditWriter(_WindowsAuditWriter):
    """Explicitly degraded plaintext NDJSON through C7a checked sessions.

    Constructed only for a checked fresh unmanaged profile. Every append
    reenters custody (home -> mordred), refuses once the audit role becomes
    enrolled, takes the writer mutex, then publishes under the C5d audit scope
    (default directory: the protected Mordred loan; custom: a preexisting
    exact-private directory with publication receipts). MRAL or unrecognized
    active files refuse; nothing is ever rotated aside. The mutex is held until
    custody has exited, so a late uncertain outcome settles before another
    thread can append. Missing ``<home>/mordred`` is created exact-private at
    the first append, never at construction.
    """

    mode: WindowsAuditMode = "plaintext-degraded"

    def __init__(
        self,
        path: Path,
        *,
        home: Path,
        rotate_bytes: int = DEFAULT_ROTATE_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        super().__init__()
        if type(rotate_bytes) is not int or rotate_bytes <= 0 or type(retention_days) is not int or retention_days < 0:
            raise ValueError("invalid audit rotation/retention bounds")
        self.path = Path(path)
        self.home = Path(home)
        self.rotate_bytes = rotate_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._last_date = ""

    def append(self, entry: Mapping[str, Any]) -> None:
        self._append(entry, custody=None, transaction=None)

    def append_in_custody(
        self,
        entry: Mapping[str, Any],
        *,
        custody: WindowsCustodySession,
        transaction: PrivateTransaction | None = None,
    ) -> None:
        """Explicit synchronous borrow; the owning outer exit acknowledges commit."""
        self._append(entry, custody=custody, transaction=transaction)

    def close(self) -> None:
        # Each append owns its own custody/audit scope; nothing is cached.
        return None

    def _custody_factory(
        self, custody: WindowsCustodySession | None
    ) -> Callable[[], AbstractContextManager[WindowsCustodySession]]:
        from ..keyvault import _windows_custody

        if custody is None:
            _require_canonical_home(self.home)
            return lambda: _windows_custody.windows_custody_session(self.home, create=True)
        custody.check()
        return lambda: _windows_custody.windows_custody_session(self.home, canonical=custody.canonical)

    def _append(
        self,
        entry: Mapping[str, Any],
        *,
        custody: WindowsCustodySession | None,
        transaction: PrivateTransaction | None,
    ) -> None:
        from ..keyvault.windows_audit import _audit_scope

        data = _entry_bytes(_serialize, entry)
        # ``held`` is outermost: the mutex is taken inside custody (lock order)
        # but released only after custody exits, so a late custody-exit failure
        # settles under the mutex before another thread can append. The role is
        # validated before the mutex, like C5d's generation check.
        with contextlib.ExitStack() as held:
            published = False
            try:
                with _custody(self._custody_factory(custody)) as session:
                    if _audit_role_enrolled(session):
                        raise AuditWriterRefused("audit-role-enrolled", "restart to use the encrypted audit role")
                    held.enter_context(self._lock)
                    self._refuse_if_sticky()
                    audit: _RecordedAudit | None = None
                    try:
                        with _audit_scope(self.path, session, transaction=transaction) as audit:
                            self._write(audit, data)
                    finally:
                        published = audit is not None and audit.published
            except BaseException as exc:
                self._remember(exc, published=published)
                raise

    def _write(self, audit: AuditSession, data: bytes) -> None:
        probe = audit.probe(audit.active_name)
        _require_plaintext(probe.kind)
        today = _today_utc_date()
        metadata = probe.metadata
        if metadata is not None:
            stale = bool(self._last_date) and self._last_date != today
            if stale or metadata.size + len(data) > self.rotate_bytes:
                self._rotate(audit, self._last_date if stale else today)
                metadata = None
        if metadata is None:
            audit.create(audit.active_name, data)
        else:
            audit.append(audit.active_name, data, expected_identity=metadata.identity)
        self._last_date = today

    def _rotate(self, audit: AuditSession, suffix: str) -> None:
        result = rotate_audit(audit, suffix)
        if result.warning is not None:
            _LOG.warning("plaintext audit rotation kept raw history (%s): %s", result.compression, result.warning)
        protected = frozenset(name for name in (result.raw_name, result.gzip_name) if name is not None)
        sweep_audit_retention(
            audit,
            cutoff_mtime_ns=time.time_ns() - self.retention_days * _DAY_NS,
            protected_names=protected,
        )


def _encrypted_writer(path: Path, home: Path, backend: NativeBackend | None) -> WindowsEncryptedAuditWriter:
    from ..keyvault import _windows_custody
    from ..keyvault._windows_profile import CustodyError
    from ..keyvault.windows_audit import WindowsAuditProvider

    if backend is None:
        try:
            backend = _windows_custody.windows_backend()  # helper discovery only; no native operation
        except CustodyError as exc:
            raise AuditWriterRefused("native-unavailable", "Windows TPM helper unavailable") from exc
    # C5d's load-only lease (ownership plus the native public key) in a nested
    # same-home custody session that joins the factory's canonical session.
    return WindowsEncryptedAuditWriter(WindowsAuditProvider(home, backend=backend).writer(path))


def _construction_key(path: Path, home: Path) -> tuple[str, str]:
    return (os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(home)))


def _forget_construction_refusals_for_tests() -> None:
    with _REFUSED_LOCK:
        _REFUSED_CONSTRUCTIONS.clear()


def _construct(
    path: Path, home: Path, backend: NativeBackend | None
) -> WindowsEncryptedAuditWriter | WindowsPlaintextAuditWriter:
    from ..keyvault import _windows_custody

    _require_canonical_home(home)
    with _custody(lambda: _windows_custody.windows_custody_session(home, backend=backend)) as session:
        managed = _audit_role_enrolled(session)
        _check_namespace(path, session, history=not managed)
        if managed:
            return _encrypted_writer(path, home, backend)
    return WindowsPlaintextAuditWriter(path, home=home)


def make_windows_audit_writer(audit_path: Path, *, home: Path, backend: NativeBackend | None = None) -> Writer:
    """Return the Windows audit writer, or raise :class:`AuditWriterRefused`.

    No catch-all plaintext fallback: only checked clean absence of the audit
    role (and of retained ciphertext) selects plaintext, and that downgrade is
    logged and reported as ``mode == "plaintext-degraded"``. Sticky refusals
    are remembered for the process; recoverable ones are retried.
    """
    path, home = Path(audit_path), Path(home)
    key = _construction_key(path, home)
    with _REFUSED_LOCK:
        remembered = _REFUSED_CONSTRUCTIONS.get(key)
    if remembered is not None:
        raise AuditWriterRefused(remembered, "remembered construction refusal; reconcile and restart")
    try:
        writer = _construct(path, home, backend)
    except Exception as exc:
        reason = classify_audit_failure(exc)
        _LOG.error("Windows audit writer refused for %s: %s (%s: %s)", path, reason, type(exc).__name__, exc)
        if not refusal_is_recoverable(reason):
            with _REFUSED_LOCK:
                _REFUSED_CONSTRUCTIONS.setdefault(key, reason)
        if isinstance(exc, AuditWriterRefused):
            raise
        raise AuditWriterRefused(reason) from exc
    if writer.mode == "plaintext-degraded":
        _LOG.warning(
            "Windows audit role is not enrolled; writing checked plaintext audit at %s "
            "(encryption is unavailable until native audit custody is explicitly enrolled)",
            path,
        )
    return writer
