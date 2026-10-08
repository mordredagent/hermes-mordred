"""Load-only Windows audit custody and the shared MRAL encrypted-log format.

This opt-in adapter does not route product factories or enroll keys. Lock order
is home -> mordred -> writer mutex -> audit directory. Custom directories must
already exist, use nonblocking child locks, and report every publication to C2.
Synchronous unwrap sinks must explicitly borrow the supplied custody session;
never resolve a fresh provider inside a custody/audit callback.
"""

from __future__ import annotations

import base64
import contextlib
import os
import threading
import time
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, TypeVar

from .._audit_session import AuditProbe, AuditSession, AuditSnapshot, audit_session, decode_audit_bytes
from .._config_io import PublicationReceipt
from .._log_rotation import rotate_audit, sweep_audit_retention, today_utc_date, utcnow_iso
from .._private_fs import (
    FileIdentity,
    FileMetadata,
    PrivateFSError,
    PrivateTransaction,
    open_optional_private_directory,
)
from . import log_encryption as mral
from ._exceptions import WrapAuthCancelled, WrapError, WrapKeyNotFound
from ._windows_custody import GenerationLease, WindowsCustodySession, windows_custody_session
from ._windows_profile import CustodyError
from .crypto import encrypt
from .wrap import DEK_LEN, AuditSink, NativeBackend, _parse_header, unwrap_dek, wrap_dek

DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024 + 65536
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_T = TypeVar("_T")


@contextlib.contextmanager
def _custody_scope(
    home: Path, custody: WindowsCustodySession | None, backend: NativeBackend | None
) -> Iterator[WindowsCustodySession]:
    if custody is not None:
        custody.check()
    with windows_custody_session(
        home,
        canonical=None if custody is None else custody.canonical,
        backend=backend if custody is None else custody.backend,
    ) as session:
        yield session


class _RecordedAudit(AuditSession):
    """Forward C7a operations and immediately account for independent children."""

    def __init__(self, session: AuditSession, receipt: PublicationReceipt) -> None:
        self._session = session
        self._receipt = receipt
        self.active_name = session.active_name
        self.published = False

    def _mutation(self, call: Callable[[], _T]) -> _T:
        try:
            result = call()
        except PrivateFSError as exc:
            if exc.commit_state == "uncertain":
                self._receipt.mark_uncertain(exc)
            raise
        self._receipt.mark_published()
        self.published = True
        return result

    def directory_identity(self) -> FileIdentity:
        return self._session.directory_identity()

    def snapshot_many(
        self, names: Sequence[str], *, max_file_bytes: int, max_total_bytes: int
    ) -> tuple[AuditSnapshot, ...]:
        return self._session.snapshot_many(names, max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes)

    def stat(self, name: str) -> FileMetadata | None:
        return self._session.stat(name)

    def probe(self, name: str, *, max_line_bytes: int = 4096) -> AuditProbe:
        return self._session.probe(name, max_line_bytes=max_line_bytes)

    def snapshot(self, name: str, *, max_bytes: int) -> AuditSnapshot | None:
        return self._session.snapshot(name, max_bytes=max_bytes)

    def list_names(self, *, max_entries: int = 4096) -> tuple[str, ...]:
        return self._session.list_names(max_entries=max_entries)

    def create(self, name: str, data: bytes) -> FileMetadata:
        return self._mutation(lambda: self._session.create(name, data))

    def append(self, name: str, data: bytes, *, expected_identity: FileIdentity) -> FileMetadata:
        return self._mutation(lambda: self._session.append(name, data, expected_identity=expected_identity))

    def rename(self, name: str, target: str, *, expected_identity: FileIdentity) -> FileMetadata:
        return self._mutation(lambda: self._session.rename(name, target, expected_identity=expected_identity))

    def delete(self, name: str, *, expected_identity: FileIdentity) -> None:
        self._mutation(lambda: self._session.delete(name, expected_identity=expected_identity))


@contextlib.contextmanager
def _audit_scope(
    path: Path, custody: WindowsCustodySession, *, transaction: PrivateTransaction | None = None
) -> Iterator[AuditSession]:
    custody.check()
    with custody.canonical.borrow_mordred_transaction() as loan:
        with open_optional_private_directory(path.parent) as directory:
            if directory is None:
                raise PrivateFSError("missing", "audit_directory")
            identity = directory.directory_identity()
        default = identity == loan.directory_identity()
        if identity == custody.canonical.home_directory_identity():
            raise PrivateFSError("unsafe", "audit_home_lock_order")
        if transaction is not None:
            transaction.assert_private_admission()
            if not default or transaction.directory_identity() != identity:
                raise PrivateFSError("unsafe", "audit_borrow_identity")
        # Receipt surrounds child exit as well as each mutation. Default loans
        # also account in C2; uniform receipt semantics keep uncertainty sticky.
        with custody.canonical.publication_receipt() as receipt:
            recorded: _RecordedAudit | None = None
            try:
                with audit_session(
                    path, blocking=False, transaction=(transaction or loan) if default else None
                ) as session:
                    recorded = _RecordedAudit(session, receipt)
                    yield recorded
            except BaseException as exc:
                if recorded is not None and recorded.published:
                    if isinstance(exc, PrivateFSError):
                        exc.commit_state = "uncertain"
                        receipt.mark_uncertain(exc)
                    else:
                        error = PrivateFSError("io", "audit_operation", commit_state="uncertain")
                        receipt.mark_uncertain(error)
                        raise error from exc
                raise


def _header_lease(path: Path, header_bytes: bytes, custody: WindowsCustodySession) -> tuple[GenerationLease, bytes]:
    header, wrapped = mral._parse_log_header(path, header_bytes)
    native = header.get("native_key_id")
    if not isinstance(native, str):
        raise mral.AuditLogDecryptError(f"{path}: Windows audit header requires an owned native selector")
    try:
        _parse_header(wrapped, mral.AUDIT_LOG_KEY_ID)
    except WrapError as exc:
        raise mral.AuditLogDecryptError(f"{path}: malformed wrapped audit DEK") from exc
    return custody.lease_for_native("audit", native), wrapped


class WindowsAuditProvider:
    """Independent, load-only audit role. No file-vault or memory initialization."""

    def __init__(self, home: Path, *, backend: NativeBackend | None = None) -> None:
        self.home = Path(home)
        self.backend = backend

    def lease(self, *, custody: WindowsCustodySession | None = None) -> GenerationLease:
        with _custody_scope(self.home, custody, self.backend) as session:
            lease = session.lease("audit")
            session.backend_for(lease)
            return lease

    def writer(
        self,
        path: Path,
        *,
        rotate_bytes: int = mral.DEFAULT_ROTATE_BYTES,
        retention_days: int = mral.DEFAULT_RETENTION_DAYS,
        custody: WindowsCustodySession | None = None,
    ) -> WindowsEncryptedWriter:
        with _custody_scope(self.home, custody, self.backend) as session:
            lease = session.lease("audit")
            backend = session.backend_for(lease)
        return WindowsEncryptedWriter(
            path,
            home=self.home,
            lease=lease,
            backend=backend,
            rotate_bytes=rotate_bytes,
            retention_days=retention_days,
        )


class WindowsEncryptedWriter:
    """A generation lease with checked C7a append/rotation, sharing MRAL crypto."""

    def __init__(
        self,
        path: Path,
        *,
        home: Path,
        lease: GenerationLease,
        backend: NativeBackend,
        rotate_bytes: int = mral.DEFAULT_ROTATE_BYTES,
        retention_days: int = mral.DEFAULT_RETENTION_DAYS,
    ) -> None:
        if type(rotate_bytes) is not int or rotate_bytes <= 0 or type(retention_days) is not int or retention_days < 0:
            raise ValueError("invalid audit rotation/retention bounds")
        if lease.role != "audit" or lease.key_id != mral.AUDIT_LOG_KEY_ID:
            raise CustodyError("writer lease is not the audit role")
        self.path = Path(path)
        self.home = Path(home)
        self.lease = lease
        self.backend = backend
        self.rotate_bytes = rotate_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._dek: bytearray | None = None
        self._aad = b""
        self._header_bytes = b""
        self._active_identity: FileIdentity | None = None
        self._last_date = ""
        self._poisoned = False

    def _wipe_dek(self) -> None:
        if self._dek is not None:
            self._dek[:] = bytes(len(self._dek))
        self._dek = None
        self._aad = b""
        self._header_bytes = b""
        self._active_identity = None

    def close(self) -> None:
        with self._lock:
            self._wipe_dek()

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

    def _append(
        self,
        entry: Mapping[str, Any],
        *,
        custody: WindowsCustodySession | None,
        transaction: PrivateTransaction | None,
    ) -> None:
        plaintext = mral._serialize({"ts": utcnow_iso(), **dict(entry)})
        incoming = mral._encrypted_line_len(len(plaintext))
        # Include owned custody/child cleanup in failure handling: even a late
        # exit error wipes cached ownership. An uncertain writer never retries.
        try:
            with _custody_scope(self.home, custody, self.backend) as session:
                session.validate_lease(self.lease)
                if session.lease("audit") != self.lease:
                    raise CustodyError("audit writer generation is no longer current")
                with self._lock:
                    if self._poisoned:
                        raise CustodyError("audit writer is poisoned; explicit reconciliation is required")
                    backend = session.backend_for(self.lease)
                    with _audit_scope(self.path, session, transaction=transaction) as audit:
                        self._append_checked(audit, session, backend, plaintext, incoming)
        except BaseException as exc:
            with self._lock:
                self._wipe_dek()
                if isinstance(exc, PrivateFSError) and exc.commit_state == "uncertain":
                    self._poisoned = True
            raise

    def _rotate(self, audit: AuditSession, suffix: str) -> None:
        self._wipe_dek()
        result = rotate_audit(audit, suffix)
        protected = frozenset(n for n in (result.raw_name, result.gzip_name) if n is not None)
        sweep_audit_retention(
            audit,
            cutoff_mtime_ns=time.time_ns() - self.retention_days * 86400 * 1_000_000_000,
            protected_names=protected,
        )

    def _append_checked(
        self,
        audit: AuditSession,
        custody: WindowsCustodySession,
        backend: NativeBackend,
        plaintext: bytes,
        incoming: int,
    ) -> None:
        probe = audit.probe(audit.active_name)
        if self._dek is not None and probe.metadata is None:
            self._poisoned = True
            self._wipe_dek()
            raise PrivateFSError("unsafe", "audit_active_missing")
        if self._dek is not None and (
            probe.metadata is None
            or probe.metadata.identity != self._active_identity
            or probe.first_line != self._header_bytes
        ):
            self._wipe_dek()
        today = today_utc_date()
        if probe.metadata is not None:
            # A checked safe file is not necessarily an owned MRAL generation.
            # Refuse copied/unknown selectors before rotation or replacement.
            if probe.kind == "mral" and probe.first_line is not None:
                _header_lease(self.path, probe.first_line, custody)
            elif probe.kind != "ndjson":
                raise mral.AuditLogDecryptError(f"{self.path}: existing audit header is not safely recognized")
            if self._dek is None or self._last_date != today or probe.metadata.size + incoming > self.rotate_bytes:
                self._rotate(audit, self._last_date or today)
        if self._dek is None:
            dek = bytearray(os.urandom(DEK_LEN))
            try:
                wrapped = wrap_dek(
                    bytes(dek), mral.AUDIT_LOG_KEY_ID, backend=backend, native_key_id=self.lease.native_key_id
                )
                header = mral._make_log_header(wrapped, mral.AUDIT_LOG_KEY_ID, self.lease.native_key_id)
                metadata = audit.create(audit.active_name, header + b"\n")
                verified = audit.probe(audit.active_name)
                if verified.metadata != metadata or verified.first_line != header:
                    raise PrivateFSError("unsafe", "audit_header_verification", commit_state="uncertain")
                self._dek = dek
                self._header_bytes = header
                self._aad = mral._entry_aad(header)
                self._active_identity = metadata.identity
            finally:
                if self._dek is not dek:
                    dek[:] = bytes(len(dek))
        self._last_date = today
        assert self._dek is not None and self._active_identity is not None
        token = base64.b64encode(encrypt(bytes(self._dek), plaintext, aad=self._aad)) + b"\n"
        audit.append(audit.active_name, token, expected_identity=self._active_identity)


def decrypt_windows_log_file(
    path: Path,
    *,
    home: Path,
    audit_sink: AuditSink,
    backend: NativeBackend | None = None,
    custody: WindowsCustodySession | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> list[dict[str, Any]]:
    """Snapshot then unlock audit before native unwrap/callbacks, retaining custody.

    No supplied raw bytes can bypass checked snapshots. A nested sink explicitly
    calls ``append_in_custody`` with the caller-owned session. No key is created.
    Custody remains locked until all entries authenticate, excluding role reset.
    """
    path = Path(path)
    with _custody_scope(Path(home), custody, backend) as session:
        with _audit_scope(path, session) as audit:
            snapshot = audit.snapshot(path.name, max_bytes=max_file_bytes)
        if snapshot is None:
            raise FileNotFoundError(path)
        try:
            raw = decode_audit_bytes(snapshot.data, max_output_bytes=max_output_bytes)
        except PrivateFSError:
            raise
        except (OSError, EOFError, zlib.error) as exc:
            raise mral.AuditLogDecryptError(f"{path}: malformed compressed audit log") from exc
        lines = raw.splitlines()
        if not lines:
            raise mral.AuditLogDecryptError(f"{path}: empty audit log file")
        lease, wrapped = _header_lease(path, lines[0], session)
        resolved = session.backend_for(lease)
        dek: bytearray | None = None
        try:
            try:
                dek = bytearray(
                    unwrap_dek(
                        wrapped,
                        mral.AUDIT_LOG_KEY_ID,
                        backend=resolved,
                        native_key_id=lease.native_key_id,
                        audit_sink=audit_sink,
                    )
                )
            except (WrapAuthCancelled, WrapKeyNotFound):
                raise
            except WrapError as exc:
                raise mral.AuditLogDecryptError(f"{path}: cannot unwrap the audit-log DEK") from exc
            return mral._decode_log_entries(path, lines, bytes(dek), mral._entry_aad(lines[0]))
        finally:
            if dek is not None:
                dek[:] = bytes(len(dek))
