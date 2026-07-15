"""mordred_keyvault.log_encryption — AES-GCM encryption layer for the audit log.

Phase 4 PR6. SPEC.md §Audit log policy / §Audit-log encryption coupling +
PLAN.md L549-555.

:class:`EncryptedWriter` is an AES-GCM-encrypting implementation of the
Phase 1 ``Writer`` Protocol frozen in
:mod:`mordred_hermes.privacy_check.audit`. At Phase 4 launch the audit
factory swaps it in for :class:`~mordred_hermes.privacy_check.audit.NDJSONWriter`
so new audit entries are encrypted at rest. Pre-Phase-4 plaintext logs are
NOT retroactively encrypted (``hermes mordred audit purge`` handles them);
an :class:`EncryptedWriter` that finds a foreign file at its path rotates
it aside rather than corrupt or overwrite it.

Wire format (``MRAL`` v1 — frozen here)::

    line 0  header   {"fmt":"MRAL","ver":1,"key_id":<str>,"wdek":<base64>}
    line 1+ entry    base64( nonce(12) ‖ AES-GCM-ciphertext ‖ tag(16) )

- ``wdek`` is the audit-log DEK wrapped by :func:`mordred_keyvault.wrap.wrap_dek`
  — a 127-byte ``MRKW`` blob. Only the *wrapped* DEK touches disk; the
  plaintext 32-byte DEK lives in process memory for the writer's lifetime
  and is dropped on :meth:`EncryptedWriter.close`.
- Each entry is encrypted independently and written as one base64 line, so
  a single :meth:`~EncryptedWriter.append` stays whole-entry atomic (Writer
  Protocol invariant #2) and the file never needs a whole-file rewrite.
- The per-entry AES-GCM AAD binds every entry to its file header
  (``MAGIC ‖ version ‖ SHA-256(header_line)``). An entry lifted from
  another file — or replayed after the header is edited — fails the GCM
  tag check.

Atomicity note: an encrypted+base64 line for a max-size (4000-byte)
plaintext entry is ~5.4 KiB, above POSIX ``PIPE_BUF`` (4096). The
``O_APPEND`` atomic-append guarantee therefore does NOT hold for
concurrent *multi-process* writers — but multi-process audit writing is
already unsupported in v1 (TODO.md §1.1 M1). Within one process the
single-writer :class:`threading.Lock` serializes every ``append`` and one
``os.write`` call delivers the whole line, so invariant #2 holds.

The DEK is unwrapped through the Secure Enclave authorization boundary
(:func:`mordred_keyvault.wrap.unwrap_dek`) only on the *read* side
(:func:`decrypt_log_file`), which the ``hermes mordred audit decrypt`` CLI
(PR8) drives. Writing never authorizes: :func:`~mordred_keyvault.wrap.wrap_dek`
is an offline operation against the Enclave's public key.

This module imports :mod:`cryptography` (via ``.crypto`` / ``.wrap``) and
so, like its keyvault crypto siblings, is only importable where the
``[macos]`` extra is installed.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import hashlib
import json
import logging
import os
import shutil
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cryptography.exceptions import InvalidTag

from .._log_rotation import next_rotation_target
from .._log_rotation import sweep_retention as _sweep_retention
from .._log_rotation import today_utc_date as _today_utc_date
from .._log_rotation import utcnow_iso as _utcnow_iso
from ._exceptions import WrapAuthCancelled, WrapError, WrapKeyNotFound
from .crypto import decrypt as _aes_decrypt
from .crypto import encrypt as _aes_encrypt
from .wrap import DEK_LEN, AuditSink, NativeBackend, unwrap_dek, wrap_dek

if TYPE_CHECKING:  # pragma: no cover - type-only conformance check
    from mordred_hermes.privacy_check.audit import Writer as _Writer

_LOG = logging.getLogger("mordred.keyvault.log_encryption")

MAGIC: Final = b"MRAL"
"""File-format magic — Mordred Audit Log (encrypted)."""

FORMAT_VERSION: Final = 1
"""``MRAL`` wire-format version. Bump only on a breaking layout change."""

AUDIT_LOG_KEY_ID: Final = "mordred.audit-log"
"""Keychain key id of the Secure-Enclave wrapping key for the audit-log DEK."""

# Cap on the *plaintext* entry, matching NDJSONWriter so callers see one
# uniform limit regardless of which writer the factory installs. (The
# encrypted on-disk line is larger; see the module docstring atomicity note.)
MAX_ENTRY_BYTES: Final = 4000

DEFAULT_ROTATE_BYTES: Final = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS: Final = 30

_GZIP_MAGIC: Final = b"\x1f\x8b"


class AuditLogDecryptError(Exception):
    """The encrypted audit log could not be read.

    Raised by :func:`decrypt_log_file` for every structural / integrity
    failure: a missing or malformed ``MRAL`` header, a non-encrypted
    (legacy plaintext) file, an empty file, a base64 / JSON decode
    failure, a wrapped-DEK that fails to unwrap for a non-authorization
    reason, or a per-entry AES-GCM tag check failure (tampered or
    cross-file-spliced line).

    Two wrap-layer exceptions deliberately propagate *unwrapped* instead
    because the caller (the ``audit decrypt`` CLI) must react differently:

    - :class:`~mordred_hermes.keyvault._exceptions.WrapAuthCancelled` —
      the user denied the Secure Enclave biometric / passcode prompt.
    - :class:`~mordred_hermes.keyvault._exceptions.WrapKeyNotFound` — the
      audit-log wrapping key is gone (different device, or revoked); the
      log is unrecoverable, not corrupt.
    """


def _serialize(entry: Mapping[str, Any]) -> bytes:
    """Serialize an audit entry to compact UTF-8 JSON (no trailing newline).

    ``sort_keys=True`` keeps the plaintext deterministic, which makes the
    test fixtures' fixed expectations stable. Raises :class:`ValueError`
    if the entry exceeds :data:`MAX_ENTRY_BYTES`.
    """
    data = json.dumps(entry, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"audit entry exceeds {MAX_ENTRY_BYTES} bytes (got {len(data)})")
    return data


def _entry_aad(header_bytes: bytes) -> bytes:
    """Derive the per-entry AES-GCM AAD that binds entries to *header_bytes*.

    ``MAGIC ‖ version ‖ SHA-256(header_line)``. The header line carries the
    file's unique random ``wdek``, so the digest differs per file: an entry
    encrypted under file A's AAD fails the tag check when spliced into
    file B, and editing the header invalidates every entry below it.
    """
    return MAGIC + bytes([FORMAT_VERSION]) + hashlib.sha256(header_bytes).digest()


def _encrypted_line_len(plaintext_len: int) -> int:
    """On-disk byte length of the base64 entry line for a plaintext of *plaintext_len*.

    ``crypto.encrypt`` prepends a 12-byte nonce and AES-GCM appends a
    16-byte tag; base64 expands by 4/3 (rounded up to a 4-char group).
    The trailing newline adds one byte. Used by the size-cap rotation
    check before the entry is actually encrypted.
    """
    enc_len = 12 + plaintext_len + 16
    b64_len = ((enc_len + 2) // 3) * 4
    return b64_len + 1


class EncryptedWriter:
    """AES-GCM-encrypting audit-log writer (Phase 1 ``Writer`` Protocol).

    One instance owns one active log file for its lifetime. Because the
    DEK is unwrappable only through an Enclave authorization prompt, an
    :class:`EncryptedWriter` cannot resume appending to an encrypted file
    written by an earlier process — on its first :meth:`append` it rotates
    any pre-existing file aside and starts a fresh file with a fresh DEK.
    Date-change and size-cap rotations during the writer's lifetime each
    likewise start a new file with a new DEK + header.

    Multi-process writes are unsupported (v1) — the :class:`threading.Lock`
    serializes only threads of one process.
    """

    def __init__(
        self,
        path: Path,
        *,
        backend: NativeBackend,
        key_id: str = AUDIT_LOG_KEY_ID,
        rotate_bytes: int = DEFAULT_ROTATE_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self.path = path
        self.backend = backend
        self.key_id = key_id
        self.rotate_bytes = rotate_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._last_date = ""
        # ``None`` => no active encrypted file yet (lazy: created on first
        # append and after each rotation). The plaintext DEK lives here for
        # the active file's lifetime; the wrapped form is on disk.
        self._dek: bytearray | None = None
        self._aad = b""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, entry: Mapping[str, Any]) -> None:
        """Encrypt one audit entry and append it as a single base64 line.

        Injects a millisecond-precision ``ts`` if the caller did not
        supply one (Writer Protocol invariant #1).
        """
        merged: dict[str, Any] = {"ts": _utcnow_iso(), **dict(entry)}
        plaintext = _serialize(merged)
        incoming = _encrypted_line_len(len(plaintext))

        with self._lock:
            self._maybe_rotate(incoming)
            dek, aad = self._active()
            token = base64.b64encode(_aes_encrypt(dek, plaintext, aad=aad))
            fd = os.open(str(self.path), os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, token + b"\n")
            finally:
                os.close(fd)

    def close(self) -> None:
        """Zero and drop the in-memory DEK.

        The DEK's authoritative buffer is a ``bytearray`` (see :meth:`_active`),
        so it is wiped in place here rather than merely dereferenced — better
        than leaving the long-lived audit-log key for the GC. Note this cannot
        be a total heap scrub: :meth:`_active` hands callers an immutable
        ``bytes`` snapshot per append and AES-GCM copies the key into OpenSSL,
        and those transient copies live until GC — wiping the ``bytearray``
        bounds the key's lifetime, it does not erase every copy. Kept for the
        ``Writer`` Protocol contract — each ``append`` already opens and closes
        its own fd.
        """
        with self._lock:
            self._wipe_dek()

    def _wipe_dek(self) -> None:
        """Zero the DEK buffer in place (it is a ``bytearray``), then drop it.

        Caller must hold ``self._lock``. Mirrors ``kek.MasterKey``'s wipe so the
        DEK's authoritative buffer is zeroed, not just dereferenced (transient
        ``bytes``/OpenSSL copies are inherent and out of scope — see
        :meth:`close`).
        """
        if self._dek is not None:
            self._dek[:] = bytes(len(self._dek))
        self._dek = None
        self._aad = b""

    # -- internals ---------------------------------------------------------

    def _active(self) -> tuple[bytes, bytes]:
        """Return ``(dek, aad)`` for the active file, creating it if needed.

        When no active file exists, any pre-existing file at ``path`` —
        a legacy plaintext NDJSON log, or an encrypted file from a prior
        process whose DEK this writer cannot unwrap without a prompt — is
        rotated aside first so it is preserved, not clobbered.
        """
        if self._dek is not None:
            return bytes(self._dek), self._aad

        if self.path.exists():
            self._rotate(_today_utc_date())

        dek = bytearray(os.urandom(DEK_LEN))
        wrapped = wrap_dek(bytes(dek), self.key_id, backend=self.backend)
        header = {
            "fmt": MAGIC.decode("ascii"),
            "ver": FORMAT_VERSION,
            "key_id": self.key_id,
            "wdek": base64.b64encode(wrapped).decode("ascii"),
        }
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        aad = _entry_aad(header_bytes)

        # O_EXCL: the file must not exist — _rotate above moved any prior
        # file aside, so a survivor here means a concurrent writer, which
        # v1 does not support. Fail loudly rather than interleave.
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, header_bytes + b"\n")
        finally:
            os.close(fd)

        self._dek = dek
        self._aad = aad
        return bytes(dek), aad

    def _maybe_rotate(self, incoming_bytes: int) -> None:
        """Rotate the active file on a UTC date change or a size-cap breach.

        Only an *active* file (``_dek is not None``) is rotated here; a
        foreign / stale file is left for :meth:`_active` to rotate aside.
        A rotation clears ``_dek`` so the next :meth:`_active` mints a
        fresh file, DEK and header.
        """
        today = _today_utc_date()
        if self._last_date and self._last_date != today and self._dek is not None and self.path.exists():
            self._rotate(self._last_date)
            self._wipe_dek()
        elif (
            self._dek is not None
            and self.path.exists()
            and self.path.stat().st_size + incoming_bytes > self.rotate_bytes
        ):
            self._rotate(today)
            self._wipe_dek()
        self._last_date = today

    def _rotate(self, date_suffix: str) -> None:
        """Rename the active file to ``<name>.<date>[.N]`` and gzip it.

        Mirrors :class:`mordred_hermes.privacy_check.audit.NDJSONWriter`'s
        rotation: same-day collisions get an ``.N`` suffix; a gzip failure
        keeps the un-gzipped rotated file rather than losing data.
        """
        if not self.path.exists():
            return

        target = next_rotation_target(self.path, date_suffix)
        os.replace(self.path, target)

        gz_target = target.with_suffix(target.suffix + ".gz")
        try:
            with target.open("rb") as src, gzip.open(gz_target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            target.unlink()
        except Exception as e:
            _LOG.warning("audit gzip rotation failed; raw rotated file kept at %s: %s", target, e)
            with contextlib.suppress(OSError):
                gz_target.unlink()
        else:
            with contextlib.suppress(OSError):
                os.chmod(gz_target, 0o600)

        _sweep_retention(self.path, self.retention_days)


def _unwrap_log_dek(
    path: Path,
    header_bytes: bytes,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> bytes:
    """Validate the ``MRAL`` header line and unwrap the audit-log DEK.

    Raises:
        AuditLogDecryptError: The header line is not valid JSON, is not a
            recognised ``MRAL`` header, is missing the ``key_id`` / ``wdek``
            fields, or carries an unwrappable DEK.
        WrapAuthCancelled / WrapKeyNotFound: Propagated from the unwrap so
            the CLI can handle a denied prompt and a missing key distinctly
            from a corrupt file.
    """
    try:
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise AuditLogDecryptError(f"{path}: header line is not valid JSON") from e
    if (
        not isinstance(header, dict)
        or header.get("fmt") != MAGIC.decode("ascii")
        or header.get("ver") != FORMAT_VERSION
    ):
        raise AuditLogDecryptError(
            f"{path}: not a {MAGIC.decode('ascii')} v{FORMAT_VERSION} encrypted audit log "
            "(a pre-Phase-4 plaintext log is read with `audit tail`, not `audit decrypt`)"
        )
    key_id = header.get("key_id")
    wdek_b64 = header.get("wdek")
    if not isinstance(key_id, str) or not isinstance(wdek_b64, str):
        raise AuditLogDecryptError(f"{path}: header is missing the key_id / wdek fields")
    try:
        wrapped = base64.b64decode(wdek_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise AuditLogDecryptError(f"{path}: header wdek is not valid base64") from e

    try:
        return unwrap_dek(wrapped, key_id, audit_sink=audit_sink, backend=backend)
    except (WrapAuthCancelled, WrapKeyNotFound):
        # Propagate unwrapped — the CLI handles a denied prompt and a
        # missing key distinctly from a corrupt file.
        raise
    except WrapError as e:
        raise AuditLogDecryptError(f"{path}: cannot unwrap the audit-log DEK") from e


def _decode_log_entries(
    path: Path,
    lines: list[bytes],
    dek: bytes,
    aad: bytes,
) -> list[dict[str, Any]]:
    """Decode every entry line (oldest first) under the unwrapped DEK.

    ``lines`` is the whole file split on newlines; the header (``lines[0]``)
    is skipped. Raises :class:`AuditLogDecryptError` on any entry that fails
    to base64-decode, authenticate, or parse as a JSON object.
    """
    out: list[dict[str, Any]] = []
    for n, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        try:
            blob = base64.b64decode(line, validate=True)
        except (binascii.Error, ValueError) as e:
            raise AuditLogDecryptError(f"{path}: line {n} is not valid base64") from e
        try:
            plaintext = _aes_decrypt(dek, blob, aad=aad)
        except InvalidTag as e:
            raise AuditLogDecryptError(
                f"{path}: line {n} failed authentication — tampered, truncated, or spliced from another file"
            ) from e
        try:
            entry = json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise AuditLogDecryptError(f"{path}: line {n} decrypted to invalid JSON") from e
        if not isinstance(entry, dict):
            raise AuditLogDecryptError(f"{path}: line {n} decrypted to a non-object JSON value")
        out.append(entry)
    return out


def decrypt_log_file(
    path: Path,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> list[dict[str, Any]]:
    """Decrypt one ``MRAL`` audit-log file and return its entries in order.

    Transparently decompresses a gzip-rotated file. Unwraps the audit-log
    DEK through :func:`mordred_keyvault.wrap.unwrap_dek` — the Secure
    Enclave authorization boundary — which emits a
    ``keyvault.unwrap_authorized`` audit entry through *audit_sink* on
    success (or ``keyvault.unwrap_denied`` on a denied prompt).

    Args:
        path: The ``audit.log`` (or rotated ``audit.log.<date>.gz``) file.
        backend: Secure-Enclave backend for the DEK unwrap.
        audit_sink: Sink the wrap layer records the unwrap decision into.

    Returns:
        The decrypted audit entries, oldest first.

    Raises:
        AuditLogDecryptError: The file is not a valid ``MRAL`` log, is
            empty, or any header / entry failed to decode or authenticate.
        WrapAuthCancelled: The user denied the Enclave prompt.
        WrapKeyNotFound: The audit-log wrapping key is missing.
    """
    raw = Path(path).read_bytes()
    if raw[:2] == _GZIP_MAGIC:
        raw = gzip.decompress(raw)

    lines = raw.splitlines()
    if not lines:
        raise AuditLogDecryptError(f"{path}: empty audit log file")

    header_bytes = lines[0]
    dek = _unwrap_log_dek(path, header_bytes, backend=backend, audit_sink=audit_sink)
    aad = _entry_aad(header_bytes)
    return _decode_log_entries(path, lines, dek, aad)


if TYPE_CHECKING:  # pragma: no cover - mypy-only Writer Protocol conformance

    def _conformance(w: EncryptedWriter) -> _Writer:
        """Fail mypy if EncryptedWriter drifts from the frozen Writer surface."""
        return w
