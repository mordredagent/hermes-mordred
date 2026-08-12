"""mordred_hermes.keyvault._secret_ops — keyvault secret operations.

Extracted from :mod:`api` (the public facade) to keep that module under the
size guideline. These are the operations on an *initialised* keyvault — as
opposed to provisioning (key generation), which stays in ``api``:

- ``encrypt`` / ``decrypt`` — per-secret MREN envelope encryption.
- ``export_backup`` / ``import_backup`` — whole-keyvault ciphertext-rewrap
  backup manifest.

``api`` re-exports all four, so the public import paths
(``mordred_hermes.keyvault.api.encrypt`` etc.) are unchanged.

This module itself grew past the repo's LOC guideline and was split further
(June sweep PR-6 follow-up). What stays here is the shared foundation used by
every operation — the DEK/envelope-id and backup-manifest wire-format
constants, the MREN envelope helpers, the commit-state helpers
(``_assert_key_committed`` / ``_clear_pending_native_key_after_commit``, also
called directly by ``api.confirm_generate``), ``_ensure_managed_subdir``, and
``encrypt`` / ``decrypt`` themselves. The backup-manifest machinery moved out
into two sibling modules that both depend on these shared helpers:

- ``_backup_export`` — :func:`export_backup` and its preflight/walk helpers.
- ``_backup_import`` — :func:`import_backup`, its manifest-parsing helpers,
  and :func:`_rollback_import` (shared with ``api.confirm_generate``, which
  calls it as ``_secret_ops._rollback_import``).

This module re-exports ``export_backup`` / ``import_backup`` /
``_rollback_import`` from those siblings below so every existing import site
(``api.py``, tests) and monkeypatch target keeps working unchanged. The
siblings reach back into this module for the shared helpers via
function-local imports rather than a top-level one, because a top-level
``from ._backup_export import export_backup`` here paired with a top-level
``from ._secret_ops import _assert_key_committed`` there would form a
``_secret_ops -> _backup_export -> _secret_ops`` load cycle. The same
function-local technique is already used below (and in ``_backup_export`` /
``_backup_import``) to break the pre-existing ``_secret_ops <-> api`` cycle.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import secrets
from pathlib import Path

# `recovery` is not otherwise referenced in this module — `import_backup`
# (which used to call `recovery.import_backup` here) now lives in
# `_backup_import`. The import is kept anyway so `_secret_ops.recovery` stays
# a valid monkeypatch target: tests/test_keyvault_api_backup.py patches
# `_secret_ops.recovery.import_backup`, and mutating that shared module
# object also affects `_backup_import`'s own `recovery.import_backup(...)`
# call, since both are the same object in `sys.modules`.
from . import (
    _native_key_id,
    _storage,
    crypto,
    recovery,  # noqa: F401
    wrap,
)
from ._backup_export import export_backup

# `_rollback_import` is not called from this module either — it is called
# directly by `api.confirm_generate` as `_secret_ops._rollback_import` (and
# internally by `_backup_import.import_backup`). `as _rollback_import` is the
# redundant-alias form mypy's `no_implicit_reexport` (implied by --strict)
# recognizes as an explicit re-export for a leading-underscore name that
# `__all__` would otherwise not cover.
from ._backup_import import _rollback_import as _rollback_import
from ._backup_import import import_backup
from ._envelope_codec import _encode_envelope, _hash_id, _parse_envelope
from .wrap import AuditSink, NativeBackend

__all__ = [
    "decrypt",
    "encrypt",
    "export_backup",
    "import_backup",
]

# ----------------------------- DEK / envelope-id constants -----------------------------
# The MREN wire-format constants (magic, version, field widths, AAD/header
# lengths, nonce/tag sizes) live in ``_envelope_codec``. These two stay here
# because ``encrypt`` / ``_new_envelope_id`` own them, not the codec.

_DEK_LEN = 32
_ENVELOPE_ID_RAND_BYTES = 16

# ----------------------------- backup manifest constants (step-E) -----------------------------
# Frozen in SPEC.md §"export_backup / import_backup (ciphertext-rewrap
# manifest)". The portable manifest AAD deliberately OMITS the per-device
# MRKW wrapped-DEK prefix that the MREN envelope AAD carries — that prefix
# changes on every machine, so a manifest entry decrypted on the import
# device could never reconstruct it. ``manifest_aad`` instead binds only
# fields that are recomputable from ``(key_id, purpose_hash)``, so a
# tampered manifest ``key_id`` / ``purpose_hash_hex`` flips the GCM tag.
#
# Defined here (rather than in ``_backup_export`` / ``_backup_import``)
# because both siblings need at least one of these constants — keeping a
# single definition avoids duplicating them across that pair.
_MANIFEST_MAGIC = b"MRMN"
_MANIFEST_VERSION = 1
_MANIFEST_ENTRY_FIELDS = (
    "purpose_hash_hex",
    "envelope_id",
    "dek_hex",
    "manifest_aes_blob_b64",
)
_MANIFEST_ROOT_FIELDS = frozenset({"version", "key_id", "envelopes"})

_LOG = logging.getLogger("mordred.keyvault.secret_ops")


# ----------------------------- MREN envelope helpers (step-C) -----------------------------


def _validate_purpose(purpose: str) -> None:
    """Reject any purpose string that could escape the storage layout or
    appear inside an audit log as a control sequence.

    Allowed: alphanumeric, dash, underscore, dot (but not the bare
    relative-path components ``"."`` / ``".."``). Rejected: empty string,
    path separators (``/`` / ``\\``), control characters (``\\x00``-``\\x1f``
    / ``\\x7f``), and the relative-path components ``"."`` / ``".."``.
    """
    if not purpose:
        raise ValueError("purpose must not be empty")
    if purpose in {".", ".."}:
        raise ValueError("purpose must not be a relative-path component")
    if "/" in purpose or "\\" in purpose:
        raise ValueError("purpose must not contain path separators")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in purpose):
        raise ValueError("purpose must not contain control characters")


def _new_envelope_id() -> str:
    """Return a URL-safe base64 string of 16 random bytes (22 chars, no padding)."""
    raw = secrets.token_bytes(_ENVELOPE_ID_RAND_BYTES)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Exactly 22 URL-safe-base64 chars (alphabet ``[A-Za-z0-9_-]``, no padding).
# Matches the output of :func:`_new_envelope_id` and rejects any caller-supplied
# value containing path separators, traversal sequences, or wrong length.
_ENVELOPE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _validate_envelope_id(envelope_id: str) -> None:
    """Reject ``envelope_id`` values that could escape the managed storage path.

    Codex pre-merge P1: ``envelope_id`` was appended verbatim into the
    filesystem path. A caller supplying ``"../something"`` or ``"a/b"``
    would make :func:`decrypt` open a ``.gcm`` file outside the keyvault
    tree. Rejecting anything that does not match the exact format
    produced by :func:`_new_envelope_id` is the simplest correct fix.
    """
    if not _ENVELOPE_ID_RE.match(envelope_id):
        raise ValueError("invalid envelope_id: must be 22 URL-safe-base64 characters (no padding)")


def _envelope_path_for(root: Path, key_id: str, purpose: str, envelope_id: str) -> Path:
    """Construct the on-disk path for an MREN envelope."""
    return root / "ciphertexts" / _hash_id(key_id).hex() / _hash_id(purpose).hex() / f"{envelope_id}.gcm"


def _committed_native_key_from_meta(
    root: Path,
    meta: dict[str, object],
    key_id: str,
    key_id_hash_hex: str,
) -> str:
    """Validate the v1 key row and digest, ignoring provisioning state."""

    try:
        expected_key_id_hash_hex = _hash_id(key_id).hex()
    except UnicodeEncodeError:
        raise _storage.KeyvaultCorruptError("encryption key metadata has an invalid logical key id") from None
    if key_id_hash_hex != expected_key_id_hash_hex:
        # ``key_id_hash_hex`` may originate in the meta.json object key. Do
        # not use it as a path component until it is proven to be the exact
        # canonical hash of the row's logical key id.
        raise _storage.KeyvaultCorruptError("encryption key metadata hash does not match its logical key id")

    keys = meta["keys"]
    if not isinstance(keys, dict):
        raise _storage.KeyvaultCorruptError("keyvault metadata keys field is malformed")
    row = keys.get(key_id_hash_hex)
    if len(keys) != 1 or not isinstance(row, dict) or row.get("key_id") != key_id:
        raise _storage.KeyvaultCorruptError("encryption key is not the single committed key in meta.json")

    digests_dir = root / "digests"
    try:
        # ``safe_read`` protects only the final component. Validate the
        # intermediate directory before constructing/reading the commit path
        # so a symlink cannot redirect a canonical hash outside the vault.
        _storage._check_dir_mode(digests_dir)
    except OSError as exc:
        raise _storage.KeyvaultCorruptError("keyvault digest directory is missing or unsafe") from exc
    commit_path = digests_dir / f"{key_id_hash_hex}.commit"
    try:
        verification_digest = _storage.safe_read(commit_path)
    except FileNotFoundError:
        raise _storage.KeyvaultCorruptError(
            "encryption key metadata exists but its verification digest commit is missing"
        ) from None
    if len(verification_digest) != 32:
        raise _storage.KeyvaultCorruptError("encryption key verification digest commit must be exactly 32 bytes")
    try:
        return _native_key_id.native_key_id_from_row(root, key_id, row)
    except _native_key_id.NativeKeyIdMismatch as exc:
        raise _storage.KeyvaultCorruptError(str(exc)) from None


def _assert_key_committed(root: Path, key_id: str, key_id_hash_hex: str) -> str:
    """Require a fully-finalized v1 key row and digest commit.

    A native backend key alone is provisional: ``confirm_generate`` and
    ``import_backup`` create it before committing filesystem state, and may
    still roll it back.  The first metadata commit deliberately retains
    ``pending_native_key`` beside the row, so even a post-rename fsync failure
    stays unusable until a separate durable save clears that journal.
    """

    meta = _storage.load_meta(root)
    if _native_key_id.PENDING_NATIVE_KEY_FIELD in meta:
        raise _storage.KeyvaultCorruptError("native-key provisioning is incomplete; reset is required")
    return _committed_native_key_from_meta(root, meta, key_id, key_id_hash_hex)


def _clear_pending_native_key_after_commit(
    root: Path,
    *,
    key_id: str,
    key_id_hash_hex: str,
    native_key_id: str,
) -> None:
    """Finalize a durably-owned main key without rolling it back on cleanup.

    The caller has already durably saved ``row + pending_native_key``.  This
    second save removes only the journal. If it raises after ``os.replace``,
    the visible no-pending row is safe to use: the prior row+pending state was
    durable, so a crash can at worst restore that fail-closed state. If the
    pending marker is still visible, the original error propagates and normal
    operations reject the incomplete provisioning.
    """

    meta = _storage.load_meta(root)
    try:
        pending = _native_key_id.pending_native_key_from_meta(root, meta)
    except _native_key_id.NativeKeyIdMismatch as exc:
        raise _storage.KeyvaultCorruptError(str(exc)) from None
    if pending != (key_id, native_key_id):
        raise _storage.KeyvaultCorruptError("native-key pending journal does not match the committed key")
    if _committed_native_key_from_meta(root, meta, key_id, key_id_hash_hex) != native_key_id:
        raise _storage.KeyvaultCorruptError("native-key ownership row does not match its pending journal")

    meta.pop(_native_key_id.PENDING_NATIVE_KEY_FIELD)
    try:
        _storage.save_meta(root, meta)
    except BaseException as exc:
        try:
            visible_native_key_id = _assert_key_committed(root, key_id, key_id_hash_hex)
        except Exception as visible_exc:
            exc.add_note(f"pending-key cleanup did not reach a committed visible state: {visible_exc}")
            raise exc from visible_exc
        if visible_native_key_id != native_key_id:
            exc.add_note("pending-key cleanup exposed a different native key")
            raise exc
        if not isinstance(exc, Exception):
            raise exc
        _LOG.warning(
            "meta.json pending-key cleanup reported %s after publishing a valid committed row; continuing",
            type(exc).__name__,
        )


def encrypt(
    key_id: str,
    plaintext: bytes,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Encrypt ``plaintext`` under a fresh per-call DEK; return ``envelope_id``.

    The DEK is wrapped offline via :func:`mordred_hermes.keyvault.wrap.wrap_dek`
    (no biometric prompt, no audit emit). The resulting envelope is persisted
    to ``<keyvault>/ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``
    via the step-B atomic-write helpers under ``keyvault_lock``.
    Returns the URL-safe-base64 ``envelope_id`` (22 chars, no padding).

    ``audit_sink`` is accepted so this surface matches the rest of the
    api.py contract; codex OD-3 specifies that ``encrypt`` does NOT emit
    audit entries at this layer (no authorization gate, and the wrap
    layer never emits on the wrap path).
    """
    del audit_sink  # documented no-op for encrypt; reserved for symmetry with decrypt
    _validate_purpose(purpose)
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)

    key_id_hash_hex = _hash_id(key_id).hex()
    purpose_hash_hex = _hash_id(purpose).hex()
    key_dir = root / "ciphertexts" / key_id_hash_hex
    purpose_dir = key_dir / purpose_hash_hex

    # The metadata check, native-key lookup/wrap, envelope construction, and
    # publication form one transaction. Provisioning creates a native key
    # before its meta/commit point and may roll it back; wrapping outside this
    # lock could otherwise build an envelope with that transient key, wait for
    # rollback, and then publish permanently undecryptable ciphertext.
    with _storage.keyvault_lock(root):
        native_key_id = _assert_key_committed(root, key_id, key_id_hash_hex)
        operation_backend = _native_key_id.backend_for_persisted_key(
            backend,
            root,
            key_id,
            native_key_id,
        )

        dek = secrets.token_bytes(_DEK_LEN)
        try:
            wrapped_dek_blob = wrap.wrap_dek(
                dek,
                key_id,
                backend=operation_backend,
                native_key_id=native_key_id,
            )
            envelope = _encode_envelope(dek, plaintext, key_id, purpose, wrapped_dek_blob)
        finally:
            # Best-effort wipe — Python bytes are immutable so we cannot zero
            # them in place; leaving the reference unbound lets the GC reclaim
            # sooner than a function-level local would.
            del dek

        envelope_id = _new_envelope_id()
        envelope_path = purpose_dir / f"{envelope_id}.gcm"

        # Validate any pre-existing directory before writing inside it: an
        # attacker who pre-creates key_dir/purpose_dir as a symlink (or with a
        # loose mode) is rejected rather than written through (codex pre-merge
        # P2-1). Shared with the backup/restore path via _ensure_managed_subdir.
        _ensure_managed_subdir(key_dir)
        _ensure_managed_subdir(purpose_dir)
        _storage.atomic_write(envelope_path, envelope)

    return envelope_id


def decrypt(
    key_id: str,
    envelope_id: str,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    """Decrypt an MREN envelope and return the plaintext.

    Reads ``ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``;
    rejects mismatched ``key_id_hash`` or ``purpose_hash`` with
    :exc:`WrapParseError` *before* calling
    :func:`mordred_hermes.keyvault.wrap.unwrap_dek` so a cross-purpose
    replay attempt does not spend a biometric prompt (codex HIGH #2).

    On purpose match the wrap layer is invoked, which may prompt the user
    for biometric authorization and emits exactly one
    ``keyvault.unwrap_authorized`` or ``keyvault.unwrap_denied`` audit
    entry via the supplied ``audit_sink``. ``decrypt`` does NOT
    double-emit at the api layer (codex OD-3).
    """
    _validate_purpose(purpose)
    _validate_envelope_id(envelope_id)
    root = _storage.resolve_keyvault_dir(home)
    envelope_path = _envelope_path_for(root, key_id, purpose, envelope_id)

    # codex second-pass P2-B: O_NOFOLLOW in safe_read only protects the
    # final .gcm component. Refuse symlinked intermediate dirs (key_dir /
    # purpose_dir) explicitly so an attacker who has swapped one of them
    # for a symlink cannot redirect the read into attacker territory.
    # Each existing dir must also be mode 0o700.
    key_dir = envelope_path.parent.parent
    purpose_dir = envelope_path.parent
    with _storage.keyvault_lock(root):
        if key_dir.exists() or key_dir.is_symlink():
            _storage._check_dir_mode(key_dir)
        if purpose_dir.exists() or purpose_dir.is_symlink():
            _storage._check_dir_mode(purpose_dir)

        blob = _storage.safe_read(envelope_path)
        aad, wrapped_dek_blob, aes_blob = _parse_envelope(blob, key_id, purpose)
        key_id_hash_hex = _hash_id(key_id).hex()
        native_key_id = _assert_key_committed(root, key_id, key_id_hash_hex)
        operation_backend = _native_key_id.backend_for_persisted_key(
            backend,
            root,
            key_id,
            native_key_id,
        )
        dek = wrap.unwrap_dek(
            wrapped_dek_blob,
            key_id,
            audit_sink=audit_sink,
            backend=operation_backend,
            native_key_id=native_key_id,
        )
        try:
            # Keep the lifecycle lock through AEAD authentication so reset
            # cannot delete the selected physical key or metadata halfway
            # through this logical decrypt transaction.
            return crypto.decrypt(dek, aes_blob, aad=aad)
        finally:
            del dek


def _ensure_managed_subdir(path: Path) -> None:
    """Create ``path`` at mode ``0o700``, or validate it if it exists.

    The shared per-directory guard applied before writing inside a managed
    keyvault subdir — by :func:`encrypt` (envelope writes) and the
    backup/restore path (``_backup_import._rebuild_envelope``): an attacker
    who pre-creates the directory as a symlink (or with a loose mode) is
    rejected rather than silently written through.

    ``_storage._check_dir_mode`` is intentionally consumed across the
    ``_secret_ops`` / ``_storage`` boundary inside the same
    ``mordred_hermes.keyvault`` package — the underscore prefix signals
    "package-internal", not "module-internal".
    """
    if path.exists() or path.is_symlink():
        _storage._check_dir_mode(path)
    else:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
