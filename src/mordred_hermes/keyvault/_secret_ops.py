"""mordred_hermes.keyvault._secret_ops — keyvault secret operations.

Extracted from :mod:`api` (the public facade) to keep that module under the
size guideline. These are the operations on an *initialised* keyvault — as
opposed to provisioning (key generation), which stays in ``api``:

- ``encrypt`` / ``decrypt`` — per-secret MREN envelope encryption.
- ``export_backup`` / ``import_backup`` — whole-keyvault ciphertext-rewrap
  backup manifest.

``api`` re-exports all four, so the public import paths
(``mordred_hermes.keyvault.api.encrypt`` etc.) are unchanged.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidTag

from . import _native_key_id, _storage, backup, crypto, recovery, wrap
from ._envelope_codec import (
    _encode_envelope,
    _encode_envelope_from_hashes,
    _hash_id,
    _parse_envelope,
    _split_envelope,
)
from .backup import BackupCorrupt, BackupImportConflict
from .digest import VerificationDigestMismatch, compute_digest
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


# ----------------------------- backup / restore (step-E) -----------------------------


def _ensure_managed_subdir(path: Path) -> None:
    """Create ``path`` at mode ``0o700``, or validate it if it exists.

    The shared per-directory guard applied before writing inside a managed
    keyvault subdir — by :func:`encrypt` (envelope writes) and the
    backup/restore path: an attacker who pre-creates the directory as a
    symlink (or with a loose mode) is rejected rather than silently written
    through.

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


def _portable_backup_entry(
    gcm_path: Path,
    *,
    key_id: str,
    native_key_id: str,
    key_id_hash: bytes,
    seed_purpose_hash: bytes,
    inspect_seed: bool,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> tuple[dict[str, str], str | None]:
    """Authenticate one envelope and build its portable manifest entry."""
    try:
        _storage._check_dir_mode(gcm_path.parent)
        blob = _storage.safe_read(gcm_path)
        aad, purpose_hash, wrapped_dek_blob, aes_blob = _split_envelope(blob, key_id_hash)
        if inspect_seed and not hmac.compare_digest(purpose_hash, seed_purpose_hash):
            raise BackupCorrupt("recovery-seed directory contains an envelope for a different purpose")
        dek = wrap.unwrap_dek(
            wrapped_dek_blob,
            key_id,
            audit_sink=audit_sink,
            backend=backend,
            native_key_id=native_key_id,
        )
        try:
            plaintext = crypto.decrypt(dek, aes_blob, aad=aad)
            try:
                stored_seed: str | None = None
                if inspect_seed:
                    with contextlib.suppress(UnicodeDecodeError):
                        stored_seed = plaintext.decode("utf-8")
                manifest_aad = _MANIFEST_MAGIC + key_id_hash + purpose_hash
                manifest_aes_blob = crypto.encrypt(dek, plaintext, aad=manifest_aad)
                entry = {
                    "purpose_hash_hex": purpose_hash.hex(),
                    "envelope_id": gcm_path.stem,
                    "dek_hex": dek.hex(),
                    "manifest_aes_blob_b64": base64.b64encode(manifest_aes_blob).decode("ascii"),
                }
                return entry, stored_seed
            finally:
                del plaintext
        finally:
            del dek
    except Exception as exc:
        # One bad envelope fails the whole export by design (the manifest
        # must be complete), but a bare integrity error names no file.
        exc.add_note(f"while exporting envelope {gcm_path}")
        raise


def _verify_stored_seed_for_export(
    *,
    cipher_root: Path,
    key_id: str,
    native_key_id: str,
    key_id_hash: bytes,
    seed_purpose_hash: bytes,
    normalized_passphrase: str,
    verification_digest: bytes,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> dict[Path, dict[str, str]]:
    """Verify an omitted export passphrase from the known recovery-seed purpose.

    Returns portable entries already built during the preflight so the matching
    seed does not need a second biometric unwrap during the full walk.
    """
    seed_dir = cipher_root / seed_purpose_hash.hex()
    if not (seed_dir.exists() or seed_dir.is_symlink()):
        raise ValueError(
            "backup export requires seed_phrase and pow_bytes for a paper-only vault "
            "(no stored recovery seed was available to verify the passphrase)"
        )
    _storage._check_dir_mode(seed_dir)
    seed_paths = sorted(seed_dir.glob("*.gcm"))
    if not seed_paths:
        raise ValueError(
            "backup export requires seed_phrase and pow_bytes for a paper-only vault "
            "(no stored recovery seed was available to verify the passphrase)"
        )

    from . import pow as keyvault_pow
    from .api import _normalize_seed_phrase

    preflight_entries: dict[Path, dict[str, str]] = {}
    saw_usable_seed = False
    for seed_path in seed_paths:
        entry, stored_seed = _portable_backup_entry(
            seed_path,
            key_id=key_id,
            native_key_id=native_key_id,
            key_id_hash=key_id_hash,
            seed_purpose_hash=seed_purpose_hash,
            inspect_seed=True,
            backend=backend,
            audit_sink=audit_sink,
        )
        preflight_entries[seed_path] = entry
        if stored_seed is None:
            continue
        saw_usable_seed = True
        normalized_seed = _normalize_seed_phrase(stored_seed)
        stored_pow = keyvault_pow.compute_pow(
            normalized_seed,
            difficulty_bits=keyvault_pow.POW_DIFFICULTY_BITS,
        )
        candidate = compute_digest(normalized_seed, normalized_passphrase, stored_pow)
        if hmac.compare_digest(candidate, verification_digest):
            return preflight_entries

    if not saw_usable_seed:
        raise ValueError(
            "backup export requires seed_phrase and pow_bytes "
            "(no usable stored recovery seed was available to verify the passphrase)"
        )
    raise VerificationDigestMismatch(
        "backup export refused: passphrase does not match the committed verification digest"
    )


def export_backup(
    key_id: str,
    passphrase: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
    seed_phrase: str | None = None,
    pow_bytes: bytes | None = None,
) -> bytes:
    """Export the whole keyvault as a portable, passphrase-protected blob.

    Cross-machine recovery is non-trivial because the Secure Enclave
    wrapping key is non-exportable (codex BLOCKER #1): an envelope's
    Enclave-wrapped DEK can never be unwrapped on a second device. So
    ``export_backup`` builds a *ciphertext-rewrap manifest* — see SPEC.md
    §"export_backup / import_backup":

    1. Walk every ``ciphertexts/<key_id_hash>/<purpose_hash>/*.gcm``
       envelope; unwrap each DEK through :func:`wrap.unwrap_dek` (one
       biometric prompt per envelope on real hardware).
    2. Decrypt the envelope under its original per-device AAD, then
       re-encrypt the plaintext under a *portable* ``manifest_aad`` that
       omits the per-device MRKW prefix (so the import device can rebuild
       it from ``key_id`` + ``purpose_hash`` alone).
    3. Pack every DEK + portable ciphertext into a canonical-JSON manifest.
    4. Wrap the manifest in a PR2 ``MRKV`` blob whose Argon2id KEK is
       derived from ``passphrase`` — that is what protects the DEKs at
       rest — embedding the keyvault's verification digest so
       :func:`import_backup` can verify-before-decrypt.

    ``passphrase`` must be the passphrase that participated in the committed
    verification digest.  Supplying ``seed_phrase`` and ``pow_bytes`` verifies
    that relationship before any envelope is opened.  For backward-compatible
    callers that omit both keywords, export looks for the recovery seed stored
    under ``"bip39.seed.v1"`` and verifies against it while walking the
    envelopes.  A paper-only vault therefore has to supply the two keywords;
    silently producing a blob encrypted under an unrelated/ mistyped
    passphrase would make the digest gate and the backup KDF mutually
    unsatisfiable at recovery time.

    The returned bytes are the caller's to persist (the wizard's
    ``hermes mordred keyvault export`` writes them to a user-chosen path).

    Emits exactly one ``keyvault.backup_exported`` audit entry (POLICY.md
    #24); a sink failure on that emit is suppressed since the blob is
    already in hand.
    """
    root = _storage.resolve_keyvault_dir(home)
    key_id_hash = _hash_id(key_id)
    key_id_hash_hex = key_id_hash.hex()

    if (seed_phrase is None) != (pow_bytes is None):
        raise ValueError("seed_phrase and pow_bytes must be supplied together")

    # Function-local to avoid api -> _secret_ops -> api at module load time.
    from .api import _normalize_passphrase, _normalize_seed_phrase

    normalized_passphrase = _normalize_passphrase(passphrase)
    has_explicit_recovery_material = seed_phrase is not None
    candidate_digest: bytes | None = None
    if has_explicit_recovery_material:
        assert seed_phrase is not None and pow_bytes is not None
        candidate_digest = compute_digest(
            _normalize_seed_phrase(seed_phrase),
            normalized_passphrase,
            pow_bytes,
        )

    cipher_root = root / "ciphertexts" / key_id_hash_hex
    entries: list[dict[str, str]] = []
    seed_purpose_hash = _hash_id("bip39.seed.v1")

    # Hold the keyvault lock for the whole walk so the manifest is a
    # consistent snapshot — a concurrent encrypt() cannot add a half-written
    # envelope mid-export. The authoritative meta/commit check and digest read
    # are inside the same hold: provisioning writes the digest before meta and
    # may still roll both/key back, so an outside read could export against a
    # transient key.
    with _storage.keyvault_lock(root):
        native_key_id = _assert_key_committed(root, key_id, key_id_hash_hex)
        operation_backend = _native_key_id.backend_for_persisted_key(
            backend,
            root,
            key_id,
            native_key_id,
        )
        verification_digest = _storage.safe_read(root / "digests" / f"{key_id_hash_hex}.commit")
        if len(verification_digest) != 32:
            raise BackupCorrupt("committed verification digest must be exactly 32 bytes")
        if candidate_digest is not None and not hmac.compare_digest(candidate_digest, verification_digest):
            raise VerificationDigestMismatch(
                "backup export refused: seed/passphrase/PoW do not match the committed verification digest"
            )

        if cipher_root.exists() or cipher_root.is_symlink():
            _storage._check_dir_mode(cipher_root)

        # Backward-compatible callers may omit explicit recovery material only
        # when a seed is enrolled. Inspect that one known purpose directory
        # first. This makes a paper-only vault fail before any unrelated
        # envelope unwrap/biometric prompt, and makes a typo reject before the
        # complete manifest walk.
        preflight_entries = (
            {}
            if has_explicit_recovery_material
            else _verify_stored_seed_for_export(
                cipher_root=cipher_root,
                key_id=key_id,
                native_key_id=native_key_id,
                key_id_hash=key_id_hash,
                seed_purpose_hash=seed_purpose_hash,
                normalized_passphrase=normalized_passphrase,
                verification_digest=verification_digest,
                backend=operation_backend,
                audit_sink=audit_sink,
            )
        )

        if cipher_root.exists():
            for gcm_path in sorted(cipher_root.glob("*/*.gcm")):
                entry = preflight_entries.get(gcm_path)
                if entry is None:
                    entry, _stored_seed = _portable_backup_entry(
                        gcm_path,
                        key_id=key_id,
                        native_key_id=native_key_id,
                        key_id_hash=key_id_hash,
                        seed_purpose_hash=seed_purpose_hash,
                        inspect_seed=False,
                        backend=operation_backend,
                        audit_sink=audit_sink,
                    )
                entries.append(entry)

    manifest_json = json.dumps(
        {"version": _MANIFEST_VERSION, "key_id": key_id, "envelopes": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    # API-boundary normalization must cover the KDF as well as the digest.
    # Otherwise canonically equivalent NFKD spellings pass the digest check but
    # derive different Argon2 keys and make recovery fail with InvalidTag.
    out = backup.export(manifest_json, normalized_passphrase, verification_digest=verification_digest)

    # Best-effort memory hygiene: every unwrapped DEK is now sealed inside
    # ``out``. Python cannot zero immutable ``bytes`` / ``str``, but dropping
    # the plaintext manifest and the per-entry ``dek_hex`` strings shortens
    # their heap lifetime instead of pinning all DEKs for the whole call.
    envelope_count = len(entries)
    for _entry in entries:
        _entry.clear()
    entries.clear()
    del manifest_json

    # Success-path emit — the blob is already built, so a sink failure must
    # not lose it (POLICY.md #24: suppress via contextlib.suppress).
    with contextlib.suppress(Exception):
        audit_sink(
            {
                "event": "keyvault.backup_export",
                "decision": "allow",
                "reason": "keyvault.backup_exported",
                "key_id_hash": wrap._audit_key_id_hex(key_id),
                "blob_version": backup.VERSION,
                "kdf_id": backup.KDF_ID_ARGON2ID,
                "envelope_count": envelope_count,
            }
        )
    return out


def _decode_manifest_aes_blob(value: str, *, index: int) -> bytes:
    """Strictly decode one canonical base64 AES-GCM field."""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BackupCorrupt(f"backup manifest envelope {index} has invalid 'manifest_aes_blob_b64'") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BackupCorrupt(f"backup manifest envelope {index} has non-canonical 'manifest_aes_blob_b64'")
    if len(decoded) < 28:
        raise BackupCorrupt(
            f"backup manifest envelope {index} AES-GCM blob is too short "
            "(expected at least a 12-byte nonce and 16-byte tag)"
        )
    return decoded


def _parse_import_envelope(
    raw_entry: object,
    *,
    index: int,
    destinations: set[tuple[bytes, str]],
) -> dict[str, str]:
    """Validate and canonicalize one authenticated manifest entry."""
    if not isinstance(raw_entry, dict):
        raise BackupCorrupt(f"backup manifest envelope {index} must be an object")
    if set(raw_entry) != set(_MANIFEST_ENTRY_FIELDS):
        raise BackupCorrupt(f"backup manifest envelope {index} must contain exactly {sorted(_MANIFEST_ENTRY_FIELDS)!r}")

    values: dict[str, str] = {}
    for field in _MANIFEST_ENTRY_FIELDS:
        value = raw_entry.get(field)
        if not isinstance(value, str):
            raise BackupCorrupt(f"backup manifest envelope {index} has missing or invalid {field!r}")
        values[field] = value

    purpose_hash_hex = values["purpose_hash_hex"]
    if re.fullmatch(r"[0-9a-fA-F]{32}", purpose_hash_hex) is None:
        raise BackupCorrupt(
            f"backup manifest envelope {index} has invalid 'purpose_hash_hex' "
            "(expected exactly 32 hexadecimal characters)"
        )
    purpose_hash = bytes.fromhex(purpose_hash_hex)

    envelope_id = values["envelope_id"]
    if _ENVELOPE_ID_RE.fullmatch(envelope_id) is None:
        raise BackupCorrupt(
            f"backup manifest envelope {index} has invalid 'envelope_id' (expected 22 URL-safe-base64 characters)"
        )

    dek_hex = values["dek_hex"]
    if re.fullmatch(r"[0-9a-fA-F]{64}", dek_hex) is None:
        raise BackupCorrupt(
            f"backup manifest envelope {index} has invalid 'dek_hex' (expected exactly 64 hexadecimal characters)"
        )

    manifest_aes_blob_b64 = values["manifest_aes_blob_b64"]
    _decode_manifest_aes_blob(manifest_aes_blob_b64, index=index)

    destination = (purpose_hash, envelope_id)
    if destination in destinations:
        raise BackupCorrupt(f"backup manifest envelope {index} duplicates an earlier destination")
    destinations.add(destination)
    return {
        "purpose_hash_hex": purpose_hash.hex(),
        "envelope_id": envelope_id,
        "dek_hex": bytes.fromhex(dek_hex).hex(),
        "manifest_aes_blob_b64": manifest_aes_blob_b64,
    }


def _parse_import_manifest(manifest_json: bytes) -> tuple[str, list[dict[str, str]]]:
    """Parse and shape-validate the AES-GCM-authenticated import manifest.

    The manifest was just authenticated, so its contents are trusted; only
    the version gate and the field shapes are enforced. A malformed field
    must fail closed as :class:`BackupCorrupt` BEFORE the caller generates a
    destination Enclave key — otherwise a raw KeyError/TypeError would
    generate and then roll back a phantom Enclave key (security review
    finding).

    Returns ``(imported_key_id, envelopes)``.
    """

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for field, value in pairs:
            if field in parsed:
                raise BackupCorrupt(f"backup manifest contains duplicate JSON field {field!r}")
            parsed[field] = value
        return parsed

    try:
        manifest = json.loads(manifest_json, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupCorrupt("backup manifest is not valid UTF-8 JSON") from exc

    if (
        not isinstance(manifest, dict)
        or set(manifest) != _MANIFEST_ROOT_FIELDS
        or type(manifest.get("version")) is not int
        or manifest["version"] != _MANIFEST_VERSION
    ):
        raise BackupCorrupt("unsupported or malformed backup manifest")
    imported_key_id = manifest.get("key_id")
    try:
        imported_key_id = _native_key_id.validate_main_key_id(imported_key_id)
    except _native_key_id.InvalidMainKeyId as exc:
        raise BackupCorrupt("backup manifest missing, invalid, or reserved 'key_id'") from exc
    envelopes_raw = manifest.get("envelopes")
    if not isinstance(envelopes_raw, list):
        raise BackupCorrupt("backup manifest missing or invalid 'envelopes'")

    envelopes: list[dict[str, str]] = []
    destinations: set[tuple[bytes, str]] = set()
    for index, raw_entry in enumerate(envelopes_raw):
        envelopes.append(
            _parse_import_envelope(
                raw_entry,
                index=index,
                destinations=destinations,
            )
        )
    return imported_key_id, envelopes


def _rebuild_envelope(
    entry: dict[str, str],
    *,
    root: Path,
    new_key_id_hash: bytes,
    new_key_id_hash_hex: str,
    imported_key_id: str,
    native_key_id: str,
    backend: NativeBackend,
) -> None:
    """Rebuild one manifest envelope against THIS device's Enclave key.

    Decrypts the portable ciphertext under its ``manifest_aad``, re-wraps the
    DEK against the new Enclave key, reconstructs the MREN envelope bound to
    this device's AAD, and atomically writes it under
    ``ciphertexts/<kid>/<purpose>/<envelope_id>.gcm``.
    """
    _validate_envelope_id(entry["envelope_id"])
    purpose_hash = bytes.fromhex(entry["purpose_hash_hex"])
    # ``_parse_import_manifest`` already validated and canonicalized every
    # field before the destination key was generated.
    manifest_aes_blob = base64.b64decode(entry["manifest_aes_blob_b64"], validate=True)
    dek = bytes.fromhex(entry["dek_hex"])
    try:
        manifest_aad = _MANIFEST_MAGIC + new_key_id_hash + purpose_hash
        plaintext = crypto.decrypt(dek, manifest_aes_blob, aad=manifest_aad)
        new_wrapped_dek = wrap.wrap_dek(
            dek,
            imported_key_id,
            backend=backend,
            native_key_id=native_key_id,
        )
        envelope_bytes = _encode_envelope_from_hashes(dek, plaintext, new_key_id_hash, purpose_hash, new_wrapped_dek)
    finally:
        del dek
    key_dir = root / "ciphertexts" / new_key_id_hash_hex
    purpose_dir = key_dir / purpose_hash.hex()
    _ensure_managed_subdir(key_dir)
    _ensure_managed_subdir(purpose_dir)
    _storage.atomic_write(purpose_dir / f"{entry['envelope_id']}.gcm", envelope_bytes)


def _rollback_import(
    root: Path,
    *,
    new_key_id_hash_hex: str,
    commit_path: Path | None,
    imported_key_id: str,
    native_key_id: str,
    backend: NativeBackend,
    remove_ciphertext_tree: bool = True,
) -> None:
    """Best-effort rollback of a failed provisioning transaction.

    Shared by :func:`import_backup` and ``api.confirm_generate`` — both
    commit the same way (Enclave key first, then the commit digest, then the
    ``meta.json`` row) and so undo the same way. Each step is independently
    suppressed so the ORIGINAL failure always propagates via the caller's
    bare ``raise``:

    - delete the destination Enclave key FIRST: an orphaned Enclave key
      makes the retry's ``generate_enclave_key`` fail with
      ``WrapKeyAlreadyExists`` and needs a destructive ``keyvault reset``
      to clear, so it must be the residue least likely to survive. The
      remaining rollback steps remove every artifact created by this
      transaction. If the process dies between steps, the next import rejects
      the non-fresh destination rather than guessing that residue is
      disposable; the operator must inspect/reset it explicitly;
    - remove the rebuilt ciphertext tree (``remove_ciphertext_tree=False``
      for ``confirm_generate``, which writes no envelopes);
    - drop the commit digest if it was written (``commit_path=None`` when
      the transaction failed before the path was even derived);
    - repair ``meta.json``: ``save_meta``'s atomic rename may have committed
      the new meta.json before a later fsync raised, so re-read and drop the
      row if it landed (codex P2).
    """
    try:
        backend.delete_enclave_key(native_key_id)
    except Exception:
        # Retain the pending ownership journal (and every other artifact) so a
        # later reset can retry the exact scoped id. Removing metadata here
        # would strand a visible helper key after a delete transport failure.
        return
    if remove_ciphertext_tree:
        with contextlib.suppress(Exception):
            shutil.rmtree(root / "ciphertexts" / new_key_id_hash_hex, ignore_errors=True)
    if commit_path is not None:
        with contextlib.suppress(OSError):
            commit_path.unlink(missing_ok=True)
    with contextlib.suppress(Exception):
        repaired = _storage.load_meta(root)
        repaired["keys"].pop(new_key_id_hash_hex, None)
        repaired.pop(_native_key_id.PENDING_NATIVE_KEY_FIELD, None)
        _storage.save_meta(root, repaired)


def _assert_fresh_import_destination(root: Path) -> None:
    """Reject import unless ``root`` is a genuinely fresh v1 keyvault.

    Backend key namespaces are not authoritative evidence about filesystem
    ownership: the same logical key id may exist under a different native
    backend. Therefore no main row, pending/committed auxiliary ownership,
    commit, or ciphertext artifact may be overwritten or removed merely
    because ``generate_enclave_key`` succeeds in the caller's backend.

    Caller holds ``keyvault_lock(root)``.
    """
    meta = _storage.load_meta(root)
    if _native_key_id.has_native_key_ownership_state(meta):
        raise BackupImportConflict(
            "backup import requires a fresh keyvault; existing key metadata or native-key ownership state is present"
        )

    digests = root / "digests"
    ciphertexts = root / "ciphertexts"
    if any(digests.iterdir()) or any(ciphertexts.iterdir()):
        raise BackupImportConflict(
            "backup import requires a fresh keyvault; existing digest or ciphertext artifacts are present"
        )


def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
    backup_passphrase: str | None = None,
) -> str:
    """Restore a keyvault from an :func:`export_backup` blob on this device.

    Verify-before-decrypt (SPEC.md §"export_backup / import_backup", PR2
    Codex review #4): the verification digest is recomputed from the
    transcribed ``(seed_phrase, passphrase, pow_bytes)`` and checked against
    the digest embedded in the blob BEFORE any KDF / decryption runs. A
    mismatch raises :class:`RecoveryDigestMismatch` with NO Enclave or
    filesystem mutation — steps 1-5 are pre-mutation.

    On a digest match, the destination must be a fresh v1 keyvault: any
    existing key metadata, commit, or ciphertext artifact raises
    :class:`BackupImportConflict` before destination-key generation. Import is
    provisioning, never an overwrite/merge operation.

    1. Decrypt the manifest, generate a fresh Enclave wrapping key for the
       imported ``key_id`` on THIS device.
    2. For each manifest entry: decrypt the portable ciphertext under its
       ``manifest_aad``, re-wrap the DEK against the new Enclave key, and
       reconstruct the MREN envelope bound to this device's AAD.
    3. Write ``digests/<kid>.commit``, durably save ``meta.json`` with both
       the row and pending ownership journal, then clear pending in a separate
       durable save under the keyvault lock.

    Any failure through the first ownership save rolls back via
    :func:`_rollback_import` — the Enclave key is deleted first, then the
    ciphertext tree, the commit digest, and a ``meta.json`` row if it
    landed — and the original exception re-raises. Failure of the later
    pending-only cleanup does not delete a durably-owned key.

    Returns the imported ``key_id``. Raises
    :class:`mordred_hermes.keyvault.backup.BackupCorrupt` for a structurally
    invalid blob or an unsupported manifest version. ``backup_passphrase`` is
    a compatibility escape hatch for backups made by older releases that
    encrypted under a passphrase different from the one committed in the
    verification digest; new backups must leave it unset.
    """
    # Function-local to avoid a module-load cycle: ``api`` imports this module
    # (to re-export the ops), so the few provisioning-side helpers we still need
    # are imported here at call time, when ``api`` is fully loaded.
    from .api import _normalize_passphrase, _normalize_seed_phrase, _utc_now_iso

    # Steps 1-4 (pre-mutation): recompute the digest with split
    # normalization, then let recovery.import_backup do the length guard +
    # structural parse + verify-before-decrypt + manifest decryption. It
    # raises RecoveryDigestMismatch / BackupCorrupt before any mutation.
    normalized_passphrase = _normalize_passphrase(passphrase)
    recomputed_digest = compute_digest(
        _normalize_seed_phrase(seed_phrase),
        normalized_passphrase,
        pow_bytes,
    )
    kdf_passphrase = backup_passphrase if backup_passphrase is not None else passphrase
    normalized_kdf_passphrase = _normalize_passphrase(kdf_passphrase)
    try:
        manifest_json = recovery.import_backup(
            blob,
            normalized_kdf_passphrase,
            recomputed_digest=recomputed_digest,
            audit_sink=audit_sink,
        )
    except InvalidTag:
        # Backward compatibility: releases before the API-boundary fix fed the
        # raw (non-NFKD) string to Argon2.  Retry only when normalization changed
        # the bytes; ASCII/current blobs still perform exactly one KDF.
        if normalized_kdf_passphrase == kdf_passphrase:
            raise
        manifest_json = recovery.import_backup(
            blob,
            kdf_passphrase,
            recomputed_digest=recomputed_digest,
            audit_sink=audit_sink,
        )

    # 5. Parse + shape-validate the authenticated manifest BEFORE generating
    #    the destination Enclave key (below).
    imported_key_id, envelopes = _parse_import_manifest(manifest_json)

    root = _storage.resolve_keyvault_dir(home)
    backend = _native_key_id.bind_backend_to_root(backend, root)
    _storage.ensure_layout(root)
    new_key_id_hash = _hash_id(imported_key_id)
    new_key_id_hash_hex = new_key_id_hash.hex()
    native_key_id = _native_key_id.scoped_native_key_id(root, imported_key_id)
    commit_path = root / "digests" / f"{new_key_id_hash_hex}.commit"

    # 6-9. Destination freshness, key creation, envelope rebuild, and metadata
    # commit share one lock hold. This serializes import with init and other
    # imports, and — crucially — rejects existing state BEFORE asking a
    # possibly-different backend namespace to generate a same-named key.
    with _storage.keyvault_lock(root):
        _assert_fresh_import_destination(root)
        generated = False
        pending_meta = _storage.load_meta(root)
        pending_native_key_id = _native_key_id.add_pending_native_key(root, pending_meta, imported_key_id)
        if pending_native_key_id != native_key_id:  # pragma: no cover - deterministic invariant
            raise RuntimeError("native key identity derivation changed during import")
        _storage.save_meta(root, pending_meta)
        try:
            # If generate raises (including duplicate), the key belongs to
            # pre-existing state and must not be deleted by rollback.
            backend.generate_enclave_key(native_key_id)
            generated = True

            # 7. Rebuild every envelope against this device's Enclave key.
            for entry in envelopes:
                _rebuild_envelope(
                    entry,
                    root=root,
                    new_key_id_hash=new_key_id_hash,
                    new_key_id_hash_hex=new_key_id_hash_hex,
                    imported_key_id=imported_key_id,
                    native_key_id=native_key_id,
                    backend=backend,
                )

            # 8. Commit digest FIRST, then durably publish row + pending.
            #    A separate save below clears pending only after ownership is
            #    known durable (mirrors confirm_generate).
            _storage.atomic_write(commit_path, recomputed_digest)
            meta = _storage.load_meta(root)
            meta["keys"][new_key_id_hash_hex] = {
                "key_id": imported_key_id,
                "created_at": _utc_now_iso(),
                _native_key_id.NATIVE_KEY_ID_FIELD: native_key_id,
            }
            _storage.save_meta(root, meta)
        except BaseException:
            # Roll back only a key this transaction observed as successfully
            # generated. A duplicate/error from generate itself may refer to
            # pre-existing backend state and must never trigger deletion.
            if generated:
                _rollback_import(
                    root,
                    new_key_id_hash_hex=new_key_id_hash_hex,
                    commit_path=commit_path,
                    imported_key_id=imported_key_id,
                    native_key_id=native_key_id,
                    backend=backend,
                )
            raise

        _clear_pending_native_key_after_commit(
            root,
            key_id=imported_key_id,
            key_id_hash_hex=new_key_id_hash_hex,
            native_key_id=native_key_id,
        )

    return imported_key_id
