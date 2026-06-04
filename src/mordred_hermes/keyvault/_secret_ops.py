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
import contextlib
import json
import os
import re
import secrets
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _storage, backup, crypto, recovery, wrap
from ._envelope_codec import (
    _AES_NONCE_LEN,
    _encode_envelope,
    _encode_envelope_from_hashes,
    _hash_id,
    _parse_envelope,
    _split_envelope,
)
from .backup import BackupCorrupt
from .digest import compute_digest
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

    dek = secrets.token_bytes(_DEK_LEN)
    try:
        wrapped_dek_blob = wrap.wrap_dek(dek, key_id, backend=backend)
        envelope = _encode_envelope(dek, plaintext, key_id, purpose, wrapped_dek_blob)
    finally:
        # Best-effort wipe — Python bytes are immutable so we cannot zero
        # them in place; leaving the reference unbound lets the GC reclaim
        # sooner than a function-level local would.
        del dek

    envelope_id = _new_envelope_id()

    key_id_hash_hex = _hash_id(key_id).hex()
    purpose_hash_hex = _hash_id(purpose).hex()
    key_dir = root / "ciphertexts" / key_id_hash_hex
    purpose_dir = key_dir / purpose_hash_hex
    envelope_path = purpose_dir / f"{envelope_id}.gcm"

    with _storage.keyvault_lock(root):
        # codex pre-merge P2-1: validate any pre-existing directory before
        # writing inside it. Without this an attacker who pre-creates the
        # key_dir as a symlink (or with wrong mode) could redirect the
        # envelope into attacker-controlled territory.
        #
        # Cross-module private access (in-tree code-reviewer LOW-3,
        # 2026-05-15): ``_storage._check_dir_mode`` is intentionally
        # consumed across the api.py / _storage.py boundary inside the
        # same ``mordred_hermes.keyvault`` package. The underscore prefix
        # signals "package-internal", not "module-internal" — the same
        # pattern PR3 uses for ``_exceptions.py`` shared between
        # ``native.py`` and ``wrap.py``. Step-G may promote the helper to
        # ``_storage.validate_existing_dir`` if a third call site appears.
        if key_dir.exists() or key_dir.is_symlink():
            _storage._check_dir_mode(key_dir)
        else:
            key_dir.mkdir(mode=0o700)
            os.chmod(key_dir, 0o700)
        if purpose_dir.exists() or purpose_dir.is_symlink():
            _storage._check_dir_mode(purpose_dir)
        else:
            purpose_dir.mkdir(mode=0o700)
            os.chmod(purpose_dir, 0o700)
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
    if key_dir.exists() or key_dir.is_symlink():
        _storage._check_dir_mode(key_dir)
    if purpose_dir.exists() or purpose_dir.is_symlink():
        _storage._check_dir_mode(purpose_dir)

    blob = _storage.safe_read(envelope_path)
    aad, wrapped_dek_blob, aes_blob = _parse_envelope(blob, key_id, purpose)
    dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
    try:
        nonce = aes_blob[:_AES_NONCE_LEN]
        ct_tag = aes_blob[_AES_NONCE_LEN:]
        return AESGCM(dek).decrypt(nonce, ct_tag, aad)
    finally:
        del dek


# ----------------------------- backup / restore (step-E) -----------------------------


def _ensure_managed_subdir(path: Path) -> None:
    """Create ``path`` at mode ``0o700``, or validate it if it exists.

    Mirrors the per-directory guard :func:`encrypt` applies before writing
    an envelope: an attacker who pre-creates the directory as a symlink (or
    with a loose mode) is rejected rather than silently written through.
    """
    if path.exists() or path.is_symlink():
        _storage._check_dir_mode(path)
    else:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)


def export_backup(
    key_id: str,
    passphrase: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
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

    The returned bytes are the caller's to persist (the wizard's
    ``hermes mordred keyvault export`` writes them to a user-chosen path).

    Emits exactly one ``keyvault.backup_exported`` audit entry (POLICY.md
    #24); a sink failure on that emit is suppressed since the blob is
    already in hand.
    """
    root = _storage.resolve_keyvault_dir(home)
    key_id_hash = _hash_id(key_id)
    key_id_hash_hex = key_id_hash.hex()

    # The verification digest written at generate time — read it first so a
    # not-yet-initialized key fails fast (FileNotFoundError) before any walk.
    verification_digest = _storage.safe_read(root / "digests" / f"{key_id_hash_hex}.commit")

    cipher_root = root / "ciphertexts" / key_id_hash_hex
    entries: list[dict[str, str]] = []

    # Hold the keyvault lock for the whole walk so the manifest is a
    # consistent snapshot — a concurrent encrypt() cannot add a half-written
    # envelope mid-export.
    with _storage.keyvault_lock(root):
        if cipher_root.exists() or cipher_root.is_symlink():
            _storage._check_dir_mode(cipher_root)
            for gcm_path in sorted(cipher_root.glob("*/*.gcm")):
                _storage._check_dir_mode(gcm_path.parent)
                blob = _storage.safe_read(gcm_path)
                aad, purpose_hash, wrapped_dek_blob, aes_blob = _split_envelope(blob, key_id_hash)
                dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
                try:
                    plaintext = AESGCM(dek).decrypt(aes_blob[:_AES_NONCE_LEN], aes_blob[_AES_NONCE_LEN:], aad)
                    # Portable AAD — no per-device MRKW prefix, so the import
                    # device reconstructs it from key_id + purpose_hash.
                    manifest_aad = _MANIFEST_MAGIC + key_id_hash + purpose_hash
                    manifest_aes_blob = crypto.encrypt(dek, plaintext, aad=manifest_aad)
                    entries.append(
                        {
                            "purpose_hash_hex": purpose_hash.hex(),
                            "envelope_id": gcm_path.stem,
                            "dek_hex": dek.hex(),
                            "manifest_aes_blob_b64": base64.b64encode(manifest_aes_blob).decode("ascii"),
                        }
                    )
                finally:
                    del dek

    manifest_json = json.dumps(
        {"version": _MANIFEST_VERSION, "key_id": key_id, "envelopes": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    out = backup.export(manifest_json, passphrase, verification_digest=verification_digest)

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


def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Restore a keyvault from an :func:`export_backup` blob on this device.

    Verify-before-decrypt (SPEC.md §"export_backup / import_backup", PR2
    Codex review #4): the verification digest is recomputed from the
    transcribed ``(seed_phrase, passphrase, pow_bytes)`` and checked against
    the digest embedded in the blob BEFORE any KDF / decryption runs. A
    mismatch raises :class:`RecoveryDigestMismatch` with NO Enclave or
    filesystem mutation — steps 1-5 are pre-mutation.

    On a digest match:

    1. Decrypt the manifest, generate a fresh Enclave wrapping key for the
       imported ``key_id`` on THIS device.
    2. For each manifest entry: decrypt the portable ciphertext under its
       ``manifest_aad``, re-wrap the DEK against the new Enclave key, and
       reconstruct the MREN envelope bound to this device's AAD.
    3. Write ``digests/<kid>.commit`` then the ``meta.json`` row (the
       transaction commit point) under the keyvault lock.

    Any failure after the Enclave key is created rolls back — the
    ciphertext tree and the Enclave key are removed, and a ``meta.json``
    row is dropped if it landed — then the original exception re-raises.

    Returns the imported ``key_id``. Raises
    :class:`mordred_hermes.keyvault.backup.BackupCorrupt` for a structurally
    invalid blob or an unsupported manifest version.
    """
    # Function-local to avoid a module-load cycle: ``api`` imports this module
    # (to re-export the ops), so the few provisioning-side helpers we still need
    # are imported here at call time, when ``api`` is fully loaded.
    from .api import _normalize_passphrase, _normalize_seed_phrase, _utc_now_iso

    # Steps 1-4 (pre-mutation): recompute the digest with split
    # normalization, then let recovery.import_backup do the length guard +
    # structural parse + verify-before-decrypt + manifest decryption. It
    # raises RecoveryDigestMismatch / BackupCorrupt before any mutation.
    recomputed_digest = compute_digest(
        _normalize_seed_phrase(seed_phrase),
        _normalize_passphrase(passphrase),
        pow_bytes,
    )
    manifest_json = recovery.import_backup(
        blob,
        passphrase,
        recomputed_digest=recomputed_digest,
        audit_sink=audit_sink,
    )

    # 5. Parse + validate the manifest. It was just AES-GCM-authenticated,
    #    so the contents are trusted; only the version gate is enforced.
    manifest = json.loads(manifest_json)
    if not isinstance(manifest, dict) or manifest.get("version") != _MANIFEST_VERSION:
        raise BackupCorrupt("unsupported or malformed backup manifest")
    # Validate the authenticated manifest's shape BEFORE generating the
    # destination Enclave key (below): a malformed field must fail closed as
    # BackupCorrupt, not raise a raw KeyError/TypeError that generates and
    # then rolls back a phantom Enclave key (security review finding).
    imported_key_id = manifest.get("key_id")
    if not isinstance(imported_key_id, str) or not imported_key_id:
        raise BackupCorrupt("backup manifest missing or invalid 'key_id'")
    envelopes_raw = manifest.get("envelopes")
    if not isinstance(envelopes_raw, list):
        raise BackupCorrupt("backup manifest missing or invalid 'envelopes'")
    envelopes: list[dict[str, str]] = envelopes_raw

    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    new_key_id_hash = _hash_id(imported_key_id)
    new_key_id_hash_hex = new_key_id_hash.hex()
    commit_path = root / "digests" / f"{new_key_id_hash_hex}.commit"

    # 6. Create the destination Enclave key. OUTSIDE the rollback try: if
    #    this raises (e.g. the key already exists) there is nothing yet to
    #    roll back and the pre-existing key must NOT be deleted.
    backend.generate_enclave_key(imported_key_id)

    try:
        with _storage.keyvault_lock(root):
            # 7. Rebuild every envelope against this device's Enclave key.
            for entry in envelopes:
                _validate_envelope_id(entry["envelope_id"])
                purpose_hash = bytes.fromhex(entry["purpose_hash_hex"])
                manifest_aes_blob = base64.b64decode(entry["manifest_aes_blob_b64"])
                dek = bytes.fromhex(entry["dek_hex"])
                try:
                    manifest_aad = _MANIFEST_MAGIC + new_key_id_hash + purpose_hash
                    plaintext = crypto.decrypt(dek, manifest_aes_blob, aad=manifest_aad)
                    new_wrapped_dek = wrap.wrap_dek(dek, imported_key_id, backend=backend)
                    envelope_bytes = _encode_envelope_from_hashes(
                        dek, plaintext, new_key_id_hash, purpose_hash, new_wrapped_dek
                    )
                finally:
                    del dek
                key_dir = root / "ciphertexts" / new_key_id_hash_hex
                purpose_dir = key_dir / purpose_hash.hex()
                _ensure_managed_subdir(key_dir)
                _ensure_managed_subdir(purpose_dir)
                _storage.atomic_write(purpose_dir / f"{entry['envelope_id']}.gcm", envelope_bytes)

            # 8. Commit digest FIRST, meta.json row LAST — meta.json is the
            #    transaction commit point (mirrors confirm_generate).
            _storage.atomic_write(commit_path, recomputed_digest)
            meta = _storage.load_meta(root)
            meta["keys"][new_key_id_hash_hex] = {
                "key_id": imported_key_id,
                "created_at": _utc_now_iso(),
            }
            _storage.save_meta(root, meta)
    except BaseException:
        # Rollback — best-effort, each step independently suppressed so the
        # ORIGINAL failure always propagates via the bare ``raise``.
        # ``BaseException`` so a KeyboardInterrupt mid-import still cleans up.
        with contextlib.suppress(Exception):
            shutil.rmtree(root / "ciphertexts" / new_key_id_hash_hex, ignore_errors=True)
        with contextlib.suppress(OSError):
            commit_path.unlink(missing_ok=True)
        with contextlib.suppress(Exception):
            backend.delete_enclave_key(imported_key_id)
        with contextlib.suppress(Exception):
            repaired = _storage.load_meta(root)
            if repaired["keys"].pop(new_key_id_hash_hex, None) is not None:
                _storage.save_meta(root, repaired)
        raise

    return imported_key_id
