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

from . import _storage, backup, crypto, recovery, wrap
from ._envelope_codec import (
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
    if key_dir.exists() or key_dir.is_symlink():
        _storage._check_dir_mode(key_dir)
    if purpose_dir.exists() or purpose_dir.is_symlink():
        _storage._check_dir_mode(purpose_dir)

    blob = _storage.safe_read(envelope_path)
    aad, wrapped_dek_blob, aes_blob = _parse_envelope(blob, key_id, purpose)
    dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
    try:
        # The envelope's aes_blob is exactly crypto.encrypt's self-contained
        # ``nonce(12) || ct || tag`` format, and _split_envelope already
        # enforced the nonce+tag minimum length, so crypto.decrypt is the
        # single nonce-split implementation.
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
                try:
                    _storage._check_dir_mode(gcm_path.parent)
                    blob = _storage.safe_read(gcm_path)
                    aad, purpose_hash, wrapped_dek_blob, aes_blob = _split_envelope(blob, key_id_hash)
                    dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
                    try:
                        plaintext = crypto.decrypt(dek, aes_blob, aad=aad)
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
                except Exception as exc:
                    # One bad envelope fails the whole export by design (the
                    # manifest must be complete), but a bare integrity error
                    # names no file and reads as tampering — attach the path
                    # so on-disk residue is diagnosable. add_note keeps the
                    # exception type and message intact.
                    exc.add_note(f"while exporting envelope {gcm_path}")
                    raise

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
    manifest = json.loads(manifest_json)
    if not isinstance(manifest, dict) or manifest.get("version") != _MANIFEST_VERSION:
        raise BackupCorrupt("unsupported or malformed backup manifest")
    imported_key_id = manifest.get("key_id")
    if not isinstance(imported_key_id, str) or not imported_key_id:
        raise BackupCorrupt("backup manifest missing or invalid 'key_id'")
    envelopes_raw = manifest.get("envelopes")
    if not isinstance(envelopes_raw, list):
        raise BackupCorrupt("backup manifest missing or invalid 'envelopes'")
    envelopes: list[dict[str, str]] = envelopes_raw
    return imported_key_id, envelopes


def _rebuild_envelope(
    entry: dict[str, str],
    *,
    root: Path,
    new_key_id_hash: bytes,
    new_key_id_hash_hex: str,
    imported_key_id: str,
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
    manifest_aes_blob = base64.b64decode(entry["manifest_aes_blob_b64"])
    dek = bytes.fromhex(entry["dek_hex"])
    try:
        manifest_aad = _MANIFEST_MAGIC + new_key_id_hash + purpose_hash
        plaintext = crypto.decrypt(dek, manifest_aes_blob, aad=manifest_aad)
        new_wrapped_dek = wrap.wrap_dek(dek, imported_key_id, backend=backend)
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
      other residues are recoverable if the process dies between rollback
      steps: a stale digest is overwritten by the retry, a stale ciphertext
      tree is cleared by ``import_backup``'s pre-rebuild rmtree, and a
      landed meta row is overwritten by an import retry (a
      ``confirm_generate`` retry, however, stops at api's "already
      initialized" guard and still needs ``keyvault reset``);
    - remove the rebuilt ciphertext tree (``remove_ciphertext_tree=False``
      for ``confirm_generate``, which writes no envelopes);
    - drop the commit digest if it was written (``commit_path=None`` when
      the transaction failed before the path was even derived);
    - repair ``meta.json``: ``save_meta``'s atomic rename may have committed
      the new meta.json before a later fsync raised, so re-read and drop the
      row if it landed (codex P2).
    """
    with contextlib.suppress(Exception):
        backend.delete_enclave_key(imported_key_id)
    if remove_ciphertext_tree:
        with contextlib.suppress(Exception):
            shutil.rmtree(root / "ciphertexts" / new_key_id_hash_hex, ignore_errors=True)
    if commit_path is not None:
        with contextlib.suppress(OSError):
            commit_path.unlink(missing_ok=True)
    with contextlib.suppress(Exception):
        repaired = _storage.load_meta(root)
        if repaired["keys"].pop(new_key_id_hash_hex, None) is not None:
            _storage.save_meta(root, repaired)


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

    Any failure after the Enclave key is created rolls back via
    :func:`_rollback_import` — the Enclave key is deleted first, then the
    ciphertext tree, the commit digest, and a ``meta.json`` row if it
    landed — and the original exception re-raises.

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

    # 5. Parse + shape-validate the authenticated manifest BEFORE generating
    #    the destination Enclave key (below).
    imported_key_id, envelopes = _parse_import_manifest(manifest_json)

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
            # 7. Clear any stale ciphertext tree for this key id before the
            #    rebuild. Reaching this line proves generate_enclave_key
            #    succeeded, i.e. no Enclave key existed for this key_id —
            #    so any pre-existing envelope here is wrapped by a destroyed
            #    key and permanently undecryptable (e.g. residue from a
            #    rollback killed between its key-delete and rmtree steps).
            #    Left in place it would poison every later export_backup,
            #    whose glob walk fails wholesale on one bad envelope.
            shutil.rmtree(root / "ciphertexts" / new_key_id_hash_hex, ignore_errors=True)

            # 8. Rebuild every envelope against this device's Enclave key.
            for entry in envelopes:
                _rebuild_envelope(
                    entry,
                    root=root,
                    new_key_id_hash=new_key_id_hash,
                    new_key_id_hash_hex=new_key_id_hash_hex,
                    imported_key_id=imported_key_id,
                    backend=backend,
                )

            # 9. Commit digest FIRST, meta.json row LAST — meta.json is the
            #    transaction commit point (mirrors confirm_generate).
            _storage.atomic_write(commit_path, recomputed_digest)
            meta = _storage.load_meta(root)
            meta["keys"][new_key_id_hash_hex] = {
                "key_id": imported_key_id,
                "created_at": _utc_now_iso(),
            }
            _storage.save_meta(root, meta)
    except BaseException:
        # Rollback — best-effort; the ORIGINAL failure always propagates via
        # the bare ``raise``. ``BaseException`` so a KeyboardInterrupt
        # mid-import still cleans up.
        _rollback_import(
            root,
            new_key_id_hash_hex=new_key_id_hash_hex,
            commit_path=commit_path,
            imported_key_id=imported_key_id,
            backend=backend,
        )
        raise

    return imported_key_id
