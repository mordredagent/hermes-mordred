"""mordred_hermes.keyvault._backup_import — import_backup (ciphertext-rewrap
manifest, import/restore direction).

Split out of ``_secret_ops`` (June sweep PR-6 follow-up) to keep that module
under the repo's LOC guideline. Owns the import half of the whole-keyvault
backup manifest described in SPEC.md §"export_backup / import_backup
(ciphertext-rewrap manifest)":

- ``_decode_manifest_aes_blob`` / ``_parse_import_envelope`` /
  ``_parse_import_manifest`` — shape-validate the AES-GCM-authenticated
  manifest before any destination key is generated.
- ``_rebuild_envelope`` — rewrap one manifest entry against this device's
  native key and publish it as an MREN envelope.
- ``_rollback_import`` — best-effort provisioning-transaction rollback,
  shared with ``api.confirm_generate`` (which calls it directly as
  ``_secret_ops._rollback_import``).
- ``_assert_fresh_import_destination`` — reject import onto a non-fresh
  keyvault.
- ``import_backup`` — the public entry point.

``_secret_ops`` re-exports ``import_backup`` and ``_rollback_import`` so
``api.import_backup`` / ``_secret_ops.import_backup`` /
``_secret_ops._rollback_import`` (and the existing test surface) stay valid.
The reverse dependency — the envelope/commit-state helpers this module needs
from ``_secret_ops`` (``_clear_pending_native_key_after_commit``,
``_ensure_managed_subdir``, ``_validate_envelope_id``, the manifest
wire-format constants) — is imported function-locally to avoid a
``_secret_ops -> _backup_import -> _secret_ops`` load cycle at import time;
see the note at the top of ``_secret_ops``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidTag

from . import _native_key_id, _storage, crypto, recovery, wrap
from ._envelope_codec import _encode_envelope_from_hashes, _hash_id
from .backup import BackupCorrupt, BackupImportConflict
from .digest import compute_digest
from .wrap import AuditSink, NativeBackend

__all__ = ["import_backup"]


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
    # Function-local: avoids the _secret_ops -> _backup_import -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _ENVELOPE_ID_RE, _MANIFEST_ENTRY_FIELDS

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
    # Function-local: avoids the _secret_ops -> _backup_import -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _MANIFEST_ROOT_FIELDS, _MANIFEST_VERSION

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
    # Function-local: avoids the _secret_ops -> _backup_import -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _MANIFEST_MAGIC, _ensure_managed_subdir, _validate_envelope_id

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
    # (via ``_secret_ops``, to re-export the ops), so the few provisioning-side
    # helpers we still need are imported here at call time, when ``api`` is
    # fully loaded.
    # Function-local: avoids the _secret_ops -> _backup_import -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _clear_pending_native_key_after_commit
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
