"""mordred_hermes.keyvault._backup_export — export_backup (ciphertext-rewrap
manifest, export direction).

Split out of ``_secret_ops`` (June sweep PR-6 follow-up) to keep that module
under the repo's LOC guideline. Owns the export half of the whole-keyvault
backup manifest described in SPEC.md §"export_backup / import_backup
(ciphertext-rewrap manifest)":

- ``_portable_backup_entry`` — authenticate one ciphertext envelope and
  rewrap its DEK under the portable ``manifest_aad``.
- ``_verify_stored_seed_for_export`` — back-compat passphrase verification
  against the stored recovery seed, for callers that omit
  ``seed_phrase``/``pow_bytes``.
- ``_collect_backup_entries`` — walk every ciphertext envelope, building the
  manifest entry list (extracted from ``export_backup`` for C901 headroom;
  see the docstring on ``export_backup`` below).
- ``export_backup`` — the public entry point.

``_secret_ops`` re-exports ``export_backup`` so ``api.export_backup`` /
``_secret_ops.export_backup`` (and the existing test surface) stay valid.
The reverse dependency — the envelope/commit-state helpers this module needs
from ``_secret_ops`` (``_assert_key_committed``, the manifest wire-format
constants) — is imported function-locally to avoid a
``_secret_ops -> _backup_export -> _secret_ops`` load cycle at import time;
see the note at the top of ``_secret_ops``.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
from pathlib import Path

from . import _native_key_id, _storage, backup, crypto, wrap
from ._canonical_json import canonical_json_bytes
from ._envelope_codec import _hash_id, _split_envelope
from .backup import BackupCorrupt
from .digest import VerificationDigestMismatch, compute_digest
from .wrap import AuditSink, NativeBackend

__all__ = ["export_backup"]


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
    # Function-local: avoids the _secret_ops -> _backup_export -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _MANIFEST_MAGIC

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


def _collect_backup_entries(
    cipher_root: Path,
    preflight_entries: dict[Path, dict[str, str]],
    *,
    key_id: str,
    native_key_id: str,
    key_id_hash: bytes,
    seed_purpose_hash: bytes,
    backend: NativeBackend,
    audit_sink: AuditSink,
) -> list[dict[str, str]]:
    """Walk every ``ciphertexts/<key_id_hash>/*/*.gcm`` envelope under
    ``cipher_root``, reusing any entry already built during the seed
    preflight, and return the manifest entry list in walk order.

    Extracted verbatim from ``export_backup`` (statements, ordering, and
    exception semantics unchanged) to give that function C901 headroom —
    PR #86's follow-up note flagged it at the cyclomatic cap.
    """
    entries: list[dict[str, str]] = []
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
                    backend=backend,
                    audit_sink=audit_sink,
                )
            entries.append(entry)
    return entries


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
    # Function-local: avoids the _secret_ops -> _backup_export -> _secret_ops
    # load cycle (see this module's docstring).
    from ._secret_ops import _MANIFEST_VERSION, _assert_key_committed

    root = _storage.resolve_keyvault_dir(home)
    key_id_hash = _hash_id(key_id)
    key_id_hash_hex = key_id_hash.hex()

    if (seed_phrase is None) != (pow_bytes is None):
        raise ValueError("seed_phrase and pow_bytes must be supplied together")

    # Function-local to avoid api -> _secret_ops -> _backup_export -> api at
    # module load time.
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

        entries = _collect_backup_entries(
            cipher_root,
            preflight_entries,
            key_id=key_id,
            native_key_id=native_key_id,
            key_id_hash=key_id_hash,
            seed_purpose_hash=seed_purpose_hash,
            backend=operation_backend,
            audit_sink=audit_sink,
        )

    manifest_json = canonical_json_bytes({"version": _MANIFEST_VERSION, "key_id": key_id, "envelopes": entries})

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
