"""mordred_hermes.keyvault.vault_master — vault master-key double seal.

The Mordred vault has ONE master key. It is sealed two ways so the vault is both
fast to open in normal operation and recoverable when the Secure Enclave is gone:

- **SE-wrap** (``wmk``): :func:`mordred_hermes.keyvault.wrap.wrap_dek` wraps the
  master under the (unattended, for B2) Secure-Enclave wrapping key. This is the
  hot path — it is carried verbatim in every ``MVLT`` file header
  (:mod:`mordred_hermes.keyvault.file_container`) and unwrapped prompt-free once
  per Hermes process via :func:`mordred_hermes.keyvault.kek.open_master_key`.
- **passphrase-wrap** (``recovery``): :func:`mordred_hermes.keyvault.backup.export`
  wraps the same master under an Argon2id passphrase KEK. This is the cold path,
  used when the Enclave is unavailable (key lost, new machine, non-macOS).

The recovery blob embeds a *verification digest* equal to ``SHA-256(wmk)``. This
is deliberately NOT derived from the passphrase: a passphrase-derived digest
sitting next to the blob would be an offline brute-force oracle. ``SHA-256(wmk)``
is non-secret (``wmk`` is device-bound but not secret), recomputable at recovery
time, and binds a recovery blob to the exact ``wmk`` it was minted with — so
:func:`open_passphrase` rejects a blob paired with the wrong ``wmk`` *before*
paying the Argon2 cost (verify-before-decrypt).

Threat note (B2 / unattended): an unattended SE wrapping key means a same-uid
process can also unwrap the master while the user is logged in. This layer
protects offline disk reads (stolen / powered-off device, backup, forensic
image), NOT a same-uid attacker on a running machine.
"""

from __future__ import annotations

import contextlib
import hashlib
import secrets
from dataclasses import dataclass

from . import backup, recovery, wrap
from ._exceptions import WrapKeyAlreadyExists
from .kek import MasterKey
from .wrap import DEK_LEN, NativeBackend


@dataclass(frozen=True, slots=True)
class SealedMaster:
    """The two at-rest seals of one vault master key.

    ``wmk``: SE-wrapped master (the 127-byte ``MRKW`` blob), recorded in every
        ``MVLT`` file header for the prompt-free hot path.
    ``recovery``: Argon2id passphrase-wrapped master (the ``MRKV`` backup blob)
        for the cold recovery path. Persist it separately from the vault.
    """

    wmk: bytes
    recovery: bytes


def _recovery_digest(wmk: bytes) -> bytes:
    """Verification digest binding a recovery blob to its ``wmk`` (not the passphrase)."""
    return hashlib.sha256(wmk).digest()


def seal(*, key_id: str, passphrase: str, backend: NativeBackend) -> tuple[SealedMaster, MasterKey]:
    """Generate a fresh vault master and seal it under both ``key_id`` and *passphrase*.

    The Secure-Enclave wrapping key for ``key_id`` must already exist (created at
    vault init via :func:`mordred_hermes.keyvault.wrap.generate_wrapping_key`).

    Returns a ``(SealedMaster, MasterKey)`` pair: persist the
    :class:`SealedMaster` (``wmk`` in file headers, ``recovery`` as a sidecar),
    and use the opened :class:`~mordred_hermes.keyvault.kek.MasterKey` to encrypt
    the initial payloads. The caller owns the returned master and should
    :meth:`~mordred_hermes.keyvault.kek.MasterKey.close` it when done.

    Raises:
        ValueError: *passphrase* is empty (recovery would be unprotected).
        WrapKeyNotFound: no Enclave wrapping key exists for ``key_id``.
    """
    if not passphrase:
        raise ValueError("vault recovery passphrase must not be empty")
    master_bytes = secrets.token_bytes(DEK_LEN)
    try:
        wmk = wrap.wrap_dek(master_bytes, key_id, backend=backend)
        recovery_blob = backup.export(master_bytes, passphrase, verification_digest=_recovery_digest(wmk))
        opened = MasterKey(master_bytes)
    finally:
        del master_bytes
    return SealedMaster(wmk=wmk, recovery=recovery_blob), opened


def open_passphrase(recovery_blob: bytes, passphrase: str, *, wmk: bytes) -> MasterKey:
    """Recover the master from its passphrase ``recovery`` blob (cold path).

    Verify-before-decrypt: the digest bound into the blob is recomputed here as
    ``SHA-256(wmk)``. A blob paired with a different ``wmk`` raises
    :class:`~mordred_hermes.keyvault.recovery.RecoveryDigestMismatch` BEFORE the
    Argon2id KDF runs. A correct ``wmk`` but wrong *passphrase* passes the digest
    check and fails the AES-GCM tag (:class:`cryptography.exceptions.InvalidTag`).

    The caller owns the returned master and should
    :meth:`~mordred_hermes.keyvault.kek.MasterKey.close` it when done.
    """
    master_bytes = recovery.import_backup(
        recovery_blob,
        passphrase,
        recomputed_digest=_recovery_digest(wmk),
    )
    try:
        return MasterKey(master_bytes)
    finally:
        # Best-effort: MasterKey copied the bytes into its own bytearray, so
        # drop our reference (mirrors seal()). Immutable bytes cannot be zeroed.
        del master_bytes


def _noop_audit(_entry: dict[str, object]) -> None:
    """Discard sink for the device unwrap during a passphrase rotation.

    Mirrors :func:`mordred_hermes.keyvault.kek.open_master_key`, which also
    unwraps prompt-free with no audit sink by default. Auditing the rotation
    itself is a possible follow-up.
    """


def rewrap_from_device(*, key_id: str, new_passphrase: str, backend: NativeBackend, wmk: bytes) -> bytes:
    """Re-seal the EXISTING master under *new_passphrase*, authorized by the device key.

    Rotates the recovery passphrase without any old passphrase: the Secure-Enclave
    (or software) wrapping key for ``key_id`` unwraps the master, which is then
    re-exported under *new_passphrase*. The master, ``wmk``, and every enrolled
    file are unchanged — the caller replaces only the recovery sidecar. The new
    blob keeps the same ``SHA-256(wmk)`` verification digest (``wmk`` is unchanged),
    so :func:`open_passphrase` still binds it correctly. The master bytes never
    leave this function.

    Raises:
        ValueError: *new_passphrase* is empty (recovery would be unprotected).
        WrapKeyNotFound / WrapError: the device wrapping key is unavailable.
    """
    if not new_passphrase:
        raise ValueError("vault recovery passphrase must not be empty")
    master_bytes = wrap.unwrap_dek(wmk, key_id, audit_sink=_noop_audit, backend=backend)
    try:
        return backup.export(master_bytes, new_passphrase, verification_digest=_recovery_digest(wmk))
    finally:
        del master_bytes


def reseal_onto_device(
    recovery_blob: bytes,
    passphrase: str,
    *,
    old_wmk: bytes,
    key_id: str,
    backend: NativeBackend,
) -> SealedMaster:
    """Re-bind the EXISTING master onto THIS machine's device key (re-key on recovery).

    The cold-path counterpart of pairing :func:`open_passphrase` with a fresh
    :func:`seal`: for a vault copied to a new machine, the Secure-Enclave
    wrapping key AND the device-bound anchor are gone, so the master can only be
    reached through the passphrase recovery blob. This opens that blob under
    *passphrase* (verify-before-decrypt against ``SHA-256(old_wmk)``, exactly as
    :func:`open_passphrase`), then re-wraps the SAME master under a freshly
    generated wrapping key for ``key_id`` on this device — restoring the SE hot
    path locally without ever changing the master, so every enrolled file still
    decrypts.

    Critically, the recovery sidecar is **re-minted against the new wmk**: the
    blob's baked-in verification digest is ``SHA-256(wmk)``, so a sidecar left
    bound to ``old_wmk`` would be rejected by :func:`open_passphrase` /
    :func:`recover_vault` once the manifest carries ``new_wmk``. The returned
    :class:`SealedMaster` therefore carries both the new ``wmk`` (for the
    manifest header + file headers) and the re-bound ``recovery`` sidecar.

    The wrapping key for ``key_id`` is generated here if absent; a key left over
    from an earlier crashed re-key is reused (``WrapKeyAlreadyExists`` is
    swallowed) rather than treated as an error. The master bytes are dropped in a
    ``finally`` (mirroring :func:`seal`); CPython cannot zero immutable
    ``bytes``, so this shortens the exposure window rather than scrubbing it.

    Raises:
        ValueError: *passphrase* is empty (recovery would be unprotected).
        recovery.RecoveryDigestMismatch: *recovery_blob* is paired with a
            different ``old_wmk`` (substituted manifest) — raised before the KDF.
        cryptography.exceptions.InvalidTag: *passphrase* is wrong.
        WrapError: the new device wrapping key could not be generated / used.
    """
    if not passphrase:
        raise ValueError("vault recovery passphrase must not be empty")
    master_bytes = recovery.import_backup(
        recovery_blob,
        passphrase,
        recomputed_digest=_recovery_digest(old_wmk),
    )
    try:
        # Provision the device wrapping key for this machine if it is missing; a
        # key surviving an earlier crashed re-key is reused, not an error.
        with contextlib.suppress(WrapKeyAlreadyExists):
            wrap.generate_wrapping_key(key_id, backend=backend)
        new_wmk = wrap.wrap_dek(master_bytes, key_id, backend=backend)
        new_recovery = backup.export(master_bytes, passphrase, verification_digest=_recovery_digest(new_wmk))
    finally:
        del master_bytes
    return SealedMaster(wmk=new_wmk, recovery=new_recovery)


def rewrap_from_passphrase(recovery_blob: bytes, old_passphrase: str, new_passphrase: str, *, wmk: bytes) -> bytes:
    """Re-seal the EXISTING master under *new_passphrase*, authorized by *old_passphrase*.

    The device-independent counterpart of :func:`rewrap_from_device` — for a
    non-macOS host or a vault copied to another machine, where the wrapping key
    is gone. Opens the current recovery blob with *old_passphrase* (same
    verify-before-decrypt ``SHA-256(wmk)`` digest as :func:`open_passphrase`) and
    re-exports under *new_passphrase*. The master bytes never leave this function.

    Raises:
        ValueError: *new_passphrase* is empty.
        recovery.RecoveryDigestMismatch: *recovery_blob* is paired with a
            different ``wmk`` (substituted manifest) — raised before the KDF cost.
        cryptography.exceptions.InvalidTag: *old_passphrase* is wrong.
    """
    if not new_passphrase:
        raise ValueError("vault recovery passphrase must not be empty")
    master_bytes = recovery.import_backup(recovery_blob, old_passphrase, recomputed_digest=_recovery_digest(wmk))
    try:
        return backup.export(master_bytes, new_passphrase, verification_digest=_recovery_digest(wmk))
    finally:
        del master_bytes
