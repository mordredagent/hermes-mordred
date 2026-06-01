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

import hashlib
import secrets
from dataclasses import dataclass

from . import backup, recovery, wrap
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
