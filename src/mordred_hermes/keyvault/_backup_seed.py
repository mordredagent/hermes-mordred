"""The recovery seed held inside a backup file, read back with the passphrase alone.

A keyvault that stores its seed (``bip39.seed.v1``, the default) exports that
envelope with every other one: the backup's manifest carries it, encrypted
under the Argon2id key derived from the passphrase. A backup file is therefore
enough, with the passphrase, to recover; nobody has to transcribe 24 words.

:func:`seed_from_backup` opens the manifest with the passphrase, takes the
seed out, and checks it against the verification digest the backup embeds
(seed, passphrase and the seed-bound PoW must reproduce it). The caller then
restores through :func:`~mordred_hermes.keyvault.api.import_backup` as with a
typed seed, so the import path itself is unchanged.

Unlike a typed seed, this decrypts before the digest can be checked: the
passphrase alone opens the manifest. A wrong passphrase still fails as
:class:`cryptography.exceptions.InvalidTag`, before anything is written.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from typing import Final

from . import backup, crypto
from . import pow as kvpow
from ._envelope_codec import _hash_id
from .backup import BackupCorrupt
from .digest import VerificationDigestMismatch, compute_digest

__all__ = ["SEED_PURPOSE", "NoSeedInBackup", "seed_from_backup"]

#: The purpose the keyvault stores its recovery seed under (``keyvault.ethereum``).
SEED_PURPOSE: Final = "bip39.seed.v1"


class NoSeedInBackup(BackupCorrupt):
    """The backup holds no recovery seed: it was made from a paper-only keyvault."""


def seed_from_backup(blob: bytes, passphrase: str) -> tuple[str, bytes]:
    """``(seed phrase, PoW)`` held by ``blob``, checked against its digest.

    Raises :class:`BackupCorrupt` for a malformed blob,
    :class:`NoSeedInBackup` when it holds no seed,
    :class:`cryptography.exceptions.InvalidTag` for a wrong passphrase, and
    :class:`VerificationDigestMismatch` when the seed found does not
    reproduce the embedded digest.
    """
    # Function-local: api imports the backup modules at load time.
    from ._backup_import import _parse_import_manifest
    from ._secret_ops import _MANIFEST_MAGIC
    from .api import _normalize_passphrase, _normalize_seed_phrase

    parsed = backup.parse_header(blob)
    normalized_passphrase = _normalize_passphrase(passphrase)
    manifest_json = backup.decrypt_body(parsed, normalized_passphrase)
    key_id, envelopes = _parse_import_manifest(manifest_json)
    purpose_hash = _hash_id(SEED_PURPOSE)
    seeds = [e for e in envelopes if hmac.compare_digest(bytes.fromhex(e["purpose_hash_hex"]), purpose_hash)]
    if not seeds:
        raise NoSeedInBackup("this backup holds no recovery seed (the keyvault kept it on paper only)")
    if len(seeds) != 1:
        raise BackupCorrupt("this backup holds more than one recovery seed")
    entry = seeds[0]
    try:
        sealed = base64.b64decode(entry["manifest_aes_blob_b64"], validate=True)
        dek = bytes.fromhex(entry["dek_hex"])
    except (binascii.Error, ValueError) as exc:
        raise BackupCorrupt("the recovery seed in this backup is malformed") from exc
    plaintext = crypto.decrypt(dek, sealed, aad=_MANIFEST_MAGIC + _hash_id(key_id) + purpose_hash)
    try:
        seed_phrase = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupCorrupt("the recovery seed in this backup is not text") from exc
    finally:
        del plaintext, dek
    normalized_seed = _normalize_seed_phrase(seed_phrase)
    pow_bytes = kvpow.compute_pow(normalized_seed, difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    digest = compute_digest(normalized_seed, normalized_passphrase, pow_bytes)
    if not hmac.compare_digest(digest, parsed.verification_digest):
        raise VerificationDigestMismatch("the recovery seed in this backup does not match its verification digest")
    return seed_phrase, pow_bytes
