"""mordred_keyvault.backup — Argon2id-wrapped backup blob.

Serializes a secret + KDF parameters + verification digest into a
self-describing wire format that can be safely persisted to disk and
recovered on a different machine.

Wire format (Phase 4 PR2 baseline, frozen 2026-05-14):

    magic(4)             = b"MRKV"
    version(1)           = 1
    kdf_id(1)            = 1                       # 1 = Argon2id
    m_cost(4 BE)         = uint32, Argon2 memory in KiB (46 * 1024 = 47104)
    t_cost(4 BE)         = uint32, Argon2 time cost (1)
    p_cost(4 BE)         = uint32, Argon2 parallelism (1)
    salt(16)             = random per export
    verification_digest(32) = output of digest.compute_digest()
    aes_blob_len(4 BE)   = uint32, length of trailing AES-GCM blob
    aes_blob(*)          = output of crypto.encrypt(...) — nonce(12) || ct || tag(16)

AAD bound to the ciphertext (Codex review #2):

    aad = magic || version || kdf_id || m_cost || t_cost || p_cost
        || salt || verification_digest                                # 66 bytes

``aes_blob_len`` is intentionally excluded from AAD — AES-GCM
authenticates ciphertext length intrinsically, so the field is
informational (used for unambiguous parsing).

``parse_header`` does NO KDF and NO AES decryption — that lets
recovery.import_backup verify the embedded digest BEFORE paying the
Argon2 cost (Codex review #4 verify-before-decrypt).
"""

from __future__ import annotations

from dataclasses import dataclass
from secrets import token_bytes as _token_bytes

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

from . import crypto

# Wire format constants — DO NOT CHANGE without bumping `version` and
# updating SPEC.md.
MAGIC: bytes = b"MRKV"
VERSION: int = 1
KDF_ID_ARGON2ID: int = 1

# Argon2id cost parameters (SPEC §`mordred_keyvault` §Implementation).
# Memory is in KiB.
_ARGON2_M_COST_KIB: int = 46 * 1024  # 47104 KiB = 46 MiB
_ARGON2_T_COST: int = 1
_ARGON2_P_COST: int = 1
_KEK_LEN: int = 32  # AES-256 key

_SALT_LEN: int = 16
_DIGEST_LEN: int = 32
_GCM_NONCE_LEN: int = 12
_GCM_TAG_LEN: int = 16
_MIN_AES_BLOB_LEN: int = _GCM_NONCE_LEN + _GCM_TAG_LEN  # 28; ciphertext can be 0 bytes

# DOS guards on parsed KDF params. A maliciously crafted blob (or a
# blob whose KDF-param bytes have been tampered with) could otherwise
# convince ``decrypt_body`` to attempt e.g. a 16 GiB Argon2 allocation
# or 16 million iterations, hanging or OOM-ing the host.
#
# Limits are well above the canonical (46 MiB / t=1 / p=1) cost yet
# below pathological levels — a future "stronger profile" KDF bump
# stays within these caps. Header-level rejects happen in parse_header
# (BackupCorrupt), so the decrypt path never sees runaway params.
_MAX_M_COST_KIB: int = 1 * 1024 * 1024  # 1 GiB upper bound
_MAX_T_COST: int = 64
_MAX_P_COST: int = 16

# Header field layout (cumulative offsets):
#   0..4    magic
#   4..5    version
#   5..6    kdf_id
#   6..10   m_cost (uint32 BE)
#  10..14   t_cost (uint32 BE)
#  14..18   p_cost (uint32 BE)
#  18..34   salt
#  34..66   verification_digest
#  66..70   aes_blob_len (uint32 BE)
HEADER_LEN: int = 70
_AAD_LEN: int = 66  # everything up to but not including aes_blob_len


class BackupCorrupt(ValueError):
    """Raised when ``parse_header`` finds a structural problem with a
    blob (bad magic, unknown version/kdf, truncation, length mismatch,
    impossibly-short AES envelope).

    Subclasses :class:`ValueError` per the keyvault module convention
    (cf. :class:`mordred_hermes.keyvault.digest.VerificationDigestMismatch`).
    """


@dataclass(frozen=True)
class ParsedHeader:
    """Result of :func:`parse_header`. Contains everything needed to
    drive :func:`decrypt_body` without re-parsing.
    """

    magic: bytes
    version: int
    kdf_id: int
    m_cost: int
    t_cost: int
    p_cost: int
    salt: bytes
    verification_digest: bytes
    aes_blob: bytes
    aad: bytes  # the 66-byte AAD that was bound at encrypt time


def _derive_kek(passphrase: str, *, salt: bytes, m_cost: int, t_cost: int, p_cost: int) -> bytes:
    """Run Argon2id with the given parameters and return the 32-byte KEK."""
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=p_cost,
        hash_len=_KEK_LEN,
        type=Argon2Type.ID,
    )


def _assert_canonical_kdf_profile_v1(*, m_cost: int, t_cost: int, p_cost: int) -> None:
    """Canonical-profile invariant check for v1 blobs (codex third-pass
    HIGH-1, 2026-05-14).

    Phase 4 PR2 ships a single KDF profile under ``version=1``:
    ``m_cost = 46 MiB`` (47104 KiB), ``t_cost = 1``, ``p_cost = 1``.
    ``export()`` always writes these values, so any deviation in a v1
    blob's parsed cost params is either header tamper or a malformed
    external blob masquerading as v1.

    Called from :func:`parse_header` AND :func:`decrypt_body` (defence
    in depth — a hand-crafted :class:`ParsedHeader` that bypasses
    parse_header still trips this guard before the KDF runs).

    When ``version=2`` lands with a stronger profile, dispatch on
    ``version`` here. The wide DOS caps in :func:`parse_header` will
    continue to bound the worst case.
    """
    if m_cost != _ARGON2_M_COST_KIB or t_cost != _ARGON2_T_COST or p_cost != _ARGON2_P_COST:
        raise BackupCorrupt(
            f"non-canonical v1 KDF profile (m_cost={m_cost}, t_cost={t_cost}, "
            f"p_cost={p_cost}); v1 requires the canonical profile "
            f"(m={_ARGON2_M_COST_KIB}, t={_ARGON2_T_COST}, p={_ARGON2_P_COST})"
        )


def export(secret: bytes, passphrase: str, *, verification_digest: bytes) -> bytes:
    """Wrap ``secret`` with a passphrase-derived KEK and serialize the
    self-describing blob.

    Raises :class:`ValueError` if ``verification_digest`` is the wrong
    length (the algorithm always emits 32 bytes; anything else is a
    caller bug, not a backup format issue).
    """
    if len(verification_digest) != _DIGEST_LEN:
        raise ValueError(f"verification_digest must be {_DIGEST_LEN} bytes, got {len(verification_digest)}")
    salt = _token_bytes(_SALT_LEN)
    kek = _derive_kek(
        passphrase,
        salt=salt,
        m_cost=_ARGON2_M_COST_KIB,
        t_cost=_ARGON2_T_COST,
        p_cost=_ARGON2_P_COST,
    )
    # AAD = magic || version || kdf_id || m || t || p || salt || digest (66 bytes).
    #
    # Built ONCE here and reused verbatim as the header prefix below
    # (``header == aad + aes_blob_len``). A previous revision hand-packed
    # this same 66-byte prefix a second time to build the header — the two
    # copies could silently drift apart on a future edit to one but not the
    # other, which would make every NEWLY-written backup fail
    # ``decrypt_body`` with ``InvalidTag`` (``parse_header`` recovers the
    # bound AAD as ``blob[:66]``) while previously-written blobs kept
    # verifying fine — a nasty split-brain. Deriving ``header`` from ``aad``
    # makes the byte-identity structural instead of "must remember to keep
    # in sync."
    aad = (
        MAGIC
        + bytes([VERSION])
        + bytes([KDF_ID_ARGON2ID])
        + _ARGON2_M_COST_KIB.to_bytes(4, "big")
        + _ARGON2_T_COST.to_bytes(4, "big")
        + _ARGON2_P_COST.to_bytes(4, "big")
        + salt
        + verification_digest
    )
    aes_blob = crypto.encrypt(kek, secret, aad=aad)
    header = aad + len(aes_blob).to_bytes(4, "big")
    return header + aes_blob


def _parse_kdf_cost_params(blob: bytes, version: int) -> tuple[int, int, int]:
    """Parse, DOS-guard, and canonical-profile-check the Argon2 cost fields.

    Reads the m/t/p-cost fields from ``blob[6:18]`` (big-endian uint32),
    rejects out-of-bounds values BEFORE any KDF runs, and — for a v1 blob —
    enforces the canonical ``(46 MiB, 1, 1)`` profile.

    Raises :class:`BackupCorrupt` on any violation.
    """
    m_cost = int.from_bytes(blob[6:10], "big")
    t_cost = int.from_bytes(blob[10:14], "big")
    p_cost = int.from_bytes(blob[14:18], "big")
    # DOS-guard the parsed KDF params. Without these caps a single
    # tampered byte in the m_cost / t_cost / p_cost fields would
    # convince ``decrypt_body`` to attempt an Argon2id run with absurd
    # cost (e.g. m_cost MSB flip → 16 GiB allocation request) and
    # hang or OOM the host. parse_header rejects BEFORE the KDF runs.
    if m_cost < 1 or m_cost > _MAX_M_COST_KIB:
        raise BackupCorrupt(
            f"m_cost {m_cost} out of bounds [1, {_MAX_M_COST_KIB}] KiB (header tampered or unsupported KDF profile)"
        )
    if t_cost < 1 or t_cost > _MAX_T_COST:
        raise BackupCorrupt(
            f"t_cost {t_cost} out of bounds [1, {_MAX_T_COST}] (header tampered or unsupported KDF profile)"
        )
    if p_cost < 1 or p_cost > _MAX_P_COST:
        raise BackupCorrupt(
            f"p_cost {p_cost} out of bounds [1, {_MAX_P_COST}] (header tampered or unsupported KDF profile)"
        )
    # Canonical v1 profile enforcement (codex third-pass HIGH-1,
    # 2026-05-14). The wide DOS caps above allow m_cost up to 1 GiB so
    # they can serve as a future-profile bound, but a v1 blob whose
    # KDF params deviate from the canonical (46 MiB, 1, 1) is by
    # definition tampered or malformed — v1 export() always produces
    # the canonical profile. Rejecting at parse keeps the recovery
    # path from running an expensive Argon2 against an attacker-chosen
    # cost profile even when the attacker happens to know the
    # verification digest.
    if version == VERSION:
        _assert_canonical_kdf_profile_v1(m_cost=m_cost, t_cost=t_cost, p_cost=p_cost)
    return m_cost, t_cost, p_cost


def parse_header(blob: bytes) -> ParsedHeader:
    """Validate and unpack the 70-byte header. Does NO KDF and NO AES
    decryption — that's :func:`decrypt_body`'s job.

    Raises :class:`BackupCorrupt` for structurally invalid blobs.
    """
    if len(blob) < HEADER_LEN:
        raise BackupCorrupt(f"blob too short to contain {HEADER_LEN}-byte header (got {len(blob)})")
    magic = blob[0:4]
    if magic != MAGIC:
        raise BackupCorrupt(f"bad magic: expected {MAGIC!r}, got {magic!r}")
    version = blob[4]
    if version != VERSION:
        raise BackupCorrupt(f"unknown version {version} (only {VERSION} is supported)")
    kdf_id = blob[5]
    if kdf_id != KDF_ID_ARGON2ID:
        raise BackupCorrupt(f"unknown kdf_id {kdf_id} (only {KDF_ID_ARGON2ID} = Argon2id is supported)")
    m_cost, t_cost, p_cost = _parse_kdf_cost_params(blob, version)
    salt = blob[18:34]
    verification_digest = blob[34:66]
    aes_blob_len = int.from_bytes(blob[66:70], "big")
    expected_total_len = HEADER_LEN + aes_blob_len
    if len(blob) != expected_total_len:
        raise BackupCorrupt(
            f"blob length mismatch: header says {expected_total_len} bytes total "
            f"(70 header + {aes_blob_len} aes_blob), got {len(blob)}"
        )
    if aes_blob_len < _MIN_AES_BLOB_LEN:
        raise BackupCorrupt(
            f"aes_blob length {aes_blob_len} is shorter than the minimum "
            f"AES-GCM envelope ({_MIN_AES_BLOB_LEN} bytes: 12 nonce + 16 tag)"
        )
    aes_blob = blob[HEADER_LEN:]
    aad = blob[:_AAD_LEN]
    return ParsedHeader(
        magic=magic,
        version=version,
        kdf_id=kdf_id,
        m_cost=m_cost,
        t_cost=t_cost,
        p_cost=p_cost,
        salt=salt,
        verification_digest=verification_digest,
        aes_blob=aes_blob,
        aad=aad,
    )


def decrypt_body(parsed: ParsedHeader, passphrase: str) -> bytes:
    """Run the KDF using ``parsed.salt`` + parsed cost params, then
    AES-GCM-decrypt ``parsed.aes_blob`` with ``parsed.aad`` bound.
    Raises :class:`cryptography.exceptions.InvalidTag` on wrong
    passphrase or tampered header/ciphertext.

    Defence-in-depth (codex third-pass MEDIUM-2, 2026-05-14): re-runs
    the canonical-profile check on the supplied :class:`ParsedHeader`.
    The check is redundant with the one in :func:`parse_header` for
    callers that go through the normal flow, but it closes the
    bypass that exists if a caller constructs a ``ParsedHeader`` by
    hand (e.g. for testing, or future API misuse). ``ParsedHeader``
    is a public dataclass and Python provides no real way to make
    its constructor private; this re-check is the practical
    enforcement boundary.
    """
    if parsed.version == VERSION:
        _assert_canonical_kdf_profile_v1(m_cost=parsed.m_cost, t_cost=parsed.t_cost, p_cost=parsed.p_cost)
    kek = _derive_kek(
        passphrase,
        salt=parsed.salt,
        m_cost=parsed.m_cost,
        t_cost=parsed.t_cost,
        p_cost=parsed.p_cost,
    )
    return crypto.decrypt(kek, parsed.aes_blob, aad=parsed.aad)
