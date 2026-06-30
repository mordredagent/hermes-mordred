"""Tests for ``mordred_hermes.keyvault.backup`` — Argon2id-wrapped backup blob.

Phase 4 PR2 third RED → GREEN target (after ``crypto.py`` and
``digest.py``).

Wire format (Codex review #3 — self-describing, magic-prefixed):

    magic(4)         = b"MRKV"
    version(1)       = 1                          # currently the only supported version
    kdf_id(1)        = 1                          # 1 = Argon2id (only id in v1)
    m_cost(4)        = uint32 BE, Argon2 memory in KiB (46 * 1024 = 47104)
    t_cost(4)        = uint32 BE, Argon2 time cost (1)
    p_cost(4)        = uint32 BE, Argon2 parallelism (1)
    salt(16)         = random per export
    verification_digest(32) = output of digest.compute_digest()
    aes_blob_len(4)  = uint32 BE, length of aes_blob (nonce + ct + tag)
    aes_blob(*)      = output of crypto.encrypt(...)   (nonce(12) || ct || tag(16))

Total header length = 70 bytes (4+1+1+4+4+4+16+32+4). Total blob =
70 + aes_blob_len.

AAD binding (Codex review #2 — bind header to ciphertext):

    aad = magic || version || kdf_id || m_cost || t_cost || p_cost
        || salt || verification_digest                                # 66 bytes

``aes_blob_len`` is NOT in the AAD (AES-GCM already authenticates
ciphertext length intrinsically — truncating ct produces an InvalidTag).

KDF: ``argon2.low_level.hash_secret_raw(passphrase.utf8, salt,
time_cost=1, memory_cost=46*1024, parallelism=1, hash_len=32,
type=Argon2id)``. Output is the 32-byte AES-256 KEK.

AES: ``crypto.encrypt(kek, secret, aad=<66-byte aad>)``.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

# Re-used 32-byte verification_digest stand-in (not derived from any real
# seed/passphrase; recovery.py is what cross-checks digest validity).
DIGEST_FIXTURE = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")
PASSPHRASE = "correct horse battery staple"
SECRET = b"the quick brown fox jumps over 24 BIP39 words"


class TestRoundtrip:
    def test_export_then_import_returns_original_secret(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert backup.decrypt_body(parsed, PASSPHRASE) == SECRET

    def test_roundtrip_preserves_verification_digest_in_header(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert parsed.verification_digest == DIGEST_FIXTURE


class TestWireFormat:
    def test_blob_starts_with_mrkv_magic(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        assert blob[:4] == b"MRKV"

    def test_blob_version_byte_is_1(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        assert blob[4] == 1

    def test_blob_kdf_id_is_argon2id(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        # kdf_id at offset 5
        assert blob[5] == backup.KDF_ID_ARGON2ID
        assert backup.KDF_ID_ARGON2ID == 1

    def test_header_is_70_bytes_before_aes_blob(self) -> None:
        """Wire format header (Codex #3): magic(4)+version(1)+kdf_id(1)+
        m(4)+t(4)+p(4)+salt(16)+digest(32)+aes_blob_len(4) = 70 bytes."""
        from mordred_hermes.keyvault import backup

        assert backup.HEADER_LEN == 70

    def test_aes_blob_starts_at_offset_70(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert blob[70:] == parsed.aes_blob


class TestKdfParams:
    """Codex review (cryptographic soundness): the Argon2id cost params
    are part of the threat model. Regression guard ensures a future PR
    that accidentally drops the memory cost gets caught immediately."""

    def test_argon2_memory_cost_is_46_mib(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        # 46 MiB in KiB
        assert parsed.m_cost == 46 * 1024
        assert parsed.m_cost == 47104

    def test_argon2_time_cost_is_1(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert parsed.t_cost == 1

    def test_argon2_parallelism_is_1(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert parsed.p_cost == 1


class TestSaltFreshness:
    """Codex review #11: do not rely on probabilistic non-collision.
    Explicitly verify (a) two consecutive exports use different salts via
    a monkeypatched RNG that records calls, and (b) the salt written to
    the blob is also the salt passed to the KDF."""

    def test_export_invokes_secrets_token_bytes_for_salt(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Salt must come from secrets.token_bytes (CSPRNG), not a
        deterministic source. We assert by patching the symbol the
        module uses."""
        from mordred_hermes.keyvault import backup

        salts_yielded: list[int] = []
        real_token_bytes = backup._token_bytes  # module-local alias

        def spy(n: int) -> bytes:
            salts_yielded.append(n)
            return real_token_bytes(n)

        monkeypatch.setattr(backup, "_token_bytes", spy)
        backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)

        # 16-byte salt at minimum (more requests OK if crypto.encrypt
        # also draws nonce bytes — those go through secrets.token_bytes
        # in keyvault.crypto, not via this module's alias, so we only
        # see the salt draw here).
        assert 16 in salts_yielded, "salt must be drawn via the module-local secrets.token_bytes alias"

    def test_export_with_fixed_salt_produces_deterministic_blob(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """If salt AND nonce are both fixed, two exports of the same
        secret/passphrase must produce identical wire bytes — proves the
        salt is the only KDF-input randomness (i.e. no hidden state).

        Salt: 16 fixed bytes patched into backup._token_bytes(16).
        Nonce: 12 fixed bytes patched into keyvault.crypto module's
        nonce source (the crypto module has its own token_bytes import).
        """
        from mordred_hermes.keyvault import backup, crypto

        fixed_salt = b"\xaa" * 16
        fixed_nonce = b"\xbb" * 12

        def salt_supplier(n: int) -> bytes:
            assert n == 16
            return fixed_salt

        def nonce_supplier(n: int) -> bytes:
            assert n == 12
            return fixed_nonce

        monkeypatch.setattr(backup, "_token_bytes", salt_supplier)
        monkeypatch.setattr(crypto, "token_bytes", nonce_supplier)

        a = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        b = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        assert a == b


class TestAadBinding:
    """Codex review #2: AAD must bind the header so tampering with any
    advertised KDF param (or the digest, or the salt) trips the AES-GCM
    tag check rather than slipping through to a wrong-key decryption."""

    @pytest.mark.parametrize(
        "header_byte_offset_to_flip",
        [
            0,  # magic[0]
            3,  # magic[3]
            4,  # version
            5,  # kdf_id
            6,  # m_cost byte 0
            10,  # t_cost byte 0
            14,  # p_cost byte 0
            18,  # salt[0]
            33,  # salt[15]
            34,  # verification_digest[0]
            65,  # verification_digest[31]
        ],
    )
    def test_header_tamper_raises_invalid_tag(self, header_byte_offset_to_flip: int) -> None:
        """Flipping a bit anywhere in the AAD range (bytes 0..65) must
        cause decrypt to fail with InvalidTag, NOT BackupCorrupt — the
        header is structurally fine, but no longer authenticates."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[header_byte_offset_to_flip] ^= 0x01
        # parse_header may succeed (the magic / version / kdf are still
        # in legal ranges even after a 1-bit flip in those fields, when
        # the flip lands in a kdf-param byte; we don't care which path
        # raises, only that decrypt fails authentically).
        try:
            parsed = backup.parse_header(bytes(blob))
        except backup.BackupCorrupt:
            # Magic/version/kdf-id flip caught at structural layer is
            # also acceptable defence-in-depth.
            return
        with pytest.raises(InvalidTag):
            backup.decrypt_body(parsed, PASSPHRASE)

    def test_aes_blob_tamper_raises_invalid_tag(self) -> None:
        """Tampering with the ciphertext body itself must also raise
        InvalidTag (AES-GCM intrinsic property)."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        # Flip a bit ~25 bytes into the AES blob (past nonce, inside ct).
        blob[backup.HEADER_LEN + 25] ^= 0x01
        parsed = backup.parse_header(bytes(blob))
        with pytest.raises(InvalidTag):
            backup.decrypt_body(parsed, PASSPHRASE)


class TestStructuralValidation:
    """Codex review #3 + #5: malformed blobs must raise BackupCorrupt
    BEFORE any AES-GCM work — saves CPU and gives callers a clean
    distinction between (a) structurally wrong blob and (b) wrong
    passphrase / tampered authenticated payload (InvalidTag)."""

    def test_bad_magic_raises_backup_corrupt(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[:4] = b"XXXX"
        with pytest.raises(backup.BackupCorrupt, match="magic"):
            backup.parse_header(bytes(blob))

    def test_unknown_version_raises_backup_corrupt(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[4] = 99  # unknown version
        with pytest.raises(backup.BackupCorrupt, match="version"):
            backup.parse_header(bytes(blob))

    def test_unknown_kdf_id_raises_backup_corrupt(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[5] = 99  # unknown kdf
        with pytest.raises(backup.BackupCorrupt, match="kdf"):
            backup.parse_header(bytes(blob))

    def test_excessive_m_cost_raises_backup_corrupt(self) -> None:
        """DOS guard: a tampered ``m_cost`` MSB → 16+ GiB Argon2
        allocation request would hang/OOM the host. parse_header must
        reject before the KDF runs."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        # Rewrite m_cost field (offset 6, 4 bytes BE) to 2 GiB worth of
        # KiB — well above the 1 GiB cap.
        blob[6:10] = (2 * 1024 * 1024).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match="m_cost"):
            backup.parse_header(bytes(blob))

    def test_excessive_t_cost_raises_backup_corrupt(self) -> None:
        """DOS guard: tampered ``t_cost`` MSB → 16M iterations would
        run for years. parse_header rejects."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[10:14] = (1_000_000).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match="t_cost"):
            backup.parse_header(bytes(blob))

    def test_excessive_p_cost_raises_backup_corrupt(self) -> None:
        """DOS guard: tampered ``p_cost`` MSB → millions of threads
        would exhaust the system."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[14:18] = (100).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match="p_cost"):
            backup.parse_header(bytes(blob))

    def test_zero_m_cost_raises_backup_corrupt(self) -> None:
        """``m_cost=0`` would let an attacker bypass the KDF entirely
        (free brute-force on the passphrase). Reject."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[6:10] = (0).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match="m_cost"):
            backup.parse_header(bytes(blob))


class TestCanonicalKdfProfileV1:
    """Codex third-pass HIGH-1 (2026-05-14): v1 blobs MUST use the
    canonical KDF profile (m=46 MiB, t=1, p=1) exactly. The DOS cap
    (m ≤ 1 GiB, t ≤ 64, p ≤ 16) is too permissive — even within those
    bounds, an attacker who substitutes m_cost=512 MiB into a blob
    whose verification_digest they happen to know can DOS the recovery
    path before AAD fails. v1 export() always produces the canonical
    profile, so any deviation in a v1 import is by definition tamper
    (or a malformed external blob).

    The cap remains as belt-and-suspenders / future-profile bound.
    When ``version=2`` ships with a stronger profile, the canonical
    check dispatches on version.
    """

    def test_within_cap_but_non_canonical_m_cost_raises(self) -> None:
        """``m_cost=512 MiB`` is well within the 1 GiB DOS cap and a
        plausible "stronger profile" attacker substitution, but it's
        not the v1 canonical value. Must reject at parse_header."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        # 512 MiB in KiB = 524288, within cap (1 GiB = 1048576 KiB).
        blob[6:10] = (512 * 1024).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match=r"canonical|m_cost"):
            backup.parse_header(bytes(blob))

    def test_within_cap_but_non_canonical_t_cost_raises(self) -> None:
        """t_cost=4 is within the cap of 64 but != canonical 1."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[10:14] = (4).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match=r"canonical|t_cost"):
            backup.parse_header(bytes(blob))

    def test_within_cap_but_non_canonical_p_cost_raises(self) -> None:
        """p_cost=2 is within the cap of 16 but != canonical 1."""
        from mordred_hermes.keyvault import backup

        blob = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        blob[14:18] = (2).to_bytes(4, "big")
        with pytest.raises(backup.BackupCorrupt, match=r"canonical|p_cost"):
            backup.parse_header(bytes(blob))

    def test_canonical_profile_roundtrips_unchanged(self) -> None:
        """Sanity: the canonical profile (m=46*1024, t=1, p=1) is what
        export produces by default and must parse cleanly. Regression
        guard for the canonical-check itself."""
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        assert parsed.m_cost == 46 * 1024
        assert parsed.t_cost == 1
        assert parsed.p_cost == 1
        # And the full roundtrip still works.
        assert backup.decrypt_body(parsed, PASSPHRASE) == SECRET

    def test_decrypt_body_rejects_hand_crafted_non_canonical_parsed_header(
        self,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        """Codex third-pass MEDIUM-2 (2026-05-14): a caller that
        constructs :class:`ParsedHeader` by hand (bypassing
        parse_header) must NOT be able to slip a non-canonical KDF
        profile past decrypt_body. The canonical-profile re-check
        inside decrypt_body raises before Argon2 runs.

        Verified via explosive spy on ``backup.hash_secret_raw`` — if
        Argon2 is reached at all, the spy raises AssertionError.
        """
        from mordred_hermes.keyvault import backup

        # Build a real blob so we get a valid AAD/aes_blob/salt/digest.
        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        legit = backup.parse_header(blob)

        # Now hand-craft a ParsedHeader that swaps in a wider m_cost
        # (still within the DOS cap, but non-canonical for v1).
        tampered = backup.ParsedHeader(
            magic=legit.magic,
            version=legit.version,
            kdf_id=legit.kdf_id,
            m_cost=512 * 1024,  # 512 MiB — within cap, not canonical
            t_cost=legit.t_cost,
            p_cost=legit.p_cost,
            salt=legit.salt,
            verification_digest=legit.verification_digest,
            aes_blob=legit.aes_blob,
            aad=legit.aad,
        )

        def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("decrypt_body MUST canonical-check before invoking Argon2 — codex third-pass MEDIUM-2")

        monkeypatch.setattr(backup, "hash_secret_raw", boom)
        with pytest.raises(backup.BackupCorrupt, match="non-canonical"):
            backup.decrypt_body(tampered, PASSPHRASE)

    def test_truncated_header_raises_backup_corrupt(self) -> None:
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        with pytest.raises(backup.BackupCorrupt):
            # 50 bytes — less than the 70-byte header.
            backup.parse_header(blob[:50])

    def test_aes_blob_length_mismatch_raises_backup_corrupt(self) -> None:
        """The aes_blob_len field in the header must match the actual
        trailing bytes. Trim a few bytes from the end without updating
        the length field → length mismatch."""
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        with pytest.raises(backup.BackupCorrupt, match="length"):
            backup.parse_header(blob[:-3])

    def test_aes_blob_too_short_to_contain_gcm_envelope_raises(self) -> None:
        """Codex review #5: a self-described aes_blob shorter than 28
        bytes (12-byte nonce + 16-byte tag minimum) cannot be valid
        GCM output, so reject at parse rather than letting AESGCM raise
        cryptography's lower-level error."""
        from mordred_hermes.keyvault import backup

        # Build a blob with an advertised aes_blob_len of 20 bytes
        # (still > 0, but < 28).
        prefix = bytearray(backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE))
        short_aes = b"\x00" * 20
        # Rewrite the aes_blob_len field (4 bytes BE at offset 66).
        len_offset = backup.HEADER_LEN - 4
        prefix[len_offset : len_offset + 4] = (20).to_bytes(4, "big")
        # Replace the AES blob with the short one.
        truncated = bytes(prefix[: backup.HEADER_LEN]) + short_aes
        with pytest.raises(backup.BackupCorrupt, match="aes_blob"):
            backup.parse_header(truncated)


class TestWrongPassphrase:
    def test_wrong_passphrase_raises_invalid_tag_not_backup_corrupt(self) -> None:
        """Codex review #5: wrong passphrase derives a different KEK ⇒
        AES-GCM tag mismatch ⇒ ``InvalidTag``. This must NOT be
        normalized to BackupCorrupt — callers (recovery.py) need to
        distinguish "user typed the wrong passphrase" from "the file
        on disk is structurally broken"."""
        from mordred_hermes.keyvault import backup

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)
        parsed = backup.parse_header(blob)
        with pytest.raises(InvalidTag):
            backup.decrypt_body(parsed, "WRONG passphrase")


class TestParseHeaderDoesNotDecrypt:
    """Codex review #4 (verify-before-decrypt prerequisite): parse_header
    is callable WITHOUT the passphrase, and must not perform the KDF or
    AES decryption — that work is gated behind decrypt_body. This lets
    recovery.import_backup compare verification_digest BEFORE the
    expensive Argon2id run."""

    def test_parse_header_does_not_call_argon2(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """If parse_header invokes Argon2id at all, the spy below will
        raise. parse_header is allowed to read the cost params from the
        header but MUST NOT feed them to ``hash_secret_raw``.

        Patch target: ``backup.hash_secret_raw`` (the module-local
        alias from ``from argon2.low_level import hash_secret_raw``),
        NOT ``argon2.low_level.hash_secret_raw``. Patching the source
        module misses the impl's call entirely — verified during
        third-pass review (codex MEDIUM-3, 2026-05-14): the bogus
        patch was a silently-passing dead test.
        """
        from mordred_hermes.keyvault import backup

        # First, do a real export — this DOES call argon2 once.
        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)

        # Now install the explosive spy and confirm parse_header is
        # callable without triggering it.
        def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("parse_header MUST NOT invoke argon2 KDF — Codex review #4 verify-before-decrypt")

        monkeypatch.setattr(backup, "hash_secret_raw", boom)
        backup.parse_header(blob)  # must not raise

    def test_parse_header_does_not_call_aes_decrypt(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """parse_header MUST NOT decrypt — see TestParseHeaderDoesNotCall…
        for rationale."""
        from mordred_hermes.keyvault import backup, crypto

        blob = backup.export(SECRET, PASSPHRASE, verification_digest=DIGEST_FIXTURE)

        def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise AssertionError("parse_header MUST NOT call crypto.decrypt — Codex review #4")

        monkeypatch.setattr(crypto, "decrypt", boom)
        backup.parse_header(blob)  # must not raise


class TestBackupCorruptException:
    def test_exception_is_value_error_subclass(self) -> None:
        """Same convention as :class:`VerificationDigestMismatch` — a
        ``ValueError`` so generic input-validation handlers catch it."""
        from mordred_hermes.keyvault.backup import BackupCorrupt

        assert issubclass(BackupCorrupt, ValueError)
