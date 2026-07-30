"""Tests for ``mordred_hermes.keyvault.api`` MREN envelope + encrypt/decrypt.

Phase 4 PR4 step-C RED (2026-05-15) — implementation lands in step-C GREEN.

The MREN envelope wire format is frozen in SPEC.md §"PR4 API contract /
MREN envelope (managed storage, decrypt requires purpose)":

    offset  bytes  field
    0       4      magic = b"MREN"
    4       1      version = 1
    5       16     key_id_hash = sha256(key_id)[:16]
    21      16     purpose_hash = sha256(purpose)[:16]
    37      127    wrapped_dek (PR3 MRKW blob, RFC 3394 AES-KW under Enclave KEK)
    164     4      aes_blob_len (uint32 BE)
    168     N      aes_blob = nonce(12) || ciphertext || tag(16)

AAD = bytes[0:164]. Total envelope >= 196 bytes (when plaintext is empty).

api.encrypt returns an ``envelope_id`` (URL-safe base64 of 16 random
bytes) and persists ``ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/
<envelope_id>.gcm``. api.decrypt requires the caller-supplied ``purpose``
so cross-purpose replay attempts can be rejected BEFORE the wrap layer
prompts the user for biometric authorization (codex HIGH #2).

These tests pin every contract above using the FakeBackend reused from
``test_keyvault_wrap`` (software P-256 keypair stand-in for the real
Secure Enclave).
"""

from __future__ import annotations

import hashlib
import inspect
import os
import stat
import typing
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _envelope_codec, _secret_ops, _storage, api, wrap
from mordred_hermes.keyvault._exceptions import (
    WrapAuthCancelled,
    WrapIntegrityError,
    WrapKeyNotFound,
    WrapParseError,
)

# Re-use FakeBackend from the wrap test module. Step-G will relocate it to a
# shared tests._keyvault_fakes module; for now an explicit import is cleaner
# than duplicating the fake.
from tests._keyvault_fakes import FakeBackend

# ----------------------------- fixtures -----------------------------


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """Hermes home rooted under tmp_path, with the keyvault layout pre-created."""
    root = tmp_path / "mordred" / "keyvault"
    _storage.ensure_layout(root)
    return tmp_path


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def captured_audit() -> tuple[list[dict[str, Any]], Any]:
    sink_log: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        sink_log.append(entry)

    return sink_log, sink


@pytest.fixture
def registered_key(backend: FakeBackend, home: Path) -> str:
    """A key_id whose native key and authoritative v1 commits both exist."""
    key_id = "test-key-1"
    wrap.generate_wrapping_key(key_id, backend=backend)
    root = _storage.resolve_keyvault_dir(home)
    key_id_hash_hex = _key_id_hash(key_id).hex()
    _storage.atomic_write(root / "digests" / f"{key_id_hash_hex}.commit", b"\x42" * 32)
    meta = _storage.load_meta(root)
    meta["keys"][key_id_hash_hex] = {
        "key_id": key_id,
        "created_at": "2026-07-30T00:00:00+00:00",
    }
    _storage.save_meta(root, meta)
    return key_id


def _key_id_hash(key_id: str) -> bytes:
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16]


def _purpose_hash(purpose: str) -> bytes:
    return hashlib.sha256(purpose.encode("utf-8")).digest()[:16]


# ----------------------------- MREN wire format -----------------------------


class TestMrenWireFormat:
    def test_constants_match_spec(self) -> None:
        # Wire-format constants moved to _envelope_codec (api re-imports the
        # codec functions it uses; the constants now live with the wire format).
        assert _envelope_codec._ENVELOPE_MAGIC == b"MREN"
        assert _envelope_codec._ENVELOPE_VERSION == 1
        assert _envelope_codec._ENVELOPE_HEADER_LEN == 168  # magic+version+kid+purpose+wrap+len
        assert _envelope_codec._ENVELOPE_AAD_LEN == 164  # all but aes_blob_len

    def test_minimum_envelope_size_is_196_bytes(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"", "purpose", backend=backend, audit_sink=sink, home=home)
        envelope_path = _envelope_path(home, registered_key, "purpose", eid)
        blob = _storage.safe_read(envelope_path)
        # AAD(164) + aes_blob_len(4) + nonce(12) + ciphertext(0) + tag(16) = 196.
        assert len(blob) == 196

    def test_envelope_starts_with_mren_magic(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        blob = _read_envelope(home, registered_key, "purpose", eid)
        assert blob[0:4] == b"MREN"

    def test_envelope_version_byte_is_one(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        blob = _read_envelope(home, registered_key, "purpose", eid)
        assert blob[4] == 1

    def test_envelope_carries_key_id_hash(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        blob = _read_envelope(home, registered_key, "purpose", eid)
        assert blob[5:21] == _key_id_hash(registered_key)

    def test_envelope_carries_purpose_hash(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "ssh-priv", backend=backend, audit_sink=sink, home=home)
        blob = _read_envelope(home, registered_key, "ssh-priv", eid)
        assert blob[21:37] == _purpose_hash("ssh-priv")

    def test_envelope_aes_blob_len_field_matches_actual(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"abcdef", "purpose", backend=backend, audit_sink=sink, home=home)
        blob = _read_envelope(home, registered_key, "purpose", eid)
        declared = int.from_bytes(blob[164:168], "big")
        assert declared == len(blob) - 168
        assert declared == 12 + 6 + 16  # nonce + ciphertext + tag


# ----------------------------- api.encrypt -----------------------------


class TestApiEncrypt:
    def test_signature_matches_spec(self) -> None:
        sig = inspect.signature(api.encrypt)
        hints = typing.get_type_hints(api.encrypt)
        assert list(sig.parameters) == ["key_id", "plaintext", "purpose", "backend", "audit_sink", "home"]
        assert hints["key_id"] is str
        assert hints["plaintext"] is bytes
        assert hints["purpose"] is str
        assert hints["return"] is str  # envelope_id
        assert sig.parameters["backend"].kind is inspect.Parameter.KEYWORD_ONLY
        assert sig.parameters["audit_sink"].kind is inspect.Parameter.KEYWORD_ONLY
        assert sig.parameters["home"].kind is inspect.Parameter.KEYWORD_ONLY

    def test_returns_envelope_id_string(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"data", "purpose", backend=backend, audit_sink=sink, home=home)
        assert isinstance(eid, str)
        # URL-safe base64 of 16 bytes is 22 chars (no padding).
        assert len(eid) == 22
        assert all(c.isalnum() or c in "-_" for c in eid)

    def test_persists_envelope_at_expected_path(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"data", "purpose", backend=backend, audit_sink=sink, home=home)
        kid_hex = _key_id_hash(registered_key).hex()
        purpose_hex = _purpose_hash("purpose").hex()
        path = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex / purpose_hex / f"{eid}.gcm"
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_uses_fresh_dek_each_call(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid1 = api.encrypt(registered_key, b"same", "purpose", backend=backend, audit_sink=sink, home=home)
        eid2 = api.encrypt(registered_key, b"same", "purpose", backend=backend, audit_sink=sink, home=home)
        blob1 = _read_envelope(home, registered_key, "purpose", eid1)
        blob2 = _read_envelope(home, registered_key, "purpose", eid2)
        # Same key_id_hash + purpose_hash, but the 127-byte MRKW prefix is
        # built from a fresh ephemeral keypair each call -> different bytes.
        assert blob1[37:164] != blob2[37:164]

    def test_uses_fresh_aes_nonce_each_call(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid1 = api.encrypt(registered_key, b"same", "purpose", backend=backend, audit_sink=sink, home=home)
        eid2 = api.encrypt(registered_key, b"same", "purpose", backend=backend, audit_sink=sink, home=home)
        blob1 = _read_envelope(home, registered_key, "purpose", eid1)
        blob2 = _read_envelope(home, registered_key, "purpose", eid2)
        # First 12 bytes after aes_blob_len are the nonce.
        assert blob1[168:180] != blob2[168:180]

    def test_envelope_id_is_unique_across_calls(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        seen = {
            api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home) for _ in range(8)
        }
        assert len(seen) == 8

    def test_does_not_emit_audit_at_api_layer(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        # codex OD-3: encrypt has no authorization gate; no audit emit at api layer.
        # The wrap layer would emit only on unwrap (not wrap). So the sink stays empty.
        log, sink = captured_audit
        api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        assert log == []

    def test_key_without_authoritative_commit_is_rejected_before_wrap(
        self, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        # A backend key is not authoritative while provision/import may still
        # roll it back. No matching meta row + digest means encrypt must fail
        # before native-key lookup and before writing any ciphertext.
        log, sink = captured_audit
        with pytest.raises(_storage.KeyvaultCorruptError, match="single committed key"):
            api.encrypt("never-registered-key", b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        # No audit entry — encrypt has no authorization gate (codex OD-3).
        assert log == []
        # No envelope persisted under the missing key_id_hash subdir.
        kid_hex = _key_id_hash("never-registered-key").hex()
        kid_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex
        assert not kid_dir.exists()

    def test_committed_key_missing_from_backend_raises_wrap_key_not_found(
        self, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        key_id = "committed-but-native-key-missing"
        key_id_hash_hex = _key_id_hash(key_id).hex()
        root = _storage.resolve_keyvault_dir(home)
        _storage.atomic_write(root / "digests" / f"{key_id_hash_hex}.commit", b"\x42" * 32)
        meta = _storage.load_meta(root)
        meta["keys"][key_id_hash_hex] = {
            "key_id": key_id,
            "created_at": "2026-07-30T00:00:00+00:00",
        }
        _storage.save_meta(root, meta)

        log, sink = captured_audit
        with pytest.raises(WrapKeyNotFound):
            api.encrypt(key_id, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        assert log == []


# ----------------------------- api.decrypt -----------------------------


class TestApiDecrypt:
    def test_signature_matches_spec(self) -> None:
        sig = inspect.signature(api.decrypt)
        hints = typing.get_type_hints(api.decrypt)
        assert list(sig.parameters) == ["key_id", "envelope_id", "purpose", "backend", "audit_sink", "home"]
        assert hints["key_id"] is str
        assert hints["envelope_id"] is str
        assert hints["purpose"] is str
        assert hints["return"] is bytes

    def test_roundtrip(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"plaintext-data", "purpose", backend=backend, audit_sink=sink, home=home)
        decrypted = api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        assert decrypted == b"plaintext-data"

    def test_roundtrip_empty_plaintext(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"", "purpose", backend=backend, audit_sink=sink, home=home)
        assert api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home) == b""

    def test_roundtrip_binary_plaintext(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        plaintext = bytes(range(256))
        eid = api.encrypt(registered_key, plaintext, "purpose", backend=backend, audit_sink=sink, home=home)
        assert api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home) == plaintext

    def test_roundtrip_unicode_plaintext(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        plaintext = "パスワード🔐 with mixed 文字 and emoji".encode()
        eid = api.encrypt(registered_key, plaintext, "purpose", backend=backend, audit_sink=sink, home=home)
        assert api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home) == plaintext

    def test_cross_purpose_replay_no_biometric_prompt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        # Encrypt under purpose="A"; attempt to decrypt with purpose="B".
        # The security contract (codex HIGH #2): no biometric prompt fires,
        # no audit entry is emitted. With managed storage the path already
        # encodes the purpose_hash so a wrong purpose hits FileNotFoundError;
        # if the attacker repositions the envelope into the wrong-purpose
        # directory, the MREN parser rejects with WrapParseError. Both
        # are pre-authorization rejections.
        log, sink = captured_audit
        eid = api.encrypt(registered_key, b"secret", "purpose-A", backend=backend, audit_sink=sink, home=home)
        before_ecdh_count = sum(1 for op, _ in backend.calls if op == "ecdh")
        with pytest.raises((WrapParseError, FileNotFoundError)):
            api.decrypt(registered_key, eid, "purpose-B", backend=backend, audit_sink=sink, home=home)
        after_ecdh_count = sum(1 for op, _ in backend.calls if op == "ecdh")
        # No ecdh call was made (= no biometric prompt would have fired).
        assert after_ecdh_count == before_ecdh_count
        # No audit emit either - parse failures are pre-authorization (PR3 HIGH-1).
        assert log == []

    def test_cross_purpose_repositioned_envelope_raises_wrap_parse_error(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        # Attacker has the envelope bytes and places them at the wrong-purpose
        # path on disk. The MREN parser must still reject before unwrap_dek.
        log, sink = captured_audit
        eid = api.encrypt(registered_key, b"secret", "purpose-A", backend=backend, audit_sink=sink, home=home)
        # Copy envelope into the purpose-B directory.
        path_a = _envelope_path(home, registered_key, "purpose-A", eid)
        purpose_b_hex = _purpose_hash("purpose-B").hex()
        kid_hex = _key_id_hash(registered_key).hex()
        dir_b = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex / purpose_b_hex
        dir_b.mkdir(mode=0o700, parents=True)
        path_b = dir_b / f"{eid}.gcm"
        _storage.atomic_write(path_b, _storage.safe_read(path_a))
        before_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        with pytest.raises(WrapParseError):
            api.decrypt(registered_key, eid, "purpose-B", backend=backend, audit_sink=sink, home=home)
        after_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        assert after_ecdh == before_ecdh
        assert log == []

    def test_wrong_envelope_id_raises_file_not_found(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        # 22-char URL-safe-base64 ID that satisfies _validate_envelope_id but
        # has no envelope on disk.
        unused_eid = "A" * 22
        with pytest.raises(FileNotFoundError):
            api.decrypt(registered_key, unused_eid, "purpose", backend=backend, audit_sink=sink, home=home)

    def test_wrong_key_id_raises_wrap_parse_error(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        # Encrypt under key_id="test-key-1"; attempt decrypt with another key_id.
        # The envelope's key_id_hash field won't match SHA-256(other-key)[:16],
        # so parse rejects pre-authorization.
        _, sink = captured_audit
        wrap.generate_wrapping_key("other-key", backend=backend)
        eid = api.encrypt(registered_key, b"secret", "purpose", backend=backend, audit_sink=sink, home=home)
        # Move the envelope to the other key's directory so the path resolves,
        # but the key_id_hash inside still mismatches "other-key".
        kid_hex_old = _key_id_hash(registered_key).hex()
        kid_hex_new = _key_id_hash("other-key").hex()
        purpose_hex = _purpose_hash("purpose").hex()
        old_path = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex_old / purpose_hex / f"{eid}.gcm"
        new_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex_new / purpose_hex
        new_dir.mkdir(parents=True, mode=0o700)
        # mkdir mode is umask-adjusted; chmod explicitly so the dir-mode check
        # in decrypt accepts these intermediate dirs and we reach the parse
        # validation (which is the contract this test pins).
        os.chmod(new_dir, 0o700)
        os.chmod(new_dir.parent, 0o700)
        new_path = new_dir / f"{eid}.gcm"
        os.rename(old_path, new_path)

        with pytest.raises(WrapParseError):
            api.decrypt("other-key", eid, "purpose", backend=backend, audit_sink=sink, home=home)

    def test_tampered_envelope_raises_invalid_tag(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        from cryptography.exceptions import InvalidTag

        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"sensitive", "purpose", backend=backend, audit_sink=sink, home=home)
        path = _envelope_path(home, registered_key, "purpose", eid)
        blob = bytearray(_storage.safe_read(path))
        # Flip a byte inside the AES ciphertext body (after the 168-byte
        # header + 12-byte nonce).
        blob[180] ^= 0x01
        _storage.atomic_write(path, bytes(blob))
        with pytest.raises(InvalidTag):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)

    def test_tampered_wrapped_dek_raises_wrap_integrity_error(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        path = _envelope_path(home, registered_key, "purpose", eid)
        blob = bytearray(_storage.safe_read(path))
        # Flip a byte inside the wrapped_dek field (offset 37, len 127).
        blob[163] ^= 0x01  # last byte of wrapped_dek
        _storage.atomic_write(path, bytes(blob))
        with pytest.raises(WrapIntegrityError):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)

    def test_emits_keyvault_unwrap_authorized_on_success(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        log, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        # Exactly one emit, from the wrap layer (api.decrypt does NOT double-emit).
        assert len(log) == 1
        assert log[0]["reason"] == "keyvault.unwrap_authorized"

    def test_emits_keyvault_unwrap_denied_on_user_cancel(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        log, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        backend.denied_reason = "user_cancelled"
        with pytest.raises(WrapAuthCancelled):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        assert len(log) == 1
        assert log[0]["reason"] == "keyvault.unwrap_denied"
        assert log[0]["native_error_code"] == "user_cancelled"


# ----------------------------- purpose validation -----------------------------


class TestPurposeValidation:
    @pytest.mark.parametrize(
        "bad",
        [
            "",  # empty
            "../etc",  # path traversal
            "..",  # bare traversal
            "a/b",  # forward slash
            "a\\b",  # backslash (Windows path sep, defensive)
            "a\x00b",  # null byte
            "a\nb",  # newline
            "a\rb",  # carriage return
        ],
    )
    def test_rejects_dangerous_purpose_in_encrypt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        bad: str,
    ) -> None:
        _, sink = captured_audit
        with pytest.raises(ValueError):
            api.encrypt(registered_key, b"x", bad, backend=backend, audit_sink=sink, home=home)

    @pytest.mark.parametrize(
        "bad",
        ["", "../etc", "a/b", "a\x00b"],
    )
    def test_rejects_dangerous_purpose_in_decrypt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        bad: str,
    ) -> None:
        _, sink = captured_audit
        with pytest.raises(ValueError):
            api.decrypt(registered_key, "dummy_eid", bad, backend=backend, audit_sink=sink, home=home)

    def test_accepts_alphanumeric_with_dashes_and_underscores(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "ssh-priv_key.v1", backend=backend, audit_sink=sink, home=home)
        assert api.decrypt(registered_key, eid, "ssh-priv_key.v1", backend=backend, audit_sink=sink, home=home) == b"x"


# ----------------------------- envelope persistence -----------------------------


class TestEnvelopePersistence:
    def test_creates_purpose_subdir_with_0700(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        api.encrypt(registered_key, b"x", "newpurpose", backend=backend, audit_sink=sink, home=home)
        kid_hex = _key_id_hash(registered_key).hex()
        purpose_hex = _purpose_hash("newpurpose").hex()
        purpose_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex / purpose_hex
        assert stat.S_IMODE(purpose_dir.stat().st_mode) == 0o700

    def test_envelopes_for_same_key_different_purpose_separate(
        self, registered_key: str, backend: FakeBackend, home: Path, captured_audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _, sink = captured_audit
        eid1 = api.encrypt(registered_key, b"x", "purpose-A", backend=backend, audit_sink=sink, home=home)
        eid2 = api.encrypt(registered_key, b"x", "purpose-B", backend=backend, audit_sink=sink, home=home)
        path1 = _envelope_path(home, registered_key, "purpose-A", eid1)
        path2 = _envelope_path(home, registered_key, "purpose-B", eid2)
        assert path1.parent != path2.parent


# ---------------------- codex pre-merge review-fix tests ----------------------


class TestEnvelopeIdValidation:
    """Codex P1: caller-supplied ``envelope_id`` was appended directly into
    the filesystem path. A malicious caller could include ``/`` or ``..``
    and redirect ``decrypt`` to a file outside the managed ciphertext
    directory (parse / prompt on an attacker-placed file). Fix: reject
    anything except the 22-char URL-safe-base64 format that ``encrypt``
    returns."""

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "../etc",
            "..",
            "a/b",
            "a\\b",
            "a\x00b",
            "x" * 21,  # too short
            "x" * 23,  # too long
            "abcd!ghij_kmnopqrstuv",  # contains '!' (not in URL-safe alphabet, 21 chars)
            "abcd!ghij_kmnopqrstuvw",  # contains '!' (22 chars, length OK but char invalid)
            "x" * 22 + "=",  # base64 padding NOT allowed
            "abcd ghij_kmnopqrstuvw",  # space inside (22 chars)
        ],
    )
    def test_rejects_invalid_envelope_id_in_decrypt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        bad: str,
    ) -> None:
        _, sink = captured_audit
        with pytest.raises(ValueError):
            api.decrypt(registered_key, bad, "purpose", backend=backend, audit_sink=sink, home=home)

    def test_accepts_valid_22_char_envelope_id(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _, sink = captured_audit
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        # Round-trip succeeds.
        assert api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home) == b"x"

    def test_encrypt_always_returns_validator_acceptable_id(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        # 64 fresh encrypts; every envelope_id must satisfy the validator.
        _, sink = captured_audit
        for _ in range(64):
            eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
            _secret_ops._validate_envelope_id(eid)  # must not raise


class TestEncryptValidatesExistingDirs:
    """Codex P2-1: ``encrypt`` skipped mode/symlink validation when the
    key/purpose ciphertext subdirectory already existed (so a pre-created
    symlinked or chmod'ed directory bypassed the file-safety contract)."""

    def test_refuses_symlinked_key_directory(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        tmp_path: Path,
    ) -> None:
        _, sink = captured_audit
        kid_hex = _key_id_hash(registered_key).hex()
        attacker_dir = tmp_path / "attacker-target"
        attacker_dir.mkdir(mode=0o700)
        ciphertexts = home / "mordred" / "keyvault" / "ciphertexts"
        # Replace the would-be key dir with a symlink to attacker territory.
        (ciphertexts / kid_hex).symlink_to(attacker_dir)
        with pytest.raises(_storage.KeyvaultPermissionError):
            api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)

    def test_refuses_symlinked_purpose_directory(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        tmp_path: Path,
    ) -> None:
        _, sink = captured_audit
        kid_hex = _key_id_hash(registered_key).hex()
        purpose_hex = _purpose_hash("purpose").hex()
        attacker_dir = tmp_path / "attacker-target"
        attacker_dir.mkdir(mode=0o700)
        kid_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex
        kid_dir.mkdir(mode=0o700)
        (kid_dir / purpose_hex).symlink_to(attacker_dir)
        with pytest.raises(_storage.KeyvaultPermissionError):
            api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)

    def test_refuses_wrong_mode_existing_key_dir(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
    ) -> None:
        _, sink = captured_audit
        kid_hex = _key_id_hash(registered_key).hex()
        kid_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex
        kid_dir.mkdir(mode=0o755)  # too permissive
        with pytest.raises(_storage.KeyvaultPermissionError):
            api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)


# ----- second codex pre-merge pass — P2-A / P2-B file-safety + parse strictness -----


class TestParseEnvelopeUndersizedAesBlob:
    """Codex second-pass P2-A: ``_parse_envelope`` only verified
    ``declared_len`` matched the actual blob tail length. An attacker who
    places a same-purpose envelope with ``aes_blob_len < 12 + 16``
    (nonce + tag minimum) would pass parse, then ``decrypt`` invokes
    ``wrap.unwrap_dek`` — spending a biometric prompt and emitting
    ``keyvault.unwrap_authorized`` — before AES-GCM rejects the
    structurally-invalid envelope. Parse must reject this BEFORE any
    wrap-layer call."""

    @pytest.mark.parametrize("declared_len", [0, 1, 11, 12, 27])  # < nonce(12) + tag(16) = 28
    def test_decrypt_rejects_undersized_aes_blob_len(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        declared_len: int,
    ) -> None:
        log, sink = captured_audit
        # Build an envelope with valid header but a too-small aes_blob_len field.
        eid = api.encrypt(registered_key, b"x", "purpose", backend=backend, audit_sink=sink, home=home)
        path = _envelope_path(home, registered_key, "purpose", eid)
        blob = bytearray(_storage.safe_read(path))
        # Overwrite the 4-byte BE aes_blob_len field (offsets 164-168).
        blob[164:168] = declared_len.to_bytes(4, "big")
        # Truncate or pad the body so that len(blob) - 168 == declared_len.
        truncated = bytes(blob[:168]) + bytes(declared_len)
        _storage.atomic_write(path, truncated)

        before_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        with pytest.raises(WrapParseError):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        after_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        # No ecdh call - no biometric prompt would have fired.
        assert after_ecdh == before_ecdh
        # No audit emit - parse failures are pre-authorization.
        assert log == []


class TestDecryptValidatesIntermediateDirs:
    """Codex second-pass P2-B: ``decrypt`` opened the final ``.gcm`` file
    via ``safe_read`` which only refuses symlinks at the final path
    component (``O_NOFOLLOW``). An intermediate symlinked directory
    (``ciphertexts/<kid_hash>`` or ``ciphertexts/<kid_hash>/<purpose_hash>``)
    would still be traversed, allowing a local attacker who can write
    inside the keyvault tree to redirect ``decrypt`` to attacker-placed
    bytes."""

    def test_refuses_symlinked_key_directory_on_decrypt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        tmp_path: Path,
    ) -> None:
        log, sink = captured_audit
        # Set up a normal envelope first.
        eid = api.encrypt(registered_key, b"secret", "purpose", backend=backend, audit_sink=sink, home=home)
        # Swap the key directory for a symlink pointing at attacker territory.
        attacker = tmp_path / "attacker"
        attacker.mkdir(mode=0o700)
        kid_hex = _key_id_hash(registered_key).hex()
        kid_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex
        # rmtree the real dir, replace with symlink.
        import shutil

        shutil.rmtree(kid_dir)
        kid_dir.symlink_to(attacker)
        before_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        with pytest.raises(_storage.KeyvaultPermissionError):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        after_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        # No ecdh: refused before any wrap-layer call.
        assert after_ecdh == before_ecdh
        # No audit emit at the api layer.
        assert log == []

    def test_refuses_symlinked_purpose_directory_on_decrypt(
        self,
        registered_key: str,
        backend: FakeBackend,
        home: Path,
        captured_audit: tuple[list[dict[str, Any]], Any],
        tmp_path: Path,
    ) -> None:
        log, sink = captured_audit
        eid = api.encrypt(registered_key, b"secret", "purpose", backend=backend, audit_sink=sink, home=home)
        attacker = tmp_path / "attacker"
        attacker.mkdir(mode=0o700)
        kid_hex = _key_id_hash(registered_key).hex()
        purpose_hex = _purpose_hash("purpose").hex()
        purpose_dir = home / "mordred" / "keyvault" / "ciphertexts" / kid_hex / purpose_hex
        import shutil

        shutil.rmtree(purpose_dir)
        purpose_dir.symlink_to(attacker)
        before_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        with pytest.raises(_storage.KeyvaultPermissionError):
            api.decrypt(registered_key, eid, "purpose", backend=backend, audit_sink=sink, home=home)
        after_ecdh = sum(1 for op, _ in backend.calls if op == "ecdh")
        assert after_ecdh == before_ecdh
        assert log == []


# ----------------------------- helpers -----------------------------


def _envelope_path(home: Path, key_id: str, purpose: str, envelope_id: str) -> Path:
    return (
        home
        / "mordred"
        / "keyvault"
        / "ciphertexts"
        / _key_id_hash(key_id).hex()
        / _purpose_hash(purpose).hex()
        / f"{envelope_id}.gcm"
    )


def _read_envelope(home: Path, key_id: str, purpose: str, envelope_id: str) -> bytes:
    return _storage.safe_read(_envelope_path(home, key_id, purpose, envelope_id))
