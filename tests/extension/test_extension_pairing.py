"""Pairing handshake tests — simulate the extension side and verify the
gateway derives the same key, signs a verifiable attestation, and issues a
valid token."""

from __future__ import annotations

import stat

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))


def _verify_attestation(challenge: bytes, se_pubkey_b64: str, signed_b64: str) -> bool:
    pub = load_der_public_key(xc.b64u_decode(se_pubkey_b64))
    raw = xc.b64u_decode(signed_b64)
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, pairing.ATTEST_CONTEXT + challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def test_full_pairing_handshake():
    code, _exp = pairing.generate_code()
    assert code.startswith("MORT-")

    # Extension side
    ext_priv = X25519PrivateKey.generate()
    ext_pub_b64 = xc.b64u_encode(xc.x25519_public_raw(ext_priv))
    challenge = b"\x11" * 32

    result = pairing.handle_pair_init(code, ext_pub_b64, xc.b64u_encode(challenge))

    # Attestation verifies against the returned SE pubkey
    att = result["attestation"]
    assert _verify_attestation(challenge, att["se_pubkey"], att["signed_challenge"])

    # Both sides derive the same AES key
    ext_key = xc.derive_shared_key(ext_priv, result["hermes_pubkey"], code)
    stored = pairing.load_pairing()
    assert stored is not None
    assert stored.aes_key == ext_key

    # Token round-trips
    assert pairing.validate_token(result["ext_token"]) is True
    assert pairing.validate_token("wrong") is False


def test_code_single_use():
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    ch = xc.b64u_encode(b"\x00" * 32)
    pairing.handle_pair_init(code, ext_pub, ch)
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init(code, ext_pub, ch)
    assert ei.value.reason == "already_used"


def test_invalid_code():
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init("MORT-AAAAAAAA-BBBBBBBB", ext_pub, xc.b64u_encode(b"\x00" * 32))
    assert ei.value.reason == "invalid_code"


def test_pair_outcome_lifecycle():
    """pending → paired, recorded on the pending entry for the polling CLI."""
    code, _ = pairing.generate_code()
    assert pairing.pair_outcome(code) == ("pending", None)

    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    assert pairing.pair_outcome(code) == ("paired", None)


def test_handshake_failure_after_consume_records_failed_outcome():
    """A pair_init that dies *after* claiming the code must not look paired:
    the CLI-visible outcome is ("failed", reason), no pairing is saved, and
    the code stays burned (single-use)."""
    code, _ = pairing.generate_code()
    with pytest.raises(pairing.PairError) as ei:
        pairing.handle_pair_init(code, "!!!not-a-key!!!", xc.b64u_encode(b"\x00" * 32))
    assert ei.value.reason == "invalid_pubkey"

    assert pairing.pair_outcome(code) == ("failed", "invalid_pubkey")
    assert pairing.load_pairing() is None
    with pytest.raises(pairing.PairError) as ei2:
        pairing.handle_pair_init(code, "!!!not-a-key!!!", xc.b64u_encode(b"\x00" * 32))
    assert ei2.value.reason == "already_used"


def test_invalid_challenge_records_failed_outcome():
    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError):
        pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x01"))  # < 16 bytes
    assert pairing.pair_outcome(code) == ("failed", "invalid_challenge")


def test_legacy_consumed_entry_reports_consumed():
    """An entry claimed by a server build that predates outcome recording
    (used=True, no result field) reads as 'consumed' — the CLI applies its
    grace fallback, not an immediate paired/failed verdict."""
    code, _ = pairing.generate_code()
    pairing._consume_code(code)
    assert pairing.pair_outcome(code) == ("consumed", None)


def test_normalize_code():
    assert pairing.normalize_code("mort-abcdefgh-jklmnpqr") == "MORT-ABCDEFGH-JKLMNPQR"
    # Strips ambiguous/garbage chars and re-groups.
    assert pairing.normalize_code("ABCDEFGHJKLMNPQR") == "MORT-ABCDEFGH-JKLMNPQR"


def test_state_write_ignores_a_preplanted_tmp_symlink(tmp_path):
    """The pairing state holds the shared AES key and the ext_token. The old
    hand-rolled writer staged them at a *predictable* ``state.json.tmp`` opened
    without ``O_NOFOLLOW``, so a symlink pre-planted there redirected the secret
    (and left state.json a symlink). ``keyvault._storage.atomic_write`` uses a
    random tmp name + ``O_EXCL | O_NOFOLLOW``."""
    ext = tmp_path / "extension"
    ext.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (ext / "state.json.tmp").symlink_to(victim)

    code, _ = pairing.generate_code()
    ext_pub = xc.b64u_encode(xc.x25519_public_raw(X25519PrivateKey.generate()))
    result = pairing.handle_pair_init(code, ext_pub, xc.b64u_encode(b"\x00" * 32))

    assert victim.read_text() == "untouched"  # no write through the symlink
    assert result["ext_token"] not in victim.read_text()
    state = ext / "state.json"
    assert state.is_file() and not state.is_symlink()
    assert stat.S_IMODE(state.lstat().st_mode) == 0o600


def test_extchat_key_is_never_persisted():
    """K_extchat is always derived from the master key (api._extchat_key); the
    dead load/save_extchat_key pair (and its state field) is gone."""
    assert not hasattr(pairing, "load_extchat_key")
    assert not hasattr(pairing, "save_extchat_key")


def test_consume_code_single_use_under_concurrency():
    """Racing pair_init frames must not consume the same one-time code twice
    (read-modify-write on pending.json is guarded by the state lock)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    code, _ = pairing.generate_code()
    n = 8
    barrier = threading.Barrier(n)

    def attempt(_i: int) -> str:
        barrier.wait()
        try:
            pairing._consume_code(code)
            return "ok"
        except pairing.PairError as e:
            return e.reason

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(attempt, range(n)))

    assert results.count("ok") == 1
    assert set(results) <= {"ok", "already_used"}
