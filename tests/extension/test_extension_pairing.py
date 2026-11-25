"""Pairing handshake tests — simulate the extension side and verify the
gateway derives the same key, signs a verifiable attestation, and issues a
valid token."""

from __future__ import annotations

import json
import stat

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from mordred_hermes.extension import extension_crypto as xc
from mordred_hermes.extension import extension_pairing as pairing


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


def _webauthn_public_key_b64() -> str:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return xc.b64u_encode(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def test_pairing_store_refuses_symlinked_extension_directory(tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    extension = tmp_path / "extension"
    extension.symlink_to(target, target_is_directory=True)

    with pytest.raises(OSError, match="real directory"):
        pairing.ensure_master()

    assert not (target / "state.json").exists()
    assert not (target / ".lock").exists()


def test_missing_json_stores_keep_first_run_api_behaviour():
    """Genuine absence remains the compatible empty first-run state."""
    assert pairing.load_pairing() is None


@pytest.mark.parametrize("payload", [b"{not-json", b"[]"])
def test_master_creation_does_not_replace_corrupt_state_store(tmp_path, payload):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    state_path = extension / "state.json"
    pairing._write_private(state_path, payload)

    with pytest.raises(RuntimeError, match=r"state\.json.*unreadable or corrupt"):
        pairing.ensure_master()

    assert state_path.read_bytes() == payload


def test_json_store_with_unsafe_permissions_fails_closed(tmp_path):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    pending = extension / "state.json"
    pairing._write_private(pending, b"{}")
    pending.chmod(0o644)

    with pytest.raises(RuntimeError, match=r"state\.json.*unreadable or corrupt"):
        pairing.ensure_master()

    assert pending.read_bytes() == b"{}"
    assert stat.S_IMODE(pending.stat().st_mode) == 0o644


def test_json_store_symlink_is_not_followed_or_replaced(tmp_path):
    extension = tmp_path / "extension"
    extension.mkdir(mode=0o700)
    victim = tmp_path / "outside.json"
    victim.write_bytes(b'{"must":"survive"}')
    pending = extension / "state.json"
    pending.symlink_to(victim)

    with pytest.raises(RuntimeError, match=r"state\.json.*unreadable or corrupt"):
        pairing.ensure_master()

    assert pending.is_symlink()
    assert victim.read_bytes() == b'{"must":"survive"}'


def test_state_write_ignores_a_preplanted_tmp_symlink(tmp_path):
    """The state holds Hermes' master key. The old
    hand-rolled writer staged them at a *predictable* ``state.json.tmp`` opened
    without ``O_NOFOLLOW``, so a symlink pre-planted there redirected the secret
    (and left state.json a symlink). ``keyvault._storage.atomic_write`` uses a
    random tmp name + ``O_EXCL | O_NOFOLLOW``."""
    ext = tmp_path / "extension"
    ext.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (ext / "state.json.tmp").symlink_to(victim)

    pairing.ensure_master()

    assert victim.read_text() == "untouched"  # no write through the symlink
    state = ext / "state.json"
    assert state.is_file() and not state.is_symlink()
    assert stat.S_IMODE(state.lstat().st_mode) == 0o600


def test_extchat_key_is_never_persisted():
    """K_extchat is always derived from the master key (api._extchat_key); the
    dead load/save_extchat_key pair (and its state field) is gone."""
    assert not hasattr(pairing, "load_extchat_key")
    assert not hasattr(pairing, "save_extchat_key")


def _count_state_json_parses(monkeypatch) -> list[int]:
    """Patch ``pairing._read_json`` to count parses of state.json specifically
    (pending.json/webauthn.json reads are unaffected and uncounted)."""
    counter = [0]
    real_read_json = pairing._read_json

    def counting_read_json(path):
        if path == pairing._state_path():
            counter[0] += 1
        return real_read_json(path)

    monkeypatch.setattr(pairing, "_read_json", counting_read_json)
    return counter


def test_load_pairing_parses_state_once_per_generation(monkeypatch):
    """state.json carries the E2E replay cache and can reach several MB at
    capacity; repeated load_pairing() calls between writes must not re-parse
    it every time (PR #88 follow-up)."""
    pairing.ensure_master()

    counter = _count_state_json_parses(monkeypatch)

    first = pairing.load_pairing()
    for _ in range(4):
        assert pairing.load_pairing() == first

    assert counter[0] == 1


def test_pairing_state_cache_invalidates_on_each_owned_write_path():
    """Every write path this module owns (master creation, clear) must be
    visible on the very next read — never a stale
    generation, and this must not depend on the filesystem's mtime
    resolution advancing between two writes in the same test tick."""
    created = pairing.ensure_master()
    assert pairing.load_pairing() == created
    # A second call keeps the master: it never leaves Hermes and is never rotated here.
    assert pairing.ensure_master() == created

    pairing.clear_pairing()
    assert pairing.load_pairing() is None


def test_fields_left_by_the_removed_channel_transport_are_kept_unread():
    """``channel_keys`` / ``e2e_replay_v3`` from older releases survive a master write."""
    created = pairing.ensure_master()
    state = json.loads(pairing._state_path().read_text())
    state["channel_keys"] = {"C1": "AQ"}
    state["e2e_replay_v3"] = [{"id": "a" * 64, "accepted_at": 1.0}]
    pairing._write_private(pairing._state_path(), json.dumps(state).encode())
    pairing._invalidate_state_cache()

    assert pairing.load_pairing() == created
    pairing._save_pairing(created)
    after = json.loads(pairing._state_path().read_text())
    assert after["channel_keys"] == {"C1": "AQ"}
    assert after["e2e_replay_v3"] == [{"id": "a" * 64, "accepted_at": 1.0}]


def test_state_cache_reloads_after_a_write_outside_this_modules_helpers():
    """The cache must not serve content older than what is currently on disk
    even when this module's own write paths never ran — e.g. state.json
    restored from a backup by another process. This exercises the per-access
    (mtime, size) guard directly, bypassing every explicit invalidation call
    this module makes on its own write paths."""
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="first",
            ext_pubkey_b64="e",
            hermes_pubkey_b64="h",
            paired_at=1.0,
        )
    )
    loaded = pairing.load_pairing()
    assert loaded is not None
    assert loaded.ext_token == "first"

    # Bypass every helper that calls _invalidate_state_cache() and write
    # directly, as an external process replacing the file out from under this
    # one would. A longer token value also changes the file's size, so the
    # cache key differs regardless of the filesystem's mtime resolution.
    raw = pairing._read_json(pairing._state_path())
    raw["ext_token"] = "rewritten-externally-with-a-longer-token-value"
    pairing._write_private(pairing._state_path(), json.dumps(raw).encode("utf-8"))

    reloaded = pairing.load_pairing()
    assert reloaded is not None
    assert reloaded.ext_token == "rewritten-externally-with-a-longer-token-value"


def test_state_cache_does_not_republish_a_snapshot_a_write_invalidated(monkeypatch):
    """A reader descheduled past a concurrent write must not install its
    pre-write snapshot after that write's invalidation.

    Readers deliberately skip ``_state_lock()`` — that is the point of the fast
    path — so ``stat -> parse -> store`` is not atomic against a writer. The
    (mtime, size) key normally catches the resulting stale store on the *next*
    read, but that is exactly the filesystem-resolution dependency the explicit
    ``_invalidate_state_cache()`` calls exist to remove. Pinning the stat key
    here reproduces the pathological case (a write that leaves mtime_ns and
    size unchanged) so the generation guard, not the clock, is what is tested.
    """
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=b"\x01" * 32,
            ext_token="before-the-racing-write",
            ext_pubkey_b64="e",
            hermes_pubkey_b64="h",
            paired_at=1.0,
        )
    )
    pinned_key = (pairing._state_path(), 1, 1)
    monkeypatch.setattr(pairing, "_state_stat_key", lambda: pinned_key)
    pairing._invalidate_state_cache()

    real_read_json = pairing._read_json
    raced = [False]

    def read_json_then_let_a_write_land(path):
        data = real_read_json(path)
        if path == pairing._state_path() and not raced[0]:
            # The writer commits between our parse and our cache store. It runs
            # under _state_lock(), which this reader never took.
            raced[0] = True
            monkeypatch.setattr(pairing, "_read_json", real_read_json)
            pairing._save_pairing(
                pairing.Pairing(
                    aes_key=b"\x02" * 32,
                    ext_token="after-the-racing-write",
                    ext_pubkey_b64="e",
                    hermes_pubkey_b64="h",
                    paired_at=2.0,
                )
            )
        return data

    monkeypatch.setattr(pairing, "_read_json", read_json_then_let_a_write_land)
    stale = pairing.load_pairing()
    assert stale is not None
    assert raced[0] is True
    # The racing reader may legitimately return its own pre-write snapshot.
    # What it must not do is leave that snapshot in the cache for everyone else.
    assert stale.ext_token == "before-the-racing-write"

    fresh = pairing.load_pairing()
    assert fresh is not None
    assert fresh.ext_token == "after-the-racing-write"
