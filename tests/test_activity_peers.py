"""Activity peer credentials: code lifecycle, token at rest, revocation, fingerprints."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mordred_hermes.activity import peers
from mordred_hermes.extension import pairing
from mordred_hermes.extension.crypto import b64u_encode, x25519_public_raw


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    return tmp_path


def _read(name: str) -> dict:
    return json.loads((pairing._ext_dir() / name).read_text("utf-8"))


def test_pair_code_lifecycle_mints_a_peer_and_is_single_use():
    code, expires_at = peers.generate_peer_code("laptop")
    assert expires_at - time.time() == pytest.approx(600, abs=5)
    assert peers.pair_outcome(code) == ("pending", None)

    result = peers.handle_pair_init(code, "peer-chosen label")
    assert result["peer_id"].startswith("operator:")
    assert len(result["peer_id"].split(":", 1)[1]) == 12
    assert peers.pair_outcome(code) == ("paired", None)

    with pytest.raises(peers.PeerPairError) as second:
        peers.handle_pair_init(code)
    assert second.value.reason == "used_code"

    principal = peers.authenticate(result["peer_token"])
    assert principal == peers.PeerPrincipal(peer_id=result["peer_id"], kind="operator")
    assert principal.trust == "paired_peer" and principal.permitted_use == "learning"
    # The operator's label wins; the wire label is a peer-supplied hint.
    assert [row["label"] for row in peers.list_peers()] == ["laptop"]


def test_code_is_accepted_in_any_case_and_spacing():
    code, _ = peers.generate_peer_code()
    sloppy = code.lower().replace("-", " ")
    assert peers.handle_pair_init(sloppy)["peer_id"].startswith("operator:")


def test_unknown_and_malformed_codes_are_invalid():
    for bad in ("MORT-AAAAAAAA-AAAAAAAA", "", None, 42):
        with pytest.raises(peers.PeerPairError) as exc:
            peers.handle_pair_init(bad)
        assert exc.value.reason == "invalid_code"


def test_expired_code_is_refused_and_reported(monkeypatch):
    code, _ = peers.generate_peer_code()
    real_time = time.time
    monkeypatch.setattr(peers.time, "time", lambda: real_time() + 601)
    with pytest.raises(peers.PeerPairError) as exc:
        peers.handle_pair_init(code)
    assert exc.value.reason == "expired_code"
    assert peers.pair_outcome(code) == ("failed", "expired_code")
    assert peers.list_peers() == []


def test_unused_expired_code_polls_as_expired(monkeypatch):
    code, _ = peers.generate_peer_code()
    real_time = time.time
    monkeypatch.setattr(peers.time, "time", lambda: real_time() + 601)
    assert peers.pair_outcome(code) == ("expired", None)


def test_revoked_code_cannot_pair():
    code, _ = peers.generate_peer_code()
    assert peers.revoke_peer_code(code) is True
    assert peers.revoke_peer_code(code) is False
    with pytest.raises(peers.PeerPairError) as exc:
        peers.handle_pair_init(code)
    assert exc.value.reason == "used_code"
    assert peers.pair_outcome(code) == ("failed", "cancelled")


def test_only_digests_are_stored_at_rest():
    code, _ = peers.generate_peer_code()
    result = peers.handle_pair_init(code)
    ext_dir = pairing._ext_dir()
    pending_raw = (ext_dir / "activity_pending.json").read_text("utf-8")
    peers_raw = (ext_dir / "activity_peers.json").read_text("utf-8")
    assert code not in pending_raw
    assert result["peer_token"] not in peers_raw
    record = _read("activity_peers.json")[result["peer_id"]]
    assert record["token_sha256"] == hashlib.sha256(result["peer_token"].encode()).hexdigest()
    assert all("token_sha256" not in row for row in peers.list_peers())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_files_are_private():
    code, _ = peers.generate_peer_code()
    peers.handle_pair_init(code)
    ext_dir = pairing._ext_dir()
    assert stat.S_IMODE(os.stat(ext_dir).st_mode) == 0o700
    for name in ("activity_pending.json", "activity_peers.json"):
        assert stat.S_IMODE(os.stat(ext_dir / name).st_mode) == 0o600


def test_wrong_and_non_string_tokens_are_refused():
    code, _ = peers.generate_peer_code()
    peers.handle_pair_init(code)
    assert peers.check_token("not-a-token") == (None, "invalid_token")
    assert peers.check_token(None) == (None, "invalid_token")
    assert peers.authenticate("") is None


def test_revoke_is_idempotent_and_refuses_the_token():
    code, _ = peers.generate_peer_code()
    result = peers.handle_pair_init(code)
    assert peers.revoke(result["peer_id"]) is True
    assert peers.revoke(result["peer_id"]) is False
    assert peers.revoke("operator:000000000000") is False
    assert peers.check_token(result["peer_token"]) == (None, "peer_revoked")
    [row] = peers.list_peers()
    assert row["revoked_at"] is not None


def test_fingerprint_tracks_revocation_per_peer():
    assert peers.fingerprint() is None
    first = peers.handle_pair_init(peers.generate_peer_code()[0])
    file_before = peers.fingerprint()
    peer_before = peers.fingerprint(first["peer_id"])
    assert file_before is not None and peer_before is not None

    # Pairing another peer changes the file but not this peer's record.
    second = peers.handle_pair_init(peers.generate_peer_code()[0])
    assert peers.fingerprint() != file_before
    assert peers.fingerprint(first["peer_id"]) == peer_before

    peers.revoke(first["peer_id"])
    assert peers.fingerprint(first["peer_id"]) is None
    assert peers.fingerprint(second["peer_id"]) is not None
    assert peers.fingerprint("operator:unknown") is None


def test_activity_code_does_not_pair_the_extension():
    code, _ = peers.generate_peer_code()
    ext_pub = b64u_encode(x25519_public_raw(X25519PrivateKey.generate()))
    with pytest.raises(pairing.PairError) as exc:
        pairing.handle_pair_init(code, ext_pub, b64u_encode(b"\x07" * 32))
    assert exc.value.reason == "invalid_code"
    assert pairing.load_pairing() is None
    # The activity code is still usable for its own purpose.
    assert peers.handle_pair_init(code)["peer_id"].startswith("operator:")


def test_extension_code_does_not_mint_an_activity_peer():
    code, _ = pairing.generate_code()
    with pytest.raises(peers.PeerPairError) as exc:
        peers.handle_pair_init(code)
    assert exc.value.reason == "invalid_code"
    assert peers.list_peers() == []
    assert pairing.pair_outcome(code) == ("pending", None)


def test_storage_failure_is_a_content_free_refusal(monkeypatch):
    code, _ = peers.generate_peer_code()

    real_write = pairing._write_private

    def failing_write(path, data):
        if path.name == "activity_peers.json":
            raise OSError("disk full")
        real_write(path, data)

    monkeypatch.setattr(pairing, "_write_private", failing_write)
    with pytest.raises(peers.PeerPairError) as exc:
        peers.handle_pair_init(code)
    assert exc.value.reason == "storage_refused"
    # The code is burned, not left reusable.
    assert peers.pair_outcome(code) == ("failed", "storage_refused")
