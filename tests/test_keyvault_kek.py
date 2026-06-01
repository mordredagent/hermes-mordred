"""Tests for the KEK (key-encryption-key) master-key helper.

The KEK pattern: wrap one random 32-byte master key under the Secure
Enclave wrapping key *once* (:func:`kek.seal_master_key`), persist the
opaque blob (e.g. base64 in ``.env``), then unwrap it *once* per session
(:func:`kek.open_master_key`) and run all bulk data crypto in software
AES-GCM via the returned :class:`kek.MasterKey`. The Enclave is the root
of trust at rest + device binding; the master key only touches RAM.

These run cross-platform: a software :class:`FakeBackend` (real P-256
ECDH, no Secure Enclave) drives the wrap/unwrap path, so the whole KEK
layer is exercised on Linux CI too.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from mordred_hermes.keyvault import kek
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound

from ._keyvault_fakes import FakeBackend

_KEY_ID = "kek-test-key"


@pytest.fixture
def backend() -> FakeBackend:
    b = FakeBackend()
    b.generate_enclave_key(_KEY_ID)
    return b


# ---------------------------------------------------------------------------
# seal_master_key
# ---------------------------------------------------------------------------


def test_seal_returns_opaque_blob(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    assert isinstance(wrapped, bytes)
    # The wrap blob is the 127-byte MRKW envelope from wrap.wrap_dek.
    assert len(wrapped) == 127


def test_seal_produces_distinct_blobs_each_call(backend: FakeBackend) -> None:
    # Each seal generates a fresh random master key AND a fresh ephemeral
    # keypair, so two blobs must differ.
    a = kek.seal_master_key(_KEY_ID, backend=backend)
    b = kek.seal_master_key(_KEY_ID, backend=backend)
    assert a != b


def test_seal_unknown_key_raises(backend: FakeBackend) -> None:
    with pytest.raises(WrapKeyNotFound):
        kek.seal_master_key("no-such-key", backend=backend)


# ---------------------------------------------------------------------------
# open_master_key + MasterKey round-trips
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    blob = mk.encrypt(b"hello world")
    assert mk.decrypt(blob) == b"hello world"


def test_blob_differs_from_plaintext(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    plaintext = b"super secret value"
    blob = mk.encrypt(plaintext)
    assert plaintext not in blob


def test_same_wrapped_blob_opens_to_same_master_key(backend: FakeBackend) -> None:
    # Journey: data encrypted in one session must decrypt in a later one,
    # because the same wrapped blob always unwraps to the same master key.
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk1 = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    mk2 = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    blob = mk1.encrypt(b"cross-session payload")
    assert mk2.decrypt(blob) == b"cross-session payload"


def test_distinct_seals_yield_independent_keys(backend: FakeBackend) -> None:
    # Two separately sealed master keys must NOT decrypt each other's data.
    w1 = kek.seal_master_key(_KEY_ID, backend=backend)
    w2 = kek.seal_master_key(_KEY_ID, backend=backend)
    mk1 = kek.open_master_key(w1, _KEY_ID, backend=backend)
    mk2 = kek.open_master_key(w2, _KEY_ID, backend=backend)
    blob = mk1.encrypt(b"x")
    with pytest.raises(InvalidTag):
        mk2.decrypt(blob)


def test_empty_plaintext_roundtrips(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    assert mk.decrypt(mk.encrypt(b"")) == b""


def test_large_plaintext_roundtrips(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    payload = b"A" * (1024 * 1024)  # 1 MiB — bulk path
    assert mk.decrypt(mk.encrypt(payload)) == payload


def test_open_unknown_key_raises(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    fresh = FakeBackend()  # has no key
    with pytest.raises(WrapKeyNotFound):
        kek.open_master_key(wrapped, _KEY_ID, backend=fresh)


# ---------------------------------------------------------------------------
# AAD binding
# ---------------------------------------------------------------------------


def test_aad_roundtrip(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    blob = mk.encrypt(b"payload", aad=b"context-v1")
    assert mk.decrypt(blob, aad=b"context-v1") == b"payload"


def test_aad_mismatch_fails(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    blob = mk.encrypt(b"payload", aad=b"context-v1")
    with pytest.raises(InvalidTag):
        mk.decrypt(blob, aad=b"context-v2")


def test_tampered_ciphertext_fails(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    blob = bytearray(mk.encrypt(b"payload"))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(InvalidTag):
        mk.decrypt(bytes(blob))


# ---------------------------------------------------------------------------
# Lifecycle: close / context manager
# ---------------------------------------------------------------------------


def test_close_blocks_further_use(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    mk.close()
    with pytest.raises(ValueError):
        mk.encrypt(b"x")
    with pytest.raises(ValueError):
        mk.decrypt(b"x")


def test_close_is_idempotent(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    mk.close()
    mk.close()  # must not raise


def test_context_manager_closes_on_exit(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    with kek.open_master_key(wrapped, _KEY_ID, backend=backend) as mk:
        blob = mk.encrypt(b"inside")
        assert mk.decrypt(blob) == b"inside"
    with pytest.raises(ValueError):
        mk.encrypt(b"after")


# ---------------------------------------------------------------------------
# Audit: open is the single Enclave authorization point
# ---------------------------------------------------------------------------


def test_open_emits_authorization_audit(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    audit: list[dict[str, object]] = []
    kek.open_master_key(wrapped, _KEY_ID, backend=backend, audit_sink=audit.append)
    assert audit and audit[-1]["reason"] == "keyvault.unwrap_authorized"


def test_seal_does_not_emit_audit(backend: FakeBackend) -> None:
    # Sealing uses only the public key (wrap_dek) — no authorization, no audit.
    audit: list[dict[str, object]] = []
    backend.calls.clear()
    kek.seal_master_key(_KEY_ID, backend=backend)
    assert audit == []
    # And it must not have triggered an ECDH (the authorization op).
    assert not any(call[0] == "ecdh" for call in backend.calls)


# ---------------------------------------------------------------------------
# MAC — domain-separated authentication keyed by the master (manifest use)
# ---------------------------------------------------------------------------


def test_mac_is_deterministic_and_32_bytes(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    tag = mk.mac(b"manifest-body", info=b"mordred-manifest-v1")
    assert isinstance(tag, bytes) and len(tag) == 32
    assert mk.mac(b"manifest-body", info=b"mordred-manifest-v1") == tag


def test_mac_differs_by_data(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    info = b"mordred-manifest-v1"
    assert mk.mac(b"body-a", info=info) != mk.mac(b"body-b", info=info)


def test_mac_differs_by_info(backend: FakeBackend) -> None:
    # Domain separation: same data under different info must not collide.
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    assert mk.mac(b"body", info=b"purpose-a") != mk.mac(b"body", info=b"purpose-b")


def test_mac_differs_by_master(backend: FakeBackend) -> None:
    w1 = kek.seal_master_key(_KEY_ID, backend=backend)
    w2 = kek.seal_master_key(_KEY_ID, backend=backend)
    mk1 = kek.open_master_key(w1, _KEY_ID, backend=backend)
    mk2 = kek.open_master_key(w2, _KEY_ID, backend=backend)
    assert mk1.mac(b"body", info=b"i") != mk2.mac(b"body", info=b"i")


def test_mac_after_close_raises(backend: FakeBackend) -> None:
    wrapped = kek.seal_master_key(_KEY_ID, backend=backend)
    mk = kek.open_master_key(wrapped, _KEY_ID, backend=backend)
    mk.close()
    with pytest.raises(ValueError):
        mk.mac(b"body", info=b"i")
