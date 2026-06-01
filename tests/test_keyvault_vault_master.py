"""Tests for vault master double-seal (``vault_master``).

The vault has ONE master key, sealed two ways:

- **SE-wrap** (``wmk``) via the unattended Secure-Enclave wrapping key — the hot
  path. Carried in every ``MVLT`` file header; opened prompt-free at Hermes
  startup (B2 = unattended operation).
- **passphrase-wrap** (``recovery``) via Argon2id (PR2 ``MRKV`` backup) — the
  cold path. Recovers the same master when the Enclave is unavailable (SE loss,
  new machine).

The recovery blob's verification digest is ``SHA-256(wmk)``: non-secret,
recomputable at recovery time, and NOT passphrase-derived (so it is not an
offline passphrase oracle). It binds a recovery blob to its ``wmk``.

:class:`FakeBackend` performs a real P-256 ECDH so the seal/open path is genuine
on Linux CI; only the hardware Secure Enclave is stubbed.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from mordred_hermes.keyvault import file_container, kek, vault_master
from mordred_hermes.keyvault.recovery import RecoveryDigestMismatch

from ._keyvault_fakes import FakeBackend

_KEY_ID = "vault-master-test-key"
_PASS = "correct horse battery staple"


@pytest.fixture
def backend() -> FakeBackend:
    b = FakeBackend()
    b.generate_enclave_key(_KEY_ID)
    return b


def test_seal_returns_wmk_recovery_and_usable_master(backend: FakeBackend) -> None:
    sealed, master = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    assert sealed.recovery[:4] == b"MRKV"  # PR2 backup magic
    # the returned master is immediately usable
    blob = file_container.encode(master, b"x", key_id=_KEY_ID, wmk=sealed.wmk, name=".env")
    assert file_container.decode(blob, master, name=".env") == b"x"


def test_se_open_yields_same_master(backend: FakeBackend) -> None:
    """The wmk unwraps (via the Enclave) to the same master that sealed it."""
    sealed, master = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    blob = file_container.encode(master, b"secret-value", key_id=_KEY_ID, wmk=sealed.wmk, name=".env")
    se_master = kek.open_master_key(sealed.wmk, _KEY_ID, backend=backend)
    assert file_container.decode(blob, se_master, name=".env") == b"secret-value"


def test_passphrase_open_yields_same_master(backend: FakeBackend) -> None:
    """The recovery blob unwraps (via Argon2id) to the same master."""
    sealed, master = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    blob = file_container.encode(master, b"secret-value", key_id=_KEY_ID, wmk=sealed.wmk, name=".env")
    pp_master = vault_master.open_passphrase(sealed.recovery, _PASS, wmk=sealed.wmk)
    assert file_container.decode(blob, pp_master, name=".env") == b"secret-value"


def test_se_and_passphrase_paths_agree(backend: FakeBackend) -> None:
    """Both seals protect the SAME master — SE and passphrase decode identically."""
    sealed, master = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    blob = file_container.encode(master, b"payload", key_id=_KEY_ID, wmk=sealed.wmk, name="config.yaml")
    se = file_container.decode(blob, kek.open_master_key(sealed.wmk, _KEY_ID, backend=backend), name="config.yaml")
    pp = file_container.decode(
        blob, vault_master.open_passphrase(sealed.recovery, _PASS, wmk=sealed.wmk), name="config.yaml"
    )
    assert se == pp == b"payload"


def test_wrong_passphrase_rejected(backend: FakeBackend) -> None:
    """Correct wmk (digest passes) but wrong passphrase fails the AES-GCM tag."""
    sealed, _master = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    with pytest.raises(InvalidTag):
        vault_master.open_passphrase(sealed.recovery, "wrong-passphrase", wmk=sealed.wmk)


def test_recovery_bound_to_wmk(backend: FakeBackend) -> None:
    """A recovery blob must not open against a different wmk — verify-before-decrypt
    (RecoveryDigestMismatch) fires before any Argon2 cost is paid."""
    sealed_a, _a = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    sealed_b, _b = vault_master.seal(key_id=_KEY_ID, passphrase=_PASS, backend=backend)
    with pytest.raises(RecoveryDigestMismatch):
        vault_master.open_passphrase(sealed_a.recovery, _PASS, wmk=sealed_b.wmk)


def test_empty_passphrase_rejected(backend: FakeBackend) -> None:
    with pytest.raises(ValueError, match="passphrase"):
        vault_master.seal(key_id=_KEY_ID, passphrase="", backend=backend)
