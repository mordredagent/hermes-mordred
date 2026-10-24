"""Integration: vault ``.env`` → env shim → usable ``HERMES_MEMORY_KEY``.

The Mordred-owned memory hook consumes this key on macOS env/vault custody
paths. This module proves vault injection and the 32-byte AES-256-GCM key
contract using portable software fakes. The real upstream memory read/write,
mutation, refusal and backup paths are exercised in the memory-hook canary.
Linux TPM and Windows CNG custody use their dedicated engines.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mordred_hermes.keyvault import _identity, _runtime_env, vault
from mordred_hermes.wizard import vault_memory_key

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

if TYPE_CHECKING:
    from mordred_hermes._database_lifecycle import ExclusiveLease

_PASSPHRASE = "correct horse battery staple"
# Matches Mordred memory_crypto filename-bound AAD: "hermes-memory-v1:<name>".
_MEMORY_AAD = b"hermes-memory-v1:MEMORY.md"


@pytest.fixture(autouse=True)
def _isolate_ambient_memory_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No ambient HERMES_MEMORY_KEY: clear the env var and point the Hermes home at an
    empty dir, so ``set_memory_key`` mints a fresh key here instead of adopting one
    from the developer's real ``~/.hermes/.env`` (keeps these tests hermetic)."""
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: tmp_path)
    from mordred_hermes.keyvault import kek, vault_master

    audit = []
    monkeypatch.setattr(kek, "_noop_audit", audit.append)
    monkeypatch.setattr(vault_master, "_noop_audit", audit.append)


def _init_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    """Materialize a real (empty) vault at ``root`` under the software fakes."""
    key_id = anchor_label = _identity.vault_identity(root)
    from mordred_hermes.wizard._vault_lifecycle import _initialization_lease

    with _initialization_lease(root) as lease:
        backend.generate_enclave_key(key_id)
        vault.init_vault(
            root,
            key_id=key_id,
            passphrase=_PASSPHRASE,
            backend=backend,
            store=store,
            anchor_label=anchor_label,
            database_lease=lease,
        ).close()


def _enroll_env(
    root: Path,
    backend: FakeBackend,
    store: FakeAnchorStore,
    env_bytes: bytes,
    *,
    database_lease: ExclusiveLease | None = None,
) -> None:
    """Enroll ``.env`` into the vault at ``root`` (hot path)."""
    key_id = anchor_label = _identity.vault_identity(root)
    opened = vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label)
    try:
        opened.enroll_file(".env", env_bytes, database_lease=database_lease)
    finally:
        opened.close()


def _decode_memory_key(value: str) -> bytes:
    """Decode a URL-safe base64 ``HERMES_MEMORY_KEY`` value (upstream padding rule)."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _assert_usable_aes256_memory_key(value: str) -> None:
    """Assert ``value`` is a 32-byte key that drives an AES-256-GCM memory round-trip."""
    key = _decode_memory_key(value)
    assert len(key) == 32  # AES-256
    aes = AESGCM(key)
    nonce = bytes(12)
    ciphertext = aes.encrypt(nonce, b"a memory entry", _MEMORY_AAD)
    assert aes.decrypt(nonce, ciphertext, _MEMORY_AAD) == b"a memory entry"


class TestVaultEnvToMemoryKey:
    """A vault-enrolled ``HERMES_MEMORY_KEY`` is injected and usable for memory encryption."""

    def test_manually_enrolled_key_injects_and_is_usable(self, tmp_path: Path) -> None:
        root = tmp_path / "mordred/vault"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)
        memory_key = base64.urlsafe_b64encode(b"\x11" * 32).decode("ascii")
        from mordred_hermes.keyvault._database_mutation import database_key_mutation

        with database_key_mutation(root=tmp_path, generation=None) as lease:
            _enroll_env(
                root,
                backend,
                store,
                f"HERMES_MEMORY_KEY={memory_key}\nFOO=bar\n".encode(),
                database_lease=lease,
            )

        environ: dict[str, str] = {}
        _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)

        assert environ["HERMES_MEMORY_KEY"] == memory_key
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])

    def test_set_memory_key_then_inject_end_to_end(self, tmp_path: Path) -> None:
        """The on-ramp + the runtime shim compose: set the key, then inject it."""
        root = tmp_path / "mordred/vault"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 0

        environ: dict[str, str] = {}
        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 1
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])

    def test_set_memory_key_preserves_other_env_vars(self, tmp_path: Path) -> None:
        """Adding the memory key must not drop existing vault ``.env`` entries."""
        root = tmp_path / "mordred/vault"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault(root, backend, store)
        _enroll_env(root, backend, store, b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n")

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0

        environ: dict[str, str] = {}
        _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ["ANTHROPIC_API_KEY"] == "sk-secret"
        assert environ["FOO"] == "bar"
        _assert_usable_aes256_memory_key(environ["HERMES_MEMORY_KEY"])


def test_custom_vault_memory_source_refuses_even_with_real_home_lease(tmp_path: Path) -> None:
    """A genuine lease cannot establish an arbitrary custom source's independence."""
    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes.keyvault._database_mutation import database_key_mutation

    root = tmp_path / "custom-vault"
    backend, store = FakeBackend(), FakeAnchorStore()
    _init_vault(root, backend, store)
    # An initial unrelated .env entry does not change the effective memory
    # source, so it remains supported without manufacturing a source lease.
    _enroll_env(root, backend, store, b"FOO=bar\n")
    before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    memory_key = base64.urlsafe_b64encode(b"\x22" * 32).decode("ascii")
    with database_key_mutation(root=tmp_path, generation=None) as lease, pytest.raises(DatabaseRefused):
        _enroll_env(root, backend, store, f"HERMES_MEMORY_KEY={memory_key}\n".encode(), database_lease=lease)
    assert {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
    environ: dict[str, str] = {}
    assert _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store) == 1
    assert environ == {"FOO": "bar"}
