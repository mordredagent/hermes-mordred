"""Tests for the runtime env transparent-decrypt shim (design note §8.2 item 3).

``_runtime_env.inject_vault_env`` opens the at-rest vault on the **hot path**
(device key — Secure Enclave or its software fallback, no passphrase) and
injects the enrolled ``.env`` into a target environ mapping, so an unattended
Hermes process (telegram / gateway / cron) reads secrets from the vault instead
of plaintext on disk.

The vault is built with the shared software fakes (:class:`FakeBackend` does a
real P-256 ECDH; :class:`FakeAnchorStore` is an in-memory keychain), so the
whole init → enroll → hot-path-open → read path runs for real on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, _runtime_env, anchor, manifest, vault
from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorError
from mordred_hermes.wizard import vault_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"


class _ReadRaisesStore(FakeAnchorStore):
    """AnchorStore whose ``read`` raises a Keychain I/O error (not item-not-found)."""

    def read(self, label: str) -> bytes | None:
        raise KeychainAnchorError(-25308, "keychain locked")


def _init_vault_with_env(root: Path, backend: FakeBackend, store: FakeAnchorStore, env_bytes: bytes | None) -> None:
    """Materialize a real vault at ``root`` and (optionally) enroll ``.env``."""
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    opened = vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    )
    try:
        if env_bytes is not None:
            opened.enroll_file(".env", env_bytes)
    finally:
        opened.close()


class TestVaultIdentity:
    """The runtime shim must open the SAME vault that ``init`` / ``migrate`` created."""

    def test_identity_matches_vault_cli(self) -> None:
        root = Path("/some/where/mordred/vault")
        assert _identity.vault_identity(root) == vault_cli._vault_identity(root)

    def test_default_root_under_hermes_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_identity, "_hermes_home", lambda: tmp_path)
        assert _identity.default_vault_root() == tmp_path / "mordred" / "vault"

    def test_default_root_matches_vault_cli_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_identity, "_hermes_home", lambda: tmp_path)
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: tmp_path)
        assert _identity.default_vault_root() == vault_cli._resolve_root(None)


class TestInjectVaultEnv:
    def test_injects_decrypted_env_vars(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n")
        environ: dict[str, str] = {}

        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 2
        assert environ["ANTHROPIC_API_KEY"] == "sk-secret"
        assert environ["FOO"] == "bar"

    def test_overrides_existing_like_dotenv(self, tmp_path: Path) -> None:
        """The vault .env is authoritative, matching load_hermes_dotenv(override=True)."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")
        environ = {"FOO": "stale", "KEEP": "me"}

        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 1
        assert environ["FOO"] == "bar"  # overridden
        assert environ["KEEP"] == "me"  # untouched

    def test_no_vault_is_noop(self, tmp_path: Path) -> None:
        environ = {"X": "1"}
        n = _runtime_env.inject_vault_env(
            root=tmp_path / "v", environ=environ, backend=FakeBackend(), store=FakeAnchorStore()
        )
        assert n == 0
        assert environ == {"X": "1"}

    def test_missing_env_name_is_noop(self, tmp_path: Path) -> None:
        """A vault with no enrolled .env injects nothing — not an error."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, None)  # init only, no .env enrolled
        environ = {"X": "1"}
        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 0
        assert environ == {"X": "1"}

    def test_keychain_read_error_fails_closed(self, tmp_path: Path) -> None:
        """A Keychain failure while probing the anchor must propagate, never silently no-op."""
        environ: dict[str, str] = {}
        with pytest.raises(anchor.AnchorError):
            _runtime_env.inject_vault_env(
                root=tmp_path / "v", environ=environ, backend=FakeBackend(), store=_ReadRaisesStore()
            )
        assert environ == {}

    def test_tampered_manifest_fails_closed(self, tmp_path: Path) -> None:
        """A present-but-tampered vault must fail closed (raise), never inject stale/empty."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")  # generation 1
        mpath = root / "manifest.1.mvmf"
        raw = bytearray(mpath.read_bytes())
        raw[-1] ^= 0x01  # flip a trailing (MAC) bit
        mpath.write_bytes(bytes(raw))

        environ: dict[str, str] = {}
        with pytest.raises((manifest.ManifestError, vault.VaultError, anchor.AnchorError)):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_anchor_absent_with_disk_artifacts_fails_closed(self, tmp_path: Path) -> None:
        """Manifests on disk but the device anchor gone → fail closed.

        Silently no-oping would let an anchor-delete downgrade the process to
        whatever plaintext remains (e.g. an un-shredded ``.env``).
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")
        store.delete(_identity.vault_identity(root))  # drop the anchor, keep manifests
        assert list(root.glob("manifest.*.mvmf"))  # vault artifacts remain on disk

        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_non_utf8_payload_fails_closed(self, tmp_path: Path) -> None:
        """A non-UTF-8 enrolled ``.env`` raises a domain VaultError, not a raw decode error."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"\xff\xfe\x00not utf-8")
        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_blob_corruption_fails_closed(self, tmp_path: Path) -> None:
        """A corrupted blob fails its content-address / AEAD check on read — fail closed."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")
        blobs = list((root / "blobs").glob("*.blob"))
        assert blobs
        raw = bytearray(blobs[0].read_bytes())
        raw[-1] ^= 0x01
        blobs[0].write_bytes(bytes(raw))

        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_does_not_interpolate_dollar_values(self, tmp_path: Path) -> None:
        """Secret values are injected verbatim — no ``${VAR}`` dotenv interpolation."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\nBAZ=${FOO}/x\n")
        environ: dict[str, str] = {}
        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 2
        assert environ["FOO"] == "bar"
        assert environ["BAZ"] == "${FOO}/x"  # literal, not the interpolated "bar/x"


class TestInstallVaultEnvDecrypt:
    def test_noop_off_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_runtime_env.sys, "platform", "linux")
        called = False

        def _spy(**_: object) -> int:
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)
        assert _runtime_env.install_vault_env_decrypt(environ={}) == 0
        assert called is False  # the device-key path is never touched off macOS

    def test_delegates_on_darwin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        seen: dict[str, object] = {}

        def _spy(*, root: Path, environ: dict[str, str], **_: object) -> int:
            seen["root"] = root
            seen["environ"] = environ
            return 3

        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)
        env: dict[str, str] = {}
        assert _runtime_env.install_vault_env_decrypt(environ=env) == 3
        assert seen["root"] == tmp_path / "v"
        assert seen["environ"] is env


class TestRegister:
    """The mordred_keyvault plugin entry point installs the shim at discovery."""

    def test_register_installs_env_decrypt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        called = False

        def _spy(**_: object) -> int:
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(_runtime_env, "install_vault_env_decrypt", _spy)
        keyvault.register(object())  # ctx is unused by this plugin
        assert called is True
