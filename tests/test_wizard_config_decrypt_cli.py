"""Tests for ``hermes mordred vault {enable,disable}-config-decrypt`` (v2-F8 Phase 3).

The operator on-ramp for config.yaml at-rest: ``enable`` enrolls
``<home>/config.yaml`` into the vault and writes the opt-in marker the startup
hook keys on; ``disable`` removes the marker and guarantees a readable plaintext
config.yaml is back on disk (recovery), leaving the vault copy intact.

Built on the shared software fakes so the real init → enroll → hot-path-open path
runs on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.keyvault._config_bootstrap import _marker_path
from mordred_hermes.wizard import config_decrypt_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
_CONFIG = b"model: gpt-x\napi_key: should-stay-encrypted\n"


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _read_vault_config(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file("config.yaml") if "config.yaml" in opened.list_files() else None


class TestEnable:
    def test_enrolls_config_and_writes_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)

        rc = config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert _marker_path(home).exists()
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_missing_config_is_error_and_no_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        # no config.yaml on disk

        rc = config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)
        assert rc == 1
        assert not _marker_path(home).exists()

    def test_uninitialised_vault_is_error_and_no_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)
        # vault never initialised → enroll must fail and the marker must NOT be written
        rc = config_decrypt_cli.enable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert not _marker_path(home).exists()


class TestDisable:
    def test_removes_marker_keeps_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)

        rc = config_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext kept

    def test_recovers_plaintext_when_sealed_away(self, tmp_path: Path) -> None:
        """If the plaintext was sealed (removed) while managed, disable decrypts it back."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)
        (home / "config.yaml").unlink()  # simulate a sealed (reseal-on-exit) state

        rc = config_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # recovered from the vault

    def test_idempotent_without_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)  # plain, unmanaged
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0
        assert (home / "config.yaml").read_bytes() == _CONFIG

    def test_idempotent_unmanaged_empty_home(self, tmp_path: Path) -> None:
        """disable on a never-managed home (no marker, no config, no vault) is a clean no-op.

        It must NOT try to open a non-existent vault and report a misleading
        'run vault init' — there is simply nothing to un-manage."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0

    def test_recovery_open_failure_returns_1(self, tmp_path: Path) -> None:
        """marker present + plaintext sealed away, but the vault can't be opened → rc 1 (fail-closed)."""
        from mordred_hermes.keyvault._config_bootstrap import _marker_path

        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        marker = _marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        # config.yaml absent AND the vault was never initialised → hot-path open fails
        rc = config_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1


class TestPurge:
    def test_unenrolls_and_keeps_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)

        rc = config_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not _marker_path(home).exists()
        assert (home / "config.yaml").read_bytes() == _CONFIG  # plaintext kept
        assert _read_vault_config(root, backend, store) is None  # removed from the vault

    def test_restores_sealed_plaintext_then_unenrolls(self, tmp_path: Path) -> None:
        """Safe order: a sealed-away plaintext is recovered BEFORE the vault copy is dropped."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / "config.yaml").write_bytes(_CONFIG)
        config_decrypt_cli.enable(home=home, root=root, backend=backend, store=store)
        (home / "config.yaml").unlink()  # sealed (reseal-on-exit removed the plaintext)

        rc = config_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / "config.yaml").read_bytes() == _CONFIG  # recovered, not lost
        assert _read_vault_config(root, backend, store) is None

    def test_idempotent_unmanaged(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = config_decrypt_cli.purge(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0

    def test_refuses_when_managed_but_no_vault_and_no_plaintext(self, tmp_path: Path) -> None:
        """Marker present, plaintext absent, vault gone → don't silently drop into 'defaults'."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        marker = _marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        # no config.yaml on disk, no vault manifest at root
        rc = config_decrypt_cli.purge(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert _marker_path(home).exists()  # marker NOT dropped — fail-closed preserved


class TestCliAdapters:
    def test_cli_enable_resolves_home_and_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse

        seen: dict[str, object] = {}

        def _enable(*, home: Path, root: Path, **_: object) -> int:
            seen["home"], seen["root"] = home, root
            return 0

        monkeypatch.setattr(config_decrypt_cli, "_hermes_home", lambda: tmp_path / "home")
        monkeypatch.setattr(config_decrypt_cli, "enable", _enable)
        assert config_decrypt_cli.cli_enable(argparse.Namespace(root=None)) == 0
        assert seen["home"] == tmp_path / "home"
        assert seen["root"] == (tmp_path / "home" / "mordred" / "vault")

    def test_cli_disable_resolves_home_and_explicit_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import argparse

        seen: dict[str, object] = {}

        def _disable(*, home: Path, root: Path, **_: object) -> int:
            seen["home"], seen["root"] = home, root
            return 0

        monkeypatch.setattr(config_decrypt_cli, "_hermes_home", lambda: tmp_path / "home")
        monkeypatch.setattr(config_decrypt_cli, "disable", _disable)
        # an explicit --root overrides the home-derived default
        assert config_decrypt_cli.cli_disable(argparse.Namespace(root=str(tmp_path / "custom"))) == 0
        assert seen["home"] == tmp_path / "home"
        assert seen["root"] == (tmp_path / "custom")
