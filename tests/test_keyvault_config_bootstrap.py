"""Tests for the config.yaml at-rest transparent-decrypt bootstrap (design §8.2 / v2-F8).

Unlike the ``.env`` shim (:mod:`mordred_hermes.keyvault._runtime_env`), which
injects secrets into ``os.environ`` lazily, ``config.yaml`` is read *eagerly at
import time* by Hermes (``cli.py`` ``CLI_CONFIG = load_cli_config()`` and the
direct ``yaml.safe_load`` readers in ``hermes_time`` / ``rl_cli`` /
``hermes_logging``), before any plugin ``register()`` runs. So the vault-enrolled
``config.yaml`` must be **materialized to its on-disk path** before the
interpreter imports those modules, and **resealed** (re-enrolled if edited, then
removed) on exit — the "decrypt-on-start / reseal-on-stop" lifecycle.

The vault is built with the shared software fakes (:class:`FakeBackend` does a
real P-256 ECDH; :class:`FakeAnchorStore` is an in-memory keychain), so the whole
init → enroll → hot-path-open → read/write path runs for real on any platform.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _config_bootstrap, _identity, anchor, manifest, vault
from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorError

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
_CONFIG = b"model: gpt-x\napi_key: should-stay-encrypted\n"


class _ReadRaisesStore(FakeAnchorStore):
    """AnchorStore whose ``read`` raises a Keychain I/O error (not item-not-found)."""

    def read(self, label: str) -> bytes | None:
        raise KeychainAnchorError(-25308, "keychain locked")


def _init_vault_with_config(
    root: Path, backend: FakeBackend, store: FakeAnchorStore, config_bytes: bytes | None
) -> None:
    """Materialize a real vault at ``root`` and (optionally) enroll ``config.yaml``."""
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    opened = vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    )
    try:
        if config_bytes is not None:
            opened.enroll_file("config.yaml", config_bytes)
    finally:
        opened.close()


def _read_vault_config(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    """Decrypt the vault-enrolled ``config.yaml`` for assertions, or ``None`` if absent."""
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        if "config.yaml" not in opened.list_files():
            return None
        return opened.read_file("config.yaml")


def _write_marker(home: Path) -> Path:
    """Create the opt-in marker that puts config.yaml on the vault-managed lifecycle."""
    marker = _config_bootstrap._marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("vault-managed\n", encoding="utf-8")
    return marker


class TestMaterializeConfig:
    def test_no_marker_is_noop(self, tmp_path: Path) -> None:
        """Without the opt-in marker, the bootstrap never touches disk (Hermes unchanged)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)

        n = _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert n == 0
        assert not (home / "config.yaml").exists()

    def test_decrypts_to_disk_when_absent(self, tmp_path: Path) -> None:
        """marker + enrolled + no plaintext → decrypt the vault config.yaml onto disk."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)

        n = _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert (home / "config.yaml").read_bytes() == _CONFIG

    def test_materialized_file_is_0600(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)

        _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        mode = stat.S_IMODE((home / "config.yaml").stat().st_mode)
        assert mode == 0o600

    def test_identical_disk_is_idempotent(self, tmp_path: Path) -> None:
        """A plaintext already equal to the vault copy stays put — still 'present' (1)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        (home / "config.yaml").write_bytes(_CONFIG)

        n = _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert (home / "config.yaml").read_bytes() == _CONFIG
        # Vault unchanged (no spurious re-enroll → no new generation).
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_differing_disk_wins_and_resyncs_vault(self, tmp_path: Path) -> None:
        """An on-disk plaintext that differs (unclean prior exit / live edit) is authoritative:
        its bytes are re-enrolled into the vault, and the working copy is left in place."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        edited = b"model: gpt-x\napi_key: should-stay-encrypted\nvoice: on\n"
        (home / "config.yaml").write_bytes(edited)

        n = _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert (home / "config.yaml").read_bytes() == edited  # disk untouched
        assert _read_vault_config(root, backend, store) == edited  # vault re-synced to disk

    def test_disk_present_but_not_enrolled_resyncs_vault(self, tmp_path: Path) -> None:
        """A plaintext on disk with NO enrolled config (e.g. enable was interrupted before
        enroll, or the vault was re-created) is authoritative: it is synced into the vault."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, None)  # init only, nothing enrolled
        _write_marker(home)
        (home / "config.yaml").write_bytes(_CONFIG)

        n = _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert (home / "config.yaml").read_bytes() == _CONFIG  # disk kept
        assert _read_vault_config(root, backend, store) == _CONFIG  # now enrolled

    def test_marker_without_enrolled_config_fails_closed(self, tmp_path: Path) -> None:
        """marker present but nothing enrolled and no plaintext → a setup error, fail closed.

        Silently proceeding would start Hermes on default config without the
        operator's vault-managed settings — a downgrade we must surface."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, None)  # init only, no config enrolled
        _write_marker(home)

        with pytest.raises(vault.VaultError):
            _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert not (home / "config.yaml").exists()

    def test_no_vault_at_all_fails_closed(self, tmp_path: Path) -> None:
        """marker present but no vault was ever initialised (empty store, no manifests) → fail closed.

        Distinct from the anchor-deletion case (artifacts remain): here nothing
        exists, so the message points at `disable-config-decrypt` recovery."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        _write_marker(home)
        with pytest.raises(vault.VaultError, match="no vault exists"):
            _config_bootstrap.materialize_config(root=root, home=home, backend=FakeBackend(), store=FakeAnchorStore())
        assert not (home / "config.yaml").exists()

    def test_keychain_read_error_fails_closed(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        _write_marker(home)
        with pytest.raises(anchor.AnchorError):
            _config_bootstrap.materialize_config(root=root, home=home, backend=FakeBackend(), store=_ReadRaisesStore())
        assert not (home / "config.yaml").exists()

    def test_tampered_manifest_fails_closed(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        mpath = root / "manifest.1.mvmf"
        raw = bytearray(mpath.read_bytes())
        raw[-1] ^= 0x01
        mpath.write_bytes(bytes(raw))

        with pytest.raises((manifest.ManifestError, vault.VaultError, anchor.AnchorError)):
            _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)
        assert not (home / "config.yaml").exists()

    def test_anchor_absent_with_disk_artifacts_fails_closed(self, tmp_path: Path) -> None:
        """Manifests on disk but the device anchor gone → fail closed (anchor-delete downgrade)."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        store.delete(_identity.vault_identity(root))  # drop anchor, keep manifests
        assert list(root.glob("manifest.*.mvmf"))

        with pytest.raises(vault.VaultError):
            _config_bootstrap.materialize_config(root=root, home=home, backend=backend, store=store)


class TestResealConfig:
    def test_no_marker_is_noop(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / "config.yaml").write_bytes(_CONFIG)  # a plaintext, but not vault-managed
        backend, store = FakeBackend(), FakeAnchorStore()

        n = _config_bootstrap.reseal_config(root=root, home=home, backend=backend, store=store)
        assert n == 0
        assert (home / "config.yaml").exists()  # an unmanaged config is never deleted

    def test_no_plaintext_is_noop(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)

        n = _config_bootstrap.reseal_config(root=root, home=home, backend=backend, store=store)
        assert n == 0

    def test_unchanged_plaintext_is_removed(self, tmp_path: Path) -> None:
        """A working copy equal to the vault is just deleted — the vault already has it."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        (home / "config.yaml").write_bytes(_CONFIG)

        n = _config_bootstrap.reseal_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert not (home / "config.yaml").exists()
        assert _read_vault_config(root, backend, store) == _CONFIG

    def test_edited_plaintext_is_reenrolled_then_removed(self, tmp_path: Path) -> None:
        """Live edits during the session are persisted into the vault before the plaintext goes."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_config(root, backend, store, _CONFIG)
        _write_marker(home)
        edited = _CONFIG + b"voice: on\n"
        (home / "config.yaml").write_bytes(edited)

        n = _config_bootstrap.reseal_config(root=root, home=home, backend=backend, store=store)
        assert n == 1
        assert not (home / "config.yaml").exists()
        assert _read_vault_config(root, backend, store) == edited  # edits survived into the vault


class TestInstallConfigDecrypt:
    def test_noop_off_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_config_bootstrap.sys, "platform", "linux")
        called = False

        def _spy(**_: object) -> int:
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(_config_bootstrap, "materialize_config", _spy)
        assert _config_bootstrap.install_config_decrypt(home=Path("/nope")) == 0
        assert called is False  # the device-key path is never touched off macOS

    def test_delegates_and_registers_reseal_on_darwin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_config_bootstrap.sys, "platform", "darwin")
        monkeypatch.setattr(_config_bootstrap, "default_vault_root", lambda: tmp_path / "v")
        seen: dict[str, object] = {}

        def _materialize(*, root: Path, home: Path, **_: object) -> int:
            seen["root"], seen["home"] = root, home
            return 1

        registered: list[object] = []
        monkeypatch.setattr(_config_bootstrap, "materialize_config", _materialize)
        monkeypatch.setattr(_config_bootstrap.atexit, "register", lambda fn, *a, **k: registered.append(fn))

        assert _config_bootstrap.install_config_decrypt(home=tmp_path / "home") == 1
        assert seen["root"] == tmp_path / "v"
        assert seen["home"] == tmp_path / "home"
        assert registered, "reseal must be registered to run at interpreter exit"

    def test_home_defaults_to_hermes_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """install_config_decrypt() with no home resolves it from hermes_home()."""
        monkeypatch.setattr(_config_bootstrap.sys, "platform", "darwin")
        monkeypatch.setattr(_config_bootstrap, "hermes_home", lambda: tmp_path / "home")
        monkeypatch.setattr(_config_bootstrap, "default_vault_root", lambda: tmp_path / "v")
        seen: dict[str, object] = {}

        def _materialize(*, root: Path, home: Path, **_: object) -> int:
            seen["home"] = home
            return 0  # 0 → no atexit registration; we only assert the home default here

        monkeypatch.setattr(_config_bootstrap, "materialize_config", _materialize)
        assert _config_bootstrap.install_config_decrypt() == 0
        assert seen["home"] == tmp_path / "home"


class TestRecoveryHint:
    def test_uses_today_working_console_script(self) -> None:
        """The fail-closed recovery hint must use ``hermes-mordred`` — the console
        script wired today (``pyproject.toml`` ``[project.scripts]``). The
        ``hermes mordred ...`` form only works once Hermes 0.12+ wires entry-point
        CLIs, so emitting it would strand a user on the recovery path on current
        installs."""
        assert "hermes-mordred vault disable-config-decrypt" in _config_bootstrap._RECOVERY_HINT
        assert "hermes mordred " not in _config_bootstrap._RECOVERY_HINT


class TestConfigHookInstalled:
    """``config_hook_installed`` detects the force-included startup ``.pth`` in the
    interpreter's site-packages, so ``encryption status`` / ``enable`` can tell
    the operator whether their runtime will actually seal config.yaml (rather than
    only whether the opt-in marker is set)."""

    _PTH = "mordred_hermes_config_decrypt.pth"

    def test_present_pth_that_wires_bootstrap_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / self._PTH).write_text(
            "__import__('mordred_hermes._pth_bootstrap', fromlist=['run']).run()\n", encoding="utf-8"
        )
        assert _config_bootstrap.config_hook_installed(site_dirs=[str(tmp_path)]) is True

    def test_absent_pth_is_not_detected(self, tmp_path: Path) -> None:
        assert _config_bootstrap.config_hook_installed(site_dirs=[str(tmp_path)]) is False

    def test_same_named_pth_without_bootstrap_is_not_a_false_positive(self, tmp_path: Path) -> None:
        (tmp_path / self._PTH).write_text("import os  # unrelated .pth\n", encoding="utf-8")
        assert _config_bootstrap.config_hook_installed(site_dirs=[str(tmp_path)]) is False

    def test_scans_every_site_dir(self, tmp_path: Path) -> None:
        empty, has = tmp_path / "a", tmp_path / "b"
        empty.mkdir()
        has.mkdir()
        (has / self._PTH).write_text("__import__('mordred_hermes._pth_bootstrap')\n", encoding="utf-8")
        assert _config_bootstrap.config_hook_installed(site_dirs=[str(empty), str(has)]) is True
