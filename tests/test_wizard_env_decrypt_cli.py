"""Tests for ``hermes mordred encryption {enable,disable,purge} env``.

The ``.env`` target completes the toggle model config.yaml already has, but with
``.env``'s **memory-only** runtime injection (the plaintext is removed on enable;
the startup shim injects from the vault into ``os.environ``, never re-writing
plaintext). Three states:

- **enable**  → enroll ``<home>/.env`` into the vault; on macOS remove the
  plaintext (no secret at rest) and clear the opt-out marker so the runtime
  injects.
- **disable** → restore a readable plaintext ``<home>/.env`` (conflict-safe) and
  write the opt-out marker so the runtime stops injecting — *reversible*, the
  vault copy is kept.
- **purge**   → restore the plaintext, then ``unenroll_file('.env')`` from the
  vault and clear the marker — *destructive*, back to plain unencrypted.

The runtime shim (:func:`...keyvault._runtime_env.install_vault_env_decrypt`)
honors the opt-out marker: a disabled env target is not injected even when still
enrolled.

Built on the software fakes so the real init → enroll → hot-path-open path runs
on any platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, _runtime_env, vault
from mordred_hermes.keyvault._runtime_env import _env_optout_marker_path
from mordred_hermes.wizard import env_decrypt_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
_ENV_A = b"ANTHROPIC_API_KEY=sk-secret\n"
_ENV_B = b"ANTHROPIC_API_KEY=sk-other\n"


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _vault_env(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file(".env") if ".env" in opened.list_files() else None


# -----------------------------------------------------------------------------
# enable
# -----------------------------------------------------------------------------
class TestEnable:
    def test_enrolls_and_removes_plaintext_on_macos(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        assert not (home / ".env").exists()  # no plaintext at rest on macOS
        assert not _env_optout_marker_path(home).exists()  # injection ON

    def test_keeps_plaintext_off_macos(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="linux", backend=backend, store=store)
        assert rc == 0
        assert _vault_env(root, backend, store) == _ENV_A  # enrolled
        # the runtime shim is a no-op off darwin, so removing the plaintext would
        # strand Hermes — keep it (status reports "inactive on this OS").
        assert (home / ".env").read_bytes() == _ENV_A

    def test_missing_env_is_error(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 1
        assert _vault_env(root, backend, store) is None

    def test_keeps_plaintext_if_disk_diverges_from_vault(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """macOS enable must not delete a plaintext that does not match the enrolled bytes."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        # simulate the enrolled copy differing from what is on disk at unlink time
        monkeypatch.setattr(env_decrypt_cli, "_read_vault_env", lambda *_a, **_k: _ENV_B)

        rc = env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # plaintext NOT deleted
        assert "leaving the plaintext" in capsys.readouterr().err.lower()

    def test_clears_optout_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")

        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert not marker.exists()


# -----------------------------------------------------------------------------
# disable (reversible)
# -----------------------------------------------------------------------------
class TestDisable:
    def test_restores_plaintext_and_writes_marker(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        assert not (home / ".env").exists()  # sealed by enable

        rc = env_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # recovered from the vault
        assert _env_optout_marker_path(home).exists()  # injection OFF
        assert _vault_env(root, backend, store) == _ENV_A  # vault copy kept (reversible)

    def test_keeps_diverging_plaintext_and_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        # operator put a DIFFERENT plaintext back by hand
        (home / ".env").write_bytes(_ENV_B)

        rc = env_decrypt_cli.disable(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_B  # never silently overwritten
        assert "drift" in capsys.readouterr().err.lower()

    def test_idempotent_unmanaged(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        rc = env_decrypt_cli.disable(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0


# -----------------------------------------------------------------------------
# purge (destructive)
# -----------------------------------------------------------------------------
class TestPurge:
    def test_unenrolls_and_restores_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)

        rc = env_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_A  # secret not lost
        assert _vault_env(root, backend, store) is None  # removed from the vault
        assert not _env_optout_marker_path(home).exists()

    def test_backs_up_diverging_vault_copy_before_purge(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The vault copy must never be destroyed silently when it differs from disk."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        (home / ".env").write_bytes(_ENV_A)
        env_decrypt_cli.enable(home=home, root=root, platform="darwin", backend=backend, store=store)
        # operator put a DIFFERENT plaintext back by hand before purging
        (home / ".env").write_bytes(_ENV_B)

        rc = env_decrypt_cli.purge(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == _ENV_B  # on-disk kept
        assert (home / ".env.vault-purged").read_bytes() == _ENV_A  # vault copy preserved, not lost
        assert _vault_env(root, backend, store) is None
        assert "vault-purged" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# runtime shim honors the opt-out marker
# -----------------------------------------------------------------------------
class TestRuntimeOptOut:
    def test_install_skips_when_optout_marker_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")

        called = {"inject": False}

        def _spy(**_: object) -> int:
            called["inject"] = True
            return 5

        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: home)
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)

        assert _runtime_env.install_vault_env_decrypt(environ={}) == 0
        assert called["inject"] is False  # opt-out → never opens the vault

    def test_install_injects_when_marker_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        called = {"inject": False}

        def _spy(**_: object) -> int:
            called["inject"] = True
            return 3

        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: home)
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)

        assert _runtime_env.install_vault_env_decrypt(environ={}) == 3
        assert called["inject"] is True
