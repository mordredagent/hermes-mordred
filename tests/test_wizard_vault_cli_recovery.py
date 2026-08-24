"""Vault CLI passphrase rotation and cross-device recovery tests."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import pytest

from mordred_hermes.keyvault import vault
from mordred_hermes.wizard import _vault_open, vault_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend
from ._wizard_vault_cli_helpers import _PASSPHRASE, _PromptIO, _ReadRaisesStore

_NEW_PASSPHRASE = "a brand new passphrase 2026"


def _build_at_cli_identity(
    root: Path, backend: FakeBackend, store: FakeAnchorStore, *, files: dict[str, bytes] | None = None
) -> None:
    """Build a real vault whose identity matches what the CLI derives from ``root``.

    ``vault_cli.change_passphrase`` derives key_id/anchor_label via
    ``_vault_identity(root)``; the fixed-id ``_build_vault`` helper would not
    match, so the device-key path needs this root-derived build (same ``backend``
    + ``store`` instances must be reused so the wrapping key and anchor persist).
    """
    ident = vault_cli._vault_identity(root)
    backend.generate_enclave_key(ident)
    opened = vault.init_vault(
        root, key_id=ident, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=ident
    )
    try:
        for name, plaintext in (files or {}).items():
            opened.enroll_file(name, plaintext)
    finally:
        opened.close()


class TestChangePassphrase:
    """`vault change-passphrase` — rotate the recovery passphrase, master unchanged."""

    def test_device_path_rotates_keeps_files_and_invalidates_old(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"SECRET=1\n"})

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0

        # The new passphrase opens the vault and the enrolled file is intact —
        # proof the master (and every blob) is unchanged, only the sidecar.
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"SECRET=1\n"
        finally:
            opened.close()

        # The old passphrase no longer opens it.
        with pytest.raises(InvalidTag):
            vault.recover_vault(root, _PASSPHRASE)

    def test_cold_path_rotation_with_old_passphrase(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"A=1\n"})
        ident = vault_cli._vault_identity(root)

        # Cold path: authorized by the current passphrase, device key unused.
        vault.change_passphrase(
            root,
            new_passphrase=_NEW_PASSPHRASE,
            old_passphrase=_PASSPHRASE,
            key_id=ident,
            anchor_label=ident,
        )
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"A=1\n"
        finally:
            opened.close()
        with pytest.raises(InvalidTag):
            vault.recover_vault(root, _PASSPHRASE)

    def test_cold_path_wrong_old_passphrase_raises_and_keeps_sidecar(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        ident = vault_cli._vault_identity(root)
        with pytest.raises(InvalidTag):
            vault.change_passphrase(
                root,
                new_passphrase=_NEW_PASSPHRASE,
                old_passphrase="the wrong current passphrase",
                key_id=ident,
                anchor_label=ident,
            )
        # The sidecar was not rewritten: the original passphrase still opens it.
        vault.recover_vault(root, _PASSPHRASE).close()

    def test_cli_falls_back_to_old_passphrase_when_device_unavailable(self, tmp_path: Path) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"Z=9\n"})

        # A store whose read raises makes the device path fail, forcing the CLI
        # fallback; the prompt then supplies the new passphrase twice, then the current one.
        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE, _PASSPHRASE]),
            backend=backend,
            store=_ReadRaisesStore(),
        )
        assert rc == 0
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"Z=9\n"
        finally:
            opened.close()

    def test_cli_empty_new_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        rc = vault_cli.change_passphrase(
            root=root, prompt_io=_PromptIO(passwords=["", ""]), backend=backend, store=store
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()
        vault.recover_vault(root, _PASSPHRASE).close()  # original passphrase still valid

    def test_cli_mismatch_new_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        rc = vault_cli.change_passphrase(
            root=root, prompt_io=_PromptIO(passwords=["alpha", "beta"]), backend=backend, store=store
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()
        vault.recover_vault(root, _PASSPHRASE).close()

    def test_cli_no_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.change_passphrase(
            root=tmp_path / "nope",
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "no vault" in capsys.readouterr().err.lower()

    def test_subcommands_are_wired_under_vault_and_encryption(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        for argv in (["vault", "change-passphrase"], ["encryption", "change-passphrase"]):
            ns = parser.parse_args(argv)
            assert ns.func.__name__ == "_handle_vault_change_passphrase"

    def test_device_key_open_unaffected_and_generation_unchanged(self, tmp_path: Path) -> None:
        """The headline claim: rotation re-wraps only the recovery sidecar, so the
        everyday device-key (hot path) open still works, the file is intact, and no
        new generation is written (nothing is re-encrypted)."""
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"K=v\n"})
        ident = vault_cli._vault_identity(root)

        before = vault.open_vault(root, key_id=ident, backend=backend, store=store, anchor_label=ident)
        try:
            gen_before = before.generation
        finally:
            before.close()

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0

        after = vault.open_vault(root, key_id=ident, backend=backend, store=store, anchor_label=ident)
        try:
            assert after.generation == gen_before  # no re-encrypt, no generation bump
            assert after.read_file(".env") == b"K=v\n"
        finally:
            after.close()

    def test_rotation_survives_missing_lock_file(self, tmp_path: Path) -> None:
        """`keyvault_lock` opens .lock without O_CREAT; a vault whose dotfile was
        dropped (backup that skipped it, manual cleanup) must still rotate —
        `change_passphrase` re-materializes the lock like the other write paths."""
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"K=v\n"})
        (root / ".lock").unlink()  # simulate a vault restored without the dotfile

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"K=v\n"
        finally:
            opened.close()


class TestRecover:
    """`vault recover` — cold-open via passphrase AND re-key onto THIS device.

    Models migrating a vault dir to a new machine: it is built at the CLI
    identity with one backend+store (the 'old machine'), then ``recover`` runs
    with a FRESH backend+store (the 'new machine' — no wrapping key, no anchor).
    A successful recover restores the writable device hot path on the new host.
    """

    def test_unsupported_production_platform_refuses_before_prompt(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            _vault_open,
            "production_file_vault_eligibility",
            lambda: (False, "no production anchor on test-platform"),
        )

        rc = vault_cli.recover(
            root=tmp_path / "vault",
            prompt_io=_PromptIO(passwords=[]),
            backend=FakeBackend(),
        )

        assert rc == 1
        assert "anchor store" in capsys.readouterr().err

    def test_happy_path_restores_hot_path(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"SECRET=1\n"})

        # The new machine: nothing provisioned yet.
        new_backend, new_store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=new_backend,
            store=new_store,
        )
        assert rc == 0
        assert "re-keyed" in capsys.readouterr().out.lower()

        # The hot path is restored: a plain device-key open (new backend + the
        # freshly flipped anchor) works and can enroll a new file.
        ident = vault_cli._vault_identity(root)
        opened = vault.open_vault(root, key_id=ident, backend=new_backend, store=new_store, anchor_label=ident)
        try:
            assert opened.read_file(".env") == b"SECRET=1\n"
            opened.enroll_file("config.yaml", b"a: 1\n")  # commit works → no longer read-only
            assert opened.read_file("config.yaml") == b"a: 1\n"
        finally:
            opened.close()

    def test_wrong_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"SECRET=1\n"})

        new_backend, new_store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password="not the passphrase"),
            backend=new_backend,
            store=new_store,
        )
        assert rc == 1
        assert "passphrase" in capsys.readouterr().err.lower()
        # No anchor was flipped on the new machine — nothing committed.
        assert new_store.read(vault_cli._vault_identity(root)) is None

    def test_no_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.recover(
            root=tmp_path / "empty",
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_tampered_manifest_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A manifest-body edit fails the MAC under the recovered master → fail closed."""
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"value"})
        mpath = root / "manifest.1.mvmf"
        body, _, b64tag = mpath.read_bytes().partition(b"\n")
        raw = bytearray(base64.b64decode(b64tag))
        raw[-1] ^= 0x01
        mpath.write_bytes(body + b"\n" + base64.b64encode(bytes(raw)))

        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cli_recover_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "recover", _spy)
        rc = vault_cli.cli_recover(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path
