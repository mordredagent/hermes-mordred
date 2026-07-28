"""Vault CLI initialization and file-enrollment tests."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from mordred_hermes.keyvault import vault
from mordred_hermes.wizard import vault_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO
from ._wizard_vault_cli_helpers import _PASSPHRASE, _PromptIO, _ReadRaisesStore


class TestInit:
    def test_creates_a_recoverable_vault(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()
        store = FakeAnchorStore()
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0
        # A real, cold-path-recoverable vault now exists at the root.
        opened = vault.recover_vault(tmp_path, _PASSPHRASE)
        try:
            assert opened.generation == 0
            assert opened.list_files() == []
        finally:
            opened.close()

    def test_passphrase_mismatch_writes_nothing(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=["alpha", "beta"]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()
        with pytest.raises(vault.VaultError):  # nothing was written
            vault.recover_vault(tmp_path, "alpha")

    def test_empty_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=["", ""]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()

    def test_reinit_existing_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()
        store = FakeAnchorStore()
        first = vault_cli.init(
            root=tmp_path, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert first == 0
        # Same root + same device store: the second init must refuse, not clobber.
        rc = vault_cli.init(
            root=tmp_path, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert rc == 1
        assert "already" in capsys.readouterr().err.lower()

    def test_success_message_points_at_recovery_passphrase(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        out = capsys.readouterr().out.lower()
        assert "vault" in out
        assert "passphrase" in out or "recovery" in out

    def test_output_teaches_the_two_key_model(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Newcomers conflate the device key with the recovery passphrase. The
        creation output must state the two-key model so the mental model lands at
        the moment of creation, not buried in docs."""
        vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        out = capsys.readouterr().out.lower()
        # both opening paths are named
        assert "two ways" in out
        assert "this device" in out
        # the passphrase is framed as the backup, not the everyday key
        assert "day to day" in out
        assert "lost" in out

    def test_cli_init_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "init", _spy)
        rc = vault_cli.cli_init(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path


class TestEnsureInitialised:
    """`ensure_initialised` — the create-the-vault-on-first-`encryption enable` path."""

    def test_noop_when_vault_already_exists(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        # An existing vault is left untouched and never re-prompts: an empty
        # password queue would IndexError if `init` were (wrongly) re-entered.
        rc = vault_cli.ensure_initialised(root=root, prompt_io=_PromptIO(passwords=[]), backend=backend, store=store)
        assert rc == 0

    def test_creates_vault_when_missing(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.ensure_initialised(
            root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert rc == 0
        vault.recover_vault(root, _PASSPHRASE).close()  # a real cold-path-recoverable vault now exists

    def test_prompts_only_once_across_repeated_calls(self, tmp_path: Path) -> None:
        """`encryption enable all` fans out over targets — the vault must be created
        (and the passphrase asked) on the first call only; a second call with the
        same store is a silent no-op that never re-prompts."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        prompt = FixedPassphrasePromptIO(_PASSPHRASE)
        assert vault_cli.ensure_initialised(root=root, prompt_io=prompt, backend=backend, store=store) == 0
        assert vault_cli.ensure_initialised(root=root, prompt_io=prompt, backend=backend, store=store) == 0
        # 2 = the first call's confirm-twice; the second call must not prompt again.
        assert prompt.password_calls == 2

    def test_empty_passphrase_returns_1_and_writes_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        rc = vault_cli.ensure_initialised(
            root=root, prompt_io=_PromptIO(passwords=["", ""]), backend=FakeBackend(), store=FakeAnchorStore()
        )
        assert rc == 1
        with pytest.raises(vault.VaultError):  # nothing was written
            vault.recover_vault(root, "")

    def test_fail_closed_when_anchor_read_errors(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A transient Keychain read failure must not be read as 'no vault' and
        clobber a possibly-existing one — ensure returns 1 and creates nothing."""
        rc = vault_cli.ensure_initialised(
            root=tmp_path / "v",
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=_ReadRaisesStore(),
        )
        assert rc == 1
        assert "determine vault state" in capsys.readouterr().err.lower()


class TestAdd:
    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def test_enrolls_file_readable_via_cold_path(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "secret.env"
        src.write_bytes(b"ANTHROPIC_API_KEY=sk-secret\n")

        rc = vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store)
        assert rc == 0
        # Readable back through the independent cold path.
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
        finally:
            opened.close()

    def test_round_trips_through_cat(self, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "c.yaml"
        src.write_bytes(b"a: 1\n")
        assert vault_cli.add(root=root, name="config.yaml", source=src, backend=backend, store=store) == 0
        capsysbinary.readouterr()  # drop add's stdout

        rc = vault_cli.cat(root=root, name="config.yaml", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        assert capsysbinary.readouterr().out == b"a: 1\n"

    def test_add_to_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = tmp_path / "x"
        src.write_bytes(b"v")
        rc = vault_cli.add(root=tmp_path / "v", name=".env", source=src, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_missing_source_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_cli.add(root=root, name=".env", source=tmp_path / "nope", backend=backend, store=store)
        assert rc == 1
        assert "nope" in capsys.readouterr().err

    def test_overwrite_supersedes(self, tmp_path: Path) -> None:
        """M-4: enrolling an existing name supersedes it (new generation)."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src1, src2 = tmp_path / "a", tmp_path / "b"
        src1.write_bytes(b"one")
        src2.write_bytes(b"two")
        assert vault_cli.add(root=root, name=".env", source=src1, backend=backend, store=store) == 0
        assert vault_cli.add(root=root, name=".env", source=src2, backend=backend, store=store) == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"two"
            assert opened.generation == 2  # init=gen0, add=gen1, overwrite=gen2
        finally:
            opened.close()

    def test_cli_add_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, name: str, source: Path, backend: object = None, store: object = None) -> int:
            seen.update(root=root, name=name, source=source)
            return 0

        monkeypatch.setattr(vault_cli, "add", _spy)
        rc = vault_cli.cli_add(argparse.Namespace(root=str(tmp_path), name=".env", source=str(tmp_path / "s")))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["name"] == ".env"
        assert seen["source"] == tmp_path / "s"
