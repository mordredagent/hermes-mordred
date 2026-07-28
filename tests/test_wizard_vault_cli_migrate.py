"""Vault CLI plaintext migration tests."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from mordred_hermes.keyvault import vault
from mordred_hermes.wizard import vault_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend
from ._wizard_vault_cli_helpers import _PASSPHRASE, _FailOnNthEnrollStore, _PromptIO, _ReadRaisesStore


class TestMigrate:
    """``vault migrate`` — batch-import existing plaintext files (design §8.2).

    A batch :func:`add`: one hot-path open, each source enrolled under its
    basename, **read-all-then-enroll-all** so a single bad path or a duplicate
    basename aborts before anything is committed (no half-migrated vault).
    """

    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def test_enrolls_each_source_under_basename(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        plain = tmp_path / "plain"
        plain.mkdir()
        (plain / ".env").write_bytes(b"ANTHROPIC_API_KEY=sk-secret\n")
        (plain / "config.yaml").write_bytes(b"a: 1\n")

        rc = vault_cli.migrate(root=root, sources=[plain / ".env", plain / "config.yaml"], backend=backend, store=store)
        assert rc == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
            assert opened.read_file("config.yaml") == b"a: 1\n"
            assert opened.generation == 2  # init=gen0, then +1 per enrolled file
        finally:
            opened.close()

    def test_missing_source_aborts_before_any_enroll(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Read-all-first: one unreadable path commits NOTHING (no partial migrate)."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        good = tmp_path / ".env"
        good.write_bytes(b"K=v\n")

        rc = vault_cli.migrate(root=root, sources=[good, tmp_path / "nope.yaml"], backend=backend, store=store)
        assert rc == 1
        assert "nope.yaml" in capsys.readouterr().err
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.list_files() == []  # nothing committed — aborted before the first enroll
            assert opened.generation == 0
        finally:
            opened.close()

    def test_duplicate_basename_refused(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Two sources mapping to the same enrolled name is ambiguous: fail-closed, nothing enrolled."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / ".env").write_bytes(b"one")
        (b / ".env").write_bytes(b"two")

        rc = vault_cli.migrate(root=root, sources=[a / ".env", b / ".env"], backend=backend, store=store)
        assert rc == 1
        assert ".env" in capsys.readouterr().err
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.list_files() == []
        finally:
            opened.close()

    def test_empty_sources_is_noop(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_cli.migrate(root=root, sources=[], backend=backend, store=store)
        assert rc == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.generation == 0  # untouched — short-circuits before opening
        finally:
            opened.close()

    def test_migrate_to_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert "init" in capsys.readouterr().err.lower()

    def test_keychain_error_opening_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=root, sources=[src], backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_does_not_remove_plaintext_source(self, tmp_path: Path) -> None:
        """Like ``add``, migrate never deletes the plaintext — the operator owns shredding."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        assert src.exists()
        assert src.read_bytes() == b"K=v\n"

    def test_overwrite_supersedes(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"old")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        src.write_bytes(b"new")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"new"
            assert opened.generation == 2
        finally:
            opened.close()

    def test_cli_migrate_uses_explicit_sources(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["root"] = root
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(
            argparse.Namespace(root=str(tmp_path), source=[str(tmp_path / ".env"), str(tmp_path / "config.yaml")])
        )
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["sources"] == [tmp_path / ".env", tmp_path / "config.yaml"]

    def test_cli_migrate_discovers_default_hermes_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No explicit sources -> import ``.env`` + ``config.yaml`` under the Hermes home."""
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"K=v\n")
        (home / "config.yaml").write_bytes(b"a: 1\n")
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 0
        # Discovery order is fixed (.env before config.yaml), so assert the list directly.
        assert seen["sources"] == [home / ".env", home / "config.yaml"]

    def test_cli_migrate_skips_absent_default_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only existing default files are migrated (``.env`` present, ``config.yaml`` absent)."""
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"K=v\n")
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 0
        assert seen["sources"] == [home / ".env"]

    def test_cli_migrate_no_sources_found_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()  # neither .env nor config.yaml present
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)

        def _never(**_: object) -> int:
            raise AssertionError("migrate must not run when discovery finds nothing")

        monkeypatch.setattr(vault_cli, "migrate", _never)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_partial_failure_reports_failed_file_and_count(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A device error on the 2nd enroll fails closed, names the failed file,
        and reports how many committed before it (the only path that exercises
        the enrolled-index attribution)."""
        root = tmp_path / "v"
        backend = FakeBackend()
        store = _FailOnNthEnrollStore(fail_on=2)  # open() only reads; 1st/2nd writes are the two enrolls
        self._init(root, backend, store)
        first, second = tmp_path / ".env", tmp_path / "config.yaml"
        first.write_bytes(b"first")
        second.write_bytes(b"second")

        store.arm()
        rc = vault_cli.migrate(root=root, sources=[first, second], backend=backend, store=store)
        assert rc == 1
        err = capsys.readouterr().err
        assert "config.yaml" in err  # the file whose commit failed
        assert "1 of 2 already enrolled" in err  # the first file committed before the failure
        # The first file did commit (each enroll is its own crash-safe generation).
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"first"
        finally:
            opened.close()

    def test_directory_source_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A directory passed as a source is unreadable (IsADirectoryError -> OSError) -> fail-closed."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        a_dir = tmp_path / "adir"
        a_dir.mkdir()
        rc = vault_cli.migrate(root=root, sources=[a_dir], backend=backend, store=store)
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""
