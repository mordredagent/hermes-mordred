"""Vault CLI fail-closed behavior and terminal error rendering tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.wizard import vault_cli
from mordred_hermes.wizard._prompt_io import _RefusingPromptIO

from ._keyvault_fakes import FakeAnchorStore, FakeBackend
from ._wizard_vault_cli_helpers import (
    _PASSPHRASE,
    _build_vault,
    _GenerateRaisesBackend,
    _PromptIO,
    _ReadRaisesStore,
)


class TestFailClosed:
    """Review H-1: every failure path returns rc 1, never an uncaught traceback."""

    def test_init_keychain_error_in_reinit_guard(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=_ReadRaisesStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_init_wraperror_generating_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=_GenerateRaisesBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_add_keychain_error_opening(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        src = tmp_path / "s"
        src.write_bytes(b"v")
        rc = vault_cli.add(root=root, name=".env", source=src, backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cold_path_corrupt_recovery_sidecar(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``cat`` still opens the cold path (unlike ``status``, which no longer
        touches the recovery sidecar at all — see the test below) — a corrupt
        sidecar fails closed."""
        _build_vault(tmp_path, files={".env": b"v"})
        rec = tmp_path / "recovery.mrkv"
        raw = bytearray(rec.read_bytes())
        raw[:4] = b"XXXX"  # corrupt the MRKV magic -> backup.BackupCorrupt
        rec.write_bytes(raw)
        rc = vault_cli.cat(root=tmp_path, name=".env", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_status_ignores_corrupt_recovery_sidecar(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``status`` reads only the manifest, never the recovery sidecar, so a
        sidecar corruption that fails ``cat`` (above) does not affect it."""
        _build_vault(tmp_path, files={".env": b"v"})
        rec = tmp_path / "recovery.mrkv"
        raw = bytearray(rec.read_bytes())
        raw[:4] = b"XXXX"
        rec.write_bytes(raw)
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 0


class TestErrorColour:
    """Vault errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network-CLI reproducer (PR #159). Uses the no-prompt
    ``migrate``-to-uninitialised-vault path so the assertion needs no passphrase
    PromptIO — the failing open prints its reason via ``_term`` either way.
    """

    def test_open_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "init" in err.lower()

    def test_open_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Off a tty the output is plain, now carrying the shared `error:` prefix.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error: no vault at")
        assert "\033" not in err
