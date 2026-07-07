"""Tests for ``hermes-mordred keyvault reset`` — destroy all key material.

``reset`` deletes every Secure-Enclave wrapping key (the live key(s) recorded
in ``meta.json`` plus the well-known default + audit-log ids) and removes the
on-disk keyvault directory. It is irreversible, so the interactive path
requires the operator to type a confirmation phrase; ``--yes`` skips it for
scripted use.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Sequence
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault.api import _DEFAULT_KEY_ID
from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
from mordred_hermes.wizard import keyvault_cli
from tests._keyvault_fakes import FakeBackend


def _key_id_hash(key_id: str) -> str:
    """On-disk key-id hash — ``SHA-256(key_id)[:16].hex()`` (api._hash_id)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


def _build_keyvault(home: Path, key_ids: Sequence[str]) -> Path:
    """Materialize a keyvault under ``home`` holding ``key_ids``. Returns the root."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id in key_ids:
        h = _key_id_hash(key_id)
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-05-16T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", b"\x11" * 32)
    _storage.save_meta(root, meta)
    return root


def _seed_enclave(backend: FakeBackend, key_ids: Sequence[str]) -> None:
    """Pre-create the Secure-Enclave keys so deletes are observable, not no-ops."""
    for key_id in key_ids:
        backend.generate_enclave_key(key_id)


class _ScriptedPrompt:
    """Minimal :class:`PromptIO` stand-in returning a queued ``ask_text`` answer."""

    def __init__(self, text_answer: str) -> None:
        self._text = text_answer
        self.asked: list[str] = []

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        self.asked.append(label)
        return self._text

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_multi(self, label: str, choices: Sequence[str], default: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(default)

    def ask_password(self, label: str, default: str = "") -> str:
        return default


def _deleted(backend: FakeBackend) -> set[str]:
    """key_ids the backend was asked to delete."""
    return {key_id for op, key_id in backend.calls if op == "delete"}


class TestResetYes:
    def test_removes_ondisk_dir_and_deletes_enclave_keys(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        _seed_enclave(backend, [_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID])

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        # Both the live key and the audit-log wrapping key are destroyed.
        assert _DEFAULT_KEY_ID in _deleted(backend)
        assert AUDIT_LOG_KEY_ID in _deleted(backend)

    def test_deletes_every_meta_key(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, ["default", "payments"])
        backend = FakeBackend()

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert {"default", "payments"} <= _deleted(backend)

    def test_corrupt_meta_still_resets_known_keys(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        backend = FakeBackend()

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        assert not root.exists()
        # A corrupt meta must not strand the default / audit-log SE keys.
        assert {_DEFAULT_KEY_ID, AUDIT_LOG_KEY_ID} <= _deleted(backend)


class _DeleteFailsBackend(FakeBackend):
    """FakeBackend whose SE-key delete always raises, to exercise best-effort."""

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        raise WrapError(f"simulated Enclave delete failure for {key_id!r}")


class TestResetDegradedPaths:
    def test_se_delete_failure_degrades_to_note_and_still_resets(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = _DeleteFailsBackend()

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        # The on-disk removal is authoritative — a best-effort SE delete failure
        # must degrade to a printed note, not abort the reset.
        assert rc == 0
        assert not root.exists()
        assert "could not delete Secure Enclave key" in capsys.readouterr().err

    def test_rmtree_failure_reports_cleanly_without_traceback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()

        def _boom(*args: object, **kwargs: object) -> None:
            raise OSError("simulated rmtree failure")

        monkeypatch.setattr(keyvault_cli.shutil, "rmtree", _boom)
        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        # The SE keys were already deleted; a directory-removal failure must
        # report a clean error and return non-zero, never a traceback.
        assert rc == 1
        assert _DEFAULT_KEY_ID in _deleted(backend)
        assert root.exists()  # rmtree was stubbed out
        assert "could not be removed" in capsys.readouterr().err.lower()


class TestResetAbsent:
    def test_absent_keyvault_is_noop(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)

        assert rc == 0
        # Outcome lines land on stdout (UX review 2026-07-07); stderr stays
        # reserved for diagnostics and the interactive WARNING chrome.
        assert "nothing to reset" in capsys.readouterr().out.lower()
        assert _deleted(backend) == set()  # never touched the Enclave


class TestResetConfirmation:
    def test_wrong_phrase_aborts_and_preserves_keyvault(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        _seed_enclave(backend, [_DEFAULT_KEY_ID])

        rc = keyvault_cli.reset_keyvault(
            home=tmp_path, backend=backend, prompt_io=_ScriptedPrompt("no"), assume_yes=False
        )

        assert rc == 1
        assert root.exists()  # nothing deleted on abort
        assert _deleted(backend) == set()
        assert "aborted" in capsys.readouterr().out.lower()

    def test_correct_phrase_proceeds(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()
        prompt = _ScriptedPrompt("reset")

        rc = keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, prompt_io=prompt, assume_yes=False)

        assert rc == 0
        assert not root.exists()
        assert prompt.asked  # the operator was prompted

    def test_phrase_match_tolerates_surrounding_whitespace(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, ["default"])
        backend = FakeBackend()

        rc = keyvault_cli.reset_keyvault(
            home=tmp_path, backend=backend, prompt_io=_ScriptedPrompt("  reset  "), assume_yes=False
        )

        assert rc == 0
        assert not root.exists()


class TestResetAdapter:
    def test_cli_reset_delegates_with_assume_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_reset(*, assume_yes: bool = False) -> int:
            captured["assume_yes"] = assume_yes
            return 0

        monkeypatch.setattr(keyvault_cli, "reset_keyvault", _fake_reset)
        rc = keyvault_cli.cli_reset(argparse.Namespace(assume_yes=True))

        assert rc == 0
        assert captured["assume_yes"] is True

    def test_cli_reset_defaults_assume_yes_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def _fake_reset(*, assume_yes: bool = False) -> int:
            captured["assume_yes"] = assume_yes
            return 0

        monkeypatch.setattr(keyvault_cli, "reset_keyvault", _fake_reset)
        rc = keyvault_cli.cli_reset(argparse.Namespace())

        assert rc == 0
        assert captured["assume_yes"] is False
