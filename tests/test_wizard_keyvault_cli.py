"""RED tests for Phase 4 PR8: ``hermes mordred keyvault {list,verify-digest}``.

SPEC.md §4.2 / TODO.md §4.2 L429-430. These are the **backend-free**
keyvault CLI commands — they only read the on-disk keyvault layout
(``meta.json`` + ``digests/<hash>.commit``) and need no Secure Enclave
``NativeBackend``:

- ``keyvault list`` — list key ids (no key material).
- ``keyvault verify-digest`` — re-display the full verification digest
  of each key for offline cross-checking.

``keyvault init`` / ``keyvault recover`` (and ``audit decrypt``) need the
production ``NativeBackend`` and are deferred to a later PR.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.wizard import keyvault_cli


def _key_id_hash(key_id: str) -> str:
    """On-disk key-id hash — ``SHA-256(key_id)[:16].hex()`` (api._hash_id)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    """Materialize a keyvault under ``home`` with the given ``{key_id: digest}``.

    Returns the keyvault root. Each digest is a 32-byte verification
    digest written to ``digests/<hash>.commit`` exactly as confirm_generate
    would; the ``meta.json`` row carries the cleartext ``key_id``.
    """
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = _key_id_hash(key_id)
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-05-16T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


# ---------------------------------------------------------------------------
# keyvault list
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_keyvault_reports_no_keys(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_absent_keyvault_dir_reports_no_keys(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No ensure_layout — the keyvault has never been initialised.
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_lists_each_key_id_and_hash(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _build_keyvault(tmp_path, {"default": b"\x11" * 32, "payments": b"\x22" * 32})
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "default" in out
        assert "payments" in out
        assert _key_id_hash("default") in out
        assert "2026-05-16T00:00:00Z" in out

    def test_list_does_not_leak_key_material(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``list`` must not print the verification digest (key material)."""
        _build_keyvault(tmp_path, {"default": b"\xab" * 32})
        keyvault_cli.list_keys(home=tmp_path)
        assert (b"\xab" * 32).hex() not in capsys.readouterr().out

    def test_cli_list_adapter_delegates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cli_list(args) delegates to list_keys against the resolved home."""
        _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_list(argparse.Namespace()) == 0


# ---------------------------------------------------------------------------
# keyvault verify-digest
# ---------------------------------------------------------------------------


class TestVerifyDigest:
    def test_no_keys_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        assert "no keys" in capsys.readouterr().err.lower()

    def test_displays_full_digest_hex(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        digest = bytes(range(32))
        _build_keyvault(tmp_path, {"default": digest})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert digest.hex() in out  # full 64-hex digest, not a prefix
        assert "default" in out

    def test_displays_every_key(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert (b"\x01" * 32).hex() in out
        assert (b"\x02" * 32).hex() in out

    def test_missing_commit_file_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A meta row whose digests/<hash>.commit is gone is surfaced, not crashed."""
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        (root / "digests" / f"{_key_id_hash('default')}.commit").unlink()
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        combined = capsys.readouterr()
        assert "default" in (combined.out + combined.err)

    def test_cli_verify_digest_adapter_delegates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _build_keyvault(tmp_path, {"default": b"\x09" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_verify_digest(argparse.Namespace()) == 0
