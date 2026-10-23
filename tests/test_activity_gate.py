"""The protection gate refuses every unprotected path to the activity store; there is no plaintext fallback."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import dbcrypt
from mordred_hermes.activity import _gate
from mordred_hermes.activity._gate import ActivityRefused, check_protection, open_store, verify_keyed_connection
from mordred_hermes.activity._paths import store_path
from mordred_hermes.dbcrypt import _monitor, _shim


@pytest.fixture
def protected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home that passes every process/home-level check (armed, shim loaded, key resolves)."""
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", lambda: object())
    dbcrypt.arm(tmp_path)
    return tmp_path


def code(home: Path) -> str | None:
    found = check_protection(home)
    return None if found is None else found.code


def test_protected_home_passes(protected: Path) -> None:
    assert check_protection(protected) is None


def test_non_macos_is_refused(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert code(protected) == "unsupported_platform"


def test_unarmed_home_is_refused(protected: Path) -> None:
    dbcrypt.marker_path(protected).unlink()
    assert code(protected) == "not_armed"


def test_profile_home_uses_the_root_marker(protected: Path) -> None:
    profile = protected / "profiles" / "work"
    profile.mkdir(parents=True)
    assert check_protection(profile) is None
    dbcrypt.marker_path(protected).unlink()
    assert code(profile) == "not_armed"


def test_process_without_the_shim_is_refused(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    assert code(protected) == "unprotected_process"


@pytest.mark.parametrize("provider", [None, lambda: None])
def test_missing_key_is_refused(protected: Path, monkeypatch: pytest.MonkeyPatch, provider: Any) -> None:
    monkeypatch.setattr(dbcrypt, "_PROVIDER", provider)
    assert code(protected) == "no_key"


def test_unopenable_vault_is_no_key(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> None:
        raise RuntimeError("vault locked")

    monkeypatch.setattr(dbcrypt, "_PROVIDER", broken)
    assert code(protected) == "no_key"


@pytest.mark.parametrize("marker", ["db-encryption.journal.json", "db-encryption.pending", "db-decryption.pending"])
def test_pending_conversion_is_refused(protected: Path, marker: str) -> None:
    (protected / "mordred" / marker).write_text("{}", encoding="utf-8")
    assert code(protected) == "conversion_pending"


def test_unkeyed_connection_is_refused(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "x.db")
    try:
        found = verify_keyed_connection(conn, tmp_path / "x.db")
    finally:
        conn.close()
    assert found is not None and found.code == "unkeyed_connection"


class _ClaimsKey(sqlite3.Connection):
    """Plain SQLite pretending to be keyed: the file check must still catch it."""

    mordred_key: Any = "pretend"


class _ClaimsKeyModule:
    @staticmethod
    def connect(database: str, **kwargs: Any) -> sqlite3.Connection:
        return sqlite3.connect(database, factory=_ClaimsKey, **kwargs)


def test_open_store_refuses_before_creating_anything_when_unprotected(tmp_path: Path) -> None:
    dbcrypt.marker_path(tmp_path).unlink(missing_ok=True)
    with pytest.raises(ActivityRefused):
        open_store(tmp_path)
    assert not (tmp_path / "plugin-data").exists()


def test_open_store_refuses_an_unkeyed_process_connection(protected: Path) -> None:
    # The gate passed (patched), but the process sqlite3 is the stdlib: no key on the connection.
    with pytest.raises(ActivityRefused) as caught:
        open_store(protected)
    assert caught.value.code == "unkeyed_connection"
    path = store_path(protected)
    assert not path.exists() or path.stat().st_size == 0


def test_open_store_refuses_a_readable_plaintext_store(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: _ClaimsKeyModule)
    with pytest.raises(ActivityRefused) as caught:
        open_store(protected)
    assert caught.value.code == "plaintext_store"


def test_open_store_refuses_a_planted_plaintext_store_before_opening_it(protected: Path) -> None:
    path = store_path(protected)
    path.parent.mkdir(parents=True, exist_ok=True)
    planted = sqlite3.connect(path)
    try:
        planted.execute("CREATE TABLE planted (x INTEGER)")
        planted.commit()
    finally:
        planted.close()

    with pytest.raises(ActivityRefused) as caught:
        open_store(protected)
    assert caught.value.code == "plaintext_store"


def test_open_store_refuses_a_store_bound_to_another_profile(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_process_sqlite", lambda: _ClaimsKeyModule)
    # The planted store stands in for a keyed one: skip the pre-open plaintext probe.
    monkeypatch.setattr(_monitor, "is_plaintext", lambda _path: False)
    other = protected / "elsewhere"
    other.mkdir()
    from mordred_hermes.activity.store import ActivityStore

    ActivityStore(store_path(protected), sqlite3.connect).initialize(other)

    with pytest.raises(ActivityRefused) as caught:
        open_store(protected)
    assert caught.value.code == "profile_mismatch"


def test_refusals_are_content_free(protected: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    with pytest.raises(ActivityRefused) as caught:
        open_store(protected)
    assert str(caught.value) == "unprotected_process"
    assert str(protected) not in caught.value.refusal.detail
