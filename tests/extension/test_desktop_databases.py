"""``POST /databases/encrypt``: the total schedule-or-report table; the route never converts or arms."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _migrate, _shim
from mordred_hermes.desktop import api

VALID_KEY = "hex:" + "22" * 32


@pytest.fixture
def db(desktop: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """SQLCipher present, no key ever unwrapped, ``migrate``/``arm`` forbidden, ``schedule`` recorded."""

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("the Desktop route must never convert, arm or unwrap a key")

    scheduled: list[Path] = []
    real_schedule = _migrate.schedule

    def schedule(home: Path) -> None:
        scheduled.append(home)
        real_schedule(home)

    monkeypatch.setattr(api, "_sqlcipher_available", lambda: True)
    monkeypatch.setattr(_migrate, "migrate", forbidden)
    monkeypatch.setattr(dbcrypt, "arm", forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key.KeyProvider", forbidden)
    monkeypatch.setattr(_migrate, "schedule", schedule)
    return SimpleNamespace(desktop=desktop, home=desktop.home, scheduled=scheduled)


def _plaintext(home: Path, name: str = "state.db") -> None:
    with sqlite3.connect(home / name) as conn:
        conn.execute("CREATE TABLE t (x)")


def _armed(home: Path) -> None:
    marker = dbcrypt.marker_path(home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("1\n", encoding="utf-8")


def _marker(home: Path, name: str) -> None:
    (home / "mordred").mkdir(parents=True, exist_ok=True)
    (home / "mordred" / name).write_text("1\n", encoding="utf-8")


def _encrypt(db: Any, body: Any = None) -> dict[str, Any]:
    return dict(db.desktop.post("/databases/encrypt", body or {}))


@pytest.mark.parametrize("plaintext", [False, True])
def test_not_armed_schedules_even_without_plaintext(db: Any, plaintext: bool) -> None:
    if plaintext:
        _plaintext(db.home)
    assert _encrypt(db) == {"ok": True, "action": "scheduled", "restart_required": True}
    assert db.scheduled == [db.home] and _migrate.pending_path(db.home).is_file()
    # Idempotent: already pending answers the same and writes nothing again.
    assert _encrypt(db) == {"ok": True, "action": "scheduled", "restart_required": True}
    assert db.scheduled == [db.home]


def test_armed_and_protected_is_done(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setenv("HERMES_MEMORY_KEY", VALID_KEY)
    assert _encrypt(db) == {"ok": True, "action": "done"}
    assert db.scheduled == []


def test_armed_but_not_protected_needs_a_restart(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    assert _encrypt(db) == {"ok": True, "action": "needs_restart", "restart_required": True}


def test_plaintext_in_an_armed_home_needs_the_terminal(db: Any) -> None:
    _armed(db.home)
    _plaintext(db.home, "new.db")
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "plaintext_in_armed_home"}
    assert db.scheduled == []  # startup skips a pending conversion once armed: scheduling would be useless


@pytest.mark.parametrize(
    ("armed", "marker", "code"),
    [
        (True, "db-encryption.pending", "stale_pending"),
        (True, "db-decryption.pending", "decrypt_pending"),
        (False, "db-decryption.pending", "decrypt_pending"),
        (True, "db-encryption.journal.json", "journal"),
        (False, "db-encryption.journal.json", "journal"),
    ],
)
def test_pending_work_and_journals_are_attention(db: Any, armed: bool, marker: str, code: str) -> None:
    if armed:
        _armed(db.home)
    _marker(db.home, marker)
    _plaintext(db.home)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": code}
    assert db.scheduled == []


def test_dry_run_changes_nothing(db: Any) -> None:
    _plaintext(db.home)
    assert _encrypt(db, {"dry_run": True}) == {"ok": True, "action": "dry_run"}
    assert db.scheduled == [] and not _migrate.pending_path(db.home).exists()
    assert _encrypt(db, {"dry_run": "yes"}) == {"ok": False, "error": "invalid_body"}


def test_a_failed_schedule_is_databases_failed(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(home: Path) -> None:
        raise PermissionError(str(home))

    monkeypatch.setattr(_migrate, "schedule", broken)
    assert _encrypt(db) == {"ok": False, "error": "databases_failed"}
    assert str(db.home) not in str(db.desktop.logs.lines)


def test_unsupported_off_macos_or_without_sqlcipher(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "_sqlcipher_available", lambda: False)
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    monkeypatch.setattr(api, "_sqlcipher_available", lambda: True)
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    assert db.desktop.get("/databases/status") == {"ok": True, "supported": False}


def test_the_sqlcipher_probe() -> None:
    assert isinstance(api._sqlcipher_available(), bool)
