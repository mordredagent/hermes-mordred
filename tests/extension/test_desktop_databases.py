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
from mordred_hermes.desktop import _databases, _seams, api

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

    monkeypatch.setattr(_seams, "sqlcipher_available", lambda: True)
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
def test_not_armed_unknown_status_refuses_scheduling_even_without_plaintext(db: Any, plaintext: bool) -> None:
    if plaintext:
        _plaintext(db.home)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}
    assert db.scheduled == [] and not _migrate.pending_path(db.home).exists()


def test_environment_key_never_makes_passive_status_done(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setenv("HERMES_MEMORY_KEY", VALID_KEY)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}
    assert db.scheduled == []


def test_configured_intent_is_not_runtime_authentication(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}


def test_existing_database_is_not_classified_by_polling(db: Any) -> None:
    _armed(db.home)
    _plaintext(db.home, "new.db")
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}
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
def test_pending_state_never_implicitly_schedules_recovery(db: Any, armed: bool, marker: str, code: str) -> None:
    if armed:
        _armed(db.home)
    _marker(db.home, marker)
    _plaintext(db.home)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}
    assert db.scheduled == []


def test_dry_run_changes_nothing(db: Any) -> None:
    _plaintext(db.home)
    assert _encrypt(db, {"dry_run": True}) == {"ok": True, "action": "dry_run"}
    assert db.scheduled == [] and not _migrate.pending_path(db.home).exists()
    assert _encrypt(db, {"dry_run": "yes"}) == {"ok": False, "error": "invalid_body"}


def test_unknown_status_never_attempts_a_schedule(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(home: Path) -> None:
        raise PermissionError(str(home))

    monkeypatch.setattr(_migrate, "schedule", broken)
    assert _encrypt(db) == {"ok": True, "action": "attention", "code": "databases_failed"}
    assert str(db.home) not in str(db.desktop.logs.lines)


def test_unsupported_off_macos_or_without_sqlcipher(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seams, "sqlcipher_available", lambda: False)
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    monkeypatch.setattr(_seams, "sqlcipher_available", lambda: True)
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    assert db.desktop.get("/databases/status")["runtime_protected"] is False


def test_the_sqlcipher_probe() -> None:
    assert isinstance(_seams.sqlcipher_available(), bool)


def test_status_object_never_probes_sql_inside_a_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither an offline classifier nor the process SQL library is allowed in passive polling."""
    home = tmp_path / "home"
    (home / "cron").mkdir(parents=True)
    plain = sqlite3.connect(home / "state.db")
    try:
        plain.execute("CREATE TABLE t (x INTEGER)")
        plain.commit()
    finally:
        plain.close()
    (home / "shared-state.db").write_bytes(bytes(range(256)) * 8)  # ciphertext stand-in: no SQLite header
    (home / "cron" / "executions.db").write_bytes(b"")  # empty: omitted, as the classifier omits it
    (home / "state.db.repair-attempts.json").write_text("{}", encoding="utf-8")  # metadata: omitted
    monkeypatch.setattr(_shim, "is_installed", lambda: True)

    def refused(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the offline classifier ran inside the runtime")

    monkeypatch.setattr(_migrate, "discover", refused)
    monkeypatch.setattr("mordred_hermes.dbcrypt._monitor._own_sqlite", refused)

    status = _databases.status_object(home, platform="darwin", sqlcipher=True, environ={})

    assert status["databases"] == []
    assert status["plaintext_backups"] is None
    assert status["armed"] is False and status["runtime_protected"] is False
