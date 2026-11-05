"""``POST /databases/encrypt`` and ``/databases/cancel``: the total table; the routes never convert or arm."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes import dbcrypt
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.dbcrypt import _migrate, _shim, _startup
from mordred_hermes.desktop import _databases, _projections, _seams

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
    monkeypatch.setattr(dbcrypt._runtime, "arm", forbidden)
    monkeypatch.setattr("mordred_hermes.dbcrypt._key.KeyProvider", forbidden)
    monkeypatch.setattr(_migrate, "schedule", schedule)
    return SimpleNamespace(desktop=desktop, home=desktop.home, scheduled=scheduled)


def _plaintext(home: Path, name: str = "state.db") -> None:
    with sqlite3.connect(home / name) as conn:
        conn.execute("CREATE TABLE t (x)")


def _private_file(home: Path, name: str, raw: bytes = b"1\n") -> Path:
    """A leaf through the checked filesystem, as Mordred writes it: the record read refuses a shared directory."""
    with open_private_directory(home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(name, raw)
    return home / "mordred" / name


def _armed(home: Path) -> None:
    _private_file(home, "db-encryption.marker")


def _marker(home: Path, name: str) -> None:
    _private_file(home, name)


def _record(home: Path, outcome: str) -> Path:
    return _private_file(home, _startup.RECORD_NAME, json.dumps({"version": 1, "outcome": outcome}).encode())


def _encrypt(db: Any, body: Any = None) -> dict[str, Any]:
    return dict(db.desktop.post("/databases/encrypt", body or {}))


def _cancel(db: Any) -> dict[str, Any]:
    return dict(db.desktop.post("/databases/cancel", {}))


def _attention(code: str) -> dict[str, Any]:
    return {"ok": True, "action": "attention", "code": code}


def _tree(home: Path) -> dict[str, tuple[int, int, bytes | None]]:
    """Name, mode, modification time and bytes of everything: an identical tree means no write at all."""
    return {
        str(path.relative_to(home)): (
            path.lstat().st_mode,
            path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None,
        )
        for path in home.rglob("*")
    }


SCHEDULED = {"ok": True, "action": "scheduled", "restart_required": True}
NEEDS_RESTART = {"ok": True, "action": "needs_restart", "restart_required": True}
CANCELLED = {"ok": True, "action": "cancelled"}


@pytest.mark.parametrize("plaintext", [False, True])
def test_not_armed_home_schedules_without_classifying_or_converting(db: Any, plaintext: bool) -> None:
    if plaintext:
        _plaintext(db.home)
    before = (db.home / "state.db").read_bytes() if plaintext else None
    assert _encrypt(db) == SCHEDULED
    assert db.scheduled == [db.home] and _migrate.pending_path(db.home).exists()
    # Scheduling is all it did: no marker, no journal, and the file is as it was.
    assert not dbcrypt.marker_path(db.home).exists() and not _migrate.journal_path(db.home).exists()
    assert (before is None) or (db.home / "state.db").read_bytes() == before


def test_a_profile_home_schedules_on_its_root(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import api

    child = db.home / "profiles" / "work"
    child.mkdir(parents=True, mode=0o700)
    (db.home / "backups").mkdir()
    (db.home / "backups" / "hermes-1.zip").write_bytes(b"zip")
    monkeypatch.setattr(api, "_home", lambda: child)
    assert _encrypt(db) == SCHEDULED
    assert db.scheduled == [db.home] and _migrate.pending_path(db.home).exists()
    assert not (child / "mordred").exists()
    facts = db.desktop.get("/databases/status")
    assert facts["encrypt_pending"] is True and facts["plaintext_backups"] == 1
    assert _cancel(db) == CANCELLED
    assert not _migrate.pending_path(db.home).exists()


def test_environment_key_never_makes_passive_status_done(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setenv("HERMES_MEMORY_KEY", VALID_KEY)
    assert _encrypt(db) == NEEDS_RESTART
    assert db.desktop.get("/databases/status")["runtime_protected"] is False
    assert db.scheduled == []


def test_configured_intent_is_not_runtime_authentication(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
    assert _encrypt(db) == NEEDS_RESTART


def test_armed_and_protected_is_done(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _armed(db.home)
    monkeypatch.setattr(_databases, "_runtime_protected", lambda root: True)
    assert _encrypt(db) == {"ok": True, "action": "done"}
    assert db.scheduled == []


def test_existing_database_is_not_classified_by_polling(db: Any) -> None:
    _armed(db.home)
    _plaintext(db.home, "new.db")
    assert _encrypt(db) == NEEDS_RESTART  # never plaintext_in_armed_home: that needs SQL
    assert db.scheduled == []  # startup refuses a pending conversion once armed: scheduling would be useless


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
    assert _encrypt(db) == _attention(code)
    assert db.scheduled == []
    assert marker == "db-encryption.pending" or not _migrate.pending_path(db.home).exists()


def test_a_journal_outranks_a_decrypt_pending_marker(db: Any) -> None:
    _marker(db.home, "db-decryption.pending")
    _marker(db.home, "db-encryption.journal.json")
    assert _encrypt(db) == _attention("journal")


@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("outcome", ["busy", "auth_interrupted", "too_large", "refused"])
def test_a_record_never_outranks_a_journal(db: Any, pending: bool, outcome: str) -> None:
    if pending:
        _marker(db.home, "db-encryption.pending")
    _marker(db.home, "db-encryption.journal.json")
    _record(db.home, outcome)
    assert _encrypt(db) == _attention("journal")
    assert db.scheduled == []


@pytest.mark.parametrize(
    ("outcome", "code"),
    [
        ("busy", "startup_busy"),
        ("memory_not_enabled", "startup_memory_required"),
        ("source_unavailable", "startup_key_unavailable"),
        ("auth_interrupted", "startup_auth_interrupted"),
        ("attempting", "startup_auth_interrupted"),  # never exposed: its holder died or is still inside it
        ("too_large", "startup_too_large"),
        ("holders_open", "startup_refused"),
        ("refused", "startup_refused"),
        ("unavailable", "startup_refused"),
        ("a_future_outcome", "startup_refused"),
    ],
)
def test_scheduled_with_startup_outcome_answers_the_outcome_code(db: Any, outcome: str, code: str) -> None:
    _marker(db.home, "db-encryption.pending")
    _record(db.home, outcome)
    before = _tree(db.home)
    assert _encrypt(db) == _attention(code)
    assert db.scheduled == [] and _tree(db.home) == before
    assert code in _projections.DATABASE_CODES


def test_every_startup_outcome_has_its_own_row_or_is_refused() -> None:
    assert _startup.OUTCOMES - set(_databases._OUTCOME_CODES) == {"holders_open", "refused", "unavailable"}
    assert set(_databases._OUTCOME_CODES.values()) <= _projections.DATABASE_CODES


@pytest.mark.parametrize(
    "raw",
    [b"{", b"[]", b'{"version": 2, "outcome": "busy"}', b'{"version": 1, "outcome": 1}', b"x" * 4097],
    ids=["truncated", "not-an-object", "other-version", "not-a-string", "oversized"],
)
def test_malformed_record_answers_startup_refused(db: Any, raw: bytes) -> None:
    _marker(db.home, "db-encryption.pending")
    _private_file(db.home, _startup.RECORD_NAME, raw)
    assert db.desktop.get("/databases/status")["startup_outcome"] == "refused"
    assert _encrypt(db) == _attention("startup_refused")
    assert db.scheduled == []


def test_scheduled_without_a_record_answers_scheduled_with_no_write(db: Any) -> None:
    _marker(db.home, "db-encryption.pending")
    before = _tree(db.home)
    assert _encrypt(db) == SCHEDULED
    assert _encrypt(db) == SCHEDULED
    assert db.scheduled == [] and _tree(db.home) == before


def test_too_large_refuses_at_press_without_scheduling(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _plaintext(db.home)
    monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 1)
    before = _tree(db.home)
    assert _encrypt(db) == _attention("startup_too_large")
    assert db.scheduled == [] and _tree(db.home) == before


def test_size_is_only_judged_when_the_press_would_schedule(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(root: Path) -> bool:
        pytest.fail("only a press that would schedule walks the tree")

    monkeypatch.setattr(_startup, "conversion_too_large", forbidden)
    _marker(db.home, "db-encryption.pending")
    assert _encrypt(db) == SCHEDULED
    _migrate.pending_path(db.home).unlink()
    _armed(db.home)
    assert _encrypt(db) == NEEDS_RESTART
    assert _encrypt(db, {"dry_run": True}) == {"ok": True, "action": "dry_run"}


def test_an_unknown_size_answers_databases_failed_without_scheduling(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(root: Path) -> bool:
        raise _migrate.MigrationError(str(root))

    monkeypatch.setattr(_startup, "conversion_too_large", broken)
    answer = _encrypt(db)
    assert answer == {"ok": False, "error": "databases_failed"}
    assert db.scheduled == [] and str(db.home) not in str(answer) and str(db.home) not in str(db.desktop.logs.lines)


def test_dry_run_changes_nothing(db: Any) -> None:
    _plaintext(db.home)
    assert _encrypt(db, {"dry_run": True}) == {"ok": True, "action": "dry_run"}
    assert db.scheduled == [] and not _migrate.pending_path(db.home).exists()
    assert _encrypt(db, {"dry_run": "yes"}) == {"ok": False, "error": "invalid_body"}


def _unsafe_home(db: Any, tmp_path: Path) -> Path:
    """A pending marker that is a link: the intent path requires checked diagnosis."""
    target = tmp_path / "elsewhere"
    target.write_text("1\n", encoding="utf-8")
    with open_private_directory(db.home / "mordred", create=True):
        pass
    link = db.home / "mordred" / "db-encryption.pending"
    link.symlink_to(target)
    return link


@pytest.mark.skipif(os.name != "posix", reason="creating a symlink needs a privilege on Windows")
def test_unknown_status_never_attempts_a_schedule(db: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(home: Path) -> None:
        pytest.fail("an unknown home must never be scheduled")

    link = _unsafe_home(db, tmp_path)
    monkeypatch.setattr(_migrate, "schedule", broken)
    facts = db.desktop.get("/databases/status")
    assert facts["armed"] is None and facts["encrypt_pending"] is None
    assert facts["decrypt_pending"] is None and facts["journal"] is None
    assert facts["startup_outcome"] is None and facts["plaintext_backups"] is None
    assert _encrypt(db) == _attention("databases_failed")
    assert _cancel(db) == _attention("databases_failed")
    assert link.is_symlink()


def test_a_schedule_failure_answers_databases_failed_without_text(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(home: Path) -> None:
        raise PermissionError(str(home))

    monkeypatch.setattr(_migrate, "schedule", broken)
    answer = _encrypt(db)
    assert answer == {"ok": False, "error": "databases_failed"}
    assert str(db.home) not in str(answer) and str(db.home) not in str(db.desktop.logs.lines)


def test_shared_unavailability_refuses_before_scheduling(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dbcrypt, "database_status", lambda home: dbcrypt.DatabaseStatus(True, 0, "unavailable", False, None)
    )
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    assert _cancel(db) == {"ok": False, "error": "databases_unsupported"}
    assert db.desktop.get("/databases/status") == {"ok": True, "supported": False}
    assert db.scheduled == []


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
    assert status["plaintext_backups"] == 0  # no backups directory: a count, not a classification
    assert status["armed"] is False and status["runtime_protected"] is False


# -- cancel ----------------------------------------------------------------------------------------


def test_cancel_scheduled_encryption_never_converts(db: Any) -> None:
    _plaintext(db.home)
    before = (db.home / "state.db").read_bytes()
    assert _encrypt(db) == SCHEDULED
    assert _cancel(db) == CANCELLED
    assert not _migrate.pending_path(db.home).exists()
    assert not dbcrypt.marker_path(db.home).exists() and not _migrate.journal_path(db.home).exists()
    assert (db.home / "state.db").read_bytes() == before


def test_cancel_clears_the_record_so_the_next_press_schedules_a_fresh_attempt(db: Any) -> None:
    _marker(db.home, "db-encryption.pending")
    record = _record(db.home, "attempting")
    assert _encrypt(db) == _attention("startup_auth_interrupted")
    assert _cancel(db) == CANCELLED
    assert not record.exists() and not _migrate.pending_path(db.home).exists()
    assert db.desktop.get("/databases/status")["startup_outcome"] is None
    assert _encrypt(db) == SCHEDULED
    assert _migrate.pending_path(db.home).exists() and not record.exists()


@pytest.mark.parametrize("name", ["db-encryption.journal.json", "db-encryption.marker"])
def test_cancel_refuses_with_a_journal_or_marker_and_changes_nothing(db: Any, name: str) -> None:
    _marker(db.home, "db-encryption.pending")
    _marker(db.home, name)
    _record(db.home, "busy")
    before = _tree(db.home)
    assert _cancel(db) == _attention("databases_cancel_refused")
    assert _tree(db.home) == before


def test_cancel_refuses_when_a_conversion_starts_after_the_facts_were_read(
    db: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _marker(db.home, "db-encryption.pending")
    real_status = _databases.status_object

    def late_journal(home: Path, **kwargs: Any) -> dict[str, object]:
        facts = real_status(home, **kwargs)
        _marker(db.home, "db-encryption.journal.json")
        return facts

    monkeypatch.setattr(_databases, "status_object", late_journal)
    assert _cancel(db) == _attention("databases_cancel_refused")
    assert _migrate.pending_path(db.home).exists()


def test_cancel_with_nothing_scheduled_creates_nothing(db: Any) -> None:
    before = _tree(db.home)
    assert _cancel(db) == CANCELLED
    assert _tree(db.home) == before


def test_a_cancel_failure_answers_databases_failed_without_text(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(home: Path) -> None:
        raise PermissionError(str(home))

    _marker(db.home, "db-encryption.pending")
    monkeypatch.setattr(_migrate, "unschedule", broken)
    answer = _cancel(db)
    assert answer == {"ok": False, "error": "databases_failed"}
    assert str(db.home) not in str(answer) and str(db.home) not in str(db.desktop.logs.lines)
    assert _migrate.pending_path(db.home).exists()


# -- Windows: the same route on an admitted server, refused on a workstation -----------------------


def _windows(monkeypatch: pytest.MonkeyPatch, *, admitted: bool) -> None:
    from mordred_hermes.dbcrypt import _capability, _windows_vfs

    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_capability, "_driver_present", lambda: True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: admitted)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: Path("owned.dll"))


def test_windows_workstation_answers_unsupported_and_never_schedules(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, admitted=False)
    assert db.desktop.get("/databases/status") == {"ok": True, "supported": False}
    assert _encrypt(db) == {"ok": False, "error": "databases_unsupported"}
    assert _cancel(db) == {"ok": False, "error": "databases_unsupported"}
    assert db.scheduled == [] and not _migrate.pending_path(db.home).exists()


def test_windows_server_schedules_like_the_other_platforms(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, admitted=True)
    assert db.desktop.get("/databases/status")["supported"] is True
    assert _encrypt(db) == SCHEDULED
    assert db.desktop.get("/databases/status")["encrypt_pending"] is True
    assert _cancel(db) == CANCELLED
