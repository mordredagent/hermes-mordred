"""Phase 4/5: noticing unprotected databases, and telling the model the real status."""

from __future__ import annotations

import sqlite3 as stdlib_sqlite3
import sys
from pathlib import Path

import pytest

pytest.importorskip("sqlcipher3")

from mordred_hermes import dbcrypt
from mordred_hermes.dbcrypt import _hooks, _key, _migrate, _monitor, _shim

KEY = _key.derive(bytes(range(32)))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "hermes"
    conn = stdlib_sqlite3.connect(base.mkdir() or base / "state.db")
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    _migrate.migrate(base, KEY, arm=dbcrypt.arm, holders_of=lambda _p: [])
    _monitor.reset_cache()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_hooks, "_home", lambda: base)
    monkeypatch.setattr(_hooks, "_reported", set())
    monkeypatch.setattr(_hooks, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(_hooks, "_notify", lambda *a, **k: None)
    return base


def _protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    monkeypatch.setattr(_hooks, "_key_available", lambda: True)


def test_clean_state_has_no_findings(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _protected(monkeypatch)
    assert _monitor.check(home, key_available=lambda: True) == []
    assert _hooks.pre_llm_call() is None
    assert "encrypted at rest" in _hooks.status_line()


def test_a_plaintext_state_db_is_noticed_on_the_next_turn(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _protected(monkeypatch)
    (home / "state.db").unlink()
    plain = stdlib_sqlite3.connect(home / "state.db")  # Hermes recreated it without SQLCipher
    plain.execute("CREATE TABLE t (a)")
    plain.commit()
    plain.close()
    monkeypatch.setattr(_hooks, "_policy_mode", lambda: "lenient")

    findings = _monitor.check(home, key_available=lambda: True)
    assert [f.code for f in findings] == ["plaintext"] and "state.db" in findings[0].detail
    warning = _hooks.pre_llm_call()
    assert warning and "NOT protected" in warning["context"]
    assert "WARNING" in _hooks.status_line()


def test_strict_policy_stops_the_turn(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: False)  # this process has the stdlib module
    monkeypatch.setattr(_hooks, "_policy_mode", lambda: "strict")
    with pytest.raises(_hooks.DatabaseEncryptionRefused, match="not protected"):
        _hooks.pre_llm_call()
    assert issubclass(_hooks.DatabaseEncryptionRefused, BaseException)
    assert not issubclass(_hooks.DatabaseEncryptionRefused, Exception)  # escapes Hermes's hook guard


def test_missing_key_and_interrupted_conversion_are_findings(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_shim, "is_installed", lambda: True)
    _migrate.journal_path(home).write_text('{"swaps": []}', encoding="utf-8")
    codes = {f.code for f in _monitor.check(home, key_available=lambda: False)}
    assert codes == {"no_key", "interrupted"}


def test_unarmed_homes_report_only_a_scheduled_conversion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(_hooks, "_home", lambda: tmp_path)
    assert _monitor.check(tmp_path) == [] and _hooks.status_line() == ""
    _migrate.schedule(tmp_path)
    assert [f.code for f in _monitor.check(tmp_path)] == ["pending"]
    assert "not active yet" in _hooks.status_line()
    assert _hooks.pre_llm_call() is None  # scheduled is not a violation


def test_the_plaintext_probe_never_touches_the_file(home: Path) -> None:
    before = sorted(p.name for p in home.iterdir())
    assert _monitor.is_plaintext(home / "state.db") is False
    assert sorted(p.name for p in home.iterdir()) == before  # no -wal/-shm created


def test_component_registers_its_hooks_and_prompt_section() -> None:
    calls: list[tuple[str, object]] = []

    class Ctx:
        def register_hook(self, name: str, fn: object) -> None:
            calls.append((name, fn))

        def register_system_prompt_section(self, name: str, fn: object, max_chars: int) -> None:
            calls.append((name, fn))

    dbcrypt.register(Ctx())
    assert [name for name, _fn in calls] == ["on_session_start", "pre_llm_call", "mordred.databases"]
