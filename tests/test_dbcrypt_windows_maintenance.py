"""Portable preparation checks; these do not qualify actual Windows native I/O."""

from __future__ import annotations

import contextlib

import pytest
import sqlcipher3.dbapi2 as sc

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt import _maintenance_windows as windows
from mordred_hermes.dbcrypt import _windows_vfs


def test_windows_maintenance_refuses_before_any_io_when_unqualified(tmp_path, monkeypatch):
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", False)
    monkeypatch.setattr(windows, "exclusive_root", lambda *args: pytest.fail("lease I/O before qualification"))
    with pytest.raises(DatabaseRefused, match="qualification"), windows.connection(tmp_path / "state.db"):
        pytest.fail("unqualified route admitted")


def test_internal_export_authorizer_replaces_prior_deny_for_only_exact_path(tmp_path):
    target = tmp_path / "quoted ' staged.db"
    with contextlib.closing(sc.connect(":memory:")) as conn:
        conn.set_authorizer(lambda action, *args: sc.SQLITE_DENY if action == sc.SQLITE_ATTACH else sc.SQLITE_OK)
        literal = str(target).replace("'", "''")
        with pytest.raises(sc.DatabaseError):
            conn.execute(f"ATTACH DATABASE '{literal}' AS enc KEY ''")
        conn.set_authorizer(windows.authorizer(target, "enc"))
        conn.execute(f"ATTACH DATABASE '{literal}' AS enc KEY ''")
        conn.execute("CREATE TABLE enc.proof(value TEXT)")
        conn.execute("DETACH DATABASE enc")
        for sql in (
            "ATTACH DATABASE ':memory:' AS wrong",
            f"ATTACH DATABASE '{tmp_path / 'foreign.db'}' AS enc",
            "DETACH DATABASE main",
            "PRAGMA temp_store=FILE",
            "PRAGMA temp_store_directory='elsewhere'",
            "PRAGMA mmap_size=1024",
            "SELECT load_extension('foreign')",
        ):
            with pytest.raises(sc.DatabaseError):
                conn.execute(sql)
        conn.execute("PRAGMA temp_store=MEMORY")
    assert target.exists() and not (tmp_path / "foreign.db").exists()


def test_windows_offline_connection_requires_genuine_ex_before_driver(tmp_path, monkeypatch):
    monkeypatch.setattr(windows, "require_qualified", lambda: None)
    monkeypatch.setattr(_windows_vfs, "register_checked_vfs", lambda *a, **k: pytest.fail("driver before EX"))
    with pytest.raises(DatabaseRefused, match="exclusive"), windows.connection(tmp_path / "state.db"):
        pytest.fail("offline SQL without EX")
