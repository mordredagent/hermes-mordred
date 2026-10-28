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
    with pytest.raises(DatabaseRefused, match="admission is disabled"), windows.connection(tmp_path / "state.db"):
        pytest.fail("unqualified route admitted")


def test_windows_maintenance_refuses_workstation_edition(monkeypatch):
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: False)
    with pytest.raises(DatabaseRefused, match="workstation editions are not qualified"):
        windows.require_qualified()
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    windows.require_qualified()


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


@pytest.mark.parametrize("native_code", [2, 3])
def test_windows_missing_staging_reserves_and_records_identity(tmp_path, monkeypatch, native_code):
    import json

    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.dbcrypt import _migrate

    (tmp_path / "mordred").mkdir(mode=0o700)
    source = tmp_path / "state.db"
    source.write_bytes(b"original remains unchanged")
    source.chmod(0o600)
    staged = tmp_path / "state.db.mordred-enc"
    entry = {"relative": source.name, "prepared": staged.name, "prepared_identity": None}
    data = {"files": [entry]}
    identity, reserve = _migrate._file_identity, _migrate._reserve
    calls = []

    def checked_identity(path):
        if path == staged and not staged.exists():
            raise PrivateFSError("missing", "open", native_code=native_code)
        return identity(path)

    def checked_reserve(path):
        calls.append(path)
        reserve(path)

    monkeypatch.setattr(_migrate, "_file_identity", checked_identity)
    monkeypatch.setattr(_migrate, "_reserve", checked_reserve)
    _migrate._reserve_journal_staging(tmp_path, data, entry)
    assert calls == [staged]
    assert staged.read_bytes() == b""
    assert source.read_bytes() == b"original remains unchanged"
    persisted = json.loads(_migrate.journal_path(tmp_path).read_bytes())
    assert persisted["files"][0]["prepared_identity"] == identity(staged)


@pytest.mark.parametrize(
    "reason,commit_state",
    [(reason, "not_committed") for reason in ("unsafe", "busy", "access_denied", "io", "unsupported", "exists")]
    + [("missing", "uncertain"), ("io", "uncertain")],
)
def test_windows_staging_errors_preserve_survivors_and_journal(tmp_path, monkeypatch, reason, commit_state):
    from mordred_hermes._private_fs import PrivateFSError
    from mordred_hermes.dbcrypt import _migrate

    (tmp_path / "mordred").mkdir(mode=0o700)
    source = tmp_path / "state.db"
    staged = tmp_path / "state.db.mordred-enc"
    for path, content in ((source, b"original"), (staged, b"existing survivor")):
        path.write_bytes(content)
        path.chmod(0o600)
    entry = {"relative": source.name, "prepared": staged.name, "prepared_identity": None}
    data = {"files": [entry]}
    _migrate._put_json(tmp_path, _migrate.JOURNAL_SUBPATH[-1], data)
    journal = _migrate.journal_path(tmp_path)
    before = {path: path.read_bytes() for path in (source, staged, journal)}
    error = PrivateFSError(reason, "open", commit_state=commit_state)

    def refusal(path):
        assert path == staged
        raise error

    monkeypatch.setattr(_migrate, "_file_identity", refusal)
    monkeypatch.setattr(_migrate, "_reserve", lambda path: pytest.fail("reserve after unclassified absence"))
    with pytest.raises(PrivateFSError) as caught:
        _migrate._reserve_journal_staging(tmp_path, data, entry)
    assert caught.value is error
    assert entry["prepared_identity"] is None
    assert {path: path.read_bytes() for path in before} == before
