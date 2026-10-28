"""The Windows fake must prove the checked-VFS selector is appended by production code."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _connection, _windows_vfs
from mordred_hermes.dbcrypt._authority import Authority
from tests._dbcrypt_windows_fakes import SELECTOR, protected_windows_environment
from tests.test_dbcrypt_authority import native_root as _native_root

native_root = _native_root


def _open(root, authority, name="state.db"):
    conn = _connection.open_protected(root / name, authority=authority)
    conn.execute("CREATE TABLE IF NOT EXISTS records(value)")
    conn.commit()
    return conn


def _assert_routed(native, root, name, *, count=1):
    hits = [uri for uri in native.routed_uris if name in uri]
    assert len(hits) == count, native.routed_uris
    assert all(uri.count(SELECTOR) == 1 for uri in hits)
    assert all(str(root.as_posix()) in uri for uri in hits)


def test_protected_open_routes_once_through_checked_vfs_under_registered_root(native_root, monkeypatch):
    root = native_root[0]
    native = protected_windows_environment(monkeypatch)
    authority = Authority.acquire(root)
    try:
        conn = _open(root, authority)
        try:
            assert list(native.roots.values()) and native.routed_uris
            _assert_routed(native, root, "state.db")
        finally:
            conn.close()
    finally:
        authority.close()


def test_backup_path_routes_through_checked_vfs(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._backup import backup_database

    root = native_root[0]
    native = protected_windows_environment(monkeypatch)
    authority = Authority.acquire(root)
    try:
        conn = _open(root, authority)
        conn.close()
        output = root.parent / "routing-backups"
        output.mkdir(mode=0o700)
        native.routed_uris.clear()
        backup_database(root / "state.db", output / "held.backup", authority=authority)
        assert any("held.backup" in uri and uri.count(SELECTOR) == 1 for uri in native.routed_uris), native.routed_uris
    finally:
        authority.close()


def test_maintenance_route_uses_checked_vfs(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _maintenance_windows as windows

    root = native_root[0]
    native = protected_windows_environment(monkeypatch)
    authority = Authority.acquire(root)
    try:
        _open(root, authority).close()
    finally:
        authority.close()
    native.routed_uris.clear()
    monkeypatch.setattr(_windows_vfs, "classify_windows_database", lambda path, **kw: Path(path))
    with acquire_exclusive(root), windows.connection(root / "state.db", root=root):
        _assert_routed(native, root, "state.db")


def test_fake_rejects_open_when_production_drops_the_selector(native_root, monkeypatch):
    root = native_root[0]
    protected_windows_environment(monkeypatch)
    real_open_bound = _connection._open_bound

    def without_selector(binding, authority, uri, *args, **kwargs):
        assert SELECTOR in uri  # the production builder still appends it; the mutant removes it
        return real_open_bound(binding, authority, uri.replace(SELECTOR, ""), *args, **kwargs)

    monkeypatch.setattr(_connection, "_open_bound", without_selector)
    authority = Authority.acquire(root)
    try:
        with pytest.raises(DatabaseRefused) as refused:
            _connection.open_protected(root / "state.db", authority=authority)
        # Production folds driver-side failures into a refusal; the fake's AssertionError is the cause.
        assert isinstance(refused.value.__context__, AssertionError)
        assert "exactly once" in str(refused.value.__context__)
        assert not (root / "state.db").exists()
    finally:
        authority.close()


def test_fake_rejects_database_outside_registered_root(native_root, monkeypatch):
    import sqlcipher3.dbapi2 as sc

    root = native_root[0]
    native = protected_windows_environment(monkeypatch)
    native.roots[1] = "\\registered\\elsewhere"
    with pytest.raises(AssertionError, match="outside registered roots"):
        sc.connect(f"file:{root.as_posix()}/state.db?mode=rwc{SELECTOR}", uri=True)
