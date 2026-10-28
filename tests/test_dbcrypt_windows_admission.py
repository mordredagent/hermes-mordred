"""Every Windows edition/lease admission refusal fails a test when removed."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._authority import Authority
from tests.test_dbcrypt_authority import native_root as _native_root

native_root = _native_root


@pytest.fixture
def authority(native_root):
    value = Authority.acquire(native_root[0])
    yield value
    value.close()


def test_protected_open_refuses_workstation_editions_before_creating_anything(native_root, authority, monkeypatch):
    from mordred_hermes.dbcrypt import _connection, _windows_vfs
    from tests._dbcrypt_windows_fakes import protected_windows_environment

    native = protected_windows_environment(monkeypatch)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: False)
    target = native_root[0] / "state.db"
    with pytest.raises(DatabaseRefused, match="workstation editions"):
        _connection.open_protected(target, authority=authority)
    assert not target.exists() and native.roots == {} and native.routed_uris == []


def test_load_native_refuses_workstation_editions(monkeypatch):
    from mordred_hermes.dbcrypt import _windows_vfs
    from tests._dbcrypt_windows_fakes import registration_environment

    real = _windows_vfs._load_native
    module, _driver, _api, _native = registration_environment(monkeypatch)
    monkeypatch.setattr(module, "windows_edition_admitted", lambda: False)
    with pytest.raises(RuntimeError, match="workstation editions"):
        real()


def test_register_checked_vfs_refuses_workstation_editions(monkeypatch):
    from tests._dbcrypt_windows_fakes import registration_environment

    module, driver, _api, native = registration_environment(monkeypatch)
    monkeypatch.setattr(module, "windows_edition_admitted", lambda: False)
    with pytest.raises(RuntimeError, match="workstation editions"):
        module.register_checked_vfs(driver, root=PureWindowsPath(r"C:\private"))
    assert native.roots == {}


@pytest.mark.parametrize("qualified", [False, True])
def test_database_lease_requires_qualified_windows_leases(tmp_path: Path, monkeypatch, qualified):
    from mordred_hermes import _database_lifecycle, _database_locking_windows

    sentinel = object()
    seen: list[Path] = []

    def windows_open(root):
        seen.append(root)
        return sentinel

    monkeypatch.setattr(_database_lifecycle, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(_database_locking_windows, "WINDOWS_LEASE_QUALIFIED", qualified)
    monkeypatch.setattr(_database_locking_windows, "open_lock", windows_open)
    if not qualified:
        with pytest.raises(DatabaseRefused, match="leases are not qualified"):
            _database_lifecycle._open(tmp_path)
        assert seen == []
    else:
        assert _database_lifecycle._open(tmp_path) is sentinel
        assert seen == [tmp_path]
