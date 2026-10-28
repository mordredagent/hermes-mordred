"""Passive capability must never become enrollment or a hardware readiness claim."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from mordred_hermes import dbcrypt
from tests.test_dbcrypt_authority import native_root as native_root


def capability():
    from mordred_hermes.dbcrypt import _capability

    return _capability


@pytest.mark.parametrize("marker", [None, b"1\n", b"unknown marker\n"])
def test_status_never_enrolls_or_unwraps(tmp_path, monkeypatch, marker):
    from mordred_hermes.dbcrypt import _key, _windows_vfs

    home = tmp_path / "home"
    (home / "mordred").mkdir(parents=True)
    if marker is not None:
        (home / "mordred/db-encryption.marker").write_bytes(marker)
    before = {p.relative_to(home): p.read_bytes() for p in home.rglob("*") if p.is_file()}

    def forbidden(*args, **kwargs):
        pytest.fail("passive status performed native, SQL, or write work")

    monkeypatch.setattr(_key, "KeyProvider", forbidden)
    monkeypatch.setattr(_windows_vfs, "_load_native", forbidden)
    import sqlcipher3.dbapi2 as driver

    monkeypatch.setattr(driver, "connect", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    assert callable(getattr(dbcrypt, "database_status", None)), "passive status API is missing"
    status = dbcrypt.database_status(home)
    assert status.authenticated is False
    assert status.configured is (marker is not None)
    assert before == {p.relative_to(home): p.read_bytes() for p in home.rglob("*") if p.is_file()}


def test_driver_import_is_not_readiness(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", False)
    monkeypatch.setattr(sys, "platform", "win32")
    assert callable(getattr(dbcrypt, "database_status", None)), "passive status API is missing"
    status = dbcrypt.database_status(tmp_path)
    assert status.capability == "unavailable"
    assert status.authenticated is False
    assert status.reason and "admission is disabled" in status.reason


@pytest.mark.parametrize("server", [False, True], ids=["workstation", "server"])
def test_windows_edition_gates_status(tmp_path, monkeypatch, server):
    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: server)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: tmp_path / "owned.dll")
    monkeypatch.setattr(capability(), "_driver_present", lambda: True)
    status = dbcrypt.database_status(tmp_path)
    if server:
        assert status.capability == "unknown"
    else:
        assert status.capability == "unavailable"
        assert status.reason == "Windows workstation editions are not qualified"


@pytest.mark.parametrize(
    ("platform", "product_type", "expected"),
    [("win32", 3, True), ("win32", 1, False), ("win32", 2, False), ("linux", 3, False)],
)
def test_windows_edition_admitted_product_type(monkeypatch, platform, product_type, expected):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setattr(
        _windows_vfs,
        "sys",
        SimpleNamespace(platform=platform, getwindowsversion=lambda: SimpleNamespace(product_type=product_type)),
    )
    assert _windows_vfs.windows_edition_admitted() is expected


def test_windows_edition_admitted_fails_closed_on_error(monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setattr(_windows_vfs, "sys", SimpleNamespace(platform="win32"))
    assert _windows_vfs.windows_edition_admitted() is False


def test_native_and_lease_admission_flags_agree():
    from mordred_hermes import _database_locking_windows
    from mordred_hermes.dbcrypt import _windows_vfs

    assert _windows_vfs.NATIVE_QUALIFIED == _database_locking_windows.WINDOWS_LEASE_QUALIFIED


def test_unknown_platform_and_unsafe_metadata_are_not_available(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "unknown")
    status = capability().database_status(tmp_path)
    assert status.capability == "unavailable" and not status.authenticated
    monkeypatch.setattr(sys, "platform", "darwin")
    (tmp_path / "mordred").mkdir()
    (tmp_path / "mordred/db-encryption.marker").symlink_to(tmp_path / "absent")
    status = capability().database_status(tmp_path)
    assert status.configured and status.capability == "unknown" and not status.authenticated


def test_diagnose_refuses_legacy_and_pending_without_acquiring(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _key

    monkeypatch.setattr(_key, "KeyProvider", lambda **kwargs: pytest.fail("unadopted authority acquired"))
    (tmp_path / "mordred").mkdir()
    (tmp_path / "mordred/db-encryption.marker").write_bytes(b"1\n")
    status = capability().diagnose_database(tmp_path)
    assert status.capability == "unavailable" and not status.authenticated
    (tmp_path / "mordred/db-encryption.pending").write_text("pending")
    status = capability().diagnose_database(tmp_path)
    assert not status.authenticated


@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit")
def test_explicit_diagnosis_authenticates_once_and_releases(native_root):
    from mordred_hermes._database_lifecycle import acquire_exclusive

    root, backend, _, _ = native_root
    assert capability().database_status(root).authenticated is False
    assert backend.calls == []
    status = capability().diagnose_database(root)
    assert status.authenticated and status.capability == "available"
    assert len(backend.calls) == 1
    with acquire_exclusive(root):
        pass  # Diagnosis cannot retain a runtime lease.


def test_dependency_count_includes_retained_database_objects_without_sql(tmp_path, monkeypatch):
    from mordred_hermes import _database_lifecycle

    (tmp_path / "mordred").mkdir()
    for name in ("state.db", "state.db-wal", "state.db.bak", "mordred/db-encryption.pending"):
        (tmp_path / name).write_bytes(b"opaque")
    monkeypatch.setattr(_database_lifecycle, "acquire_runtime", lambda *a: pytest.fail("status acquired lease"))
    real = Path.open

    def metadata_only(path, *args, **kwargs):
        assert path.name not in {"state.db", "state.db-wal", "state.db.bak"}, "status opened raw database"
        return real(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", metadata_only)
    status = capability().database_status(tmp_path)
    assert status.dependencies == 4


def test_incomplete_inventory_reports_unknown_count(tmp_path):
    (tmp_path / "foreign.db.unknown").write_bytes(b"opaque")
    status = capability().database_status(tmp_path)
    assert status.dependencies is None
    assert status.reason and "inventory" in status.reason


def test_prompt_status_never_runs_monitor_or_acquires_key(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _hooks

    (tmp_path / "mordred").mkdir()
    (tmp_path / "mordred/db-encryption.marker").write_bytes(b"1\n")
    monkeypatch.setattr(_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setattr(_hooks, "_findings", lambda: pytest.fail("status opened SQL or acquired key"))
    text = _hooks.status_line()
    assert "encrypted at rest" not in text
    assert "not been authenticated" in text


@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit")
def test_native_prompt_does_not_revoke_registered_sql_on_changed_metadata(native_root, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _hooks, _key, _monitor
    from mordred_hermes.dbcrypt._connection import ProtectedConnection

    root, backend, _, _ = native_root
    provider = _key.KeyProvider(home=root)
    authority = provider.authority
    monkeypatch.setattr(dbcrypt, "_PROVIDER", provider)
    monkeypatch.setattr(_hooks, "_home", lambda: root)
    monkeypatch.setattr(_hooks, "_observation", None)
    _hooks.evaluate("test_runtime")
    calls = list(backend.calls)
    raw_calls = []
    connection = object.__new__(ProtectedConnection)
    connection._authority = authority
    connection._raw = SimpleNamespace(
        **{
            name: lambda *args, name=name: raw_calls.append(name)
            for name in ("set_authorizer", "set_progress_handler", "rollback", "close")
        }
    )
    connection._pid = os.getpid()
    connection._closed = connection._revoked = False
    connection._active = 0
    connection._vfs = None
    authority.register_connection(connection)
    monkeypatch.setattr(_monitor, "monitor_runtime", lambda *a: pytest.fail("render opened SQL"))
    monkeypatch.setattr(_key.KeyProvider, "__call__", lambda *a: pytest.fail("render acquired key"))
    monkeypatch.setattr(authority, "check", lambda: pytest.fail("render checked/revoked authority"))
    try:
        for changed in (False, True):
            if changed:
                (root / "mordred/db-encryption.marker").write_bytes(b"1\n")
            text = _hooks.status_line()
            assert raw_calls == [], "passive rendering revoked registered raw SQL"
            assert "encrypted at rest" not in text
            assert "NOT protected" not in text
            assert "not checked" in text
        monkeypatch.setattr(_hooks, "_observation", None)
        assert "not checked" in _hooks.status_line()
        monkeypatch.setattr(
            _hooks, "_observation", (root, authority, (_monitor.Finding("wrong_key", "recorded failure"),))
        )
        assert "NOT protected" in _hooks.status_line()
        assert backend.calls == calls
        assert not authority.terminal
        assert not connection._closed and not connection._revoked
    finally:
        provider.close()  # Explicit operational cleanup remains responsible for revocation.


@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit")
def test_diagnosis_authentication_failure_releases_lease(native_root, monkeypatch):
    from mordred_hermes._database_lifecycle import acquire_exclusive

    root, backend, _, _ = native_root

    def failed_hardware(*args, **kwargs):
        raise RuntimeError("PRIVATE-NATIVE-ERROR")

    monkeypatch.setattr(backend, "enclave_ecdh", failed_hardware)
    status = capability().diagnose_database(root)
    assert not status.authenticated and status.capability == "unavailable"
    assert status.reason and "PRIVATE" not in status.reason
    with acquire_exclusive(root):
        pass


def test_status_has_zero_os_write_and_raw_database_open_events(tmp_path):
    import subprocess

    (tmp_path / "mordred").mkdir()
    (tmp_path / "state.db").write_bytes(b"opaque retained database")
    (tmp_path / "mordred/db-encryption.marker").write_bytes(b"1\n")
    code = """
import os, sys, types
from pathlib import Path
audit = types.ModuleType('mordred_hermes._audit_support')
audit.safe_audit_append = lambda *args, **kwargs: None
sys.modules[audit.__name__] = audit
from mordred_hermes.dbcrypt import database_status
writes = []
def observe(event, args):
    if event == 'open':
        path, mode, flags = args
        if isinstance(path, (str, bytes)) and os.fsdecode(path).endswith('.db'):
            raise AssertionError('status opened raw database descriptor')
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            writes.append((event, str(path)))
    elif event in {'os.mkdir', 'os.rename', 'os.remove', 'os.rmdir', 'os.chmod', 'os.truncate', 'ctypes.dlopen'}:
        writes.append((event, str(args)))
sys.addaudithook(observe)
status = database_status(Path(os.environ['HERMES_HOME']))
assert status.configured and status.dependencies == 2 and not status.authenticated
assert writes == [], writes
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        env={**os.environ, "HERMES_HOME": str(tmp_path)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("eligible", [False, True], ids=["unavailable", "eligible"])
def test_pending_prompt_is_passive_and_requires_explicit_maintenance(tmp_path, monkeypatch, eligible):
    import sqlcipher3.dbapi2 as driver

    from mordred_hermes.dbcrypt import _hooks, _key, _migrate, _windows_vfs

    (tmp_path / "mordred").mkdir()
    (tmp_path / "mordred/db-encryption.pending").write_bytes(b"pending")
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: eligible)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: tmp_path / "owned.dll")
    monkeypatch.setattr(capability(), "_driver_present", lambda: True)
    monkeypatch.setattr(_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)

    def forbidden(*args, **kwargs):
        pytest.fail("passive pending status performed native, SQL, discovery, or conversion work")

    monkeypatch.setattr(_key, "KeyProvider", forbidden)
    monkeypatch.setattr(_windows_vfs, "_load_native", forbidden)
    monkeypatch.setattr(driver, "connect", forbidden)
    monkeypatch.setattr(_migrate, "discover", forbidden)
    status = capability().database_status(tmp_path)
    assert status.capability == ("unknown" if eligible else "unavailable")
    assert not status.authenticated
    text = _hooks.status_line()
    if eligible:
        assert "explicit supported maintenance" in text and "not active yet" in text
        assert "unavailable" not in text
    else:
        assert "unavailable" in text and "driver pair is unqualified" in text
    assert "until Hermes restarts" not in text
    assert "runs the next time Hermes starts" not in text
    assert before == {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("platform", ["linux", "win32"])
@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit")
def test_automatic_native_startup_installs_real_guarded_shim(native_root, monkeypatch, platform):
    """The public bootstrap must reach native custody, not its old platform refusal."""
    from types import SimpleNamespace

    from mordred_hermes import _runtime_bootstrap
    from mordred_hermes.dbcrypt import _shim, _windows_vfs

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(capability(), "sys", SimpleNamespace(platform=platform))
    # Platform-specific distribution metadata only; real Authority/lease/shim remain.
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: root / "owned.dll")
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setitem(sys.modules, "sqlite3", __import__("sqlite3"))
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2"))
    before = (root / "mordred/db-key-source.json").read_bytes()
    try:
        _runtime_bootstrap._install_database_encryption()
        assert _shim.is_installed()
        assert dbcrypt._PROVIDER.authority.root == root
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        assert (root / "mordred/db-key-source.json").read_bytes() == before
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_native_passive_eligibility_is_unauthenticated_and_requires_driver(tmp_path, monkeypatch, platform):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _key, _windows_vfs

    module = capability()
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: tmp_path / "owned.dll")
    monkeypatch.setattr(_key, "KeyProvider", lambda **kw: pytest.fail("passive custody acquisition"))
    monkeypatch.setattr(module, "_driver_present", lambda: True)
    before = list(tmp_path.iterdir())
    status = module.database_status(tmp_path)
    assert status.capability == "unknown" and not status.authenticated
    assert list(tmp_path.iterdir()) == before
    monkeypatch.setattr(module, "_driver_present", lambda: False)
    status = module.database_status(tmp_path)
    assert status.capability == "unavailable" and not status.authenticated


def test_windows_activation_still_refuses_unqualified_driver_or_missing_owned_asset(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setattr(capability(), "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: False)
    status = capability().database_status(tmp_path)
    assert "driver pair" in status.reason
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: True)
    monkeypatch.setattr(_windows_vfs, "packaged_library_path", lambda: None)
    assert "owned Windows VFS asset" in capability().database_status(tmp_path).reason


@pytest.mark.parametrize("failure", ["driver", "asset", "qualification"])
@pytest.mark.skipif(os.name != "posix", reason="uses the POSIX authority fixture; Windows native proof is explicit")
def test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody(native_root, monkeypatch, failure):
    from types import SimpleNamespace

    from mordred_hermes import _runtime_bootstrap
    from mordred_hermes.dbcrypt import _windows_vfs

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(capability(), "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", failure != "qualification")
    monkeypatch.setattr(_windows_vfs, "windows_edition_admitted", lambda: True)
    monkeypatch.setattr(_windows_vfs, "driver_distribution_qualified", lambda: failure != "driver")
    monkeypatch.setattr(
        _windows_vfs, "packaged_library_path", lambda: None if failure == "asset" else root / "owned.dll"
    )
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setitem(sys.modules, "sqlite3", __import__("sqlite3"))
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2"))
    try:
        with pytest.raises(RuntimeError, match="database runtime unavailable"):
            _runtime_bootstrap._install_database_encryption()
        assert backend.calls == []
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()
