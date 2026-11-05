"""Lexical refusal precedes bootstrap or any native database open."""

from __future__ import annotations

import importlib
import sqlite3
import sys
from pathlib import Path
from types import ModuleType

import pytest

from tests.test_dbcrypt_authority import native_root as native_root


def implementation() -> ModuleType:
    from mordred_hermes import dbcrypt

    assert importlib.util.find_spec(f"{dbcrypt.__name__}._windows_vfs") is not None, "checked VFS admission is missing"
    return importlib.import_module(f"{dbcrypt.__name__}._windows_vfs")


@pytest.mark.parametrize(
    ("path", "uri"),
    [
        (r"\\server\share\state.db", False),
        (r"\\?\C:\private\state.db", False),
        (r"\\.\C:\private\state.db", False),
        (r"C:\private\state.db:stream", False),
        (r"C:state.db", False),
        (r"\private\state.db", False),
        (r"C:\private\state.db.", False),
        (r"C:\private\state.db ", False),
        (r"C:\private\..\state.db", False),
        (r"C:\private\CON.db", False),
        (r"C:\private\LPT¹.db", False),
        (r"C:\private\state?.db", False),
        ("C:\\private\\state.db\x00ignored", False),
        (r"C:\private-other\state.db", False),
        (r"D:\private\state.db", False),
        (r"C:\private", False),
        (r"C:\private\\state.db", False),
        ("file:///C:/private/state.db%3fstream", True),
        ("file:///C:/private/state.db?vfs=win32", True),
        ("file:///C:/private/state.db?vfs=mordred_checked_v1", True),
        ("file:C:/private/state.db", True),
        ("file:///C:/private/state.db", True),
        (":memory:", False),
        ("", False),
        ("C:\\private\\" + "x" * 218 + ".db", False),
    ],
)
def test_unsupported_path_never_calls_xopen(path: str, uri: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    unchecked_opens: list[str] = []

    def unexpected(*args: object, **kwargs: object) -> None:
        unchecked_opens.append(str(args))
        pytest.fail("classification must not touch the native boundary")

    monkeypatch.setattr(module, "_load_native", unexpected)
    with pytest.raises(ValueError):
        module.classify_windows_database(path, uri=uri, root=Path(r"C:\private"))
    assert unchecked_opens == []


@pytest.mark.parametrize("path", [r"C:\private\state.db", r"c:\PRIVATE\nested\state.db", "C:/private/日本語.db"])
def test_supported_drive_path_is_classified_without_resolving_on_host(path: str) -> None:
    result = implementation().classify_windows_database(path, uri=False, root=Path(r"C:\private"))
    assert str(result).replace("\\", "/").casefold() == path.replace("\\", "/").casefold()


@pytest.mark.parametrize("root", ["C:\\", r"C:private", r"\\server\private", r"C:\private.", r"C:\private\.."])
def test_invalid_root_is_refused(root: str) -> None:
    with pytest.raises(ValueError):
        implementation().classify_windows_database(r"C:\private\state.db", uri=False, root=Path(root))


def test_unqualified_registration_cannot_enable_runtime_support(tmp_path: Path, monkeypatch) -> None:
    # A supported adapter still refuses an unqualified driver pair before
    # selecting or loading any library, including an ambient override.
    module = implementation()
    library = tmp_path / "unchecked.dll"
    library.write_bytes(b"inert fixture; never loaded")
    monkeypatch.setenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", str(library))
    monkeypatch.setattr(module, "windows_edition_admitted", lambda: True)  # the driver check is under test
    monkeypatch.setattr(module, "driver_distribution_qualified", lambda: False)

    def forbidden(*args, **kwargs):
        pytest.fail("unqualified driver reached native library selection or loading")

    monkeypatch.setattr(module, "packaged_library_path", forbidden)
    monkeypatch.setattr(module.ctypes, "CDLL", forbidden)
    with pytest.raises(
        RuntimeError, match=r"^Windows checked VFS requires its qualified SQLCipher 0\.5\.7 driver pair$"
    ):
        module._load_native()
    assert library.read_bytes() == b"inert fixture; never loaded"


def test_other_platform_registration_does_not_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    monkeypatch.setattr(module.sys, "platform", "darwin")
    driver = ModuleType("no_driver_calls")
    with pytest.raises(RuntimeError, match="Windows"):
        module.register_checked_vfs(driver, root=Path(r"C:\private"))


def test_non_cipher_driver_refuses_before_loading_native(monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module, "windows_edition_admitted", lambda: True)  # the driver check is under test

    def unexpected() -> None:
        pytest.fail("must not pin a non-SQLCipher driver's API table")

    monkeypatch.setattr(module, "_load_native", unexpected)
    with pytest.raises(RuntimeError, match="SQLCipher"):
        module.register_checked_vfs(sqlite3, root=Path(r"C:\private"))


def test_same_root_leases_survive_independent_close_and_busy_last_release(monkeypatch):
    from pathlib import PureWindowsPath

    from tests._dbcrypt_windows_fakes import registration_environment

    module, driver, _api, native = registration_environment(monkeypatch)
    first = module.register_checked_vfs(driver, root=PureWindowsPath(r"C:\private"))
    second = None
    try:
        second = module.register_checked_vfs(driver, root=PureWindowsPath(r"c:\PRIVATE"))
        assert first is not second and first._token == second._token
        first.close()
        first.close()
        assert len(native.roots) == 1
        native.busy.add(second._token)
        with pytest.raises(RuntimeError, match="busy"):
            second.close()
        assert len(native.roots) == 1
        native.busy.clear()
        second.close()
        assert native.roots == {}
    finally:
        native.busy.clear()
        if second is not None:
            second.close()
        first.close()


def test_concurrent_root_leases_share_one_registration(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import PureWindowsPath

    from tests._dbcrypt_windows_fakes import registration_environment

    module, driver, _api, native = registration_environment(monkeypatch)
    with ThreadPoolExecutor(max_workers=4) as workers:
        leases = list(
            workers.map(lambda _: module.register_checked_vfs(driver, root=PureWindowsPath(r"C:\private")), range(8))
        )
        assert len(native.roots) == 1
        list(workers.map(lambda lease: lease.close(), leases))
    assert native.roots == {}


@pytest.mark.parametrize("change", ["identity", "driver", "library", "owner", "overlap"])
def test_shared_registration_never_reuses_an_incompatible_root(monkeypatch, change):
    from pathlib import PureWindowsPath

    from mordred_hermes._private_fs import FileIdentity
    from tests._dbcrypt_windows_fakes import NativeRegistry, registration_environment

    module, driver, api, native = registration_environment(monkeypatch)
    root = PureWindowsPath(r"C:\private")
    first = module.register_checked_vfs(driver, root=root)
    try:
        if change == "identity":
            api.change(str(root), identity=FileIdentity(11, b"changed-identity!"))
        elif change == "driver":
            other = ModuleType("other_driver")
            other.connect = driver.connect
            driver = other
        elif change == "library":
            other_native = NativeRegistry()
            other_native._name = "other DLL"
            monkeypatch.setattr(module, "_load_native", lambda: other_native)
        elif change == "owner":
            api.user = b"other-user"
        else:
            root /= "nested"
            api.add(str(root), True)
        with pytest.raises((RuntimeError, OSError)):
            module.register_checked_vfs(driver, root=root)
        assert len(native.roots) == 1
    finally:
        first.close()


@pytest.mark.parametrize("directory", [False, True])
def test_windows_identity_uses_private_dacl_instead_of_synthesized_write_bits(monkeypatch, directory):
    import os
    import stat
    from pathlib import PureWindowsPath
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _connection
    from tests._dbcrypt_windows_fakes import registration_environment

    _module, _driver, _api, _native = registration_environment(monkeypatch)
    monkeypatch.setattr(_connection, "os", SimpleNamespace(name="nt", getpid=os.getpid))
    kind = stat.S_IFDIR if directory else stat.S_IFREG

    class WindowsPath(PureWindowsPath):
        def lstat(self):
            return SimpleNamespace(st_mode=kind | 0o666, st_nlink=1, st_ino=4, st_dev=11, st_uid=0)

    path = WindowsPath(r"C:\private" if directory else r"C:\private\state.db")
    identity = _connection._identity(path, directory=directory)
    assert identity[:2] == (11, int.from_bytes(bytes([2 if directory else 3]) * 16))


@pytest.mark.parametrize("change", ["owner", "dacl", "reparse", "hardlink"])
def test_windows_identity_still_refuses_unsafe_native_metadata(monkeypatch, change):
    import os
    from pathlib import PureWindowsPath
    from types import SimpleNamespace

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes._private_fs._windows_security import Ace
    from mordred_hermes.dbcrypt import _connection
    from tests._dbcrypt_windows_fakes import registration_environment

    _module, _driver, api, _native = registration_environment(monkeypatch)
    monkeypatch.setattr(_connection, "os", SimpleNamespace(name="nt", getpid=os.getpid))
    path = r"C:\private\state.db"
    if change == "owner":
        api.user = b"foreign"
    elif change == "dacl":
        api.descriptors[path.casefold()].aces.append(Ace(0, 0, 1, b"everyone"))
    else:
        api.change(path, **({"reparse": True} if change == "reparse" else {"links": 2}))
    with pytest.raises(DatabaseRefused):
        _connection._identity(PureWindowsPath(path), directory=False)


_REMOTE_DATABASE_NAMES = [
    r"\\server\share\state.db",
    "//server/share/state.db",
    r"\/server\share/state.db",
    r"\\?\UNC\server\share\state.db",
    r"\\?\C:\private\state.db",
    r"\\.\C:\private\state.db",
    r"\??\C:\private\state.db",
    "/??/C:/private/state.db",
]


@pytest.mark.parametrize("name", _REMOTE_DATABASE_NAMES)
@pytest.mark.parametrize("representation", ["str", "bytes", "pathlike"])
def test_native_shim_refuses_windows_remote_names_before_path_io(monkeypatch, name, representation):
    import os
    from types import SimpleNamespace

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _policy, _shim

    monkeypatch.setattr(_policy, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(_shim, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    value = name if representation == "str" else os.fsencode(name) if representation == "bytes" else Path(name)

    def forbidden(*args, **kwargs):
        pytest.fail("remote name reached filesystem classification")

    # Exercise the actual shim entry, including its scope/realpath decision.
    authority = SimpleNamespace(check=lambda: None, root=Path("C:/private"))
    connect = _shim._native_connect(authority)
    with monkeypatch.context() as guard:
        guard.setattr(Path, "absolute", forbidden)
        guard.setattr(Path, "exists", forbidden)
        guard.setattr(Path, "stat", forbidden)
        guard.setattr(os.path, "realpath", forbidden)
        with pytest.raises(DatabaseRefused) as refused:
            connect(value)
    assert name not in str(refused.value)


@pytest.mark.parametrize("name", _REMOTE_DATABASE_NAMES)
@pytest.mark.parametrize("mode", ["ro", "rw", "rwc"])
def test_native_shim_refuses_encoded_remote_uri_before_exists(monkeypatch, name, mode):
    import os
    from types import SimpleNamespace
    from urllib.parse import quote

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _policy, _shim

    monkeypatch.setattr(_policy, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(_shim, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    uri = f"file:{quote(name, safe='')}?mode={mode}"

    def forbidden(*args, **kwargs):
        pytest.fail("URI reached filesystem before lexical refusal")

    with monkeypatch.context() as guard:
        guard.setattr(Path, "exists", forbidden)
        guard.setattr(Path, "absolute", forbidden)
        with pytest.raises(DatabaseRefused):
            _shim._native_path(uri, uri=True)


@pytest.mark.parametrize("entry", ["shim", "direct"])
def test_windows_relative_path_on_unc_cwd_refused_after_absolutizing(monkeypatch, entry):
    import os
    from pathlib import PureWindowsPath
    from types import SimpleNamespace

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _connection, _policy, _shim

    for module in (_policy, _shim, _connection):
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(_connection, "_PathBinding", lambda *a, **k: pytest.fail("remote binding attempted"))
    authority = SimpleNamespace(check=lambda: None)
    with monkeypatch.context() as guard:
        guard.setattr(Path, "absolute", lambda self: PureWindowsPath(r"\\server\share\state.db"))
        with pytest.raises(DatabaseRefused, match="namespace"):
            if entry == "shim":
                _shim._native_path("state.db", uri=False)
            else:
                _connection._open(Path("state.db"), authority=authority, timeout=5, readonly=False, protected=True)


@pytest.mark.parametrize("name", _REMOTE_DATABASE_NAMES)
def test_direct_connection_refuses_remote_names_before_absolute_binding_or_sql(monkeypatch, name):
    import os
    from types import SimpleNamespace

    import sqlcipher3.dbapi2 as sc

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _connection, _policy

    for module in (_policy, _connection):
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))

    def forbidden(*args, **kwargs):
        pytest.fail("remote destination reached I/O")

    monkeypatch.setattr(_connection, "_PathBinding", forbidden)
    monkeypatch.setattr(sc, "connect", forbidden)
    authority = SimpleNamespace(check=lambda: None)
    with monkeypatch.context() as guard:
        guard.setattr(Path, "absolute", forbidden)
        guard.setattr(Path, "stat", forbidden)
        guard.setattr(Path, "lstat", forbidden)
        with pytest.raises(DatabaseRefused) as refused:
            _connection._open(Path(name), authority=authority, timeout=5, readonly=False, protected=True)
    assert name not in str(refused.value)


@pytest.mark.parametrize("name", ["state.db", "C:/private/state.db", ":memory:"])
def test_windows_lexical_guard_keeps_local_and_memory_paths(monkeypatch, name):
    import os
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _policy, _shim

    for module in (_policy, _shim):
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    path, readonly = _shim._native_path(name, uri=False)
    assert path == (None if name == ":memory:" else Path(name).absolute())
    assert not readonly


def test_posix_double_slash_path_keeps_existing_policy():
    import os

    from mordred_hermes.dbcrypt import _shim

    if os.name == "nt":
        pytest.skip("POSIX compatibility")
    path, readonly = _shim._native_path("//local/state.db", uri=False)
    assert path == Path("//local/state.db").absolute()
    assert not readonly


def test_native_memory_uri_rw_keeps_existing_refusal(tmp_path, monkeypatch):
    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _shim

    monkeypatch.chdir(tmp_path)
    with pytest.raises(DatabaseRefused, match="does not exist"):
        _shim._native_path("file::memory:?mode=rw", uri=True)


def _simulate_windows_backup(monkeypatch):
    import os
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _backup, _maintenance_windows, _policy

    for module in (_policy, _backup):
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    # Off Windows the edition gate refuses too, which would hide a missing guard.
    monkeypatch.setattr(_maintenance_windows, "require_qualified", lambda: None)
    return _backup


def _forbid_remote_io(guard, remote):
    """Fail on any filesystem step for ``remote``; other paths keep real behavior."""
    import os

    from mordred_hermes.dbcrypt import _backup

    def wrap(owner, name):
        original = getattr(owner, name)

        def checked(*args, **kwargs):
            if args and any(isinstance(a, str | Path) and str(a) == str(Path(remote)) for a in args):
                pytest.fail(f"{name} reached a remote backup path before refusal")
            return original(*args, **kwargs)

        guard.setattr(owner, name, checked)

    for name in ("absolute", "resolve", "exists", "stat", "lstat"):
        wrap(Path, name)
    wrap(os.path, "realpath")
    wrap(_backup, "open_private_directory")


@pytest.mark.parametrize("name", _REMOTE_DATABASE_NAMES)
def test_backup_destination_refuses_remote_names_before_any_filesystem_call(monkeypatch, name):
    import os

    from mordred_hermes._core._database_contracts import DatabaseRefused

    backup = _simulate_windows_backup(monkeypatch)

    def forbidden(*args, **kwargs):
        pytest.fail("remote destination reached the filesystem")

    with monkeypatch.context() as guard:
        for method in ("absolute", "resolve", "exists", "stat", "lstat"):
            guard.setattr(Path, method, forbidden)
        guard.setattr(os.path, "realpath", forbidden)
        guard.setattr(backup, "open_private_directory", forbidden)
        with pytest.raises(DatabaseRefused, match="namespace") as refused:
            backup._canonical_destination(Path(name))
    assert name not in str(refused.value)


def test_backup_relative_destination_under_unc_cwd_refused_after_absolute(monkeypatch):
    from pathlib import PureWindowsPath

    from mordred_hermes._core._database_contracts import DatabaseRefused

    backup = _simulate_windows_backup(monkeypatch)
    monkeypatch.setattr(backup, "open_private_directory", lambda *a, **k: pytest.fail("remote directory opened"))
    resolved = []

    class UncAbsolute(PureWindowsPath):
        def resolve(self, *args, **kwargs):
            resolved.append(self)
            return self

    with monkeypatch.context() as guard:
        guard.setattr(Path, "absolute", lambda self: UncAbsolute(r"\\server\share\x.db"))
        with pytest.raises(DatabaseRefused, match="namespace"):
            backup._canonical_destination(Path("x.db"))
    assert resolved == []


@pytest.mark.parametrize("name", _REMOTE_DATABASE_NAMES)
@pytest.mark.parametrize("entry", ["find", "delete", "pending_destination", "pending_prepared"])
def test_registered_backup_values_refuse_remote_names_before_filesystem(monkeypatch, tmp_path, name, entry):
    from contextlib import nullcontext

    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes.dbcrypt import _migrate

    backup = _simulate_windows_backup(monkeypatch)
    local = str(tmp_path.resolve() / "x.db")
    monkeypatch.setattr(backup, "asdict", lambda snapshot: {"synthetic": True})
    monkeypatch.setattr(backup, "open_private_directory", lambda *a, **k: nullcontext())
    journal = {"version": 1, "snapshot": {"synthetic": True}, "phase": "preparing"}
    journal |= {"destination": name, "prepared": local}
    if entry == "pending_prepared":
        journal |= {"destination": local, "prepared": name}
    monkeypatch.setattr(_migrate, "_read_json", lambda root, record: journal)
    calls = {
        "find": lambda: backup._find(tmp_path, Path(name), None),
        "delete": lambda: backup._delete_registered_file({"path": name}, []),
        "pending_destination": lambda: backup._pending(tmp_path, None),
        "pending_prepared": lambda: backup._pending(tmp_path, None),
    }
    with monkeypatch.context() as guard:
        _forbid_remote_io(guard, name)
        with pytest.raises(DatabaseRefused, match="namespace"):
            calls[entry]()


# ``native_root`` builds POSIX custody, whose locking needs ``os.O_DIRECTORY``. The
# refusal order is simulated here; test_dbcrypt_windows_native_paths.py runs on Windows.
@pytest.mark.skipif(sys.platform == "win32", reason="the native_root fixture uses POSIX custody")
@pytest.mark.parametrize(
    "route",
    [
        "backup_destination",
        "backup_source",
        "restore_source",
        "restore_destination",
        "export_source",
        "export_output",
        "delete",
    ],
)
def test_public_backup_routes_refuse_remote_operator_paths_first(monkeypatch, native_root, route):
    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt._authority import Authority

    root = native_root[0]
    remote = r"\\server\share\x.db"
    local = root / "state.db"
    outside = root.parent / "outside.db"
    backup = _simulate_windows_backup(monkeypatch)

    def attempt():
        if route.startswith(("backup", "delete")):
            authority = Authority.acquire(root)
            try:
                if route == "backup_destination":
                    backup.backup_database(local, Path(remote), authority=authority)
                elif route == "backup_source":
                    backup.backup_database(Path(remote), outside, authority=authority)
                else:
                    backup.delete_backup(Path(remote), authority=authority)
            finally:
                authority.close()
            return
        with acquire_exclusive(root) as lease:
            if route == "restore_source":
                backup.restore_database(Path(remote), local, lease=lease)
            elif route == "restore_destination":
                backup.restore_database(outside, Path(remote), lease=lease)
            elif route == "export_source":
                backup.export_database(root, Path(remote), outside, lease=lease)
            else:
                backup.export_database(root, outside, Path(remote), lease=lease)

    with monkeypatch.context() as guard:
        _forbid_remote_io(guard, remote)
        with pytest.raises(DatabaseRefused, match="namespace"):
            attempt()


@pytest.mark.parametrize("remote", [r"\\server\share\x.db", r"\\?\C:\private\x.db", "//server/share/x.db"])
def test_abandon_state_never_touches_remote_or_device_paths(monkeypatch, remote):
    backup = _simulate_windows_backup(monkeypatch)
    monkeypatch.setattr(Path, "lstat", lambda self: pytest.fail("lstat reached a remote backup path"))
    assert backup._lexical_state(Path(remote)) == "unknown"


def test_abandon_with_remote_journal_paths_reports_unknown_without_io(monkeypatch, native_root):
    import json

    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt._authority import Authority
    from tests.test_dbcrypt_adoption import cipher

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    destination = root.parent / (root.name + "-remote.backup")
    from mordred_hermes.dbcrypt import _backup

    def crash(point):
        if point == "verified":
            raise RuntimeError("crash")

    authority = Authority.acquire(root)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(_backup, "_transition", crash)
            with pytest.raises(RuntimeError, match="crash"):
                _backup.backup_database(root / "state.db", destination, authority=authority)
    finally:
        authority.close()
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    data["destination"] = "//server/share/x.db"
    data["prepared"] = "//server/share/x.db.mordred-backup-ab"
    journal.write_text(json.dumps(data))
    backup = _simulate_windows_backup(monkeypatch)
    real_lstat = Path.lstat

    def guarded(self):
        if str(self).startswith("//server"):
            pytest.fail("lstat reached a remote backup path")
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", guarded)
    with acquire_exclusive(root) as lease:
        preview = backup.abandon_backup_journal(root, lease=lease, commit=False)
    assert preview is not None
    assert (preview.destination_state, preview.staging_state) == ("unknown", "unknown")
