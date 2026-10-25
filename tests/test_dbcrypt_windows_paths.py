"""Lexical refusal precedes bootstrap or any native database open."""

from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest


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

    from mordred_hermes._database_contracts import DatabaseRefused
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
