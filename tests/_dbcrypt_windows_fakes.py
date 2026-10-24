"""Native ABI doubles only; real private-path/DACL and registration policy runs."""

from contextlib import contextmanager
from dataclasses import replace
from types import ModuleType, SimpleNamespace

from mordred_hermes._private_fs import FileIdentity, PrivateFSError
from mordred_hermes._private_fs._windows_api import Metadata
from mordred_hermes._private_fs._windows_security import ADMINISTRATORS, SYSTEM, Ace, Descriptor


class MetadataAPI:
    def __init__(self):
        self.user = b"fixture-user"
        self.entries = {}
        self.descriptors = {}
        for name, directory in (("C:\\", True), (r"C:\private", True), (r"C:\private\state.db", False)):
            self.add(name, directory)

    def add(self, path, directory):
        self.entries[path.casefold()] = Metadata(
            FileIdentity(11, bytes([len(self.entries) + 1]) * 16), directory, False, 1, 0
        )
        self.descriptors[path.casefold()] = Descriptor(
            self.user, True, [Ace(0, 0, 0x1F01FF, sid) for sid in (self.user, SYSTEM, ADMINISTRATORS)]
        )

    @contextmanager
    def open(self, path, **kwargs):
        if path.casefold() not in self.entries:
            raise PrivateFSError("missing", "open")
        yield SimpleNamespace(api=self, path=path)

    def user_sid(self):
        return self.user

    def metadata(self, handle):
        return self.entries[handle.path.casefold()]

    def descriptor(self, handle):
        return self.descriptors[handle.path.casefold()]

    def final_path(self, handle):
        return handle.path

    def validate_drive(self, drive):
        assert drive.casefold() == "c:\\"

    def validate_volume(self, handle):
        assert self.metadata(handle).identity.volume == 11

    def mtime_ns(self, handle):
        return 0

    def change(self, path, **kwargs):
        self.entries[path.casefold()] = replace(self.entries[path.casefold()], **kwargs)


class NativeRegistry:
    def __init__(self):
        self.roots = {}
        self.busy = set()
        self.serial = 0

    def mordred_vfs_register_root(self, path, token):
        path = path.replace("/", "\\").casefold()
        if any(
            path == other or path.startswith(other + "\\") or other.startswith(path + "\\")
            for other in self.roots.values()
        ):
            return 5
        self.serial += 1
        token._obj.value = self.serial
        self.roots[self.serial] = path
        return 0

    def mordred_vfs_close_root(self, token):
        if token in self.busy:
            return 5
        del self.roots[token]
        return 0


def registration_environment(monkeypatch):
    from mordred_hermes._private_fs import _windows_paths, _windows_security
    from mordred_hermes.dbcrypt import _windows_vfs

    api, native = MetadataAPI(), NativeRegistry()
    monkeypatch.setattr(_windows_paths, "get_api", lambda: api)
    monkeypatch.setattr(_windows_security, "current_user_sid", api.user_sid)
    monkeypatch.setattr(_windows_vfs, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "_load_native", lambda: native)
    driver = ModuleType("synthetic_native_boundary")
    native._name = "synthetic fixture DLL"
    driver.connect = lambda *a: SimpleNamespace(
        execute=lambda sql, *p: SimpleNamespace(fetchone=lambda: ("synthetic SQLCipher ABI",)),
        enable_load_extension=lambda enabled: None,
        close=lambda: None,
    )
    return _windows_vfs, driver, api, native


def protected_windows_environment(monkeypatch):
    """Exercise Python ownership with real POSIX SQLCipher, never claim native I/O."""
    import os

    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _backup, _connection, _windows_vfs

    native = NativeRegistry()
    native._name = "synthetic native ABI"
    connect = sc.connect
    identity = _connection._identity

    def posix_identity(path, *, directory):
        with monkeypatch.context() as local:
            local.setattr(_connection, "os", os)
            return identity(path, directory=directory)

    class Bootstrap:
        def __init__(self):
            self.raw = connect(":memory:")

        def execute(self, sql, *args):
            if sql.startswith("SELECT load_extension"):
                return None
            return self.raw.execute(sql, *args)

        def enable_load_extension(self, enabled):
            pass

        def close(self):
            self.raw.close()

    def routed(path, *args, **kwargs):
        if path == ":memory:":
            return Bootstrap()
        return connect(str(path).replace("&vfs=mordred_checked_v1", ""), *args, **kwargs)

    monkeypatch.setattr(_connection, "os", SimpleNamespace(name="nt", getpid=os.getpid))
    monkeypatch.setattr(_backup, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(_windows_vfs, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", True)
    monkeypatch.setattr(_windows_vfs, "checked_path_identity", posix_identity)
    monkeypatch.setattr(_windows_vfs, "classify_windows_database", lambda path, **kw: path)
    monkeypatch.setattr(_windows_vfs, "_path_parts", lambda path: (path,))
    monkeypatch.setattr(_windows_vfs, "_load_native", lambda: native)
    monkeypatch.setattr(sc, "connect", routed)
    return native
