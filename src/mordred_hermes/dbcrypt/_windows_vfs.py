"""Windows checked-VFS bootstrap for the qualified distribution-owned driver pair.

Lexical classification is deliberately separate from native admission. Only the
native adapter holds and validates the handles used for SQLite I/O. This module
does not turn a pathname precheck into permission for the default Windows VFS.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
import sys
import threading
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from types import ModuleType
from typing import Any, Final

# Release admission is source-controlled, never granted by an environment flag.
# Actual platform acceptance is recorded separately by the production matrix.
NATIVE_QUALIFIED: Final = True
_VER_NT_SERVER: Final = 3


def windows_edition_admitted() -> bool:
    """Admit Windows Server editions only; workstation and unknown editions fail closed."""
    try:
        return bool(sys.platform == "win32" and sys.getwindowsversion().product_type == _VER_NT_SERVER)  # type: ignore[attr-defined,unused-ignore]
    except Exception:
        return False


_NAME: Final = "mordred_checked_v1"
_LOCK = threading.RLock()
_LIBRARIES: dict[str, Any] = {}
_ROOTS: dict[str, _RootRegistration] = {}


def checked_path_identity(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    """Read native identity/security metadata, never DB bytes or POSIX modes."""
    from .._database_contracts import DatabaseRefused
    from .._private_fs import PrivateFSError
    from .._private_fs._windows_io import open_private_directory
    from .._private_fs._windows_security import current_user_sid

    try:
        with open_private_directory(path if directory else path.parent) as parent:
            identity = parent.directory_identity() if directory else parent.stat(path.name).identity
            return (
                identity.volume,
                int.from_bytes(identity.file_id),
                stat.S_IFDIR if directory else stat.S_IFREG,
                int.from_bytes(current_user_sid()),
            )
    except PrivateFSError as error:
        if error.reason == "missing":
            raise FileNotFoundError(os.fspath(path)) from None
        raise DatabaseRefused("Windows database path identity/security refused") from None


def _path_parts(raw: str) -> tuple[str, ...]:
    raw = raw.replace("/", "\\")
    if len(raw.encode("utf-16-le", errors="surrogatepass")) > 478 or not re.match(r"^[a-zA-Z]:\\", raw):
        raise ValueError("unsupported Windows database path")
    parts = raw.split("\\")
    if len(parts) < 2 or not parts[-1]:
        raise ValueError("unsupported Windows database path")
    for part in parts[1:]:
        base = part.split(".")[0].upper()
        if (
            not part
            or part in (".", "..")
            or part.endswith((" ", "."))
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF or c in ':<>"|?*%' for c in part)
            or base in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
            or re.fullmatch(r"(COM|LPT)[1-9¹²³]", base)
        ):
            raise ValueError("unsupported Windows database path")
    return tuple(parts)


def classify_windows_database(path: str, *, uri: bool, root: Path) -> Path:
    """Admit only literal absolute drive paths beneath root, without any I/O.

    User-supplied URIs are unsupported. The trusted connection layer may construct
    its own URI after classification, selecting exactly ``mordred_checked_v1``.
    Filesystem type, reparse points, links and ACLs require native handle admission.
    """
    # Reserve eight UTF-16 units for SQLite's longest supported sidecar suffix
    # (-journal), so a valid main name cannot fail only after creating the DB.
    if uri or not isinstance(path, str) or len(path.encode("utf-16-le", errors="surrogatepass")) > 462:
        raise ValueError("Windows database URIs are unsupported")
    parts, root_parts = _path_parts(path), _path_parts(os.fspath(root))
    if len(parts) <= len(root_parts) or tuple(p.casefold() for p in parts[: len(root_parts)]) != tuple(
        p.casefold() for p in root_parts
    ):
        raise ValueError("Windows database is outside the registered root")
    return Path("\\".join(parts))


def driver_distribution_qualified() -> bool:
    """Static pair constraint, never an authentication/readiness assertion."""
    try:
        return version("sqlcipher3-wheels") == "0.5.7"
    except PackageNotFoundError:
        return False


def packaged_library_path() -> Path | None:
    """Find the exact installed distribution-owned asset, including editables.

    Editable Python modules live in the checkout while forced native resources
    live in site-packages. Module __file__ and diagnostic environment paths are
    therefore never resource ownership proofs.
    """
    parts = ("mordred_hermes", "_native", "dbcrypt-vfs", "mordred_dbcrypt_vfs.dll")
    try:
        installed = distribution("hermes-mordred")
        owned = [entry for entry in installed.files or () if str(entry) == "/".join(parts)]
        if len(owned) != 1:
            return None
        root = Path(str(installed.locate_file(""))).resolve(strict=True)
        candidate = root.joinpath(*parts)
        if Path(str(installed.locate_file(owned[0]))).resolve(strict=True) != candidate:
            return None
        current = root
        for part in parts:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                return None
        return candidate if stat.S_ISREG(metadata.st_mode) else None
    except (PackageNotFoundError, OSError, ValueError):
        return None


def _load_native() -> Any:
    # Qualification retains its explicit test-library seam. Production ignores
    # that environment override and selects only the installed owned wheel.
    if not windows_edition_admitted():
        raise RuntimeError("Windows checked VFS admits Windows Server editions only")
    if NATIVE_QUALIFIED and not driver_distribution_qualified():
        raise RuntimeError("Windows checked VFS requires its qualified SQLCipher 0.5.7 driver pair")
    value = packaged_library_path() if NATIVE_QUALIFIED else os.environ.get("MORDRED_DBCRYPT_CHECKED_LIBRARY")
    if not value or not Path(value).is_absolute() or not Path(value).is_file():
        raise RuntimeError("checked VFS library is unavailable")
    path = str(Path(value).resolve(strict=True))
    if path not in _LIBRARIES:
        native = ctypes.CDLL(path)
        native.mordred_vfs_register_root.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64)]
        native.mordred_vfs_register_root.restype = ctypes.c_int
        native.mordred_vfs_close_root.argtypes = [ctypes.c_uint64]
        native.mordred_vfs_close_root.restype = ctypes.c_int
        _LIBRARIES[path] = native
    return _LIBRARIES[path]


class _RootRegistration:
    def __init__(self, native: Any, token: int, root: Path, driver: ModuleType, identity: tuple[int, ...] = ()) -> None:
        self.native, self.token, self.root, self.driver = native, token, root, driver
        self.identity = identity
        self.references = 0


class VfsRegistration:
    """A root lease. Close refuses while database/sidecar handles remain live.

    An abandoned lease intentionally remains pinned until process exit; a Python
    finalizer must never free callback state behind a live SQLite connection.
    """

    name: Final = _NAME

    def __init__(
        self, native: Any, token: int, root: Path, driver: ModuleType, *, _owner: _RootRegistration | None = None
    ) -> None:
        self._native = native
        self._token = token
        self.root = root
        self._driver = driver  # Pin the exact loading driver for the lease.
        self._owner = _owner or _RootRegistration(native, token, root, driver)
        self._owner.references += 1

    def close(self) -> None:
        with _LOCK:
            if not self._token:
                return
            owner = self._owner
            if owner.references == 1:
                if self._native.mordred_vfs_close_root(self._token) != 0:
                    raise RuntimeError("checked VFS root is busy or could not be released")
                name = os.fspath(owner.root).replace("/", "\\").casefold()
                if _ROOTS.get(name) is owner:
                    del _ROOTS[name]
            owner.references -= 1
            self._token = 0


def register_checked_vfs(driver: ModuleType, *, root: Path) -> VfsRegistration:
    """Pin the same-library extension and register an existing private root.

    Admission is source-controlled: Windows Server x64 with the qualified 0.5.7
    driver pair and the distribution-owned DLL. Workstation editions are
    refused. Native acceptance is recorded separately in docs/dev/CI.md.
    """
    if sys.platform != "win32":
        raise RuntimeError("checked VFS requires Windows")
    if not windows_edition_admitted():
        raise RuntimeError("Windows checked VFS admits Windows Server editions only")
    _path_parts(os.fspath(root))
    with _LOCK:
        connection = driver.connect(":memory:")
        try:
            version = connection.execute("PRAGMA cipher_version").fetchone()
            if not version or not isinstance(version[0], str) or not version[0]:
                raise RuntimeError("checked VFS requires a SQLCipher driver")
            native = _load_native()
            connection.enable_load_extension(True)
            try:
                connection.execute("SELECT load_extension(?, ?)", (native._name, "sqlite3_mordredvfs_init"))
            finally:
                connection.enable_load_extension(False)
        finally:
            connection.close()
        name = os.fspath(root).replace("/", "\\").casefold()
        identity = checked_path_identity(root, directory=True)
        owner = _ROOTS.get(name)
        if owner is not None:
            if owner.native is not native or owner.driver is not driver or owner.identity != identity:
                raise RuntimeError("checked VFS root or driver binding changed")
            return VfsRegistration(native, owner.token, root, driver, _owner=owner)
        token = ctypes.c_uint64()
        if native.mordred_vfs_register_root(os.fspath(root), ctypes.byref(token)) != 0:
            raise RuntimeError("checked VFS root admission refused")
        owner = _RootRegistration(native, token.value, root, driver, identity)
        lease = VfsRegistration(native, token.value, root, driver, _owner=owner)
        # Native pins now prevent namespace replacement. Bind the admitted root
        # to the same pre-registration observation before publishing a share.
        try:
            if checked_path_identity(root, directory=True) != identity:
                raise RuntimeError("checked VFS root changed during registration")
        except BaseException:
            lease.close()
            raise
        _ROOTS[name] = owner
        return lease
