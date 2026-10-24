"""Explicit, unqualified Windows checked-VFS bootstrap (no runtime activation).

Lexical classification is deliberately separate from native admission. Only the
native adapter holds and validates the handles used for SQLite I/O. This module
does not turn a pathname precheck into permission for the default Windows VFS.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import threading
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from types import ModuleType
from typing import Any, Final

NATIVE_QUALIFIED: Final = False
_NAME: Final = "mordred_checked_v1"
_LOCK = threading.RLock()
_LIBRARIES: dict[str, Any] = {}


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


def packaged_library_path() -> Path:
    """Locate only the owned wheel asset; no native library is loaded here."""
    return Path(__file__).resolve().parent.parent / "_native" / "dbcrypt-vfs" / "mordred_dbcrypt_vfs.dll"


def _load_native() -> Any:
    # Qualification retains its explicit test-library seam. Production ignores
    # that environment override and selects only the installed owned wheel.
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


class VfsRegistration:
    """A root lease. Close refuses while database/sidecar handles remain live.

    An abandoned lease intentionally remains pinned until process exit; a Python
    finalizer must never free callback state behind a live SQLite connection.
    """

    name: Final = _NAME

    def __init__(self, native: Any, token: int, root: Path, driver: ModuleType) -> None:
        self._native = native
        self._token = token
        self.root = root
        self._driver = driver  # Pin the exact loading driver for the lease.

    def close(self) -> None:
        with _LOCK:
            if not self._token:
                return
            if self._native.mordred_vfs_close_root(self._token) != 0:
                raise RuntimeError("checked VFS root is busy or could not be released")
            self._token = 0


def register_checked_vfs(driver: ModuleType, *, root: Path) -> VfsRegistration:
    """Pin the same-library extension and register an existing private root.

    This is an explicit implementation/acceptance interface; production remains
    unavailable until the independent native qualification gate is satisfied.
    """
    if sys.platform != "win32":
        raise RuntimeError("checked VFS requires Windows")
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
        token = ctypes.c_uint64()
        if native.mordred_vfs_register_root(os.fspath(root), ctypes.byref(token)) != 0:
            raise RuntimeError("checked VFS root admission refused")
        return VfsRegistration(native, token.value, root, driver)
