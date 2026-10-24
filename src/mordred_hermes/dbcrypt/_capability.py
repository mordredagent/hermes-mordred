"""Passive database capability observation and explicit authority diagnosis.

Presence of a driver or a marker never establishes authenticated protection.
Ordinary status only observes metadata and software availability; it neither
opens SQLite nor constructs native custody, acquires leases, or enrolls state.
"""

from __future__ import annotations

import importlib.util
import stat
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class DatabaseStatus:
    configured: bool
    dependencies: int | None
    capability: Literal["available", "unavailable", "unknown"]
    authenticated: bool
    reason: str | None


def _root(home: Path) -> Path:
    # Lexical observation only. Explicit diagnosis later resolves the physical
    # domain through Authority; status never turns realpath into authorization.
    return home.parent.parent if home.parent.name == "profiles" else home


def _intent(home: Path) -> tuple[bool, bool]:
    directory = _root(home) / "mordred"
    configured = False
    unsafe = ".." in home.parts or home.name.casefold() == "profiles"
    unsafe |= home.parent.name.casefold() == "profiles" and home.parent.name != "profiles"
    for parent in (*reversed(home.absolute().parents), home.absolute()):
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            break
        if not stat.S_ISDIR(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            return False, True
    for parent in (*reversed(directory.parents), directory):
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            return configured, unsafe
        if not stat.S_ISDIR(metadata.st_mode):
            return configured, True
    for name in (
        "db-encryption.marker",
        "db-encryption.pending",
        "db-decryption.pending",
        "db-encryption.journal.json",
    ):
        try:
            metadata = (directory / name).lstat()
        except FileNotFoundError:
            continue
        configured = True
        unsafe |= not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
    return configured, unsafe


def _driver_present() -> bool:
    try:
        return importlib.util.find_spec("sqlcipher3") is not None
    except (ImportError, ValueError):
        return False


def _dependency_count(home: Path) -> int | None:
    from .._database_inventory import scan_dependencies

    try:
        inventory = scan_dependencies(_root(home))
    except OSError:
        return None
    return len(inventory.entries) if inventory.complete else None


def database_status(home: Path) -> DatabaseStatus:
    """Return passive facts, always unauthenticated; no SQL or custody access."""
    try:
        configured, unsafe = _intent(home)
    except OSError:
        return DatabaseStatus(False, None, "unknown", False, "database intent metadata is unavailable")
    if unsafe:
        return DatabaseStatus(configured, None, "unknown", False, "database intent path requires checked diagnosis")
    dependencies = _dependency_count(home)
    if dependencies is None:
        return DatabaseStatus(configured, None, "unknown", False, "database dependency inventory is incomplete")
    if sys.platform == "win32":
        from ._windows_vfs import NATIVE_QUALIFIED, driver_distribution_qualified, packaged_library_path

        if not NATIVE_QUALIFIED:
            return DatabaseStatus(
                configured, dependencies, "unavailable", False, "Windows VFS native qualification is incomplete"
            )
        if not driver_distribution_qualified():
            return DatabaseStatus(
                configured, dependencies, "unavailable", False, "Windows SQLCipher driver pair is unqualified"
            )
        if packaged_library_path() is None:
            return DatabaseStatus(
                configured, dependencies, "unavailable", False, "owned Windows VFS asset is unavailable"
            )
    elif sys.platform != "darwin":
        return DatabaseStatus(
            configured,
            dependencies,
            "unavailable",
            False,
            "database runtime activation is unavailable on this platform",
        )
    if not _driver_present():
        return DatabaseStatus(configured, dependencies, "unavailable", False, "SQLCipher driver extra is unavailable")
    # Static dependencies do not prove native source custody, marker binding,
    # generation, usable VFS, or authenticated schema access for this home.
    return DatabaseStatus(
        configured, dependencies, "unknown", False, "native database authority has not been authenticated"
    )


def diagnose_database(home: Path) -> DatabaseStatus:
    """Explicitly authenticate existing authority, then release it on every path.

    Legacy intent and all pending state refuse through the existing checked
    Authority gate; this operation never performs enrollment or recovery.
    """
    status = database_status(home)
    if (
        not status.configured
        or status.capability != "unknown"
        or status.reason != "native database authority has not been authenticated"
    ):
        return status
    from ..keyvault._database_authority import resolve_database_domain
    from ._key import KeyProvider
    from ._marker import Marker, read_marker

    try:
        root = resolve_database_domain(home).root
        for name in ("db-encryption.pending", "db-decryption.pending", "db-encryption.journal.json"):
            try:
                (root / "mordred" / name).lstat()
            except FileNotFoundError:
                continue
            return replace(status, capability="unavailable", reason="pending database state requires explicit recovery")
        if not isinstance(read_marker(root), Marker):
            return replace(status, capability="unavailable", reason="database marker requires explicit adoption")
    except Exception:
        return replace(status, capability="unavailable", reason="database intent cannot be checked safely")
    provider = KeyProvider(home=home)
    try:
        authority = provider.authority
        authority.check()
        return replace(status, capability="available", authenticated=True, reason=None)
    except Exception:
        return replace(status, capability="unavailable", reason="database authority authentication was refused")
    finally:
        provider.close()
