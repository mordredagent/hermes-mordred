"""Find Hermes backup ZIPs that must retain their database key until resolved.

Inspect bounded database headers without extracting or rewriting archives.
Only root/profile ``backups`` directories inside the selected home are in scope.
"""

from __future__ import annotations

import os
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from ..dbcrypt._policy import looks_like_database_name

_SQLITE_MAGIC = b"SQLite format 3\x00"
_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def _archives(home: Path) -> Iterator[Path]:
    def fail(exc: OSError) -> None:
        raise RuntimeError(f"cannot inspect Hermes backup directory {exc.filename}: {exc}") from exc

    base = home.resolve()
    directories = [home / "backups"]
    profiles = home / "profiles"
    if profiles.is_dir() and not profiles.is_symlink():
        directories.extend(path / "backups" for path in sorted(profiles.iterdir()) if not path.is_symlink())
    for directory in directories:
        if not directory.is_dir() or directory.is_symlink():
            continue
        for root, dirs, files in os.walk(directory, onerror=fail):
            dirs[:] = sorted(name for name in dirs if not Path(root, name).is_symlink())
            for name in sorted(files):
                path = Path(root, name)
                if path.suffix.casefold() == ".zip" and not path.is_symlink() and path.resolve().is_relative_to(base):
                    yield path


def _suspect(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                name = PurePosixPath(member.filename.replace("\\", "/"))
                if name.parts[-2:] == ("mordred", "db-encryption.marker"):
                    return True
                if not looks_like_database_name(name.name):
                    continue
                with archive.open(member) as stream:
                    header = stream.read(100)
                if not header:
                    continue  # SQLite can create an empty database file.
                if header.startswith(_SQLITE_MAGIC):
                    # SQLCipher leaves the SQLite header but reserves bytes in
                    # every page for its nonce/MAC. Plain SQLite reserves none.
                    if len(header) < 100 or header[20] != 0:
                        return True
                elif name.suffix.casefold() in _DB_SUFFIXES:
                    return True  # malformed/unreadable database payload
    except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile, NotImplementedError, zlib.error):
        return True  # no evidence that a damaged/password-protected ZIP is safe
    return False


def protected_archives(home: Path) -> list[Path]:
    """Encrypted or uninspectable Hermes backup ZIPs, even without a live marker."""
    return [path for path in _archives(home) if _suspect(path)]


def refuse_archives(home: Path) -> None:
    archives = protected_archives(home)
    if archives:
        raise RuntimeError(
            "encrypted or unreadable Hermes backup archives still need their database key: "
            + ", ".join(str(path) for path in archives)
            + ". Restore and decrypt these archives separately before uninstalling, or explicitly delete them "
            "with `uninstall --erase-encrypted`; nothing was removed"
        )
