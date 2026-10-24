"""Metadata-only root database dependencies, usable below SQL and custody."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Final, Literal

from ._database_contracts import DatabaseRefused, Dependency, Inventory, decode_database_source_binding
from ._database_lifecycle import ExclusiveLease
from ._private_fs import open_private_directory

# Keep these scope/name rules aligned with dbcrypt._policy. Importing that
# package here would execute dbcrypt.__init__ below the custody boundary.
_DENY_DIRS: Final = frozenset(
    {
        "installs",
        "tools",
        "hermes-agent",
        "hermes-setup",
        "bootstrap-cache",
        "cache",
        "source-checks",
        "node_modules",
        "mcp-installs",
        "desktop",
        "desktop-plugins",
        "skills",
        "vault",
        "mordred",
        "logs",
    }
)
_DB_SUFFIXES: Final = (".db", ".sqlite", ".sqlite3")
_SIDECARS: Final = ("-wal", "-shm", "-journal")
_ARCHIVES: Final = (".zip", ".tar", ".gz", ".tgz")
_Kind = Literal["database", "pending", "journal", "backup", "unknown"]
_STATE_KINDS: Final[dict[str, _Kind]] = {
    "db-encryption.marker": "journal",
    "db-encryption.pending": "pending",
    "db-decryption.pending": "pending",
    "db-encryption.journal.json": "journal",
    "db-backups.json": "backup",
    "db-backups.journal.json": "journal",
}


def _home_parts(parts: tuple[str, ...]) -> tuple[str, ...]:
    if len(parts) >= 3 and parts[0] == "profiles":
        return parts[2:]
    return parts


def _excluded(parts: tuple[str, ...]) -> bool:
    if parts[0] == "mordred":
        # Inspect only database lifecycle records in this otherwise denied tree.
        return len(parts) > 1 and (
            len(parts) != 2
            or not (
                parts[1].casefold().startswith("db-") or parts[1].casefold().lstrip(".").startswith("db-key-source")
            )
        )
    return parts[0] in _DENY_DIRS


def _database_name(name: str) -> bool:
    return name.endswith(_DB_SUFFIXES) or any(f"{suffix}." in name for suffix in _DB_SUFFIXES)


def _kind(parts: tuple[str, ...]) -> _Kind | None:
    name = parts[-1].casefold()
    if name.endswith(".lock"):
        return None
    if len(parts) == 2 and parts[0].casefold() == "mordred" and name.lstrip(".").startswith("db-key-source"):
        return "unknown"  # Only the exact checked root record can be omitted later.
    if parts[0] == "mordred":
        return _STATE_KINDS.get(name, "unknown") if len(parts) == 2 else None
    for suffix in _SIDECARS:
        if name.endswith(suffix):
            return "journal" if _database_name(name[: -len(suffix)]) else None
    if not _database_name(name):
        return "backup" if parts[0] == "backups" and name.endswith(_ARCHIVES) else None
    if name.endswith(".mordred-enc"):
        return "pending"
    if name.endswith(_DB_SUFFIXES):
        return "database"
    if name.endswith((".bak", ".backup")):
        return "backup"
    return "unknown"


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns


def _reparse(info: os.stat_result) -> bool:
    # FILE_ATTRIBUTE_REPARSE_POINT also covers junction/cloud points whose mode
    # can look like an ordinary directory. POSIX stat results lack these fields.
    return bool(getattr(info, "st_reparse_tag", 0) or getattr(info, "st_file_attributes", 0) & 0x400)


def _inspect(child: os.DirEntry[str], path: Path, kind: _Kind | None) -> tuple[Dependency | None, bool]:
    try:
        info = child.stat(follow_symlinks=False)
        if _reparse(info):
            return Dependency(path, "unknown", None), False
        if kind is None and stat.S_ISLNK(info.st_mode) and stat.S_ISREG(child.stat().st_mode):
            return None, False  # An alias of an ordinary config/text file carries no database state.
    except OSError:
        return Dependency(path, "unknown", None), False
    if stat.S_ISDIR(info.st_mode):
        # A file-shaped dependency is not a usable directory.
        return (Dependency(path, "unknown", None), False) if kind is not None else (None, True)
    if stat.S_ISLNK(info.st_mode) or (kind is not None and not stat.S_ISREG(info.st_mode)):
        # Never traverse an ambiguous alias into/out of the managed root.
        return Dependency(path, "unknown", None), False
    return (Dependency(path, kind, None), False) if kind is not None else (None, False)


def _source_binding_metadata(root: Path, path: Path) -> bool:
    """Omit only one checked root-local POSIX authority record, never its copies."""
    if path.relative_to(root).parts != ("mordred", "db-key-source.json") or os.name != "posix":
        return False
    from ._database_locking_posix import identify_root

    try:
        identity = identify_root(root)
        with open_private_directory(root / "mordred") as directory:
            before = directory.stat("db-key-source.json")
            data = directory.read_bytes("db-key-source.json", max_bytes=4096)
            source = decode_database_source_binding(data)
            return (
                directory.stat("db-key-source.json") == before
                and identify_root(root) == identity
                and source.root == identity
            )
    except (OSError, DatabaseRefused):
        return False


def scan_dependencies(root: Path) -> Inventory:
    """Scan names/metadata only; absence is trusted only after complete discovery.

    Generations remain unknown until the registered-backup/binding protocol is
    implemented. This deliberately retains every discovered dependency, without
    opening a live database, parsing its header, or authenticating native keys.
    Only the exact checked root source binding is decoded as public metadata.
    """
    entries: dict[Path, Dependency] = {}
    directories = [root]

    def unknown(path: Path) -> None:
        entries[path] = Dependency(path, "unknown", None)

    while directories:
        directory = directories.pop()
        try:
            before = directory.lstat()
            if not stat.S_ISDIR(before.st_mode) or _reparse(before):
                unknown(directory)
                continue
            with os.scandir(directory) as children:
                for child in children:
                    path = directory / child.name
                    parts = _home_parts(path.relative_to(root).parts)
                    if _excluded(parts):
                        continue
                    dependency, descend = _inspect(child, path, _kind(parts))
                    if dependency is not None and not _source_binding_metadata(root, path):
                        entries[path] = dependency
                    if descend:
                        directories.append(path)
            after = directory.lstat()
            if (
                not stat.S_ISDIR(after.st_mode)
                or _reparse(after)
                or _directory_identity(before) != _directory_identity(after)
            ):
                unknown(directory)
        except OSError:
            # Permission, disappearance, and traversal failures are all unknown,
            # including when an otherwise empty directory could not be listed.
            unknown(directory)
    ordered = tuple(entries[path] for path in sorted(entries))
    return Inventory(ordered, all(entry.kind != "unknown" for entry in ordered))


def assert_mutation_safe(root: Path, generation: str | None, lease: ExclusiveLease) -> None:
    """Refuse destruction unless a preceding exclusive lease proves safety."""
    if not isinstance(lease, ExclusiveLease):
        raise DatabaseRefused("a preceding exclusive database lease is required")
    ExclusiveLease.assert_held(lease, root)
    inventory = scan_dependencies(root)
    ExclusiveLease.assert_held(lease, root)
    if not inventory.complete:
        raise DatabaseRefused("database dependency inventory is incomplete")
    if any(
        entry.kind == "unknown" or generation is None or entry.generation is None or entry.generation == generation
        for entry in inventory.entries
    ):
        raise DatabaseRefused("database dependencies still require this native key generation")
