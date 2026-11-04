"""Read-only preflight and post-restoration proof for root-wide uninstall."""

from __future__ import annotations

import contextlib
import shutil
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from .._core._database_contracts import DatabaseRefused, Dependency, NativeSnapshot
from .._core._database_inventory import scan_dependencies
from .._core._database_lifecycle import ExclusiveLease
from ..keyvault._uninstall_authority import UninstallAuthorization, _issue, fingerprint
from . import _backup, _migrate
from ._key import DatabaseKey
from ._policy import looks_like_database_name

_SIDECARS = ("-wal", "-shm", "-journal")


@dataclass
class Preflight:
    root: Path
    purge: bool
    snapshot: NativeSnapshot | None
    databases: dict[Path, dict[str, Any]]
    backups: tuple[Path, ...]
    before: tuple[tuple[object, ...], ...]
    encrypted: frozenset[Path] = frozenset()

    def unchanged(self, lease: ExclusiveLease) -> None:
        ExclusiveLease.assert_held(lease, self.root)
        if fingerprint(self.root) != self.before:
            raise DatabaseRefused("database targets changed after preflight")


@contextlib.contextmanager
def archive_member(root: Path, source: Path, member: str) -> Iterator[Path]:
    """Copy one member to private staging; never use archive paths as OS paths."""
    with tempfile.TemporaryDirectory(prefix="mordred-export-", dir=root / "mordred") as directory:
        path = Path(directory) / "member.db"
        with zipfile.ZipFile(source) as archive:
            matches = [info for info in archive.infolist() if info.filename == member and not info.is_dir()]
            if len(matches) != 1:
                raise DatabaseRefused("archive member is missing or ambiguous")
            with archive.open(matches[0]) as reader, path.open("xb") as writer:
                path.chmod(0o600)
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
        yield path


def archive_schemas(root: Path, source: Path, key: DatabaseKey | None) -> dict[str, dict[str, Any]]:
    result = {}
    protected = False
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = PurePosixPath(info.filename.replace("\\", "/")).name
            if info.is_dir():
                continue
            if name in {"db-encryption.marker", "db-backups.json", "db-key-source.json"}:
                protected = True
            if name.endswith(_SIDECARS) or ".mordred-" in name:
                raise DatabaseRefused("backup archive contains unresolved database sidecars or staging")
            if not looks_like_database_name(name):
                continue
            if info.filename in result:
                raise DatabaseRefused("backup archive has duplicate database members")
            with archive_member(root, source, info.filename) as path:
                result[info.filename] = _read_schema(path, key, root)
    if protected and not result:
        raise DatabaseRefused("backup archive has protection metadata without recoverable databases")
    return result


def _read_schema(path: Path, key: DatabaseKey | None, root: Path) -> dict[str, Any]:
    try:
        return _migrate._schema(path, None, root=root)
    except Exception as plain_error:
        if key is None:
            raise DatabaseRefused(f"database cannot be verified without its key: {path}") from plain_error
        try:
            return _migrate._schema(path, key, root=root)
        except Exception as exc:
            raise DatabaseRefused(f"database cannot be verified with the retained key: {path}") from exc


def preflight(  # noqa: C901, PLR0912, PLR0915 - explicit inventory refusal cases
    root: Path,
    *,
    lease: ExclusiveLease,
    purge: bool,
    source: NativeSnapshot | None = None,
    erase: frozenset[Path] = frozenset(),
) -> Preflight:
    ExclusiveLease.assert_held(lease, root)
    before = fingerprint(root)
    inventory = scan_dependencies(root)
    if not inventory.complete:
        raise DatabaseRefused("database dependency inventory is incomplete")
    for entry in inventory.entries:
        if entry.path in erase:
            continue
        if entry.kind in {"pending", "journal"} and entry.path.name != "db-encryption.marker":
            if not entry.path.name.endswith(_SIDECARS):
                raise DatabaseRefused("incomplete database/backup maintenance; recover before uninstall")
            base = Path(str(entry.path).rsplit("-", 1)[0])
            if not base.is_file():
                raise DatabaseRefused("orphan database sidecar")
    _migrate._refuse_if_open([_migrate.Database(e.path, str(e.path), "") for e in inventory.entries], None)
    if fingerprint(root) != before:
        raise DatabaseRefused("database dependencies changed during inventory")
    if purge:
        blockers = []
        for entry in inventory.entries:
            path = entry.path
            if entry.kind != "backup" or path in erase or path.name == "db-backups.json":
                continue
            if path.suffix.casefold() == ".zip":
                try:
                    archive_schemas(root, path, None)
                except Exception:
                    blockers.append(path)
            else:
                blockers.append(path)
        if blockers:
            raise DatabaseRefused(
                "retained backup dependencies prevent key/helper deletion: "
                + ", ".join(map(str, blockers))
                + "; export/decrypt separately, or review the scoped --erase-encrypted plan"
            )
    snapshot: NativeSnapshot | None = None
    key: DatabaseKey | None = None
    # A retained binding also covers backups after live decryption/reinstallation.
    if (
        source is not None
        or (root / "mordred/db-key-source.json").exists()
        or any(e.path.name in {"db-encryption.marker", "db-backups.json"} for e in inventory.entries)
    ):
        snapshot, key = _migrate._authenticate(root, None, lease)
    registry = _backup._load_inventory(root, snapshot) if snapshot is not None else {"entries": []}
    registered = {Path(e["path"]): e for e in registry["entries"]}
    databases: dict[Path, dict[str, Any]] = {}
    backups = []
    encrypted: set[Path] = set()
    for entry in inventory.entries:
        path = entry.path
        if path in erase:
            continue
        if entry.kind == "database" and path not in registered:
            try:
                databases[path] = _migrate._schema(path, None, root=root)
            except Exception:
                databases[path] = _read_schema(path, key, root)
                encrypted.add(path)
        elif entry.kind == "backup" and path.name != "db-backups.json":
            if path in registered:
                record = registered[path]
                if _migrate._file_identity(path) != record["identity"]:
                    raise DatabaseRefused("registered backup identity changed")
                if key is None or _migrate._schema(path, key, root=root) != record["verification"]:
                    raise DatabaseRefused("registered backup verification failed")
                backups.append(path)
            elif path.suffix.casefold() == ".zip":
                try:
                    archive_schemas(root, path, None)
                except DatabaseRefused:
                    archive_schemas(root, path, key)
                    backups.append(path)
            else:
                raise DatabaseRefused(f"unsupported or unregistered backup: {path}")
    if purge and backups:
        raise DatabaseRefused(
            "retained backup dependencies prevent key/helper deletion: " + ", ".join(map(str, backups))
        )
    if fingerprint(root) != before:
        raise DatabaseRefused("database dependencies changed during preflight")
    return Preflight(root, purge, snapshot, databases, tuple(backups), before, frozenset(encrypted))


@contextlib.contextmanager
def verified(  # noqa: C901 - ordered post-restoration proof and registry retirement
    report: Preflight, *, lease: ExclusiveLease
) -> Iterator[UninstallAuthorization]:
    root = report.root
    ExclusiveLease.assert_held(lease, root)
    inventory = scan_dependencies(root)
    if not inventory.complete:
        raise DatabaseRefused("database dependency inventory is incomplete")
    proof_before = fingerprint(root)
    actual = {entry.path for entry in inventory.entries if entry.kind == "database"}
    if actual != set(report.databases):
        raise DatabaseRefused("database inventory changed during restoration")
    for entry in inventory.entries:
        if entry.kind in {"pending", "journal"} and not entry.path.name.endswith(_SIDECARS):
            raise DatabaseRefused("database restoration is incomplete")
    for path, expected in report.databases.items():
        if _migrate._schema(path, None, root=root) != expected:
            raise DatabaseRefused("restored plaintext schema/count verification failed")
    # Re-authenticate retained copies, generation and paths after conversion.
    current = preflight(root, lease=lease, purge=report.purge, source=report.snapshot)
    if current.before != proof_before or current.encrypted or current.databases != report.databases:
        raise DatabaseRefused("database inventory changed during plaintext verification")
    retained = {*report.backups, root / "mordred/db-backups.json"}
    previous_backups = tuple(row for row in report.before if cast(Dependency, row[0]).path in retained)
    current_backups = tuple(row for row in current.before if cast(Dependency, row[0]).path in retained)
    if current_backups != previous_backups:
        raise DatabaseRefused("retained backups changed during restoration")
    if current.snapshot != report.snapshot or current.backups != report.backups:
        raise DatabaseRefused("backup or native generation changed during restoration")
    issuance = current.before
    registry = root / "mordred/db-backups.json"
    if report.purge and registry.exists():
        if current.snapshot is None or _backup._load_inventory(root, current.snapshot)["entries"]:
            raise DatabaseRefused("backup registry is not authenticated empty")
        if fingerprint(root) != issuance:
            raise DatabaseRefused("backup registry changed before retirement")
        _migrate._remove_record(root, "db-backups.json")
        issuance = tuple(row for row in issuance if cast(Dependency, row[0]).path != registry)
    with _issue(root, lease, "delete" if report.purge else "restore", report.snapshot, issuance) as permit:
        yield permit


def known_blockers(root: Path, *, purge: bool, erase: frozenset[Path]) -> list[str]:
    """Metadata-only plan notes; deliberately no key or SQL authentication."""
    inventory = scan_dependencies(root)
    reasons = []
    if not inventory.complete:
        reasons.append("database dependency inventory is incomplete")
    for entry in inventory.entries:
        if entry.path in erase or entry.path.name == "db-encryption.marker":
            continue
        if entry.kind in {"pending", "journal"} and not entry.path.name.endswith(_SIDECARS):
            reasons.append(f"incomplete database maintenance: {entry.path}")
        elif entry.kind == "backup" and entry.path.name != "db-backups.json":
            if entry.path.suffix.casefold() in {".tar", ".gz", ".tgz"}:
                reasons.append(f"unsupported backup format: {entry.path}")
            elif purge:
                reasons.append(f"backup must be proven independent of the deleted key: {entry.path}")
    return reasons
