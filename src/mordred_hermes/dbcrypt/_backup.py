"""Checked same-driver encrypted backups and durable generation dependencies.

Only registered copies are managed. External/offline copies are deliberately
undiscoverable and must be retained by their owner together with their key.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .._database_contracts import DatabaseRefused, NativeSnapshot
from .._database_lifecycle import ExclusiveLease
from .._private_fs import PrivateFSError, open_private_directory
from . import _migrate
from ._authority import Authority
from ._key import DatabaseKey
from ._policy import in_scope

_INVENTORY = "db-backups.json"
_JOURNAL = "db-backups.journal.json"
_FORMAT = "mordred-sqlcipher-v1"
_ACTIVE: dict[int, _Destination] = {}


def _transition(phase: str) -> None:
    """Durable crash boundary; native subprocess tests terminate here."""


@contextlib.contextmanager
def _registry(root: Path) -> Iterator[None]:
    # A distinct metadata lock, taken after lifecycle/source custody scopes.
    # Runtime SH continues to exclude key retirement throughout publication.
    with (
        open_private_directory(root / "mordred/backup-registry", create=True) as directory,
        directory.transaction(blocking=False),
    ):
        yield


def _canonical_destination(path: Path) -> Path:
    if os.name == "nt":
        from ._maintenance_windows import require_qualified

        require_qualified()
    absolute = path.absolute()
    if ".." in path.parts or absolute.parent != absolute.parent.resolve(strict=True):
        raise DatabaseRefused("backup destination must have a canonical private parent")
    with open_private_directory(absolute.parent):
        pass
    return absolute


def _load_inventory(root: Path, snapshot: NativeSnapshot) -> dict[str, Any]:
    try:
        value = _migrate._read_json(root, _INVENTORY)
    except PrivateFSError as exc:
        if exc.reason != "missing":
            raise
        return {"version": 1, "snapshot": asdict(snapshot), "entries": []}
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "snapshot", "entries"}
        or value["version"] != 1
        or value["snapshot"] != asdict(snapshot)
        or not isinstance(value["entries"], list)
    ):
        raise DatabaseRefused("backup inventory belongs to another root/generation or is invalid")
    seen: set[str] = set()
    for entry in value["entries"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "identity", "format", "verification"}
            or entry["format"] != _FORMAT
            or not isinstance(entry["path"], str)
            or entry["path"] in seen
            or not Path(entry["path"]).is_absolute()
        ):
            raise DatabaseRefused("invalid registered backup")
        seen.add(entry["path"])
    return value


def _no_pending(root: Path) -> None:
    for name in (
        _JOURNAL,
        _migrate.JOURNAL_SUBPATH[-1],
        _migrate.PENDING_SUBPATH[-1],
        _migrate.DECRYPT_PENDING_SUBPATH[-1],
    ):
        try:
            (root / "mordred" / name).lstat()
        except FileNotFoundError:
            continue
        raise DatabaseRefused("database maintenance requires recovery before backup")


class _Destination:
    """One live checked publication, never a caller-asserted backup role."""

    def __init__(self) -> None:
        raise DatabaseRefused("backup destinations are issued by the checked registry")

    authority: Authority
    source: Any
    path: Path
    identity: list[int]
    parent_identity: list[dict[str, Any]]
    verification: dict[str, Any]

    def check(self, source: Any) -> None:
        if _ACTIVE.get(id(self)) is not self or self.source is not source:
            raise DatabaseRefused("backup destination is not an active checked publication")
        self.authority.check()
        if (
            _migrate._parents(self.path.parent, self.path) != self.parent_identity
            or _migrate._file_identity(self.path) != self.identity
        ):
            raise DatabaseRefused("checked backup destination changed")
        with open_private_directory(self.path.parent):
            pass


def _copy(source: Any, path: Path, authority: Authority) -> dict[str, Any]:
    destination = object.__new__(_Destination)
    destination.authority, destination.source, destination.path = authority, source, path
    destination.identity = _migrate._file_identity(path)
    destination.parent_identity = _migrate._parents(path.parent, path)
    _ACTIVE[id(destination)] = destination
    try:
        source.backup(destination)
        destination.check(source)
        return destination.verification
    finally:
        _ACTIVE.pop(id(destination), None)


def _registered_entry(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": data["destination"],
        "identity": data["identity"],
        "format": _FORMAT,
        "verification": data["verification"],
    }


def _register(root: Path, snapshot: NativeSnapshot, data: dict[str, Any]) -> None:
    inventory = _load_inventory(root, snapshot)
    entry = _registered_entry(data)
    existing = [e for e in inventory["entries"] if e["path"] == entry["path"]]
    if existing and existing != [entry]:
        raise DatabaseRefused("backup destination already registered with another identity")
    if not existing:
        inventory["entries"].append(entry)
    _migrate._put_json(root, _INVENTORY, inventory)
    _transition("registered")
    _migrate._remove_record(root, _JOURNAL)
    _transition("complete")


def _destination_absent(destination: Path) -> None:
    with open_private_directory(destination.parent) as directory:
        try:
            directory.stat(destination.name)
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return
            raise
    raise DatabaseRefused("backup destination already exists")


def _update_pending(root: Path, previous: dict[str, Any], data: dict[str, Any]) -> None:
    with _registry(root):
        if _migrate._read_json(root, _JOURNAL) != previous:
            raise DatabaseRefused("backup publication journal changed")
        _migrate._put_json(root, _JOURNAL, data)


def _prepare_backup(source: Any, destination: Path, authority: Authority, data: dict[str, Any]) -> None:
    staged = Path(data["prepared"])
    previous = dict(data)
    with open_private_directory(destination.parent) as directory, directory.transaction() as tx:
        _destination_absent(destination)
        tx.create_bytes(staged.name, b"")
        data["identity"] = _migrate._file_identity(staged)
    _update_pending(authority.root, previous, data)
    _transition("staged")
    previous = dict(data)
    # Neither native metadata custody nor SQLite runs under the registry lock.
    data["verification"] = _copy(source, staged, authority)
    with open_private_directory(destination.parent) as directory, directory.transaction() as tx:
        if _migrate._file_identity(staged) != data["identity"]:
            raise DatabaseRefused("backup staging identity changed")
        tx.flush_file(staged.name, expected_identity=tx.stat(staged.name).identity)
    data["phase"] = "verified"
    _update_pending(authority.root, previous, data)
    _transition("verified")


def _publish_backup(destination: Path, authority: Authority, data: dict[str, Any]) -> None:
    staged = Path(data["prepared"])
    authority.check()
    with open_private_directory(destination.parent) as directory, directory.transaction() as tx:
        if (
            _migrate._parents(destination.parent, destination) != data["parent"]
            or _migrate._file_identity(staged) != data["identity"]
        ):
            raise DatabaseRefused("backup publication identity changed")
        tx.rename_file(staged.name, destination.name, expected_identity=tx.stat(staged.name).identity)
    _transition("published")
    if _migrate._file_identity(destination) != data["identity"]:
        raise DatabaseRefused("published backup changed identity")
    authority.check()
    with _registry(authority.root):
        if _migrate._read_json(authority.root, _JOURNAL) != data:
            raise DatabaseRefused("backup publication journal changed")
        _register(authority.root, authority.snapshot, data)


def backup_database(source: Path, destination: Path, *, authority: Authority) -> Path:
    from ._connection import open_protected

    if type(authority) is not Authority:
        raise DatabaseRefused("backup requires a live native database authority")
    authority.check()
    source = source.absolute()
    destination = _canonical_destination(destination)
    if not in_scope(source, authority.root) or destination.is_relative_to(authority.root):
        raise DatabaseRefused("backup needs a protected source and separate private destination")
    with (
        authority.operation(),
        contextlib.closing(open_protected(source, authority=authority, readonly=True)) as connection,
    ):
        if connection.execute("PRAGMA journal_mode").fetchone() == ("wal",) and _migrate.wal_reset_vulnerable(
            _migrate._sqlcipher().sqlite_version_info
        ):
            raise DatabaseRefused("WAL backup refuses a WAL-reset vulnerable SQLite version")
        _destination_absent(destination)
        staged = destination.with_name(f"{destination.name}.mordred-backup-{secrets.token_hex(16)}")
        data: dict[str, Any] = {
            "version": 1,
            "snapshot": asdict(authority.snapshot),
            "transaction": secrets.token_hex(16),
            "phase": "preparing",
            "source": str(source.relative_to(authority.root)),
            "source_identity": _migrate._file_identity(source),
            "source_parents": _migrate._parents(authority.root, source),
            "parent": _migrate._parents(destination.parent, destination),
            "destination": str(destination),
            "prepared": str(staged),
            "identity": None,
            "verification": None,
        }
        with _registry(authority.root):
            _no_pending(authority.root)
            _load_inventory(authority.root, authority.snapshot)
            _migrate._put_json(authority.root, _JOURNAL, data)
        _transition("pending")
        _prepare_backup(connection, destination, authority, data)
        _publish_backup(destination, authority, data)
    return destination


def _pending(root: Path, snapshot: NativeSnapshot) -> dict[str, Any]:
    data = _migrate._read_json(root, _JOURNAL)
    if (
        not isinstance(data, dict)
        or data.get("version") != 1
        or data.get("snapshot") != asdict(snapshot)
        or data.get("phase") not in {"preparing", "verified"}
    ):
        raise DatabaseRefused("backup journal belongs to another root/generation")
    destination = _canonical_destination(Path(data["destination"]))
    prepared = _canonical_destination(Path(data["prepared"]))
    if (
        prepared.parent != destination.parent
        or prepared == destination
        or not prepared.name.startswith(destination.name + ".mordred-backup-")
        or in_scope(destination, root)
        or in_scope(prepared, root)
        or _migrate._parents(destination.parent, destination) != data.get("parent")
    ):
        raise DatabaseRefused("invalid backup journal paths")
    return data


def recover_backups(root: Path, *, lease: ExclusiveLease) -> None:
    ExclusiveLease.assert_held(lease, root)
    snapshot, key = _migrate._authenticate(root, None, lease)
    if snapshot is None:
        raise DatabaseRefused("backup recovery requires native source proof")
    with _registry(root):
        pending = _migrate._read_json(root, _JOURNAL)
        if isinstance(pending, dict) and pending.get("operation") == "delete":
            _recover_delete(root, snapshot, pending)
            return
        data = _pending(root, snapshot)
        if data["phase"] != "verified":
            _recover_preparing(root, data, key)
        destination, prepared = Path(data["destination"]), Path(data["prepared"])
        candidate = prepared if prepared.exists() else destination
        if (
            _migrate._file_identity(candidate) != data["identity"]
            or _migrate._schema(candidate, key, root=root) != data["verification"]
        ):
            raise DatabaseRefused("backup recovery identity/schema proof failed")
        if candidate == prepared:
            with open_private_directory(prepared.parent) as directory, directory.transaction() as tx:
                tx.rename_file(prepared.name, destination.name, expected_identity=tx.stat(prepared.name).identity)
        ExclusiveLease.assert_held(lease, root)
        _register(root, snapshot, data)


def _offline_copy(source: Path, staged: Path, key: DatabaseKey, root: Path) -> None:
    from ._shim import apply_key

    sc = _migrate._sqlcipher()
    with (
        _migrate._offline_connection(source, readonly=True, root=root) as reader,
        _migrate._offline_connection(staged, root=root) as writer,
    ):
        apply_key(reader, key)
        apply_key(writer, key)
        if reader.execute("PRAGMA journal_mode").fetchone() == ("wal",) and _migrate.wal_reset_vulnerable(
            sc.sqlite_version_info
        ):
            raise DatabaseRefused("WAL backup refuses a WAL-reset vulnerable SQLite version")
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM sqlite_master").fetchone()
        reader.backup(writer)
        reader.rollback()


def _recover_preparing(root: Path, data: dict[str, Any], key: DatabaseKey) -> None:
    """Rebuild only the journal-owned staging file from a verified survivor.

    No source is erased/repaired. If the source or staged ownership is uncertain,
    all copies and the journal remain dependencies for explicit intervention.
    """
    source = _migrate._bound_path(root, data["source"])
    destination, staged = Path(data["destination"]), Path(data["prepared"])
    if (
        destination.exists()
        or _migrate._file_identity(source) != data["source_identity"]
        or _migrate._parents(root, source) != data["source_parents"]
    ):
        raise DatabaseRefused("incomplete backup source or destination changed")
    _migrate._refuse_if_open([_migrate.Database(p, str(p), "") for p in (source, staged) if p.exists()], None)
    expected = _migrate._schema(source, key, root=root)
    with open_private_directory(staged.parent) as directory, directory.transaction() as tx:
        try:
            observed = tx.stat(staged.name)
        except PrivateFSError as exc:
            if exc.reason != "missing" or data["identity"] is not None:
                raise DatabaseRefused("backup staging ownership is uncertain") from exc
        else:
            if _migrate._file_identity(staged) != data["identity"]:
                raise DatabaseRefused("backup staging ownership is uncertain")
            # The source is intact/authenticated; only our recorded staging inode
            # can be removed. Never erase an unrecorded or potentially only copy.
            tx.delete_file(staged.name, expected_identity=observed.identity)
        tx.create_bytes(staged.name, b"")
        data["identity"] = _migrate._file_identity(staged)
        _migrate._put_json(root, _JOURNAL, data)
        _offline_copy(source, staged, key, root)
        tx.flush_file(staged.name, expected_identity=tx.stat(staged.name).identity)
        if _migrate._schema(staged, key, root=root) != expected:
            raise DatabaseRefused("recovered backup schema/count proof failed")
        data["verification"], data["phase"] = expected, "verified"
        _migrate._put_json(root, _JOURNAL, data)


def _find(root: Path, source: Path, snapshot: NativeSnapshot) -> dict[str, Any]:
    source = _canonical_destination(source)
    inventory = _load_inventory(root, snapshot)
    entries = [entry for entry in inventory["entries"] if entry["path"] == str(source)]
    if len(entries) != 1 or _migrate._file_identity(source) != entries[0]["identity"]:
        raise DatabaseRefused("backup is not registered to this root, generation and physical file")
    return dict(entries[0])


def restore_database(source: Path, destination: Path, *, lease: ExclusiveLease) -> None:
    # Resolve root from the actual lease registry, never trust a backup's root.
    from .._database_lifecycle import current_thread_exclusive_leases
    from ..keyvault._database_authority import resolve_database_domain

    if type(lease) is not ExclusiveLease or lease not in current_thread_exclusive_leases():
        raise DatabaseRefused("restore requires a preceding exclusive lease")
    # A destination must already exist in a protected home; restore cannot create
    # an empty replacement for an ambiguous or missing database.
    destination = destination.absolute()
    root: Path | None = None
    for parent in destination.parents:
        try:
            domain = resolve_database_domain(parent)
            if domain.identities[0] == lease.root:
                root = domain.root
                break
        except (DatabaseRefused, OSError):
            continue
    if root is None or not in_scope(destination, root):
        raise DatabaseRefused("restore destination does not belong to exclusive root")
    ExclusiveLease.assert_held(lease, root)
    snapshot, key = _migrate._authenticate(root, None, lease)
    if snapshot is None:
        raise DatabaseRefused("restore requires native source proof")
    _migrate._inventory(root)
    _migrate._refuse_if_open([_migrate.Database(p, str(p), "") for p in (source, destination)], None)
    with _registry(root):
        _no_pending(root)
        entry = _find(root, source, snapshot)
        if _migrate._schema(source, key, root=root) != entry["verification"]:
            raise DatabaseRefused("backup schema/count verification failed")
        _migrate._schema(destination, key)
        _restore_copy(root, source, destination, key, lease, snapshot, entry)


def _restore_copy(
    root: Path,
    source: Path,
    destination: Path,
    key: DatabaseKey,
    lease: ExclusiveLease,
    snapshot: NativeSnapshot,
    entry: dict[str, Any],
) -> None:
    # Offline EX uses the same SQLCipher backup API and authenticated source.
    # No raw database descriptor is opened while SQLite owns a live lock.
    staged = Path(str(destination) + _migrate.PREPARED_SUFFIX)
    identity = _migrate._file_identity(destination)
    _migrate._reserve(staged)
    before = _migrate._file_identity(source)
    _offline_copy(source, staged, key, root)
    _migrate._fsync_file(staged)
    if _migrate._file_identity(source) != before or _migrate._schema(staged, key, root=root) != entry["verification"]:
        raise DatabaseRefused("backup changed during restore")
    transaction = secrets.token_hex(16)
    data = {
        "version": 2,
        "root": asdict(lease.root),
        "snapshot": asdict(snapshot),
        "transaction": transaction,
        "publication": "retained" if _migrate._two_step_publication() else "replace",
        "inventory": _migrate._inventory_binding(root),
        "direction": "encrypt",
        "files": [
            {
                "relative": str(destination.relative_to(root)),
                "prepared": str(staged.relative_to(root)),
                "retained": str(destination.relative_to(root)) + _migrate.RETAINED_SUFFIX + transaction,
                "source_identity": identity,
                "source_revision": _migrate._revision(destination),
                "prepared_identity": _migrate._file_identity(staged),
                "verification": entry["verification"],
                "phase": "verified",
            }
        ],
    }
    _migrate._save_journal(root, data, "verified")
    _migrate._finish(root, data, key, snapshot, lease, None, None)


def _recover_delete(root: Path, snapshot: NativeSnapshot, data: dict[str, Any]) -> None:
    if (
        set(data) != {"version", "operation", "snapshot", "entry", "parent"}
        or data["version"] != 1
        or data["snapshot"] != asdict(snapshot)
        or not isinstance(data["entry"], dict)
    ):
        raise DatabaseRefused("invalid backup deletion journal")
    entry = data["entry"]
    inventory = _load_inventory(root, snapshot)
    if entry not in inventory["entries"]:
        # A crash after the durable inventory commit may leave only the intent.
        if any(e["path"] == entry.get("path") for e in inventory["entries"]):
            raise DatabaseRefused("backup deletion registry changed")
        _migrate._remove_record(root, _JOURNAL)
        return
    source = _canonical_destination(Path(entry["path"]))
    if _migrate._parents(source.parent, source) != data["parent"]:
        raise DatabaseRefused("backup deletion parent identity changed")
    with open_private_directory(source.parent) as directory, directory.transaction() as tx:
        try:
            observed = tx.stat(source.name)
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
        else:
            if _migrate._file_identity(source) != entry["identity"]:
                raise DatabaseRefused("registered backup identity changed")
            tx.delete_file(source.name, expected_identity=observed.identity)
    _transition("deleted")
    inventory["entries"].remove(entry)
    if inventory["entries"]:
        _migrate._put_json(root, _INVENTORY, inventory)
    else:
        _migrate._remove_record(root, _INVENTORY)
    _migrate._remove_record(root, _JOURNAL)


def delete_backup(source: Path, *, authority: Authority) -> None:
    """Unregister only after identity-checked deletion has become durable."""
    authority.check()
    with authority.operation(), _registry(authority.root):
        _no_pending(authority.root)
        entry = _find(authority.root, source, authority.snapshot)
        source = Path(entry["path"])
        data = {
            "version": 1,
            "operation": "delete",
            "snapshot": asdict(authority.snapshot),
            "entry": entry,
            "parent": _migrate._parents(source.parent, source),
        }
        _migrate._put_json(authority.root, _JOURNAL, data)
        _recover_delete(authority.root, authority.snapshot, data)
