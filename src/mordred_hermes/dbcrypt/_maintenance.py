"""Small checked EX SQL lifetime for component-owned offline finalization.

The caller owns a preceding exclusive lease. No runtime, recovery, callback,
raw SQL handle or key is exported; rows are materialized before leaving checks.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._database_contracts import DatabaseRefused, NativeSnapshot
from .._database_lifecycle import ExclusiveLease, current_thread_exclusive_leases
from ..keyvault._database_authority import CheckedDatabaseDomain, observe_database_source, resolve_database_domain
from . import _migrate
from ._connection import _check_sql, _MaintenanceConnection, _parameters, _PathBinding, _sql_action_denied
from ._key import DatabaseKey
from ._marker import Marker, read_marker
from ._policy import in_scope
from ._shim import apply_key


@dataclass(frozen=True)
class MaintenanceRows:
    """Immutable values, with no cursor or retained SQL resource."""

    rows: tuple[tuple[Any, ...], ...]

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> tuple[tuple[Any, ...], ...]:
        return self.rows

    def __iter__(self) -> Iterator[tuple[Any, ...]]:
        return iter(self.rows)


class MaintenanceConnection:
    """Factory-issued statement/transaction facade; never a database authority input."""

    def __init__(self) -> None:
        raise DatabaseRefused("maintenance connections require a checked EX scope")

    _scope: MaintenanceScope
    _owner: _MaintenanceConnection
    _binding: _PathBinding
    _closed: bool
    _denied: bool

    def _check(self) -> None:
        self._scope._check()
        if self._closed:
            raise DatabaseRefused("maintenance connection is closed")
        self._owner._check()
        try:
            self._binding.check()
        except Exception:
            self._scope._invalidate()
            raise DatabaseRefused("maintenance destination changed") from None

    def _authorize(self, action: int, first: Any, second: Any, database: Any, trigger: Any) -> int:
        import sqlcipher3.dbapi2 as sc

        try:
            self._check()
            denied = _sql_action_denied(action, first, second)
            if action == sc.SQLITE_PRAGMA:
                name, value = str(first or "").lower(), str(second or "").lower()
                denied |= name == "temp_store" and second is not None and value not in {"memory", "2"}
                denied |= name == "mmap_size" and second is not None and value != "0"
                denied |= name == "journal_mode" and second is not None and value != "delete"
            if denied:
                self._denied = True
                return int(sc.SQLITE_DENY)
            return int(sc.SQLITE_OK)
        except Exception:
            self._denied = True
            return int(sc.SQLITE_DENY)

    def _progress(self) -> int:
        try:
            self._check()
            return 0
        except Exception:
            self._denied = True
            return 1

    @contextlib.contextmanager
    def _operation(self) -> Iterator[None]:
        self._check()
        self._denied = False
        try:
            yield
            self._check()
        except Exception as error:
            if self._denied or isinstance(error, DatabaseRefused):
                self._scope._invalidate()
                raise DatabaseRefused("maintenance SQL admission was refused") from None
            raise

    def execute(self, sql: str, parameters: Any = ()) -> MaintenanceRows:
        values = _parameters(parameters)
        with self._operation():
            _check_sql(sql)
            cursor = self._owner.execute(sql, values)
            try:
                rows: list[tuple[Any, ...]] = []
                while True:
                    self._check()
                    row = cursor.fetchone()
                    if row is None:
                        break
                    rows.append(tuple(row))
                return MaintenanceRows(tuple(rows))
            finally:
                cursor.close()

    def executemany(self, sql: str, parameters: Iterable[Any]) -> None:
        # No arbitrary adapter or lazy iterator runs inside SQL admission.
        batches = tuple(_parameters(values) for values in parameters)
        with self._operation():
            _check_sql(sql)
        for values in batches:
            self.execute(sql, values)

    def commit(self) -> None:
        with self._operation():
            self._owner.commit()

    def rollback(self) -> None:
        with self._operation():
            self._owner.rollback()


def _verify_component_database(connection: MaintenanceConnection, entry: dict[str, Any] | None) -> None:
    """Verify through the guarded facade after registry metadata exclusion ends."""
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA mmap_size=0")
    if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
        raise DatabaseRefused("component maintenance requires rollback journal mode")
    if connection.execute("PRAGMA cipher_integrity_check").fetchall() or connection.execute(
        "PRAGMA quick_check"
    ).fetchone() != ("ok",):
        raise DatabaseRefused("maintenance database authentication failed")
    if entry is not None:
        verification = {
            "counts": _migrate._counts(connection),
            "ids": list(_migrate._ids(connection)),
            "schema_sha256": _migrate._schema_hash(
                connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
            ),
        }
        if verification != entry["verification"]:
            raise DatabaseRefused("registered backup verification failed")


class MaintenanceScope:
    """One native authentication under an actual EX lease, with terminal refusal."""

    def __init__(self) -> None:
        raise DatabaseRefused("maintenance scopes require a preceding exclusive lease")

    _key: DatabaseKey | None
    _lease: ExclusiveLease
    _domain: CheckedDatabaseDomain
    _snapshot: NativeSnapshot
    _pid: int
    _thread: int
    _terminal: bool
    _active: bool

    def _invalidate(self) -> None:
        self._terminal = True
        self._key = None

    def _check(self) -> None:
        # PID/thread admission precedes inherited Python locks and SQL cleanup.
        if self._pid != os.getpid() or self._thread != threading.get_ident() or self._terminal:
            self._invalidate()
            raise DatabaseRefused("maintenance scope owner is closed or changed")
        try:
            ExclusiveLease.assert_held(self._lease, self._domain.root)
            from ._backup import _no_pending

            _no_pending(self._domain.root)
            if resolve_database_domain(self._domain.home) != self._domain:
                raise DatabaseRefused("maintenance profile mapping changed")
            if read_marker(self._domain.root) != Marker(self._snapshot):
                raise DatabaseRefused("maintenance marker changed")
            if observe_database_source(root=self._domain.root) != self._snapshot:
                raise DatabaseRefused("maintenance native source changed")
            ExclusiveLease.assert_held(self._lease, self._domain.root)
        except Exception:
            self._invalidate()
            raise DatabaseRefused("maintenance source or exclusive lease changed") from None

    @contextlib.contextmanager
    def connection(self, path: Path, *, readonly: bool = False) -> Iterator[MaintenanceConnection]:
        self._check()
        if type(readonly) is not bool or self._active:
            raise DatabaseRefused("maintenance connections must be sequential with a boolean read policy")
        root = self._domain.root
        key = self._key
        if key is None:
            raise DatabaseRefused("maintenance key lifetime is closed")
        entry = None
        if not path.is_absolute() or ".." in path.parts:
            raise DatabaseRefused("maintenance path must be canonical")
        protected = path.is_relative_to(root) and in_scope(path, root)
        if not protected:
            if path.is_relative_to(root) or not readonly:
                raise DatabaseRefused("foreign maintenance access requires a registered readonly backup")
            from . import _backup

            # Release registry metadata exclusion before any external SQL.
            with _backup._registry(root):
                _backup._no_pending(root)
                entry = _backup._find(root, path, self._snapshot)
        binding = _PathBinding(path, root if protected else path.parent, protected=protected)
        if binding.leaf is None:
            raise DatabaseRefused("maintenance never creates a missing database")
        self._check()
        self._active = True
        try:
            with _migrate._offline_connection(path, readonly=readonly, root=root) as owner:
                binding.check()
                self._check()
                apply_key(owner, key)  # private bootstrap; never a caller SQL surface
                binding.check()
                self._check()
                connection = object.__new__(MaintenanceConnection)
                connection._scope, connection._owner, connection._binding = self, owner, binding
                connection._closed = connection._denied = False
                connection._check()
                owner._install_component_policy(connection)
                try:
                    _verify_component_database(connection, entry)
                    yield connection
                    connection._check()
                finally:
                    # Cleanup is owned and PID-bound, even after metadata denial.
                    owner._clear_component_policy()
                    connection._closed = True
        finally:
            self._active = False


@contextlib.contextmanager
def maintenance_scope(home: Path, *, lease: ExclusiveLease) -> Iterator[MaintenanceScope]:
    if type(lease) is not ExclusiveLease or lease not in current_thread_exclusive_leases():
        raise DatabaseRefused("component SQL requires a preceding exclusive lease")
    domain = resolve_database_domain(home)
    ExclusiveLease.assert_held(lease, domain.root)
    snapshot, key = _migrate._authenticate(domain.root, None, lease)
    if snapshot is None or read_marker(domain.root) != Marker(snapshot):
        raise DatabaseRefused("component SQL requires an adopted native marker")
    scope = object.__new__(MaintenanceScope)
    scope._domain, scope._snapshot, scope._key, scope._lease = domain, snapshot, key, lease
    scope._pid, scope._thread = os.getpid(), threading.get_ident()
    scope._terminal = scope._active = False
    try:
        scope._check()
        yield scope
        scope._check()
    finally:
        scope._invalidate()
