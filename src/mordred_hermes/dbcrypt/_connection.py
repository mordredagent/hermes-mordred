"""Checked SQLCipher facades: no documented API exposes an unguarded handle.

The owning driver performs all database I/O. Filesystem observations below are
metadata only: opening/closing a second database fd would release POSIX locks.
Unsupported export/callback APIs refuse before I/O; backup authorization belongs
in the offline registry layer, not an ambient filename or environment exemption.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import stat
import threading
import weakref
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .._database_contracts import DatabaseRefused
from ..keyvault._database_authority import resolve_database_domain
from ._authority import Authority
from ._policy import in_scope

# Qualified against Hermes's installed declarative schema. Future versions need
# explicit compatibility qualification before opening an existing state.db.
_MAX_SESSION_SCHEMA_VERSION = 22
# An inherited SQLite handle must neither execute nor finalize in a child.
# Quarantine both connections and cursors before Python resumes after fork;
# captured _exit runs before module/C finalizers on an orderly child exit.
_INHERITED: list[Any] = []
_LIVE_CONNECTIONS: weakref.WeakSet[ProtectedConnection] = weakref.WeakSet()
_LIVE_CURSORS: weakref.WeakSet[ProtectedCursor] = weakref.WeakSet()
_LIVE_MAINTENANCE: weakref.WeakSet[_MaintenanceConnection] = weakref.WeakSet()
_FORKED = [False]


def _after_fork() -> None:
    connections, cursors = tuple(_LIVE_CONNECTIONS), tuple(_LIVE_CURSORS)
    maintenance = tuple(_LIVE_MAINTENANCE)
    if connections or cursors or maintenance:
        _FORKED[0] = True
        _INHERITED.extend(connections)
        _INHERITED.extend(cursors)
        _INHERITED.extend(maintenance)  # Owners retain every raw cursor before child GC.


def _exit_forked_child(state: list[bool] = _FORKED, exit_process: Any = os._exit) -> None:
    if state[0]:
        exit_process(74)


atexit.register(_exit_forked_child)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _identity(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    if os.name == "nt":
        from ._windows_vfs import checked_path_identity

        return checked_path_identity(path, directory=directory)
    info = path.lstat()
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or info.st_mode & 0o022 or (not directory and info.st_nlink != 1):
        raise DatabaseRefused("database path must be owned, physical and not writable by other users")
    if os.name == "posix" and info.st_uid != os.getuid():
        raise DatabaseRefused("database path owner changed")
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid


class _PathBinding:
    def __init__(self, path: Path, root: Path, *, protected: bool = True) -> None:
        if ".." in path.parts or not path.is_absolute() or not path.is_relative_to(root):
            raise DatabaseRefused("database destination is outside the authority root")
        if protected and not in_scope(path, root):
            raise DatabaseRefused("database destination is outside the protected scope")
        self.path = path
        parts = path.relative_to(root).parts
        self.profile = (
            resolve_database_domain(root / "profiles" / parts[1])
            if protected and len(parts) >= 3 and parts[0] == "profiles"
            else None
        )
        self.parents = tuple(reversed(path.parents[: len(path.parents) - len(root.parents)]))
        self.identities = tuple(_identity(p, directory=True) for p in self.parents)
        self.leaf: tuple[int, int, int, int] | None
        try:
            self.leaf = _identity(path, directory=False)
        except FileNotFoundError:
            self.leaf = None

    def check(self, *, newly_created: bool = False) -> None:
        if self.profile is not None and resolve_database_domain(self.profile.home) != self.profile:
            raise DatabaseRefused("database profile mapping changed")
        if tuple(_identity(p, directory=True) for p in self.parents) != self.identities:
            raise DatabaseRefused("database parent identity changed")
        leaf = _identity(self.path, directory=False)
        if self.leaf is None and newly_created:
            self.leaf = leaf
        if leaf != self.leaf:
            raise DatabaseRefused("database identity changed")


def _skip_quoted(sql: str, index: int) -> int:
    close = "]" if sql[index] == "[" else sql[index]
    index += 1
    while index < len(sql):
        if sql[index] == close:
            index += 1
            if close != "]" and index < len(sql) and sql[index] == close:
                index += 1
                continue
            break
        index += 1
    return index


def _check_sql(sql: str) -> None:
    """Recognize bare SQLite keywords, skipping literals, identifiers and comments.

    RETURNING keeps a write statement live after execute(), whose C destructor
    can implicitly commit without another Python admission. Refuse before prepare
    until a driver with guarded statement-finalization support is qualified.
    """
    if type(sql) is not str:
        raise DatabaseRefused("SQL must be an ordinary string")
    index = 0
    while index < len(sql):
        char = sql[index]
        if sql.startswith("--", index):
            end = sql.find("\n", index + 2)
            index = len(sql) if end < 0 else end + 1
        elif sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = len(sql) if end < 0 else end + 2
        elif char in "'\"`[":
            index = _skip_quoted(sql, index)
        elif char.isalpha() or char == "_" or ord(char) >= 128 or char in ":@$":
            start = index
            index += 1
            while index < len(sql) and (sql[index].isalnum() or sql[index] in "_$" or ord(sql[index]) >= 128):
                index += 1
            if sql[start:index].lower() == "returning":
                raise DatabaseRefused("RETURNING statements require guarded native finalization")
        else:
            index += 1


def _parameters(values: Any) -> Any:
    """Materialize bindings before admission; do not invoke arbitrary adapters in SQL."""

    def safe(value: Any) -> Any:
        if value is None or type(value) in (int, float, str, bytes):
            return value
        if type(value) in (bytearray, memoryview):
            return bytes(value)
        raise DatabaseRefused("custom SQL parameter adapters are unsupported")

    if isinstance(values, Mapping):
        return {str(k): safe(v) for k, v in values.items()}
    return tuple(safe(v) for v in values)


def _sql_action_denied(action: int, first: Any, second: Any) -> bool:
    """Shared runtime/component SQL escape policy; admission remains owner-specific."""
    import sqlcipher3.dbapi2 as sc

    prohibited = action in (sc.SQLITE_ATTACH, sc.SQLITE_DETACH)
    if action == sc.SQLITE_PRAGMA:
        name = (first or "").lower()
        prohibited |= (
            name.startswith("cipher") and not (name in {"cipher_version", "cipher_integrity_check"} and second is None)
        ) or name in {
            "key",
            "rekey",
            "hexkey",
            "hexrekey",
            "writable_schema",
            "temp_store_directory",
            "data_store_directory",
        }
        # OFF/MEMORY disables durable rollback; ordinary Hermes WAL is allowed.
        prohibited |= name == "journal_mode" and (second or "").lower() in {"off", "memory"}
    if action == sc.SQLITE_FUNCTION:
        prohibited |= (second or "").lower() in {"load_extension", "sqlcipher_export", "writefile", "readfile"}
    return prohibited


class ProtectedCursor:
    """Every fetch/iteration step returns through the owning connection guard."""

    def __init__(self, connection: ProtectedConnection, cursor: Any) -> None:
        self._connection = connection
        self._cursor = cursor
        self._row_factory: Any = connection.row_factory
        self._install_row_factory()
        _LIVE_CURSORS.add(self)

    @property
    def connection(self) -> ProtectedConnection:
        return self._connection

    def _install_row_factory(self) -> None:
        import sqlcipher3.dbapi2 as sc

        factory = self._row_factory
        if factory is None or factory is sc.Row:
            self._cursor.row_factory = factory
        else:

            def row(_raw: Any, values: Any) -> Any:
                self._connection._check()
                result = factory(self, values)
                self._connection._check()
                return result

            self._cursor.row_factory = row

    @property
    def row_factory(self) -> Any:
        with self._connection._operation():
            return self._row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        with self._connection._operation():
            self._row_factory = value
            self._install_row_factory()

    def execute(self, sql: str, parameters: Any = ()) -> ProtectedCursor:
        _check_sql(sql)
        values = _parameters(parameters)
        with self._connection._operation():
            self._cursor.execute(sql, values)
        return self

    def executemany(self, sql: str, seq_of_parameters: Any) -> ProtectedCursor:
        _check_sql(sql)

        def checked_parameters() -> Iterator[Any]:
            for parameters in seq_of_parameters:
                values = _parameters(parameters)
                self._connection._check()
                yield values
            self._connection._check()

        with self._connection._operation():
            self._cursor.executemany(sql, checked_parameters())
        return self

    def executescript(self, sql_script: str) -> ProtectedCursor:
        _check_sql(sql_script)
        with self._connection._operation():
            self._cursor.executescript(sql_script)
        return self

    def fetchone(self) -> Any:
        with self._connection._operation():
            return self._cursor.fetchone()

    def fetchmany(self, size: int | None = None) -> Any:
        with self._connection._operation():
            return self._cursor.fetchmany() if size is None else self._cursor.fetchmany(size)

    def fetchall(self) -> Any:
        with self._connection._operation():
            return self._cursor.fetchall()

    def __iter__(self) -> ProtectedCursor:
        self._connection._check()
        return self

    def __next__(self) -> Any:
        with self._connection._operation():
            return next(self._cursor)

    def close(self) -> None:
        if not self._connection._closed:
            with self._connection._operation():
                self._cursor.close()
                _LIVE_CURSORS.discard(self)

    @property
    def arraysize(self) -> int:
        with self._connection._operation():
            return int(self._cursor.arraysize)

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        with self._connection._operation():
            self._cursor.arraysize = value

    @property
    def description(self) -> Any:
        with self._connection._operation():
            return self._cursor.description

    @property
    def rowcount(self) -> int:
        with self._connection._operation():
            return int(self._cursor.rowcount)

    @property
    def lastrowid(self) -> Any:
        with self._connection._operation():
            return self._cursor.lastrowid

    def setinputsizes(self, sizes: Any) -> None:
        with self._connection._operation():
            self._cursor.setinputsizes(sizes)

    def setoutputsize(self, size: Any, column: Any = None) -> None:
        with self._connection._operation():
            self._cursor.setoutputsize(size, column)


class ProtectedConnection:
    """Composition, not C inheritance: base descriptors cannot bypass guards."""

    _authority: Authority
    _binding: _PathBinding | _MemoryBinding
    _raw: Any
    _pid: int
    _thread: int
    _same_thread: bool
    _protected: bool
    _closed: bool
    _revoked: bool
    _active: int
    _denied: bool
    _row_factory: Any
    _vfs: Any

    def __init__(self) -> None:
        raise DatabaseRefused("protected connections must be opened through their authority")

    def _check(self) -> None:
        # Authority checks PID before any inherited Python or SQLite lock.
        self._authority.check()
        if self._closed or self._revoked:
            raise DatabaseRefused("database connection is closed or revoked")
        if self._same_thread and threading.get_ident() != self._thread:
            import sqlcipher3.dbapi2 as sc

            raise sc.ProgrammingError("SQLite objects created in a thread can only be used in that same thread")
        try:
            self._binding.check()
        except (OSError, DatabaseRefused):
            self._authority.invalidate("database path changed")
            raise DatabaseRefused("database path authority changed") from None

    @contextlib.contextmanager
    def _operation(self) -> Iterator[None]:
        with self._authority.operation():
            self._check()
            self._active += 1
            self._denied = False
            try:
                yield
                self._check()
            except Exception:
                if self._denied or self._revoked or self._authority.terminal:
                    raise DatabaseRefused("database operation refused by authority policy") from None
                raise
            finally:
                self._active -= 1
                if self._revoked and not self._active:
                    self._dispose()

    def _authorize(self, action: int, first: Any, second: Any, database: Any, trigger: Any) -> int:
        import sqlcipher3.dbapi2 as sc

        try:
            self._check()
            prohibited = _sql_action_denied(action, first, second)
            if prohibited:
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

    def _dispose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._authority.unregister_connection(self)
        if self._pid != os.getpid():
            # Do not run inherited transactions, finalizers or C mutexes here.
            _INHERITED.append(self._raw)
            return
        self._raw.set_authorizer(None)
        self._raw.set_progress_handler(None, 0)
        try:
            self._raw.rollback()
        finally:
            try:
                # Retained Python cursors must lose their C statements before
                # we stop treating them as inherited live handles at fork.
                for cursor in tuple(_LIVE_CURSORS):
                    if cursor._connection is self:
                        cursor._cursor.close()
                        _LIVE_CURSORS.discard(cursor)
            finally:
                self._raw.close()
                _LIVE_CONNECTIONS.discard(self)
                if self._vfs is not None:
                    self._vfs.close()

    def invalidate(self) -> None:
        self._revoked = True
        if not self._active or self._pid != os.getpid():
            self._dispose()

    def close(self) -> None:
        if self._pid != os.getpid():
            self._authority.check()
        with self._authority.operation(check=False):
            if self._active:
                self._revoked = True
            else:
                self._dispose()

    def cursor(self, factory: Any = None) -> ProtectedCursor:
        with self._operation():
            if factory not in (None, ProtectedCursor):
                raise DatabaseRefused("custom cursor factories are unsupported")
            return ProtectedCursor(self, self._raw.cursor())

    def execute(self, sql: str, parameters: Any = ()) -> ProtectedCursor:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Any) -> ProtectedCursor:
        return self.cursor().executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> ProtectedCursor:
        return self.cursor().executescript(sql_script)

    def commit(self) -> None:
        with self._operation():
            self._raw.commit()

    def rollback(self) -> None:
        with self._operation():
            self._raw.rollback()

    def __enter__(self) -> ProtectedConnection:
        self._check()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()

    @property
    def mordred_key(self) -> bool | None:
        """Legacy activity admission flag, without exposing key bytes."""
        with self._operation():
            return True if self._protected else None

    @property
    def isolation_level(self) -> Any:
        with self._operation():
            return self._raw.isolation_level

    @isolation_level.setter
    def isolation_level(self, value: Any) -> None:
        with self._operation():
            self._raw.isolation_level = value

    @property
    def row_factory(self) -> Any:
        with self._operation():
            return self._row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        with self._operation():
            self._row_factory = value

    @property
    def text_factory(self) -> Any:
        with self._operation():
            return self._raw.text_factory

    @text_factory.setter
    def text_factory(self, value: Any) -> None:
        with self._operation():
            if value not in (str, bytes):
                raise DatabaseRefused("custom text factories are unsupported")
            self._raw.text_factory = value

    @property
    def in_transaction(self) -> bool:
        with self._operation():
            return bool(self._raw.in_transaction)

    @property
    def total_changes(self) -> int:
        with self._operation():
            return int(self._raw.total_changes)

    def backup(
        self, target: Any, *, pages: int = -1, progress: Any = None, name: str = "main", sleep: float = 0.250
    ) -> None:
        from ._backup import _Destination

        if type(target) is not _Destination or progress is not None or name != "main" or pages != -1 or sleep != 0.250:
            self._unsupported()
        _copy_registered_backup(self, target)

    def _unsupported(self, *args: Any, **kwargs: Any) -> Any:
        self._check()
        raise DatabaseRefused("this SQL surface requires an authorized implementation")

    open_blob = blobopen = serialize = deserialize = iterdump = _unsupported
    set_authorizer = set_progress_handler = set_trace_callback = _unsupported
    enable_load_extension = load_extension = set_key = reset_key = _unsupported
    create_function = create_aggregate = create_window_function = create_collation = _unsupported
    set_busy_handler = set_busy_timeout = interrupt = _unsupported
    autocommit = property(_unsupported, _unsupported)


def _verify_database(connection: ProtectedConnection) -> None:
    """Read schema and authenticated pages through the exact owning SQLCipher."""
    # Admission before the public authorizer is installed permits cipher checks.
    raw = connection._raw
    if not raw.execute("PRAGMA cipher_version").fetchone():
        raise DatabaseRefused("SQLCipher is unavailable")
    raw.execute("SELECT count(*) FROM sqlite_master").fetchone()
    if raw.execute("PRAGMA cipher_integrity_check").fetchall():
        raise DatabaseRefused("database authentication check failed")
    if connection._binding.path.name == "state.db":
        present = raw.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
        if present:
            versions = raw.execute("SELECT version FROM schema_version").fetchall()
            if (
                len(versions) != 1
                or type(versions[0][0]) is not int
                or not 0 <= versions[0][0] <= _MAX_SESSION_SCHEMA_VERSION
            ):
                raise DatabaseRefused("unsupported Hermes session schema")


def verify_database(connection: ProtectedConnection) -> None:
    with connection._operation():
        _verify_database(connection)


class _MemoryBinding:
    path = Path(":memory:")
    leaf = None

    def check(self, *, newly_created: bool = False) -> None:
        pass


def open_protected(
    path: Path, *, authority: Authority, timeout: float = 5.0, readonly: bool = False, check_same_thread: bool = True
) -> ProtectedConnection:
    if type(check_same_thread) is not bool:
        raise DatabaseRefused("thread policy must be a boolean")
    return _open(
        path,
        authority=authority,
        timeout=timeout,
        readonly=readonly,
        protected=True,
        check_same_thread=check_same_thread,
    )


def _open_unprotected(
    path: Path | None, *, authority: Authority, timeout: float = 5.0, readonly: bool = False
) -> ProtectedConnection:
    return _open(path, authority=authority, timeout=timeout, readonly=readonly, protected=False)


def _matches_native_cipher(path: Path, authority: Authority) -> bool:
    """Classify a foreign copy by authentication, never its plaintext header.

    Classification is not a grant: a matching foreign file still needs Task 7's
    registration before it may be returned. Both probes use the owning library.
    """
    import sqlcipher3.dbapi2 as sc

    from ._shim import apply_key, wrong_key_errors

    probe = sc.connect(f"file:{quote(path.as_posix(), safe='/:')}?mode=ro", uri=True)
    try:
        apply_key(probe, authority.key)
        probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return not probe.execute("PRAGMA cipher_integrity_check").fetchall()
    except wrong_key_errors(sc):
        return False
    finally:
        probe.close()


def _sqlite_busy(error: BaseException) -> bool:
    """Only the driver's numeric BUSY/LOCKED codes denote transient contention."""
    import sqlcipher3.dbapi2 as sc

    code = getattr(error, "sqlite_errorcode", None)
    return isinstance(error, sc.OperationalError) and isinstance(code, int) and code & 255 in (5, 6)


def _open(
    path: Path | None,
    *,
    authority: Authority,
    timeout: float,
    readonly: bool,
    protected: bool,
    check_same_thread: bool = True,
) -> ProtectedConnection:
    import sqlcipher3.dbapi2 as sc

    authority.check()
    path = path.absolute() if path is not None else None
    if os.name == "nt" and path is not None:
        from ._windows_vfs import NATIVE_QUALIFIED

        if not NATIVE_QUALIFIED or not protected:
            raise DatabaseRefused("Windows destination is not qualified for guarded SQL")
    with authority.operation():
        binding: _PathBinding | _MemoryBinding = (
            _PathBinding(path, authority.root if protected else path.parent, protected=protected)
            if path is not None
            else _MemoryBinding()
        )
        if readonly and binding.leaf is None:
            raise DatabaseRefused("read-only database does not exist")
        if not protected and path is not None and binding.leaf is not None and path.stat().st_size:
            if _matches_native_cipher(path, authority):
                raise DatabaseRefused("encrypted foreign copies require registered backup authority")
            binding.check()
        vfs = None
        mode = "ro" if readonly else ("rw" if binding.leaf is not None else "rwc")
        uri = f"file:{quote(path.as_posix(), safe='/:')}?mode={mode}" if path is not None else ":memory:"
        if os.name == "nt" and path is not None:
            from ._windows_vfs import NATIVE_QUALIFIED, classify_windows_database, register_checked_vfs

            if not NATIVE_QUALIFIED:
                raise DatabaseRefused("Windows checked VFS is not qualified")
            classify_windows_database(str(path), uri=False, root=authority.root)
            vfs = register_checked_vfs(sc, root=authority.root)
            uri += "&vfs=mordred_checked_v1"
        return _open_bound(
            binding, authority, uri, vfs, timeout=timeout, protected=protected, check_same_thread=check_same_thread
        )


def _open_bound(
    binding: _PathBinding | _MemoryBinding,
    authority: Authority,
    uri: str,
    vfs: Any,
    *,
    timeout: float,
    protected: bool,
    check_same_thread: bool = True,
) -> ProtectedConnection:
    """Own a registration through driver acquisition and checked admission.

    The caller holds the authority operation mutex for this entire scope.
    """
    import sqlcipher3.dbapi2 as sc

    from ._shim import apply_key

    result = object.__new__(ProtectedConnection)
    result._authority, result._binding = authority, binding
    result._pid, result._thread = os.getpid(), threading.get_ident()
    result._same_thread, result._protected = check_same_thread, protected
    result._closed = result._revoked = result._denied = False
    result._active = 0
    result._row_factory, result._vfs = None, vfs
    # Thread policy is enforced at the facade; revocation may close from a
    # different thread only while holding the shared authority operation lock.
    raw = None
    try:
        raw = sc.connect(uri, uri=True, timeout=timeout, check_same_thread=False, cached_statements=0)
        result._raw = raw
        binding.check(newly_created=True)
        if protected:
            apply_key(raw, authority.key)
            _verify_database(result)
        else:
            # Classification never grants a key to the returned connection.
            raw.execute("SELECT count(*) FROM sqlite_master").fetchone()
        authority.register_connection(result)
        _LIVE_CONNECTIONS.add(result)
        raw.set_authorizer(result._authorize)
        raw.set_progress_handler(result._progress, 1000)
        result._check()
        return result
    except BaseException as error:
        if raw is None:
            if vfs is not None:
                vfs.close()
        else:
            result._dispose()
        if _sqlite_busy(error):
            raise
        raise DatabaseRefused("database admission refused; no replacement was created") from None


def _copy_registered_backup(source: ProtectedConnection, destination: Any) -> None:
    """A concrete registry-issued route; no callback or raw-handle export."""
    import sqlcipher3.dbapi2 as sc

    from . import _migrate
    from ._shim import apply_key

    with source._operation():
        destination.check(source)
        if not source._protected or source._raw.in_transaction:
            raise DatabaseRefused("backup requires an idle protected source")
        if source._raw.execute("PRAGMA journal_mode").fetchone() == ("wal",) and _migrate.wal_reset_vulnerable(
            sc.sqlite_version_info
        ):
            raise DatabaseRefused("WAL backup refuses a WAL-reset vulnerable SQLite version")
        registration = None
        uri = f"file:{quote(destination.path.as_posix(), safe='/:')}?mode=rw"
        if os.name == "nt":
            from ._maintenance_windows import require_qualified
            from ._windows_vfs import register_checked_vfs

            require_qualified()
            registration = register_checked_vfs(sc, root=destination.path.parent)
            uri += "&vfs=mordred_checked_v1"
        raw = None
        try:
            raw = _MaintenanceConnection(sc.connect(uri, uri=True))
            apply_key(raw, source._authority.key)
            raw.execute("PRAGMA journal_mode=DELETE")
            source.execute("BEGIN")
            # Reading establishes the exact snapshot copied by sqlite3_backup.
            expected_counts, expected_ids = _migrate._counts(source), _migrate._ids(source)
            schema_sql = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            expected_schema = source.execute(schema_sql).fetchall()

            def check_progress(status: int, remaining: int, total: int) -> None:
                source._check()
                destination.check(source)
                if status & 255 in (5, 6):
                    raise DatabaseRefused("backup destination is busy")

            source._raw.backup(raw._raw, pages=64, progress=check_progress, sleep=0)
            source._check()
            destination.check(source)
            if (
                raw.execute("PRAGMA cipher_integrity_check").fetchall()
                or raw.execute("PRAGMA quick_check").fetchone() != ("ok",)
                or _migrate._counts(raw) != expected_counts
                or _migrate._ids(raw) != expected_ids
                or raw.execute(schema_sql).fetchall() != expected_schema
            ):
                raise DatabaseRefused("backup schema/count authentication failed")
            destination.verification = {
                "counts": expected_counts,
                "ids": list(expected_ids),
                "schema_sha256": _migrate._schema_hash(expected_schema),
            }
        finally:
            if source._pid != os.getpid():
                raise DatabaseRefused("backup SQL cannot unwind inherited handles")
            source._raw.rollback()
            if raw is not None:
                raw.close()
            if registration is not None:
                registration.close()


class _MaintenanceCursor:
    """Internal owned statement; never finalize an inherited SQLite cursor."""

    def __init__(self, owner: _MaintenanceConnection, raw: Any) -> None:
        self._owner, self._raw = owner, raw
        self._closed = False
        owner._cursors.append(self)

    def _check(self) -> None:
        self._owner._check()
        if self._closed:
            raise DatabaseRefused("maintenance cursor is closed")

    def execute(self, sql: str, parameters: Any = ()) -> _MaintenanceCursor:
        self._check()
        _check_sql(sql)
        self._raw.execute(sql, parameters)
        return self

    def fetchone(self) -> Any:
        self._check()
        return self._raw.fetchone()

    def fetchall(self) -> Any:
        self._check()
        return self._raw.fetchall()

    def __iter__(self) -> _MaintenanceCursor:
        self._check()
        return self

    def __next__(self) -> Any:
        self._check()
        return next(self._raw)

    def close(self) -> None:
        if self._closed:
            return
        self._check()
        self._raw.close()
        self._closed = True
        self._owner._cursors.remove(self)


class _MaintenanceConnection:
    """Private same-driver EX SQL owner, sharing runtime's fork quarantine.

    Public maintenance APIs return reports/paths, never this object. Every
    Python cursor is owned before preparation and closed before its connection.
    """

    def __init__(self, raw: Any) -> None:
        self._raw = raw
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._closed = False
        self._cursors: list[_MaintenanceCursor] = []
        _LIVE_MAINTENANCE.add(self)

    def _check(self) -> None:
        if self._pid != os.getpid():
            raise DatabaseRefused("maintenance SQL cannot survive fork")
        if self._closed or self._thread != threading.get_ident():
            raise DatabaseRefused("maintenance SQL owner is closed or belongs to another thread")

    def execute(self, sql: str, parameters: Any = ()) -> _MaintenanceCursor:
        self._check()
        cursor = _MaintenanceCursor(self, self._raw.cursor())
        return cursor.execute(sql, parameters)

    def commit(self) -> None:
        self._check()
        self._raw.commit()

    def rollback(self) -> None:
        self._check()
        self._raw.rollback()

    def backup(self, target: _MaintenanceConnection) -> None:
        self._check()
        if type(target) is not _MaintenanceConnection:
            raise DatabaseRefused("offline backup requires the same owned driver")
        target._check()

        def check_progress(status: int, remaining: int, total: int) -> None:
            self._check()
            target._check()
            if status & 255 in (5, 6):
                raise DatabaseRefused("offline backup is busy")

        self._raw.backup(target._raw, pages=64, progress=check_progress, sleep=0)
        self._check()
        target._check()

    def _install_export_policy(self, target: Path | None, alias: str | None) -> None:
        self._check()
        from ._maintenance_windows import authorizer

        self._raw.enable_load_extension(False)
        self._raw.set_authorizer(authorizer(target, alias))

    def _install_component_policy(self, connection: Any) -> None:
        from ._maintenance import MaintenanceConnection

        self._check()
        if type(connection) is not MaintenanceConnection or connection._owner is not self:
            raise DatabaseRefused("component policy requires its exact checked owner")
        # Key pragmas are private bootstrap statements. Finalize them before
        # component DDL/transactions rather than retaining live C statements.
        for cursor in tuple(self._cursors):
            cursor.close()
        self._raw.enable_load_extension(False)
        self._raw.set_authorizer(connection._authorize)
        self._raw.set_progress_handler(connection._progress, 1000)

    def _clear_component_policy(self) -> None:
        self._check()  # Never touch inherited C handles, even for cleanup.
        self._raw.set_authorizer(None)
        self._raw.set_progress_handler(None, 0)

    def close(self) -> None:
        if self._closed:
            return
        self._check()  # PID refusal precedes locks, cursor finalization and C cleanup.
        self._raw.rollback()
        for cursor in tuple(self._cursors):
            cursor.close()
        self._raw.close()
        self._closed = True
        _LIVE_MAINTENANCE.discard(self)
