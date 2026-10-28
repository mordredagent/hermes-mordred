"""Make ``import sqlite3`` resolve to SQLCipher and key Hermes's databases.

The whole module is replaced, not just ``connect``: Hermes catches
``sqlite3.DatabaseError`` & co. hundreds of times and subclasses
``sqlite3.Connection``, so the exception and connection types must be
SQLCipher's. Constants SQLCipher's module lacks are filled from the stdlib
module. A connection that is not keyed is plain SQLite, so every database
that is not Hermes's own behaves exactly as before.

Keying (``PRAGMA key`` and friends) is the first thing done on a connection:

- Hermes's own databases (:func:`._policy.in_scope`) are always keyed. Without
  a key they are refused instead of opened — an unkeyed open of an encrypted
  file must never lead Hermes to create a fresh plaintext database.
- Anywhere else, an existing file is keyed only if it *is* one of these
  encrypted databases (a copy Hermes staged elsewhere, e.g. for an export).

``cipher_plaintext_header_size = 112``: Hermes reads fields of the 100-byte
SQLite header straight from the file (format string, page size, the
``application_id`` behind its "file was replaced" guard). The header holds no
row data; 112 is the smallest multiple of 16 that covers it.
"""

from __future__ import annotations

import os
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import parse_qsl, unquote, urlsplit

if TYPE_CHECKING:
    from ._authority import Authority

from ._key import DatabaseKey
from ._policy import in_scope, lexically_in_scope

PLAINTEXT_HEADER_BYTES: Final = 112
SQLITE_MAGIC: Final = b"SQLite format 3\x00"
KEY_UNAVAILABLE: Final = (
    "Mordred: this Hermes database is encrypted and the database key is not available "
    "(the vault could not be opened). Refusing to open it unencrypted."
)
KEY_DOES_NOT_OPEN: Final = (
    "Mordred: the database key does not open this Hermes database (it was encrypted with another key, "
    "or it is a plaintext copy). Refusing to open it; nothing was changed."
)
#: Set on the replacement module so a second install (and the integrity
#: checks) can tell it apart from the stdlib module.
MARKER: Final = "__mordred_sqlcipher__"


def _database_path(database: Any, uri: bool) -> str | None:
    """The file behind a ``connect()`` argument, or ``None`` for in-memory / temp databases."""
    if isinstance(database, bytes):
        database = os.fsdecode(database)
    text = os.fspath(database) if isinstance(database, os.PathLike) else database
    if not isinstance(text, str) or text in ("", ":memory:"):
        return None
    if uri or text.startswith("file:"):
        parts = urlsplit(text)
        if "mode=memory" in parts.query:
            return None
        path = unquote(parts.path or parts.netloc)
        return path or None
    return text


def apply_key(conn: Any, key: DatabaseKey) -> None:
    conn.execute(f"PRAGMA key = \"x'{key.key.hex()}'\"")
    conn.execute(f"PRAGMA cipher_plaintext_header_size = {PLAINTEXT_HEADER_BYTES}")
    conn.execute(f"PRAGMA cipher_salt = \"x'{key.salt.hex()}'\"")


def _is_encrypted_copy(path: str, key: DatabaseKey, sc: Any) -> bool:
    """An existing file outside Hermes's home that is one of our encrypted databases.

    Probed only through ``sc``, the library of every connection this module
    opens, never with a plain ``open()``: Hermes may have the file open
    already, and closing any other descriptor of it would drop every POSIX
    lock this process holds on it (see ``_monitor._own_sqlite``). SQLite
    rejects a file without its header itself.
    """
    try:
        if os.path.getsize(path) == 0:
            return False  # a new file Hermes is about to create, not a copy
        probe = sc.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    except (OSError, sc.Error):
        return False
    try:
        apply_key(probe, key)
        probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except wrong_key_errors(sc):
        return False
    finally:
        probe.close()


def wrong_key_errors(sc: Any) -> tuple[type[BaseException], ...]:
    """What reading an encrypted file with the wrong (or no) key raises.

    Usually ``DatabaseError`` ("SQL logic error", "file is not a database").
    With the plaintext header SQLite sometimes parses the encrypted page as a
    schema and puts its random bytes into the error message, which the module
    fails to decode (``UnicodeDecodeError``); a WAL-mode file can report
    ``SQLITE_NOMEM``, which the module raises as ``MemoryError``.
    """
    return (sc.DatabaseError, UnicodeDecodeError, MemoryError)


def _key_opens(conn: Any, sc: Any) -> bool:
    """Whether a keyed connection to an existing file can read its schema."""
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except sc.OperationalError as exc:
        # Another process is writing: not a key problem.
        return any(word in str(exc).lower() for word in ("locked", "busy"))
    except wrong_key_errors(sc):
        return False


def _keyed_connection_class(sc: Any) -> Any:
    class Connection(sc.Connection):  # type: ignore[misc]
        """Remembers its key, so ``backup()`` into a new database encrypts it the same way.

        SQLCipher cannot back an encrypted database up into a plaintext one
        (``SQL logic error``). Hermes stages its backups outside the home (next
        to the zip of ``hermes backup``), where the destination is a new,
        unkeyed file: it gets the source's key instead of failing.
        """

        mordred_key: DatabaseKey | None = None
        mordred_new_file = False

        def backup(self, target: Any, *args: Any, **kwargs: Any) -> Any:
            key = self.mordred_key
            if key is not None and getattr(target, "mordred_key", 0) is None and target.mordred_new_file:
                apply_key(target, key)
                target.mordred_key = key
            return super().backup(target, *args, **kwargs)

    return Connection


class _Opener:
    """Opens (and keys) connections for the replacement ``connect``."""

    def __init__(self, sc: Any) -> None:
        self._sc = sc
        self._connection = _keyed_connection_class(sc)

    def open(self, database: Any, path: str | None, key: DatabaseKey | None, args: Any, kwargs: Any) -> Any:
        custom_factory = "factory" in kwargs or len(args) >= 5
        new_file = path is not None and (not os.path.exists(path) or os.path.getsize(path) == 0)
        if custom_factory:
            conn = self._sc.connect(database, *args, **kwargs)
        else:
            conn = self._sc.connect(database, *args, factory=self._connection, **kwargs)
        if key is not None:
            apply_key(conn, key)
        if not custom_factory:
            conn.mordred_key = key
            conn.mordred_new_file = new_file
        return conn

    def open_hermes_database(self, database: Any, path: str, key: DatabaseKey, args: Any, kwargs: Any) -> Any:
        existing = os.path.isfile(path) and os.path.getsize(path) > 0
        conn = self.open(database, path, key, args, kwargs)
        if existing and not _key_opens(conn, self._sc):
            # A wrong key otherwise surfaces later as "SQL logic error" or MemoryError
            # inside Hermes, which may take it for corruption.
            conn.close()
            raise self._sc.OperationalError(KEY_DOES_NOT_OPEN)
        return conn


_STDLIB: types.ModuleType | None = None


def stdlib_sqlite3() -> types.ModuleType:
    """The real stdlib ``sqlite3`` (also after the swap), for plaintext checks."""
    global _STDLIB
    if _STDLIB is None:
        current = sys.modules.get("sqlite3")
        if current is not None and not getattr(current, MARKER, False):
            _STDLIB = current
        else:
            import importlib.util

            spec = importlib.util.find_spec("sqlite3")
            if spec is None or spec.loader is None:  # pragma: no cover - CPython always ships it
                raise ImportError("stdlib sqlite3 is unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _STDLIB = module
    return _STDLIB


def build_module(
    *,
    key: Callable[[], DatabaseKey | None] | None = None,
    home: Callable[[], Path] | None = None,
    has_key: Callable[[], bool] | None = None,
    authority: Authority | None = None,
) -> types.ModuleType:
    """A ``sqlite3`` replacement backed by ``sqlcipher3`` (``import`` errors propagate)."""
    import sqlcipher3.dbapi2 as sc

    stdlib = stdlib_sqlite3()
    module = types.ModuleType("sqlite3", stdlib.__doc__)
    module.__dict__.update({k: v for k, v in vars(stdlib).items() if not k.startswith("__")})
    module.__dict__.update({k: v for k, v in vars(sc).items() if not k.startswith("__")})

    if authority is not None:
        from ._connection import ProtectedConnection, ProtectedCursor

        module.Connection = ProtectedConnection  # type: ignore[attr-defined]
        module.Cursor = ProtectedCursor  # type: ignore[attr-defined]
        module.connect = _native_connect(authority)  # type: ignore[attr-defined]
        module.register_adapter = _refuse_registration  # type: ignore[attr-defined]
        module.register_converter = _refuse_registration  # type: ignore[attr-defined]
        module.dbapi2 = module  # type: ignore[attr-defined]
        setattr(module, MARKER, True)
        return module
    if key is None or home is None or has_key is None:
        raise TypeError("legacy shim requires an explicit key, home and has_key seam")
    legacy_key, legacy_home, legacy_has_key = key, home, has_key
    opener = _Opener(sc)

    def connect(database: Any, *args: Any, **kwargs: Any) -> Any:
        path = _database_path(database, bool(kwargs.get("uri", False)))
        if path is not None and in_scope(path, legacy_home()):
            try:
                resolved = legacy_key()
            except Exception as exc:  # the vault could not be opened
                raise sc.OperationalError(f"{KEY_UNAVAILABLE} ({type(exc).__name__})") from exc
            if resolved is None:
                raise sc.OperationalError(KEY_UNAVAILABLE)
            return opener.open_hermes_database(database, path, resolved, args, kwargs)
        if path is not None and legacy_has_key() and os.path.isfile(path):
            resolved = legacy_key()
            if resolved is not None and _is_encrypted_copy(path, resolved, sc):
                return opener.open(database, path, resolved, args, kwargs)
        return opener.open(database, path, None, args, kwargs)

    connect.__doc__ = sc.connect.__doc__
    module.connect = connect  # type: ignore[attr-defined]
    module.dbapi2 = module  # type: ignore[attr-defined]
    setattr(module, MARKER, True)
    return module


def _refuse_registration(*args: Any, **kwargs: Any) -> None:
    from .._database_contracts import DatabaseRefused

    raise DatabaseRefused("custom SQL adaptation callbacks are unsupported in the guarded runtime")


def _native_path(database: Any, *, uri: bool) -> tuple[Path | None, bool]:
    from .._database_contracts import DatabaseRefused

    text = os.fsdecode(os.fspath(database))
    readonly = False
    if text.startswith("file:") or uri:
        parsed = urlsplit(text)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if (
            parsed.scheme != "file"
            or parsed.netloc
            or parsed.fragment
            or len(query) > 1
            or any(k != "mode" or v not in {"ro", "rw", "rwc"} for k, v in query)
        ):
            raise DatabaseRefused("unsafe database URI")
        text = unquote(parsed.path)
        readonly = query == [("mode", "ro")]
        if query == [("mode", "rw")] and not Path(text).exists():
            raise DatabaseRefused("read-write database does not exist")
    if not text or "\x00" in text:
        raise DatabaseRefused("temporary or invalid database names are unsupported")
    path = None if text == ":memory:" else Path(text).absolute()
    return path, readonly


def _native_connect(authority: Authority) -> Callable[..., Any]:
    from .._database_contracts import DatabaseRefused
    from ._connection import ProtectedConnection, _open_unprotected, open_protected

    def connect(database: Any, *args: Any, **kwargs: Any) -> Any:
        authority.check()
        names = (
            "timeout",
            "detect_types",
            "isolation_level",
            "check_same_thread",
            "factory",
            "cached_statements",
            "uri",
        )
        if len(args) > len(names) or set(kwargs).difference(names):
            raise DatabaseRefused("unsupported connection options")
        options = dict(zip(names, args, strict=False))
        if options.keys() & kwargs.keys():
            raise TypeError("duplicate connection argument")
        options.update(kwargs)
        if options.get("factory", ProtectedConnection) is not ProtectedConnection:
            raise DatabaseRefused("custom connection factories cannot bypass authority")
        if options.get("detect_types", 0):
            raise DatabaseRefused("custom SQL converters are unsupported")
        path, readonly = _native_path(database, uri=bool(options.get("uri", False)))
        timeout = float(options.get("timeout", 5.0))
        # Lexical scope must not be erased by resolving an unsafe symlink.
        scoped = path is not None and (in_scope(path, authority.root) or lexically_in_scope(path, authority.root))
        if scoped:
            assert path is not None
            conn = open_protected(path, authority=authority, timeout=timeout, readonly=readonly)
        else:
            conn = _open_unprotected(path, authority=authority, timeout=timeout, readonly=readonly)
        try:
            conn._same_thread = bool(options.get("check_same_thread", True))
            if "isolation_level" in options:
                conn.isolation_level = options["isolation_level"]
            return conn
        except BaseException:
            conn.close()
            raise

    return connect


def is_installed() -> bool:
    return bool(getattr(sys.modules.get("sqlite3"), MARKER, False))


def install_module(module: types.ModuleType) -> None:
    """Put ``module`` in place of ``sqlite3`` / ``sqlite3.dbapi2`` for every later import."""
    sys.modules["sqlite3"] = module
    sys.modules["sqlite3.dbapi2"] = module
