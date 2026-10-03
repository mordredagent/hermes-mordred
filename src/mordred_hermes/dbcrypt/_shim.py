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
from typing import Any, Final
from urllib.parse import unquote, urlsplit

from ._key import DatabaseKey
from ._policy import in_scope

PLAINTEXT_HEADER_BYTES: Final = 112
SQLITE_MAGIC: Final = b"SQLite format 3\x00"
KEY_UNAVAILABLE: Final = (
    "Mordred: this Hermes database is encrypted and the database key is not available "
    "(the vault could not be opened). Refusing to open it unencrypted."
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
    """An existing file outside Hermes's home that is one of our encrypted databases."""
    try:
        with open(path, "rb") as handle:
            if handle.read(len(SQLITE_MAGIC)) != SQLITE_MAGIC:
                return False
    except OSError:
        return False
    probe = sc.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        apply_key(probe, key)
        probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except (sc.DatabaseError, UnicodeDecodeError):  # a wrong key can surface as a decode error
        return False
    finally:
        probe.close()


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
    key: Callable[[], DatabaseKey | None],
    home: Callable[[], Path],
    has_key: Callable[[], bool],
) -> types.ModuleType:
    """A ``sqlite3`` replacement backed by ``sqlcipher3`` (``import`` errors propagate)."""
    import sqlcipher3.dbapi2 as sc

    stdlib = stdlib_sqlite3()
    module = types.ModuleType("sqlite3", stdlib.__doc__)
    module.__dict__.update({k: v for k, v in vars(stdlib).items() if not k.startswith("__")})
    module.__dict__.update({k: v for k, v in vars(sc).items() if not k.startswith("__")})

    def connect(database: Any, *args: Any, **kwargs: Any) -> Any:
        path = _database_path(database, bool(kwargs.get("uri", False)))
        if path is not None and in_scope(path, home()):
            try:
                resolved = key()
            except Exception as exc:  # the vault could not be opened
                raise sc.OperationalError(f"{KEY_UNAVAILABLE} ({type(exc).__name__})") from exc
            if resolved is None:
                raise sc.OperationalError(KEY_UNAVAILABLE)
            conn = sc.connect(database, *args, **kwargs)
            apply_key(conn, resolved)
            return conn
        if path is not None and has_key() and os.path.isfile(path):
            resolved = key()
            if resolved is not None and _is_encrypted_copy(path, resolved, sc):
                conn = sc.connect(database, *args, **kwargs)
                apply_key(conn, resolved)
                return conn
        return sc.connect(database, *args, **kwargs)

    connect.__doc__ = sc.connect.__doc__
    module.connect = connect  # type: ignore[attr-defined]
    module.dbapi2 = module  # type: ignore[attr-defined]
    setattr(module, MARKER, True)
    return module


def is_installed() -> bool:
    return bool(getattr(sys.modules.get("sqlite3"), MARKER, False))


def install_module(module: types.ModuleType) -> None:
    """Put ``module`` in place of ``sqlite3`` / ``sqlite3.dbapi2`` for every later import."""
    sys.modules["sqlite3"] = module
    sys.modules["sqlite3.dbapi2"] = module
