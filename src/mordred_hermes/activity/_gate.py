"""The protection gate: the activity store is opened only through SQLCipher, or not at all.

There is no plaintext fallback anywhere in this package. :func:`open_store`
requires, in order: macOS, no database conversion in flight, the encryption
marker (armed), the SQLCipher shim installed in this process, a resolvable
database key, a keyed connection to this very store, a store file the stdlib
``sqlite3`` cannot read, and a store bound to this profile home. Any failure
raises :class:`ActivityRefused` with a content-free :class:`Refusal` code.

Every check is cheap (a few ``stat`` calls, one cached key lookup, one
read-only header probe) and none is retried: a refusal is reported, the
caller's foreground work continues without activity persistence.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .config import ActivityConfig
    from .store import ActivityStore

__all__ = [
    "ActivityRefused",
    "Refusal",
    "check_protection",
    "keyed_opener",
    "open_store",
    "verify_keyed_connection",
]


@dataclass(frozen=True)
class Refusal:
    #: unsupported_platform | not_armed | unprotected_process | no_key | conversion_pending
    #: | unkeyed_connection | plaintext_store | profile_mismatch | schema_newer | busy
    #: | disk_full | collection_disabled | store_unavailable | conflict
    code: str
    #: Operator-facing and content-free: never a path fragment, URL, target or event text.
    detail: str


class ActivityRefused(Exception):
    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.code)
        self.refusal = refusal

    @property
    def code(self) -> str:
        return self.refusal.code


_DETAILS = {
    "unsupported_platform": "activity storage requires macOS database encryption",
    "conversion_pending": "a database encryption conversion is pending or interrupted",
    "not_armed": "database encryption is not enabled for this Hermes home",
    "unprotected_process": "this process did not load the SQLCipher database layer",
    "no_key": "the database key is not available",
    "unkeyed_connection": "the activity store connection is not keyed",
    "plaintext_store": "the activity store is readable without the database key",
    "profile_mismatch": "the activity store belongs to another Hermes profile",
}


def refusal(code: str) -> Refusal:
    return Refusal(code, _DETAILS.get(code, code.replace("_", " ")))


def _conversion_pending(root: Path) -> bool:
    from ..dbcrypt import _migrate

    return any(
        path.is_file()
        for path in (_migrate.journal_path(root), _migrate.pending_path(root), _migrate.decrypt_pending_path(root))
    )


def _key_resolves() -> bool:
    from .. import dbcrypt

    provider = dbcrypt._PROVIDER
    if provider is None:
        return False
    try:
        return provider() is not None
    except Exception:  # an unopenable vault is "no key", not a crash of the caller
        return False


def check_protection(home: Path) -> Refusal | None:
    """Process- and home-level protection; ``None`` when the store may be opened."""
    if sys.platform != "darwin":
        return refusal("unsupported_platform")
    from .. import dbcrypt
    from ..dbcrypt import _shim

    root = dbcrypt.root_home(home)
    if _conversion_pending(root):
        return refusal("conversion_pending")
    if not dbcrypt.armed(root):
        return refusal("not_armed")
    if not _shim.is_installed():
        return refusal("unprotected_process")
    if not _key_resolves():
        return refusal("no_key")
    return None


def verify_keyed_connection(conn: Any, path: Path) -> Refusal | None:
    """The connection carries the shim's key, and (once written) the file is not plaintext."""
    if getattr(conn, "mordred_key", None) is None:
        return refusal("unkeyed_connection")
    from ..dbcrypt import _monitor

    if path.is_file() and path.stat().st_size > 0 and _monitor.is_plaintext(path):
        return refusal("plaintext_store")
    return None


def _process_sqlite() -> Any:
    """The ``sqlite3`` this process uses now: the SQLCipher replacement once installed."""
    return sys.modules.get("sqlite3", sqlite3)


def keyed_opener(path: Path) -> sqlite3.Connection:
    """A connection to ``path`` through the process ``sqlite3``; refused unless the shim keyed it."""
    from .store import BUSY_TIMEOUT_S

    conn = _process_sqlite().connect(str(path), timeout=BUSY_TIMEOUT_S)
    if getattr(conn, "mordred_key", None) is None:
        conn.close()
        raise ActivityRefused(refusal("unkeyed_connection"))
    return cast(sqlite3.Connection, conn)


_keyed_opener = keyed_opener  # compatibility alias for the pre-imports private name


def _copy_opener(path: Path) -> sqlite3.Connection:
    """A backup source or destination outside the store: keyed by the shim when it is one of ours."""
    from .store import BUSY_TIMEOUT_S

    return cast(sqlite3.Connection, _process_sqlite().connect(str(path), timeout=BUSY_TIMEOUT_S))


def _verify_copy(path: Path) -> Refusal | None:
    from ..dbcrypt import _monitor

    return refusal("plaintext_store") if _monitor.is_plaintext(path) else None


def open_store(home: Path, *, config: ActivityConfig | None = None) -> ActivityStore:
    """Gate, open, verify and bind the store of ``home``; raises :class:`ActivityRefused`.

    ``config`` is accepted so callers that already loaded it can pass it on;
    opening the store does not depend on collection settings (status and
    retention must work while collection is off).
    """
    del config
    found = check_protection(home)
    if found is not None:
        raise ActivityRefused(found)
    from ._paths import store_path
    from .store import ActivityStore

    path = store_path(home)
    from ..dbcrypt import _monitor

    if path.is_file() and path.stat().st_size > 0 and _monitor.is_plaintext(path):
        raise ActivityRefused(refusal("plaintext_store"))
    store = ActivityStore(path, keyed_opener, copy_opener=_copy_opener, verify_copy=_verify_copy)
    store.initialize(Path(os.path.realpath(home)))
    with store.connection() as conn:
        found = verify_keyed_connection(conn, path)
    if found is not None:
        raise ActivityRefused(found)
    return store
