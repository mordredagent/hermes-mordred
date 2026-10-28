"""Activity admission through the existing shared database runtime.

Passive checks inspect capability and metadata only. Actual opens reuse the
runtime provider's authenticated authority and Task 6 guarded SQLCipher; no
ambient key, independent unwrap, raw database probe or plaintext fallback.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ..dbcrypt._authority import Authority
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
    "unsupported_platform": "activity storage requires qualified native database encryption",
    "conversion_pending": "a database encryption conversion is pending or interrupted",
    "not_armed": "database encryption is not enabled for this Hermes home",
    "unprotected_process": "this process did not load the SQLCipher database layer",
    "no_key": "the database key is not available",
    "unkeyed_connection": "the activity store connection is not keyed",
    "plaintext_store": "the activity store is readable without the database key",
    "profile_mismatch": "the activity store belongs to another Hermes profile",
    "backup_wal_unsupported": "the backup is in WAL mode; restore takes the rollback-journal backups Mordred writes",
}


def refusal(code: str) -> Refusal:
    return Refusal(code, _DETAILS.get(code, code.replace("_", " ")))


def _conversion_pending(root: Path) -> bool:
    for name in ("db-encryption.journal.json", "db-encryption.pending", "db-decryption.pending"):
        try:
            (root / "mordred" / name).lstat()
        except FileNotFoundError:
            continue
        return True
    return False


def check_protection(home: Path) -> Refusal | None:
    """Passive eligibility only; ``None`` never authenticates a later SQL open."""
    from .. import dbcrypt
    from ..dbcrypt import _capability, _shim

    status = _capability.database_status(home)
    if status.capability == "unavailable":
        return refusal("unsupported_platform")
    if status.reason != "native database authority has not been authenticated":
        return refusal("store_unavailable")
    root = home.parent.parent if home.parent.name == "profiles" else home
    try:
        if _conversion_pending(root):
            return refusal("conversion_pending")
        if not (root / "mordred" / "db-encryption.marker").is_file():
            return refusal("not_armed")
    except OSError:
        return refusal("store_unavailable")
    if not _shim.is_installed():
        return refusal("unprotected_process")
    provider = dbcrypt._PROVIDER
    if provider is None or not provider.runtime_native:
        return refusal("no_key")
    current = provider.current_authority
    if current is not None and current.terminal:
        return refusal("no_key")
    return None


def runtime_authority(home: Path, *, acquire: bool = True) -> Authority:
    """Reuse the installed provider; never construct, retarget or replace it."""
    from .. import dbcrypt
    from ..keyvault._database_authority import resolve_database_domain

    provider = dbcrypt._PROVIDER
    if provider is None or not provider.runtime_native:
        raise ActivityRefused(refusal("no_key"))
    try:
        authority = provider.authority if acquire else provider.current_authority
        if authority is None:
            raise ActivityRefused(refusal("no_key"))
        domain = resolve_database_domain(home)
        if domain.root != authority.root:
            raise ActivityRefused(refusal("profile_mismatch"))
        authority.check()
        return authority
    except ActivityRefused:
        raise
    except Exception:
        raise ActivityRefused(refusal("no_key")) from None


def verify_keyed_connection(conn: Any, path: Path) -> Refusal | None:
    """Recognize the guarded SQL facade; its admission already authenticated the schema."""
    from ..dbcrypt._connection import ProtectedConnection

    del path
    if not isinstance(conn, ProtectedConnection) or conn.mordred_key is None:
        return refusal("unkeyed_connection")
    return None


def _open_guarded(
    path: Path, *, authority: Authority, timeout: float, readonly: bool = False, check_same_thread: bool = True
) -> sqlite3.Connection:
    from .._database_contracts import DatabaseRefused
    from ..dbcrypt._connection import open_protected

    try:
        conn = open_protected(
            path, authority=authority, timeout=timeout, readonly=readonly, check_same_thread=check_same_thread
        )
        try:
            conn.execute("PRAGMA temp_store = MEMORY")
        except BaseException:
            conn.close()
            raise
        return cast(sqlite3.Connection, conn)
    except DatabaseRefused:
        raise ActivityRefused(refusal("store_unavailable")) from None


def keyed_opener(path: Path, *, timeout: float | None = None) -> sqlite3.Connection:
    """Open only the profile's protected activity destination through shared authority."""
    from .store import BUSY_TIMEOUT_S

    # The activity layout is fixed; classification remains separate from actual
    # Task 6 handle admission. No Path return value authorizes a later raw open.
    home = path.parent.parent.parent
    from ..imports._protected_destination import checked_store_destination

    checked_store_destination(path, home=home)
    return _open_guarded(
        path, authority=runtime_authority(home), timeout=BUSY_TIMEOUT_S if timeout is None else timeout
    )


_keyed_opener = keyed_opener


def open_store(
    home: Path, *, config: ActivityConfig | None = None, busy_timeout_s: float | None = None
) -> ActivityStore:
    """Authenticate before directory creation, then initialize through guarded SQL."""
    del config
    found = check_protection(home)
    if found is not None:
        raise ActivityRefused(found)
    authority = runtime_authority(home)
    from .._database_contracts import DatabaseRefused
    from ._paths import store_path
    from .store import BUSY_TIMEOUT_S, ActivityStore

    try:
        with authority.operation():
            path = store_path(home)
    except (OSError, DatabaseRefused):
        raise ActivityRefused(refusal("store_unavailable")) from None
    timeout = BUSY_TIMEOUT_S if busy_timeout_s is None else busy_timeout_s

    def opener(target: Path) -> sqlite3.Connection:
        return _open_guarded(target, authority=authority, timeout=timeout)

    store = ActivityStore(path, opener, busy_timeout_s=timeout, authority=authority)
    store.initialize(Path(os.path.realpath(home)))
    return store
