"""At-rest encryption of Hermes's SQLite databases with SQLCipher.

Armed by ``<home>/mordred/db-encryption.marker`` (written once every database
has been converted). When armed, :func:`install` — called from Mordred's
interpreter-startup bootstrap, before Hermes imports ``sqlite3`` — swaps the
``sqlite3`` module for SQLCipher and keys Hermes's own databases with a key
derived from the existing agent-memory key. When not armed nothing changes.

The implementation and the process-wide key-provider state (``_PROVIDER``)
live in :mod:`._runtime`; this package module only re-exports the public API.
See ``docs/dev/STATE_DB_ENCRYPTION.md``.
"""

from __future__ import annotations

from ._capability import (
    DatabaseStatus,
    database_status,
    diagnose_database,
)
from ._runtime import (
    arm,
    armed,
    install,
    is_installed,
    marker_path,
    register,
    root_home,
)

__all__ = [
    "DatabaseStatus",
    "arm",
    "armed",
    "database_status",
    "diagnose_database",
    "install",
    "is_installed",
    "marker_path",
    "register",
    "root_home",
]
