"""At-rest encryption of Hermes's SQLite databases with SQLCipher.

Armed by ``<home>/mordred/db-encryption.marker`` (written once every database
has been converted). When armed, :func:`install` — called from Mordred's
interpreter-startup bootstrap, before Hermes imports ``sqlite3`` — swaps the
``sqlite3`` module for SQLCipher and keys Hermes's own databases with a key
derived from the existing agent-memory key. When not armed nothing changes.

macOS only, like the vault that holds the key. See
``docs/dev/STATE_DB_ENCRYPTION.md``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

from ._key import KeyProvider

MARKER_SUBPATH: Final = ("mordred", "db-encryption.marker")
_PROVIDER: KeyProvider | None = None


def marker_path(home: Path) -> Path:
    return home.joinpath(*MARKER_SUBPATH)


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def armed(home: Path | None = None) -> bool:
    return sys.platform == "darwin" and marker_path(home or _home()).is_file()


def install(*, home: Path | None = None, provider: KeyProvider | None = None) -> bool:
    """Swap ``sqlite3`` for SQLCipher if database encryption is armed. Returns whether it did.

    Raises when armed but SQLCipher cannot be loaded: Hermes's databases are
    encrypted then, and the stdlib module cannot open them.
    """
    from . import _shim

    if _shim.is_installed():
        return True
    base = home or _home()
    if not armed(base):
        return False
    global _PROVIDER
    _PROVIDER = provider or KeyProvider()
    key_provider = _PROVIDER

    def has_key() -> bool:
        return bool(os.environ.get("HERMES_MEMORY_KEY"))

    module = _shim.build_module(key=key_provider, home=lambda: base, has_key=has_key)
    _shim.install_module(module)
    return True


def is_installed() -> bool:
    from . import _shim

    return _shim.is_installed()


__all__ = ["armed", "install", "is_installed", "marker_path"]
