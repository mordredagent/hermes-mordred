"""Which SQLite files get the database key.

Hermes keeps its databases in its home (``state.db``, ``shared-state.db``,
``projects.db``, ``response_store.db``, ``memory_store.db``, ``kanban.db``,
``cron/executions.db``, ``telemetry/shared_metrics/metrics.sqlite3``, ...) and
in each profile home under ``profiles/<name>/``. Every such file is encrypted;
new ones are created encrypted. Directories that hold *other* programs' files
(Hermes's own install, toolchains, MCP servers, skills' scripts, browser data)
are left alone, and nothing outside the Hermes home is in scope (the agent
opens Chrome's cookie store and the user's project databases too).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

#: Top-level directories of a Hermes (or profile) home whose files belong to
#: other programs, or to Mordred's own encrypted stores.
DENY_DIRS: Final = frozenset(
    {
        "installs",
        "tools",
        "hermes-agent",
        "hermes-setup",
        "bootstrap-cache",
        "cache",
        "source-checks",
        "node_modules",
        "mcp-installs",
        "desktop",
        "desktop-plugins",
        "skills",
        "vault",
        "mordred",
        "logs",
    }
)

_DB_SUFFIXES: Final = (".db", ".sqlite", ".sqlite3")
#: SQLite's own sidecars and Hermes's lock files are never opened as databases.
_NOT_DATABASES: Final = ("-wal", "-shm", "-journal", ".lock")


def looks_like_database_name(name: str) -> bool:
    """``x.db`` / ``x.sqlite[3]`` and the copies Hermes writes beside them (``state.db.pre-update-….bak``)."""
    lowered = name.casefold()
    if lowered.endswith(_NOT_DATABASES):
        return False
    return lowered.endswith(_DB_SUFFIXES) or any(f"{suffix}." in lowered for suffix in _DB_SUFFIXES)


def _relative_to_a_home(path: Path, home: Path) -> tuple[str, ...] | None:
    try:
        parts = path.relative_to(home).parts
    except ValueError:
        return None
    if len(parts) >= 3 and parts[0] == "profiles":
        return parts[2:]  # inside a profile home: same layout as the main home
    return parts


def _homes(home: Path) -> list[Path]:
    """``home`` and, for a profile home (``<root>/profiles/<name>``), the root home too."""
    resolved = Path(os.path.realpath(home))
    if resolved.parent.name == "profiles":
        return [resolved.parent.parent, resolved]
    return [resolved]


def in_scope(path: str | os.PathLike[str], home: Path) -> bool:
    """Whether ``path`` is one of Hermes's own databases (and must be keyed)."""
    resolved = Path(os.path.realpath(path))
    for base in _homes(home):
        parts = _relative_to_a_home(resolved, base)
        if not parts or not looks_like_database_name(parts[-1]):
            continue
        return not (len(parts) > 1 and parts[0] in DENY_DIRS)
    return False
