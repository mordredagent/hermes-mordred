"""Names the database dependency inventory recognizes in a Hermes home."""

from __future__ import annotations

from typing import Final

#: Chromium's per-run link under ``browser-profile/chrome`` that may point to a live Unix socket.
CHROMIUM_SOCKET_LINK_NAME: Final = "SingletonSocket"
#: Chromium recreates these per-run links under its profile; none can hold a database.
CHROMIUM_PROCESS_LINK_NAMES: Final = frozenset(
    {"RunningChromeVersion", "SingletonCookie", "SingletonLock", CHROMIUM_SOCKET_LINK_NAME}
)

#: Suffix of SQLite's WAL index file; a read rewrites it, and it holds no committed data.
SQLITE_WAL_INDEX_SUFFIX: Final = "-shm"
