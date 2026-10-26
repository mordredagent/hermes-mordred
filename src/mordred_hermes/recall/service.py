"""Recall for the extension gateway: opens the gated import store per call.

The store is opened afresh for every request, like the Telegram history path:
the protection gate (armed, keyed SQLCipher, no pending conversion) is checked
each time, and nothing is cached across a key change. Every failure becomes a
content-free :class:`RecallError` code.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from .index import RecallIndex, RecallStore

_log = logging.getLogger(__name__)

#: The selection is cut here before it is searched (the extension cuts at 1000).
MAX_TEXT_CHARS = 4000
MAX_LIMIT = 20
MAX_CONTEXT = 5

StoreOpener = Callable[[Path], RecallStore]
_T = TypeVar("_T")


class RecallError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _default_opener(home: Path) -> RecallStore:
    from ..imports.store import open_import_store

    return open_import_store(home)


class RecallService:
    def __init__(self, *, opener: StoreOpener | None = None, home: Path | None = None) -> None:
        self._opener = opener or _default_opener
        self._home = home

    def _index(self) -> RecallIndex:
        from ..imports.store import ImportRefused

        home = self._home
        if home is None:
            from .._home import hermes_home

            home = hermes_home()
        try:
            return RecallIndex(self._opener(home))
        except ImportRefused as exc:
            _log.info("recall: import store not opened (%s)", exc.code)
            raise RecallError("import_store_unavailable") from None

    def _guarded(self, run: Callable[[RecallIndex], _T]) -> _T:
        from ..imports.store import ImportRefused

        index = self._index()
        try:
            return run(index)
        except ImportRefused as exc:
            _log.info("recall: store refused (%s)", exc.code)
            raise RecallError("import_store_unavailable") from None

    def query(self, text: str, *, limit: int = 8) -> dict[str, Any]:
        cut = text[:MAX_TEXT_CHARS]
        result = self._guarded(lambda index: index.search(cut, limit=limit))
        return result.as_dict(cut)

    def open(self, part_uid: str, *, before: int = 2, after: int = 2) -> list[dict[str, Any]]:
        return self._guarded(lambda index: index.open(part_uid, before=before, after=after))

    def dismiss(self, conv_uid: str) -> None:
        self._guarded(lambda index: index.dismiss(conv_uid))
