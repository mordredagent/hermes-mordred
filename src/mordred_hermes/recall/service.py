"""Recall for the extension gateway: opens the gated import store per call.

The store is opened afresh for every request, like the Telegram history path:
the protection gate (armed, keyed SQLCipher, no pending conversion) is checked
each time, and nothing is cached across a key change. Every failure becomes a
content-free :class:`RecallError` code.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from . import topics
from .index import RecallIndex, RecallStore

_log = logging.getLogger(__name__)

#: The selection is cut here before it is searched (the extension cuts at 1000).
MAX_TEXT_CHARS = 4000
MAX_LIMIT = 20
MAX_CONTEXT = 5
MAX_EVENTS = 10

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

    def _store(self) -> RecallStore:
        home = self._home
        if home is None:
            from .._home import hermes_home

            home = hermes_home()
        return self._opener(home)

    def _index(self) -> RecallIndex:
        from ..imports.store import ImportRefused

        try:
            return RecallIndex(self._store())
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

    def query(self, text: str, *, limit: int = 8, words: bool = False) -> dict[str, Any]:
        """A selection's recall, or with ``words`` the parts containing every typed word."""
        cut = text[:MAX_TEXT_CHARS]
        if words:
            result = self._guarded(lambda index: index.search_words(cut, limit=limit))
        else:
            result = self._guarded(lambda index: index.search(cut, limit=limit))
        return result.as_dict(cut)

    def events(self, text: str, *, limit: int = 5, headlines: bool = True) -> dict[str, Any]:
        """The stored events holding the typed words (:mod:`.topics`); no grouping or model runs here.

        A store never built is built first (once, without lines). ``headlines``
        false leaves the stored lines out.
        """
        cut = text[:MAX_TEXT_CHARS]

        def run(index: RecallIndex) -> dict[str, Any]:
            built = topics.TopicIndex(index.store)
            if not built.built():
                _log.info("recall topics: first build on demand")
                topics.build(index.store)
            result = built.events(cut, limit=limit, suppressed=index.suppressed(time.time()))
            if not headlines:
                for event in result.events:
                    event.headline = None
                    for branch in event.branches:
                        branch.summary = None
            counts = topics.line_counts(index.store)
            return {**result.as_dict(), "headlines": "stored" if headlines else "off", "lines": counts}

        return self._guarded(run)

    def topics_updater(self, *, interval_s: float = 60.0) -> topics.TopicsUpdater:
        """A background updater over this service's store, with the configured local model (if any)."""
        from ..extension.telegram.llm import LlmConfigError
        from .headlines import HeadlineWriter, target_from_env

        try:
            target = target_from_env()
        except LlmConfigError as exc:
            _log.info("recall lines off (%s)", exc.code)
            target = None
        writer = HeadlineWriter(target) if target is not None else None
        return topics.TopicsUpdater(self._store, writer, interval_s=interval_s)

    def open(self, part_uid: str, *, before: int = 2, after: int = 2) -> list[dict[str, Any]]:
        return self._guarded(lambda index: index.open(part_uid, before=before, after=after))

    def dismiss(self, conv_uid: str) -> None:
        self._guarded(lambda index: index.dismiss(conv_uid))
