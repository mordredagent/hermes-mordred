"""Recall for the extension gateway: opens the gated import store per call.

The store is opened afresh for every request, like the Telegram history path:
the protection gate (armed, keyed SQLCipher, no pending conversion) is checked
each time, and nothing is cached across a key change. Every failure becomes a
content-free :class:`RecallError` code.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Sequence
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
#: A selection this short (whitespace-collapsed) is first searched as typed, like the search box.
SHORT_SELECTION_CHARS = 24
#: A longer selection offers this many keywords; the search takes the ones one event holds together.
SELECTION_KEYWORDS = 8
#: A keyword of hiragana alone (もと, つい, まとめ) is a function word that the stop list missed.
_KANA_ONLY = re.compile(r"[\u3041-\u309fー]+")

StoreOpener = Callable[[Path], RecallStore]
_T = TypeVar("_T")


def selection_queries(text: str, covering: Sequence[str], keywords: Sequence[str]) -> list[str]:
    """The word searches to try for a page selection, best first.

    The event search ANDs its words, so a sentence finds nothing: a short
    selection is tried as typed (as the search box would), then the keywords
    one stored event holds together (``covering``), then the rarest keyword alone.
    """
    typed = " ".join(text.split())
    queries: list[str] = []
    for query in (
        typed if typed and len(typed) <= SHORT_SELECTION_CHARS else "",
        " ".join(covering),
        keywords[0] if keywords else "",
    ):
        if query and query not in queries:
            queries.append(query)
    return queries


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

    def events(self, text: str, *, limit: int = 5, headlines: bool = True, selection: bool = False) -> dict[str, Any]:
        """The stored events holding the typed words (:mod:`.topics`); no grouping or model runs here.

        A store never built is built first (once, without lines). ``headlines``
        false leaves the stored lines out. With ``selection`` the text is a page
        selection: searched as typed when short, otherwise (or when that finds
        nothing) by its derived keywords (:func:`selection_queries`); the
        result then also carries ``derived``.
        """
        cut = text[:MAX_TEXT_CHARS]

        def run(index: RecallIndex) -> dict[str, Any]:
            built = topics.TopicIndex(index.store)
            if not built.built():
                _log.info("recall topics: first build on demand")
                topics.build(index.store)
            hidden = index.suppressed(time.time())
            derived = index.derive(cut) if selection else None
            if derived is None:
                queries = [cut]
            else:
                offered = index.keywords(cut, limit=SELECTION_KEYWORDS)
                keywords = [word for word in offered if not _KANA_ONLY.fullmatch(word)]
                queries = selection_queries(cut, built.covering_words(keywords), keywords)
            result = built.events(queries[0] if queries else "", limit=limit, suppressed=hidden)
            for query in queries[1:]:
                if result.events:
                    break
                result = built.events(query, limit=limit, suppressed=hidden)
            if not headlines:
                for event in result.events:
                    event.headline = None
                    for branch in event.branches:
                        branch.summary = None
            counts = topics.line_counts(index.store)
            found = {**result.as_dict(), "headlines": "stored" if headlines else "off", "lines": counts}
            if derived is not None:
                found["derived"] = derived.as_dict()
            return found

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
