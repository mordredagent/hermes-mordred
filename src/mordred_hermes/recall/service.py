"""Recall for the extension gateway: opens the gated import store per call.

The store is opened afresh for every request, like the Telegram history path:
the protection gate (armed, keyed SQLCipher, no pending conversion) is checked
each time, and nothing is cached across a key change. Every failure becomes a
content-free :class:`RecallError` code; a store held by another connection past
the busy timeout is ``store_busy`` (retry shortly), any other refusal
``import_store_unavailable``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from . import topics
from .derive import selection_words
from .index import RecallIndex, RecallStore

_log = logging.getLogger(__name__)

#: The selection is cut here before it is searched (the extension cuts at 1000).
MAX_TEXT_CHARS = 4000
MAX_LIMIT = 20
MAX_CONTEXT = 5
#: Text one conversation view carries; a longer conversation is cut around the matched part.
MAX_CONVERSATION_CHARS = 400_000
MAX_EVENTS = 10
#: A selection this short (whitespace-collapsed) is first searched as typed, like the search box.
SHORT_SELECTION_CHARS = 24

StoreOpener = Callable[[Path], RecallStore]
_T = TypeVar("_T")


class RecallError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _refused_code(store_code: str) -> str:
    """``store_busy`` while another connection holds the store (e.g. a topics rebuild), a
    passing state worth retrying; every other refusal is ``import_store_unavailable``."""
    return "store_busy" if store_code == "busy" else "import_store_unavailable"


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
            raise RecallError(_refused_code(exc.code)) from None

    def _guarded(self, run: Callable[[RecallIndex], _T]) -> _T:
        from ..imports.store import ImportRefused

        index = self._index()
        try:
            return run(index)
        except ImportRefused as exc:
            _log.info("recall: store refused (%s)", exc.code)
            raise RecallError(_refused_code(exc.code)) from None

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
        nothing) by the share of its nouns each event holds
        (:meth:`.topics.TopicIndex.selection_events`); the result then also
        carries ``derived``.
        """
        cut = text[:MAX_TEXT_CHARS]

        def run(index: RecallIndex) -> dict[str, Any]:
            built = topics.TopicIndex(index.store)
            if not built.built():
                _log.info("recall topics: first build on demand")
                topics.build(index.store)
            hidden = index.suppressed(time.time())
            typed = " ".join(cut.split())
            if not selection or len(typed) <= SHORT_SELECTION_CHARS:
                result = built.events(typed if selection else cut, limit=limit, suppressed=hidden)
            if selection and (len(typed) > SHORT_SELECTION_CHARS or not result.events):
                result = built.selection_events(selection_words(cut), limit=limit, suppressed=hidden)
            if not headlines:
                for event in result.events:
                    event.headline = None
                    for branch in event.branches:
                        branch.summary = None
            counts = topics.line_counts(index.store)
            found = {**result.as_dict(), "headlines": "stored" if headlines else "off", "lines": counts}
            if selection:
                found["derived"] = index.derive(cut).as_dict()
            return found

        return self._guarded(run)

    def recommend(
        self,
        text: str,
        *,
        selection: bool = False,
        on_item: Callable[[dict[str, Any]], None],
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        """Memories for what :meth:`events` searched, handed to ``on_item`` as the local model finds them.

        The words are the first answer's own (``query``), so the memories follow
        the same search; nothing comes back when no local model is configured.
        """
        from . import recommend

        target = recommend.target_from_environ()
        if target is None:
            raise RecallError("recall_agent_unavailable")
        first = self.events(text, limit=3, headlines=False, selection=selection)
        words = str(first.get("query") or "").split() or text.split()

        def run(index: RecallIndex) -> int:
            hidden = index.suppressed(time.time())
            given = 0
            for memory in recommend.Recommender(index.store, target).run(words, suppressed=hidden, cancelled=cancelled):
                on_item(memory)
                given += 1
            return given

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

    def conversation(self, part_uid: str) -> dict[str, Any]:
        """The whole conversation around ``part_uid`` (cut to :data:`MAX_CONVERSATION_CHARS` around it)."""
        return self._guarded(lambda index: index.conversation(part_uid, max_chars=MAX_CONVERSATION_CHARS))

    def dismiss(self, conv_uid: str) -> None:
        self._guarded(lambda index: index.dismiss(conv_uid))

    def restore(self, conv_uid: str) -> None:
        self._guarded(lambda index: index.restore(conv_uid))

    def hidden(self) -> list[dict[str, Any]]:
        return self._guarded(lambda index: index.hidden(time.time()))
