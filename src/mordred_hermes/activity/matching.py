"""Term matching and a per-session budget for Hermes-side use of the browser history.

Both helpers come from the removed lesson recall (2026-10-22); the history
surfaces (:mod:`.history`, :mod:`.hooks_history`, :mod:`.tools`) use them:

- :func:`terms` folds a text into match terms: words of at least three
  characters (or all digits) outside a small stopword list, and each CJK run
  as overlapping character bigrams (a single CJK character stays one term), so
  scripts without spaces still match;
- :class:`SessionBudget` is an in-process, bounded per-session ledger of
  characters injected and items already shown (``(episode id, revision)``
  pairs), so an episode is shown once per session until it changes, and the
  oldest session is forgotten past ``max_sessions``.

Nothing here opens the store or reads configuration.
"""

from __future__ import annotations

import collections
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final

__all__ = ["MAX_SESSIONS", "SessionBudget", "terms"]

MAX_SESSIONS: Final = 256

_WORD_RE: Final = re.compile(r"[^\W_]+")
#: Words that carry no task meaning.
_STOPWORDS: Final = frozenset(
    {"and", "the", "for", "with", "from", "into", "that", "this", "then", "than", "when", "task", "like", "operating"}
)
_CJK_RE: Final = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]+")


def terms(text: str) -> set[str]:
    """Case-folded match terms of ``text``; CJK runs become character bigrams."""
    folded = text.casefold()
    found = {
        word
        for word in _WORD_RE.findall(folded)
        if not _CJK_RE.fullmatch(word) and (len(word) >= 3 or word.isdigit()) and word not in _STOPWORDS
    }
    for run in _CJK_RE.findall(folded):
        found.update({run} if len(run) == 1 else {run[i : i + 2] for i in range(len(run) - 1)})
    return found


@dataclass
class _SessionState:
    chars: int = 0
    shown: set[tuple[str, int]] = field(default_factory=set)


class SessionBudget:
    """In-process per-session budget; the oldest session is forgotten past ``max_sessions``.

    ``chars`` counts what was injected into the session; ``shown`` holds the
    ``(item id, revision)`` pairs already given to it.
    """

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._max = max_sessions
        self._sessions: collections.OrderedDict[str, _SessionState] = collections.OrderedDict()
        self._lock = threading.Lock()

    def _state(self, key: str) -> _SessionState:
        state = self._sessions.get(key)
        if state is None:
            state = self._sessions[key] = _SessionState()
            while len(self._sessions) > self._max:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(key)
        return state

    def snapshot(self, key: str) -> tuple[int, frozenset[tuple[str, int]]]:
        with self._lock:
            state = self._state(key)
            return state.chars, frozenset(state.shown)

    def charge(self, key: str, chars: int, shown: Iterable[tuple[str, int]]) -> None:
        with self._lock:
            state = self._state(key)
            state.chars += chars
            state.shown.update(shown)
