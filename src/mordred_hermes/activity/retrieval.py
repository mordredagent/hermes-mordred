"""Recall of **admitted** lesson revisions for ordinary Hermes sessions, with hard bounds.

Nothing here reads raw events, candidates or any other unadmitted state:
every query is filtered on ``state = 'admitted'`` and on the excluded-site set
at call time, so a suspended lesson disappears from search *and* from detail
requests by id. Responses are bounded per call (items, tokens, bytes) and per
Hermes session (a token budget, and a lesson already shown in the session is
returned only as a reference). Every full item returned is recorded in
``activity_uses`` as a retrieval; application and outcome are recorded
separately and never inferred from retrieval.
"""

from __future__ import annotations

import collections
import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from .config import ActivityConfig
from .contracts import site_excluded
from .store import ActivityStore

__all__ = ["SOURCE_LABEL", "RecallResponse", "SessionBudget", "get", "search"]

SOURCE_LABEL: Final = "mordred-activity admitted lesson"
MAX_SESSIONS: Final = 256
PROCESS_KEY: Final = "_process"
_MAX_CANDIDATES: Final = 500
_MAX_QUERY_CHARS: Final = 2000
_MAX_ID_CHARS: Final = 64

_ITEM_COLUMNS: Final = (
    "lesson_id, revision, scope_site, scope_route, applies_when, does_not_apply, check_before_use, guidance, "
    "success_measure, adopted_at, scope_task"
)
_WORD_RE: Final = re.compile(r"[^\W_]+")
#: Words that carry no task meaning, including the deterministic candidate's template words.
_STOPWORDS: Final = frozenset(
    {"and", "the", "for", "with", "from", "into", "that", "this", "then", "than", "when", "task", "like", "operating"}
)
_CJK_RE: Final = re.compile(r"[぀-ヿ㐀-䶿一-鿿豈-﫿가-힯]+")


@dataclass(frozen=True)
class RecallResponse:
    #: ``ok`` | ``budget_exhausted`` | ``unavailable``
    status: str
    items: tuple[dict[str, Any], ...] = ()
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"status": self.status, "items": list(self.items)}
        if self.reason is not None:
            body["reason"] = self.reason
        return body

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass
class _SessionState:
    tokens: int = 0
    shown: set[tuple[str, int]] = field(default_factory=set)


class SessionBudget:
    """In-process per-session recall budget; the oldest session is forgotten past ``max_sessions``."""

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
            return state.tokens, frozenset(state.shown)

    def charge(self, key: str, tokens: int, shown: Iterable[tuple[str, int]]) -> None:
        with self._lock:
            state = self._state(key)
            state.tokens += tokens
            state.shown.update(shown)


_BUDGET = SessionBudget()


def _key(store: ActivityStore, session_id: str | None) -> str:
    # One process can serve several profiles: a session key never crosses stores.
    return f"{store.path}\0{session_id or PROCESS_KEY}"


# --- matching ------------------------------------------------------------------------------------


def _terms(text: str) -> set[str]:
    folded = text.casefold()
    terms = {
        word
        for word in _WORD_RE.findall(folded)
        if not _CJK_RE.fullmatch(word) and (len(word) >= 3 or word.isdigit()) and word not in _STOPWORDS
    }
    for run in _CJK_RE.findall(folded):
        terms.update({run} if len(run) == 1 else {run[i : i + 2] for i in range(len(run) - 1)})
    return terms


def _host(site: str | None) -> str | None:
    if site is None:
        return None
    host = site.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    return host.split("/", 1)[0] or None


def _site_matches(query_site: str, scope_site: str | None) -> bool:
    return scope_site is not None and (query_site == scope_site or query_site.endswith("." + scope_site))


def _item(row: Sequence[Any]) -> dict[str, Any]:
    return {
        "lesson_id": row[0],
        "revision": row[1],
        "scope_site": row[2],
        "scope_route": row[3],
        "applies_when": row[4],
        "does_not_apply": row[5],
        "check_before_use": row[6],
        "guidance": row[7],
        "success_measure": row[8],
        "adopted_at": row[9],
        "source": SOURCE_LABEL,
    }


def _admitted_rows(conn: sqlite3.Connection, excluded_sites: frozenset[str]) -> list[tuple[Any, ...]]:
    rows = conn.execute(
        f"SELECT {_ITEM_COLUMNS} FROM activity_lessons WHERE state = 'admitted' "
        "ORDER BY adopted_at DESC, lesson_id LIMIT ?",
        (_MAX_CANDIDATES,),
    ).fetchall()
    return [tuple(row) for row in rows if not site_excluded(row[2], excluded_sites)]


def _ranked(rows: Sequence[tuple[Any, ...]], task: str, site: str | None, account: str | None) -> list[tuple[Any, ...]]:
    wanted = _terms(task)
    folded_account = account.casefold() if account else None
    scored: list[tuple[int, int, tuple[Any, ...]]] = []
    for index, row in enumerate(rows):
        if site is not None and not _site_matches(site, row[2]):
            continue
        if folded_account and folded_account not in f"{row[10] or ''}\n{row[4] or ''}".casefold():
            continue
        score = len(wanted & _terms(f"{row[10] or ''} {row[4] or ''} {row[7] or ''}"))
        # Without a site scope only a lesson sharing terms with the task is relevant.
        if score or site is not None:
            scored.append((-score, index, row))
    return [row for _, _, row in sorted(scored)]


# --- bounds --------------------------------------------------------------------------------------


def _tokens(entries: Sequence[dict[str, Any]]) -> int:
    return -(-len(json.dumps(entries, ensure_ascii=False)) // 4)


def _bounded(entries: list[dict[str, Any]], config: ActivityConfig, token_cap: int) -> list[dict[str, Any]]:
    """Drop the lowest-ranked entries until the reply fits every bound."""
    kept = entries[: config.recall_max_items]
    while kept and (
        _tokens(kept) > min(config.recall_max_tokens, token_cap)
        or len(RecallResponse("ok", tuple(kept)).to_json().encode("utf-8")) > config.recall_max_bytes
    ):
        kept.pop()
    return kept


def _reference(entry: dict[str, Any]) -> dict[str, Any]:
    return {"lesson_id": entry["lesson_id"], "revision": entry["revision"], "already_shown": True}


def _record_uses(store: ActivityStore, items: Sequence[dict[str, Any]], session_id: str | None, task: str) -> None:
    full = [item for item in items if not item.get("already_shown")]
    if not full:
        return
    now = time.time()
    task_ref = hashlib.sha256(task.encode("utf-8")).hexdigest()[:16]
    with store._transaction() as conn:
        conn.executemany(
            "INSERT INTO activity_uses (use_id, lesson_id, revision, hermes_session_id, task_ref, retrieved_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(str(uuid.uuid4()), i["lesson_id"], i["revision"], session_id or None, task_ref, now) for i in full],
        )


def _respond(
    store: ActivityStore,
    ranked: Sequence[dict[str, Any]],
    *,
    task: str,
    session_id: str | None,
    config: ActivityConfig,
    budget: SessionBudget,
) -> RecallResponse:
    key = _key(store, session_id)
    used, shown = budget.snapshot(key)
    remaining = config.recall_session_token_budget - used
    if remaining <= 0:
        return RecallResponse("budget_exhausted")
    entries = [_reference(e) if (e["lesson_id"], e["revision"]) in shown else e for e in ranked]
    kept = _bounded(entries, config, remaining)
    if entries and not kept:
        return RecallResponse("budget_exhausted")
    _record_uses(store, kept, session_id, task)
    fresh = [(e["lesson_id"], e["revision"]) for e in kept if not e.get("already_shown")]
    budget.charge(key, _tokens(kept) if kept else 0, fresh)
    return RecallResponse("ok", tuple(kept))


# --- public operations ---------------------------------------------------------------------------


def search(
    store: ActivityStore,
    *,
    task: str,
    site: str | None = None,
    account: str | None = None,
    limit: int = 3,
    now: float | None = None,
    session_id: str | None = None,
    config: ActivityConfig | None = None,
    budget: SessionBudget | None = None,
) -> RecallResponse:
    """Admitted lessons matching ``task`` (and ``site``/``account`` when given), bounded."""
    del now  # admitted state is checked at call time; no time-based eligibility yet
    config = config or ActivityConfig()
    if not isinstance(task, str) or not task.strip():
        return RecallResponse("unavailable", reason="invalid_request")
    task = task[:_MAX_QUERY_CHARS]
    with store._transaction(write=False) as conn:
        rows = _admitted_rows(conn, config.excluded_sites)
    ranked = _ranked(rows, task, _host(site), account)[: max(0, min(limit, config.recall_max_items))]
    return _respond(
        store,
        [_item(row) for row in ranked],
        task=task,
        session_id=session_id,
        config=config,
        budget=budget or _BUDGET,
    )


def get(
    store: ActivityStore,
    lesson_id: str,
    revision: int | None = None,
    *,
    session_id: str | None = None,
    config: ActivityConfig | None = None,
    budget: SessionBudget | None = None,
) -> RecallResponse:
    """One admitted revision by id; state and exclusions are rechecked now, never trusted from earlier."""
    config = config or ActivityConfig()
    if not isinstance(lesson_id, str) or not lesson_id or len(lesson_id) > _MAX_ID_CHARS:
        return RecallResponse("unavailable", reason="invalid_request")
    query = f"SELECT {_ITEM_COLUMNS} FROM activity_lessons WHERE lesson_id = ? AND state = 'admitted'"
    params: tuple[Any, ...] = (lesson_id,)
    if revision is not None:
        query += " AND revision = ?"
        params = (lesson_id, revision)
    with store._transaction(write=False) as conn:
        row = conn.execute(query + " ORDER BY revision DESC LIMIT 1", params).fetchone()
    if row is None or site_excluded(row[2], config.excluded_sites):
        return RecallResponse("unavailable", reason="not_admitted")
    return _respond(
        store, [_item(row)], task=f"get:{lesson_id}", session_id=session_id, config=config, budget=budget or _BUDGET
    )
