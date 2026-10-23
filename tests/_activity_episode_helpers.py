"""Shared fixtures for activity store, correction and CLI tests (plain SQLite through the opener seam)."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mordred_hermes.activity.contracts import DEFAULT_EXCLUDED_SITES, NormalizedEvent, normalize_event
from mordred_hermes.activity.store import ActivityStore

PEER = "operator:peer-a"
PRODUCER = "prod-1"
TASK_TEXT = "Export the monthly finance report"
CORRECTION_TEXT = "Use the account switcher to select Finance before opening Reports"
RAW_SECRET = "ZQX-RAW-7731"


def plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def make_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", plain_opener)
    store.initialize(home)
    return store


def raw_event(seq: int, episode: str, *, phase: str, op: str, **overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": seq,
        "episode_id": episode,
        "source": "operator",
        "actor": "agent",
        "observed_at": 1000.0 + seq,
        "phase": phase,
        "action": {"op": op, "target": f"Reports {RAW_SECRET}", "site": "app.example.com", "route": "/reports"},
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
    }
    raw.update(overrides)
    return raw


def normalized(raw: dict[str, Any]) -> NormalizedEvent:
    return normalize_event(raw, excluded_sites=DEFAULT_EXCLUDED_SITES)


@dataclass(frozen=True)
class Episode:
    episode_id: str
    attempt_id: str
    task_start: NormalizedEvent
    attempt: tuple[NormalizedEvent, ...]


def seed_episode(
    store: ActivityStore,
    *,
    episode: str = "ep-1",
    site: str = "app.example.com",
    task: str = TASK_TEXT,
    seq0: int = 1,
) -> Episode:
    attempt_id = f"att-{uuid.uuid4().hex[:8]}"
    action = {"op": "click", "target": f"Reports {RAW_SECRET}", "site": site, "route": "/reports"}
    start = normalized(
        raw_event(
            seq0,
            episode,
            phase="boundary",
            op="task_start",
            actor="human",
            text=task,
            action={"op": "task_start", "site": site},
        )
    )
    attempt = tuple(
        normalized(raw_event(seq0 + offset, episode, phase=phase, op="click", attempt_id=attempt_id, action=action))
        for offset, phase in ((1, "intended"), (2, "dispatched"), (3, "observed"))
    )
    store.append_batch(PEER, PRODUCER, [start, *attempt])
    return Episode(episode, attempt_id, start, attempt)


def rows(store: ActivityStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params)]
