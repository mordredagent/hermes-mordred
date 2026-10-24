"""Shared fixtures for the Hermes-side browser history tests (plain SQLite through the opener seam)."""

from __future__ import annotations

import json
import time
import types
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _capture_audit, _history_access, hooks_history
from mordred_hermes.activity.contracts import NormalizedEvent
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.privacy_check import _runtime
from tests._activity_episode_helpers import PEER, PRODUCER, make_store, normalized

TASK = "open the invoices page"
CORRECTION = "invoices are under the account menu, not search"
TITLE = "Billing overview"
PAGE_TEXT = "PAGE-TEXT-MARKER the invoice table lists October"
TYPED = "typed words marker"
QUERY_VALUE = "qvalue123"

ENABLED: dict[str, Any] = {"enabled": True}


class Seq:
    """Monotonic producer sequence numbers across episodes of one test."""

    def __init__(self, start: int = 0) -> None:
        self.value = start

    def __call__(self) -> int:
        self.value += 1
        return self.value


def event(seq: int, episode: str, *, at: float, phase: str, action: dict[str, Any], **extra: Any) -> NormalizedEvent:
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": seq,
        "episode_id": episode,
        "source": "operator",
        "actor": "agent",
        "observed_at": at,
        "phase": phase,
        "action": action,
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
    }
    raw.update(extra)
    return normalized(raw)


@dataclass(frozen=True)
class Seeded:
    episode_id: str
    site: str


def seed_episode(
    store: ActivityStore,
    seq: Seq,
    *,
    episode: str,
    site: str = "example.com",
    task: str | None = TASK,
    correction: str | None = CORRECTION,
    title: str | None = TITLE,
    page_text: str | None = PAGE_TEXT,
    typed: str | None = TYPED,
    age_s: float = 3600.0,
    routes: tuple[str, ...] = ("/account", f"/account/billing?q={QUERY_VALUE}"),
    outcome: str = "claimed_success",
    peer: str = PEER,
) -> Seeded:
    """One finished episode: task start, navigations with titles and page text, a typed value, a correction."""
    at = time.time() - age_s
    events: list[NormalizedEvent] = []
    if task is not None:
        events.append(
            event(
                seq(),
                episode,
                at=at,
                phase="boundary",
                actor="human",
                text=task,
                action={"op": "task_start", "site": site},
            )
        )
    for index, route in enumerate(routes):
        events.append(
            event(
                seq(),
                episode,
                at=at + 1 + index,
                phase="observed",
                attempt_id=f"{episode}-nav{index}",
                action={"op": "navigate", "site": site, "route": route},
                page_title=title,
                page_text=page_text,
            )
        )
    if typed is not None:
        events.append(
            event(
                seq(),
                episode,
                at=at + 20,
                phase="dispatched",
                attempt_id=f"{episode}-type",
                action={"op": "type", "site": site, "route": routes[-1], "args": {"field_kind": "text"}},
                text=typed,
            )
        )
    if correction is not None:
        events.append(
            event(
                seq(),
                episode,
                at=at + 30,
                phase="correction",
                source="user_correction",
                actor="human",
                text=correction,
                action={"op": "other", "site": site},
            )
        )
    events.append(
        event(
            seq(),
            episode,
            at=at + 40,
            phase="boundary",
            action={"op": "task_end", "site": site},
            result={"status": outcome},
        )
    )
    store.append_batch(peer, PRODUCER, events)
    return Seeded(episode, site)


def write_config(home: Path, section: dict[str, Any]) -> None:
    (home / "config.yaml").write_text(json.dumps({"plugins": {"mordred_activity": section}}), encoding="utf-8")


@pytest.fixture
def history_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, ActivityStore]]:
    """A profile home with a plain-SQLite store; the gated reader is replaced by that store."""
    home = tmp_path / "home"
    home.mkdir()
    store = make_store(home)
    monkeypatch.setattr(_history_access, "home", lambda: home)
    monkeypatch.setattr(_history_access, "reader", lambda _home: store)
    yield home, store


@pytest.fixture
def audit_entries(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Fresh per-process state: budget, config cache, host memory, audit dedupe; audit entries captured."""
    monkeypatch.setattr(_history_access, "BUDGET", type(_history_access.BUDGET)())
    monkeypatch.setattr(_history_access, "_configs", {})
    monkeypatch.setattr(_history_access, "_retry", {})
    monkeypatch.setattr(hooks_history, "_last_hosts", type(hooks_history._last_hosts)())
    monkeypatch.setattr(_capture_audit, "_HISTORY_EMITTED", set())
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(_runtime, "ensure_state", lambda: types.SimpleNamespace(audit=object()))
    monkeypatch.setattr(
        _capture_audit, "safe_audit_append", lambda audit, entry, *, logger: entries.append(dict(entry))
    )
    return entries


def navigate_result(url: str, *, title: str = "Live title", success: bool = True) -> str:
    if not success:
        return json.dumps({"success": False, "error": "Navigation failed"})
    return json.dumps({"success": True, "url": url, "title": title, "snapshot": "- link [ref=e1]"}, ensure_ascii=False)
