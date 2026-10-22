"""Shared fixtures for the conditional-review suites: a plain-SQLite store, events and fake LLM facades."""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.contracts import DEFAULT_EXCLUDED_SITES, NormalizedEvent, canonical_digest, normalize_event
from mordred_hermes.activity.store import ActivityStore

PEER = "operator:peer-a"
SITE = "example.com"


def plain_opener(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def make_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", plain_opener)
    store.initialize(home)
    return store


def rows(store: ActivityStore, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    with store.connection() as conn:
        return [tuple(row) for row in conn.execute(sql, params)]


_seq = iter(range(1, 1_000_000))


def event(
    episode: str, *, phase: str = "dispatched", op: str = "click", route: str = "/r", **extra: Any
) -> NormalizedEvent:
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": next(_seq),
        "episode_id": episode,
        "source": extra.pop("source", "operator"),
        "actor": "agent",
        "observed_at": 1000.0,
        "phase": phase,
        "action": {"op": op, "target": "Reports", "site": extra.pop("site", SITE), "route": route},
        "result": {"status": extra.pop("status", "unknown")},
        "quality": {"coverage": "selected_tab"},
        "session_ref": {"run_id": "run-1"},
    }
    raw.update(extra)
    return normalize_event(raw, excluded_sites=frozenset())


def verified(item: NormalizedEvent, status: str) -> NormalizedEvent:
    """A receiver-side verification result (collectors cannot claim one)."""
    changed = replace(item, result_status=status, exclusions=())
    return replace(changed, content_digest=canonical_digest(changed))


def append(store: ActivityStore, *events: NormalizedEvent) -> None:
    store.append_batch(PEER, "producer-1", list(events))


def correction_episode(store: ActivityStore, episode: str = "ep-corr") -> list[NormalizedEvent]:
    items = [
        event(episode),
        event(episode, phase="correction", op="other", source="user_correction", text="use the account switcher"),
    ]
    append(store, *items)
    return items


def completed_episode(store: ActivityStore, episode: str, steps: tuple[tuple[str, str], ...]) -> None:
    items = [event(episode, op=op, route=route) for op, route in steps]
    items.append(event(episode, phase="boundary", op="task_end", route="/done", status="claimed_success"))
    append(store, *items)


def config(**overrides: Any) -> ActivityConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "collection_enabled": True,
        "review_provider": "openrouter",
        "review_model": "vendor/model-a",
        "excluded_sites": DEFAULT_EXCLUDED_SITES,
    }
    values.update(overrides)
    return ActivityConfig(**values)


def answer(
    evidence: list[str],
    *,
    decision: str = "candidate",
    site: str | None = SITE,
    guidance: str = "Open the account switcher and confirm the visible account before opening reports.",
    **extra: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "decision": decision,
        "explanation": "The user corrected the account before reports.",
        "lesson": {
            "applies_when": "Opening reports on example.com",
            "does_not_apply": "Other sites",
            "check_before_use": "The account indicator is visible",
            "guidance": guidance,
            "success_measure": "No account correction is needed",
        },
        "scope": {"site": site, "route": "/r"},
        "evidence_ids": evidence,
        "verification_proposal": "Read the account indicator on the reports page.",
    }
    payload.update(extra)
    return payload


def result(
    parsed: Any = None,
    *,
    text: str | None = None,
    provider: str = "openrouter",
    model: str = "vendor/model-a-2026",
    tokens: tuple[int, int] = (812, 140),
    cost: float | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        text=json.dumps(parsed) if text is None else text,
        parsed=parsed,
        provider=provider,
        model=model,
        usage=SimpleNamespace(input_tokens=tokens[0], output_tokens=tokens[1], total_tokens=sum(tokens), cost_usd=cost),
    )


class LegacyLlm:
    """The Hermes 0.19.0 facade shape: no ``task`` parameter."""

    def __init__(self, reply: Any = None, error: BaseException | None = None) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def _answer(self, kwargs: dict[str, Any]) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.reply

    def complete_structured(
        self,
        *,
        instructions: str,
        input: Any,
        json_schema: Any = None,
        json_mode: bool = False,
        schema_name: str | None = None,
        system_prompt: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
        agent_id: str | None = None,
        profile: str | None = None,
        purpose: str | None = None,
    ) -> Any:
        return self._answer(dict(locals(), self=None))


class TaskLlm(LegacyLlm):
    """The newer facade shape: ``task=`` selects a registered auxiliary task."""

    def complete_structured(  # type: ignore[override]
        self,
        *,
        instructions: str,
        input: Any,
        json_schema: Any = None,
        json_mode: bool = False,
        schema_name: str | None = None,
        system_prompt: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
        agent_id: str | None = None,
        profile: str | None = None,
        purpose: str | None = None,
        task: str | None = None,
    ) -> Any:
        return self._answer(dict(locals(), self=None))


class FakeLessons:
    """Stands in for ``activity.lessons`` so these suites do not depend on it; writes a real lesson row."""

    def __init__(self, *, joins_transaction: bool = True, fail: BaseException | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = fail
        self.module = ModuleType("mordred_hermes.activity.lessons")
        if joins_transaction:
            self.module.create_candidate_in = self.create_candidate_in  # type: ignore[attr-defined]
        self.module.create_candidate = self.create_candidate  # type: ignore[attr-defined]

    def _insert(self, conn: sqlite3.Connection, kwargs: dict[str, Any]) -> SimpleNamespace:
        self.calls.append(kwargs)
        if self.fail is not None:
            raise self.fail
        lesson_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO activity_lessons (lesson_id, revision, state, origin, episode_id, created_at) "
            "VALUES (?, 1, 'candidate', ?, ?, 0)",
            (lesson_id, kwargs["origin"], kwargs["episode_id"]),
        )
        return SimpleNamespace(lesson_id=lesson_id, revision=1)

    def create_candidate_in(self, conn: sqlite3.Connection, **kwargs: Any) -> SimpleNamespace:
        return self._insert(conn, kwargs)

    def create_candidate(self, store: ActivityStore, **kwargs: Any) -> SimpleNamespace:
        with store.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            created = self._insert(conn, kwargs)
            conn.execute("COMMIT")
        return created

    def install(self, monkeypatch: pytest.MonkeyPatch) -> FakeLessons:
        import mordred_hermes.activity as package

        monkeypatch.setitem(sys.modules, "mordred_hermes.activity.lessons", self.module)
        monkeypatch.setattr(package, "lessons", self.module, raising=False)
        return self
