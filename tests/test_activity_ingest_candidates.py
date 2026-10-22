"""Operator corrections arriving through the receiver get their deterministic candidate lesson."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import corrections, ingest, lessons
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
from mordred_hermes.activity.store import ActivityStore

OPERATOR = PeerPrincipal(peer_id="operator:ab12", kind="operator")
SECRET = "ZQX-CORRECTION-4410"


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ingest, "_LAST_RETENTION", {})
    monkeypatch.setattr(lessons, "_audit", lambda entry: None)
    body = {"plugins": {"mordred_activity": {"enabled": True, "collection_enabled": True}}}
    (tmp_path / "config.yaml").write_text(json.dumps(body), encoding="utf-8")


def make_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", sqlite3.connect)
    store.initialize(home)
    return store


def receiver(home: Path) -> StoreReceiver:
    return StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=make_store)


def event(seq: int, phase: str, *, op: str = "click", **overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": seq,
        "episode_id": "ep-1",
        "source": "operator",
        "actor": "agent",
        "observed_at": 1760950000.0 + seq,
        "phase": phase,
        "action": {"op": op, "target": "Reports", "site": "app.example.com", "route": "/reports"},
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
    }
    raw.update(overrides)
    return raw


def task_start(seq: int, **overrides: Any) -> dict[str, Any]:
    return event(
        seq,
        "boundary",
        op="task_start",
        actor="human",
        text="Export the monthly finance report",
        action={"op": "task_start", "site": "app.example.com"},
        **overrides,
    )


def correction(seq: int, attempt: str = "att-1", **overrides: Any) -> dict[str, Any]:
    return event(
        seq, "correction", actor="human", attempt_id=attempt, text=f"Select Finance first {SECRET}", **overrides
    )


def attempt(seq: int, attempt_id: str = "att-1") -> list[dict[str, Any]]:
    return [event(seq, "intended", attempt_id=attempt_id), event(seq + 1, "dispatched", attempt_id=attempt_id)]


def batch(*events: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "producer_id": "prod-1", "producer_kind": "operator", "events": list(events)}


def ack(accepted: int, duplicates: int = 0) -> dict[str, Any]:
    return {
        "type": "activity_ack",
        "status": "ok",
        "accepted": accepted,
        "duplicates": duplicates,
        "episode_revisions": {"ep-1": 1},
    }


def test_an_ingested_correction_yields_one_candidate_and_a_replay_none(tmp_path: Path) -> None:
    sent = batch(task_start(1), *attempt(2), fix := correction(4))

    assert receiver(tmp_path).ingest(OPERATOR, sent) == ack(4)
    assert receiver(tmp_path).ingest(OPERATOR, sent) == ack(0, duplicates=4)

    store = make_store(tmp_path)
    [lesson] = lessons.list_lessons(store)
    assert (lesson.state, lesson.origin, lesson.guidance) == ("candidate", "correction", fix["text"])
    evidence = {row.event_id for row in lessons.evidence(store, lesson.lesson_id, lesson.revision)}
    assert evidence == {raw["event_id"] for raw in sent["events"]}


def test_candidates_are_bounded_per_batch(tmp_path: Path) -> None:
    fixes = [correction(10 + n) for n in range(12)]

    assert receiver(tmp_path).ingest(OPERATOR, batch(task_start(1), *attempt(2), *fixes)) == ack(15)

    assert len(lessons.list_lessons(make_store(tmp_path))) == 10


def test_a_refused_candidate_is_logged_by_code_and_leaves_the_ack(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    reply = receiver(tmp_path).ingest(OPERATOR, batch(*attempt(2), correction(4)))

    assert reply == ack(3)
    assert "task_unknown" in caplog.text
    assert SECRET not in caplog.text
    assert lessons.list_lessons(make_store(tmp_path)) == []


def test_an_unexpected_candidate_failure_leaves_the_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(corrections, "deterministic_candidate", boom)

    assert receiver(tmp_path).ingest(OPERATOR, batch(task_start(1), *attempt(2), correction(4))) == ack(4)
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


def operator_task_then_correction() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # The collector closes its episode at task end; the typed correction opens a fresh one.
    task = [task_start(1), *attempt(2), event(4, "boundary", op="task_end", action={"op": "task_end"})]
    return task, correction(5, episode_id="ep-2")


def test_a_post_task_correction_yields_one_candidate_scoped_to_the_attempt(tmp_path: Path) -> None:
    task, fix = operator_task_then_correction()
    sent = batch(fix)

    assert receiver(tmp_path).ingest(OPERATOR, batch(*task))["accepted"] == 4
    assert receiver(tmp_path).ingest(OPERATOR, sent)["accepted"] == 1
    assert receiver(tmp_path).ingest(OPERATOR, sent)["duplicates"] == 1

    store = make_store(tmp_path)
    [lesson] = lessons.list_lessons(store)
    assert (lesson.scope_site, lesson.scope_route, lesson.guidance) == ("app.example.com", "/reports", fix["text"])
    assert lesson.episode_id == "ep-1"


def test_a_post_task_correction_in_one_flushed_batch_yields_one_candidate(tmp_path: Path) -> None:
    task, fix = operator_task_then_correction()
    sent = batch(*task, fix)

    assert receiver(tmp_path).ingest(OPERATOR, sent)["accepted"] == 5
    assert receiver(tmp_path).ingest(OPERATOR, sent)["duplicates"] == 5

    [lesson] = lessons.list_lessons(make_store(tmp_path))
    assert lesson.scope_site == "app.example.com"
