"""Recall returns admitted lesson revisions only, within response and session bounds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import lessons, retrieval
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.retrieval import SessionBudget
from tests._activity_lesson_helpers import (
    CORRECTION_TEXT,
    RAW_SECRET,
    admitted,
    corrected_candidate,
    make_store,
    rows,
)

CANDIDATE_SECRET = "ZQX-CAND-4410"


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lessons, "_audit", lambda entry: None)


def _search(store: Any, budget: SessionBudget, **kw: Any) -> retrieval.RecallResponse:
    params: dict[str, Any] = {"task": "export the monthly finance report", "session_id": "s1", "budget": budget}
    params.update(kw)
    return retrieval.search(store, **params)


def test_search_returns_only_admitted_lessons(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, adopted = corrected_candidate(store)
    admitted(store, adopted)
    _, _, candidate = corrected_candidate(store, episode="ep-2", seq0=20, text=f"Never adopted {CANDIDATE_SECRET}")

    response = _search(store, SessionBudget(), site="app.example.com")

    assert response.status == "ok"
    [item] = response.items
    assert (item["lesson_id"], item["revision"]) == (adopted.lesson_id, 1)
    assert item["guidance"] == CORRECTION_TEXT
    assert item["source"] == "mordred-activity admitted lesson"
    assert set(item) == {
        "lesson_id",
        "revision",
        "scope_site",
        "scope_route",
        "applies_when",
        "does_not_apply",
        "check_before_use",
        "guidance",
        "success_measure",
        "adopted_at",
        "source",
    }
    text = response.to_json()
    assert CANDIDATE_SECRET not in text
    assert RAW_SECRET not in text
    assert candidate.lesson_id not in text
    assert retrieval.get(store, candidate.lesson_id, session_id="s1", budget=SessionBudget()).status == "unavailable"


def test_cross_site_query_returns_nothing_and_subdomains_match(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store, site="example.com")
    admitted(store, lesson)

    assert _search(store, SessionBudget(), site="other.test").items == ()
    assert _search(store, SessionBudget(), site="notexample.com").items == ()
    assert len(_search(store, SessionBudget(), site="app.example.com").items) == 1


def test_unrelated_task_without_site_returns_nothing(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store)
    admitted(store, lesson)

    assert _search(store, SessionBudget(), task="book a dentist appointment").items == ()
    assert len(_search(store, SessionBudget(), task="finance report").items) == 1


def test_cjk_task_matches_by_bigrams(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store, task="月次の経理レポートを出力する")
    admitted(store, lesson)

    assert len(_search(store, SessionBudget(), task="経理レポートの出力").items) == 1
    assert _search(store, SessionBudget(), task="歯医者の予約").items == ()


def test_account_filter(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store, task="Export the Finance team report")
    admitted(store, lesson)

    assert len(_search(store, SessionBudget(), site="app.example.com", account="finance").items) == 1
    assert _search(store, SessionBudget(), site="app.example.com", account="marketing").items == ()


def test_suspension_stops_search_and_get(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store)
    admitted(store, lesson)
    assert retrieval.get(store, lesson.lesson_id, session_id="s1", budget=SessionBudget()).status == "ok"

    lessons.suspend(store, lesson.lesson_id, 1, reason="user_contradicted")

    assert _search(store, SessionBudget(), site="app.example.com").items == ()
    response = retrieval.get(store, lesson.lesson_id, 1, session_id="s1", budget=SessionBudget())
    assert (response.status, response.items) == ("unavailable", ())


def test_get_rechecks_excluded_sites(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store)
    admitted(store, lesson)
    config = ActivityConfig.from_mapping({"excluded_sites": ["example.com"]})

    response = retrieval.get(store, lesson.lesson_id, session_id="s1", config=config, budget=SessionBudget())

    assert response.status == "unavailable"
    assert _search(store, SessionBudget(), site="app.example.com", config=config).items == ()


def test_repeat_returns_a_reference_only(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store)
    admitted(store, lesson)
    budget = SessionBudget()

    first = _search(store, budget, site="app.example.com")
    again = retrieval.get(store, lesson.lesson_id, session_id="s1", budget=budget)
    other_session = _search(store, budget, site="app.example.com", session_id="s2")

    assert first.items[0]["guidance"] == CORRECTION_TEXT
    assert again.items == ({"lesson_id": lesson.lesson_id, "revision": 1, "already_shown": True},)
    assert other_session.items[0]["guidance"] == CORRECTION_TEXT


def test_uses_are_recorded_per_full_item(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    _, _, lesson = corrected_candidate(store)
    admitted(store, lesson)
    budget = SessionBudget()

    _search(store, budget, site="app.example.com")
    _search(store, budget, site="app.example.com")

    [use] = rows(store, "SELECT lesson_id, revision, hermes_session_id, task_ref, applied, outcome FROM activity_uses")
    assert use[:3] == (lesson.lesson_id, 1, "s1")
    assert len(use[3]) == 16
    assert use[4:] == (None, None)


def test_response_bounds_drop_lowest_ranked_items(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    for index in range(4):
        _, _, lesson = corrected_candidate(store, episode=f"ep-{index}", seq0=10 * index + 1)
        admitted(store, lesson, now=5000.0 + index)

    three = _search(store, SessionBudget(), site="app.example.com", limit=10)
    assert len(three.items) == 3

    tight = ActivityConfig.from_mapping({"recall_max_bytes": 1500})
    bounded = _search(store, SessionBudget(), site="app.example.com", config=tight)
    assert 0 < len(bounded.items) < 3
    assert len(bounded.to_json().encode("utf-8")) <= 1500

    one_item_tokens = ActivityConfig.from_mapping({"recall_max_tokens": 200})
    assert len(_search(store, SessionBudget(), site="app.example.com", config=one_item_tokens).items) == 1


def test_session_budget_exhaustion(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    for index in range(3):
        _, _, lesson = corrected_candidate(store, episode=f"ep-{index}", seq0=10 * index + 1)
        admitted(store, lesson, now=5000.0 + index)
    config = ActivityConfig.from_mapping({"recall_session_token_budget": 300})
    budget = SessionBudget()

    first = _search(store, budget, site="app.example.com", config=config)
    repeat = _search(store, budget, site="app.example.com", config=config)
    other = next(lesson for lesson in lessons.list_lessons(store) if lesson.lesson_id != first.items[0]["lesson_id"])
    exhausted = retrieval.get(store, other.lesson_id, session_id="s1", config=config, budget=budget)

    assert len(first.items) == 1
    assert repeat.items == ({"lesson_id": first.items[0]["lesson_id"], "revision": 1, "already_shown": True},)
    assert exhausted.status == "budget_exhausted"
    assert exhausted.items == ()
    assert json.loads(exhausted.to_json()) == {"status": "budget_exhausted", "items": []}


def test_session_budget_is_bounded() -> None:
    budget = SessionBudget(max_sessions=2)
    budget.charge("a", 10, [("l", 1)])
    budget.charge("b", 10, [])
    budget.charge("c", 10, [])

    assert budget.snapshot("a") == (0, frozenset())
