"""Hermes's own capture after the B2 live check (2026-10-22): a correction turn is never a task, a correction in a
new process finds the session's last call in the store, an episode of refused calls is no work to show, and the
two findings fixed before (the session's own episode, the route after a click or Enter) stay fixed."""

from __future__ import annotations

import itertools
import json
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _history_access, capture_hermes, history, hooks_history, tools
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
from mordred_hermes.activity.store import ActivityStore
from tests._activity_capture_helpers import (
    CAPTURING,
    SITE,
    audit_entries,
    call,
    calls,
    capture_home,
    end_turn,
    events,
    nav_result,
    navigate,
    ok,
    stored_text,
    turn,
    write_config,
)

pytestmark = pytest.mark.usefixtures(capture_home.__name__, audit_entries.__name__)

TASK = "open the invoices on shop.example.com"
BODY = "use the account menu instead"
CORRECTION = f"correct: {BODY}"


def _payload(result: str) -> dict[str, Any]:
    _opening, _note, body, _closing = result.split("\n")
    return dict(json.loads(body))


def _lookup(query: str, **args: Any) -> list[dict[str, Any]]:
    return list(_payload(tools.browser_history({"query": query, **args}, session_id="s9"))["episodes"])


def _turn_block(message: str, session: str = "s8") -> str | None:
    block = hooks_history.pre_llm_call(user_message=message, session_id=session, turn_id=f"{session}:t:1")
    return None if block is None else str(block["context"])


def _corrections(store: ActivityStore) -> list[Any]:
    return [event for event in events(store) if event.phase == "correction"]


def _new_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """What ``hermes chat --resume`` / ``-c`` / a restart starts with: no session state, a new producer."""
    monkeypatch.setattr(capture_hermes, "_sessions", type(capture_hermes._sessions)())
    monkeypatch.setattr(capture_hermes, "_PRODUCER_ID", str(uuid.uuid4()))
    monkeypatch.setattr(capture_hermes, "_SEQ", itertools.count(1))


# --- 1. a correction turn's browser calls are not a second task ----------------------------------------------


@pytest.mark.parametrize("message", [CORRECTION, f"訂正\uff1a{BODY}"])
def test_a_correction_turns_calls_join_the_corrected_episode(capture_home, message: str) -> None:
    _home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"), turn_id="s1:t1:aa11")
    turn(message, turn_id="s1:t1:bb22")
    navigate(turn_id="s1:t1:bb22")
    call("browser_click", {"ref": "@e8"}, ok(clicked="@e8"), turn_id="s1:t1:bb22")
    end_turn(turn_id="s1:t1:bb22")

    [record] = store.list_episodes()
    starts = [event for event in events(store) if event.op == "task_start"]
    assert [(event.text, event.actor) for event in starts] == [(TASK, "human")]
    [correction] = _corrections(store)
    assert correction.text == BODY and correction.episode_id == record.episode_id
    assert [event.turn_id for event in calls(store) if event.phase == "dispatched"] == ["s1:t1:aa11"] * 2 + [
        "s1:t1:bb22"
    ] * 2
    assert message not in stored_text(store)

    # The turn-start block of a later session: one episode, its task and the correction, no "correct:" task.
    block = _turn_block(f"continue the invoices on {SITE}")
    assert block is not None and block.count("\n20") == 1  # one episode line (they start with the year)
    assert f'task "{TASK}"' in block and f'user correction: "{BODY}"' in block and "correct:" not in block
    # The lookup tool: the same single episode.
    [found] = _lookup("invoices account menu")
    assert (found["task"], found["corrections"]) == (TASK, [BODY])


def test_a_correction_refused_at_the_turns_end_leaves_its_calls_in_the_corrected_episode(
    capture_home, monkeypatch
) -> None:
    """The correction is written when its turn ends (like a task start); a refused write loses it, never its
    turn's calls, which already joined the corrected episode."""
    _home, store = capture_home
    opened: list[int] = []

    def fourth_open_fails(_home: Path) -> ActivityStore:
        opened.append(1)
        if len(opened) == 4:
            raise OSError("store unavailable")
        return store

    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", fourth_open_fails)
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")  # open 1
    end_turn(turn_id="s1:t1:aa11")  # open 2: the task start
    turn(CORRECTION, turn_id="s1:t1:cc33")
    navigate(turn_id="s1:t1:cc33")  # open 3: joins the corrected episode
    end_turn(turn_id="s1:t1:cc33")  # open 4 fails: the correction is lost

    [record] = store.list_episodes()
    assert [event.op for event in store.events_for_episode(record.episode_id)] == ["navigate", "task_start", "navigate"]
    assert _corrections(store) == []
    assert BODY not in stored_text(store)


def test_a_correction_with_nothing_to_correct_starts_an_episode_without_user_text(capture_home) -> None:
    _home, store = capture_home
    turn(CORRECTION, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    assert [event.op for event in events(store)] == ["navigate"] and _corrections(store) == []
    assert _turn_block(f"{BODY} on {SITE}") is None  # no words of the user: never in the turn-start block
    [found] = _lookup("", site=SITE)
    assert found["task"] is None and found["corrections"] == []


def test_a_correction_is_no_task_start_while_corrections_are_off(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "history_chat_corrections": False})
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    turn(CORRECTION, turn_id="s1:t1:bb22")
    navigate(turn_id="s1:t1:bb22")
    assert [event.text for event in events(store) if event.op == "task_start"] == [TASK]
    assert _corrections(store) == [] and CORRECTION not in stored_text(store)


# --- 2. a correction in a new process finds the session's last call in the store ------------------------------


def test_a_correction_in_a_new_process_links_the_stored_last_call(capture_home, monkeypatch) -> None:
    home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"), turn_id="s1:t1:aa11", call_id="call_last")
    end_turn(turn_id="s1:t1:aa11")
    _new_process(monkeypatch)
    assert capture_hermes.own_episodes(home, "s1", "t1") == frozenset()

    assert turn(CORRECTION, turn_id="s1:t2:bb22") is None
    scroll = [event for event in calls(store) if event.op == "scroll"][-1]
    assert capture_hermes.own_episodes(home, "s1", "t1") == {scroll.episode_id}
    # The correction turn's own calls join the corrected episode; the correction is written when the turn ends.
    navigate(turn_id="s1:t2:bb22")
    end_turn(turn_id="s1:t2:bb22")
    [correction] = _corrections(store)
    assert (correction.attempt_id, correction.episode_id) == (scroll.attempt_id, scroll.episode_id)
    assert (scroll.attempt_id or "").startswith("call-last-")
    assert (correction.site, correction.route, correction.query) == (SITE, "/login", "?next=%2Faccount")
    assert (correction.source, correction.actor, correction.text, correction.turn_id) == (
        "user_correction",
        "human",
        BODY,
        "s1:t2:bb22",
    )
    assert len(store.list_episodes()) == 1
    assert [event.text for event in events(store) if event.op == "task_start"] == [TASK]
    [summary] = history.episodes_for_sites(store, [SITE], excluded_sites=frozenset()).episodes
    assert summary.corrections == (BODY,)


def test_the_newest_stored_call_of_the_session_is_the_one_corrected(capture_home, monkeypatch) -> None:
    _home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    turn("now the receipts on shop.example.com", turn_id="s1:t1:bb22")
    navigate(turn_id="s1:t1:bb22", call_id="call_newest")
    turn("unrelated work", session="s2", turn_id="s2:t:1")
    navigate(session="s2", turn_id="s2:t:1")  # another session, recorded later
    _new_process(monkeypatch)
    turn(CORRECTION, turn_id="s1:t2:cc33")
    end_turn(turn_id="s1:t2:cc33")
    [correction] = _corrections(store)
    newest = next(event for event in calls(store) if (event.attempt_id or "").startswith("call-newest-"))
    assert (correction.attempt_id, correction.episode_id) == (newest.attempt_id, newest.episode_id)


def test_the_stored_lookup_ignores_other_sessions_peers_and_corrections(capture_home, monkeypatch) -> None:
    home, store = capture_home
    turn(TASK, session="s2", turn_id="s2:t:1")
    navigate(session="s2", turn_id="s2:t:1")  # Hermes, another session
    receiver = StoreReceiver(home, config_loader=_history_access.config, store_factory=lambda _home: store)
    forged = {
        "event_id": str(uuid.uuid4()),
        "seq": 1,
        "episode_id": "op-episode",
        "attempt_id": "op-attempt",
        "source": "hermes",  # a paired peer naming Hermes as the source and this session
        "actor": "agent",
        "observed_at": time.time(),
        "phase": "dispatched",
        "action": {"op": "click", "site": SITE, "route": "/x"},
        "session_ref": {"hermes_session_id": "s1"},
    }
    batch = {"schema_version": 1, "producer_id": "prod-op", "producer_kind": "operator", "events": [forged]}
    assert receiver.ingest(PeerPrincipal("operator:peer-a", "operator"), batch)["type"] == "activity_ack"
    _new_process(monkeypatch)
    turn(CORRECTION, turn_id="s1:t2:aa11")
    assert _corrections(store) == []
    assert history.last_hermes_call(store, peer_id="hermes:default", session_id="s1") is None
    assert history.last_hermes_call(store, peer_id="operator:peer-a", session_id="s1") is not None


@pytest.mark.parametrize(
    ("section", "platform"),
    [
        ({**CAPTURING, "history_chat_corrections": False}, "cli"),
        ({**CAPTURING, "history_enabled": False}, "cli"),
        ({**CAPTURING, "excluded_sites": "bank.example"}, "cli"),  # invalid: every history surface is off
        ({"enabled": True}, "cli"),
        (CAPTURING, "telegram"),  # not the user's words: no correction at all
    ],
)
def test_the_stored_lookup_respects_the_switches(capture_home, monkeypatch, section, platform) -> None:
    home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    _new_process(monkeypatch)
    write_config(home, section)
    reads: list[Path] = []
    monkeypatch.setattr(_history_access, "reader", lambda home: reads.append(home) or store)
    turn(CORRECTION, turn_id="s1:t2:bb22", platform=platform)
    assert reads == [] and _corrections(store) == []


@pytest.mark.parametrize(
    ("error", "code"),
    [(ActivityRefused(refusal("not_armed")), "not_armed"), (RuntimeError("boom"), "internal_error")],
)
def test_the_stored_lookup_fails_open(capture_home, monkeypatch, audit_entries, error, code) -> None:
    _home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    end_turn(turn_id="s1:t1:aa11")
    _new_process(monkeypatch)

    def refused(_home: Path) -> ActivityStore:
        raise error

    monkeypatch.setattr(_history_access, "reader", refused)
    assert turn(CORRECTION, turn_id="s1:t2:bb22") is None
    assert _corrections(store) == []
    assert [(entry["reason"], entry["code"]) for entry in audit_entries] == [("activity.history_unavailable", code)]
    navigate(turn_id="s1:t2:bb22")  # the turn's calls still record, without the correction as a task
    end_turn(turn_id="s1:t2:bb22")
    assert [event.text for event in events(store) if event.op == "task_start"] == [TASK]


def test_the_stored_lookup_is_bounded_to_the_newest_episodes(capture_home, monkeypatch) -> None:
    _home, store = capture_home
    turn(TASK, turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    for index in range(2):  # newer episodes of other sessions
        turn("other work", session=f"o{index}", turn_id=f"o{index}:t:1")
        navigate(session=f"o{index}", turn_id=f"o{index}:t:1")
    _new_process(monkeypatch)
    monkeypatch.setattr(history, "LAST_CALL_SCAN_EPISODES", 2)
    turn(CORRECTION, turn_id="s1:t2:bb22")
    assert _corrections(store) == []
    monkeypatch.setattr(history, "LAST_CALL_SCAN_EPISODES", 3)
    turn(CORRECTION, turn_id="s1:t2:cc33")
    end_turn(turn_id="s1:t2:cc33")
    assert len(_corrections(store)) == 1


# --- 3. an episode of refused calls is no work to show -------------------------------------------------------


def _refused_episode(session: str = "s1") -> None:
    turn("open the quarterly report and export it", session=session, turn_id=f"{session}:t:1")
    for tool in ("browser_snapshot", "browser_click", "browser_scroll"):
        call(
            tool,
            {},
            json.dumps({"error": "Blocked by policy"}),
            session=session,
            turn_id=f"{session}:t:1",
            status="blocked",
        )
    end_turn(session=session, turn_id=f"{session}:t:1")


def test_an_episode_of_refused_calls_stays_out_of_the_turn_start_block(capture_home) -> None:
    _home, store = capture_home
    _refused_episode()
    [record] = store.list_episodes()
    assert record.site is None and {event.phase for event in calls(store)} == {"cancelled"}
    assert _turn_block("open the quarterly report again") is None
    # The explicit tools still return it.
    [found] = _lookup("quarterly report")
    assert found["episode_id"] == record.episode_id and found["outcome"] == "cancelled"
    detail = _payload(tools.browser_history_episode({"episode_id": record.episode_id}, session_id="s9"))
    assert detail["episode"]["episode_id"] == record.episode_id


def test_a_failed_call_without_a_site_is_no_work_and_a_successful_one_is(capture_home) -> None:
    _home, store = capture_home
    turn("open the quarterly report and export it", turn_id="s1:t:1")
    call("browser_scroll", {"direction": "down"}, json.dumps({"success": False, "error": "x"}), turn_id="s1:t:1")
    end_turn(turn_id="s1:t:1")
    assert _turn_block("open the quarterly report again") is None
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"), turn_id="s1:t:1")  # ran, on an unknown page
    block = _turn_block("open the quarterly report again", session="s7")
    assert block is not None and '(no site) task "open the quarterly report and export it"' in block
    assert len(store.list_episodes()) == 1


def test_refused_calls_on_a_named_site_are_still_shown(capture_home) -> None:
    _home, _store = capture_home
    turn(TASK, turn_id="s1:t:1")
    call(
        "browser_navigate",
        {"url": f"https://{SITE}/invoices"},
        json.dumps({"error": "Blocked by policy"}),
        turn_id="s1:t:1",
        status="blocked",
    )
    end_turn(turn_id="s1:t:1")
    block = _turn_block(f"the invoices on {SITE} again")
    assert block is not None and f'task "{TASK}" → cancelled' in block
    result = hooks_history.transform_tool_result(
        tool_name="browser_navigate",
        args={"url": f"https://{SITE}/"},
        result=nav_result(f"https://{SITE}/"),
        session_id="s7",
        task_id="t7",
    )
    assert result is not None and TASK in json.loads(result)[hooks_history.RESULT_KEY]


# --- (a) and (b), fixed before the live check's report: they stay fixed --------------------------------------


def test_the_live_check_flow_keeps_no_stale_route_and_no_own_episode(capture_home) -> None:
    """(b) After Enter or a link click the next events have no route until a navigation reports the page; (a) the
    session's own episode never leads its navigation block."""
    _home, store = capture_home
    index = "https://127.0.0.1:8499/index.html"
    snapshot = '- searchbox "Search invoices" [ref=e1]\n- link "Notes" [ref=e2]'
    turn("search for Contoso invoice, then open the notes page", turn_id="s1:t:1")
    call("browser_navigate", {"url": index}, nav_result(index, snapshot=snapshot), turn_id="s1:t:1")
    call("browser_type", {"ref": "@e1", "text": "Contoso invoice"}, ok(element="@e1"), turn_id="s1:t:1")
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"), turn_id="s1:t:1")  # loads /search.html?q=…
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"), turn_id="s1:t:1")
    call("browser_click", {"ref": "@e2"}, ok(clicked="@e2"), turn_id="s1:t:1")  # loads /notes.html
    call("browser_type", {"ref": "@e5", "text": "Call the accountant on Friday"}, ok(element="@e5"), turn_id="s1:t:1")
    assert [(event.op, event.route) for event in calls(store)] == [
        ("navigate", "/index.html"),
        ("type", "/index.html"),
        ("key", "/index.html"),
        ("scroll", None),
        ("click", None),
        ("type", None),
    ]
    out = hooks_history.transform_tool_result(
        tool_name="browser_navigate", args={"url": index}, result=nav_result(index), session_id="s1", task_id="t1"
    )
    assert out is None  # its only episode is its own: no block
