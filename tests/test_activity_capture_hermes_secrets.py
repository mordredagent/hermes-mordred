"""Hermes's own capture never stores a password the user named in a message (B2 live check 2026-10-22, D1).

The live message named the password before its keyword ("... and Hunter2-fake-pw as the password ..."); its task
start was stored verbatim and re-sent to the model by every later session. Two layers keep such a value out:
the free-text redactor reads value-first phrasings (``contracts.redact_text_secrets``), and, independent of any
phrasing, a value Hermes typed into a secret field (or one that looks like a secret) is replaced by ``redacted`` in
the turn's task start and correction, which are written only when the turn ends.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

import pytest

from mordred_hermes.activity import _history_access, capture_hermes, contracts, hooks_history, tools
from mordred_hermes.activity.ingest import StoreReceiver
from mordred_hermes.activity.store import ActivityStore
from tests._activity_capture_helpers import (
    CAPTURING,
    audit_entries,
    call,
    calls,
    capture_home,
    end_turn,
    events,
    nav_result,
    ok,
    turn,
    write_config,
)

pytestmark = pytest.mark.usefixtures(capture_home.__name__, audit_entries.__name__)

LOGIN = "http://127.0.0.1:8499/login.html"
LOGIN_SNAPSHOT = "\n".join(
    [
        '- heading "Sign in to Acme" [ref=e1] [level=1]',
        '- textbox "Username" [ref=e2]',
        '- textbox "Password" [ref=e3]',
        '- button "Sign in" [ref=e4]',
        '- textbox "Search" [ref=e5]',
    ]
)
#: The B2 live check's message (scenario 2), stored verbatim in its task start before the fix.
LIVE_MESSAGE = (
    "Open http://127.0.0.1:8499/login.html, type demo-user as the username and Hunter2-fake-pw as the password, "
    "then log in."
)
PASSWORD = "Hunter2-fake-pw"
T1, T2 = "s1:t1:aa11", "s1:t1:bb22"


def _navigate(turn_id: str = T1) -> None:
    call(
        "browser_navigate",
        {"url": LOGIN},
        nav_result(LOGIN, title="Sign in to Acme", snapshot=LOGIN_SNAPSHOT),
        turn_id=turn_id,
    )


def _login(message: str, password: str, *, turn_id: str = T1, end: bool = True) -> None:
    """The live check's turn: open the login page, type the user name and the password, press Enter."""
    turn(message, turn_id=turn_id)
    _navigate(turn_id)
    call("browser_type", {"ref": "@e2", "text": "demo-user"}, ok(element="@e2"), turn_id=turn_id)
    call("browser_type", {"ref": "@e3", "text": password}, ok(element="@e3"), turn_id=turn_id)
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"), turn_id=turn_id)
    if end:
        end_turn(turn_id=turn_id, message=message)


def _starts(store: ActivityStore) -> list[contracts.NormalizedEvent]:
    return [event for event in events(store) if event.op == "task_start"]


def _corrections(store: ActivityStore) -> list[contracts.NormalizedEvent]:
    return [event for event in events(store) if event.phase == "correction"]


def _whole_store(store: ActivityStore) -> str:
    """Every row of every table of the store."""
    with sqlite3.connect(store.path) as conn:
        tables = [str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        rows = {table: conn.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
    return json.dumps(rows, ensure_ascii=False, default=str)


def _shown_to_later_sessions(store: ActivityStore) -> list[str]:
    """What later sessions get from the history: the turn-start block, the navigation block and both tools."""
    block = hooks_history.pre_llm_call(
        user_message="What did you do in the browser on 127.0.0.1 earlier?", session_id="s5", turn_id="s5:t:1"
    )
    navigation = hooks_history.transform_tool_result(
        tool_name="browser_navigate",
        args={"url": LOGIN},
        result=nav_result(LOGIN, title="Sign in to Acme", snapshot=LOGIN_SNAPSHOT),
        session_id="s6",
        task_id="t6",
    )
    lookup = tools.browser_history({"query": "", "site": "127.0.0.1"}, session_id="s7", task_id="t7")
    [record] = store.list_episodes()
    detail = tools.browser_history_episode({"episode_id": record.episode_id}, session_id="s7", task_id="t7")
    assert block is not None and navigation is not None
    shown = [str(block["context"]), navigation, lookup, detail]
    assert all("as the password" in text for text in shown), shown  # every surface shows the task
    return shown


# --- the live repro, through the real capture path -----------------------------------------------------------


def test_the_live_message_never_reaches_the_store_or_a_later_session(capture_home) -> None:
    _home, store = capture_home
    _login(LIVE_MESSAGE, PASSWORD)

    [start] = _starts(store)
    assert start.text == (
        "Open http://127.0.0.1:8499/login.html, type demo-user as the username and redacted as the password, "
        "then log in."
    )
    assert "text_secrets_redacted" in start.exclusions
    username, password = [event for event in calls(store) if event.op == "type"]
    assert (username.text, password.text) == ("demo-user", None)
    dump = _whole_store(store)
    assert PASSWORD not in dump and "hunter2" not in dump.lower()
    for shown in _shown_to_later_sessions(store):
        assert PASSWORD not in shown and "hunter2" not in shown.lower()
        assert "demo-user as the username" in shown


# --- the value-based scrub, independent of phrasing ------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "password", "stored"),
    [
        (
            "Sign in at http://127.0.0.1:8499/login.html with demo-user / Swordfish-77, please.",
            "Swordfish-77",
            "Sign in at http://127.0.0.1:8499/login.html with demo-user / redacted, please.",
        ),
        (
            "log in on 127.0.0.1 as demo-user, then swordfish",
            "swordfish",
            "log in on 127.0.0.1 as demo-user, then redacted",
        ),
        (
            "127.0.0.1 に demo-user と kumo-2026 でログイン",
            "kumo-2026",
            "127.0.0.1 に demo-user と redacted でログイン",
        ),
        ("log in on 127.0.0.1 with SWORDFISH-77", "swordfish-77", "log in on 127.0.0.1 with redacted"),
    ],
)
def test_a_value_typed_into_a_secret_field_is_scrubbed_from_the_task_start(
    capture_home, message: str, password: str, stored: str
) -> None:
    _home, store = capture_home
    assert contracts.redact_text_secrets(message) == (message, False)  # no phrasing rule finds it
    _login(message, password)

    [start] = _starts(store)
    assert start.text == stored and "text_secrets_redacted" in start.exclusions
    assert password.lower() not in _whole_store(store).lower()


def test_a_secret_looking_value_typed_into_any_field_is_scrubbed(capture_home) -> None:
    _home, store = capture_home
    secret = "Xk9#mQ2$vL7pR4wZ"
    turn(f"search 127.0.0.1 for {secret}")
    _navigate()
    call("browser_type", {"ref": "@e5", "text": secret}, ok(element="@e5"))  # a text field
    end_turn()

    [start] = _starts(store)
    assert start.text == "search 127.0.0.1 for redacted"
    [typed] = [event for event in calls(store) if event.op == "type"]
    assert typed.text is None and "typed_text_dropped" in typed.exclusions
    assert secret not in _whole_store(store)


def test_a_value_shorter_than_four_characters_is_not_scrubbed(capture_home) -> None:
    _home, store = capture_home
    _login("open 127.0.0.1 and sign in with abc", "abc")
    [start] = _starts(store)
    assert start.text == "open 127.0.0.1 and sign in with abc"
    assert "text_secrets_redacted" not in start.exclusions


def test_text_kept_in_an_ordinary_field_is_not_scrubbed(capture_home) -> None:
    _home, store = capture_home
    turn("search 127.0.0.1 for Contoso invoices")
    _navigate()
    call("browser_type", {"ref": "@e5", "text": "Contoso invoices"}, ok(element="@e5"))
    end_turn()
    [start] = _starts(store)
    assert start.text == "search 127.0.0.1 for Contoso invoices"


# --- a turn's text is written when the turn ends ---------------------------------------------------------------


def test_the_task_start_waits_for_the_end_of_its_turn(capture_home) -> None:
    _home, store = capture_home
    message = "Sign in at http://127.0.0.1:8499/login.html with demo-user / Swordfish-77, please."
    _login(message, "Swordfish-77", end=False)

    assert [event.op for event in events(store)] == ["navigate", "type", "type", "key"]
    assert "demo-user /" not in _whole_store(store)
    end_turn(turn_id="s1:t1:other")  # another turn's end writes nothing
    assert _starts(store) == []

    end_turn()
    [start] = _starts(store)
    nav = calls(store)[0]
    assert (start.episode_id, start.turn_id, start.actor) == (nav.episode_id, T1, "human")
    assert start.observed_at < nav.observed_at  # its time is the turn's start
    end_turn()  # written once
    assert len(_starts(store)) == 1


def test_a_turn_that_ends_without_post_llm_call_is_written_by_the_next_turn(capture_home) -> None:
    """An interrupted turn gets no ``post_llm_call``; the session's next turn writes its text."""
    _home, store = capture_home
    _login("Sign in on 127.0.0.1 with demo-user / Swordfish-77", "Swordfish-77", end=False)
    turn("thanks", turn_id=T2)
    [start] = _starts(store)
    assert start.text == "Sign in on 127.0.0.1 with demo-user / redacted"


def test_hermes_0_13_ends_a_turn_without_ids(capture_home) -> None:
    """hermes-agent 0.13.0 passes neither ``task_id`` nor ``turn_id`` to ``pre_llm_call`` / ``post_llm_call``."""
    _home, store = capture_home
    capture_hermes.pre_llm_call(session_id="s1", user_message="log in on 127.0.0.1 with Swordfish-77", platform="cli")
    capture_hermes.post_tool_call(
        tool_name="browser_navigate",
        args={"url": LOGIN},
        result=nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT),
        session_id="s1",
        tool_call_id="call_1",
    )
    capture_hermes.post_tool_call(
        tool_name="browser_type",
        args={"ref": "@e3", "text": "Swordfish-77"},
        result=ok(element="@e3"),
        session_id="s1",
        tool_call_id="call_2",
    )
    assert capture_hermes.post_llm_call(session_id="s1", assistant_response="done") is None
    [start] = _starts(store)
    assert start.text == "log in on 127.0.0.1 with redacted" and start.turn_id is None


def test_a_turn_ended_while_capture_is_off_writes_nothing(capture_home) -> None:
    home, store = capture_home
    _login("Sign in on 127.0.0.1 with demo-user / Swordfish-77", "Swordfish-77", end=False)
    write_config(home, {**CAPTURING, "history_capture_hermes": False})
    end_turn()
    assert _starts(store) == []
    write_config(home, CAPTURING)
    end_turn()  # the held text was dropped, not kept for later
    assert _starts(store) == []


# --- corrections --------------------------------------------------------------------------------------------


def test_a_correction_is_scrubbed_of_a_value_typed_later_in_its_turn(capture_home) -> None:
    _home, store = capture_home
    turn("open the login page on 127.0.0.1", turn_id=T1)
    _navigate(T1)
    end_turn(turn_id=T1)

    turn("correct: wrong account, use Winter-2027-x instead", turn_id=T2)
    assert _corrections(store) == []  # held until the turn ends
    call("browser_type", {"ref": "@e3", "text": "Winter-2027-x"}, ok(element="@e3"), turn_id=T2)
    end_turn(turn_id=T2)

    [correction] = _corrections(store)
    assert correction.text == "wrong account, use redacted instead"
    assert "text_secrets_redacted" in correction.exclusions
    assert correction.episode_id == calls(store)[0].episode_id
    assert "Winter-2027-x" not in _whole_store(store)


def test_a_correction_is_scrubbed_of_a_value_typed_in_an_earlier_turn(capture_home) -> None:
    _home, store = capture_home
    _login("log in on 127.0.0.1 as demo-user", "Spring-2026-y")
    turn("correct: Spring-2026-y was the old one", turn_id=T2)
    end_turn(turn_id=T2)
    [correction] = _corrections(store)
    assert correction.text == "redacted was the old one"
    assert "Spring-2026-y" not in _whole_store(store)


def test_with_capture_off_a_correction_drops_every_value_typed_in_its_turn(capture_home) -> None:
    """Without capture the field cannot be classified: every value typed in the correction's turn is scrubbed."""
    home, store = capture_home
    turn("open the login page on 127.0.0.1", turn_id=T1)
    _navigate(T1)
    end_turn(turn_id=T1)
    write_config(home, {**CAPTURING, "history_capture_hermes": False})

    turn("correct: try the account Fabrikam-2", turn_id=T2)
    call("browser_type", {"ref": "@e2", "text": "Fabrikam-2"}, ok(element="@e2"), turn_id=T2)
    end_turn(turn_id=T2)

    [correction] = _corrections(store)
    assert correction.text == "try the account redacted"
    assert [event.op for event in calls(store) if event.phase == "dispatched"] == ["navigate"]  # no type


# --- rows stored before the fix ---------------------------------------------------------------------------------


def test_a_task_start_stored_before_the_fix_is_redacted_on_every_surface(capture_home, monkeypatch) -> None:
    home, store = capture_home
    receiver = StoreReceiver(home, config_loader=_history_access.config, store_factory=lambda _home: store)
    base = {"episode_id": "ep-old", "source": "hermes", "quality": {"coverage": "selected_tab"}}
    old = [
        {
            **base,
            "event_id": str(uuid.uuid4()),
            "seq": 1,
            "actor": "human",
            "observed_at": time.time() - 120,
            "phase": "boundary",
            "action": {"op": "task_start"},
            "text": LIVE_MESSAGE,
            "session_ref": {"hermes_session_id": "s-old"},
        },
        {
            **base,
            "event_id": str(uuid.uuid4()),
            "seq": 2,
            "actor": "agent",
            "observed_at": time.time() - 100,
            "phase": "dispatched",
            "attempt_id": "call-old-1",
            "action": {"op": "navigate", "site": "127.0.0.1", "route": "/login.html"},
            "result": {"status": "claimed_success"},
            "page_title": "Sign in to Acme",
            "session_ref": {"hermes_session_id": "s-old"},
        },
    ]
    batch: dict[str, Any] = {"schema_version": 1, "producer_id": "prod-old", "producer_kind": "hermes", "events": old}
    with monkeypatch.context() as patch:  # the receiver before value-first redaction existed
        patch.setattr(contracts, "redact_text_secrets", lambda text: (text, False))
        assert receiver.ingest(capture_hermes.principal(home), batch)["type"] == "activity_ack"
    assert PASSWORD in _whole_store(store)  # the old receiver really stored it

    for shown in _shown_to_later_sessions(store):
        assert PASSWORD not in shown
        assert "redacted as the password" in shown
