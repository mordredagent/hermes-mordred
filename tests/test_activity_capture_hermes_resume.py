"""Hermes's own capture after ``hermes chat --resume`` (B2 final live check 2026-10-22, M1 and M2).

A resumed process (``--resume``, ``-c``, a restart) has no snapshot yet, while the transcript hands Hermes the old
page's refs. Live, a keyword-less password typed into the transcript's password-field ref was stored as typed text
(``other``, M2). Now typed text and the scrub share one classification: a ref the session's most recent snapshot in
this process does not list is ``sensitive``, so the value is withheld and scrubbed from the user's words. The
transcript is never read for field kinds, so an ordinary value typed before the first snapshot is withheld and
scrubbed too (M1, an accepted trade-off).
"""

from __future__ import annotations

import itertools
import json
import sqlite3
import uuid
from typing import Any

import pytest

from mordred_hermes.activity import capture_hermes
from mordred_hermes.activity.contracts import NormalizedEvent
from mordred_hermes.activity.store import ActivityStore
from tests._activity_capture_helpers import (
    audit_entries,
    call,
    calls,
    capture_home,
    end_turn,
    events,
    failed,
    nav_result,
    ok,
    turn,
)

pytestmark = pytest.mark.usefixtures(capture_home.__name__, audit_entries.__name__)

LOGIN = "http://127.0.0.1:8499/login.html"
NOTES = "http://127.0.0.1:8499/notes.html"
LOGIN_SNAPSHOT = "\n".join(
    [
        '- heading "Sign in to Acme" [ref=e1] [level=1]',
        '- textbox "Username" [ref=e2]',
        '- textbox "Password" [ref=e3]',
        '- button "Log in" [ref=e4]',
        '- searchbox "Search invoices" [ref=e5]',
    ]
)
FIRST_MESSAGE = f"Open {LOGIN} and type demo-user into the Username box. Do not log in yet."
#: The live repro's keyword-less password (x1r) and an ordinary value (s6r2).
PASSWORD = "Kiwi7-fake-pw"
PASSWORD_MESSAGE = f"Now put {PASSWORD} into the second field and press Log in."
SEARCH_MESSAGE = "Search for Northwind in the Search invoices box."
SEARCH_SCRUBBED = "Search for redacted in the Search invoices box."
T1, T2 = "s1:t1:aa11", "s1:t1:bb22"


def _new_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """What ``hermes chat --resume`` / ``-c`` / a restart starts with: no session state, a new producer."""
    monkeypatch.setattr(capture_hermes, "_sessions", type(capture_hermes._sessions)())
    monkeypatch.setattr(capture_hermes, "_PRODUCER_ID", str(uuid.uuid4()))
    monkeypatch.setattr(capture_hermes, "_SEQ", itertools.count(1))


def _first_process() -> list[dict[str, Any]]:
    """Process A of the live repro (x1): open the login page, type the user name, exit. Returns its transcript as
    hermes-agent passes it to the resumed process (``conversation_history``), the login page's snapshot included."""
    turn(FIRST_MESSAGE, turn_id=T1)
    result = nav_result(LOGIN, title="Sign in to Acme", snapshot=LOGIN_SNAPSHOT)
    call("browser_navigate", {"url": LOGIN}, result, turn_id=T1)
    call("browser_type", {"ref": "@e2", "text": "demo-user"}, ok(element="@e2"), turn_id=T1)
    end_turn(turn_id=T1, message=FIRST_MESSAGE)
    tool_call = {"id": "call_nav1", "function": {"name": "browser_navigate", "arguments": "{}"}}
    return [
        {"role": "user", "content": FIRST_MESSAGE},
        {"role": "assistant", "content": "", "tool_calls": [tool_call]},
        {"role": "tool", "tool_call_id": "call_nav1", "tool_name": "browser_navigate", "content": result},
        {"role": "assistant", "content": "Done."},
    ]


def _resume(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    """Process B: ``--resume`` with process A's transcript, which the capture never reads for field kinds."""
    history = _first_process()
    _new_process(monkeypatch)
    turn(message, turn_id=T2, conversation_history=history, is_first_turn=False)


def _type_unknown_ref(ref: str, text: str) -> None:
    """Hermes types a transcript ref in a fresh browser: ``Unknown ref`` (live x1r and s6r)."""
    call("browser_type", {"ref": ref, "text": text}, failed(f"Unknown ref: {ref[1:]}"), turn_id=T2, status="error")


def _typed(store: ActivityStore) -> NormalizedEvent:
    return [event for event in calls(store) if event.op == "type"][-1]


def _held_text(store: ActivityStore) -> NormalizedEvent:
    """The last task start or correction: the user's words of the last turn."""
    return [event for event in events(store) if event.op == "task_start" or event.phase == "correction"][-1]


def _whole_store(store: ActivityStore) -> str:
    with sqlite3.connect(store.path) as conn:
        tables = [str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        rows = {table: conn.execute(f"SELECT * FROM {table}").fetchall() for table in tables}
    return json.dumps(rows, ensure_ascii=False, default=str)


def _assert_kept(store: ActivityStore, typed_value: str, message: str) -> None:
    typed = _typed(store)
    assert json.loads(typed.args_json)["field_kind"] == "text"
    assert typed.text == typed_value and "typed_text_dropped" not in typed.exclusions
    held = _held_text(store)
    assert held.text == message and "text_secrets_redacted" not in held.exclusions


def _assert_withheld(store: ActivityStore, typed_value: str, scrubbed_message: str) -> None:
    typed = _typed(store)
    assert json.loads(typed.args_json)["field_kind"] == "sensitive"
    assert typed.text is None and {"sensitive_field", "typed_text_dropped"} <= set(typed.exclusions)
    held = _held_text(store)
    assert held.text == scrubbed_message and "text_secrets_redacted" in held.exclusions
    assert typed_value not in _whole_store(store)


# --- after a resume, a value typed before the process's first snapshot is withheld and scrubbed -----------------


@pytest.mark.parametrize(
    ("ref", "value", "message", "scrubbed"),
    [
        # M2: the transcript's password field, a keyword-less password.
        ("@e3", PASSWORD, PASSWORD_MESSAGE, "Now put redacted into the second field and press Log in."),
        # M1, the accepted trade-off: the transcript's search box, an ordinary value.
        ("@e5", "Northwind", SEARCH_MESSAGE, SEARCH_SCRUBBED),
        # M1 live repro 1: a correction typed into the transcript's user name box.
        (
            "@e2",
            "Contoso Ltd",
            "correct: the user name should have been Contoso Ltd, with the suffix",
            "the user name should have been redacted, with the suffix",
        ),
        # A ref the transcript never listed.
        ("@e9", "Northwind", SEARCH_MESSAGE, SEARCH_SCRUBBED),
    ],
)
def test_after_resume_a_value_typed_before_any_snapshot_is_withheld_and_scrubbed(
    capture_home, monkeypatch, ref: str, value: str, message: str, scrubbed: str
) -> None:
    _home, store = capture_home
    _resume(monkeypatch, message)
    _type_unknown_ref(ref, value)
    end_turn(turn_id=T2, message=message)
    _assert_withheld(store, value, scrubbed)


def test_after_resume_a_snapshot_restores_the_usual_classification(capture_home, monkeypatch) -> None:
    _home, store = capture_home
    _resume(monkeypatch, SEARCH_MESSAGE)
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT), turn_id=T2)
    call("browser_type", {"ref": "@e5", "text": "Northwind"}, ok(element="@e5"), turn_id=T2)
    end_turn(turn_id=T2, message=SEARCH_MESSAGE)
    _assert_kept(store, "Northwind", SEARCH_MESSAGE)
    assert _typed(store).target == 'searchbox "Search invoices"'


_PAGE_CALLS_WITHOUT_SNAPSHOT: dict[str, tuple[str, dict[str, Any], str, str]] = {
    "navigate": ("browser_navigate", {"url": LOGIN}, ok(url=LOGIN, title="Sign in to Acme"), "ok"),
    "failed navigate": ("browser_navigate", {"url": LOGIN}, failed("net::ERR_CONNECTION_REFUSED"), "error"),
    "click": ("browser_click", {"ref": "@e4"}, ok(clicked="@e4"), "ok"),
    "empty snapshot": ("browser_snapshot", {}, ok(snapshot="", element_count=0), "ok"),
}


@pytest.mark.parametrize("page_call", list(_PAGE_CALLS_WITHOUT_SNAPSHOT))
def test_after_resume_a_page_call_without_a_snapshot_still_fails_closed(
    capture_home, monkeypatch, page_call: str
) -> None:
    _home, store = capture_home
    _resume(monkeypatch, SEARCH_MESSAGE)
    tool, args, result, status = _PAGE_CALLS_WITHOUT_SNAPSHOT[page_call]
    call(tool, args, result, turn_id=T2, status=status)
    _type_unknown_ref("@e5", "Northwind")
    end_turn(turn_id=T2, message=SEARCH_MESSAGE)
    _assert_withheld(store, "Northwind", SEARCH_SCRUBBED)


# --- a fresh session: the same rule ----------------------------------------------------------------------------


def test_a_ref_typed_before_the_first_snapshot_of_a_fresh_session_fails_closed(capture_home) -> None:
    """A fresh process cannot hold a valid ref before a snapshot: what Hermes types there is withheld (M2)."""
    _home, store = capture_home
    message = f"type {PASSWORD} into the second field"
    turn(message)
    call("browser_type", {"ref": "@e3", "text": PASSWORD}, failed("Unknown ref: e3"), status="error")
    end_turn(message=message)
    _assert_withheld(store, PASSWORD, "type redacted into the second field")


@pytest.mark.parametrize(
    "args", [{"text": "Northwind"}, {"ref": "#search", "text": "Northwind"}, {"ref": 5, "text": "Northwind"}]
)
def test_a_target_that_is_no_ref_fails_closed(capture_home, args: dict[str, Any]) -> None:
    """``browser_type`` takes only a snapshot ref (required in hermes-agent 0.13.0 and 0.19.0; no selector): a call
    without one cannot be classified, so its value is withheld and scrubbed, also on a freshly read page."""
    _home, store = capture_home
    turn(SEARCH_MESSAGE)
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT))
    call("browser_type", args, failed("Unknown ref"), status="error")
    end_turn(message=SEARCH_MESSAGE)
    _assert_withheld(store, "Northwind", SEARCH_SCRUBBED)


def test_an_empty_snapshot_names_no_field(capture_home) -> None:
    """A fresh read of the page that lists nothing leaves no kind standing, not the previous snapshot's."""
    _home, store = capture_home
    turn(SEARCH_MESSAGE)
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT))
    call("browser_snapshot", {}, ok(snapshot="", element_count=0))
    call("browser_type", {"ref": "@e5", "text": "Northwind"}, ok(element="@e5"))
    end_turn(message=SEARCH_MESSAGE)
    _assert_withheld(store, "Northwind", SEARCH_SCRUBBED)


def test_a_ref_the_open_pages_snapshot_does_not_list_fails_closed_whatever_an_older_page_listed(capture_home) -> None:
    """Refs are numbered per snapshot, and Hermes cuts a long snapshot (``_truncate_snapshot``) while the refs past
    the cut still work: an older page's ``link "Article 50"`` says nothing about this page's ``e50`` (security
    review of the resume fix)."""
    _home, store = capture_home
    message = "put Summer2024! into the field at the bottom, then Contoso Ltd into the search box"
    turn(message)
    article = '- link "Article 50" [ref=e50]\n- searchbox "Search invoices" [ref=e5]'
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, snapshot=article))
    cut = '- heading "Sign in" [ref=e1] [level=1]\n[... more lines truncated, see the full snapshot ...]'
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=cut))
    call("browser_type", {"ref": "@e50", "text": "Summer2024!"}, ok(element="@e50"))
    call("browser_type", {"ref": "@e5", "text": "Contoso Ltd"}, failed("Unknown ref: e5"), status="error")
    end_turn(message=message)
    typed = [event for event in calls(store) if event.op == "type"]
    assert [(json.loads(event.args_json)["field_kind"], event.text) for event in typed] == [
        ("sensitive", None),
        ("sensitive", None),
    ]
    assert _held_text(store).text == "put redacted into the field at the bottom, then redacted into the search box"
    assert "Summer2024!" not in _whole_store(store)
