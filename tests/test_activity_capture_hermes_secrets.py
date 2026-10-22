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

from mordred_hermes.activity import (
    _browser_results,
    _history_access,
    capture_hermes,
    contracts,
    history,
    hooks_history,
    tools,
)
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


def _shown_to_later_sessions(store: ActivityStore, task_words: str = "as the password") -> list[str]:
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
    assert all(task_words in text for text in shown), shown  # every surface shows the task
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


# --- only a real secret is scrubbed, as a whole word (live B2 re-run, N1) --------------------------------------

NOTES = "http://127.0.0.1:8499/notes.html"
NOTES_SNAPSHOT = '- heading "Notes" [ref=e1] [level=1]\n- textbox "Note" [ref=e2]\n- button "Save" [ref=e3]'


def test_a_value_typed_after_enter_is_withheld_but_never_scrubbed_from_the_users_words(capture_home) -> None:
    """After Enter the snapshot is stale, so the field counts as secret for the typed text, but it is no secret
    field: its value must not rewrite the task ("notes.html" once became "redacteds.html")."""
    _home, store = capture_home
    message = "Open http://127.0.0.1:8499/notes.html, press Enter, then type Fabrikam into the Note box."
    turn(message)
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"))
    call("browser_type", {"ref": "@e2", "text": "Fabrikam"}, ok(element="@e2"))
    call("browser_type", {"ref": "@e2", "text": "Note"}, ok(element="@e2"))
    end_turn()
    [start] = _starts(store)
    assert start.text == message and "text_secrets_redacted" not in start.exclusions
    typed = [event for event in calls(store) if event.op == "type"]
    assert [event.text for event in typed] == [None, None]  # the stale field still withholds what was typed
    turn("correct: the note should say Fabrikam Inc", turn_id=T2)  # nothing learned for later turns either
    end_turn(turn_id=T2)
    assert [event.text for event in events(store) if event.phase == "correction"] == [
        "the note should say Fabrikam Inc"
    ]


def test_a_secret_looking_value_typed_into_an_unknown_field_is_still_scrubbed(capture_home) -> None:
    _home, store = capture_home
    turn("log in on 127.0.0.1 and paste Xk9#mQ2$vL7pR4wZ")
    call("browser_type", {"ref": "@e9", "text": "Xk9#mQ2$vL7pR4wZ"}, ok(element="@e9"))  # before any snapshot
    _navigate()
    end_turn()
    [start] = _starts(store)
    assert start.text == "log in on 127.0.0.1 and paste redacted"


def test_a_secret_is_scrubbed_as_a_whole_word_also_inside_a_url(capture_home) -> None:
    _home, store = capture_home
    message = "sign in at http://example.com/example with example, not xexample or example2 or EXAMPLE"
    turn(message)
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT))
    call("browser_type", {"ref": "@e3", "text": "example"}, ok(element="@e3"))  # a real password field
    end_turn()
    [start] = _starts(store)
    assert start.text == ("sign in at http://redacted.com/redacted with redacted, not xexample or example2 or redacted")


def test_a_secret_in_a_url_authority_is_scrubbed(capture_home) -> None:
    """Security review of the N1 fix: an exemption for a URL's scheme and host let a value the regex took for the
    host survive (userinfo, a host label)."""
    _home, store = capture_home
    turn("open http://Swordfish-9@127.0.0.1/a and https://Swordfish-9.example.com/b")
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=LOGIN_SNAPSHOT))
    call("browser_type", {"ref": "@e3", "text": "Swordfish-9"}, ok(element="@e3"))
    end_turn()
    [start] = _starts(store)
    assert "Swordfish-9" not in (start.text or "") and "swordfish-9" not in _whole_store(store).lower()


# --- a value typed while the snapshot is stale: the field's last known kind decides (security review of N1) ----


def test_a_plain_password_typed_after_a_click_into_a_field_last_seen_as_secret_is_scrubbed(capture_home) -> None:
    _home, store = capture_home
    turn("log in on 127.0.0.1 as demo-user with swordfish")
    _navigate()
    call("browser_click", {"ref": "@e4"}, ok(clicked="@e4"))  # the snapshot is stale now
    call("browser_type", {"ref": "@e3", "text": "swordfish"}, ok(element="@e3"))  # last seen: textbox "Password"
    end_turn()
    [start] = _starts(store)
    assert start.text == "log in on 127.0.0.1 as demo-user with redacted"


def test_a_value_typed_into_a_field_no_snapshot_listed_is_scrubbed(capture_home) -> None:
    """Fail closed: a field Hermes never saw has no known kind."""
    _home, store = capture_home
    turn("log in on 127.0.0.1 with swordfish")
    _navigate()
    call("browser_click", {"ref": "@e4"}, ok(clicked="@e4"))
    call("browser_type", {"ref": "@e42", "text": "swordfish"}, ok(element="@e42"))
    end_turn()
    [start] = _starts(store)
    assert start.text == "log in on 127.0.0.1 with redacted"


def test_a_field_named_in_an_older_snapshot_keeps_its_kind(capture_home) -> None:
    """The most recent snapshot that listed the ref decides, also when a newer snapshot does not list it."""
    _home, store = capture_home
    turn("open the notes on 127.0.0.1 and write Fabrikam")
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    call("browser_snapshot", {}, ok(snapshot='- heading "Other" [ref=e9]'))  # e2 not listed any more
    call("browser_click", {"ref": "@e9"}, ok(clicked="@e9"))
    call("browser_type", {"ref": "@e2", "text": "Fabrikam"}, ok(element="@e2"))  # last listed: textbox "Note"
    end_turn()
    [start] = _starts(store)
    assert start.text == "open the notes on 127.0.0.1 and write Fabrikam"


# --- a ref is read from its element's own annotation, never from text the page writes (security review) --------

#: A page can write "[ref=e5]" into another element's accessible name.
SPOOFED = '- heading "Sign in" [ref=e1]\n- textbox "Note [ref=e5]" [ref=e2]\n- textbox "Password" [ref=e5]'


def test_a_bare_ref_written_inside_an_accessible_name_never_names_the_field() -> None:
    """Codex review of 6da5ccad2 (P1), verbatim."""
    snapshot = '- textbox "Note for [e3]" [ref=e2]\n- textbox "Password" [ref=e3]'
    assert _browser_results.ref_line(snapshot, "@e3") == '- textbox "Password" [ref=e3]'
    assert _browser_results.ref_kind(snapshot, "@e3") == "sensitive"
    assert _browser_results.ref_kinds(snapshot) == {"e3": "sensitive", "e2": "text"}


def test_a_ref_written_inside_an_accessible_name_never_names_the_field() -> None:
    assert _browser_results.ref_line(SPOOFED, "@e5") == '- textbox "Password" [ref=e5]'
    assert _browser_results.ref_line(SPOOFED, "@e2") == '- textbox "Note [ref=e5]" [ref=e2]'
    kinds = _browser_results.ref_kinds(SPOOFED)
    assert (kinds["e5"], kinds["e2"], kinds["e1"]) == ("sensitive", "text", "text")


@pytest.mark.parametrize(
    "snapshot",
    [
        '- textbox "Note" [ref=e5]\n- textbox "Password" [ref=e5]',
        '- textbox "Password" [ref=e5]\n- textbox "Note" [ref=e5]',
        '- textbox "Note" [ref=e5]\n- link "x [ref=e5]" [ref=e6]',  # also written inside a name: ambiguous
        '- textbox "Note" [ref=e2]: see [ref=e5]\n- textbox "Name" [ref=e5]',  # also written inside a value
    ],
)
def test_a_ref_on_several_lines_or_also_in_page_text_takes_the_most_sensitive_kind(snapshot: str) -> None:
    assert _browser_results.ref_kinds(snapshot)["e5"] == "sensitive"
    assert _browser_results.ref_kind(snapshot, "@e5") == "sensitive"


def test_a_ref_written_only_in_page_text_is_treated_as_secret() -> None:
    snapshot = '- textbox "Note" [ref=e2]: see [ref=e7] and "[e8]"'
    assert _browser_results.ref_line(snapshot, "@e7") is None
    assert _browser_results.ref_kind(snapshot, "@e7") == "sensitive"
    assert _browser_results.ref_kind(snapshot, "@e8") == "sensitive"
    assert _browser_results.ref_kind(snapshot, "@e9") == "other"  # nowhere: unknown


def test_a_password_typed_into_a_spoofed_ref_is_withheld_and_scrubbed(capture_home) -> None:
    _home, store = capture_home
    turn("log in on 127.0.0.1 with swordfish")
    call("browser_navigate", {"url": LOGIN}, nav_result(LOGIN, snapshot=SPOOFED))
    call("browser_type", {"ref": "@e5", "text": "swordfish"}, ok(element="@e5"))  # fresh snapshot
    call("browser_click", {"ref": "@e1"}, ok(clicked="@e1"))
    call("browser_type", {"ref": "@e5", "text": "swordfish"}, ok(element="@e5"))  # stale: its last known kind
    end_turn()
    typed = [event for event in calls(store) if event.op == "type"]
    assert [event.text for event in typed] == [None, None]
    assert typed[0].target == 'textbox "Password"'
    [start] = _starts(store)
    assert start.text == "log in on 127.0.0.1 with redacted"
    assert "swordfish" not in _whole_store(store)


# --- a value the message calls a secret is withheld when typed (live B2 re-run, N5) ------------------------------


def test_each_value_of_two_readings_is_withheld_when_typed(capture_home) -> None:
    """Codex review of 6da5ccad2 (P2): "PIN code=1234" merges "code=1234" (after "pin") and "1234" (after
    "pin code"); both are named secrets, so "1234" typed into an ordinary field is withheld too."""
    _home, store = capture_home
    turn("Open http://127.0.0.1:8499/notes.html; my PIN code=1234")
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    call("browser_type", {"ref": "@e2", "text": "1234"}, ok(element="@e2"))  # a text field
    end_turn()
    [typed] = [event for event in calls(store) if event.op == "type"]
    assert typed.text is None and "typed_text_dropped" in typed.exclusions
    assert "1234" not in _whole_store(store)


def test_a_value_the_message_calls_a_password_is_withheld_from_any_field(capture_home) -> None:
    _home, store = capture_home
    turn("Open http://127.0.0.1:8499/notes.html and type Zebra-77-fake as the password into the Note box")
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    call("browser_type", {"ref": "@e2", "text": "Zebra-77-fake"}, ok(element="@e2"))  # a text field
    call("browser_type", {"ref": "@e2", "text": "remember Zebra-77-fake"}, ok(element="@e2"))
    call("browser_type", {"ref": "@e2", "text": "Contoso"}, ok(element="@e2"))
    end_turn()
    typed = [event for event in calls(store) if event.op == "type"]
    assert [event.text for event in typed] == [None, None, "Contoso"]
    assert all("typed_text_dropped" in event.exclusions for event in typed[:2])
    assert "Zebra-77-fake" not in _whole_store(store)


def test_a_message_naming_more_values_than_are_listed_withholds_every_value_typed_in_its_turn(capture_home) -> None:
    """Codex review of 7a1084bee: each "pin:" of a run names the rest of it, so the values a message names are
    bounded (``contracts.secret_values``); past the bound the list is incomplete and every value typed in that turn
    is withheld and scrubbed from its task start (fail closed). The next turn's message is read afresh."""
    _home, store = capture_home
    turn("Open http://127.0.0.1:8499/notes.html and type Contoso into the Note box. " + "pin:" * 1000 + "1234")
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    call("browser_type", {"ref": "@e2", "text": "Contoso"}, ok(element="@e2"))  # a text field
    end_turn()
    turn("Open http://127.0.0.1:8499/notes.html and type Fabrikam into the Note box", turn_id=T2)
    call("browser_type", {"ref": "@e2", "text": "Fabrikam"}, ok(element="@e2"), turn_id=T2)
    end_turn(turn_id=T2)
    typed = [event for event in calls(store) if event.op == "type"]
    assert [event.text for event in typed] == [None, "Fabrikam"]
    assert "typed_text_dropped" in typed[0].exclusions
    assert "Contoso" not in _whole_store(store)
    [first, _second] = _starts(store)
    assert first.text is not None and first.text.startswith("Open http://127.0.0.1:8499/notes.html and type redacted ")


def _turn_and_type_seconds(size: int, runs: int = 3) -> tuple[float, float]:
    """The best time of ``pre_llm_call`` with Codex's message of ``size`` characters, and of one ``browser_type``
    of ordinary text in that turn."""
    message = "pin:" * (size // 4) + "1234"
    best_turn = best_type = float("inf")
    for run in range(runs):
        turn_id = f"s1:t{size}:{run}"
        started = time.perf_counter()
        turn(message, turn_id=turn_id)
        best_turn = min(best_turn, time.perf_counter() - started)
        started = time.perf_counter()
        call("browser_type", {"ref": "@e2", "text": "ordinary typed text"}, ok(element="@e2"), turn_id=turn_id)
        best_type = min(best_type, time.perf_counter() - started)
        end_turn(turn_id=turn_id)
    return best_turn, best_type


def test_a_turn_naming_overlapping_values_and_its_typing_take_linear_time(capture_home) -> None:
    """Codex review of 7a1084bee: the 4 KB message once took 1.3 s to check ordinary typed text (2 ms before)."""
    turn("Open http://127.0.0.1:8499/notes.html")
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    end_turn()
    small = _turn_and_type_seconds(10_000)
    large = _turn_and_type_seconds(40_000)
    assert max(large) < 0.05, (small, large)
    assert all(slow < 6 * max(fast, 0.002) for fast, slow in zip(small, large, strict=True)), (small, large)


def _type_seconds(typed: str, runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        call("browser_type", {"ref": "@e2", "text": typed}, ok(element="@e2"))
        best = min(best, time.perf_counter() - started)
    return best


def test_typing_against_many_overlapping_named_values_takes_linear_time(capture_home) -> None:
    """Codex review of f435dfc10: a message names ``"-a-" * i`` as passwords (i = 1..64, within the bound), then
    ``"-a-" * 13333`` is typed; listing every place a value stands in it took 1.4-1.8 s (under 10 ms before)."""
    _home, store = capture_home
    message = "Open http://127.0.0.1:8499/notes.html; " + "; ".join(
        f"password: {'-a-' * count}" for count in range(1, 65)
    )
    assert contracts.secret_values(message).complete  # the values are compared, not withheld wholesale
    turn(message)
    call("browser_navigate", {"url": NOTES}, nav_result(NOTES, title="Notes", snapshot=NOTES_SNAPSHOT))
    small = _type_seconds("-a-" * 3_333)
    large = _type_seconds("-a-" * 13_333)
    end_turn()
    assert large < 0.05, (small, large)
    assert large < 6 * max(small, 0.002), (small, large)
    typed = [event for event in calls(store) if event.op == "type"]
    assert len(typed) == 6 and all(event.text is None and "typed_text_dropped" in event.exclusions for event in typed)


# --- a secret-shaped token in the user's own words (live B2 re-run, N4) -------------------------------------------


def test_a_secret_shaped_token_in_the_users_words_is_redacted_without_a_keyword(capture_home) -> None:
    _home, store = capture_home
    message = "My login for http://127.0.0.1:8499/login.html is demo-user / Kx9-Hunter2-fake-pw-77 — please sign in."
    turn(message)
    _navigate()
    end_turn()
    [start] = _starts(store)
    assert start.text == ("My login for http://127.0.0.1:8499/login.html is demo-user / redacted — please sign in.")
    assert "text_secrets_redacted" in start.exclusions


def test_a_secret_shaped_token_stored_before_the_rule_is_hidden_on_every_surface(capture_home, monkeypatch) -> None:
    home, store = capture_home
    token = "Kx9-Hunter2-fake-pw-77"
    message = f"My login for http://127.0.0.1:8499/login.html is demo-user / {token} - please sign in"
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
            "text": message,
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
        },
    ]
    batch: dict[str, Any] = {"schema_version": 1, "producer_id": "prod-old", "producer_kind": "hermes", "events": old}
    with monkeypatch.context() as patch:  # a receiver before either rule existed
        patch.setattr(contracts, "redact_text_secrets", lambda text: (text, False))
        patch.setattr(contracts, "redact_secret_shaped_tokens", lambda text: (text, False))
        assert receiver.ingest(capture_hermes.principal(home), batch)["type"] == "activity_ack"
    assert token in _whole_store(store)

    for shown in _shown_to_later_sessions(store, task_words="demo-user / "):
        assert token not in shown and "demo-user / redacted" in shown


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


def test_a_task_start_written_after_more_calls_than_a_summary_reads_is_still_shown(capture_home) -> None:
    """Codex review P2: a turn with more calls than a summary reads (:data:`.history.MAX_SUMMARY_EVENTS`) gets its
    task start after all of them; the summary, both blocks, the lookup and the episode detail still show it."""
    _home, store = capture_home
    task = "export every invoice on 127.0.0.1 page by page"
    turn(task)
    _navigate()
    for _ in range(history.MAX_SUMMARY_EVENTS):
        call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    end_turn()
    [record] = store.list_episodes()
    assert record.event_count == history.MAX_SUMMARY_EVENTS + 2
    assert store.events_for_episode(record.episode_id)[-1].op == "task_start"  # received last
    assert record.started_at == _starts(store)[0].observed_at  # the episode starts with its turn

    [summary] = history.episodes_for_sites(store, ["127.0.0.1"], excluded_sites=frozenset()).episodes
    assert summary.tasks == (task,)
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
    lookup = json.loads(tools.browser_history({"query": "invoice page"}, session_id="s7").split("\n")[2])
    assert block is not None and f'task "{task}"' in block["context"]
    assert navigation is not None and task in navigation
    assert [episode["task"] for episode in lookup["episodes"]] == [task]
    detail = history.episode_detail(store, record.episode_id, excluded_sites=frozenset())
    assert detail is not None and detail.summary.tasks == (task,)
    assert (detail.events[0].op, detail.events[0].text) == ("task_start", task)  # in time order: the turn's start


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
    """Without capture no field can be classified, so every value typed during the correction's turn is
    scrubbed from it (fail closed; security review of the N1 fix)."""
    home, store = capture_home
    turn("open the login page on 127.0.0.1", turn_id=T1)
    _navigate(T1)
    end_turn(turn_id=T1)
    write_config(home, {**CAPTURING, "history_capture_hermes": False})

    turn("correct: try the account Fabrikam-2 with Xk9#mQ2$vL7pR4wZ", turn_id=T2)
    call("browser_type", {"ref": "@e2", "text": "Fabrikam-2"}, ok(element="@e2"), turn_id=T2)
    call("browser_type", {"ref": "@e3", "text": "Xk9#mQ2$vL7pR4wZ"}, ok(element="@e3"), turn_id=T2)
    end_turn(turn_id=T2)

    [correction] = _corrections(store)
    assert correction.text == "try the account redacted with redacted"
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
