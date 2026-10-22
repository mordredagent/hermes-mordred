"""Hermes's own capture: the open page, stale snapshots, whose words a turn holds, page-text secrets, profiles,
attempt ids, the session's own episodes and batch limits (security reviews of 2026-10-22)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _history_access, capture_hermes, history, hooks_history
from mordred_hermes.activity.store import ActivityStore
from tests._activity_capture_helpers import (
    CAPTURING,
    LOGIN_URL,
    MESSAGE,
    SITE,
    SNAPSHOT,
    audit_entries,
    call,
    calls,
    capture_home,
    events,
    failed,
    nav_result,
    navigate,
    ok,
    stored_text,
    turn,
    write_config,
)
from tests._activity_episode_helpers import plain_opener

pytestmark = pytest.mark.usefixtures(capture_home.__name__, audit_entries.__name__)


# --- the open page: a click or key press may leave it (security review 2026-10-22, finding 1) ------------------

BANK = "https://www.bank.example/pay"
EXCLUDING: dict[str, Any] = {**CAPTURING, "excluded_sites": ["bank.example"]}


def test_after_a_click_to_an_excluded_host_nothing_is_recorded_until_the_page_is_known(capture_home) -> None:
    home, store = capture_home
    write_config(home, EXCLUDING)
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))  # agent-browser: no URL; it opened the bank's page
    call("browser_type", {"ref": "@e2", "text": "transfer 500 to Alice"}, ok(element="@e2"))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    call("browser_snapshot", {}, ok(snapshot='- button "Confirm transfer" [ref=e1]'))  # no URL either
    call("browser_click", {"ref": "@e1"}, ok(clicked="@e1"))
    navigate()
    recorded = calls(store)
    assert [(event.op, event.site) for event in recorded] == [("navigate", SITE), ("click", SITE), ("navigate", SITE)]
    dump = stored_text(store)
    assert "Alice" not in dump and "Confirm transfer" not in dump and "bank" not in dump


def test_after_enter_to_an_excluded_host_nothing_is_recorded(capture_home) -> None:
    home, store = capture_home
    write_config(home, EXCLUDING)
    turn()
    navigate()
    call("browser_type", {"ref": "@e6", "text": "pay the bill"}, ok(element="@e6"))
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"))  # submits, the bank's page opens
    call("browser_type", {"ref": "@e2", "text": "account 12345678"}, ok(element="@e2"))
    call("browser_press", {"key": "Tab"}, ok(pressed="Tab"))
    assert [(event.op, event.site) for event in calls(store)] == [("navigate", SITE), ("type", SITE), ("key", SITE)]
    assert "12345678" not in stored_text(store)


def test_without_exclusions_an_unknown_page_is_recorded_without_a_route(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"))
    navigate_click, unknown_scroll, unknown_key = calls(store)[1:]
    assert (navigate_click.site, navigate_click.route) == (SITE, "/login")
    assert [(event.site, event.route) for event in (unknown_scroll, unknown_key)] == [(None, None), (None, None)]


def test_a_result_that_reports_the_url_places_the_next_calls(capture_home) -> None:
    """The Camofox backend's click result carries the URL the click reached; a snapshot may report its top frame."""
    home, store = capture_home
    write_config(home, EXCLUDING)
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="e7", url=f"https://{SITE}/account"))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    call("browser_click", {"ref": "@e8"}, ok(clicked="e8", url=BANK))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))  # on the bank's page: refused
    call("browser_click", {"ref": "@e1"}, ok(clicked="e1", url=""))  # Camofox without a URL: unknown again
    call("browser_scroll", {"direction": "up"}, ok(scrolled="up"))
    frames = {"top": {"frame_id": "f1", "url": f"https://{SITE}/orders", "origin": f"https://{SITE}"}}
    call("browser_snapshot", {}, ok(snapshot=SNAPSHOT, frame_tree=frames))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert [(event.op, event.route) for event in calls(store)] == [
        ("navigate", "/login"),
        ("click", "/login"),
        ("scroll", "/account"),
        ("click", "/account"),
        ("other", "/orders"),
        ("scroll", "/orders"),
    ]


@pytest.mark.parametrize(
    ("tool", "args", "result", "status"),
    [
        ("browser_snapshot", {}, failed("Blocked: page URL targets a private or internal address"), "error"),
        ("browser_navigate", {"url": f"https://{SITE}/next"}, failed("Blocked: redirect landed elsewhere"), "error"),
        ("browser_back", {}, ok(url=""), "ok"),
        ("browser_console", {"expression": "location.href = 'https://www.bank.example/'"}, ok(result="ok"), "ok"),
        ("browser_cdp", {"method": "Page.navigate"}, ok(), "ok"),
        ("browser_dialog", {"action": "accept"}, ok(), "ok"),
        ("browser_type", {"ref": "@e6", "text": "search\n"}, ok(element="@e6"), "ok"),
        ("browser_click", {"ref": "@e7"}, json.dumps({"error": "timed out"}), "timeout"),
        ("browser_navigate", {"url": "https://bücher.example/"}, nav_result("https://bücher.example/"), "ok"),
    ],
)
def test_calls_that_may_leave_the_page_make_it_unknown(capture_home, tool, args, result, status) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call(tool, args, result, status=status)
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert (calls(store)[-1].op, calls(store)[-1].site) == ("scroll", None)


@pytest.mark.parametrize(
    ("tool", "args", "result", "status"),
    [
        ("browser_click", {"ref": "@e7"}, json.dumps({"error": "Blocked by policy"}), "blocked"),
        ("browser_type", {"ref": "@e2", "text": "alice@example.com"}, ok(element="@e2"), "ok"),
        ("browser_scroll", {"direction": "down"}, failed("Failed to scroll down"), "error"),
        ("browser_vision", {"question": "q"}, ok(analysis="a"), "ok"),
        ("browser_get_images", {}, ok(images=[]), "ok"),
        ("browser_snapshot", {}, ok(snapshot=SNAPSHOT), "ok"),
    ],
)
def test_calls_that_stay_on_the_page_keep_it(capture_home, tool, args, result, status) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call(tool, args, result, status=status)
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert (calls(store)[-1].site, calls(store)[-1].route) == (SITE, "/login")


def test_a_session_starts_on_an_unknown_page(capture_home) -> None:
    home, store = capture_home
    write_config(home, EXCLUDING)
    turn()
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))  # whatever an earlier session left open
    navigate()
    assert [event.op for event in events(store)] == ["task_start", "navigate"]


def test_an_about_page_is_known_and_has_no_route(capture_home) -> None:
    home, store = capture_home
    write_config(home, EXCLUDING)
    turn()
    call("browser_navigate", {"url": "about:blank"}, ok(url="about:blank", title="", snapshot=""))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert [(event.op, event.site) for event in calls(store)] == [("navigate", None), ("scroll", None)]


# --- a stale snapshot never names a field (security review 2026-10-22, finding 2) ------------------------------


def test_text_typed_after_a_click_is_withheld_until_a_fresh_snapshot(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    call("browser_type", {"ref": "@e6", "text": "words after the click"}, ok(element="@e6"))  # e6 may be a password now
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"))
    call("browser_type", {"ref": "@e2", "text": "words after enter"}, ok(element="@e2"))
    call("browser_back", {}, ok(url=f"https://{SITE}/"))  # back reports no snapshot either
    call("browser_type", {"ref": "@e2", "text": "words after back"}, ok(element="@e2"))
    typed = [event for event in calls(store) if event.op == "type"]
    assert len(typed) == 3
    for event in typed:
        assert event.text is None and event.target is None
        assert json.loads(event.args_json) == {"field_kind": "sensitive"}
        assert {"sensitive_field", "typed_text_dropped"} <= set(event.exclusions)
    assert "words after" not in stored_text(store)


def test_after_a_fresh_snapshot_an_unnamed_field_keeps_its_text(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    call("browser_snapshot", {}, ok(snapshot=SNAPSHOT, element_count=11))
    call("browser_type", {"ref": "@e5", "text": "unnamed field words"}, ok(element="@e5"))
    call("browser_type", {"ref": "@e99", "text": "missing ref words"}, ok(element="@e99"))
    call("browser_type", {"ref": "@e2", "text": "alice@example.com"}, ok(element="@e2"))
    typed = [event for event in calls(store) if event.op == "type"]
    assert [json.loads(event.args_json)["field_kind"] for event in typed] == ["other", "other", "text"]
    assert [event.text for event in typed] == ["unnamed field words", "missing ref words", "alice@example.com"]


def test_after_a_fresh_snapshot_a_password_line_withholds_the_text(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    call("browser_snapshot", {}, ok(snapshot=SNAPSHOT, element_count=11))
    call("browser_type", {"ref": "@e3", "text": "hunter2-plain"}, ok(element="@e3"))
    typed = calls(store)[-1]
    assert (typed.target, typed.text, json.loads(typed.args_json)) == (
        'textbox "Password"',
        None,
        {"field_kind": "sensitive"},
    )
    assert "hunter2-plain" not in stored_text(store)


def test_a_navigation_without_a_snapshot_leaves_the_snapshot_stale(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    url = f"https://{SITE}/next"
    call("browser_navigate", {"url": url}, json.dumps({"success": True, "url": url, "title": "Next"}))
    call("browser_type", {"ref": "@e2", "text": "typed on the next page"}, ok(element="@e2"))
    typed = calls(store)[-1]
    assert (typed.site, typed.text, json.loads(typed.args_json)) == (SITE, None, {"field_kind": "sensitive"})


# --- which turns are the user's words (security review 2026-10-22, finding 3) ---------------------------------


@pytest.mark.parametrize("platform", ["cli", "tui", "desktop", " CLI "])
def test_the_local_surfaces_are_the_users_words(capture_home, platform: str) -> None:
    """hermes-agent 0.19.0: the classic CLI and ``hermes -z`` (``cli``), ``hermes --tui`` (``tui``), the desktop
    app's chat panel (``desktop``)."""
    _home, store = capture_home
    turn(platform=platform)
    navigate()
    turn("correct: use the account menu", platform=platform, turn_id="s1:t1:zz99")
    [start] = [event for event in events(store) if event.op == "task_start"]
    assert start.actor == "human"
    assert [event.text for event in events(store) if event.phase == "correction"] == ["use the account menu"]


@pytest.mark.parametrize(
    "platform",
    [
        "telegram",
        "discord",
        "slack",
        "whatsapp",
        "whatsapp_cloud",
        "signal",
        "matrix",
        "mattermost",
        "email",
        "sms",
        "feishu",
        "weixin",
        "api_server",
        "webhook",
        "acp",
        "webui",
        "subagent",
        "cron",
        "curator",
        "gateway",
        "",
        "CLI-bridge",
        42,
        None,
    ],
)
def test_any_other_platform_is_not_the_users_words(capture_home, platform: Any) -> None:
    _home, store = capture_home
    turn("goal written by someone else on shop.example.com", platform=platform)
    navigate()
    [start] = [event for event in events(store) if event.op == "task_start"]
    assert start.actor == "agent" and start.text == "goal written by someone else on shop.example.com"
    assert not history.speaks_for_user(start.phase, start.op, start.source, start.actor)
    assert history.episodes_for_sites(store, [SITE], excluded_sites=frozenset(), require_human_text=True).episodes == ()
    turn("correct: not the user's correction", platform=platform, turn_id="s1:t1:zz99")
    assert not [event for event in events(store) if event.phase == "correction"]


def test_a_turn_without_a_platform_is_not_the_users_words(capture_home) -> None:
    _home, store = capture_home
    capture_hermes.pre_llm_call(session_id="s1", task_id="t1", turn_id="s1:t1:aa11", user_message=MESSAGE)
    navigate()
    capture_hermes.pre_llm_call(session_id="s1", task_id="t1", turn_id="s1:t1:bb22", user_message="correct: x")
    assert [(event.op, event.actor) for event in events(store)] == [("task_start", "agent"), ("navigate", "agent")]


def test_a_configured_gateway_platform_is_the_users_words(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "history_human_platforms": ["cli", " Telegram "]})
    turn("check my orders on shop.example.com", platform="telegram")
    navigate()
    turn("correct: the orders are under the account menu", platform="telegram", turn_id="s1:t1:bb22")
    turn("a TUI turn is no longer the user's", platform="tui", turn_id="s1:t1:cc33", session="s2")
    navigate(session="s2", turn_id="s1:t1:cc33")
    starts = {event.hermes_session_id: event.actor for event in events(store) if event.op == "task_start"}
    assert starts == {"s1": "human", "s2": "agent"}
    assert [event.text for event in events(store) if event.phase == "correction"] == [
        "the orders are under the account menu"
    ]


# --- page text keeps no secret value (Codex review, P1) --------------------------------------------------------

FILLED = "\n".join(
    [
        '- heading "Checkout" [ref=e1]',
        '- textbox "Email" [ref=e2]: alice@example.com',
        '- textbox "PIN" [ref=e3]: 852951',
        '- textbox "Card number" [ref=e4]: 4111 1111 1111 1111',
        '- textbox "パスワード" [ref=e5]: hunter2-plain',
        "- text: Your one-time code is 731904",
        "- text: api key sk-proj-AbCdEf0123456789xyz",
        '- button "Pay" [ref=e6]',
    ]
)


def test_page_text_drops_the_values_of_secret_fields() -> None:
    text = capture_hermes.page_text(FILLED)
    for secret in ("852951", "4111 1111", "hunter2-plain", "731904", "sk-proj-AbCdEf0123456789xyz"):
        assert secret not in text
    assert '- textbox "PIN"\n- textbox "Card number"\n- textbox "パスワード"' in text
    assert '- textbox "Email" [ref=e2]: alice@example.com' in text and '- button "Pay" [ref=e6]' in text


def test_a_filled_in_secret_never_reaches_the_store_or_the_lookup(capture_home) -> None:
    from mordred_hermes.activity import tools

    _home, store = capture_home
    turn()
    call("browser_navigate", {"url": LOGIN_URL}, nav_result(snapshot=FILLED))
    [nav] = calls(store)
    assert nav.page_text and "alice@example.com" in nav.page_text
    dump = stored_text(store)
    for secret in ("852951", "4111 1111", "hunter2-plain", "731904", "sk-proj"):
        assert secret not in dump
    detail = tools.browser_history_episode({"episode_id": nav.episode_id}, session_id="s9")
    assert "852951" not in detail and "4111 1111" not in detail


# --- several profiles in one process (Codex review, P1) --------------------------------------------------------


def test_profiles_never_share_a_sessions_state(capture_home, tmp_path: Path, monkeypatch, audit_entries) -> None:
    home_a, store_a = capture_home
    home_b = tmp_path / "other"
    home_b.mkdir()
    store_b = ActivityStore(home_b / "mordred.db", plain_opener, busy_timeout_s=capture_hermes.WRITE_BUSY_S)
    store_b.initialize(home_b)
    write_config(home_b, CAPTURING)
    stores = {home_a: store_a, home_b: store_b}
    active = [home_a]
    monkeypatch.setattr(_history_access, "home", lambda: active[0])
    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", lambda home: stores[home])

    turn()
    navigate()  # profile A, session s1
    assert capture_hermes.own_episodes(home_a, "s1", "t1") and not capture_hermes.own_episodes(home_b, "s1", "t1")
    active[0] = home_b
    turn("correct: typed in profile B", turn_id="s1:t1:bb22")  # same session id, another profile
    assert events(store_b) == []
    assert not [event for event in events(store_a) if event.phase == "correction"]

    # Slow writes suspend one profile's session only.
    def slow(home: Path) -> ActivityStore:
        time.sleep(0.03)
        return stores[home]

    monkeypatch.setattr(capture_hermes, "SLOW_APPEND_S", 0.01)
    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", slow)
    for _ in range(capture_hermes.SLOW_APPENDS_TO_SUSPEND):
        call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert [entry["reason"] for entry in audit_entries] == ["activity.capture_suspended"]
    active[0] = home_a
    before = len(events(store_a))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    assert len(events(store_a)) == before + 1


# --- a repeated tool_call_id (Codex review, P2) ----------------------------------------------------------------


def test_a_repeated_tool_call_id_keeps_attempts_and_corrections_apart(capture_home) -> None:
    _home, store = capture_home
    turn("first task on shop.example.com", turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11", call_id="acp_call_1")
    turn("second task on shop.example.com", turn_id="s1:t1:bb22")
    navigate(turn_id="s1:t1:bb22", call_id="acp_call_1")  # the Copilot ACP fallback repeats its ids
    navigate(session="s2", turn_id="s2:t:1", call_id="acp_call_1")
    turn("correct: the second one was wrong", turn_id="s1:t1:cc33")

    by_turn = {event.turn_id: event for event in calls(store) if event.op == "navigate"}
    first, second, other = by_turn["s1:t1:aa11"], by_turn["s1:t1:bb22"], by_turn["s2:t:1"]
    assert len({first.attempt_id, second.attempt_id, other.attempt_id}) == 3
    assert all((event.attempt_id or "").startswith("acp-call-1-") for event in (first, second, other))
    [correction] = [event for event in events(store) if event.phase == "correction"]
    assert (correction.attempt_id, correction.episode_id) == (second.attempt_id, second.episode_id)
    assert first.episode_id != second.episode_id


def test_occurrence_ids_fit_the_receivers_identifier_rule() -> None:
    long_base = capture_hermes.attempt_id("x" * 64)
    made = {capture_hermes.occurrence_id(long_base) for _ in range(20)}
    assert len(made) == 20
    assert all(len(value) <= 64 and value.startswith("x") for value in made)


# --- the session's own episodes are not shown back to it (Codex review, P2) ------------------------------------


def test_the_navigation_block_never_shows_the_sessions_own_episode(capture_home) -> None:
    home, _store = capture_home
    write_config(home, {**CAPTURING, "history_max_episodes": 1})
    turn("earlier task on shop.example.com", session="s0", turn_id="s0:t:1")
    navigate(session="s0", turn_id="s0:t:1")

    def navigation_block(session: str, turn_id: str) -> str | None:
        result = nav_result()
        navigate(session=session, turn_id=turn_id)  # post_tool_call runs before transform_tool_result
        out = hooks_history.transform_tool_result(
            tool_name="browser_navigate", args={"url": LOGIN_URL}, result=result, session_id=session, task_id="t1"
        )
        return None if out is None else json.loads(out).get(hooks_history.RESULT_KEY)

    turn(session="s1", turn_id="s1:t1:aa11")
    block = navigation_block("s1", "s1:t1:aa11")
    assert block is not None and "earlier task" in block and MESSAGE not in block
    spent = _history_access.BUDGET.snapshot("s1")[0]
    turn("now the invoices on shop.example.com", session="s1", turn_id="s1:t1:bb22")
    assert navigation_block("s1", "s1:t1:bb22") is None  # its own episodes changed, still not shown
    assert _history_access.BUDGET.snapshot("s1")[0] == spent
    # The turn-start block leaves them out too.
    assert hooks_history.pre_llm_call(user_message=MESSAGE, session_id="s1", task_id="t1") is None
    other = hooks_history.pre_llm_call(user_message=MESSAGE, session_id="s3", task_id="t1")
    assert other is not None and "earlier task" not in other["context"]


# --- batch limits (Codex review, P2) ---------------------------------------------------------------------------


def test_a_one_event_batch_limit_still_records_the_whole_turn(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "max_batch_events": 1})
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    turn("correct: use the account menu", turn_id="s1:t1:bb22")
    assert [event.op for event in events(store)] == ["task_start", "navigate", "click", "other"]
    assert len([event for event in events(store) if event.op == "task_start"]) == 1


def test_a_split_batch_sends_nothing_when_its_call_would_be_refused(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**EXCLUDING, "max_batch_events": 1})
    turn("pay the bill, then check shop.example.com")
    call("browser_navigate", {"url": BANK}, nav_result(BANK))
    assert events(store) == []  # no task start without its call
    navigate()
    assert [event.op for event in events(store)] == ["task_start", "navigate"]


def test_batches_follow_the_count_and_byte_limits() -> None:
    from mordred_hermes.activity.config import ActivityConfig

    small = {"text": "a" * 100}
    large = {"text": "b" * 5000}
    by_count = ActivityConfig.from_mapping({"max_batch_events": 2})
    assert [len(batch) for batch in capture_hermes._batches(by_count, [small, small, small])] == [2, 1]
    by_bytes = ActivityConfig.from_mapping({"max_batch_bytes": 5700})
    assert [len(batch) for batch in capture_hermes._batches(by_bytes, [small, large, small, large])] == [2, 2]
    assert [len(batch) for batch in capture_hermes._batches(ActivityConfig(), [small, large])] == [2]
