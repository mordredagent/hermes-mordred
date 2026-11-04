"""Hermes as a collector: its own browser calls and the user's chat corrections, recorded through the receiver."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _gate, _history_access, capture_hermes, history, hooks_history
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
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
    end_turn,
    events,
    failed,
    nav_result,
    navigate,
    ok,
    stored_text,
    turn,
    write_config,
)

pytestmark = pytest.mark.usefixtures(capture_home.__name__, audit_entries.__name__)


# --- mapping -----------------------------------------------------------------------------------------------


def test_navigate_records_route_title_and_page_text_and_the_turn_end_the_task_start(capture_home) -> None:
    _home, store = capture_home
    assert turn() is None
    assert navigate(call_id="call_nav1") is None
    assert [event.op for event in events(store)] == ["navigate"]  # the task start waits for the turn's end
    assert end_turn() is None

    nav, start = events(store)
    assert (start.phase, start.op, start.source, start.actor, start.text) == (
        "boundary",
        "task_start",
        "hermes",
        "human",
        MESSAGE,
    )
    assert (start.hermes_session_id, start.turn_id) == ("s1", "s1:t1:aa11")
    assert (nav.phase, nav.op, nav.source, nav.actor) == ("dispatched", "navigate", "hermes", "agent")
    assert nav.result_status == "claimed_success"
    assert (nav.site, nav.route, nav.query) == (SITE, "/login", "?next=%2Faccount")
    assert nav.page_title == "Sign in — Shop"
    assert nav.page_text == " ".join(capture_hermes.page_text(SNAPSHOT).split())
    assert nav.page_text and 'textbox "Search orders" [ref=e6]: last month' in nav.page_text
    # The tool_call_id in the receiver's identifier alphabet, made unique for this call.
    assert nav.attempt_id and nav.attempt_id.startswith("call-nav1-") and len(nav.attempt_id) == len("call-nav1-") + 12
    assert nav.episode_id == start.episode_id
    assert (nav.hermes_session_id, nav.turn_id) == ("s1", "s1:t1:aa11")
    [record] = store.list_episodes()
    assert record.observed_outcome == "claimed_success" and record.site == SITE


def test_each_browser_tool_maps_to_its_operation(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_type", {"ref": "@e2", "text": "alice@example.com"}, ok(typed="alice@example.com", element="@e2"))
    call("browser_click", {"ref": "@e7"}, ok(clicked="@e7"))
    call("browser_press", {"key": "Enter"}, ok(pressed="Enter"))
    call("browser_scroll", {"direction": "down"}, ok(scrolled="down"))
    call("browser_back", {}, ok(url=f"https://{SITE}/"))
    call("browser_snapshot", {"full": False}, ok(snapshot=SNAPSHOT, element_count=11))
    call("browser_vision", {"question": "what is on the page?"}, ok(analysis="a login form"))
    call("web_search", {"query": "not a browser tool"})  # not recorded

    recorded = calls(store)
    assert [event.op for event in recorded] == ["navigate", "type", "click", "key", "scroll", "back", "other", "other"]
    assert len({event.episode_id for event in events(store)}) == 1
    # A click result carries no URL (agent-browser): the page after it is unknown until the back result.
    assert [event.site for event in recorded] == [SITE, SITE, SITE, None, None, SITE, SITE, SITE]
    typed, click, key, scroll, back, snapshot, vision = recorded[1:]
    assert click.target == 'button "Sign in"'
    assert (typed.target, json.loads(typed.args_json), typed.text) == (
        'textbox "Email"',
        {"field_kind": "text"},
        "alice@example.com",
    )
    assert json.loads(key.args_json) == {"keys": ["Enter"]}
    assert json.loads(scroll.args_json) == {"direction": "down"}
    assert back.route == "/"
    assert (snapshot.target, vision.target) == ("browser_snapshot", "browser_vision")
    assert vision.text is None and "what is on the page" not in stored_text(store)
    assert {event.result_status for event in recorded} == {"claimed_success"}


def test_a_field_is_named_by_its_label_never_its_value(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_click", {"ref": "e6"}, ok(clicked="@e6"))  # without the "@"
    [_nav, click] = calls(store)
    assert click.target == 'textbox "Search orders"'
    assert "last month" not in (click.target or "")


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ('- textbox "Password" [ref=e3]', "sensitive"),
        ('- textbox "Current passwd" [ref=e3]', "sensitive"),
        ('- textbox "Passwort" [ref=e3]', "sensitive"),
        ('- textbox "パスワード\uff08確認\uff09" [ref=e4]', "sensitive"),
        ('- textbox "暗証番号" [ref=e4]', "sensitive"),
        ('- textbox "API secret" [ref=e4]', "sensitive"),
        ('- textbox "Access token" [ref=e4]', "sensitive"),
        ('- textbox "Card number" [ref=e4]', "sensitive"),
        ('- textbox "カード番号" [ref=e9]', "sensitive"),
        ('- textbox "One-time code" [ref=e10]', "sensitive"),
        ('- textbox "ワンタイムパスワード" [ref=e10]', "sensitive"),
        ('- textbox "Enter your PIN" [ref=e10]', "sensitive"),
        ('- textbox "CVC" [ref=e10]', "sensitive"),
        ('- textbox "Email" [ref=e2]', "text"),
        ('- textbox "氏名" [ref=e11]', "text"),
        ('- textbox "Spinner speed" [ref=e11]', "text"),
        ('- button "Discard changes" [ref=e11]', "text"),
        ("- textbox [ref=e5]", "other"),
        ('- textbox "" [ref=e5]', "other"),
        ("- textbox [ref=e5]: typed value", "other"),
        (None, "other"),
        ("", "other"),
    ],
)
def test_field_kind_from_the_ref_line(line: str | None, kind: str) -> None:
    assert capture_hermes.field_kind(line) == kind


def test_ref_lines_match_exactly_one_element() -> None:
    snapshot = '- link "A" [ref=e1]\n- link "B" [ref=e10]\n- link "C" [xref=e2]\n[e3] textbox "D"'
    assert capture_hermes.ref_line(snapshot, "@e1") == '- link "A" [ref=e1]'
    assert capture_hermes.ref_line(snapshot, "e10") == '- link "B" [ref=e10]'
    assert capture_hermes.ref_line(snapshot, "@e2") is None  # "xref=e2" is not a ref
    assert capture_hermes.ref_line(snapshot, "@e3") == '[e3] textbox "D"'
    assert capture_hermes.ref_line(snapshot, "@e4") is None
    assert capture_hermes.ref_line(snapshot, "e1; drop") is None
    assert capture_hermes.ref_line(None, "@e1") is None
    assert capture_hermes.element_label('[e3] textbox "D"') == 'textbox "D"'
    assert capture_hermes.element_label("- textbox [ref=e5]: typed value") == "textbox"


def test_text_typed_into_a_sensitive_field_is_withheld(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_type", {"ref": "@e3", "text": "hunter2-plain"}, ok(typed="hunter2-plain", element="@e3"))
    call("browser_type", {"ref": "@e4", "text": "確認用ひみつ"}, ok(element="@e4"))
    for typed in calls(store)[1:]:
        assert typed.text is None
        assert json.loads(typed.args_json) == {"field_kind": "sensitive"}
        assert {"sensitive_field", "typed_text_dropped"} <= set(typed.exclusions)
    assert calls(store)[1].target == 'textbox "Password"'
    dump = stored_text(store)
    assert "hunter2-plain" not in dump and "確認用ひみつ" not in dump


def test_text_typed_into_an_unnamed_field_is_kept_and_into_an_unknown_ref_withheld(capture_home) -> None:
    """An unnamed field keeps what was typed (owner decision 2026-10-22); a ref no snapshot listed, before the first
    snapshot too, is a possible secret field (B2 final live check, M2)."""
    _home, store = capture_home
    turn()
    call("browser_type", {"ref": "@e5", "text": "before any snapshot"}, ok(element="@e5"))
    navigate()
    call("browser_type", {"ref": "@e5", "text": "unnamed field words"}, ok(element="@e5"))
    call("browser_type", {"ref": "@e99", "text": "missing ref words"}, ok(element="@e99"))
    typed = [event for event in calls(store) if event.op == "type"]
    assert [json.loads(event.args_json)["field_kind"] for event in typed] == ["sensitive", "other", "sensitive"]
    assert [event.text for event in typed] == [None, "unnamed field words", None]
    assert typed[1].target == "textbox"
    assert "before any snapshot" not in stored_text(store) and "missing ref words" not in stored_text(store)


@pytest.mark.parametrize("ref", ["@e2", "@e5", "@e99"])
def test_secret_looking_text_is_withheld_whatever_the_field(capture_home, ref: str) -> None:
    _home, store = capture_home
    turn()
    navigate()
    secret = "sk-proj-AbCdEf0123456789xyz"
    call("browser_type", {"ref": ref, "text": secret}, ok(element=ref))
    typed = calls(store)[-1]
    assert typed.text is None and "typed_text_dropped" in typed.exclusions
    assert secret not in stored_text(store)


def test_a_single_character_pressed_is_not_kept(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    call("browser_press", {"key": "x"}, ok(pressed="x"))
    key = calls(store)[-1]
    assert key.op == "key" and json.loads(key.args_json) == {} and "typed_text_dropped" in key.exclusions


@pytest.mark.parametrize(
    ("status", "result", "phase", "outcome", "reason"),
    [
        ("error", failed("Failed to click @e99"), "dispatched", "claimed_failure", None),
        ("ok", failed("Failed to click @e99"), "dispatched", "claimed_failure", None),
        (None, failed("Failed to click @e99"), "dispatched", "claimed_failure", None),  # 0.13.0: no status
        (None, ok(clicked="@e7"), "dispatched", "claimed_success", None),
        ("blocked", json.dumps({"error": "Blocked by policy"}), "cancelled", "unknown", "blocked"),
        (
            "cancelled",
            json.dumps({"error": "Tool execution cancelled", "status": "cancelled"}),
            "cancelled",
            "unknown",
            "cancelled",
        ),
        ("timeout", json.dumps({"error": "timed out"}), "timed_out", "unknown", None),
    ],
)
def test_status_maps_to_phase_and_claimed_result(capture_home, status, result, phase, outcome, reason) -> None:
    _home, store = capture_home
    turn()
    call("browser_click", {"ref": "@e7"}, result, status=status)
    [click] = calls(store)
    assert (click.phase, click.result_status) == (phase, outcome)
    assert json.loads(click.args_json).get("reason") == reason


def test_a_failed_navigation_keeps_the_requested_url_and_no_page_fields(capture_home) -> None:
    _home, store = capture_home
    turn()
    call("browser_navigate", {"url": f"https://{SITE}/missing"}, failed("Navigation failed"), status="error")
    call("browser_navigate", {"url": "about:blank"}, ok(url="about:blank", title="", snapshot=""))
    failed_nav, blank = calls(store)
    assert (failed_nav.site, failed_nav.route, failed_nav.result_status) == (SITE, "/missing", "claimed_failure")
    assert failed_nav.page_title is None and failed_nav.page_text is None
    assert (blank.site, blank.route) == (None, None)


def test_a_large_page_text_is_shortened_to_fit_the_event_limit(capture_home) -> None:
    _home, store = capture_home
    turn()
    snapshot = "あ" * 9000  # 8000 characters kept, 24 000 UTF-8 bytes: above the 16 KiB event limit
    call("browser_navigate", {"url": LOGIN_URL}, nav_result(snapshot=snapshot))
    [nav] = calls(store)
    assert nav.page_text and set(nav.page_text) == {"あ"} and len(nav.page_text) < 8000
    assert nav.truncated


# --- episodes and the user's own words ---------------------------------------------------------------------


def test_one_episode_per_turn_with_browser_calls(capture_home) -> None:
    _home, store = capture_home
    turn("first task on shop.example.com", turn_id="s1:t1:aa11")
    navigate(turn_id="s1:t1:aa11")
    call("browser_click", {"ref": "@e7"}, turn_id="s1:t1:aa11")
    turn("just chatting, no browser", turn_id="s1:t1:bb22")
    call("web_search", {"query": "x"}, turn_id="s1:t1:bb22")
    turn("second task on shop.example.com", turn_id="s1:t1:cc33")
    navigate(turn_id="s1:t1:cc33")
    end_turn(turn_id="s1:t1:cc33")

    records = store.list_episodes()
    assert len(records) == 2
    starts = [event for event in events(store) if event.op == "task_start"]
    assert [event.text for event in starts] == ["first task on shop.example.com", "second task on shop.example.com"]
    assert [event.turn_id for event in starts] == ["s1:t1:aa11", "s1:t1:cc33"]
    assert [len(store.events_for_episode(record.episode_id)) for record in records[::-1]] == [3, 2]


def test_the_hermes_0_13_payload_still_gives_one_episode_per_turn(capture_home) -> None:
    """hermes-agent 0.13.0 passes no ``turn_id`` / ``task_id`` to ``pre_llm_call`` and no ``turn_id`` /
    ``status`` to ``post_tool_call``."""
    _home, store = capture_home

    def turn_013(message: str) -> None:
        capture_hermes.pre_llm_call(
            session_id="s1",
            user_message=message,
            conversation_history=[],
            is_first_turn=False,
            model="m",
            platform="cli",
            sender_id="",
        )

    def call_013(tool: str, args: dict[str, Any], result: str) -> None:
        capture_hermes.post_tool_call(
            tool_name=tool, args=args, result=result, task_id="", session_id="s1", tool_call_id="call_1", duration_ms=3
        )

    turn_013("first on shop.example.com")
    call_013("browser_navigate", {"url": LOGIN_URL}, nav_result())
    turn_013("second on shop.example.com")
    call_013("browser_click", {"ref": "@e7"}, failed("Failed to click @e7"))
    capture_hermes.post_llm_call(session_id="s1", user_message="second on shop.example.com", assistant_response="ok")

    assert len(store.list_episodes()) == 2
    starts = [event for event in events(store) if event.op == "task_start"]
    assert [event.text for event in starts] == ["first on shop.example.com", "second on shop.example.com"]
    assert all(event.turn_id is None for event in events(store))  # a local turn key is never recorded as an id
    assert [event.result_status for event in calls(store)] == ["claimed_success", "claimed_failure"]


def test_the_task_start_is_the_users_words_in_the_history(capture_home) -> None:
    _home, store = capture_home
    turn()
    navigate()
    end_turn()
    [start] = [event for event in events(store) if event.op == "task_start"]
    assert history.speaks_for_user(start.phase, start.op, start.source, start.actor)

    found = history.episodes_for_sites(store, [SITE], excluded_sites=frozenset(), require_human_text=True)
    [summary] = found.episodes
    assert summary.tasks == (MESSAGE,)
    # B1's turn-start block (another session) quotes it as the user's task.
    block = hooks_history.pre_llm_call(user_message=f"continue on {SITE}", session_id="s2", turn_id="s2:t:1")
    assert block is not None and f'task "{MESSAGE}"' in block["context"]


@pytest.mark.parametrize("platform", ["subagent", "cron"])
def test_a_subagent_or_cron_prompt_is_not_the_users_words(capture_home, platform: str) -> None:
    _home, store = capture_home
    turn("delegated goal written by the parent agent", platform=platform)
    navigate()
    end_turn()
    [start] = [event for event in events(store) if event.op == "task_start"]
    assert start.actor == "agent"
    assert not history.speaks_for_user(start.phase, start.op, start.source, start.actor)
    found = history.episodes_for_sites(store, [SITE], excluded_sites=frozenset(), require_human_text=True)
    assert found.episodes == ()
    turn("correct: a correction typed by an agent", platform=platform, turn_id="s1:t1:zz99")
    assert not [event for event in events(store) if event.phase == "correction"]


def test_a_turn_without_a_text_message_gets_no_task_start(capture_home) -> None:
    _home, store = capture_home
    turn([{"type": "text", "text": "multimodal"}, {"type": "image_url", "image_url": {"url": "data:"}}])
    navigate()
    assert [event.op for event in events(store)] == ["navigate"]


# --- chat corrections --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "body"),
    [
        ("correct: the invoices are under the account menu", "the invoices are under the account menu"),
        ("  CORRECT :  use the account menu", "use the account menu"),
        ("訂正: アカウントメニューから開く", "アカウントメニューから開く"),
        ("訂正\uff1aアカウントメニューから開く", "アカウントメニューから開く"),
    ],
)
def test_a_chat_correction_links_the_last_browser_call(capture_home, message: str, body: str) -> None:
    _home, store = capture_home
    turn()
    navigate(call_id="call_nav")
    call("browser_click", {"ref": "@e7"}, call_id="call_click")
    assert turn(message, turn_id="s1:t1:dd44") is None  # the message reaches the model unchanged
    end_turn(turn_id="s1:t1:dd44")

    [correction] = [event for event in events(store) if event.phase == "correction"]
    click = calls(store)[1]
    assert (correction.source, correction.actor, correction.op, correction.text) == (
        "user_correction",
        "human",
        "other",
        body,
    )
    assert correction.attempt_id == click.attempt_id and (click.attempt_id or "").startswith("call-click-")
    assert correction.episode_id == click.episode_id
    assert (correction.site, correction.turn_id) == (SITE, "s1:t1:dd44")
    assert history.speaks_for_user(correction.phase, correction.op, correction.source, correction.actor)
    [summary] = history.episodes_for_sites(store, [SITE], excluded_sites=frozenset()).episodes
    assert summary.corrections == (body,)
    assert store.episode(click.episode_id).has_correction  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "message", ["correct:   ", "訂正\uff1a", "please correct: this", "corrected: no", "incorrect: x"]
)
def test_messages_that_are_no_correction_record_none(capture_home, message: str) -> None:
    _home, store = capture_home
    turn()
    navigate()
    turn(message, turn_id="s1:t1:ee55")
    assert not [event for event in events(store) if event.phase == "correction"]


def test_a_correction_before_any_browser_call_records_nothing(capture_home) -> None:
    _home, store = capture_home
    turn("correct: nothing to correct yet")
    call("browser_navigate", {"url": LOGIN_URL}, nav_result(), session="s2", turn_id="s2:t:1")  # another session
    turn("correct: still nothing in this session", turn_id="s1:t1:ff66")
    assert not [event for event in events(store) if event.phase == "correction"]


# --- switches, exclusions, gate ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "section",
    [
        {},
        {"enabled": True},
        {"collection_enabled": True},
        {**CAPTURING, "history_enabled": False},
        {**CAPTURING, "history_capture_hermes": False},
    ],
)
def test_switches_off_write_nothing(capture_home, audit_entries, section: dict[str, Any]) -> None:
    home, store = capture_home
    write_config(home, section)
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"})
    turn("correct: nothing is linked", turn_id="s1:t1:gg77")
    assert events(store) == [] and audit_entries == []


def test_chat_corrections_off_keeps_recording_calls(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "history_chat_corrections": False})
    turn()
    navigate()
    turn("correct: not recorded", turn_id="s1:t1:hh88")
    end_turn(turn_id="s1:t1:hh88")
    assert [event.op for event in events(store)] == ["navigate", "task_start"]


def test_an_invalid_excluded_sites_refuses_like_the_receiver(capture_home, audit_entries) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "excluded_sites": "bank.example"})
    turn()
    navigate()
    navigate()
    assert events(store) == []
    assert [(entry["reason"], entry["code"], entry["peer_id"]) for entry in audit_entries] == [
        ("activity.capture_refused", "excluded_sites_invalid", "hermes:default")
    ]


def test_an_excluded_site_is_never_recorded(capture_home) -> None:
    home, store = capture_home
    write_config(home, {**CAPTURING, "excluded_sites": ["bank.example"]})
    turn("pay the bill, then check shop.example.com")
    call("browser_navigate", {"url": "https://www.bank.example/pay"}, nav_result("https://www.bank.example/pay"))
    call("browser_type", {"ref": "@e2", "text": "transfer 500 to Alice"}, ok(element="@e2"))
    assert events(store) == []  # the page host is still the bank's, so the type is refused too
    navigate()
    end_turn()
    assert [event.op for event in events(store)] == ["navigate", "task_start"]  # its first recorded call
    assert "bank.example" not in stored_text(store) and "Alice" not in stored_text(store)


def test_a_gate_refusal_fails_open(capture_home, monkeypatch, audit_entries) -> None:
    _home, store = capture_home

    def refused(_home: Path) -> ActivityStore:
        raise ActivityRefused(refusal("not_armed"))

    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", refused)
    assert turn() is None
    assert navigate() is None
    assert call("browser_click", {"ref": "@e7"}) is None
    assert events(store) == []
    assert [entry["code"] for entry in audit_entries] == ["store_unavailable"]


def test_an_unexpected_error_never_escapes(monkeypatch) -> None:

    def broken(_home: Path) -> ActivityStore:
        raise RuntimeError("boom")

    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", broken)
    turn()
    assert navigate() is None
    monkeypatch.setattr(_history_access, "config", broken)
    assert turn("correct: x") is None
    assert call("browser_click", {"ref": "@e7"}) is None
    assert capture_hermes.post_tool_call(tool_name="browser_click", args="not a mapping", result=object()) is None
    assert capture_hermes.post_tool_call() is None and capture_hermes.pre_llm_call() is None


def test_the_gated_store_bounds_the_lock_wait(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_open_store(home: Path, **kwargs: Any) -> Any:
        seen.update(kwargs, home=home)
        return "store"

    monkeypatch.setattr(_gate, "open_store", fake_open_store)
    assert capture_hermes._gated_store(tmp_path) == "store"
    assert seen == {"home": tmp_path, "busy_timeout_s": capture_hermes.WRITE_BUSY_S}


def test_the_principal_is_local_and_per_profile(tmp_path: Path) -> None:
    root = tmp_path / ".hermes"
    profile = root / "profiles" / "work"
    profile.mkdir(parents=True)
    assert capture_hermes.principal(root) == PeerPrincipal("hermes:default", "hermes", "local", "learning")
    assert capture_hermes.principal(profile).peer_id == "hermes:work"


@pytest.mark.parametrize(
    ("tool_call_id", "expected"),
    [
        ("call-abc123", "call-abc123"),
        ("call_abc123", "call-abc123"),
        ("toolu_01A09q90qw90lq917835lq9", "toolu-01A09q90qw90lq917835lq9"),
    ],
)
def test_attempt_ids_follow_the_tool_call_id(tool_call_id: str, expected: str) -> None:
    assert capture_hermes.attempt_id(tool_call_id) == expected


def test_attempt_ids_that_cannot_be_kept_are_hashed_or_fresh() -> None:
    long_id = "call_" + "x" * 80
    hashed = capture_hermes.attempt_id(long_id)
    assert hashed.startswith("tc-") and hashed == capture_hermes.attempt_id(long_id) and len(hashed) == 35
    assert capture_hermes.attempt_id("_leading").startswith("tc-")
    assert capture_hermes.attempt_id("") != capture_hermes.attempt_id("")
    assert capture_hermes.attempt_id(None) != capture_hermes.attempt_id(None)


# --- failure behavior: slow writes, a concurrent writer ------------------------------------------------------


def test_three_slow_writes_suspend_the_session(capture_home, monkeypatch, audit_entries) -> None:
    _home, store = capture_home
    opened: list[str] = []

    def slow(_home: Path) -> ActivityStore:
        opened.append("open")
        time.sleep(0.03)
        return store

    monkeypatch.setattr(capture_hermes, "SLOW_APPEND_S", 0.01)
    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", slow)
    turn()
    navigate()
    call("browser_click", {"ref": "@e7"})
    call("browser_click", {"ref": "@e7"})
    assert len(opened) == 3
    call("browser_click", {"ref": "@e7"})
    turn("correct: not recorded while suspended", turn_id="s1:t1:ii99")
    assert len(opened) == 3  # suspended: nothing more is attempted for this session (the held task start too)
    assert [event.op for event in events(store)] == ["navigate", "click", "click"]
    [entry] = audit_entries
    assert entry == {
        "event": "activity_capture",
        "decision": "refuse",
        "reason": "activity.capture_suspended",
        "code": "slow_append",
        "peer_id": "hermes:default",
    }
    navigate(session="s2", turn_id="s2:t:1")  # another session still records
    assert len(opened) == 4


def test_a_write_blocked_by_another_writer_is_dropped_quickly(capture_home) -> None:
    _home, store = capture_home
    holder = sqlite3.connect(store.path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")  # the extension gateway's receiver in the middle of a batch
    try:
        turn()
        started = time.monotonic()
        assert navigate() is None
        elapsed = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()
    assert elapsed < 1.5  # bounded by WRITE_BUSY_S, not the store's 2 s default
    assert events(store) == []
    call("browser_click", {"ref": "@e7"})
    end_turn()
    assert [event.op for event in events(store)] == ["click", "task_start"]  # the first recorded call's episode


def test_capture_and_the_gateway_receiver_write_concurrently(capture_home) -> None:
    home, store = capture_home
    receiver = StoreReceiver(home, config_loader=_history_access.config, store_factory=lambda _home: store)
    operator = PeerPrincipal("operator:peer-a", "operator")
    replies: list[str] = []
    errors: list[BaseException] = []

    def gateway() -> None:
        try:
            for index in range(20):
                event = {
                    "event_id": str(uuid.uuid4()),
                    "seq": index + 1,
                    "episode_id": "op-episode",
                    "source": "operator",
                    "actor": "agent",
                    "observed_at": time.time(),
                    "phase": "observed",
                    "action": {"op": "navigate", "site": "other.example", "route": f"/p{index}"},
                }
                batch = {"schema_version": 1, "producer_id": "prod-op", "producer_kind": "operator", "events": [event]}
                replies.append(str(receiver.ingest(operator, batch)["type"]))
        except BaseException as exc:  # pragma: no cover - the assertion below reports it
            errors.append(exc)

    worker = threading.Thread(target=gateway)
    turn()
    worker.start()
    for _ in range(20):
        assert call("browser_scroll", {"direction": "down"}) is None
    worker.join(timeout=30)
    assert not errors and not worker.is_alive()
    stored = events(store)
    operator_events = [event for event in stored if event.source == "operator"]
    assert len(operator_events) == replies.count("activity_ack")
    assert 0 < len([event for event in stored if event.source == "hermes"]) <= 21


# --- registration -------------------------------------------------------------------------------------------


def test_registration_never_reads_configuration(monkeypatch) -> None:
    class Ctx:
        def __init__(self) -> None:
            self.hooks: list[tuple[str, Any]] = []

        def register_hook(self, name: str, fn: Any) -> None:
            self.hooks.append((name, fn))

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("registration must not read configuration or open the store")

    monkeypatch.setattr(_history_access, "config", forbidden)
    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", forbidden)
    ctx = Ctx()
    capture_hermes.register_hooks(ctx)
    assert ctx.hooks == [
        ("post_tool_call", capture_hermes.post_tool_call),
        ("pre_llm_call", capture_hermes.pre_llm_call),
        ("post_llm_call", capture_hermes.post_llm_call),
    ]
