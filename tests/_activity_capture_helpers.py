"""Shared fixtures and recorded hermes-agent 0.19.0 payloads for the Hermes capture tests."""

from __future__ import annotations

import json
import sqlite3
import types
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _capture_audit, _history_access, capture_hermes, hooks_history
from mordred_hermes.activity.contracts import NormalizedEvent
from mordred_hermes.activity.store import ActivityStore
from mordred_hermes.privacy_check import _runtime
from tests._activity_episode_helpers import plain_opener
from tests._activity_history_helpers import write_config

__all__ = [
    "CAPTURING",
    "LOGIN_URL",
    "MESSAGE",
    "SITE",
    "SNAPSHOT",
    "audit_entries",
    "call",
    "calls",
    "capture_home",
    "events",
    "failed",
    "nav_result",
    "navigate",
    "ok",
    "stored_text",
    "turn",
    "write_config",
]

SITE = "shop.example.com"
LOGIN_URL = f"https://{SITE}/login?next=%2Faccount"
MESSAGE = "open my order history on shop.example.com"
#: An agent-browser accessibility snapshot as ``browser_navigate`` / ``browser_snapshot`` return it.
SNAPSHOT = "\n".join(
    [
        '- heading "Sign in" [ref=e1] [level=1]',
        '- textbox "Email" [ref=e2]',
        '- textbox "Password" [ref=e3]',
        '- textbox "パスワード\uff08確認\uff09" [ref=e4]',
        "- textbox [ref=e5]",
        '- textbox "Search orders" [ref=e6]: last month',
        '- button "Sign in" [ref=e7]',
        '- link "Forgot your PIN?" [ref=e8]',
        '- textbox "カード番号" [ref=e9]',
        '- textbox "One-time code" [ref=e10]',
        '- textbox "氏名" [ref=e11]',
    ]
)
CAPTURING: dict[str, Any] = {"enabled": True, "collection_enabled": True}


# --- recorded hermes-agent 0.19.0 browser tool results (tools/browser_tool.py) -------------------------------


def nav_result(url: str = LOGIN_URL, *, title: str = "Sign in — Shop", snapshot: str = SNAPSHOT) -> str:
    return json.dumps(
        {"success": True, "url": url, "title": title, "snapshot": snapshot, "element_count": 11}, ensure_ascii=False
    )


def ok(**fields: Any) -> str:
    return json.dumps({"success": True, **fields}, ensure_ascii=False)


def failed(error: str) -> str:
    return json.dumps({"success": False, "error": error}, ensure_ascii=False)


# --- fixtures ----------------------------------------------------------------------------------------------


@pytest.fixture
def capture_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, ActivityStore]]:
    """A profile home with a plain-SQLite store behind the capture's store seam and the history reader."""
    home = tmp_path / "home"
    home.mkdir()
    store = ActivityStore(home / "mordred.db", plain_opener, busy_timeout_s=capture_hermes.WRITE_BUSY_S)
    store.initialize(home)
    write_config(home, CAPTURING)
    monkeypatch.setattr(_history_access, "home", lambda: home)
    monkeypatch.setattr(_history_access, "reader", lambda _home: store)
    monkeypatch.setattr(_history_access, "_configs", {})
    monkeypatch.setattr(_history_access, "_retry", {})
    monkeypatch.setattr(_history_access, "BUDGET", type(_history_access.BUDGET)())
    monkeypatch.setattr(hooks_history, "_last_hosts", type(hooks_history._last_hosts)())
    monkeypatch.setattr(capture_hermes, "STORE_FACTORY", lambda _home: store)
    monkeypatch.setattr(capture_hermes, "_sessions", type(capture_hermes._sessions)())
    yield home, store


@pytest.fixture
def audit_entries(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    monkeypatch.setattr(_capture_audit, "_EMITTED", set())
    monkeypatch.setattr(_capture_audit, "_HISTORY_EMITTED", set())
    monkeypatch.setattr(_capture_audit, "_SUSPENDED", [0])
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(_runtime, "ensure_state", lambda: types.SimpleNamespace(audit=object()))
    monkeypatch.setattr(
        _capture_audit, "safe_audit_append", lambda audit, entry, *, logger: entries.append(dict(entry))
    )
    return entries


def turn(message: Any = MESSAGE, *, session: str = "s1", turn_id: str = "s1:t1:aa11", **extra: Any) -> Any:
    """``pre_llm_call`` with the hermes-agent 0.19.0 payload (``agent/turn_context.py``)."""
    payload: dict[str, Any] = {
        "session_id": session,
        "task_id": "t1",
        "turn_id": turn_id,
        "user_message": message,
        "conversation_history": [],
        "is_first_turn": True,
        "model": "m",
        "platform": "cli",
        "sender_id": "",
        "telemetry_schema_version": 1,
    }
    payload.update(extra)
    return capture_hermes.pre_llm_call(**payload)


def call(
    tool: str,
    args: dict[str, Any] | None = None,
    result: Any = None,
    *,
    session: str = "s1",
    turn_id: str = "s1:t1:aa11",
    call_id: str | None = None,
    status: str | None = "ok",
) -> Any:
    """``post_tool_call`` with the hermes-agent 0.19.0 payload (``model_tools._emit_post_tool_call_hook``)."""
    return capture_hermes.post_tool_call(
        tool_name=tool,
        args=args or {},
        result=result if result is not None else ok(),
        task_id="t1",
        session_id=session,
        tool_call_id=call_id or f"call_{uuid.uuid4().hex[:8]}",
        turn_id=turn_id,
        api_request_id="req-1",
        duration_ms=12,
        status=status,
        error_type=None,
        error_message=None,
        middleware_trace=[],
        telemetry_schema_version=1,
    )


def events(store: ActivityStore) -> list[NormalizedEvent]:
    return [event for record in store.list_episodes(100)[::-1] for event in store.events_for_episode(record.episode_id)]


def calls(store: ActivityStore) -> list[NormalizedEvent]:
    return [event for event in events(store) if event.phase != "boundary"]


def stored_text(store: ActivityStore) -> str:
    with sqlite3.connect(store.path) as conn:
        rows = conn.execute("SELECT * FROM activity_events").fetchall()
    return json.dumps(rows, ensure_ascii=False, default=str)


def navigate(url: str = LOGIN_URL, **kwargs: Any) -> Any:
    return call("browser_navigate", {"url": url}, nav_result(url), **kwargs)
