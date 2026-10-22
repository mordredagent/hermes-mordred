"""History hooks: navigation block in browser results, turn-start context, master switch, fail-open."""

from __future__ import annotations

import json
import os
import time
import types
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _history_access, history
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.hooks_history import RESULT_KEY, pre_llm_call, transform_tool_result
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
from mordred_hermes.activity.tools import browser_history, browser_history_episode
from tests._activity_history_helpers import (
    CORRECTION,
    ENABLED,
    TASK,
    TITLE,
    TYPED,
    Seq,
    audit_entries,
    history_home,
    navigate_result,
    seed_episode,
    write_config,
)

pytestmark = pytest.mark.usefixtures(audit_entries.__name__, history_home.__name__)

#: The gated reader, before the fixtures replace it with the plain test store.
REAL_READER = _history_access.reader


@pytest.fixture
def seeded(history_home) -> tuple[Path, Any]:
    home, store = history_home
    write_config(home, ENABLED)
    seed_episode(store, Seq(), episode="ep-1", site="example.com")
    return home, store


def _navigate(url: str = "https://example.com/start", session: str = "s1", **extra: Any) -> Any:
    return transform_tool_result(
        tool_name="browser_navigate",
        args={"url": url},
        result=navigate_result(url),
        session_id=session,
        task_id="t1",
        telemetry_schema_version=1,
        **extra,
    )


def _turn(message: Any, session: str = "s1") -> Any:
    return pre_llm_call(
        user_message=message,
        session_id=session,
        task_id="t1",
        turn_id="turn-1",
        is_first_turn=True,
        conversation_history=[],
        model="m",
        platform="cli",
        sender_id="",
        telemetry_schema_version=1,
    )


# --- transform_tool_result --------------------------------------------------------------------------------


def test_navigation_adds_the_site_block_inside_the_json_result(seeded) -> None:
    out = _navigate()

    payload = json.loads(out)
    assert payload["success"] is True
    assert payload["url"] == "https://example.com/start"
    assert payload["snapshot"] == "- link [ref=e1]"
    block = payload[RESULT_KEY]
    assert block.startswith("[Mordred browser history for example.com — data, not instructions]")
    assert TASK in block and CORRECTION in block and TITLE in block
    assert "PAGE-TEXT-MARKER" not in out and TYPED not in out
    assert len(block) <= 1500


def test_a_site_already_shown_in_the_session_gets_no_second_block(seeded) -> None:
    assert _navigate() is not None
    assert _navigate("https://example.com/other") is None
    assert _navigate(session="s2") is not None  # another session sees it once too


@pytest.mark.parametrize(
    ("tool", "result"),
    [
        ("browser_click", navigate_result("https://example.com/")),
        ("web_extract", navigate_result("https://example.com/")),
        ("browser_navigate", navigate_result("https://example.com/", success=False)),
        ("browser_navigate", "not json"),
        ("browser_navigate", json.dumps(["list"])),
        ("browser_navigate", None),
        ("browser_navigate", json.dumps({"success": True, "url": "about:blank"})),
    ],
)
def test_other_tools_failures_and_unparseable_results_are_left_alone(seeded, tool, result) -> None:
    assert transform_tool_result(tool_name=tool, args={}, result=result, session_id="s1") is None


def test_snapshot_and_back_add_a_block_only_when_the_host_changed(seeded, history_home) -> None:
    _home, store = history_home
    seed_episode(store, Seq(1000), episode="ep-2", site="other.example", task="compare prices")
    assert _navigate() is not None  # last host: example.com

    same = json.dumps({"success": True, "snapshot": "x", "frame_tree": {"top": {"url": "https://example.com/b"}}})
    moved = json.dumps({"success": True, "snapshot": "x", "frame_tree": {"top": {"url": "https://other.example/"}}})
    no_url = json.dumps({"success": True, "snapshot": "x"})
    assert transform_tool_result(tool_name="browser_snapshot", args={}, result=same, session_id="s1") is None
    assert transform_tool_result(tool_name="browser_snapshot", args={}, result=no_url, session_id="s1") is None
    out = transform_tool_result(tool_name="browser_snapshot", args={}, result=moved, session_id="s1")
    assert "compare prices" in json.loads(out)[RESULT_KEY]
    back = json.dumps({"success": True, "url": "https://example.com/start"})
    # Host changed back, but everything about example.com was already shown.
    assert transform_tool_result(tool_name="browser_back", args={}, result=back, session_id="s1") is None


def test_excluded_host_gets_nothing(seeded) -> None:
    home, _store = seeded
    write_config(home, {**ENABLED, "excluded_sites": ["example.com"]})
    assert _navigate() is None


@pytest.mark.parametrize(
    "section",
    [
        {},  # feature disabled (default)
        {"enabled": True, "history_enabled": False},
        {"enabled": True, "history_on_navigate": False},
        {"enabled": True, "history_session_budget_chars": 0},
    ],
)
def test_switches_and_budget_gate_the_navigation_block(seeded, section) -> None:
    home, _store = seeded
    write_config(home, section)
    assert _navigate() is None


def test_session_budget_caps_the_injected_characters(history_home) -> None:
    home, store = history_home
    write_config(home, {**ENABLED, "history_session_budget_chars": 700, "history_max_episodes": 1})
    seq = Seq()
    for index in range(4):
        seed_episode(store, seq, episode=f"ep-{index}", site=f"site{index}.example")

    blocks = [_navigate(f"https://site{index}.example/") for index in range(4)]

    injected = [json.loads(out)[RESULT_KEY] for out in blocks if out is not None]
    assert injected
    assert sum(len(block) for block in injected) <= 700
    assert blocks[-1] is None


# --- pre_llm_call -----------------------------------------------------------------------------------------


def test_turn_context_for_a_named_host_holds_only_human_text_and_metadata(seeded) -> None:
    out = _turn("Please open https://example.com/billing and get the October invoice")

    assert set(out) == {"context"}
    context = out["context"]
    assert context.startswith(history.TURN_HEADER)
    assert TASK in context and CORRECTION in context and "example.com" in context
    for forbidden in (TITLE, "PAGE-TEXT-MARKER", TYPED, "qvalue123"):
        assert forbidden not in context


def test_turn_context_from_shared_task_terms(seeded) -> None:
    out = _turn("can you open the invoices page again?")
    assert out is not None and TASK in out["context"]


def test_unrelated_messages_and_repeats_get_no_context(seeded) -> None:
    assert _turn("what is the weather like") is None
    assert _turn("open the invoices page") is not None
    assert _turn("open the invoices page") is None  # already shown in this session


@pytest.mark.parametrize("message", [None, "", "   ", [{"type": "text", "text": "open the invoices page"}]])
def test_non_text_or_empty_messages_get_no_context(seeded, message) -> None:
    assert _turn(message) is None


@pytest.mark.parametrize(
    "section",
    [
        {},
        {"enabled": True, "history_enabled": False},
        {"enabled": True, "history_turn_context": False},
    ],
)
def test_switches_gate_the_turn_context(seeded, section) -> None:
    home, _store = seeded
    write_config(home, section)
    assert _turn("open the invoices page on example.com") is None


def test_master_switch_applies_on_the_next_turn_without_restart(seeded) -> None:
    home, _store = seeded
    write_config(home, {**ENABLED, "history_enabled": False})
    assert _turn("open the invoices page") is None

    write_config(home, {**ENABLED, "history_enabled": True})
    stat = (home / "config.yaml").stat()
    os.utime(home / "config.yaml", ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    assert _turn("open the invoices page") is not None


def test_config_is_read_once_per_file_version(seeded, monkeypatch) -> None:
    from mordred_hermes.activity.config import ActivityConfig

    loads: list[Path] = []
    original = ActivityConfig.load

    def counting(home: Path) -> ActivityConfig:
        loads.append(home)
        return original(home)

    monkeypatch.setattr(ActivityConfig, "load", staticmethod(counting))
    home, _store = seeded
    for _ in range(3):
        _history_access.config(home)
    assert len(loads) == 1


# --- fail open --------------------------------------------------------------------------------------------


def test_gate_refusal_fails_open_and_is_audited_once_per_code(seeded, monkeypatch, audit_entries) -> None:
    codes = iter(["not_armed", "not_armed", "no_key"])

    def refusing(_home: Path) -> Any:
        raise ActivityRefused(refusal(next(codes)))

    monkeypatch.setattr(_history_access, "reader", refusing)
    assert _navigate() is None
    assert _turn("open the invoices page") is None
    assert _navigate(session="s3") is None

    assert audit_entries == [
        {"event": "activity_history", "decision": "refuse", "reason": "activity.history_unavailable", "code": code}
        for code in ("not_armed", "no_key")
    ]


def test_the_real_reader_runs_the_protection_gate_first(seeded, monkeypatch, audit_entries) -> None:
    monkeypatch.setattr(_history_access, "reader", REAL_READER)
    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", lambda _h: refusal("no_key"))
    opened: list[Path] = []
    monkeypatch.setattr("mordred_hermes.activity._gate.open_store", lambda h, **_: opened.append(h))

    assert _navigate() is None
    assert opened == []
    assert [entry["code"] for entry in audit_entries] == ["no_key"]


def _real_reader_on(monkeypatch, store, *, plaintext: bool = False) -> None:
    """The real reader over the plain test store: gate passed, keyed opener replaced by the test opener."""
    monkeypatch.setattr(_history_access, "reader", REAL_READER)
    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", lambda _h: None)
    monkeypatch.setattr("mordred_hermes.activity._history_access.STORE_NAME", store.path.name)
    monkeypatch.setattr("mordred_hermes.activity._history_access.PLUGIN_DATA_SUBPATH", ())
    monkeypatch.setattr("mordred_hermes.activity._history_access._plaintext", lambda _p: plaintext)
    monkeypatch.setattr(_history_access, "OPENER", store._opener)


def test_the_real_reader_opens_read_only_after_the_gate(seeded, monkeypatch) -> None:
    home, store = seeded
    _real_reader_on(monkeypatch, store)
    monkeypatch.setattr("mordred_hermes.activity._gate.open_store", lambda *_a, **_k: pytest.fail("never opened"))
    before = store.path.stat().st_mtime_ns

    opened = REAL_READER(home)

    assert opened.path == store.path
    assert store.path.stat().st_mtime_ns == before  # nothing was written (no initialize, no migration)
    assert _navigate() is not None


def test_the_real_reader_refuses_a_plaintext_file(seeded, monkeypatch) -> None:
    home, store = seeded
    _real_reader_on(monkeypatch, store, plaintext=True)
    with pytest.raises(ActivityRefused) as refused:
        REAL_READER(home)
    assert refused.value.code == "plaintext_store"


@pytest.mark.parametrize(
    ("meta", "code"),
    [
        ({"profile_home": "/elsewhere"}, "profile_mismatch"),
        ({"schema_version": "99"}, "schema_newer"),
        ({"schema_version": "1"}, "store_unavailable"),
    ],
)
def test_the_real_reader_checks_binding_and_schema(seeded, monkeypatch, meta, code) -> None:
    home, store = seeded
    _real_reader_on(monkeypatch, store)
    with store.connection() as conn:
        for key, value in meta.items():
            conn.execute("UPDATE activity_meta SET value = ? WHERE key = ?", (value, key))
    with pytest.raises(ActivityRefused) as refused:
        REAL_READER(home)
    assert refused.value.code == code


def test_a_refusal_keeps_the_store_untouched_for_a_while(seeded, monkeypatch, audit_entries) -> None:
    home, store = seeded
    _real_reader_on(monkeypatch, store)
    calls: list[Path] = []

    def refusing(h: Path) -> Any:
        calls.append(h)
        return refusal("no_key")

    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", refusing)
    assert _navigate() is None
    assert _navigate(session="s2") is None
    assert len(calls) == 1  # the second call did not even run the gate

    _history_access.forget(home)
    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", lambda _h: None)
    assert _navigate(session="s3") is not None
    assert [entry["code"] for entry in audit_entries] == ["no_key"]


def test_cached_refusals_never_postpone_the_next_attempt(seeded, monkeypatch, audit_entries) -> None:
    home, store = seeded
    _real_reader_on(monkeypatch, store)
    clock = [1000.0]
    monkeypatch.setattr(_history_access, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    calls: list[Path] = []

    def refusing(h: Path) -> Any:
        calls.append(h)
        return refusal("no_key")

    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", refusing)
    key = os.path.realpath(home)

    assert _navigate() is None  # a real attempt, refused: the deadline is 1060
    for index, now in enumerate((1030.0, 1050.0, 1059.9)):
        clock[0] = now
        assert _navigate(session=f"cached-{index}") is None
        assert _turn("open the invoices page", session=f"turn-{index}") is None
        assert _history_access._retry[key][0] == 1000.0 + _history_access.RETRY_AFTER_S
    assert len(calls) == 1

    clock[0] = 1060.0
    assert _navigate(session="after-deadline") is None
    assert len(calls) == 2  # retried on time although calls kept coming every few seconds
    assert _history_access._retry[key][0] == 1060.0 + _history_access.RETRY_AFTER_S
    assert [entry["code"] for entry in audit_entries] == ["no_key"]


@pytest.mark.parametrize("error", [RuntimeError("boom"), OSError("disk"), KeyError("x")])
def test_any_exception_in_the_store_path_fails_open(seeded, monkeypatch, audit_entries, error) -> None:
    def broken(_home: Path) -> Any:
        raise error

    monkeypatch.setattr(_history_access, "reader", broken)
    assert _navigate() is None
    assert _turn("open the invoices page") is None
    expected = "store_unavailable" if isinstance(error, OSError) else "internal_error"
    assert [entry["code"] for entry in audit_entries] == [expected]


def test_exceptions_before_the_store_never_escape_the_hooks(seeded, monkeypatch) -> None:
    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("config exploded")

    monkeypatch.setattr(_history_access, "config", explode)
    assert _navigate() is None
    assert _turn("open the invoices page") is None


def test_a_missing_store_is_quietly_no_history(seeded, monkeypatch, audit_entries) -> None:
    def missing(_home: Path) -> Any:
        raise _history_access.NoHistory

    monkeypatch.setattr(_history_access, "reader", missing)
    assert _navigate() is None
    assert _turn("open the invoices page") is None
    assert audit_entries == []


def test_reader_without_a_store_file_raises_no_history(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", lambda _h: None)
    with pytest.raises(_history_access.NoHistory):
        REAL_READER(tmp_path)
    assert not (tmp_path / "plugin-data").exists()


# --- registration -----------------------------------------------------------------------------------------


class _Ctx:
    def __init__(self) -> None:
        self.hooks: list[tuple[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self.skills: list[tuple[str, Path]] = []

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks.append((name, callback))

    def register_tool(self, **kwargs: Any) -> None:
        self.tools.append(kwargs)

    def register_skill(self, name: str, path: Path, description: str = "") -> None:
        assert description
        self.skills.append((name, path))


def test_register_wires_hooks_tools_and_skill_without_reading_anything(monkeypatch) -> None:
    from mordred_hermes import activity

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("registration must not read configuration or open the store")

    monkeypatch.setattr(_history_access, "config", forbidden)
    monkeypatch.setattr(_history_access, "reader", forbidden)
    ctx = _Ctx()

    activity.register(ctx)

    from mordred_hermes.activity import capture_hermes

    # The capture hooks come last: a turn's history block is read before that turn's correction is stored.
    assert ctx.hooks == [
        ("transform_tool_result", transform_tool_result),
        ("pre_llm_call", pre_llm_call),
        ("post_tool_call", capture_hermes.post_tool_call),
        ("pre_llm_call", capture_hermes.pre_llm_call),
        ("post_llm_call", capture_hermes.post_llm_call),
    ]
    assert [tool["name"] for tool in ctx.tools] == ["mordred_browser_history", "mordred_browser_history_episode"]
    assert {tool["toolset"] for tool in ctx.tools} == {"mordred_activity"}
    [(name, path)] = ctx.skills
    assert name == "browser-history" and path.is_file()


# --- review follow-ups ------------------------------------------------------------------------------------


def test_turn_context_needs_human_text_and_ignores_host_labels(history_home) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seed_episode(
        store, Seq(), episode="ep-passive", site="monthly-report-invoices.evil.example", task=None, correction=None
    )

    assert _turn("please continue the monthly report invoices") is None
    assert _turn("open monthly-report-invoices.evil.example") is None
    # The navigation block (inside Hermes's untrusted wrapper) may still show the visit.
    assert _navigate("https://monthly-report-invoices.evil.example/") is not None


def test_navigation_block_is_for_the_exact_host_only(history_home) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seed_episode(store, Seq(), episode="ep-sub", site="user.github.io")
    assert _navigate("https://github.io/") is None
    assert _navigate("https://user.github.io/") is not None


@pytest.mark.parametrize("raw", ["bank.example", ["ok.example", ""], ["not a host"]])
def test_invalid_exclusions_switch_every_surface_off(seeded, raw) -> None:
    home, _store = seeded
    write_config(home, {**ENABLED, "excluded_sites": raw})
    assert _navigate() is None
    assert _turn("open the invoices page") is None


def test_normalized_exclusions_apply(seeded) -> None:
    home, _store = seeded
    write_config(home, {**ENABLED, "excluded_sites": ["https://Example.com/", "*.other.example"]})
    assert _navigate() is None
    assert _turn("open the invoices page on example.com") is None


@pytest.mark.parametrize("tool_name", [["browser_navigate"], {"a": 1}, 7, None])
def test_odd_tool_names_never_raise(seeded, tool_name) -> None:
    assert transform_tool_result(tool_name=tool_name, args={}, result="{}", session_id="s1") is None


# --- the live finding: a password in the operator's task text ------------------------------------------------


def test_the_live_password_never_reaches_the_store_the_turn_block_or_a_tool(history_home) -> None:
    home, store = history_home
    write_config(home, {"enabled": True, "collection_enabled": True})
    receiver = StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=lambda _home: store)
    live = "Log in with the username demo-user and the password Hunter2-fake-pw"
    base = {"episode_id": "ep-live", "source": "operator", "quality": {"coverage": "selected_tab"}}
    events = [
        {
            **base,
            "event_id": "ev-live-1",
            "seq": 1,
            "actor": "human",
            "observed_at": time.time() - 60,
            "phase": "boundary",
            "action": {"op": "task_start", "site": "example.com"},
            "text": live,
        },
        {
            **base,
            "event_id": "ev-live-2",
            "seq": 2,
            "actor": "agent",
            "observed_at": time.time() - 50,
            "phase": "observed",
            "attempt_id": "att-live",
            "action": {"op": "navigate", "site": "example.com", "route": "/login"},
            "page_title": "Sign in",
        },
    ]
    batch = {"schema_version": 1, "producer_id": "prod-live", "producer_kind": "operator", "events": events}

    reply = receiver.ingest(PeerPrincipal(peer_id="operator:0123456789ab", kind="operator"), batch)

    assert reply["type"] == "activity_ack"
    with store.connection() as conn:
        rows = conn.execute("SELECT * FROM activity_events").fetchall()
        [(text, exclusions)] = conn.execute(
            "SELECT text, exclusions FROM activity_events WHERE event_id = 'ev-live-1'"
        ).fetchall()
    assert text == "Log in with the username demo-user and the password redacted"
    assert "text_secrets_redacted" in json.loads(exclusions)
    assert "Hunter2-fake-pw" not in repr(rows)

    block = _turn("what did I do on example.com yesterday?")["context"]
    assert 'task "Log in with the username demo-user and the password redacted"' in block
    lookup = browser_history({"query": "log in demo-user"}, session_id="s-tool", task_id="t1")
    episode = browser_history_episode({"episode_id": "ep-live"}, session_id="s-tool", task_id="t1")
    for shown in (block, lookup, episode):
        assert "Hunter2-fake-pw" not in shown
        assert "the password redacted" in shown
