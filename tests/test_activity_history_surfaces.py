"""Every history surface (navigation block, turn-start context, both lookup tools) after the B1 security review.

- Read-time exclusion looks at every host an episode names: its events' sites and the URLs in their route,
  query and target label, so a host added to ``excluded_sites`` after capture hides the episode everywhere.
- Only text the collector attributes to the user is shown as the user's task or correction.
- Rows stored before a URL rule existed are scrubbed again when shown.
- A writer's lock refuses a read within the read bound, opening included.
"""

from __future__ import annotations

import json
import sqlite3
import time
import types
from typing import Any

import pytest

from mordred_hermes.activity import _history_access, contracts, history
from mordred_hermes.activity._gate import ActivityRefused
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.hooks_history import RESULT_KEY, pre_llm_call, transform_tool_result
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
from mordred_hermes.activity.tools import browser_history, browser_history_episode
from tests._activity_episode_helpers import PEER, PRODUCER
from tests._activity_history_helpers import (
    CORRECTION,
    ENABLED,
    TASK,
    Seq,
    audit_entries,
    event,
    history_home,
    navigate_result,
    seed_episode,
    write_config,
)

pytestmark = pytest.mark.usefixtures(audit_entries.__name__, history_home.__name__)

#: The gated reader, before the fixtures replace it with the plain test store.
REAL_READER = _history_access.reader
NAMED_TASK = "settle the utility bill NAMEDMARKER"
MARKER = "ATTRIBUTIONMARKER"


def _navigate(session: str, url: str = "https://example.com/start") -> Any:
    return transform_tool_result(
        tool_name="browser_navigate", args={"url": url}, result=navigate_result(url), session_id=session, task_id="t"
    )


def _turn(message: str, session: str) -> Any:
    return pre_llm_call(user_message=message, session_id=session, task_id="t")


def _framed(result: str) -> dict[str, Any]:
    return json.loads(result.split("\n")[2])


def _lookup(session: str, **args: Any) -> dict[str, Any]:
    return _framed(browser_history(args, session_id=session))


def _episode(episode_id: str, session: str) -> str:
    return browser_history_episode({"episode_id": episode_id}, session_id=session)


def _surfaces(episode_id: str, tag: str) -> dict[str, str]:
    """What each surface returns for example.com, one fresh session each (``tag`` keeps the sessions apart)."""
    nav = _navigate(f"{tag}-nav")
    turn = _turn("open the invoices page on example.com again", f"{tag}-turn")
    return {
        "navigation": json.loads(nav)[RESULT_KEY] if nav else "",
        "turn": turn["context"] if turn else "",
        "lookup": json.dumps(_lookup(f"{tag}-lookup", query="", site="example.com")),
        "lookup_terms": json.dumps(_lookup(f"{tag}-terms", query=NAMED_TASK)),
        "episode": _episode(episode_id, f"{tag}-episode"),
    }


# --- read-time exclusion over every host an episode names -------------------------------------------------


NAMED_ELSEWHERE = {
    "route URL query": {
        "action": {"op": "navigate", "site": "example.com", "route": "/login?next=https://bank.example/x"}
    },
    "encoded query value": {
        "action": {"op": "navigate", "site": "example.com", "route": "/out"},
        "query": "?u=https%3A%2F%2Feu.bank.example%2Fpay",
    },
    "target label": {
        "action": {"op": "click", "site": "example.com", "route": "/links", "target": "https://bank.example/pay"}
    },
}


@pytest.mark.parametrize("where", sorted(NAMED_ELSEWHERE))
def test_an_exclusion_added_after_capture_hides_an_episode_naming_the_host_anywhere(history_home, where) -> None:
    home, store = history_home
    seq = Seq()
    seed_episode(store, seq, episode="ep-clean", site="example.com", age_s=7200)
    seed_episode(store, seq, episode="ep-named", site="example.com", task=NAMED_TASK, correction=None)
    extra = NAMED_ELSEWHERE[where]
    store.append_batch(PEER, PRODUCER, [event(seq(), "ep-named", at=time.time() - 60, phase="observed", **extra)])
    with store.connection() as conn:  # captured while nothing was excluded: the host is only in route/query/target
        assert conn.execute("SELECT DISTINCT site FROM activity_events").fetchall() == [("example.com",)]

    write_config(home, ENABLED)
    before = _surfaces("ep-named", "before")
    assert all("NAMEDMARKER" in text for text in before.values()), before

    write_config(home, {**ENABLED, "excluded_sites": ["bank.example"]})
    after = _surfaces("ep-named", "after")
    assert not any("NAMEDMARKER" in text for text in after.values()), after
    assert json.loads(after["episode"]) == {"status": "not_found"}
    assert TASK in after["navigation"] and TASK in after["turn"]  # the clean episode still shows
    assert (
        history.latest_page_text(store, ["ep-named"], "example.com", 600, excluded_sites=frozenset({"bank.example"}))
        == {}
    )


def test_the_host_check_reads_nothing_without_exclusions() -> None:
    class NoReads:
        def execute(self, *_args: Any) -> Any:
            raise AssertionError("no query without exclusions")

    assert history._hidden(NoReads(), ["ep-1"], {"ep-1": ["bank.example"]}, frozenset()) == set()  # type: ignore[arg-type]


def test_excluded_sites_are_checked_on_site_rows_without_reading_urls(history_home) -> None:
    _home, store = history_home
    seed_episode(store, Seq(), episode="ep-bank", site="bank.example")
    with store.connection() as conn:
        assert history._hidden(conn, ["ep-bank"], {"ep-bank": ["bank.example"]}, frozenset({"bank.example"})) == {
            "ep-bank"
        }


# --- which text speaks for the user -----------------------------------------------------------------------


ATTRIBUTIONS = [
    # (phase, op, source, actor, the user's own words?)
    ("boundary", "task_start", "operator", "human", True),
    ("boundary", "task_start", "browser", "human", True),
    ("boundary", "task_start", "operator", "agent", False),
    ("boundary", "task_start", "operator", "unknown", False),
    ("boundary", "task_end", "operator", "human", False),
    ("correction", "other", "user_correction", "human", True),
    ("correction", "other", "user_correction", "agent", False),
    ("correction", "other", "user_correction", "unknown", False),
    ("correction", "other", "operator", "human", False),
    ("correction", "other", "hermes", "agent", False),
]


@pytest.mark.parametrize(("phase", "op", "source", "actor", "own"), ATTRIBUTIONS)
def test_only_text_attributed_to_the_user_is_shown_as_theirs(history_home, phase, op, source, actor, own) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seq = Seq()
    seed_episode(store, seq, episode="ep-1", task=None, correction=None)
    text = f"{MARKER} invoices page example"
    store.append_batch(
        PEER,
        PRODUCER,
        [
            event(
                seq(),
                "ep-1",
                at=time.time() - 30,
                phase=phase,
                source=source,
                actor=actor,
                text=text,
                action={"op": op, "site": "example.com"},
            )
        ],
    )

    assert history.speaks_for_user(phase, op, source, actor) is own
    with store.connection() as conn:  # the SQL rule and the Python rule agree
        hits = conn.execute(f"SELECT COUNT(*) FROM activity_events WHERE {history.USER_TEXT_SQL}").fetchone()[0]
    assert hits == int(own)
    [summary] = history.episodes_for_site(store, "example.com", excluded_sites=frozenset()).episodes
    assert (MARKER in " ".join(summary.tasks + summary.corrections)) is own

    turn = _turn("invoices page example.com", "turn")
    assert (turn is not None and MARKER in turn["context"]) is own  # without the user's words: no turn block
    nav = json.loads(_navigate("nav"))[RESULT_KEY]
    labelled = f'task "{text}"' in nav or f'user correction: "{text}"' in nav
    assert labelled is own and (MARKER in nav) is own

    [record] = _lookup("lookup", query="", site="example.com")["episodes"]
    assert (MARKER in json.dumps([record["task"], record["corrections"]])) is own
    events = _framed(_episode("ep-1", "episode"))["events"]
    [marked] = [item for item in events if MARKER in item.get("text", "")]  # other text is still shown...
    assert marked.get("from_user", False) is own  # ...but only the user's is marked as theirs


def _operator_event(seq: int, episode: str, phase: str, op: str, *, source: str, actor: str, **fields: Any) -> dict:
    """An event exactly as the operator collector builds it (mordred-browser-os ``ActivityRecorder._event``)."""
    action = {"op": op, "target": fields.pop("target", None), "site": "example.com", "route": "/billing", "args": {}}
    return {
        "event_id": f"{episode}-{seq}",
        "seq": seq,
        "episode_id": episode,
        "attempt_id": fields.pop("attempt_id", None),
        "parent_attempt_id": None,
        "source": source,
        "actor": actor,
        "observed_at": round(time.time() - 100 + seq, 3),
        "phase": phase,
        "action": action,
        "result": {"status": fields.pop("status", "unknown"), "method": None, "evidence": []},
        "quality": {
            "coverage": "selected_tab",
            "exclusions": [],
            "truncated": False,
            "page_sig_before": None,
            "page_sig_after": None,
        },
        "session_ref": {"hermes_session_id": None, "turn_id": None, "run_id": "run-1"},
        "text": fields.pop("text", None),
        **fields,
    }


def test_the_operators_real_field_values_qualify_and_its_summary_does_not(history_home) -> None:
    home, store = history_home
    write_config(home, {**ENABLED, "collection_enabled": True})
    receiver = StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=lambda _home: store)
    summary = "AGENTSUMMARY I opened the invoices page and found three invoices"
    events = [
        _operator_event(1, "ep-op", "boundary", "task_start", source="operator", actor="human", text=TASK),
        _operator_event(
            2, "ep-op", "intended", "click", source="operator", actor="agent", attempt_id="a1", target="Invoices"
        ),
        _operator_event(
            3, "ep-op", "boundary", "task_end", source="operator", actor="agent", text=summary, status="claimed_success"
        ),
        _operator_event(4, "ep-op", "correction", "other", source="user_correction", actor="human", text=CORRECTION),
    ]
    batch = {"schema_version": 1, "producer_id": "prod-op", "producer_kind": "operator", "events": events}
    ack = receiver.ingest(PeerPrincipal(peer_id="operator:0123456789ab", kind="operator"), batch)
    assert ack["type"] == "activity_ack" and ack["accepted"] == 4

    turn = _turn("open the invoices page again", "turn")["context"]
    assert f'task "{TASK}"' in turn and f'user correction: "{CORRECTION}"' in turn
    assert "AGENTSUMMARY" not in turn
    [record] = _lookup("lookup", query="invoices")["episodes"]
    assert (record["task"], record["corrections"]) == (TASK, [CORRECTION])
    events_out = _framed(_episode("ep-op", "episode"))["events"]
    marked = {(item["phase"], item["op"]) for item in events_out if item.get("from_user")}
    assert marked == {("boundary", "task_start"), ("correction", "other")}
    [end] = [item for item in events_out if item["op"] == "task_end"]
    assert "AGENTSUMMARY" in end["text"] and "from_user" not in end


# --- rows stored before a URL rule existed ----------------------------------------------------------------


OLD_VALUES = ("OldVerifierValue", "OldAssertionValue", "AbCdEfGhIjKlMnOpQrStUvWxYz")
OLD_URL = "https://AbCdEfGhIjKlMnOpQrStUvWxYz@idp.example/cb?code_verifier=OldVerifierValue&client_assertion=OldAssertionValue"


def test_old_url_credentials_are_scrubbed_again_on_every_surface(history_home, monkeypatch) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seq = Seq()
    with monkeypatch.context() as patch:  # a receiver that knew neither parameter nor the opaque user name
        patch.setattr(contracts, "credential_param", lambda _name: False)
        patch.setattr(contracts, "_secret_username", lambda _name: False)
        seed_episode(
            store,
            seq,
            episode="ep-old",
            task=f"sign in again at {OLD_URL}",
            correction=f"use {OLD_URL} instead",
            title=f"Signed in via {OLD_URL}",
            page_text=f"Continue: {OLD_URL}",
            routes=("/account", "/cb?code_verifier=OldVerifierValue&client_assertion=OldAssertionValue"),
        )
        store.append_batch(
            PEER,
            PRODUCER,
            [
                event(
                    seq(),
                    "ep-old",
                    at=time.time() - 10,
                    phase="observed",
                    action={"op": "click", "site": "example.com", "route": "/account", "target": f"link {OLD_URL}"},
                )
            ],
        )
    with store.connection() as conn:
        stored = repr(conn.execute("SELECT * FROM activity_events").fetchall())
    assert all(value in stored for value in OLD_VALUES)  # the bypass really stored them

    shown = {
        "navigation": json.loads(_navigate("nav"))[RESULT_KEY],
        "turn": _turn("sign in again on example.com", "turn")["context"],
        "lookup": browser_history({"query": "sign in", "site": "example.com"}, session_id="lookup"),
        "episode": _episode("ep-old", "episode"),
    }
    for surface, text in shown.items():
        assert not any(value in text for value in OLD_VALUES), surface
    assert "code_verifier=redacted" in shown["episode"] and "client_assertion=redacted" in shown["episode"]
    assert "https://redacted@idp.example" in shown["lookup"]


def test_a_secret_shaped_route_segment_never_reaches_the_turn_block(history_home) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seed_episode(store, Seq(), episode="ep-reset", routes=("/account", "/reset/aBcdEfghIjklMno1x"))

    turn = _turn("open the invoices page on example.com", "turn")["context"]

    assert "aBcdEfghIjklMno1x" not in turn and "/reset/:id" in turn


# --- the read bound under a writer's lock -----------------------------------------------------------------


class _Keyed(sqlite3.Connection):
    mordred_key: object = None


def _shim_like(calls: list[float]) -> types.SimpleNamespace:
    """The SQLCipher shim's ``connect`` shape: open with ``timeout``, probe the schema (a lock is no key
    problem), mark the connection keyed."""

    def connect(path: str, *, timeout: float) -> sqlite3.Connection:
        calls.append(timeout)
        conn = sqlite3.connect(path, timeout=timeout, factory=_Keyed)
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlite3.OperationalError as exc:
            assert "locked" in str(exc)
        conn.mordred_key = object()
        return conn

    return types.SimpleNamespace(connect=connect)


def test_a_writer_lock_fails_the_history_open_within_the_read_bound(history_home, monkeypatch, audit_entries) -> None:
    home, store = history_home
    write_config(home, ENABLED)
    seed_episode(store, Seq(), episode="ep-1")
    calls: list[float] = []
    monkeypatch.setattr(_history_access, "reader", REAL_READER)
    monkeypatch.setattr("mordred_hermes.activity._history_access.check_protection", lambda _h: None)
    monkeypatch.setattr("mordred_hermes.activity._history_access.STORE_NAME", store.path.name)
    monkeypatch.setattr("mordred_hermes.activity._history_access.PLUGIN_DATA_SUBPATH", ())
    monkeypatch.setattr("mordred_hermes.activity._history_access._plaintext", lambda _p: False)
    monkeypatch.setattr("mordred_hermes.activity._gate._process_sqlite", lambda: _shim_like(calls))
    holder = sqlite3.connect(store.path, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        started = time.monotonic()
        with pytest.raises(ActivityRefused):
            REAL_READER(home)
        refused_in = time.monotonic() - started
        _history_access.forget(home)
        started = time.monotonic()
        assert _navigate("locked") is None  # the hook fails open...
        navigated_in = time.monotonic() - started
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    assert calls and set(calls) == {history.READ_BUSY_MS / 1000}  # the shim's probe got the read bound
    # One read bound (250 ms) for opening and reading together, plus scheduling slack; the store's 2 s
    # write timeout used to apply to the probe (about 2.5 s in all).
    assert refused_in < 1.0 and navigated_in < 1.0
    assert [entry["code"] for entry in audit_entries] == ["busy"]  # ...and is audited once
