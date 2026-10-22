"""Every history surface (navigation block, turn-start context, both lookup tools) after the B1 security review.

- Read-time exclusion looks at every host an episode names: its events' sites and the URLs in their route,
  query and target label, so a host added to ``excluded_sites`` after capture hides the episode everywhere.
- An episode holding a ``source_excluded`` refusal marker (a batch the receiver refused as an excluded host's) is
  hidden everywhere, whatever ``excluded_sites`` holds at read time (live check 2026-10-22, D1); so is one holding
  the collector's ``site_excluded`` mark (a host excluded in the collector itself, live check 2026-10-22, C2).
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


class _Recorder:
    """A connection that records its queries and finds nothing."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    def execute(self, sql: str, *_args: Any) -> Any:
        self.queries.append(sql)
        return iter(())


def test_without_exclusions_the_check_reads_only_the_markers() -> None:
    conn = _Recorder()
    assert history._hidden(conn, ["ep-1"], {"ep-1": ["bank.example"]}, frozenset()) == set()  # type: ignore[arg-type]
    [query] = conn.queries  # one query, for both markers: no URL is read
    assert history._URL_FIELDS_SQL not in query
    assert history.REFUSED_SQL in query and history.COLLECTOR_EXCLUDED_SQL in query
    nothing = _Recorder()
    assert history._hidden(nothing, [], {}, frozenset({"bank.example"})) == set()  # type: ignore[arg-type]
    assert nothing.queries == []


def test_with_exclusions_the_check_is_one_query() -> None:
    conn = _Recorder()
    ids = [f"ep-{index}" for index in range(50)]
    assert history._hidden(conn, ids, {}, frozenset({"bank.example"})) == set()  # type: ignore[arg-type]
    [query] = conn.queries
    assert history._URL_FIELDS_SQL in query
    assert history.REFUSED_SQL in query and history.COLLECTOR_EXCLUDED_SQL in query


def test_excluded_sites_are_checked_on_site_rows_without_reading_urls(history_home) -> None:
    _home, store = history_home
    seed_episode(store, Seq(), episode="ep-bank", site="bank.example")
    with store.connection() as conn:
        assert history._hidden(conn, ["ep-bank"], {"ep-bank": ["bank.example"]}, frozenset({"bank.example"})) == {
            "ep-bank"
        }


# --- an episode the receiver refused part of as an excluded host's ---------------------------------------

OPERATOR = PeerPrincipal(peer_id="operator:0123456789ab", kind="operator")


def _operator_batch(*events: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "producer_id": "prod-op", "producer_kind": "operator", "events": list(events)}


def _unplaced(seq: int, episode: str, op: str, *, actor: str, text: str) -> dict[str, Any]:
    """A task boundary as the operator sent it in the live check (D1): no site or route, the page's content."""
    marker = episode.upper()
    raw = _operator_event(seq, episode, "boundary", op, source="operator", actor=actor, text=f"{text} {marker}")
    raw["action"] = {"op": op, "target": None, "site": None, "route": None, "args": {}}
    raw.update(page_title=f"{marker} Acme Portal", page_text=f"{marker} HOME-PAGE-TEXT-7731 Search invoices")
    return raw


def _pre_fix(store: Any, raw: dict[str, Any]) -> None:
    """``raw`` stored as a receiver stored it before the page-host rule existed (it checked named hosts only)."""
    store.append_batch(OPERATOR.peer_id, "prod-op", [contracts.normalize_event(raw, excluded_sites=frozenset())])


def _operator_episode(store: Any, receiver: StoreReceiver, episode: str, seq0: int, *, refused: bool) -> None:
    """An operator task: its start and end without a page host (stored before the page-host rule), a navigation
    on example.com through the receiver and, with ``refused``, an action on the excluded ``localhost`` (refused)
    and the gap marker the operator records for that refused batch."""
    _pre_fix(store, _unplaced(seq0, episode, "task_start", actor="human", text="settle the utility bill"))
    navigation = _operator_event(
        seq0 + 1,
        episode,
        "observed",
        "navigate",
        source="operator",
        actor="agent",
        attempt_id=f"{episode}-a1",
        status="claimed_success",
        page_title="Billing overview",
        page_text=f"{episode.upper()} the invoice table",
    )
    assert receiver.ingest(OPERATOR, _operator_batch(navigation))["type"] == "activity_ack"
    if refused:
        click = _operator_event(seq0 + 2, episode, "dispatched", "click", source="operator", actor="agent")
        click["action"].update(site="localhost", route="/index.html")
        assert receiver.ingest(OPERATOR, _operator_batch(click)) == {
            "type": "activity_refused",
            "reason": "source_excluded",
        }
        gap = _operator_event(seq0 + 3, episode, "gap", "other", source="operator", actor="unknown")
        gap["action"] = {"op": "other", "site": None, "route": None, "args": {"reason": "source_excluded"}}
        gap["quality"]["coverage"] = "gap"
        assert receiver.ingest(OPERATOR, _operator_batch(gap))["type"] == "activity_ack"
    _pre_fix(store, _unplaced(seq0 + 9, episode, "task_end", actor="agent", text="I settled the bill on the portal"))


def _every_surface(tag: str) -> dict[str, str]:
    nav = _navigate(f"{tag}-nav")
    turn = _turn("settle the utility bill on example.com again", f"{tag}-turn")
    return {
        "navigation": json.loads(nav)[RESULT_KEY] if nav else "",
        "turn": turn["context"] if turn else "",
        "lookup": json.dumps(_lookup(f"{tag}-lookup", query="", site="example.com")),
        "lookup_terms": json.dumps(_lookup(f"{tag}-terms", query="settle the utility bill")),
        "episode_refused": _episode("ep-refused", f"{tag}-episode"),
        "episode_kept": _episode("ep-kept", f"{tag}-kept"),
    }


@pytest.mark.parametrize("excluded", [["localhost"], []], ids=["still-excluded", "exclusion-removed"])
def test_an_episode_with_a_refused_excluded_batch_is_hidden_from_every_surface(history_home, excluded) -> None:
    home, store = history_home
    write_config(home, {**ENABLED, "collection_enabled": True, "excluded_sites": ["localhost"]})
    receiver = StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=lambda _home: store)
    _operator_episode(store, receiver, "ep-kept", 1, refused=False)
    _operator_episode(store, receiver, "ep-refused", 20, refused=True)
    with store.connection() as conn:  # the excluded pages' content is in the store, as in the live check
        leaked = conn.execute(
            "SELECT COUNT(*) FROM activity_events WHERE site IS NULL AND page_text LIKE '%EP-REFUSED%'"
        ).fetchone()
    assert leaked == (2,)

    write_config(home, {**ENABLED, "excluded_sites": excluded})
    shown = _every_surface("refused")

    for surface, text in shown.items():
        assert "EP-KEPT" in text or surface == "episode_refused", surface  # without a marker: unaffected
        assert "EP-REFUSED" not in text, surface
    assert json.loads(shown["episode_refused"]) == {"status": "not_found"}
    assert history.episode_detail(store, "ep-refused", excluded_sites=frozenset()) is None
    assert history.latest_page_text(store, ["ep-refused"], "example.com", 600, excluded_sites=frozenset()) == {}


# --- an episode on a host the collector itself excludes ----------------------------------------------------

SITE_EXCLUDED = "site_excluded"


def _position_only(seq: int, episode: str, phase: str, op: str, *, marks: list[str], **fields: Any) -> dict[str, Any]:
    """An event as the operator sends it on a host excluded in the collector itself (``--activity-exclude-site``,
    live check 2026-10-22, C2): its position only (no site, route, target or content), coverage ``partial`` and
    the collector's ``marks``."""
    raw = _operator_event(seq, episode, phase, op, source="operator", actor="agent", **fields)
    raw["action"] = {"op": op, "target": None, "site": None, "route": None, "args": {}}
    raw["quality"].update(coverage="partial", exclusions=marks)
    return raw


def _collector_excluded_episode(
    receiver: StoreReceiver, episode: str, seq0: int, *, marks: list[str], moved: bool
) -> None:
    """The user's task (a human task start with the instruction and no host) and, with ``moved``, a navigation on
    example.com; then a click and the task end on the host the collector excludes, one batch through the
    receiver (``marks`` on those last events)."""
    task = _operator_event(
        seq0,
        episode,
        "boundary",
        "task_start",
        source="operator",
        actor="human",
        text=f"settle the utility bill {episode.upper()}",
    )
    task["action"].update(site=None, route=None)
    events = [task]
    if moved:
        navigation = _operator_event(
            seq0 + 1,
            episode,
            "observed",
            "navigate",
            source="operator",
            actor="agent",
            attempt_id=f"{episode}-a1",
            status="claimed_success",
            page_title="Billing overview",
            page_text=f"{episode.upper()} the invoice table",
        )
        events.append(navigation)
    click = {"attempt_id": f"{episode}-a2"}
    events += [
        _position_only(seq0 + 2, episode, "intended", "click", marks=marks, **click),
        _position_only(seq0 + 3, episode, "dispatched", "click", marks=marks, status="claimed_success", **click),
        _position_only(seq0 + 4, episode, "boundary", "task_end", marks=marks, status="claimed_success"),
    ]
    assert receiver.ingest(OPERATOR, _operator_batch(*events))["type"] == "activity_ack"


@pytest.mark.parametrize("moved", [False, True], ids=["started-there", "moved-there"])
@pytest.mark.parametrize("excluded", [["localhost"], []], ids=["both-sides", "collector-only"])
def test_an_episode_on_a_host_the_collector_excludes_is_hidden_from_every_surface(
    history_home, excluded, moved
) -> None:
    home, store = history_home
    write_config(home, {**ENABLED, "collection_enabled": True, "excluded_sites": excluded})
    receiver = StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=lambda _home: store)
    _collector_excluded_episode(receiver, "ep-plain", 1, marks=[], moved=moved)
    _collector_excluded_episode(receiver, "ep-marked", 20, marks=[SITE_EXCLUDED], moved=moved)
    with store.connection() as conn:  # stored as sent: the user's instruction, then position-only marked events
        stored = conn.execute(
            "SELECT op, site, text, exclusions FROM activity_events WHERE episode_id = 'ep-marked' AND site IS NULL "
            "ORDER BY producer_seq"
        ).fetchall()
    assert [(op, site, text) for op, site, text, _marks in stored] == [
        ("task_start", None, "settle the utility bill EP-MARKED"),
        ("click", None, None),
        ("click", None, None),
        ("task_end", None, None),
    ]
    assert [SITE_EXCLUDED in json.loads(marks) for *_row, marks in stored] == [False, True, True, True]

    write_config(home, {**ENABLED, "excluded_sites": excluded})
    turn = _turn("settle the utility bill on example.com again", "marked-turn")
    shown = {
        "turn": turn["context"] if turn else "",
        "lookup_terms": json.dumps(_lookup("marked-terms", query="settle the utility bill")),
        "episode_plain": _episode("ep-plain", "marked-plain"),
        "episode_marked": _episode("ep-marked", "marked-episode"),
    }
    if moved:  # only an episode that named example.com is shown for it
        nav = _navigate("marked-nav")
        shown["navigation"] = json.loads(nav)[RESULT_KEY] if nav else ""
        shown["lookup"] = json.dumps(_lookup("marked-lookup", query="", site="example.com"))

    for surface, text in shown.items():
        assert "EP-PLAIN" in text or surface == "episode_marked", surface  # without the mark: unaffected
        assert "EP-MARKED" not in text, surface
    assert json.loads(shown["episode_marked"]) == {"status": "not_found"}
    assert history.episode_detail(store, "ep-marked", excluded_sites=frozenset()) is None
    if moved:
        assert history.latest_page_text(store, ["ep-marked"], "example.com", 600, excluded_sites=frozenset()) == {}
        assert "EP-PLAIN" in history.latest_page_text(
            store, ["ep-plain"], "example.com", 600, excluded_sites=frozenset()
        ).get("ep-plain", "")


@pytest.mark.parametrize(
    ("marks", "hidden"),
    [
        ([SITE_EXCLUDED], True),
        (["page_host_unknown", SITE_EXCLUDED], True),
        (["site_excluded_v2"], False),
        (["no_site_excluded"], False),
        (["sensitive_field"], False),
        ([], False),
    ],
)
def test_only_the_exact_collector_mark_in_exclusions_hides_an_episode(history_home, marks, hidden) -> None:
    _home, store = history_home
    seq = Seq()
    seed_episode(store, seq, episode="ep-1", task=f'what does "{SITE_EXCLUDED}" mean', correction=None)
    marked = event(
        seq(),
        "ep-1",
        at=time.time() - 30,
        phase="dispatched",
        action={"op": "click", "site": "example.com", "route": "/links"},
        quality={"coverage": "partial", "exclusions": marks},
    )
    store.append_batch(PEER, PRODUCER, [marked])
    with store.connection() as conn:  # the token in the user's text never counts: only ``exclusions`` is read
        assert history._hidden(conn, ["ep-1"], {"ep-1": ["example.com"]}, frozenset()) == (
            {"ep-1"} if hidden else set()
        )


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


# --- a task start the collector sends when the task ends --------------------------------------------------


def _page(
    seq: int, episode: str, phase: str, op: str, route: str, at: float, *, site: str = "example.com", **fields: Any
) -> dict[str, Any]:
    """An operator event observed at ``at`` on ``site`` / ``route``; ``actor`` defaults to ``agent``."""
    actor = fields.pop("actor", "agent")
    raw = _operator_event(seq, episode, phase, op, source="operator", actor=actor, observed_at=at, **fields)
    raw["action"].update(site=site, route=route)
    return raw


def _ingest(home: Any, store: Any, *batches: list[dict[str, Any]]) -> None:
    """Each batch through the real receiver, in order (the order the store receives the events)."""
    write_config(home, {**ENABLED, "collection_enabled": True})
    receiver = StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=lambda _home: store)
    for batch in batches:
        assert receiver.ingest(OPERATOR, _operator_batch(*batch))["type"] == "activity_ack"


def _late_start(home: Any, store: Any, *, start_site: str = "example.com") -> None:
    """An operator task as its collector sends it now: the task's actions as they happen; then, once the task
    ends, its start (held until then: its ``observed_at`` is still the task's start, and it names the start page
    with that page's title and text) and its end (no page read)."""
    t0 = round(time.time() - 100, 3)
    actions = [
        _page(
            1,
            "ep-late",
            "observed",
            "navigate",
            "/search.html",
            t0 + 2,
            attempt_id="a1",
            status="claimed_success",
            page_title="Search results",
            page_text="SEARCH-PAGE-TEXT",
        ),
        _page(2, "ep-late", "dispatched", "click", "/search.html", t0 + 3, attempt_id="a2", target="First result"),
    ]
    held = [
        _page(
            3,
            "ep-late",
            "boundary",
            "task_start",
            "/index.html",
            t0,
            site=start_site,
            actor="human",
            text=TASK,
            page_title="Acme home",
            page_text="HOME-PAGE-TEXT",
        ),
        _page(4, "ep-late", "boundary", "task_end", "/search.html", t0 + 4, status="claimed_success"),
    ]
    _ingest(home, store, actions, held)


def test_a_task_start_received_last_leads_the_route_and_titles_by_its_time(history_home) -> None:
    home, store = history_home
    _late_start(home, store)

    [summary] = history.episodes_for_site(store, "example.com", excluded_sites=frozenset()).episodes
    assert [hop.route for hop in summary.route] == ["/index.html", "/search.html"]
    assert summary.titles == ("Acme home", "Search results")
    assert summary.tasks == (TASK,)
    assert "route /index.html → /search.html" in json.loads(_navigate("nav"))[RESULT_KEY]
    [record] = _lookup("lookup", query="", site="example.com")["episodes"]
    assert record["routes"] == ["/index.html", "/search.html"]
    assert record["page_text"] == "SEARCH-PAGE-TEXT"  # the newest page in time, not the start page received last


def test_a_task_start_received_last_names_the_episodes_first_site(history_home) -> None:
    home, store = history_home
    _late_start(home, store, start_site="start.example")

    [summary] = history.episodes_for_site(store, "example.com", excluded_sites=frozenset()).episodes
    detail = history.episode_detail(store, "ep-late", excluded_sites=frozenset())
    assert detail is not None
    assert summary.sites == detail.summary.sites == ("start.example", "example.com")
    [record] = _lookup("lookup", query="", site="example.com")["episodes"]
    assert (record["site"], record["other_sites"]) == ("start.example", ["example.com"])


def test_events_observed_at_the_same_time_keep_the_order_they_were_received(history_home) -> None:
    home, store = history_home
    at = round(time.time() - 100, 3)
    zeta = _page(
        1,
        "ep-tie",
        "observed",
        "navigate",
        "/zeta",
        at,
        site="zeta.example",
        attempt_id="a1",
        page_title="Zeta",
    )
    alpha = _page(
        2,
        "ep-tie",
        "observed",
        "navigate",
        "/alpha",
        at,
        site="alpha.example",
        attempt_id="a2",
        page_title="Alpha",
    )
    _ingest(home, store, [zeta], [alpha])

    [summary] = history.episodes_for_terms(store, set(), excluded_sites=frozenset(), newest_if_none=True).episodes
    assert [hop.route for hop in summary.route] == ["/zeta", "/alpha"]
    assert summary.titles == ("Zeta", "Alpha")
    assert summary.sites == ("zeta.example", "alpha.example")


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
