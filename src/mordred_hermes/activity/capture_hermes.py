"""Hermes as a collector: its own browser tool calls and the user's chat corrections, recorded into ``mordred.db``.

Phase B2 of the browser-history design. Two hooks:

- ``pre_llm_call`` (:func:`pre_llm_call`) remembers the turn per Hermes
  session of a profile (state is keyed by the profile home's real path and the
  session, so one process serving several profiles never mixes them): its id
  (Hermes's ``turn_id``; hermes-agent 0.13.0 passes none, so a local id is
  made for every call), when it started, the user message (at most
  :data:`.contracts.MAX_TEXT_CHARS` characters) and whether that message is a
  person's words: only a turn whose ``platform`` is one of
  ``history_human_platforms`` (default the local interactive surfaces ``cli``,
  ``tui`` and ``desktop``); any other platform, a missing one included, is an
  agent's, a job's or an unknown sender's prompt. A person's message starting
  with ``correct:`` or ``訂正:`` (also with a full-width colon; the operator's
  convention, any case) also records a correction of the session's last
  recorded browser call: the one this process recorded, else (``--resume``,
  ``-c``, a restart: a new process) the newest one the store holds for the
  session (:func:`.history.last_hermes_call`, through the gated reader). The
  hook returns ``None``: the message reaches the model unchanged.
- ``post_tool_call`` (:func:`post_tool_call`) turns every ``browser_*`` call
  into one event with ``source`` ``hermes``, ``actor`` ``agent``, the Hermes
  session and turn ids and an ``attempt_id`` of its own: the
  ``tool_call_id`` (:func:`attempt_id`) and a random suffix
  (:func:`occurrence_id`), because a provider may repeat a ``tool_call_id``
  across turns and sessions. ``browser_navigate`` → ``navigate`` (route from
  the final URL; ``page_title`` from the result; ``page_text`` = the first
  :data:`PAGE_TEXT_CHARS` characters of its ``snapshot`` with the values of
  secret fields removed, :func:`page_text`), ``browser_click``
  → ``click``, ``browser_type`` → ``type``, ``browser_press`` → ``key``,
  ``browser_scroll`` → ``scroll``, ``browser_back`` → ``back``; any other
  browser tool → ``other`` with the tool name as its target. A click or type
  names its element by the ref's line in the snapshot of the page now open
  (:func:`element_label`: role and accessible name, never the field's value).
  ``status`` ``ok`` (or no status, as in 0.13.0) is ``dispatched`` /
  ``claimed_success`` unless the result reports an error, ``error`` is
  ``claimed_failure``, ``blocked`` and ``cancelled`` are the ``cancelled``
  phase and ``timeout`` the ``timed_out`` phase.

Episodes: one per ``(session, turn)`` with browser calls. Its first recorded
call is preceded by a ``boundary`` / ``task_start`` holding the turn's message,
``actor`` ``human`` for a person's message (:func:`.history.speaks_for_user`
then counts it as the user's words) and ``agent`` otherwise. A correction joins
the episode of the call it corrects, as ``user_correction`` / ``human`` /
``correction``. A person's correction message is never a task start: the
browser calls of its turn join the corrected episode while that is still the
session's last episode, and otherwise start an episode without a task start.
The episodes a session recorded are its own work, already in its conversation:
the history hooks leave them out of their blocks (:func:`own_episodes`).

Typed text (:func:`field_kind`): a ref line naming a password (English or
Japanese), secret, token, card, one-time code or PIN is ``sensitive`` and its
text is never sent; a missing line, or one naming nothing, is ``other`` and a
named field ``text``, both kept (owner decision 2026-10-22). While the
snapshot is stale (below) the field is ``sensitive``: its line may describe
another page. The receiver's value check still withholds anything that
:func:`.contracts.looks_like_secret`. A single character pressed with
``browser_press`` is typing too and is not kept.

The open page (:func:`_observe`): a navigate or back result sets its URL (an
``about:`` page has none; a missing URL or one outside the receiver's host
rules leaves it unknown) and its snapshot; a successful ``browser_snapshot``
refreshes the snapshot (and the URL when it reports one). Any call that may
leave the page (a click, a key press, a type with a line break, console, CDP,
dialog, any other browser tool; a failed or cancelled call too, except one
Hermes blocked before it ran) makes the URL unknown and the snapshot stale
unless its result reports them; in hermes-agent 0.19.0 only the Camofox
backend's click result carries a URL and none carries a snapshot. A call on a
page whose URL is unknown is not recorded while any ``excluded_sites`` is
configured (it could be an excluded host's page; ``source_excluded``, like the
receiver), and is recorded without a route otherwise. A session starts with
the URL unknown and no snapshot.

Writes go through the receiver (:class:`.ingest.StoreReceiver`) as the
in-process principal ``hermes:<profile>`` (producer kind ``hermes``, trust
``local``, permitted use ``learning``), so configuration, the contract, size
limits, secret redaction, excluded sites, episode ownership and the protection
gate (SQLCipher only) apply unchanged; nothing leaves the process. Recording
needs ``enabled``, ``collection_enabled``, the master switch ``history_enabled``
and ``history_capture_hermes`` (corrections: ``history_chat_corrections``);
an invalid ``excluded_sites`` is refused by the receiver as usual.

Failure behavior: neither hook ever raises ``Exception`` or changes the call or
the turn. Work per call is bounded (one receiver call of one or two events, or
two calls when ``max_batch_events`` or ``max_batch_bytes`` cannot hold both; a
correction without a call this process recorded first reads the store once,
:func:`.history.last_hermes_call`, and goes on without it when that read is
refused or fails; the snapshot kept for ref lookup is capped at
:data:`MAX_SNAPSHOT_CHARS`; at most :data:`MAX_SESSIONS` sessions are
remembered). A write waits at most
:data:`WRITE_BUSY_S` for another writer's lock (the extension gateway's
receiver writes the same store) and is then refused as ``busy`` and dropped. A
write that takes longer than :data:`SLOW_APPEND_S` counts as slow; after
:data:`SLOW_APPENDS_TO_SUSPEND` slow writes recording stops for that session
and ``activity.capture_suspended`` is audited.
"""

from __future__ import annotations

import collections
import hashlib
import itertools
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ._browser_results import PAGE_TEXT_CHARS, element_label, field_kind, page_text, ref_line
from ._browser_results import json_object as _json_object
from ._browser_results import page_location as _page
from ._browser_results import reported_url as _reported_url
from ._browser_results import text_field as _text_field
from .contracts import (
    COLLECTOR_SENSITIVE_MARK,
    EXCLUSION_TYPED_TEXT,
    MAX_TARGET_CHARS,
    MAX_TEXT_CHARS,
    SCHEMA_VERSION,
    SENSITIVE_FIELD_KIND,
    ContractError,
    PeerPrincipal,
    canonical_json,
    check_batch_envelope,
    event_size,
    normalize_event,
)

if TYPE_CHECKING:
    from .config import ActivityConfig
    from .store import ActivityStore

__all__ = [
    "MAX_SESSIONS",
    "MAX_SNAPSHOT_CHARS",
    "PAGE_TEXT_CHARS",
    "PRODUCER_KIND",
    "SLOW_APPENDS_TO_SUSPEND",
    "SLOW_APPEND_S",
    "STORE_FACTORY",
    "WRITE_BUSY_S",
    "attempt_id",
    "correction_text",
    "element_label",
    "field_kind",
    "occurrence_id",
    "own_episodes",
    "page_text",
    "post_tool_call",
    "pre_llm_call",
    "principal",
    "ref_line",
    "register_hooks",
    "speaks_as_user",
]

_LOG = logging.getLogger(__name__)

PRODUCER_KIND: Final = "hermes"
#: An in-process principal: Hermes itself, not a paired peer.
TRUST: Final = "local"
PERMITTED_USE: Final = "learning"
#: A write slower than this counts towards suspending the session's capture.
SLOW_APPEND_S: Final = 0.2
SLOW_APPENDS_TO_SUSPEND: Final = 3
#: How long a capture write waits for another writer's lock, opening included (the bound of Hermes-side reads,
#: :data:`.history.READ_BUSY_MS`).
WRITE_BUSY_S: Final = 0.25
#: Characters of the session's last snapshot kept for ref lookup.
MAX_SNAPSHOT_CHARS: Final = 60_000
#: Hermes sessions remembered (oldest forgotten first).
MAX_SESSIONS: Final = 128
#: Episodes remembered per session as its own (:func:`own_episodes`).
MAX_OWN_EPISODES: Final = 64
#: Characters of the ``tool_call_id`` part of an attempt id (:func:`occurrence_id` adds ``-`` and 12 hex).
_ATTEMPT_PREFIX_CHARS: Final = 51
#: Browser tools that never leave the open page (a ``browser_type`` whose text has a line break may submit a form).
_STAYS_ON_PAGE: Final = frozenset({"browser_type", "browser_scroll", "browser_vision", "browser_get_images"})
#: Browser tools whose successful result's ``url`` and ``snapshot`` describe the page open after the call.
_REPORTS_PAGE: Final = frozenset(
    {"browser_navigate", "browser_back", "browser_click", "browser_press", "browser_snapshot"}
)
#: ``correct: …`` / ``訂正: …`` (also with a full-width colon; the operator's convention, ``mordred/app.py``),
#: any case.
CORRECTION_RE: Final = re.compile(r"^\s*(?:訂正\s*[:\uff1a]|correct\s*:)\s*(.*)$", re.IGNORECASE | re.DOTALL)
#: The receiver's identifier rules (``contracts._ID_RE`` / ``contracts._REF_RE``).
_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}")
_SESSION_REF_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PROFILE_RE: Final = re.compile(r"[^A-Za-z0-9_.-]")
#: Below this raw size an event is sent as is; above, it is fitted to the receiver's per-event limit first.
_FIT_MARGIN: Final = 2048
_SHRINK_ORDER: Final = ("page_text", "text", "page_title")

#: This process's producer: sequence numbers only need to grow within it.
_PRODUCER_ID: Final = str(uuid.uuid4())
_SEQ = itertools.count(1)
_LOCAL_TURNS = itertools.count(1)


@dataclass(frozen=True)
class _Attempt:
    attempt_id: str
    episode_id: str
    #: The page the call acted on: its URL, or (``site`` set) the stored route path and query.
    url: str | None
    site: str | None = None


@dataclass
class _Session:
    lock: threading.Lock = field(default_factory=threading.Lock)
    #: The current turn's key (Hermes's ``turn_id``, else a local one) and Hermes's own id when it gave one.
    turn: str | None = None
    turn_ref: str | None = None
    turn_at: float = 0.0
    message: str | None = None
    message_cut: bool = False
    #: The turn's message is the user's own words (:func:`speaks_as_user`).
    human: bool = False
    episode: str | None = None
    episode_turn: str | None = None
    task_recorded: bool = False
    #: The episode the current turn's correction was recorded into: the turn's browser calls join it.
    joins: str | None = None
    #: The last browser call that was recorded: what a chat correction refers to.
    last: _Attempt | None = None
    #: The open page's URL (``None`` for an ``about:`` page) when ``page_known``; unknown after a call that may
    #: have left the page without reporting where it is.
    page_url: str | None = None
    page_known: bool = False
    #: The open page's snapshot (refs point into it); ``snapshot_stale`` when the page may have changed since the
    #: last one, which is then dropped.
    snapshot: str | None = None
    snapshot_stale: bool = False
    #: The episodes this session recorded into (newest last; :func:`own_episodes`).
    episodes: collections.deque[str] = field(default_factory=lambda: collections.deque(maxlen=MAX_OWN_EPISODES))
    slow: int = 0
    suspended: bool = False


#: A session's state key: the profile home's real path and Hermes's session (:func:`._history_access.session_key`).
_Key = tuple[str, str]
_sessions_lock = threading.Lock()
_sessions: collections.OrderedDict[_Key, _Session] = collections.OrderedDict()


def _state_key(home: Path, session_id: Any, task_id: Any) -> _Key:
    from . import _history_access as access

    return os.path.realpath(home), access.session_key(session_id, task_id)


def _session(key: _Key) -> _Session:
    with _sessions_lock:
        state = _sessions.get(key)
        if state is None:
            state = _sessions[key] = _Session()
        _sessions.move_to_end(key)
        while len(_sessions) > MAX_SESSIONS:
            _sessions.popitem(last=False)
        return state


def own_episodes(home: Path, session_id: Any = None, task_id: Any = None) -> frozenset[str]:
    """The episodes this Hermes session of ``home`` recorded (at most :data:`MAX_OWN_EPISODES`): its own work,
    which the history hooks never show back to it. Never creates a session's state."""
    with _sessions_lock:
        state = _sessions.get(_state_key(home, session_id, task_id))
    if state is None:
        return frozenset()
    with state.lock:
        return frozenset(state.episodes)


# --------------------------------------------------------------------------- #
# Configuration, principal, store
# --------------------------------------------------------------------------- #


def _recording(config: ActivityConfig) -> bool:
    return config.enabled and config.collection_enabled and config.history_enabled


def _capturing(config: ActivityConfig) -> bool:
    return _recording(config) and config.history_capture_hermes


def _correcting(config: ActivityConfig) -> bool:
    return _recording(config) and config.history_chat_corrections


def principal(home: Path) -> PeerPrincipal:
    """``hermes:<profile>`` (``default`` for the root home), producer kind ``hermes``, trust ``local``."""
    resolved = Path(os.path.realpath(home))
    name = resolved.name if resolved.parent.name == "profiles" else "default"
    profile = _PROFILE_RE.sub("-", name)[:64] or "default"
    return PeerPrincipal(f"hermes:{profile}", PRODUCER_KIND, trust=TRUST, permitted_use=PERMITTED_USE)


def _gated_store(home: Path) -> ActivityStore:
    """The store through the protection gate (:func:`._gate.open_store`), with the capture's lock wait."""
    from ._gate import open_store

    return open_store(home, busy_timeout_s=WRITE_BUSY_S)


#: How the receiver opens the store; production only ever uses the gate (tests replace this seam).
STORE_FACTORY: Callable[[Path], ActivityStore] = _gated_store


def _open(home: Path) -> ActivityStore:
    return STORE_FACTORY(home)


# --------------------------------------------------------------------------- #
# Identifiers and text helpers
# --------------------------------------------------------------------------- #


def attempt_id(tool_call_id: Any) -> str:
    """``tool_call_id`` as the receiver's identifier: as is when it fits, else with every other character
    replaced by ``-`` (``call_abc`` → ``call-abc``), else ``tc-`` and 32 hex of its SHA-256; a call without one
    gets a fresh id."""
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return str(uuid.uuid4())
    if _ID_RE.fullmatch(tool_call_id):
        return tool_call_id
    safe = re.sub(r"[^A-Za-z0-9-]", "-", tool_call_id)
    if _ID_RE.fullmatch(safe):
        return safe
    return "tc-" + hashlib.sha256(tool_call_id.encode("utf-8", "replace")).hexdigest()[:32]


def occurrence_id(base: str) -> str:
    """An attempt id for one call: ``base`` (:func:`attempt_id`, cut to fit) and ``-`` with 12 random hex, so a
    ``tool_call_id`` a provider repeats never makes two calls (or a correction) share an attempt."""
    return f"{base[:_ATTEMPT_PREFIX_CHARS]}-{uuid.uuid4().hex[:12]}"


def _ref(value: Any) -> str | None:
    """A Hermes session or turn id as the receiver accepts it, else ``None`` (never a made-up id)."""
    return value if isinstance(value, str) and _SESSION_REF_RE.fullmatch(value) else None


def correction_text(message: Any) -> str | None:
    """The correction in a ``correct: …`` / ``訂正: …`` message, else ``None`` (also for an empty one)."""
    if not isinstance(message, str):
        return None
    match = CORRECTION_RE.match(message)
    body = match.group(1).strip() if match else ""
    return body[:MAX_TEXT_CHARS] or None


# --------------------------------------------------------------------------- #
# Tool calls → events
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Call:
    tool: str
    args: Mapping[str, Any]
    payload: dict[str, Any] | None
    status: str | None
    attempt_id: str

    @property
    def succeeded(self) -> bool:
        return self.payload is not None and self.payload.get("success") is True


@dataclass(frozen=True)
class _Mapped:
    op: str
    route: str | None = None
    target: str | None = None
    args: Mapping[str, Any] = field(default_factory=dict)
    text: str | None = None
    page_title: str | None = None
    page_text: str | None = None
    exclusions: tuple[str, ...] = ()
    #: Whether ``route`` is the page's (``None`` for an ``about:`` page) or the page is unknown.
    page_known: bool = True


def _navigate(call: _Call, state: _Session) -> _Mapped:
    del state
    if not call.succeeded:  # nothing opened: the URL that was asked for, no page fields
        known, route = _page(call.args.get("url"))
        return _Mapped("navigate", route=route, page_known=known)
    known, route = _page(_reported_url(call.payload))
    snapshot = _text_field(call.payload, "snapshot")
    return _Mapped(
        "navigate",
        route=route,
        page_known=known,
        page_title=_text_field(call.payload, "title"),
        page_text=page_text(snapshot) if snapshot else None,
    )


def _on_page(op: str, state: _Session, **fields: Any) -> _Mapped:
    """An event on the open page: its URL, or none while the page is unknown."""
    return _Mapped(op, route=state.page_url if state.page_known else None, page_known=state.page_known, **fields)


def _click(call: _Call, state: _Session) -> _Mapped:
    return _on_page("click", state, target=element_label(ref_line(state.snapshot, call.args.get("ref"))))


def _type(call: _Call, state: _Session) -> _Mapped:
    line = ref_line(state.snapshot, call.args.get("ref"))
    # A stale snapshot's line may describe another page's field: treated as a secret one.
    kind = SENSITIVE_FIELD_KIND if state.snapshot_stale else field_kind(line)
    typed = call.args.get("text")
    typed = typed if isinstance(typed, str) and typed else None
    base = _on_page("type", state, target=element_label(line), args={"field_kind": kind})
    if kind != SENSITIVE_FIELD_KIND:
        return replace(base, text=typed)
    # What is typed into a secret field never leaves this function.
    marks = (COLLECTOR_SENSITIVE_MARK, EXCLUSION_TYPED_TEXT) if typed else (COLLECTOR_SENSITIVE_MARK,)
    return replace(base, exclusions=marks)


def _press(call: _Call, state: _Session) -> _Mapped:
    key = call.args.get("key")
    if isinstance(key, str) and 1 < len(key) <= 32:  # Enter, Tab, Control+a: named keys are kept
        return _on_page("key", state, args={"keys": [key]})
    # A single character pressed is typing into a field Hermes cannot classify here.
    marks = (EXCLUSION_TYPED_TEXT,) if isinstance(key, str) and key else ()
    return _on_page("key", state, exclusions=marks)


def _scroll(call: _Call, state: _Session) -> _Mapped:
    direction = call.args.get("direction")
    args = {"direction": direction} if isinstance(direction, str) and 0 < len(direction) <= 16 else {}
    return _on_page("scroll", state, args=args)


def _back(call: _Call, state: _Session) -> _Mapped:
    if not call.succeeded:  # the page it was called on
        return _on_page("back", state)
    known, route = _page(_reported_url(call.payload))
    return _Mapped("back", route=route, page_known=known)


def _snapshot(call: _Call, state: _Session) -> _Mapped:
    reported = _reported_url(call.payload) if call.succeeded else None
    if reported is None:
        return _other(call, state)
    known, route = _page(reported)  # the page it read (a snapshot never navigates)
    return _Mapped("other", route=route, page_known=known, target=call.tool[:MAX_TARGET_CHARS])


def _other(call: _Call, state: _Session) -> _Mapped:
    return _on_page("other", state, target=call.tool[:MAX_TARGET_CHARS])


_MAPPERS: Final[Mapping[str, Callable[[_Call, _Session], _Mapped]]] = {
    "browser_navigate": _navigate,
    "browser_click": _click,
    "browser_type": _type,
    "browser_press": _press,
    "browser_scroll": _scroll,
    "browser_back": _back,
    "browser_snapshot": _snapshot,
}


def _outcome(call: _Call) -> tuple[str, str, str | None]:
    """``(phase, result status, reason)`` of a call from Hermes's ``status`` (absent in 0.13.0) and its result."""
    if call.status in ("blocked", "cancelled"):
        return "cancelled", "unknown", call.status
    if call.status == "timeout":
        return "timed_out", "unknown", None
    reported = call.payload is not None and (call.payload.get("success") is False or bool(call.payload.get("error")))
    failed = call.status == "error" or reported
    return "dispatched", "claimed_failure" if failed else "claimed_success", None


def _stays_on_page(call: _Call) -> bool:
    """The call cannot have left the open page: Hermes blocked it before it ran, or the tool never navigates."""
    if call.status == "blocked":
        return True
    if call.tool not in _STAYS_ON_PAGE:
        return False
    text = call.args.get("text") if call.tool == "browser_type" else None
    return not (isinstance(text, str) and ("\n" in text or "\r" in text))


def _observe(call: _Call, state: _Session) -> None:
    """What the call tells about the page open after it: its URL and the snapshot refs point into (module
    docstring, "The open page")."""
    if _stays_on_page(call):
        return
    payload = call.payload if call.succeeded and call.tool in _REPORTS_PAGE else None
    reported = _reported_url(payload)
    snapshot = _text_field(payload, "snapshot")
    if call.tool == "browser_snapshot" and payload is not None:
        # The same page read again: a fresh snapshot, and its URL only when the result reports one.
        state.snapshot, state.snapshot_stale = (snapshot[:MAX_SNAPSHOT_CHARS] if snapshot else None), False
        if reported is not None:
            state.page_known, state.page_url = _page(reported)
        return
    state.page_known, state.page_url = _page(reported)
    state.snapshot, state.snapshot_stale = (snapshot[:MAX_SNAPSHOT_CHARS], False) if snapshot else (None, True)


def _envelope(episode: str, refs: Mapping[str, str | None], *, phase: str, at: float) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "seq": next(_SEQ),
        "episode_id": episode,
        "source": "hermes",
        "actor": "agent",
        "observed_at": at,
        "phase": phase,
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab"},
        "session_ref": dict(refs),
    }


def _refs(session_id: Any, turn_ref: str | None) -> dict[str, str | None]:
    return {"hermes_session_id": _ref(session_id), "turn_id": turn_ref}


def _task_start(state: _Session, episode: str, refs: Mapping[str, str | None]) -> dict[str, Any]:
    event = _envelope(episode, refs, phase="boundary", at=state.turn_at or time.time())
    event.update(actor="human" if state.human else "agent", action={"op": "task_start"}, text=state.message)
    event["quality"]["truncated"] = state.message_cut
    return event


def _call_event(call: _Call, mapped: _Mapped, episode: str, refs: Mapping[str, str | None]) -> dict[str, Any]:
    phase, status, reason = _outcome(call)
    args = {**mapped.args, **({"reason": reason} if reason else {})}
    event = _envelope(episode, refs, phase=phase, at=time.time())
    event.update(
        attempt_id=call.attempt_id,
        action={"op": mapped.op, "target": mapped.target, "route": mapped.route, "args": args},
        result={"status": status},
    )
    event["quality"]["exclusions"] = list(mapped.exclusions)
    optional = {"text": mapped.text, "page_title": mapped.page_title, "page_text": mapped.page_text}
    event.update({key: value for key, value in optional.items() if value is not None})
    return event


def _correction_event(attempt: _Attempt, body: str, refs: Mapping[str, str | None]) -> dict[str, Any]:
    event = _envelope(attempt.episode_id, refs, phase="correction", at=time.time())
    action: dict[str, Any] = {"op": "other", "route": attempt.url}
    if attempt.site is not None:
        action["site"] = attempt.site
    event.update(attempt_id=attempt.attempt_id, source="user_correction", actor="human", action=action, text=body)
    return event


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def _raw_size(event: Mapping[str, Any]) -> int:
    return len(json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _shrunk(event: dict[str, Any], over: int) -> dict[str, Any] | None:
    """``event`` with its page text (then text, then title) shortened by ``over`` UTF-8 bytes; ``None`` when
    nothing is left to shorten."""
    for key in _SHRINK_ORDER:
        value = event.get(key)
        if not isinstance(value, str) or not value:
            continue
        raw = value.encode("utf-8")
        kept = raw[: max(0, len(raw) - over)].decode("utf-8", "ignore").rstrip()
        smaller = {**event, "quality": {**event["quality"], "truncated": True}}
        if kept:
            smaller[key] = kept
        else:
            smaller.pop(key)
        return smaller
    return None


def _fit(event: dict[str, Any], limit: int) -> dict[str, Any]:
    """``event`` shortened until its normalized form fits the receiver's per-event limit (bounded passes)."""
    if _raw_size(event) <= limit - _FIT_MARGIN:
        return event
    for _ in range(len(_SHRINK_ORDER) + 2):
        try:
            normalized = normalize_event(event, excluded_sites=frozenset(), max_event_bytes=1 << 30)
        except ContractError:
            return event  # the receiver refuses it under its own code
        over = event_size(normalized) - limit
        if over <= 0:
            return event
        smaller = _shrunk(event, over + 256)
        if smaller is None:
            return event
        event = smaller
    return event


def _batch(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "producer_id": _PRODUCER_ID,
        "producer_kind": PRODUCER_KIND,
        "events": events,
    }


def _batch_size(events: list[dict[str, Any]]) -> int:
    """The size the receiver measures for a batch of ``events`` (:func:`.contracts.check_batch_envelope`)."""
    return len(canonical_json(_batch(events), ascii_only=False).encode("utf-8"))


def _fit_batch(event: dict[str, Any], limit: int) -> dict[str, Any]:
    """``event`` shortened (page text, then text, then title) until a batch of it alone fits ``limit`` bytes."""
    for _ in range(len(_SHRINK_ORDER) + 2):
        over = _batch_size([event]) - limit
        if over <= 0:
            return event
        smaller = _shrunk(event, over + 64)
        if smaller is None:
            return event  # the receiver refuses it as batch_too_large
        event = smaller
    return event


def _batches(config: ActivityConfig, events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """``events`` in order, in as few batches as ``max_batch_events`` and ``max_batch_bytes`` hold."""
    batches: list[list[dict[str, Any]]] = []
    for event in events:
        last = batches[-1] if batches else None
        if (
            last is not None
            and len(last) < config.max_batch_events
            and _batch_size([*last, event]) <= (config.max_batch_bytes)
        ):
            last.append(event)
        else:
            batches.append([event])
    return batches


def _acceptable(config: ActivityConfig, batches: list[list[dict[str, Any]]]) -> bool:
    """Every batch passes the receiver's envelope limits and every event its contract (excluded sites and size
    included)."""
    try:
        for batch in batches:
            check_batch_envelope(
                _batch(batch), max_events=config.max_batch_events, max_bytes_raw=config.max_batch_bytes
            )
            for event in batch:
                normalize_event(event, excluded_sites=config.excluded_sites, max_event_bytes=config.max_event_bytes)
    except ContractError:
        return False
    return True


def _submit(home: Path, events: list[dict[str, Any]]) -> bool:
    """One batch through the receiver; ``True`` when it was acknowledged."""
    from . import _history_access as access
    from .ingest import StoreReceiver

    batch = _batch(events)
    receiver = StoreReceiver(home, config_loader=access.config, store_factory=_open)
    reply = receiver.ingest(principal(home), batch)
    if reply.get("type") != "activity_ack":
        _LOG.debug("mordred activity capture: batch refused (%s)", reply.get("reason"))
        return False
    return True


def _write(state: _Session, home: Path, config: ActivityConfig, events: list[dict[str, Any]]) -> int:
    """Submit ``events`` in order and time it; how many were acknowledged (a refused batch stops the rest).

    Each event is first shortened to the per-event and per-batch limits. The events go as one batch unless the
    configured limits cannot hold them; then each batch goes alone, and only when the receiver would accept
    every batch and every event, so a task start is never stored without its call. A failure part-way returns
    what was acknowledged before it. Slow writes count towards suspending the session. Never raises."""
    started = time.monotonic()
    done = 0
    try:
        if config.collection_refusal is None:
            events = [_fit_batch(_fit(event, config.max_event_bytes), config.max_batch_bytes) for event in events]
        batches = _batches(config, events)
        if len(batches) > 1 and not _acceptable(config, batches):
            return 0
        for batch in batches:
            if not _submit(home, batch):
                break
            done += len(batch)
    except Exception as exc:  # recording must never break the call or the turn
        _LOG.debug("mordred activity capture: write failed (%s)", type(exc).__name__)
    finally:
        _note_duration(state, home, time.monotonic() - started)
    return done


def _note_duration(state: _Session, home: Path, elapsed: float) -> None:
    if elapsed <= SLOW_APPEND_S or state.suspended:
        return
    state.slow += 1
    if state.slow >= SLOW_APPENDS_TO_SUSPEND:
        from ._capture_audit import audit_capture_suspended

        state.suspended = True
        audit_capture_suspended("slow_append", peer_id=principal(home).peer_id)


# --------------------------------------------------------------------------- #
# Hooks
# --------------------------------------------------------------------------- #


def _turn_of(state: _Session, turn_id: Any) -> tuple[str, str | None]:
    """``(turn key, Hermes's turn id)`` of a browser call: Hermes's ``turn_id`` (0.19.0), else the session's
    current turn (0.13.0 passes none; a call before any turn gets a local one, never recorded as an id)."""
    if isinstance(turn_id, str) and turn_id:
        return turn_id, _ref(turn_id)
    if state.turn is None:
        state.turn, state.turn_ref = f"local-{next(_LOCAL_TURNS)}", None
    return state.turn, state.turn_ref


def _episode_for(state: _Session, turn: str) -> tuple[str, bool]:
    """``(episode id, whether its task start is still to be written)`` for a browser call of ``turn``; the
    task start needs the turn's message, so a call of a turn whose ``pre_llm_call`` was not seen gets none.

    A correction turn's calls join the corrected episode while it is still the session's last one (it has its
    task start); otherwise, or after a correction that was not recorded, they start an episode without one (the
    turn has no message: :func:`_record_turn`)."""
    if state.episode is None or state.episode_turn != turn:
        joined = state.joins if state.turn == turn and state.episodes and state.episodes[-1] == state.joins else None
        state.episode, state.episode_turn, state.task_recorded = joined or str(uuid.uuid4()), turn, joined is not None
    pending = not state.task_recorded and state.turn == turn and state.message is not None
    return state.episode, pending


def _record_call(
    tool_name: str, args: Any, result: Any, session_id: Any, task_id: Any, tool_call_id: Any, turn_id: Any, status: Any
) -> None:
    from . import _history_access as access

    home = access.home()
    config = access.config(home)
    if not _capturing(config):
        return
    state = _session(_state_key(home, session_id, task_id))
    with state.lock:
        if state.suspended:
            return
        call = _Call(
            tool_name,
            args if isinstance(args, Mapping) else {},
            _json_object(result),
            status if isinstance(status, str) else None,
            occurrence_id(attempt_id(tool_call_id)),
        )
        turn, turn_ref = _turn_of(state, turn_id)
        episode, pending = _episode_for(state, turn)
        refs = _refs(session_id, turn_ref)
        mapped = _MAPPERS.get(tool_name, _other)(call, state)
        _observe(call, state)
        if _unplaced(config, mapped):
            _LOG.debug("mordred activity capture: call dropped (source_excluded: the page is unknown)")
            return
        events = [_task_start(state, episode, refs)] if pending else []
        events.append(_call_event(call, mapped, episode, refs))
        done = _write(state, home, config, events)
        if done and episode not in state.episodes:
            state.episodes.append(episode)
        state.task_recorded = state.task_recorded or (pending and done > 0)
        if done == len(events):
            state.last = _Attempt(call.attempt_id, episode, mapped.route)


def _unplaced(config: ActivityConfig, mapped: _Mapped) -> bool:
    """A call on an unknown page while sites are excluded: it could be an excluded host's, so nothing is sent
    (the task start waits for the next call). A refused collection still goes to the receiver, which audits it."""
    return not mapped.page_known and bool(config.excluded_sites) and config.collection_refusal is None


def post_tool_call(
    tool_name: Any = None,
    args: Any = None,
    result: Any = None,
    session_id: Any = None,
    task_id: Any = None,
    tool_call_id: Any = None,
    turn_id: Any = None,
    status: Any = None,
    **_kwargs: Any,
) -> None:
    """Record a ``browser_*`` call (``turn_id`` and ``status`` are read when Hermes passes them); never raises
    ``Exception`` and returns nothing (Hermes ignores the return value)."""
    try:
        if not isinstance(tool_name, str) or not tool_name.startswith("browser_"):
            return
        _record_call(tool_name, args, result, session_id, task_id, tool_call_id, turn_id, status)
    except Exception as exc:  # recording must never break a tool call
        _LOG.debug("mordred activity capture: call skipped (%s)", type(exc).__name__)


def _begin_turn(state: _Session, user_message: Any, turn_id: Any, human: bool) -> None:
    hermes_turn = turn_id if isinstance(turn_id, str) and turn_id else None
    state.turn = hermes_turn or f"local-{next(_LOCAL_TURNS)}"
    state.turn_ref = _ref(hermes_turn)
    state.turn_at = time.time()
    state.human = human
    state.joins = None
    text = user_message.strip() if isinstance(user_message, str) else ""
    state.message = text[:MAX_TEXT_CHARS] or None
    state.message_cut = len(text) > MAX_TEXT_CHARS


def speaks_as_user(config: ActivityConfig, platform: Any) -> bool:
    """Whether a turn's message is the user's own words: its ``platform`` is one of
    ``history_human_platforms``; a missing or unknown platform never is."""
    return isinstance(platform, str) and platform.strip().lower() in config.history_human_platforms


def _stored_last(home: Path, config: ActivityConfig, state: _Session, session_id: Any) -> _Attempt | None:
    """The session's last browser call recorded by another process (``--resume``, ``-c``, a restart), from the
    store through the gated reader (:func:`.history.last_hermes_call`: same principal, ``source`` ``hermes``,
    this ``hermes_session_id``, newest receipt, bounded); it becomes the session's last call and its episode one
    of the session's own. ``None`` without one, while the history is off, or when the read fails (fail open,
    reported like any history surface: :func:`._history_access.unavailable`)."""
    from . import _history_access as access
    from .history import last_hermes_call

    session = _ref(session_id)
    if session is None or not config.history_active:
        return None
    try:
        found = last_hermes_call(access.reader(home), peer_id=principal(home).peer_id, session_id=session)
    except access.NoHistory:
        return None
    except Exception as exc:
        access.unavailable(home, exc)
        return None
    if found is None:
        return None
    state.last = _Attempt(found.attempt_id, found.episode_id, found.route, found.site)
    if found.episode_id not in state.episodes and len(state.episodes) < MAX_OWN_EPISODES:
        state.episodes.appendleft(found.episode_id)  # older than any episode this process recorded into
    return state.last


def _record_turn(user_message: Any, session_id: Any, task_id: Any, turn_id: Any, platform: Any) -> None:
    from . import _history_access as access

    home = access.home()
    config = access.config(home)
    if not (_capturing(config) or _correcting(config)):
        return
    state = _session(_state_key(home, session_id, task_id))
    with state.lock:
        human = speaks_as_user(config, platform)
        body = correction_text(user_message) if human else None
        # A correction is never the turn's task: its browser calls get no task start (:func:`_episode_for`).
        _begin_turn(state, None if body is not None else user_message, turn_id, human)
        if body is None or not _correcting(config) or state.suspended:
            return
        attempt = state.last or _stored_last(home, config, state, session_id)
        if attempt is None:
            return
        event = _correction_event(attempt, body, _refs(session_id, state.turn_ref))
        if _write(state, home, config, [event]) == 1:
            state.joins = attempt.episode_id


def pre_llm_call(
    user_message: Any = None,
    session_id: Any = None,
    task_id: Any = None,
    turn_id: Any = None,
    platform: Any = None,
    **_kwargs: Any,
) -> None:
    """Remember the turn and record a chat correction (``task_id``, ``turn_id`` and ``platform`` are read when
    Hermes passes them); always returns ``None`` (the message goes to the model unchanged), never raises
    ``Exception``."""
    try:
        _record_turn(user_message, session_id, task_id, turn_id, platform)
    except Exception as exc:  # recording must never abort the turn
        _LOG.debug("mordred activity capture: turn skipped (%s)", type(exc).__name__)


def register_hooks(ctx: Any) -> None:
    """Register both hooks; registration never reads configuration or opens the store."""
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("pre_llm_call", pre_llm_call)
